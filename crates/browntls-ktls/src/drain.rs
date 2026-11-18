//! The pauses of `shutdown` while the kernel gives its last records to TCP.
//!
//! The kernel sends the records it holds from a work item, scheduled when
//! the socket gets room; nothing wakes a task when that work is done. So
//! once the socket has room, `shutdown` looks at the kernel's counters
//! again after a pause: at first it only yields, since the work was
//! scheduled before the task was woken and runs within microseconds on an
//! idle processor; later it has a thread wake it after a few milliseconds.
//! The pauses do not use a timer of the runtime, which may have none.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use crate::ledger::Backlog;
use crate::sys::Room;

/// How long after the socket was found with room the task only yields
/// between two looks.
const YIELDING: Duration = Duration::from_millis(1);

/// The first pause after that; each later one is twice as long, up to
/// [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_millis(1);

const LONGEST_PAUSE: Duration = Duration::from_millis(8);

/// How long the kernel may hold the same records, with room to send them
/// and nothing in flight whose acknowledgement would make it send, before
/// the wait is given up. The kernel's own retry, when it finds its
/// transmit lock taken, comes after 10 ms.
const STALLED: Duration = Duration::from_secs(5);

/// How the wait before the FIN ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// TCP has every record (or, without the kernel's counters, the socket
    /// has room): the FIN may follow.
    Sent,
    /// The connection ended while the kernel held records, which will not
    /// be sent.
    Lost,
}

/// The state of one such wait.
#[derive(Debug)]
pub(crate) struct Drain {
    /// When the socket was first found with room in this stretch.
    since: Option<Instant>,
    /// Since when the kernel has held this many bytes with nothing in
    /// flight.
    idle: Option<(Instant, u64)>,
    /// The next pause.
    pause: Duration,
    sleeper: Arc<Sleeper>,
}

impl Drain {
    pub(crate) fn new() -> Self {
        Self {
            since: None,
            idle: None,
            pause: FIRST_PAUSE,
            sleeper: Arc::default(),
        }
    }

    /// One step of the wait `shutdown` makes between its last record and
    /// the FIN. `backlog` is what the kernel holds, as just read; `room`
    /// waits until the kernel reports room on the socket (or its end),
    /// registering the task; `waker` is the task's.
    ///
    /// A FIN ahead of records the kernel holds would cut the stream short,
    /// so this is `Pending` while there are any: the socket has no room
    /// (the kernel sends when room appears, and `room` wakes the task), or
    /// it has and the kernel has yet to use it (the task is woken for
    /// another look after a pause). Without the kernel's counters, room is
    /// all there is to wait for.
    pub(crate) fn step(
        &mut self,
        now: Instant,
        backlog: io::Result<Backlog>,
        waker: &Waker,
        room: impl FnOnce() -> Poll<io::Result<Room>>,
    ) -> Poll<io::Result<Outcome>> {
        if matches!(backlog, Ok(Backlog { unsent: 0, .. })) {
            return Poll::Ready(Ok(Outcome::Sent));
        }
        let room = match room() {
            Poll::Ready(Ok(room)) => room,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => {
                self.reset();
                return Poll::Pending;
            }
        };
        let Ok(backlog) = backlog else {
            return Poll::Ready(Ok(Outcome::Sent));
        };
        if room == Room::Ended {
            return Poll::Ready(Ok(Outcome::Lost));
        }
        match self.wait(now, backlog, waker) {
            Ok(()) => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    /// The socket has no room: the wait is for the socket, and a new
    /// stretch begins when it has room again.
    fn reset(&mut self) {
        self.since = None;
        self.idle = None;
        self.pause = FIRST_PAUSE;
    }

    /// The socket has room and the kernel still holds `backlog`: has
    /// `waker` woken for the next look.
    ///
    /// Fails when the kernel has held the same records for [`STALLED`]
    /// although nothing kept it from sending them.
    fn wait(&mut self, now: Instant, backlog: Backlog, waker: &Waker) -> io::Result<()> {
        match self.idle {
            _ if backlog.in_flight => self.idle = None,
            Some((since, unsent)) if unsent == backlog.unsent => {
                if now.saturating_duration_since(since) >= STALLED {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("the kernel holds {unsent} bytes of TLS records it does not send"),
                    ));
                }
            }
            _ => self.idle = Some((now, backlog.unsent)),
        }
        let since = *self.since.get_or_insert(now);
        if now.saturating_duration_since(since) >= YIELDING
            && self.sleeper.wake_after(self.pause, waker)
        {
            self.pause = (self.pause * 2).min(LONGEST_PAUSE);
        } else {
            // Yield: the task runs again after the others that are ready.
            waker.wake_by_ref();
        }
        Ok(())
    }
}

/// Wakes a task from a thread that sleeps first: at most one thread at a
/// time, which wakes the last waker it was given.
#[derive(Debug, Default)]
struct Sleeper {
    state: Mutex<Sleep>,
}

#[derive(Debug, Default)]
struct Sleep {
    waker: Option<Waker>,
    /// A thread is asleep and will take `waker`.
    asleep: bool,
}

impl Sleeper {
    fn lock(&self) -> MutexGuard<'_, Sleep> {
        // The state stays consistent whatever a panicking holder did.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Has `waker` woken after `pause`, or when the thread already asleep
    /// wakes. `false` when no thread could be started.
    fn wake_after(self: &Arc<Self>, pause: Duration, waker: &Waker) -> bool {
        let mut sleep = self.lock();
        match &mut sleep.waker {
            Some(current) => current.clone_from(waker),
            slot => *slot = Some(waker.clone()),
        }
        if sleep.asleep {
            return true;
        }
        let sleeper = Arc::clone(self);
        let started = thread::Builder::new()
            .name("browntls-ktls-drain".into())
            .spawn(move || {
                thread::sleep(pause);
                let waker = {
                    let mut sleep = sleeper.lock();
                    sleep.asleep = false;
                    sleep.waker.take()
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
            });
        sleep.asleep = started.is_ok();
        if !sleep.asleep {
            sleep.waker = None;
        }
        sleep.asleep
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    use super::*;

    #[derive(Default)]
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counter() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count::default());
        (Arc::clone(&count), Waker::from(count))
    }

    fn woken(count: &Count) -> usize {
        count.0.load(Ordering::SeqCst)
    }

    fn wait_for(count: &Count, wakes: usize) {
        let start = Instant::now();
        while woken(count) < wakes {
            assert!(start.elapsed() < Duration::from_secs(20), "never woken");
            thread::sleep(Duration::from_millis(1));
        }
    }

    const HELD: Backlog = Backlog {
        unsent: 100,
        in_flight: true,
    };

    /// The decision before the FIN, for each thing the kernel can report.
    #[test]
    fn the_fin_waits_while_the_kernel_holds_records() {
        let (count, waker) = counter();
        let mut drain = Drain::new();
        let now = Instant::now();
        let free = || Poll::Ready(Ok(Room::Free));
        let no_counters = || Err(io::ErrorKind::Unsupported.into());

        // Everything is with TCP: no need to ask for room.
        let sent = Backlog {
            unsent: 0,
            in_flight: true,
        };
        let step = drain.step(now, Ok(sent), &waker, || panic!("asked for room"));
        assert!(matches!(step, Poll::Ready(Ok(Outcome::Sent))));

        // Records held and no room: the socket's wait, which wakes the
        // task itself.
        let step = drain.step(now, Ok(HELD), &waker, || Poll::Pending);
        assert!(step.is_pending());
        assert_eq!(woken(&count), 0);

        // Records held although the socket has room: the kernel has yet to
        // send them, so no FIN, and another look is arranged.
        let step = drain.step(now, Ok(HELD), &waker, free);
        assert!(step.is_pending(), "a FIN ahead of the kernel's records");
        assert_eq!(woken(&count), 1);

        // The connection ended with records held.
        let step = drain.step(now, Ok(HELD), &waker, || Poll::Ready(Ok(Room::Ended)));
        assert!(matches!(step, Poll::Ready(Ok(Outcome::Lost))));

        // An error from the socket's wait is passed on.
        let step = drain.step(now, Ok(HELD), &waker, || {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        });
        assert!(
            matches!(step, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::ConnectionReset)
        );

        // No counters: room is waited for, and is enough.
        let step = drain.step(now, no_counters(), &waker, || Poll::Pending);
        assert!(step.is_pending());
        let step = drain.step(now, no_counters(), &waker, free);
        assert!(matches!(step, Poll::Ready(Ok(Outcome::Sent))));
        let step = drain.step(now, no_counters(), &waker, || Poll::Ready(Ok(Room::Ended)));
        assert!(matches!(step, Poll::Ready(Ok(Outcome::Sent))));
        assert_eq!(woken(&count), 1);
    }

    #[test]
    fn yields_first_then_sleeps_in_longer_pauses() {
        let (count, waker) = counter();
        let mut drain = Drain::new();
        let start = Instant::now();

        // Within the first millisecond: woken before `wait` returns.
        drain.wait(start, HELD, &waker).unwrap();
        assert_eq!(woken(&count), 1);
        drain
            .wait(start + YIELDING - Duration::from_nanos(1), HELD, &waker)
            .unwrap();
        assert_eq!(woken(&count), 2);

        // Afterwards a thread wakes it, later, and the pauses grow.
        drain.wait(start + YIELDING, HELD, &waker).unwrap();
        assert_eq!(drain.pause, FIRST_PAUSE * 2);
        wait_for(&count, 3);
        for _ in 0..8 {
            let before = woken(&count);
            drain.wait(start + YIELDING, HELD, &waker).unwrap();
            wait_for(&count, before + 1);
        }
        assert_eq!(drain.pause, LONGEST_PAUSE);

        // A socket without room starts the next stretch from the top.
        drain.reset();
        let before = woken(&count);
        drain.wait(start + STALLED * 2, HELD, &waker).unwrap();
        assert_eq!(woken(&count), before + 1);
        assert_eq!(drain.pause, FIRST_PAUSE);
    }

    #[test]
    fn one_thread_sleeps_and_wakes_the_last_waker() {
        let sleeper = Arc::new(Sleeper::default());
        let (first, first_waker) = counter();
        let (second, second_waker) = counter();
        assert!(sleeper.wake_after(Duration::from_millis(300), &first_waker));
        // The task moved on to another waker while the thread sleeps: no
        // second thread, and the new waker is the one woken.
        assert!(sleeper.wake_after(Duration::from_secs(3600), &second_waker));
        wait_for(&second, 1);
        assert_eq!(woken(&first), 0);
        assert!(!sleeper.lock().asleep);
        assert!(sleeper.lock().waker.is_none());
        // And it can sleep again.
        assert!(sleeper.wake_after(Duration::from_millis(1), &first_waker));
        wait_for(&first, 1);
    }

    #[test]
    fn records_held_with_nothing_in_the_way_end_the_wait() {
        let (_count, waker) = counter();
        let mut drain = Drain::new();
        let start = Instant::now();
        let idle = Backlog {
            unsent: 100,
            in_flight: false,
        };
        let short = STALLED - Duration::from_millis(1);

        drain.wait(start, idle, &waker).unwrap();
        drain.wait(start + short, idle, &waker).unwrap();
        // Progress starts the clock again.
        let less = Backlog { unsent: 60, ..idle };
        drain.wait(start + STALLED, less, &waker).unwrap();
        drain.wait(start + STALLED + short, less, &waker).unwrap();
        // So do bytes in flight: their acknowledgement makes the kernel
        // send.
        let flying = Backlog {
            in_flight: true,
            ..less
        };
        drain.wait(start + STALLED * 2, flying, &waker).unwrap();
        drain.wait(start + STALLED * 4, flying, &waker).unwrap();
        drain.wait(start + STALLED * 4, less, &waker).unwrap();
        drain
            .wait(start + STALLED * 4 + short, less, &waker)
            .unwrap();
        let err = drain.wait(start + STALLED * 5, less, &waker).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("60 bytes"), "{err}");
    }
}
