//! The pauses of `shutdown` while the kernel gives its last records to TCP.
//!
//! The kernel sends the records it holds from a work item, scheduled when
//! the socket gets room; nothing wakes a task when that work is done. So
//! once the socket has room, `shutdown` looks at the kernel's counters
//! again after a pause. A few times it only yields: the work was scheduled
//! before the task was woken, and may be done by the next look. Where it
//! is not, more yields were not seen to help (see [`YIELDS`]), so after
//! that the task is woken by a clock thread, one for the whole process,
//! which lives only while streams wait: first after a quarter of a
//! millisecond, then after longer pauses. The pauses do not use a timer of
//! the runtime, which may have none.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use crate::ledger::Backlog;

/// How many looks in a row, once the socket was found with room, end in
/// a yield only.
///
/// Observed on one Linux 7.0 host, in the ten of sixty runs of a test that
/// came to this wait: one or two looks were enough in six; in the other
/// four the same records stayed held through 315 to 393 looks within a
/// millisecond of yielding and were gone after the first pause. A likely
/// reading, not shown: the kernel's work item is queued on the task's own
/// processor and may not run until the thread blocks or the scheduler's
/// next tick. Four leaves a margin over the two that were seen to be
/// enough.
const YIELDS: u32 = 4;

/// The first pause after that; each later one is twice as long, up to
/// [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_micros(250);

const LONGEST_PAUSE: Duration = Duration::from_millis(8);

/// How long the kernel may hold the same records, with room to send them
/// and nothing in flight whose acknowledgement would make it send, before
/// the wait is given up. The kernel's own retry, when it finds its
/// transmit lock taken, comes after 10 ms.
const STALLED: Duration = Duration::from_secs(5);

/// How long a wait may go unobserved (its future dropped, or its task not
/// run) before what it saw earlier no longer counts towards [`STALLED`].
const UNWATCHED: Duration = Duration::from_secs(1);

/// What the kernel reports about sending on the socket, once it no longer
/// reports it full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Room {
    /// Room to send, or a socket on which the wait for room cannot be
    /// left to the runtime: either way the kernel's counters are looked
    /// at again after a pause.
    Free,
    /// The connection is over: nothing more will be sent.
    Ended,
}

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
    /// How many looks of this stretch (the socket having room) ended in
    /// a yield.
    yields: u32,
    /// Since when the kernel has held this many bytes with nothing in
    /// flight.
    idle: Option<(Instant, u64)>,
    /// When the kernel was last found holding records with room to send.
    looked: Option<Instant>,
    /// The next pause.
    pause: Duration,
    sleeper: Arc<Sleeper>,
}

impl Drain {
    pub(crate) fn new() -> Self {
        Self {
            yields: 0,
            idle: None,
            looked: None,
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
    /// another look after a pause). Where the stream has no count
    /// (`backlog` fails with `Unsupported`), room is all there is to wait
    /// for; any other failure to read the counters is passed on, since the
    /// wait for room alone is known to let a FIN through too early.
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
        let backlog = match backlog {
            Ok(backlog) => backlog,
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                return Poll::Ready(Ok(Outcome::Sent));
            }
            Err(err) => return Poll::Ready(Err(err)),
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
        self.yields = 0;
        self.idle = None;
        self.looked = None;
        self.pause = FIRST_PAUSE;
    }

    /// The socket has room and the kernel still holds `backlog`: has
    /// `waker` woken for the next look.
    ///
    /// Fails when the kernel has held the same records for [`STALLED`]
    /// although nothing kept it from sending them.
    fn wait(&mut self, now: Instant, backlog: Backlog, waker: &Waker) -> io::Result<()> {
        // A wait nobody watched for a while starts over: the time in
        // between says nothing about the kernel.
        if self
            .looked
            .is_some_and(|looked| now.saturating_duration_since(looked) >= UNWATCHED)
        {
            self.reset();
        }
        self.looked = Some(now);
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
        if self.yields >= YIELDS && self.sleeper.wake_after(&CLOCK, self.pause, waker) {
            self.pause = (self.pause * 2).min(LONGEST_PAUSE);
        } else {
            // Yield: the task runs again after the others that are ready.
            // Also when the clock has no thread (none could be started):
            // the wait then costs processor time instead of failing.
            self.yields = self.yields.saturating_add(1);
            waker.wake_by_ref();
        }
        Ok(())
    }
}

/// One task's place with the [`Clock`]: the waker to wake, and whether a
/// wake is already due.
#[derive(Debug, Default)]
struct Sleeper {
    state: Mutex<Sleep>,
}

#[derive(Debug, Default)]
struct Sleep {
    waker: Option<Waker>,
    /// The clock holds an alarm that will take `waker`.
    asleep: bool,
}

impl Sleeper {
    fn lock(&self) -> MutexGuard<'_, Sleep> {
        // The state stays consistent whatever a panicking holder did.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Has `waker` woken after `pause`, or when the alarm already set goes
    /// off. `false` when the clock's thread could not be started.
    fn wake_after(self: &Arc<Self>, clock: &'static Clock, pause: Duration, waker: &Waker) -> bool {
        let mut sleep = self.lock();
        if sleep.asleep {
            match &mut sleep.waker {
                Some(current) => current.clone_from(waker),
                slot => *slot = Some(waker.clone()),
            }
            return true;
        }
        if !clock.set(Instant::now() + pause, Arc::clone(self)) {
            return false;
        }
        sleep.waker = Some(waker.clone());
        sleep.asleep = true;
        true
    }

    /// The alarm went off.
    fn wake(&self) {
        let waker = {
            let mut sleep = self.lock();
            sleep.asleep = false;
            sleep.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// How long the clock's thread stays when it has no alarm left.
const LINGER: Duration = Duration::from_secs(5);

/// The alarms of every stream in the process, kept by one thread, which
/// is started with the first alarm and ends [`LINGER`] after the last.
#[derive(Debug)]
struct Clock {
    state: Mutex<Alarms>,
    changed: Condvar,
}

static CLOCK: Clock = Clock {
    state: Mutex::new(Alarms {
        due: BinaryHeap::new(),
        set: 0,
        running: false,
    }),
    changed: Condvar::new(),
};

#[derive(Debug)]
struct Alarms {
    /// Earliest first.
    due: BinaryHeap<Alarm>,
    /// How many alarms were ever set: tells alarms of one instant apart.
    set: u64,
    /// The thread is alive and will see what is pushed.
    running: bool,
}

#[derive(Debug)]
struct Alarm {
    at: Instant,
    order: u64,
    sleeper: Arc<Sleeper>,
}

impl PartialEq for Alarm {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Alarm {}

impl PartialOrd for Alarm {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Alarm {
    /// Reversed, so that the heap's greatest is the earliest.
    fn cmp(&self, other: &Self) -> Ordering {
        (other.at, other.order).cmp(&(self.at, self.order))
    }
}

impl Clock {
    fn lock(&self) -> MutexGuard<'_, Alarms> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets an alarm that wakes `sleeper` at `at`. `false` when there is
    /// no thread to keep it and none could be started.
    fn set(&'static self, at: Instant, sleeper: Arc<Sleeper>) -> bool {
        let mut alarms = self.lock();
        if !alarms.running {
            let started = thread::Builder::new()
                .name("browntls-ktls-clock".into())
                .spawn(move || self.run());
            if started.is_err() {
                return false;
            }
            alarms.running = true;
        }
        alarms.set += 1;
        let order = alarms.set;
        alarms.due.push(Alarm { at, order, sleeper });
        drop(alarms);
        self.changed.notify_one();
        true
    }

    /// The thread: wakes each sleeper when its alarm is due.
    fn run(&self) {
        let mut alarms = self.lock();
        loop {
            let now = Instant::now();
            let wait = match alarms.due.peek() {
                Some(next) if next.at <= now => {
                    let alarm = alarms.due.pop();
                    drop(alarms);
                    if let Some(alarm) = alarm {
                        // A waker is the executor's code. Should one
                        // panic, the clock must go on for the others: the
                        // panic (already reported by the panic hook) ends
                        // here and not the thread.
                        let wake = AssertUnwindSafe(|| alarm.sleeper.wake());
                        let _ = panic::catch_unwind(wake);
                    }
                    alarms = self.lock();
                    continue;
                }
                Some(next) => next.at - now,
                None => LINGER,
            };
            let (guard, result) = self
                .changed
                .wait_timeout(alarms, wait)
                .unwrap_or_else(PoisonError::into_inner);
            alarms = guard;
            if result.timed_out() && alarms.due.is_empty() {
                // Under the lock: an alarm set from now on starts a thread.
                alarms.running = false;
                return;
            }
        }
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

        // Counters that fail or do not fit are not taken for none: room
        // alone would let the FIN through.
        let step = drain.step(now, Err(io::Error::other("mismatch")), &waker, free);
        assert!(matches!(step, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Other));
    }

    #[test]
    fn yields_first_then_sleeps_in_longer_pauses() {
        let (count, waker) = counter();
        let mut drain = Drain::new();
        let start = Instant::now();

        // The first looks: woken before `wait` returns, however long the
        // looks took.
        let yields = YIELDS as usize;
        for look in 1..=yields {
            let now = start + Duration::from_millis(look as u64 * 10);
            drain.wait(now, HELD, &waker).unwrap();
            assert_eq!(woken(&count), look);
            assert_eq!(drain.pause, FIRST_PAUSE);
        }

        // Afterwards the clock wakes it, later, and the pauses grow.
        drain.wait(start, HELD, &waker).unwrap();
        assert_eq!(drain.pause, FIRST_PAUSE * 2);
        wait_for(&count, yields + 1);
        for _ in 0..8 {
            let before = woken(&count);
            drain.wait(start, HELD, &waker).unwrap();
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
    fn the_clock_wakes_the_last_waker_of_each_sleeper() {
        let (first, first_waker) = counter();
        let (second, second_waker) = counter();
        let (other, other_waker) = counter();
        let sleeper = Arc::new(Sleeper::default());
        let late = Arc::new(Sleeper::default());
        let pause = Duration::from_millis(50);

        // A later alarm set first does not hold up an earlier one.
        let start = Instant::now();
        assert!(late.wake_after(&CLOCK, pause * 20, &other_waker));
        assert!(sleeper.wake_after(&CLOCK, pause, &first_waker));
        // The task moved on to another waker before the alarm: the alarm
        // stays as it is, and the new waker is the one woken.
        assert!(sleeper.wake_after(&CLOCK, pause, &second_waker));
        // Unless this thread was held up past the first alarm, which then
        // woke the first waker as it should.
        let in_time = start.elapsed() < pause;
        wait_for(&second, 1);
        if in_time {
            assert_eq!(woken(&first), 0);
        }
        assert!(!sleeper.lock().asleep);
        assert!(sleeper.lock().waker.is_none());
        if start.elapsed() < pause * 20 {
            assert_eq!(woken(&other), 0, "the later alarm went off early");
        }

        // It can sleep again, and the later alarm goes off in its turn.
        assert!(sleeper.wake_after(&CLOCK, Duration::from_millis(1), &first_waker));
        wait_for(&first, 1);
        wait_for(&other, 1);
        assert_eq!(woken(&second), 1);
        assert_eq!(woken(&other), 1);
    }

    /// A waker that panics does not stop the clock for everyone else.
    #[test]
    fn a_panicking_waker_leaves_the_clock_running() {
        struct Panics;
        impl Wake for Panics {
            fn wake(self: Arc<Self>) {
                panic!("a waker that panics (expected in this test)");
            }
        }
        let panics = Arc::new(Sleeper::default());
        assert!(panics.wake_after(
            &CLOCK,
            Duration::from_millis(1),
            &Waker::from(Arc::new(Panics))
        ));
        let (count, waker) = counter();
        let sleeper = Arc::new(Sleeper::default());
        assert!(sleeper.wake_after(&CLOCK, Duration::from_millis(20), &waker));
        wait_for(&count, 1);
        assert!(!panics.lock().asleep);
        // And for the same sleeper again.
        assert!(panics.wake_after(&CLOCK, Duration::from_millis(1), &waker));
        wait_for(&count, 2);
    }

    #[test]
    fn alarms_come_out_earliest_first() {
        let now = Instant::now();
        let alarm = |after: u64, order| Alarm {
            at: now + Duration::from_millis(after),
            order,
            sleeper: Arc::default(),
        };
        let mut due = BinaryHeap::new();
        due.extend([alarm(30, 1), alarm(10, 2), alarm(20, 3), alarm(10, 4)]);
        let order: Vec<u64> = std::iter::from_fn(|| due.pop()).map(|a| a.order).collect();
        assert_eq!(order, [2, 4, 3, 1]);
    }

    #[test]
    fn records_held_with_nothing_in_the_way_end_the_wait() {
        let (_count, waker) = counter();
        let mut drain = Drain::new();
        let idle = Backlog {
            unsent: 100,
            in_flight: false,
        };
        let less = Backlog { unsent: 60, ..idle };
        let flying = Backlog {
            in_flight: true,
            ..less
        };
        // Looks every 100 ms, as a watched wait makes them (more often).
        let step = Duration::from_millis(100);
        let looks = (STALLED.as_millis() / step.as_millis()) as u32;
        let mut now = Instant::now();
        let mut look = |drain: &mut Drain, backlog| {
            now += step;
            drain.wait(now, backlog, &waker)
        };

        // The same records for almost the whole time, then progress, which
        // starts the clock again.
        for _ in 0..looks {
            look(&mut drain, idle).unwrap();
        }
        for _ in 0..looks {
            look(&mut drain, less).unwrap();
        }
        // So do bytes in flight: their acknowledgement makes the kernel
        // send. However long that takes, it is not the kernel's stall.
        for _ in 0..looks * 3 {
            look(&mut drain, flying).unwrap();
        }
        for _ in 0..looks {
            look(&mut drain, less).unwrap();
        }
        let err = look(&mut drain, less).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("60 bytes"), "{err}");

        // A wait nobody watched (the future dropped, the task not run)
        // does not count the time in between.
        let mut drain = Drain::new();
        let start = Instant::now();
        drain.wait(start, idle, &waker).unwrap();
        drain.wait(start + STALLED * 3, idle, &waker).unwrap();
        drain
            .wait(start + STALLED * 3 + step, idle, &waker)
            .unwrap();
    }
}
