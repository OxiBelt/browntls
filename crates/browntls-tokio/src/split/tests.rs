//! The halves' turn-taking, with a stand-in stream whose reads stay in
//! their poll for as long as a test wants.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Barrier, Mutex, TryLockError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{ReuniteError, Shared, Side, split};

/// A point in `Shared`'s locking path.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Point {
    /// Before the half leaves its waker.
    BeforeWaiting,
    /// After it left the waker, before it looks at the stream again.
    BeforeSecondLook,
    /// A poisoned acquisition holds the stream guard before releasing it.
    PoisonedAcquired,
}

/// Something to do at a point.
type Action = (Point, Box<dyn FnOnce()>);

thread_local! {
    /// What this thread's next `poll_lock` does when it reaches a point.
    static AT: RefCell<Option<Action>> = const { RefCell::new(None) };
}

/// Called by `poll_lock` on its way through `point`.
pub(super) fn reached(point: Point) {
    let action = AT.with(|at| {
        let mut at = at.borrow_mut();
        match &*at {
            Some((wanted, _)) if *wanted == point => at.take(),
            _ => None,
        }
    });
    if let Some((_, action)) = action {
        action();
    }
}

/// What a read of [`Slow`] does once it is let go.
enum Then {
    Return,
    Panic,
}

/// A stream whose reads announce themselves and then wait, inside the poll,
/// to be told how to end; writes complete at once.
#[derive(Debug)]
struct Slow {
    entered: Sender<()>,
    then: Receiver<Then>,
    writes: usize,
}

/// A [`Slow`] stream, the channel its reads announce themselves on and the
/// channel that lets them go.
fn slow() -> (Slow, Receiver<()>, Sender<Then>) {
    let (entered, entered_rx) = channel();
    let (then_tx, then) = channel();
    let stream = Slow {
        entered,
        then,
        writes: 0,
    };
    (stream, entered_rx, then_tx)
}

impl AsyncRead for Slow {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.entered.send(()).unwrap();
        match self.then.recv().unwrap() {
            Then::Return => {
                buf.put_slice(b"r");
                Poll::Ready(Ok(()))
            }
            Then::Panic => panic!("the read panics, as the test asked"),
        }
    }
}

impl AsyncWrite for Slow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Counts its wakeups.
#[derive(Default)]
struct Wakeups(AtomicUsize);

impl Wake for Wakeups {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Wakeups {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// On each wakeup, notes whether the stream of `shared` was free to take.
struct Probe {
    shared: Arc<Shared<Slow>>,
    free: Mutex<Vec<bool>>,
}

impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        let free = !matches!(self.shared.stream.try_lock(), Err(TryLockError::WouldBlock));
        self.free.lock().unwrap().push(free);
    }
}

/// Reads one byte through `half` with a waker nobody looks at.
fn read_once<R: AsyncRead + Unpin>(half: &mut R) -> Poll<io::Result<()>> {
    let mut byte = [0u8];
    let mut buf = ReadBuf::new(&mut byte);
    Pin::new(half).poll_read(&mut Context::from_waker(Waker::noop()), &mut buf)
}

#[test]
fn a_half_does_not_wait_in_its_poll_for_the_other_halfs_poll() {
    let (stream, entered, then) = slow();
    let (mut read, mut write) = split(stream);
    let reader = thread::spawn(move || {
        let poll = read_once(&mut read);
        (read, poll)
    });
    // The read half's poll now has the stream, on the other thread.
    entered.recv().unwrap();

    let wakeups = Arc::new(Wakeups::default());
    let waker = Waker::from(wakeups.clone());
    let mut cx = Context::from_waker(&waker);
    // The write half returns instead of waiting for that poll (if it
    // waited, this test would hang here: the read is let go only below).
    assert!(Pin::new(&mut write).poll_write(&mut cx, b"w").is_pending());
    assert!(Pin::new(&mut write).poll_flush(&mut cx).is_pending());
    assert_eq!(wakeups.count(), 0);

    // The read's poll ends: the write half is woken, once, and has its turn.
    then.send(Then::Return).unwrap();
    let (read, poll) = reader.join().unwrap();
    assert!(matches!(poll, Poll::Ready(Ok(()))));
    assert_eq!(wakeups.count(), 1);
    assert!(matches!(
        Pin::new(&mut write).poll_write(&mut cx, b"w"),
        Poll::Ready(Ok(1))
    ));

    // Nobody waited during that poll: nothing more is woken.
    assert_eq!(wakeups.count(), 1);
    let stream = read.reunite(write).unwrap();
    assert_eq!(stream.writes, 1);
}

#[test]
fn a_panic_in_one_halfs_poll_fails_the_other_half_instead_of_hanging_it() {
    let (stream, entered, then) = slow();
    let (mut read, mut write) = split(stream);
    let reader = thread::spawn(move || {
        let _ = read_once(&mut read);
    });
    entered.recv().unwrap();

    // The write half waits for its turn while the read's poll runs.
    let wakeups = Arc::new(Wakeups::default());
    let waker = Waker::from(wakeups.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut write).poll_write(&mut cx, b"w").is_pending());

    then.send(Then::Panic).unwrap();
    assert!(reader.join().is_err());
    // The panicking poll still woke the waiting half, which now fails, as
    // does every later operation: the stream's state is unknown.
    assert_eq!(wakeups.count(), 1);
    for _ in 0..2 {
        let Poll::Ready(Err(err)) = Pin::new(&mut write).poll_write(&mut cx, b"w") else {
            panic!("a write through a poisoned stream must fail");
        };
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
    assert!(matches!(
        Pin::new(&mut write).poll_shutdown(&mut cx),
        Poll::Ready(Err(_))
    ));
}

#[test]
fn a_poisoned_acquisition_wakes_either_waiting_half() {
    for (holder_side, waiting_side) in [(Side::Read, Side::Write), (Side::Write, Side::Read)] {
        let (stream, entered, release_panic) = slow();
        let (mut read, mut write) = split(stream);
        release_panic.send(Then::Panic).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| read_once(&mut read))).is_err());
        entered.recv().unwrap();

        let shared = read.shared.clone();
        let holder_shared = shared.clone();
        let (acquired, acquired_rx) = channel();
        let (release, release_rx) = channel();
        let holder = thread::spawn(move || {
            AT.with(|at| {
                *at.borrow_mut() = Some((
                    Point::PoisonedAcquired,
                    Box::new(move || {
                        acquired.send(()).unwrap();
                        release_rx.recv().unwrap();
                    }),
                ));
            });
            let poll =
                holder_shared.poll_lock(holder_side, &mut Context::from_waker(Waker::noop()));
            assert!(matches!(poll, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Other));
            assert!(AT.with(|at| at.borrow().is_none()));
        });
        acquired_rx.recv().unwrap();

        let probe = Arc::new(Probe {
            shared: shared.clone(),
            free: Mutex::default(),
        });
        let waker = Waker::from(probe.clone());
        let poll = shared.poll_lock(waiting_side, &mut Context::from_waker(&waker));
        release.send(()).unwrap();
        holder.join().unwrap();
        assert!(poll.is_pending(), "the competing half did not wait");
        assert_eq!(*probe.free.lock().unwrap(), [true]);

        let poll = shared.poll_lock(waiting_side, &mut Context::from_waker(&waker));
        assert!(matches!(poll, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Other));
        assert!(
            matches!(read_once(&mut read), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Other)
        );
        assert!(matches!(
            Pin::new(&mut write).poll_write(&mut Context::from_waker(&waker), b"w"),
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Other
        ));
    }
}

#[test]
fn the_stream_is_free_by_the_time_the_waiting_half_is_woken() {
    // A task woken while the stream is still taken would find it so, wait
    // again and never be woken: the poll that had the stream is over.
    for then in [Then::Return, Then::Panic] {
        let (stream, entered, release) = slow();
        let (mut read, mut write) = split(stream);
        let reader = thread::spawn(move || {
            let _ = read_once(&mut read);
        });
        entered.recv().unwrap();

        let probe = Arc::new(Probe {
            shared: write.shared.clone(),
            free: Mutex::default(),
        });
        let waker = Waker::from(probe.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut write).poll_write(&mut cx, b"w").is_pending());

        release.send(then).unwrap();
        let _ = reader.join();
        assert_eq!(*probe.free.lock().unwrap(), [true]);
    }
}

/// The other half's poll ends while a half is at `point` in `poll_lock`:
/// what the half's poll returns, and how often it was woken.
fn other_poll_ends_at(point: Point) -> (Poll<io::Result<usize>>, usize) {
    let (stream, entered, release) = slow();
    let (mut read, mut write) = split(stream);
    let reader = thread::spawn(move || {
        let _ = read_once(&mut read);
        read
    });
    entered.recv().unwrap();

    // The write half finds the stream taken; then the read's poll ends,
    // completely (the thread is joined), before the write half goes on.
    AT.with(|at| {
        let end_the_read: Box<dyn FnOnce()> = Box::new(move || {
            release.send(Then::Return).unwrap();
            drop(reader.join().unwrap());
        });
        *at.borrow_mut() = Some((point, end_the_read));
    });
    let wakeups = Arc::new(Wakeups::default());
    let waker = Waker::from(wakeups.clone());
    let poll = Pin::new(&mut write).poll_write(&mut Context::from_waker(&waker), b"w");
    assert!(AT.with(|at| at.borrow().is_none()), "{point:?} not reached");
    // Whichever way it went, the half left no waker behind.
    assert!(write.shared.take_waiting(Side::Write).is_none());
    (poll, wakeups.count())
}

#[test]
fn a_poll_that_ends_before_the_waker_is_left_is_seen_by_the_second_look() {
    // Nobody will wake this half: the other poll looked for a waker and
    // found none. It must not wait.
    let (poll, wakeups) = other_poll_ends_at(Point::BeforeWaiting);
    assert!(matches!(poll, Poll::Ready(Ok(1))));
    assert_eq!(wakeups, 0);
}

#[test]
fn a_poll_that_ends_after_the_waker_is_left_wakes_it_and_frees_the_stream() {
    let (poll, wakeups) = other_poll_ends_at(Point::BeforeSecondLook);
    assert!(matches!(poll, Poll::Ready(Ok(1))));
    assert_eq!(wakeups, 1);
}

#[test]
fn a_half_left_waiting_is_always_woken() {
    // One short poll of the read half and one poll of the write half start
    // together, time and again, a little apart in either direction. When
    // the write half is left waiting, the end of the read's poll wakes it.
    const ROUNDS: usize = 20_000;
    let (stream, entered, release) = slow();
    let (mut read, mut write) = split(stream);
    let start = Arc::new(Barrier::new(2));
    let (go, going) = channel::<usize>();
    let (done, finished) = channel();
    let reader = {
        let start = start.clone();
        thread::spawn(move || {
            for delay in going {
                start.wait();
                for _ in 0..delay {
                    std::hint::spin_loop();
                }
                // The write half's poll may have the stream: look again.
                let poll = loop {
                    match read_once(&mut read) {
                        Poll::Ready(result) => break result,
                        Poll::Pending => std::hint::spin_loop(),
                    }
                };
                poll.unwrap();
                done.send(()).unwrap();
            }
        })
    };

    let mut waited = 0;
    for round in 0..ROUNDS {
        // The read returns as soon as it has announced itself.
        release.send(Then::Return).unwrap();
        let wakeups = Arc::new(Wakeups::default());
        let waker = Waker::from(wakeups.clone());
        go.send(round % 64).unwrap();
        start.wait();
        for _ in 0..(round / 64) % 64 {
            std::hint::spin_loop();
        }
        let poll = Pin::new(&mut write).poll_write(&mut Context::from_waker(&waker), b"w");
        finished.recv().unwrap();
        entered.recv().unwrap();
        match poll {
            Poll::Ready(result) => assert_eq!(result.unwrap(), 1),
            Poll::Pending => {
                waited += 1;
                assert_eq!(
                    wakeups.count(),
                    1,
                    "round {round}: left waiting, never woken"
                );
            }
        }
    }
    drop(go);
    reader.join().unwrap();
    // How often the polls met depends on the machine (on one processor,
    // hardly ever), so that is not asserted: the two tests above are what
    // holds on every machine, and this one adds the orders they do not
    // stage.
    let _ = waited;
}

#[test]
fn halves_reunite_only_with_their_own_other_half() {
    let (first, _entered, _then) = slow();
    let (second, _entered2, _then2) = slow();
    let (read, write) = split(first);
    let (read2, write2) = split(second);
    assert!(read.is_pair_of(&write) && write.is_pair_of(&read));
    assert!(!read.is_pair_of(&write2) && !write.is_pair_of(&read2));

    let ReuniteError(read, write2) = read.reunite(write2).unwrap_err();
    let err = write.reunite(read2).unwrap_err();
    assert_eq!(
        err.to_string(),
        "the halves are not the two halves of one TLS stream"
    );
    assert!(format!("{err:?}").starts_with("ReuniteError"));
    let ReuniteError(read2, write) = err;

    // The halves that came back are the ones that went in.
    assert!(read.reunite(write).is_ok());
    assert!(write2.reunite(read2).is_ok());
}

#[test]
fn a_dropped_half_leaves_the_stream_to_the_other() {
    let (stream, _entered, _then) = slow();
    let (read, mut write) = split(stream);
    drop(read);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut write).poll_write(&mut cx, b"w"),
        Poll::Ready(Ok(1))
    ));
    assert!(write.is_write_vectored());
    assert_eq!(format!("{write:?}"), "WriteHalf { .. }");

    let (stream, entered, then) = slow();
    let (mut read, write) = split(stream);
    drop(write);
    then.send(Then::Return).unwrap();
    assert!(matches!(read_once(&mut read), Poll::Ready(Ok(()))));
    entered.recv().unwrap();
    assert_eq!(format!("{read:?}"), "ReadHalf { .. }");
}
