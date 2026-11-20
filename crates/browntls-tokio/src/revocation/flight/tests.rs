//! The fetch's lock and the wake-ups of the lookups that wait for it.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use super::{Begin, Engine, Flight, Key, Limits, Lookup, Outcome, Starter};

fn engine() -> Arc<Engine> {
    Arc::new(Engine::new(Limits {
        max_entries: 8,
        max_bytes: 1 << 16,
        ttl: Duration::ZERO,
        unavailable_ttl: Duration::ZERO,
        max_flights: 8,
    }))
}

fn wait(begin: Begin) -> Lookup {
    match begin {
        Begin::Wait(lookup) => lookup,
        Begin::Known(_) => panic!("nothing is remembered"),
        Begin::Busy => panic!("one flight runs at most"),
    }
}

/// Pending at its first poll, then panics.
struct PanicsAtSecondPoll {
    polls: usize,
}

impl Future for PanicsAtSecondPoll {
    type Output = Outcome;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Outcome> {
        self.polls += 1;
        assert!(self.polls < 2, "the application's fetch panics");
        Poll::Pending
    }
}

/// How the fetch's lock stood each time a lookup was woken.
#[derive(Default)]
struct Observed {
    held: AtomicUsize,
    free_or_poisoned: AtomicUsize,
}

/// A waiting lookup's waker that looks at the fetch's lock when woken, as
/// the lookup would if another thread polled it right then.
struct LookingWaker {
    flight: Mutex<Option<Arc<Flight>>>,
    observed: Arc<Observed>,
}

impl Wake for LookingWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let flight = self.flight.lock().unwrap().clone();
        let Some(flight) = flight else {
            return;
        };
        let counter = match flight.task.try_lock() {
            Err(TryLockError::WouldBlock) => &self.observed.held,
            Ok(_) | Err(TryLockError::Poisoned(_)) => &self.observed.free_or_poisoned,
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_panicking_fetch_lets_go_of_its_lock_before_it_wakes_the_waiting_lookups() {
    let engine = engine();
    let key = Key::new(&[7; 32], b"request");
    let starter = || -> Starter { Box::new(|| Box::pin(PanicsAtSecondPoll { polls: 0 })) };
    let mut waiting = wait(engine.begin(key.clone(), starter));
    let mut driving = wait(engine.begin(key, starter));
    assert!(Arc::ptr_eq(&waiting.flight, &driving.flight));

    let observed = Arc::new(Observed::default());
    let looking = Arc::new(LookingWaker {
        flight: Mutex::new(None),
        observed: observed.clone(),
    });
    let waker = Waker::from(looking.clone());
    // The first lookup starts the fetch, which is pending, and waits.
    assert!(waiting.poll(&mut Context::from_waker(&waker)).is_pending());
    *looking.flight.lock().unwrap() = Some(waiting.flight.clone());

    // The second one drives the fetch on, and the fetch panics.
    let noop = Waker::noop();
    let poll = panic::catch_unwind(AssertUnwindSafe(|| {
        driving.poll(&mut Context::from_waker(noop))
    }));
    assert!(
        poll.is_err(),
        "the fetch's panic reaches the driving lookup"
    );

    assert_eq!(
        observed.held.load(Ordering::SeqCst),
        0,
        "a waiting lookup was woken while the fetch's lock was still held",
    );
    assert!(observed.free_or_poisoned.load(Ordering::SeqCst) > 0);
    // Polled once more, the waiting lookup finds the flight failed.
    assert_eq!(
        waiting.poll(&mut Context::from_waker(noop)),
        Poll::Ready(None)
    );
}

/// Counts its wakes.
#[derive(Default)]
struct Counting(AtomicUsize);

impl Wake for Counting {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A lookup dropped while others wait (a task cancelled after it drove the
/// fetch, maybe while another found the lock held) wakes them: one of them
/// drives the fetch from now on.
#[test]
fn a_dropped_lookup_wakes_the_ones_that_stay() {
    let engine = engine();
    let key = Key::new(&[9; 32], b"request");
    let starter = || -> Starter { Box::new(|| Box::pin(PanicsAtSecondPoll { polls: 0 })) };
    let mut staying = wait(engine.begin(key.clone(), starter));
    let leaving = wait(engine.begin(key, starter));

    let counting = Arc::new(Counting::default());
    let waker = Waker::from(counting.clone());
    assert!(staying.poll(&mut Context::from_waker(&waker)).is_pending());
    assert_eq!(counting.0.load(Ordering::SeqCst), 0);
    drop(leaving);
    assert_eq!(counting.0.load(Ordering::SeqCst), 1);
}
