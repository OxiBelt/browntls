//! One lookup per certificate status request at a time, and a bounded
//! memory of the answers.
//!
//! A [`Flight`] is one run of the application's fetch. Every connection
//! that asks for the same request while it runs holds a [`Lookup`] on it,
//! and whichever of them is polled drives the fetch: no task is spawned.
//! When the last of them is dropped, so is the fetch.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use tokio::time::Instant;

/// What a lookup came to: the responder's DER body, or nothing.
pub(super) type Outcome = Option<Arc<[u8]>>;

/// One run of the application's fetch, bounded by the deadline.
pub(super) type Fetch = Pin<Box<dyn Future<Output = Outcome> + Send>>;

/// Starts a [`Fetch`]; called by the first poll of its flight.
pub(super) type Starter = Box<dyn FnOnce() -> Fetch + Send>;

/// What tells two requests apart: the issuer's key hash and the request.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct Key(Arc<[u8]>);

impl Key {
    pub(super) fn new(issuer_key_hash: &[u8; 32], request_der: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(issuer_key_hash.len() + request_der.len());
        bytes.extend_from_slice(issuer_key_hash);
        bytes.extend_from_slice(request_der);
        Self(bytes.into())
    }
}

/// The bounds of an [`Engine`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    /// How many answers are remembered.
    pub(super) max_entries: usize,
    /// How many bytes the remembered answers and their keys may take.
    pub(super) max_bytes: usize,
    /// How long a response is remembered; zero for not at all.
    pub(super) ttl: Duration,
    /// How long a failed lookup is remembered; zero for not at all.
    pub(super) unavailable_ttl: Duration,
    /// How many fetches may run at the same time.
    pub(super) max_flights: usize,
}

/// What the bookkeeping of one remembered answer is counted as, besides
/// its key and its bytes.
const ENTRY_OVERHEAD: usize = 64;

struct Entry {
    outcome: Outcome,
    expires: Instant,
    /// Where the entry stands in [`Cache::order`].
    seq: u64,
    cost: usize,
}

/// Remembered answers, oldest out first.
#[derive(Default)]
struct Cache {
    entries: HashMap<Key, Entry>,
    /// The keys by age.
    order: BTreeMap<u64, Key>,
    next_seq: u64,
    bytes: usize,
}

impl Cache {
    fn get(&mut self, key: &Key, now: Instant) -> Option<Outcome> {
        let entry = self.entries.get(key)?;
        if entry.expires <= now {
            self.remove(key);
            return None;
        }
        Some(entry.outcome.clone())
    }

    fn remove(&mut self, key: &Key) {
        if let Some(entry) = self.entries.remove(key) {
            self.order.remove(&entry.seq);
            self.bytes = self.bytes.saturating_sub(entry.cost);
        }
    }

    fn insert(&mut self, key: Key, outcome: Outcome, expires: Instant, limits: &Limits) {
        self.remove(&key);
        let len = outcome.as_ref().map_or(0, |der| der.len());
        let cost = ENTRY_OVERHEAD
            .saturating_add(key.0.len())
            .saturating_add(len);
        if limits.max_entries == 0 || cost > limits.max_bytes {
            return;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.bytes = self.bytes.saturating_add(cost);
        self.order.insert(seq, key.clone());
        self.entries.insert(
            key,
            Entry {
                outcome,
                expires,
                seq,
                cost,
            },
        );
        while self.entries.len() > limits.max_entries || self.bytes > limits.max_bytes {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(entry.cost);
            }
        }
    }
}

#[derive(Default)]
struct Shared {
    cache: Cache,
    /// The fetches some lookup still waits for.
    flights: HashMap<Key, Arc<Flight>>,
}

/// The cache and the running fetches of one fetcher.
pub(super) struct Engine {
    limits: Limits,
    shared: Mutex<Shared>,
}

/// How a lookup begins.
pub(super) enum Begin {
    /// The answer was remembered.
    Known(Outcome),
    /// A fetch runs, or is about to.
    Wait(Lookup),
    /// Too many fetches are running already.
    Busy,
}

/// Locks state that no foreign code runs under: a panic elsewhere left it
/// consistent.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Engine {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            limits,
            shared: Mutex::new(Shared::default()),
        }
    }

    /// The remembered answer for `key`, the fetch that already runs for
    /// it, or a new one that `starter` makes.
    pub(super) fn begin(self: &Arc<Self>, key: Key, starter: impl FnOnce() -> Starter) -> Begin {
        let mut shared = lock(&self.shared);
        if let Some(outcome) = shared.cache.get(&key, Instant::now()) {
            return Begin::Known(outcome);
        }
        let flight = match shared.flights.get(&key) {
            Some(flight) => flight.clone(),
            None => {
                if shared.flights.len() >= self.limits.max_flights {
                    return Begin::Busy;
                }
                let flight = Arc::new(Flight {
                    key: key.clone(),
                    waiters: Mutex::new(Waiters::default()),
                    task: Mutex::new(Task::Idle(starter())),
                });
                shared.flights.insert(key, flight.clone());
                flight
            }
        };
        // Joined under the engine's lock: the flight is not given up
        // between being found and being waited for.
        let id = lock(&flight.waiters).join();
        Begin::Wait(Lookup {
            engine: self.clone(),
            flight,
            id,
        })
    }

    /// Forgets the remembered answer for `key` if it is `response`: the
    /// connection it was given to refused it.
    pub(super) fn forget(&self, key: &Key, response: &Arc<[u8]>) {
        let mut shared = lock(&self.shared);
        let same = shared
            .cache
            .entries
            .get(key)
            .and_then(|entry| entry.outcome.as_ref())
            .is_some_and(|der| Arc::ptr_eq(der, response));
        if same {
            shared.cache.remove(key);
        }
    }

    /// The flight is over: later lookups start afresh, or find its answer.
    fn finish(&self, flight: &Arc<Flight>, outcome: &Outcome) {
        let mut shared = lock(&self.shared);
        shared.retire(flight);
        let ttl = match outcome {
            Some(_) => self.limits.ttl,
            None => self.limits.unavailable_ttl,
        };
        if !ttl.is_zero() {
            let expires = Instant::now() + ttl;
            shared
                .cache
                .insert(flight.key.clone(), outcome.clone(), expires, &self.limits);
        }
    }
}

impl Shared {
    fn retire(&mut self, flight: &Arc<Flight>) {
        if self
            .flights
            .get(&flight.key)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            self.flights.remove(&flight.key);
        }
    }
}

/// The lookups waiting for a flight, and whom to wake for each.
#[derive(Default)]
struct Waiters {
    next_id: u64,
    wakers: Vec<(u64, Option<Waker>)>,
}

impl Waiters {
    fn join(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.wakers.push((id, None));
        id
    }

    fn register(&mut self, id: u64, waker: &Waker) {
        if let Some((_, slot)) = self.wakers.iter_mut().find(|(waiter, _)| *waiter == id) {
            match slot {
                Some(current) if current.will_wake(waker) => {}
                _ => *slot = Some(waker.clone()),
            }
        }
    }
}

enum Task {
    /// No lookup was polled yet.
    Idle(Starter),
    Running(Fetch),
    Done(Outcome),
    /// Every lookup was dropped before the fetch ended, or starting it
    /// panicked.
    Abandoned,
}

struct Flight {
    key: Key,
    waiters: Mutex<Waiters>,
    /// Held by the lookup whose poll drives the fetch, and by nothing that
    /// waits: the others return `Pending` and are woken.
    task: Mutex<Task>,
}

impl Flight {
    /// Wakes every lookup. They stay registered: each wake of the fetch
    /// reaches all of them, as any one may be the next to be polled.
    fn wake_all(&self) {
        let wakers: Vec<Waker> = lock(&self.waiters)
            .wakers
            .iter()
            .filter_map(|(_, waker)| waker.clone())
            .collect();
        for waker in wakers {
            waker.wake();
        }
    }
}

impl Wake for Flight {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

/// One connection's wait for a flight. Dropping it leaves the flight, and
/// the last one to leave drops the fetch.
pub(super) struct Lookup {
    engine: Arc<Engine>,
    flight: Arc<Flight>,
    id: u64,
}

/// Ends the flight if the fetch panics: the lookups that wait for it are
/// woken and find it failed.
struct PanicGuard<'a> {
    lookup: &'a Lookup,
    armed: bool,
}

impl Drop for PanicGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            lock(&self.lookup.engine.shared).retire(&self.lookup.flight);
            self.lookup.flight.wake_all();
        }
    }
}

impl Lookup {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Outcome> {
        // Registered before the fetch is looked at: whoever holds it wakes
        // every lookup registered by the time it lets go.
        lock(&self.flight.waiters).register(self.id, cx.waker());
        let mut task = match self.flight.task.try_lock() {
            Ok(task) => task,
            Err(TryLockError::WouldBlock) => return Poll::Pending,
            // The fetch panicked in another lookup's poll.
            Err(TryLockError::Poisoned(_)) => return Poll::Ready(None),
        };
        let mut guard = PanicGuard {
            lookup: self,
            armed: true,
        };
        if matches!(*task, Task::Idle(_))
            && let Task::Idle(starter) = mem::replace(&mut *task, Task::Abandoned)
        {
            *task = Task::Running(starter());
        }
        let poll = match &mut *task {
            Task::Running(fetch) => {
                let waker = Waker::from(self.flight.clone());
                fetch.as_mut().poll(&mut Context::from_waker(&waker))
            }
            Task::Done(outcome) => {
                guard.armed = false;
                return Poll::Ready(outcome.clone());
            }
            Task::Idle(_) | Task::Abandoned => {
                guard.armed = false;
                return Poll::Ready(None);
            }
        };
        guard.armed = false;
        let Poll::Ready(outcome) = poll else {
            return Poll::Pending;
        };
        // The fetch is dropped once the lock is released.
        let fetch = mem::replace(&mut *task, Task::Done(outcome.clone()));
        drop(task);
        drop(fetch);
        self.engine.finish(&self.flight, &outcome);
        self.flight.wake_all();
        Poll::Ready(outcome)
    }
}

impl Drop for Lookup {
    fn drop(&mut self) {
        let last = {
            let mut shared = lock(&self.engine.shared);
            let mut waiters = lock(&self.flight.waiters);
            waiters.wakers.retain(|(id, _)| *id != self.id);
            let last = waiters.wakers.is_empty();
            drop(waiters);
            if last {
                shared.retire(&self.flight);
            }
            last
        };
        if !last {
            return;
        }
        // Nothing waits for the fetch any more: cancel it. No other lookup
        // exists to hold the lock, and a poisoned one has nothing to drop.
        let fetch = match self.flight.task.try_lock() {
            Ok(mut task) if matches!(*task, Task::Idle(_) | Task::Running(_)) => {
                Some(mem::replace(&mut *task, Task::Abandoned))
            }
            _ => None,
        };
        drop(fetch);
    }
}
