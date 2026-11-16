//! Load-aware routing: moving work off a backend that runs slower than usual.
//!
//! The [acceleration policy](super) picks one backend per algorithm family,
//! the *primary*. A processor's hardware for one kind of instruction is a
//! fixed resource: when something else is using it (another thread of this
//! process, another process, a neighbour on the same core), work that
//! depends on it takes longer than it usually does. This module watches for
//! that and, while it lasts, routes a share of a family's calls to another
//! of its backends (an *alternate*), which uses different instructions.
//!
//! Routing is off by default; [`enable`] turns it on for the process.
//!
//! # Mechanism
//!
//! A family has one *stream* per homogeneous kind of work (for example
//! "records" for an AEAD), reported by [`status`]. For each stream:
//!
//! 1. **Observe.** Some calls are timed (about one long record in sixteen;
//!    every key exchange or signature). Per backend, a short-term average
//!    cost and a *baseline*, its cost in normal operation, are kept in
//!    nanoseconds per unit of work. The baseline follows slow drift and
//!    improvements, but not a run of slow calls.
//! 2. **Detect.** The primary is *congested* when its short-term cost exceeds
//!    its baseline by more than [`Config::threshold_percent`] and at least
//!    five of its last eight timed calls were each that slow.
//! 3. **Probe.** One call in eight then goes to the next alternate, in the
//!    family's preference order, to measure it under the same conditions,
//!    until at least four such calls and sixteen calls of the primary were
//!    timed.
//! 4. **Shift.** If the alternate measured cheaper than the congested
//!    primary, a share of the calls moves to it. The share is reconsidered
//!    after every eight timed calls of the primary: it grows while the
//!    primary is still congested and the alternate cheaper (up to
//!    [`Config::max_shift_percent`]) and shrinks when the primary recovers
//!    or the alternate is the slower one. If the alternate did not measure
//!    cheaper, the next one is probed; when none helps, the present cost is
//!    accepted as the baseline (at most doubling it at a time).
//!
//! An episode that moved nothing, or that ended with nothing left on the
//! alternate while the primary was still slow, is followed by a pause of
//! 256 timed calls of the primary, doubled for each such episode up to
//! 65536; a doubling is forgotten after 4096 uneventful timed calls. A
//! probe or a shift that ended because the primary recovered is followed
//! by a quarter of that pause. Pauses are counted in timed calls, not in
//! time: a stream with little traffic pauses for long.
//!
//! Only backends that the family's [`Policy`](super::Policy) permits and the
//! CPU can run are alternates, so policies keep their meaning: forbidding a
//! kind of acceleration also keeps shifted work away from it.
//!
//! Which calls are timed, probed or shifted is decided by a per-thread
//! counter mixed with a per-thread random key, so the calls are spread
//! evenly and a peer cannot tell in advance where a call will run.
//!
//! # What does not change
//!
//! * **Results.** Every backend of a family computes the same function, bit
//!   for bit; routing changes which instructions run, never an output, a
//!   negotiated parameter or a record on the wire.
//! * **The default.** With routing disabled a routed call costs one relaxed
//!   atomic load more than it otherwise would.
//!
//! # Security considerations
//!
//! * Routing decisions are functions of call counters, input lengths (which
//!   the callers already treat as public) and measured durations. No secret
//!   value is read.
//! * Durations are those of the backends, which are written to run in time
//!   independent of secret data. The balancer adds no secret-dependent
//!   behaviour of its own, but it could amplify one: if a backend's duration
//!   did depend on a secret, that dependence could show in which backend
//!   runs later. The backends' constant-time properties (see the roadmap's
//!   governance gaps for how far they are verified) therefore matter as much
//!   with routing as without it.
//! * [`StreamStatus`] reports average durations of recent calls, including
//!   secret-key operations, to the picosecond. Treat it as diagnostic data
//!   for the operator, not something to publish to peers.
//! * An alternate takes work only while its timed calls are cheaper than the
//!   primary's timed calls. Load that slows every backend alike therefore
//!   moves little: in simulations of such load (steady, random and periodic
//!   bursts) under 1% of the calls ran on an alternate, and the time lost
//!   to them stayed under 1% even with an alternate three times slower.
//!   Someone who can slow the primary's calls and not the alternate's does
//!   move work, and the alternate is then slower than an undisturbed
//!   primary would be, by at most the factor to which the primary was
//!   slowed. Contention for the primary's instructions has that effect, by
//!   design. Slowing individual calls by their backend would need the
//!   schedule, which is why it is keyed; the mixing function is not a
//!   cryptographic one, so this resists peers, not someone who can observe
//!   many routing decisions exactly.
//! * Which backend handles a call, and so its duration, depends on the
//!   machine's load. Call durations already do.
//!
//! # Limits
//!
//! * Timing needs a clock and the schedule needs per-thread state: routing
//!   requires the `std` feature on a target whose `std` has a clock.
//!   Otherwise [`enable`] fails and nothing is routed.
//! * A slowdown that affects every backend alike (too few cores, a
//!   descheduled virtual machine) is detected, probed and then accepted as
//!   the new baseline; routing cannot help there.
//! * Costs are measured in wall-clock time, so they include preemption. A
//!   sample is clamped to four times its backend's baseline, and a first
//!   sample that turns out four times slower than the second is discarded.
//! * With jittery costs the baseline settles below their mean, so the
//!   threshold is relative to a good day rather than an average one; very
//!   noisy timings (half-width of 30% and more) or timed calls that
//!   alternate between two cost levels cause fruitless episodes and, with
//!   them, long pauses.
//! * Calls shorter than 4096 bytes are too short to time: outside a fixed
//!   share they always run on the primary, and a workload of short records
//!   alone is never shifted.
//! * The cost per byte of a record depends somewhat on its length (about
//!   10% between 4096 and 16384 bytes for ChaCha20-Poly1305 on one
//!   machine), so a change of record sizes looks like a small change of
//!   speed; the smallest threshold is 20% for that reason.
//! * A marginal alternate (one that is nearly as slow as the congested
//!   primary) is given up when timings are noisy; work then stays on the
//!   primary.
//! * A keyed object (for example an AEAD key) is routed only while the
//!   policy still selects the backend it was created for.
//! * A keyed object whose key is expanded per backend (an AES-GCM key) can
//!   only be routed to backends it holds an expanded key for. It expands its
//!   key for the alternates when it is created, and only if routing is
//!   enabled at that moment and the crate has the `alloc` feature: a key
//!   created earlier stays on its primary, and one created under another
//!   policy or [`Config::portable`] setting holds the alternates of that
//!   moment. Each alternate costs memory per key (see [`crate::gcm`]).
//!
//! ```
//! use browntls_crypto::accel::{Algorithm, load};
//!
//! if load::enable(load::Config::DEFAULT).is_ok() {
//!     for s in load::status_all() {
//!         println!("{s}");
//!     }
//!     // Send a quarter of the ChaCha20 record work to the next backend,
//!     // whatever the measurements say (for experiments).
//!     if load::set_fixed(Algorithm::ChaCha20, 0, 0, 25).is_ok() {
//!         load::clear_fixed(Algorithm::ChaCha20, 0);
//!     }
//!     load::disable();
//! }
//! ```

mod control;

use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

pub use control::Phase;
pub(crate) use control::Stream;
use control::{FULL_SHARE, MAX_AUTO_SHARE, Params, SLOTS, picos};

use super::{Algorithm, Backends, POLICIES, nibble, permits_bits};
use crate::Error;

/// How the balancer decides to shift work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Config {
    /// How much slower than its baseline the primary backend must run
    /// before work is shifted, in percent (20 to 200; values outside are
    /// clamped).
    pub threshold_percent: u8,
    /// The largest share of a stream's work that is shifted, in percent (1
    /// to 93; values outside are clamped). The primary always keeps some
    /// work, so that its recovery is noticed.
    pub max_shift_percent: u8,
    /// Whether the portable implementation is an alternate. Like every
    /// alternate it is probed when the primary is congested and takes a
    /// share only while it measures faster.
    pub portable: bool,
}

impl Config {
    /// Shift when the primary is 25% slower than usual, up to 90% of the
    /// work, to any permitted backend.
    pub const DEFAULT: Self = Self {
        threshold_percent: 25,
        max_shift_percent: 90,
        portable: true,
    };

    const fn clamped(self) -> Self {
        const fn clamp(v: u8, lo: u8, hi: u8) -> u8 {
            if v < lo {
                lo
            } else if v > hi {
                hi
            } else {
                v
            }
        }
        Self {
            threshold_percent: clamp(self.threshold_percent, 20, 200),
            max_shift_percent: clamp(self.max_shift_percent, 1, 93),
            portable: self.portable,
        }
    }

    const fn to_bits(self) -> u32 {
        ENABLED
            | (if self.portable { PORTABLE } else { 0 })
            | ((self.threshold_percent as u32) << 8)
            | ((self.max_shift_percent as u32) << 16)
    }

    // Both fields are masked to eight bits.
    #[allow(clippy::cast_possible_truncation)]
    const fn from_bits(v: u32) -> Self {
        Self {
            threshold_percent: ((v >> 8) & 0xff) as u8,
            max_shift_percent: ((v >> 16) & 0xff) as u8,
            portable: v & PORTABLE != 0,
        }
    }

    const fn params(self) -> Params {
        let max_share = self.max_shift_percent as u32 * FULL_SHARE / 100;
        Params {
            threshold: self.threshold_percent as u32,
            max_share: if max_share > MAX_AUTO_SHARE {
                MAX_AUTO_SHARE
            } else {
                max_share
            },
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const ENABLED: u32 = 1;
const PORTABLE: u32 = 2;

/// The configuration: 0 while routing is disabled, else [`Config::to_bits`].
static CONFIG: AtomicU32 = AtomicU32::new(0);

// `std` on bare WebAssembly has no clock (`Instant::now` panics there).
#[cfg(all(
    feature = "std",
    not(all(target_family = "wasm", target_os = "unknown"))
))]
mod clock {
    use std::cell::Cell;
    use std::collections::hash_map::RandomState;
    use std::hash::BuildHasher;

    use super::control::mix;

    pub(super) type Stamp = std::time::Instant;

    pub(super) const AVAILABLE: bool = true;

    pub(super) fn now() -> Stamp {
        Stamp::now()
    }

    pub(super) fn nanos_since(start: Stamp) -> u64 {
        u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    std::thread_local! {
        /// The thread's schedule: a secret key and a call counter with a
        /// secret starting point, both from the standard library's
        /// randomly keyed hasher.
        static SCHEDULE: (u64, Cell<u64>) = {
            let random = RandomState::new();
            (random.hash_one(0u8), Cell::new(random.hash_one(1u8)))
        };
    }

    /// The word that decides where the thread's next routed call runs (see
    /// `Stream::decide`): evenly spread over the calls and not predictable
    /// without the key. `None` while the thread is shutting down.
    pub(super) fn next_word() -> Option<u64> {
        SCHEDULE
            .try_with(|(key, counter)| {
                let n = counter.get();
                counter.set(n.wrapping_add(1));
                mix(mix(n) ^ key)
            })
            .ok()
    }
}

#[cfg(not(all(
    feature = "std",
    not(all(target_family = "wasm", target_os = "unknown"))
)))]
mod clock {
    //! No clock and no per-thread state: routing cannot be enabled, so
    //! these are never reached.
    #[derive(Clone, Copy)]
    pub(super) struct Stamp;

    pub(super) const AVAILABLE: bool = false;

    pub(super) fn now() -> Stamp {
        Stamp
    }

    pub(super) fn nanos_since(_start: Stamp) -> u64 {
        0
    }

    pub(super) fn next_word() -> Option<u64> {
        None
    }
}

/// Turns load-aware routing on for the process, or changes its
/// configuration. Statistics gathered so far are kept.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] when the crate is built without the `std`
/// feature, which provides the clock and the per-thread schedule, or for a
/// target whose `std` has no clock.
pub fn enable(config: Config) -> Result<(), Error> {
    if !clock::AVAILABLE {
        return Err(Error::Unsupported);
    }
    CONFIG.store(config.clamped().to_bits(), Relaxed);
    Ok(())
}

/// Turns load-aware routing off: every call runs on the backend its policy
/// selects. Statistics, shifts and fixed shares are forgotten.
pub fn disable() {
    CONFIG.store(0, Relaxed);
    for alg in Algorithm::ALL {
        for_family!(alg, reset_family);
    }
}

/// The configuration in force (with its values clamped), or `None` while
/// routing is disabled.
#[must_use]
pub fn config() -> Option<Config> {
    let bits = CONFIG.load(Relaxed);
    (bits & ENABLED != 0).then(|| Config::from_bits(bits))
}

fn reset_family<B: Backends>() {
    for stream in B::streams() {
        stream.reset();
    }
}

/// The primary's slot and the mask of slots that may take shifted work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Candidates {
    primary: usize,
    mask: u8,
}

const CACHE_VALID: u32 = 1 << 31;

/// The candidates of `B`'s family under its current policy.
///
/// Walking the preference list costs a feature test per backend, so the
/// result is cached in the stream, keyed by what it depends on: the family's
/// policy and whether the portable backend is a candidate. `None` when no
/// backend within the first [`SLOTS`] is permitted (not reached: stored
/// policies are satisfiable and no family has more backends).
fn candidates<B: Backends>(stream: &Stream, cfg: u32) -> Option<Candidates> {
    let policy = nibble(POLICIES.load(Relaxed), B::ALGORITHM);
    let key = CACHE_VALID | (u32::from(policy) << 16) | ((cfg & PORTABLE) << 20);
    let cached = stream.cache.load(Relaxed);
    if cached & !0xffff == key {
        return Some(Candidates {
            primary: ((cached >> 8) & 7) as usize,
            mask: (cached & 0xff) as u8,
        });
    }
    let mut primary = None;
    let mut mask = 0u8;
    for (slot, b) in B::PREFERENCE.iter().enumerate().take(SLOTS) {
        if !permits_bits(policy, b.uses().bits()) || !b.available() {
            continue;
        }
        if primary.is_none() {
            primary = Some(slot);
        } else if b.uses().any() || cfg & PORTABLE != 0 {
            mask |= 1 << slot;
        }
    }
    let primary = primary?;
    // `primary` < SLOTS = 8, so it fits its three bits.
    #[allow(clippy::cast_possible_truncation)]
    stream
        .cache
        .store(key | ((primary as u32) << 8) | u32::from(mask), Relaxed);
    Some(Candidates { primary, mask })
}

/// The alternates of the family of `own` under its current policy and the
/// configuration in force, most preferred first: the backends for which a
/// keyed object created for `own` expands its key as well, so that
/// [`route`] can move its calls to them.
///
/// Nothing while routing is disabled, or when `own` is not the backend the
/// policy selects (such an object is never routed).
#[cfg(feature = "alloc")]
pub(crate) fn alternates<B: Backends>(stream: &Stream, own: B) -> impl Iterator<Item = B> {
    alternates_under(stream, own, CONFIG.load(Relaxed))
}

#[cfg(feature = "alloc")]
fn alternates_under<B: Backends>(stream: &Stream, own: B, cfg: u32) -> impl Iterator<Item = B> {
    let mask = if cfg & ENABLED == 0 {
        0
    } else {
        candidates::<B>(stream, cfg)
            .filter(|c| B::PREFERENCE.get(c.primary) == Some(&own))
            .map_or(0, |c| c.mask)
    };
    B::PREFERENCE
        .iter()
        .enumerate()
        .take(SLOTS)
        .filter(move |(slot, _)| mask & (1 << slot) != 0)
        .map(|(_, b)| *b)
}

/// The measurement of one routed call.
struct Observation {
    stream: &'static Stream,
    slot: usize,
    units: usize,
    candidates: Candidates,
    params: Params,
    start: clock::Stamp,
}

/// The backend one call runs on.
#[must_use = "run the call on `backend()`, then report it with `done()`"]
pub(crate) struct Route<B> {
    backend: B,
    observation: Option<Observation>,
}

impl<B: Backends> Route<B> {
    /// `backend`, unconditionally and untimed.
    pub(crate) fn fixed(backend: B) -> Self {
        Self {
            backend,
            observation: None,
        }
    }

    /// The backend to run the call on: the caller's own backend or one for
    /// which [`Backends::available`] returned `true`.
    pub(crate) fn backend(&self) -> B {
        self.backend
    }

    /// The same route without its measurement, for a call whose duration
    /// its unit count does not describe.
    pub(crate) fn untimed(self) -> Self {
        Self::fixed(self.backend)
    }

    /// Reports that the call completed. A call that failed, or that did less
    /// work than its length implies, is simply not reported.
    pub(crate) fn done(self) {
        if let Some(o) = self.observation {
            let nanos = clock::nanos_since(o.start);
            o.stream.observe(
                o.slot,
                o.units,
                nanos,
                o.candidates.primary,
                o.candidates.mask,
                o.params,
            );
        }
    }
}

/// Routes one call of `units` units by an object created for backend `own`.
///
/// `usable` tells whether the object can run a given alternate (a keyed
/// object can only use the backends it holds a key for).
#[inline]
pub(crate) fn route<B: Backends>(
    stream: &'static Stream,
    own: B,
    units: usize,
    usable: impl Fn(B) -> bool,
) -> Route<B> {
    let cfg = CONFIG.load(Relaxed);
    if cfg & ENABLED == 0 {
        return Route::fixed(own);
    }
    route_enabled(stream, own, units, usable, cfg)
}

/// Routes one call of `units` units of a family that selects per call.
#[inline]
pub(crate) fn route_call<B: Backends>(stream: &'static Stream, units: usize) -> Route<B> {
    route(stream, super::select::<B>(), units, |_| true)
}

fn route_enabled<B: Backends>(
    stream: &'static Stream,
    own: B,
    units: usize,
    usable: impl Fn(B) -> bool,
    cfg: u32,
) -> Route<B> {
    if stream.passes(units) {
        return Route::fixed(own);
    }
    let Some(candidates) = candidates::<B>(stream, cfg) else {
        return Route::fixed(own);
    };
    // An object created under another policy keeps its backend: the
    // controller's statistics describe the present primary.
    if B::PREFERENCE.get(candidates.primary) != Some(&own) {
        return Route::fixed(own);
    }
    let Some(word) = clock::next_word() else {
        return Route::fixed(own);
    };
    let (mut slot, sample) = stream.decide(word, units, candidates.primary, candidates.mask);
    let mut backend = own;
    if slot != candidates.primary {
        match B::PREFERENCE.get(slot) {
            Some(&alternate) if usable(alternate) => backend = alternate,
            _ => slot = candidates.primary,
        }
    }
    let observation = sample.then(|| Observation {
        stream,
        slot,
        units,
        candidates,
        params: Config::from_bits(cfg).params(),
        start: clock::now(),
    });
    Route {
        backend,
        observation,
    }
}

/// The state of one stream of an algorithm family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamStatus {
    /// The algorithm family.
    pub algorithm: Algorithm,
    /// The stream's index within the family, as taken by [`status`].
    pub lane: usize,
    /// The kind of work, e.g. `"records"`.
    pub name: &'static str,
    /// The unit of work costs refer to: `"byte"` or `"op"`.
    pub unit: &'static str,
    /// What the stream is doing.
    pub phase: Phase,
    /// The backend the policy selects, e.g. `"AVX-512"`.
    pub primary: &'static str,
    /// The backend being probed or taking shifted work.
    pub alternate: Option<&'static str>,
    /// The share of the work routed to `alternate`, in percent.
    pub shifted_percent: u8,
    /// The primary's short-term cost in picoseconds per unit, once measured.
    pub primary_cost: Option<u64>,
    /// The primary's long-run cost in picoseconds per unit, once measured.
    pub baseline_cost: Option<u64>,
    /// The alternate's short-term cost in picoseconds per unit.
    pub alternate_cost: Option<u64>,
    /// How many alternates the stream has (see [`set_fixed`]).
    pub alternates: usize,
}

impl fmt::Display for StreamStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn cost(f: &mut fmt::Formatter<'_>, ps: Option<u64>, unit: &str) -> fmt::Result {
            match ps {
                Some(ps) => write!(f, "{ps} ps/{unit}"),
                None => f.write_str("not measured"),
            }
        }
        write!(
            f,
            "{} {}: {} on {} (",
            self.algorithm, self.name, self.phase, self.primary
        )?;
        cost(f, self.primary_cost, self.unit)?;
        f.write_str(", baseline ")?;
        cost(f, self.baseline_cost, self.unit)?;
        f.write_str(")")?;
        if let Some(alternate) = self.alternate {
            write!(f, ", {}% on {alternate} (", self.shifted_percent)?;
            cost(f, self.alternate_cost, self.unit)?;
            f.write_str(")")?;
        }
        Ok(())
    }
}

fn lanes_of<B: Backends>() -> usize {
    B::streams().len()
}

fn status_of<B: Backends>(lane: usize) -> Option<StreamStatus> {
    let stream = B::streams().get(lane)?;
    let cfg = CONFIG.load(Relaxed);
    // While disabled, report the candidates the default configuration has.
    let cfg = if cfg & ENABLED == 0 {
        Config::DEFAULT.to_bits()
    } else {
        cfg
    };
    let c = candidates::<B>(stream, cfg)?;
    let snap = stream.snapshot();
    let active = snap.ctl.phase != Phase::Steady
        && snap.ctl.primary == c.primary
        && c.mask & (1 << snap.ctl.alt) != 0;
    let (fast, slow, _) = snap.channels[c.primary];
    // A share is at most 256, so the percentage is at most 100.
    #[allow(clippy::cast_possible_truncation)]
    let percent = ((snap.ctl.share * 100 + FULL_SHARE / 2) / FULL_SHARE) as u8;
    Some(StreamStatus {
        algorithm: B::ALGORITHM,
        lane,
        name: stream.name(),
        unit: stream.unit(),
        phase: if active {
            snap.ctl.phase
        } else {
            Phase::Steady
        },
        primary: B::PREFERENCE[c.primary].name(),
        alternate: active.then(|| B::PREFERENCE[snap.ctl.alt].name()),
        shifted_percent: if active { percent } else { 0 },
        primary_cost: picos(fast),
        baseline_cost: picos(slow),
        alternate_cost: active
            .then(|| picos(snap.channels[snap.ctl.alt].0))
            .flatten(),
        alternates: c.mask.count_ones() as usize,
    })
}

/// How many streams `alg` has. A family without streams is never routed.
#[must_use]
pub fn lanes(alg: Algorithm) -> usize {
    for_family!(alg, lanes_of)
}

/// The state of stream `lane` of `alg`, or `None` if there is no such
/// stream.
#[must_use]
pub fn status(alg: Algorithm, lane: usize) -> Option<StreamStatus> {
    for_family!(alg, status_of, lane)
}

/// The state of every stream of every algorithm family.
pub fn status_all() -> impl Iterator<Item = StreamStatus> {
    Algorithm::ALL
        .into_iter()
        .flat_map(|alg| (0..lanes(alg)).filter_map(move |lane| status(alg, lane)))
}

fn fix<B: Backends>(lane: usize, alternate: usize, percent: u8) -> Result<(), Error> {
    let cfg = CONFIG.load(Relaxed);
    if cfg & ENABLED == 0 || percent > 100 {
        return Err(Error::Unsupported);
    }
    let stream = B::streams().get(lane).ok_or(Error::Unsupported)?;
    let c = candidates::<B>(stream, cfg).ok_or(Error::Unsupported)?;
    let slot = (0..SLOTS)
        .filter(|s| c.mask & (1 << s) != 0)
        .nth(alternate)
        .ok_or(Error::Unsupported)?;
    stream.fix(c.primary, slot, u32::from(percent) * FULL_SHARE / 100);
    Ok(())
}

fn unfix<B: Backends>(lane: usize) {
    if let Some(stream) = B::streams().get(lane) {
        stream.release();
    }
}

/// Routes `percent` of the work of stream `lane` of `alg` to its
/// `alternate`-th alternate (counted from 0 in the family's preference
/// order, skipping the primary), whatever the measurements say, until
/// [`clear_fixed`] or [`disable`]. For experiments and tests; unlike the
/// balancer this can move work to a slower backend, and it applies to calls
/// of every length. The share is the probability that a call is moved.
///
/// The share takes effect for objects that can use that backend; it is
/// ignored while the policy selects another primary or forbids the
/// alternate.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] when routing is disabled, `percent`
/// exceeds 100, or the stream or the alternate does not exist (see
/// [`StreamStatus::alternates`]).
pub fn set_fixed(alg: Algorithm, lane: usize, alternate: usize, percent: u8) -> Result<(), Error> {
    for_family!(alg, fix, lane, alternate, percent)
}

/// Ends a share set by [`set_fixed`]; the balancer takes over again.
pub fn clear_fixed(alg: Algorithm, lane: usize) {
    for_family!(alg, unfix, lane);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fits<B: Backends>() -> bool {
        B::PREFERENCE.len() <= SLOTS
    }

    #[test]
    fn every_family_fits_the_slots() {
        for alg in Algorithm::ALL {
            assert!(for_family!(alg, fits), "{alg}");
        }
    }

    #[test]
    fn configuration_round_trips_and_clamps() {
        let c = Config::DEFAULT;
        assert_eq!(Config::default(), c);
        assert_eq!(Config::from_bits(c.to_bits()), c);
        assert_eq!(c.params().threshold, 25);
        assert_eq!(c.params().max_share, 230);
        let wild = Config {
            threshold_percent: 0,
            max_shift_percent: 255,
            portable: false,
        }
        .clamped();
        assert_eq!((wild.threshold_percent, wild.max_shift_percent), (20, 93));
        assert!(wild.params().max_share <= MAX_AUTO_SHARE);
        assert_eq!(Config::from_bits(wild.to_bits()), wild);
        let low = Config {
            threshold_percent: 255,
            max_shift_percent: 0,
            portable: true,
        }
        .clamped();
        assert_eq!((low.threshold_percent, low.max_shift_percent), (200, 1));
        assert_eq!(low.params().max_share, 2);
    }

    /// The cached candidates are those of the policy, and the primary is
    /// the backend `select` returns. Read-only: tests in this binary run
    /// concurrently, so the process-wide state is exercised in
    /// `tests/accel_load.rs`.
    fn candidates_match<B: Backends + fmt::Debug>() {
        let Some(stream) = B::streams().first() else {
            return;
        };
        for cfg in [ENABLED, ENABLED | PORTABLE] {
            // Twice: computed, then from the cache.
            for _ in 0..2 {
                let c = candidates::<B>(stream, cfg).unwrap();
                assert_eq!(B::PREFERENCE[c.primary], super::super::select::<B>());
                assert_eq!(c.mask & (1 << c.primary), 0);
                for (slot, b) in B::PREFERENCE.iter().enumerate() {
                    let candidate = c.mask & (1 << slot) != 0;
                    if candidate {
                        assert!(b.available(), "{b:?}");
                        assert!(slot > c.primary);
                    }
                    if slot > c.primary && b.available() {
                        assert_eq!(candidate, b.uses().any() || cfg & PORTABLE != 0, "{b:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn candidates_follow_the_policy() {
        candidates_match::<crate::chacha::Backend>();
        candidates_match::<crate::aes::Backend>();
    }

    /// A keyed object's alternates are the candidates of its backend, in
    /// preference order, and there are none while routing is disabled or
    /// for a backend the policy does not select. Read-only, like
    /// `candidates_match`.
    #[cfg(feature = "alloc")]
    fn alternates_match<B: Backends + fmt::Debug>() {
        use std::vec::Vec;
        let Some(stream) = B::streams().first() else {
            return;
        };
        let alternates = |own, cfg| alternates_under::<B>(stream, own, cfg).collect::<Vec<B>>();
        for portable in [0, PORTABLE] {
            let cfg = ENABLED | portable;
            let c = candidates::<B>(stream, cfg).unwrap();
            let primary = B::PREFERENCE[c.primary];
            let expected: Vec<B> = B::PREFERENCE
                .iter()
                .enumerate()
                .filter(|(slot, _)| c.mask & (1 << slot) != 0)
                .map(|(_, b)| *b)
                .collect();
            let found = alternates(primary, cfg);
            assert_eq!(found, expected);
            assert_eq!(found.len(), c.mask.count_ones() as usize);
            for b in &found {
                assert!(b.available() && *b != primary, "{b:?}");
                assert!(b.uses().any() || portable != 0, "{b:?}");
            }
            // The portable backend is last, and an alternate only if asked.
            let last = B::PREFERENCE[B::PREFERENCE.len() - 1];
            assert_eq!(found.contains(&last), portable != 0 && last != primary);
            // Disabled (whatever the other bits say): nothing.
            assert_eq!(alternates(primary, portable), []);
            // Another backend than the primary is not routed.
            for own in B::PREFERENCE.iter().filter(|b| **b != primary) {
                assert_eq!(alternates(*own, cfg), [], "{own:?}");
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn alternates_are_the_candidates_of_the_primary() {
        alternates_match::<crate::chacha::Backend>();
        alternates_match::<crate::aes::Backend>();
        // Routing is never enabled in this test binary.
        let own = crate::aes::Backend::select();
        assert_eq!(alternates(&crate::aes::LOAD[1], own).count(), 0);
    }

    #[test]
    fn call_words_are_spread_and_per_thread() {
        let words: std::vec::Vec<u64> = (0..4096).map(|_| clock::next_word().unwrap()).collect();
        // The bits that place a call within a share are uniform.
        let low = words.iter().filter(|w| *w >> 56 < 64).count();
        assert!(low.abs_diff(1024) < 150, "{low}");
        let mut sorted = words.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), words.len());
        // Another thread has another key and starting point.
        let other = std::thread::spawn(|| clock::next_word().unwrap())
            .join()
            .unwrap();
        assert!(!words.contains(&other));
    }

    #[test]
    fn status_renders() {
        let s = StreamStatus {
            algorithm: Algorithm::Aes,
            lane: 0,
            name: "records",
            unit: "byte",
            phase: Phase::Shifting,
            primary: "VAES (AVX-512)",
            alternate: Some("AES-NI"),
            shifted_percent: 62,
            primary_cost: Some(210),
            baseline_cost: Some(84),
            alternate_cost: None,
            alternates: 3,
        };
        assert_eq!(
            std::format!("{s}"),
            "AES records: shifting on VAES (AVX-512) (210 ps/byte, baseline 84 ps/byte), \
             62% on AES-NI (not measured)"
        );
        assert_eq!(std::format!("{}", Phase::Fixed), "fixed");
    }
}
