//! Per-stream statistics and the shift controller.
//!
//! Everything here is a function of the observations it is given: there is no
//! clock, no backend type and no source of randomness, so the state machine
//! is tested with synthetic costs. A *slot* is the index of a backend in its
//! family's preference list.
//!
//! State is a handful of atomics updated with relaxed loads and stores. Racing
//! updates may lose a sample or a controller step; every value stays within
//! its range and the next observation corrects the state, so no lock is
//! needed on the record path.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

/// Backends per family that a stream can track.
pub(crate) const SLOTS: usize = 8;

/// Costs are nanoseconds per unit of work, scaled by `2^COST_SHIFT`.
const COST_SHIFT: u32 = 32;
/// Largest stored cost (2^24 ns, about 17 ms, per unit).
const MAX_COST: u64 = 1 << 56;

/// Weight `1/8` for the short-term average of a channel.
const FAST_WEIGHT: u64 = 8;
/// Weight of a sample above the baseline: the baseline follows a slow drift
/// upwards (and never a run of slow samples; see `Stream::observe`).
const BASELINE_UP_WEIGHT: u64 = 1024;
/// Weight of a sample below the baseline: improvements count sooner, so a
/// slow level that was once accepted is left behind when it ends. The
/// price is a baseline somewhat below the mean of a jittery cost (about a
/// third of the jitter's half-width when it is uniform).
const BASELINE_DOWN_WEIGHT: u64 = 256;
/// Samples a channel needs before its baseline is trusted.
const MIN_BASELINE: u32 = 32;
/// A sample is clamped to this multiple of the baseline, so that one call
/// interrupted by the scheduler cannot dominate the averages.
const OUTLIER: u64 = 4;
/// Of the last eight timed calls of the primary, how many must be slow,
/// besides a slow average, before it counts as congested: one interrupted
/// call is not congestion, slow calls mixed with a few normal ones are.
const RUN: u32 = 5;
/// Primary samples to see after a change of the share before the next.
const SETTLE: u32 = 8;
/// Primary samples to see while probing before the comparison.
const PROBE_SETTLE: u32 = 16;
/// Samples of an alternate taken before it is compared with the primary.
const PROBES: u32 = 4;
/// While probing, one call in this many goes to the alternate.
const PROBE_PERIOD: u64 = 8;
/// Primary samples to wait for the probes before giving up on an alternate.
const PROBE_PATIENCE: u32 = 64;
/// Change of the shifted share per controller step, in 256ths.
const STEP: u32 = 16;
/// An alternate must be this much cheaper than the primary to gain share.
const MARGIN_PERCENT: u128 = 5;
/// Primary samples to wait after an episode that shifted nothing; doubled
/// for each further such episode.
const BASE_COOLDOWN: u32 = 256;
const MAX_BACKOFF: u32 = 8;
/// Uneventful primary samples after which one doubling is forgotten.
const QUIET: u32 = 4096;
/// The pause and the quiet stretch are counted in steps of this many primary
/// samples, so that the control word, which every routed call reads, is
/// written for one sample in so many and not for each.
const BATCH: u32 = 16;
/// Accepting a slow level raises the baseline by at most this factor at a
/// time.
const MAX_REBASE: u64 = 2;
/// While work is being shifted, both channels are sampled at least this often.
const BUSY_SAMPLE_MASK: u64 = 3;

/// The whole of a stream's work, as a share.
pub(crate) const FULL_SHARE: u32 = 256;
/// The largest share the controller shifts by itself: the primary keeps one
/// call in sixteen, so its recovery is still observed.
pub(crate) const MAX_AUTO_SHARE: u32 = 240;

/// What a stream is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Phase {
    /// All work runs on the primary backend, whose cost is being watched.
    Steady,
    /// The primary is slower than its baseline; a few calls measure an
    /// alternate.
    Probing,
    /// A share of the work runs on an alternate that measured faster.
    Shifting,
    /// A share set with [`set_fixed`](super::set_fixed), not by measurements.
    Fixed,
}

impl Phase {
    /// `"steady"`, `"probing"`, `"shifting"` or `"fixed"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Steady => "steady",
            Self::Probing => "probing",
            Self::Shifting => "shifting",
            Self::Fixed => "fixed",
        }
    }

    const fn bits(self) -> u64 {
        match self {
            Self::Steady => 0,
            Self::Probing => 1,
            Self::Shifting => 2,
            Self::Fixed => 3,
        }
    }

    const fn from_bits(v: u64) -> Self {
        match v & 3 {
            0 => Self::Steady,
            1 => Self::Probing,
            2 => Self::Shifting,
            _ => Self::Fixed,
        }
    }
}

impl core::fmt::Display for Phase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// The control word of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ctl {
    /// Share of the work routed to `alt`, in 256ths (0..=256).
    pub(crate) share: u32,
    /// The alternate's slot (meaningful outside [`Phase::Steady`]).
    pub(crate) alt: usize,
    /// The primary's slot when the phase began.
    pub(crate) primary: usize,
    pub(crate) phase: Phase,
    /// While steady, the last eight primary samples, one bit each (set when
    /// slow); while probing, the primary samples seen so far; while
    /// shifting, those seen since the share last changed.
    patience: u32,
    /// Episodes that shifted nothing, less those forgotten since.
    backoff: u32,
    /// Primary samples left before congestion is looked for again.
    cooldown: u32,
    /// Uneventful primary samples since the last episode.
    quiet: u32,
}

impl Ctl {
    const fn steady(primary: usize) -> Self {
        Self {
            share: 0,
            alt: 0,
            primary,
            phase: Phase::Steady,
            patience: 0,
            backoff: 0,
            cooldown: 0,
            quiet: 0,
        }
    }

    /// Bits 0-8 share, 9-11 alternate, 12-14 primary, 15-16 phase, 17-24
    /// patience, 25-28 back-off, 32-48 cool-down, 49-61 quiet samples.
    const fn pack(self) -> u64 {
        (self.share as u64 & 0x1ff)
            | ((self.alt as u64 & 7) << 9)
            | ((self.primary as u64 & 7) << 12)
            | (self.phase.bits() << 15)
            | ((self.patience as u64 & 0xff) << 17)
            | ((self.backoff as u64 & 0xf) << 25)
            | ((self.cooldown as u64 & 0x1_ffff) << 32)
            | ((self.quiet as u64 & 0x1fff) << 49)
    }

    // Every field is masked to its width before the narrowing casts.
    #[allow(clippy::cast_possible_truncation)]
    const fn unpack(v: u64) -> Self {
        let share = (v & 0x1ff) as u32;
        let backoff = ((v >> 25) & 0xf) as u32;
        Self {
            share: if share > FULL_SHARE {
                FULL_SHARE
            } else {
                share
            },
            alt: ((v >> 9) & 7) as usize,
            primary: ((v >> 12) & 7) as usize,
            phase: Phase::from_bits(v >> 15),
            patience: ((v >> 17) & 0xff) as u32,
            backoff: if backoff > MAX_BACKOFF {
                MAX_BACKOFF
            } else {
                backoff
            },
            cooldown: ((v >> 32) & 0x1_ffff) as u32,
            quiet: ((v >> 49) & 0x1fff) as u32,
        }
    }

    /// The steady state after an episode that shifted nothing: no new
    /// episode starts for `pause` primary samples, doubled for each such
    /// episode before this one.
    const fn paused(self, pause: u32) -> Self {
        Self {
            cooldown: pause << self.backoff,
            backoff: if self.backoff < MAX_BACKOFF {
                self.backoff + 1
            } else {
                MAX_BACKOFF
            },
            ..Self::steady(self.primary)
        }
    }
}

// The largest cool-down and the quiet count fit their fields.
const _: () = assert!(BASE_COOLDOWN << MAX_BACKOFF <= 0x1_ffff && QUIET + BATCH <= 0x1fff);
// A pause is a whole number of counting steps.
const _: () = assert!((BASE_COOLDOWN / 4).is_multiple_of(BATCH) && QUIET.is_multiple_of(BATCH));

/// A change to the statistics that goes with a controller step. It is
/// applied only by the thread whose step was stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect {
    None,
    /// Forget what is known about a slot: it is about to be probed.
    Restart(usize),
    /// Accept this cost as the primary's baseline.
    Rebase(u64),
}

/// Limits the controller works within (from the public configuration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Params {
    /// Slowdown over the baseline that counts as congestion, in percent.
    pub(crate) threshold: u32,
    /// Largest share to shift, in 256ths.
    pub(crate) max_share: u32,
}

/// Cost statistics of one backend within a stream.
struct Channel {
    /// Short-term average cost; 0 before the first sample.
    fast: AtomicU64,
    /// Long-run cost in normal operation (the baseline); 0 before the first
    /// sample.
    slow: AtomicU64,
    samples: AtomicU32,
}

impl Channel {
    const fn new() -> Self {
        Self {
            fast: AtomicU64::new(0),
            slow: AtomicU64::new(0),
            samples: AtomicU32::new(0),
        }
    }

    fn reset(&self) {
        self.fast.store(0, Relaxed);
        self.slow.store(0, Relaxed);
        self.samples.store(0, Relaxed);
    }
}

/// Moves `avg` towards `cost` with weight `1/weight`; the first `weight`
/// samples form a plain mean, so a new average is usable at once.
fn average(avg: &AtomicU64, seen: u32, cost: u64, weight: u64) {
    let old = avg.load(Relaxed);
    let w = (u64::from(seen) + 1).min(weight);
    let new = if old == 0 || w == 1 {
        cost
    } else {
        old - old / w + cost / w
    };
    avg.store(new.clamp(1, MAX_COST), Relaxed);
}

/// `fast` exceeds `slow` by more than `percent`.
fn exceeds(fast: u64, slow: u64, percent: u32) -> bool {
    slow != 0 && u128::from(fast) * 100 > u128::from(slow) * (100 + u128::from(percent))
}

/// `alt` is cheaper than `primary` by the margin.
fn cheaper(alt: u64, primary: u64) -> bool {
    alt != 0 && u128::from(alt) * 100 < u128::from(primary) * (100 - MARGIN_PERCENT)
}

/// The last eight primary samples, one bit each (set when slow), after one
/// more.
fn history(recent: u32, slow_sample: bool) -> u32 {
    ((recent << 1) | u32::from(slow_sample)) & 0xff
}

/// The lowest slot of `mask` above `after` (any slot when `after` is `None`).
fn next_slot(mask: u8, after: Option<usize>) -> Option<usize> {
    let from = after.map_or(0, |a| a + 1);
    (from..SLOTS).find(|&s| mask & (1 << s) != 0)
}

/// A 64-bit mixing function (the SplitMix64 finaliser). The caller derives
/// one word per call from a counter and a secret key with it; the bits of
/// that word decide where the call runs (see [`Stream::decide`]).
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) const fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// A snapshot of a stream for status reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) ctl: Ctl,
    /// Short-term cost, baseline and sample count per slot.
    pub(crate) channels: [(u64, u64, u32); SLOTS],
}

/// The statistics of a stream, on cache lines of their own: timed calls
/// write them, and every routed call of every thread reads the rest of the
/// stream, which would otherwise be invalidated with each of those writes.
#[repr(align(64))]
struct Channels([Channel; SLOTS]);

/// One homogeneous kind of work of an algorithm family (for example its
/// record encryptions), whose calls are routed between the family's backends.
///
/// The other fields are read by every routed call and seldom written.
pub(crate) struct Stream {
    name: &'static str,
    unit: &'static str,
    /// Calls are timed when the sampling bits of their word are zero under
    /// this mask.
    sample_mask: u64,
    /// Calls with fewer units are never timed (clock noise would dominate).
    min_units: usize,
    ctl: AtomicU64,
    /// The primary slot and candidate mask derived from the policy (see
    /// `super::candidates`).
    pub(super) cache: AtomicU32,
    channels: Channels,
}

impl Stream {
    const fn new(name: &'static str, unit: &'static str, sample_mask: u64, min: usize) -> Self {
        Self {
            name,
            unit,
            sample_mask,
            min_units: min,
            ctl: AtomicU64::new(0),
            cache: AtomicU32::new(0),
            channels: Channels([const { Channel::new() }; SLOTS]),
        }
    }

    /// A stream of calls whose cost is proportional to a byte count. One call
    /// in sixteen of at least 4096 bytes is timed.
    pub(crate) const fn bulk(name: &'static str) -> Self {
        Self::new(name, "byte", 15, 4096)
    }

    /// A stream of calls of one fixed cost (a key exchange, a signature).
    /// Every call is timed: two clock readings are negligible next to it.
    pub(crate) const fn op(name: &'static str) -> Self {
        Self::new(name, "op", 0, 1)
    }

    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) fn unit(&self) -> &'static str {
        self.unit
    }

    /// Whether a call of `units` units is neither timed nor moved whatever
    /// its word: it is too short to time and no share is fixed. Such a call
    /// needs no decision.
    pub(crate) fn passes(&self, units: usize) -> bool {
        units < self.min_units && Ctl::unpack(self.ctl.load(Relaxed)).phase != Phase::Fixed
    }

    /// Chooses the slot for a call of `units` units and whether to time it.
    ///
    /// `word` is the call's word (see [`mix`]): bits 56-63 place the call
    /// within the shifted share, bits 48-50 select the probes and bits 32-35
    /// the timed calls, so the three choices are independent. Callers pass
    /// words that an observer of the calls cannot predict; otherwise someone
    /// able to slow chosen calls could slow only those of one backend.
    ///
    /// `primary` is the slot the policy selects and `mask` the slots work may
    /// be shifted to. The controller only moves calls it can time: if the
    /// work turned into short calls alone, no sample would ever end a probe
    /// or a shift, so those stay on the primary.
    pub(crate) fn decide(
        &self,
        word: u64,
        units: usize,
        primary: usize,
        mask: u8,
    ) -> (usize, bool) {
        let ctl = Ctl::unpack(self.ctl.load(Relaxed));
        let measurable = units >= self.min_units;
        let sampling = word >> 32;
        let sampled = measurable && sampling & self.sample_mask == 0;
        if ctl.phase == Phase::Steady || ctl.primary != primary || mask & (1 << ctl.alt) == 0 {
            return (primary, sampled);
        }
        if !measurable && ctl.phase != Phase::Fixed {
            return (primary, false);
        }
        match ctl.phase {
            Phase::Steady => (primary, sampled),
            Phase::Probing => {
                if (word >> 48).is_multiple_of(PROBE_PERIOD) {
                    (ctl.alt, true)
                } else {
                    (primary, sampling & self.sample_mask & BUSY_SAMPLE_MASK == 0)
                }
            }
            Phase::Shifting | Phase::Fixed => {
                let slot = if word >> 56 < u64::from(ctl.share) {
                    ctl.alt
                } else {
                    primary
                };
                let mask = if ctl.phase == Phase::Fixed {
                    self.sample_mask
                } else {
                    self.sample_mask & BUSY_SAMPLE_MASK
                };
                (slot, measurable && sampling & mask == 0)
            }
        }
    }

    /// Chooses the slot for work that is placed as a whole and stays where
    /// it was put (a connection's records, see `super::kernel`), with the
    /// share and the probes of [`Stream::decide`]. Whether its calls are
    /// timed is decided call by call ([`Stream::timed`]).
    ///
    /// A probe cannot wait for one placement in eight: placements may be
    /// rare next to the calls, and the probe is given up after
    /// [`PROBE_PATIENCE`] samples of the primary. So until the alternate
    /// has its [`PROBES`] samples, every placement goes to it.
    pub(crate) fn place(&self, word: u64, primary: usize, mask: u8) -> usize {
        let ctl = Ctl::unpack(self.ctl.load(Relaxed));
        if ctl.phase == Phase::Probing
            && ctl.primary == primary
            && mask & (1 << ctl.alt) != 0
            && self.channels.0[ctl.alt].samples.load(Relaxed) < PROBES
        {
            return ctl.alt;
        }
        self.decide(word, self.min_units, primary, mask).0
    }

    /// Whether to time a call of `units` units that runs on `slot` whatever
    /// its word, because its work was placed before ([`Stream::place`]):
    /// the calls [`Stream::decide`] would time on that slot, and every
    /// measurable call of an alternate while it is probed, since no call
    /// can be sent there for the purpose.
    pub(crate) fn timed(&self, word: u64, units: usize, slot: usize) -> bool {
        if units < self.min_units {
            return false;
        }
        let ctl = Ctl::unpack(self.ctl.load(Relaxed));
        let sampling = word >> 32;
        match ctl.phase {
            Phase::Steady | Phase::Fixed => sampling & self.sample_mask == 0,
            Phase::Probing if slot == ctl.alt => true,
            Phase::Probing | Phase::Shifting => sampling & self.sample_mask & BUSY_SAMPLE_MASK == 0,
        }
    }

    /// Whether a call of `units` units is long enough to time.
    pub(crate) fn measurable(&self, units: usize) -> bool {
        units >= self.min_units
    }

    /// Records that `units` units of work took `nanos` nanoseconds on `slot`
    /// and lets the controller react.
    pub(crate) fn observe(
        &self,
        slot: usize,
        units: usize,
        nanos: u64,
        primary: usize,
        mask: u8,
        params: Params,
    ) {
        if units == 0 || slot >= SLOTS || primary >= SLOTS {
            return;
        }
        let cost = (u128::from(nanos) << COST_SHIFT) / units as u128;
        let mut cost = u64::try_from(cost).unwrap_or(MAX_COST).clamp(1, MAX_COST);

        let ctl = Ctl::unpack(self.ctl.load(Relaxed));
        let ch = &self.channels.0[slot];
        let mut seen = ch.samples.load(Relaxed);
        let mut slow = ch.slow.load(Relaxed);
        if seen == 1 && cost.saturating_mul(OUTLIER) < slow {
            // The first sample was an interrupted call or a cold start:
            // begin again from this one.
            seen = 0;
            slow = 0;
        }
        if slow != 0 {
            cost = cost.min(slow.saturating_mul(OUTLIER));
        }
        let slow_sample = exceeds(cost, slow, params.threshold);
        let tick = seen % BATCH == BATCH - 1;
        average(&ch.fast, seen, cost, FAST_WEIGHT);
        let own = slot == primary && ctl.primary == primary;
        let run = own
            && ctl.phase == Phase::Steady
            && history(ctl.patience, slow_sample).count_ones() >= RUN;
        let held = slot == primary
            && seen >= MIN_BASELINE
            && ((slow_sample && run)
                || (own && matches!(ctl.phase, Phase::Probing | Phase::Shifting)));
        if !held {
            let mut level = cost;
            if slot == primary && slow_sample && seen >= MIN_BASELINE {
                level = level.min(slow + slow / 100 * u64::from(params.threshold));
            }
            let weight = if level < slow {
                BASELINE_DOWN_WEIGHT
            } else {
                BASELINE_UP_WEIGHT
            };
            average(&ch.slow, seen, level, weight);
        }
        ch.samples.store(seen.saturating_add(1), Relaxed);

        let (next, effect) = self.step(ctl, slot, slow_sample, tick, primary, mask, params);
        // Losing the race to another thread's step is fine: that step was
        // computed from the same statistics, and this one changes nothing.
        if next != ctl
            && self
                .ctl
                .compare_exchange(ctl.pack(), next.pack(), Relaxed, Relaxed)
                .is_ok()
        {
            match effect {
                Effect::None => {}
                Effect::Restart(alt) => self.channels.0[alt].reset(),
                Effect::Rebase(cost) => self.channels.0[primary].slow.store(cost, Relaxed),
            }
        }
    }

    /// The controller: the control word that follows `ctl` after a sample on
    /// `slot`, which was `slow_sample` if it exceeded that channel's baseline
    /// by the threshold, and the change to the statistics that goes with it.
    /// `tick` is set for one sample of the slot in [`BATCH`].
    #[allow(clippy::too_many_arguments)]
    fn step(
        &self,
        ctl: Ctl,
        slot: usize,
        slow_sample: bool,
        tick: bool,
        primary: usize,
        mask: u8,
        params: Params,
    ) -> (Ctl, Effect) {
        if ctl.phase == Phase::Fixed {
            return (ctl, Effect::None);
        }
        if ctl.primary != primary || (ctl.phase != Phase::Steady && mask & (1 << ctl.alt) == 0) {
            // The policy selects another backend now, or the alternate is no
            // longer allowed: start over.
            return (Ctl::steady(primary), Effect::None);
        }
        let p = &self.channels.0[primary];
        let (fast_p, slow_p) = (p.fast.load(Relaxed), p.slow.load(Relaxed));
        let congested = exceeds(fast_p, slow_p, params.threshold);
        let recovered = !exceeds(fast_p, slow_p, params.threshold / 2);
        let a = &self.channels.0[ctl.alt];

        match ctl.phase {
            Phase::Steady => {
                if slot != primary {
                    return (ctl, Effect::None);
                }
                let recent = history(ctl.patience, slow_sample);
                if ctl.cooldown > 0 {
                    let next = Ctl {
                        cooldown: ctl.cooldown.saturating_sub(if tick { BATCH } else { 0 }),
                        patience: recent,
                        ..ctl
                    };
                    return (next, Effect::None);
                }
                if p.samples.load(Relaxed) >= MIN_BASELINE
                    && congested
                    && recent.count_ones() >= RUN
                {
                    return match next_slot(mask, None) {
                        Some(alt) => Self::probe(ctl, alt),
                        None => Self::accept(ctl, fast_p, slow_p),
                    };
                }
                // A long uneventful stretch forgets one doubling of the pause.
                let (backoff, quiet) = match (ctl.backoff, ctl.quiet + BATCH) {
                    (0, _) => (0, 0),
                    (b, _) if !tick => (b, ctl.quiet),
                    (b, q) if q >= QUIET => (b - 1, 0),
                    (b, q) => (b, q),
                };
                let next = Ctl {
                    patience: recent,
                    backoff,
                    quiet,
                    ..ctl
                };
                (next, Effect::None)
            }
            Phase::Probing => {
                if recovered {
                    // A blip. A short pause keeps a load that comes and goes
                    // from holding the stream in this phase.
                    return (ctl.paused(BASE_COOLDOWN / 4), Effect::None);
                }
                if a.samples.load(Relaxed) >= PROBES && ctl.patience >= PROBE_SETTLE {
                    return if cheaper(a.fast.load(Relaxed), fast_p) {
                        let next = Ctl {
                            phase: Phase::Shifting,
                            share: STEP.min(params.max_share),
                            patience: 0,
                            ..ctl
                        };
                        (next, Effect::None)
                    } else {
                        Self::advance(ctl, mask, Some((fast_p, slow_p)))
                    };
                }
                if slot != primary {
                    return (ctl, Effect::None);
                }
                if ctl.patience >= PROBE_PATIENCE {
                    // No probe was timed (for example, no caller holds this
                    // backend).
                    return Self::advance(ctl, mask, Some((fast_p, slow_p)));
                }
                let next = Ctl {
                    patience: ctl.patience + 1,
                    ..ctl
                };
                (next, Effect::None)
            }
            Phase::Shifting => {
                // The share changes on evidence from the primary that
                // postdates the last change.
                if slot != primary {
                    return (ctl, Effect::None);
                }
                if ctl.patience + 1 < SETTLE {
                    let next = Ctl {
                        patience: ctl.patience + 1,
                        ..ctl
                    };
                    return (next, Effect::None);
                }
                let fast_a = a.fast.load(Relaxed);
                let share = if recovered || fast_a > fast_p {
                    ctl.share.saturating_sub(STEP)
                } else if congested && cheaper(fast_a, fast_p) {
                    (ctl.share + STEP).min(params.max_share)
                } else {
                    ctl.share.min(params.max_share)
                };
                if share == ctl.share {
                    let next = Ctl {
                        patience: SETTLE,
                        ..ctl
                    };
                    (next, Effect::None)
                } else if share > 0 {
                    let next = Ctl {
                        share,
                        patience: 0,
                        ..ctl
                    };
                    (next, Effect::None)
                } else if recovered {
                    let next = Ctl {
                        cooldown: BASE_COOLDOWN / 4,
                        backoff: ctl.backoff,
                        ..Ctl::steady(primary)
                    };
                    (next, Effect::None)
                } else {
                    Self::advance(ctl, mask, None)
                }
            }
            Phase::Fixed => (ctl, Effect::None),
        }
    }

    /// Starts measuring `alt` afresh.
    fn probe(ctl: Ctl, alt: usize) -> (Ctl, Effect) {
        let next = Ctl {
            phase: Phase::Probing,
            alt,
            share: 0,
            patience: 0,
            quiet: 0,
            ..ctl
        };
        (next, Effect::Restart(alt))
    }

    /// The current alternate does not help (any more): tries the next one,
    /// or pauses. With `accept`, the primary's short-term cost and baseline,
    /// the episode moved nothing and the present cost is accepted as well;
    /// after a shift that did help for a while the baseline stays, so the
    /// congestion is looked at again after the pause.
    fn advance(ctl: Ctl, mask: u8, accept: Option<(u64, u64)>) -> (Ctl, Effect) {
        match (next_slot(mask, Some(ctl.alt)), accept) {
            (Some(alt), _) => Self::probe(ctl, alt),
            (None, Some((fast_p, slow_p))) => Self::accept(ctl, fast_p, slow_p),
            (None, None) => (ctl.paused(BASE_COOLDOWN), Effect::None),
        }
    }

    /// Nothing helps: the primary's present cost becomes its baseline (in
    /// steps of at most [`MAX_REBASE`], so that a burst of slow samples
    /// cannot raise it without bound) and the stream pauses.
    fn accept(ctl: Ctl, fast_p: u64, slow_p: u64) -> (Ctl, Effect) {
        let effect = if fast_p > slow_p && slow_p != 0 {
            Effect::Rebase(fast_p.min(slow_p.saturating_mul(MAX_REBASE)))
        } else {
            Effect::None
        };
        (ctl.paused(BASE_COOLDOWN), effect)
    }

    /// Routes `share` 256ths of the work to `alt` until [`Stream::release`].
    pub(crate) fn fix(&self, primary: usize, alt: usize, share: u32) {
        let ctl = Ctl {
            phase: Phase::Fixed,
            alt,
            share: share.min(FULL_SHARE),
            ..Ctl::steady(primary)
        };
        self.ctl.store(ctl.pack(), Relaxed);
    }

    /// Ends a fixed share (and nothing else).
    pub(crate) fn release(&self) {
        let ctl = Ctl::unpack(self.ctl.load(Relaxed));
        if ctl.phase == Phase::Fixed {
            let _ = self.ctl.compare_exchange(
                ctl.pack(),
                Ctl::steady(ctl.primary).pack(),
                Relaxed,
                Relaxed,
            );
        }
    }

    /// Forgets every statistic and returns to [`Phase::Steady`].
    pub(crate) fn reset(&self) {
        self.ctl.store(0, Relaxed);
        for ch in &self.channels.0 {
            ch.reset();
        }
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            ctl: Ctl::unpack(self.ctl.load(Relaxed)),
            channels: core::array::from_fn(|i| {
                let ch = &self.channels.0[i];
                (
                    ch.fast.load(Relaxed),
                    ch.slow.load(Relaxed),
                    ch.samples.load(Relaxed),
                )
            }),
        }
    }
}

/// A stored cost in picoseconds per unit.
pub(crate) fn picos(cost: u64) -> Option<u64> {
    (cost != 0).then(|| u64::try_from((u128::from(cost) * 1000) >> COST_SHIFT).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests;
