//! Kernel TLS at the head of the routing order.
//!
//! The backends of a family are code of this crate, and [`route`](super)
//! chooses between them call by call. Linux kernel TLS is another place
//! where the records of a connection can be protected: the kernel is given
//! the connection's keys and makes the records itself (the `browntls-ktls`
//! crate does the handover). This module puts that place in front of the
//! backends, for the record work the kernel can take ([`Records`]):
//!
//! 1. kernel TLS, while it is [active](activate);
//! 2. the family's backends in their usual order: for AES-GCM those with
//!    dedicated AES instructions, widest first; for ChaCha20-Poly1305 the
//!    SIMD backends; then the portable code.
//!
//! While kernel TLS is not active nothing changes: every connection stays
//! with the backends, routed between them as before.
//!
//! # A connection is placed once
//!
//! The kernel takes a whole connection, not single records, and does not
//! give one back. So the choice is made per connection, when it is ready to
//! be handed over: [`place`] says where its records go, and it stays there.
//! A connection that stays in userspace is then routed between the
//! backends record by record like any other.
//!
//! With load-aware routing [enabled](super::enable), each kind of record
//! work has a stream of its own here, with two channels, the kernel (the
//! primary) and userspace (its one alternate), and the controller of the
//! other streams: while writes to the kernel cost more than they usually
//! do, new connections stay in userspace to measure it (the first 64 of
//! them until four of their writes were timed, then one in eight), and if
//! it measures cheaper a growing share of the new connections stays there,
//! until the kernel has recovered. With routing disabled every connection
//! is placed with the kernel while it is active.
//!
//! # What is measured
//!
//! This crate does not see the socket, so the driver reports the costs
//! ([`sample`], [`Sample::done`]): for a timed write, the bytes of
//! application data the socket accepted and the time it took, measured the
//! same way for both places, from the plaintext to the bytes TCP has
//! taken. For userspace that is the encryption by a backend and the
//! `send`; for the kernel it is the `send` that encrypts. Only costs
//! measured alike can be compared, and a cost that includes waiting for
//! the peer says nothing about either place: `browntls-ktls` reports the
//! processor time of the calling thread, which leaves the waiting out.
//!
//! # Limits
//!
//! * Only new connections move. A connection keeps its place for life, so
//!   a shift acts as fast as connections come and go, and a process with a
//!   few long-lived connections is never rebalanced.
//! * Userspace is measured by the connections that are there: those kept
//!   back for it, and those the kernel refused. While the kernel is probed
//!   and no such connection makes a write long enough to time, the probe
//!   ends without a comparison, after 64 timed writes to the kernel or
//!   after 4096 new connections if the kernel's writes stop as well, and
//!   the kernel's present cost is accepted, as for a backend nobody holds
//!   a key for.
//! * Only writes are timed. A connection is placed for both directions by
//!   what sending costs.
//! * Writes shorter than 4096 bytes are too short to time, as for the
//!   other streams.
//! * The costs include the kernel's network stack on both sides. Load on
//!   it slows both places alike, which the controller probes once and then
//!   accepts.
//! * What the kernel can do and userspace cannot (sending a file without
//!   copying it, a network device that encrypts) is not part of a cost per
//!   byte written. An application that depends on it hands its connections
//!   to the kernel itself and does not ask [`place`].
//!
//! # Security considerations
//!
//! Where a connection's records are protected changes no byte on the wire:
//! both places implement the same record protection with the same keys.
//! The placement is a function of call counters, lengths of writes and
//! measured durations, as for the other streams; no secret value is read.
//! The kernel holds the traffic keys of the connections placed with it,
//! which is what kernel TLS means, with or without this module. A peer
//! that reads slowly makes writes shorter, not slower per byte of
//! processor time; one that could slow the kernel's writes and not
//! userspace's would move new connections to userspace, where they are
//! protected as they would be without kernel TLS.
//!
//! ```
//! use browntls_crypto::accel::load::kernel;
//!
//! // Not active: connections stay with the backends.
//! assert_eq!(kernel::place(kernel::Records::Aes256Gcm), kernel::Place::Userspace);
//!
//! // The driver found kernel TLS (browntls-ktls does this).
//! kernel::activate();
//! assert_eq!(kernel::place(kernel::Records::Aes256Gcm), kernel::Place::Kernel);
//! for s in kernel::status_all() {
//!     println!("{s}"); // "AES connections (256-bit key): steady on kernel TLS (...)"
//! }
//! kernel::deactivate();
//! ```

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

use super::control::{FULL_SHARE, Params, Phase, Stream, picos};
use super::{CONFIG, Config, ENABLED, StreamStatus, clock};
use crate::Error;
use crate::accel::Algorithm;

/// The kernel's slot in a stream of this module, which is the primary.
const KERNEL: usize = 0;
/// Userspace's slot: the stream's only alternate.
const USERSPACE: usize = 1;
const ALTERNATES: u8 = 1 << USERSPACE;

/// Whether kernel TLS is at the head of the order.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// One stream per [`Records`], in the order of [`Records::ALL`].
static STREAMS: [Stream; 3] = [
    Stream::bulk("connections (128-bit key)"),
    Stream::bulk("connections (256-bit key)"),
    Stream::bulk("connections"),
];

/// The record work that kernel TLS can take over from the backends: the
/// record protection whose backends are routed ([`super`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Records {
    /// AES-128-GCM records.
    Aes128Gcm,
    /// AES-256-GCM records.
    Aes256Gcm,
    /// ChaCha20-Poly1305 records.
    ChaCha20Poly1305,
}

impl Records {
    /// Every kind of record work, in reporting order.
    pub const ALL: [Self; 3] = [Self::Aes128Gcm, Self::Aes256Gcm, Self::ChaCha20Poly1305];

    /// The family whose backends protect these records in userspace.
    #[must_use]
    pub const fn algorithm(self) -> Algorithm {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => Algorithm::Aes,
            Self::ChaCha20Poly1305 => Algorithm::ChaCha20,
        }
    }

    /// The family's stream for these records ([`super::status`]), which
    /// routes the connections that stay in userspace.
    #[must_use]
    pub const fn lane(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => 0,
            Self::Aes256Gcm => 1,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Aes128Gcm => 0,
            Self::Aes256Gcm => 1,
            Self::ChaCha20Poly1305 => 2,
        }
    }

    fn stream(self) -> &'static Stream {
        &STREAMS[self.index()]
    }
}

/// Where the records of a connection are protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Place {
    /// By the kernel, which is handed the connection.
    Kernel,
    /// By this crate's backends, in userspace.
    Userspace,
}

impl Place {
    /// `"kernel TLS"` or `"userspace"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kernel => "kernel TLS",
            Self::Userspace => "userspace",
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::Kernel => KERNEL,
            Self::Userspace => USERSPACE,
        }
    }
}

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Puts kernel TLS at the head of the routing order: [`place`] now sends
/// connections to the kernel. For the driver, once it knows that the
/// kernel can take connections.
pub fn activate() {
    ACTIVE.store(true, Relaxed);
}

/// Takes kernel TLS out of the routing order again: every connection is
/// placed in userspace, as before [`activate`]. Statistics, shifts and
/// fixed shares of this module's streams are forgotten. Connections the
/// kernel has stay with it.
pub fn deactivate() {
    ACTIVE.store(false, Relaxed);
    reset();
}

/// Whether kernel TLS is at the head of the routing order.
#[must_use]
pub fn is_active() -> bool {
    ACTIVE.load(Relaxed)
}

/// Forgets every statistic, shift and fixed share ([`super::disable`]).
pub(super) fn reset() {
    for stream in &STREAMS {
        stream.reset();
    }
}

/// The configuration word while kernel TLS is active and routing enabled.
fn routing() -> Option<u32> {
    if !is_active() {
        return None;
    }
    let cfg = CONFIG.load(Relaxed);
    (cfg & ENABLED != 0).then_some(cfg)
}

/// Where the records of a new connection go.
///
/// [`Place::Userspace`] while kernel TLS is not active. While it is,
/// [`Place::Kernel`], unless load-aware routing is enabled and keeps this
/// connection in userspace: those that measure it while the kernel is
/// probed, the shifted share while it is congested, a share fixed with
/// [`set_fixed`].
///
/// The answer is advice to the driver. A connection the kernel then
/// refuses stays in userspace, and its writes are reported as such.
#[must_use]
pub fn place(records: Records) -> Place {
    if !is_active() {
        return Place::Userspace;
    }
    if CONFIG.load(Relaxed) & ENABLED == 0 {
        return Place::Kernel;
    }
    // Without a schedule (the thread is shutting down) the order decides.
    let Some(word) = clock::next_word() else {
        return Place::Kernel;
    };
    if records.stream().place(word, KERNEL, ALTERNATES) == USERSPACE {
        Place::Userspace
    } else {
        Place::Kernel
    }
}

/// A write that is being timed for the stream of its connection.
#[must_use = "time the write, then report it with `done()`"]
pub struct Sample {
    stream: &'static Stream,
    slot: usize,
    params: Params,
}

impl Sample {
    /// Reports that the write gave `bytes` bytes of application data to
    /// the socket in `nanos` nanoseconds, measured from the plaintext to
    /// the bytes accepted and without time spent waiting (see the
    /// [module documentation](self)). A write that failed is simply not
    /// reported; one that was cut too short to time is ignored, and so is
    /// one that ends after kernel TLS was [deactivated](deactivate) or
    /// routing disabled.
    pub fn done(self, bytes: usize, nanos: u64) {
        // (A report that races with either on another thread can still
        // leave its one sample behind; nothing is placed by it.)
        if routing().is_some() && self.stream.measurable(bytes) {
            self.stream
                .observe(self.slot, bytes, nanos, KERNEL, ALTERNATES, self.params);
        }
    }
}

impl fmt::Debug for Sample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sample")
            .field("stream", &self.stream.name())
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

/// Whether to time a write of `bytes` bytes of application data on a
/// connection whose records are protected at `place`: `Some` for the
/// writes the stream wants timed, which the driver then reports with
/// [`Sample::done`].
///
/// `None` while kernel TLS is not active or load-aware routing is
/// disabled, at the cost of two relaxed atomic loads.
#[must_use]
pub fn sample(records: Records, place: Place, bytes: usize) -> Option<Sample> {
    let cfg = routing()?;
    let stream = records.stream();
    if !stream.measurable(bytes) {
        return None;
    }
    let slot = place.slot();
    stream
        .timed(clock::next_word()?, bytes, slot)
        .then(|| Sample {
            stream,
            slot,
            params: Config::from_bits(cfg).params(),
        })
}

/// The state of the stream that places the connections with `records`, or
/// `None` while kernel TLS is not active.
///
/// The report has the form of the backends' streams: its
/// [`algorithm`](StreamStatus::algorithm) and [`lane`](StreamStatus::lane)
/// name the family's stream that routes the connections which stay in
/// userspace, its primary is `"kernel TLS"` and its one alternate
/// `"userspace"`. Costs are per byte of application data written.
#[must_use]
pub fn status(records: Records) -> Option<StreamStatus> {
    if !is_active() {
        return None;
    }
    let stream = records.stream();
    let snap = stream.snapshot();
    let shifted = snap.ctl.phase != Phase::Steady && routing().is_some();
    let (fast, slow, _) = snap.channels[KERNEL];
    // A share is at most 256, so the percentage is at most 100.
    #[allow(clippy::cast_possible_truncation)]
    let percent = ((snap.ctl.share * 100 + FULL_SHARE / 2) / FULL_SHARE) as u8;
    Some(StreamStatus {
        algorithm: records.algorithm(),
        lane: records.lane(),
        name: stream.name(),
        unit: stream.unit(),
        phase: if shifted {
            snap.ctl.phase
        } else {
            Phase::Steady
        },
        primary: Place::Kernel.name(),
        alternate: shifted.then_some(Place::Userspace.name()),
        shifted_percent: if shifted { percent } else { 0 },
        primary_cost: picos(fast),
        baseline_cost: picos(slow),
        alternate_cost: shifted.then(|| picos(snap.channels[USERSPACE].0)).flatten(),
        alternates: 1,
    })
}

/// The state of every stream of this module; nothing while kernel TLS is
/// not active.
pub fn status_all() -> impl Iterator<Item = StreamStatus> {
    Records::ALL.into_iter().filter_map(status)
}

/// Keeps `percent` of the new connections with `records` in userspace,
/// whatever the measurements say, until [`clear_fixed`],
/// [`deactivate`] or [`super::disable`]. For experiments and tests. The
/// share is the probability that a connection is kept.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] when kernel TLS is not active, when
/// load-aware routing is disabled, or when `percent` exceeds 100.
pub fn set_fixed(records: Records, percent: u8) -> Result<(), Error> {
    if routing().is_none() || percent > 100 {
        return Err(Error::Unsupported);
    }
    records
        .stream()
        .fix(KERNEL, USERSPACE, u32::from(percent) * FULL_SHARE / 100);
    Ok(())
}

/// Ends a share set by [`set_fixed`]; the controller takes over again.
pub fn clear_fixed(records: Records) {
    records.stream().release();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accel::Backends;

    /// Below the kernel, a family's backends with dedicated instructions
    /// come before those with SIMD alone, and the portable one is last.
    fn dedicated_then_simd<B: Backends + fmt::Debug>() {
        let rank = |b: &B| match (b.uses().dedicated, b.uses().simd) {
            (true, _) => 0,
            (false, true) => 1,
            (false, false) => 2,
        };
        assert!(B::PREFERENCE.is_sorted_by_key(rank), "{:?}", B::PREFERENCE);
    }

    #[test]
    fn the_order_below_the_kernel_is_dedicated_then_simd() {
        dedicated_then_simd::<crate::aes::Backend>();
        dedicated_then_simd::<crate::chacha::Backend>();
    }

    #[test]
    fn records_name_their_family_stream() {
        for (i, records) in Records::ALL.into_iter().enumerate() {
            assert_eq!(records.index(), i);
            let lanes = super::super::lanes(records.algorithm());
            assert!(records.lane() < lanes, "{records:?}");
            assert_eq!(records.stream().unit(), "byte");
        }
        // The streams of one family are told apart as the family's are.
        for records in Records::ALL {
            let family = super::super::status(records.algorithm(), records.lane());
            assert_eq!(
                family.and_then(|s| s.name.strip_prefix("records")),
                records.stream().name().strip_prefix("connections"),
                "{records:?}"
            );
        }
        assert_eq!(std::format!("{}", Place::Kernel), "kernel TLS");
        assert_eq!(std::format!("{}", Place::Userspace), "userspace");
        assert_ne!(Place::Kernel.slot(), Place::Userspace.slot());
        assert_eq!(ALTERNATES & (1 << KERNEL), 0);
    }
}
