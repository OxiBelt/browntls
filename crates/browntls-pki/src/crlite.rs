//! CRLite revocation filters in the Mozilla Clubcard encodings V3 and V4.
//!
//! CRLite compresses the revocation status of every certificate known to a
//! set of Certificate Transparency logs into a *Clubcard*: a pair of ribbon
//! filters partitioned by issuer (Schanck, "Clubcards for the WebPKI:
//! smaller certificate revocation tests in theory and practice", 2025). A
//! publisher distributes one full filter and a sequence of smaller delta
//! filters; a client answers "is this certificate revoked?" locally.
//!
//! This module is a first-party decoder and query engine for that format. It
//! contains no cryptography and no network or storage code:
//!
//! * [`CrliteFilter`] decodes one Clubcard (encoding V3 or V4) with every
//!   count, offset, rank and allocation bounded by [`CrliteLimits`].
//! * [`CrliteSnapshot`] validates one full filter and its deltas together
//!   with the generation, expiry and delta numbering the caller obtained
//!   from its authenticated distribution channel. The deltas must be
//!   numbered contiguously and end at the delta the channel lists as newest,
//!   so a delta withheld from the middle or the end is detected. A snapshot
//!   never changes after construction, so a holder can replace it
//!   atomically.
//!
//! # Trust boundaries
//!
//! Filter bytes are treated as untrusted while they are decoded: malformed
//! input yields a [`CrliteError`], never a panic or an unbounded allocation.
//! Decoding establishes only that a filter is well formed. Whether its
//! *content* is true is a property of the channel that delivered it, which
//! the caller must authenticate before building a snapshot.
//!
//! The Clubcard encodings carry no generation, effective time, expiry or
//! delta number. Those values come from the caller
//! ([`CrliteSnapshotSource`]) and must be taken from the same authenticated
//! channel as the filter bytes. In particular the number of the newest
//! delta must be authenticated: it is what lets a snapshot notice that the
//! most recent revocations were withheld.
//!
//! An expired snapshot never vouches for a certificate, but keeps reporting
//! the revocations it holds; a snapshot dated after the caller's clock
//! answers normally. [`CrliteSnapshot::status`] states both rules.
//!
//! A filter only knows certificates that its publisher saw in a CT log
//! within a per-log timestamp interval. Coverage is therefore decided from
//! signed certificate timestamps, and a forged timestamp could move a
//! revoked certificate out of (or an unknown certificate into) the covered
//! set. [`CrliteSct::from_verified`] is the only way to supply a timestamp,
//! and its contract is that the caller has verified the SCT signature
//! against a log it trusts.
//!
//! # Query inputs
//!
//! This crate has no hash function, so the caller computes the two SHA-256
//! digests of a [`CrliteKey`]. The serial number itself is also needed,
//! because a Clubcard lists the serials it could not encode in the filter
//! matrices verbatim.
//!
//! # Differences from the reference decoder
//!
//! Every filter that the reference encoder emits is accepted. This decoder
//! additionally rejects input that the reference tolerates but never
//! produces: trailing bytes after a V3 filter, boolean bytes other than 0
//! and 1, block identifiers that are not 32 bytes, duplicate issuers or
//! logs, coverage intervals with `low > high`, a rank larger than the number
//! of filter columns (on which the reference panics), and V3 sizes that a V4
//! filter could not express.

use core::fmt;

mod filter;
mod reader;
mod snapshot;
mod v3;
mod v4;

pub use filter::CrliteFilter;
pub use snapshot::{CrliteDelta, CrliteLayer, CrliteSnapshot, CrliteSnapshotSource};

/// Resource limits applied while decoding filters and building a snapshot.
///
/// Every allocation made by this module is proportional to the encoded input
/// it was decoded from, so `max_layer_len` and `max_total_len` bound memory;
/// the other limits bound per-query work and reject implausible structure
/// early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrliteLimits {
    /// Largest accepted encoding of a single filter, in bytes.
    pub max_layer_len: usize,
    /// Largest accepted sum of the encodings of all filters of a snapshot.
    pub max_total_len: usize,
    /// Largest accepted number of delta filters in a snapshot.
    pub max_deltas: usize,
    /// Largest accepted number of CT logs in the coverage of one filter.
    pub max_coverage_logs: usize,
    /// Largest accepted number of issuers in one filter.
    pub max_issuers: usize,
    /// Largest accepted rank (number of approximate-filter columns that one
    /// query evaluates).
    pub max_rank: u8,
    /// Largest accepted number of exception serials in one filter.
    pub max_exceptions: usize,
}

impl CrliteLimits {
    /// Limits sized for the filters Mozilla publishes, with generous margin.
    pub const DEFAULT: Self = Self {
        max_layer_len: 64 << 20,
        max_total_len: 128 << 20,
        max_deltas: 128,
        max_coverage_logs: 1024,
        max_issuers: 1 << 16,
        max_rank: 64,
        max_exceptions: 1 << 16,
    };
}

impl Default for CrliteLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The limit of [`CrliteLimits`] that an input exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrliteLimit {
    /// [`CrliteLimits::max_layer_len`].
    LayerLen,
    /// [`CrliteLimits::max_total_len`].
    TotalLen,
    /// [`CrliteLimits::max_deltas`].
    Deltas,
    /// [`CrliteLimits::max_coverage_logs`].
    CoverageLogs,
    /// [`CrliteLimits::max_issuers`].
    Issuers,
    /// [`CrliteLimits::max_rank`].
    Rank,
    /// [`CrliteLimits::max_exceptions`].
    Exceptions,
}

/// Why a filter or snapshot was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CrliteError {
    /// The input exceeds a configured limit.
    LimitExceeded(CrliteLimit),
    /// The encoding ends before a complete filter was read.
    Truncated,
    /// Bytes follow the encoded filter.
    TrailingData,
    /// The leading version byte names an encoding other than V3 or V4.
    UnsupportedVersion(u8),
    /// A field has a value the encoding does not allow.
    Malformed,
    /// The coverage lists the same CT log twice.
    DuplicateLog,
    /// The index lists the same issuer twice.
    DuplicateIssuer,
    /// A coverage interval ends before it starts.
    InvalidCoverageInterval,
    /// An issuer needs more approximate-filter columns than the filter has.
    RankOutOfRange,
    /// A block size or offset cannot be expressed in 32 bits.
    OffsetOutOfRange,
    /// The deltas are not numbered 1, 2, 3, ... in the order given: one is
    /// missing from the middle, repeated or out of place.
    DeltaOutOfSequence,
    /// The last delta is not the one the distribution channel lists as the
    /// newest: deltas are missing from the end, or unlisted ones are present.
    DeltaTipMismatch,
    /// The effective times of the full filter and its deltas are not strictly
    /// increasing.
    LayerOutOfOrder,
    /// The snapshot expiry is not later than its newest effective time.
    ExpiryNotAfterEffective,
    /// Memory for the decoded filter could not be allocated.
    AllocationFailed,
}

impl fmt::Display for CrliteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded(limit) => write!(f, "CRLite limit exceeded: {limit:?}"),
            Self::Truncated => f.write_str("truncated CRLite filter"),
            Self::TrailingData => f.write_str("trailing data after CRLite filter"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported CRLite filter version {version}")
            }
            Self::Malformed => f.write_str("malformed CRLite filter"),
            Self::DuplicateLog => f.write_str("duplicate CT log in CRLite coverage"),
            Self::DuplicateIssuer => f.write_str("duplicate issuer in CRLite index"),
            Self::InvalidCoverageInterval => f.write_str("invalid CRLite coverage interval"),
            Self::RankOutOfRange => f.write_str("CRLite rank exceeds filter columns"),
            Self::OffsetOutOfRange => f.write_str("CRLite block size or offset out of range"),
            Self::DeltaOutOfSequence => f.write_str("CRLite deltas are not contiguously numbered"),
            Self::DeltaTipMismatch => f.write_str("CRLite deltas do not end at the expected delta"),
            Self::LayerOutOfOrder => f.write_str("CRLite layers are not in effective order"),
            Self::ExpiryNotAfterEffective => {
                f.write_str("CRLite snapshot expires before it takes effect")
            }
            Self::AllocationFailed => f.write_str("CRLite filter allocation failed"),
        }
    }
}

impl core::error::Error for CrliteError {}

/// The wire encoding of a decoded filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrliteEncoding {
    /// Version 3: fixed-width little-endian fields with 64-bit lengths.
    V3,
    /// Version 4: big-endian fields with TLS-style length prefixes.
    V4,
}

/// The certificate a query asks about.
#[derive(Clone, Copy, Debug)]
pub struct CrliteKey<'a> {
    pub(crate) issuer: [u8; 32],
    pub(crate) serial: &'a [u8],
    pub(crate) query: [u8; 32],
}

impl<'a> CrliteKey<'a> {
    /// Builds a key from digests the caller computed.
    ///
    /// * `issuer_spki_sha256` is the SHA-256 digest of the DER
    ///   `SubjectPublicKeyInfo` of the certificate's issuer.
    /// * `serial` is the content of the certificate's DER `serialNumber`
    ///   INTEGER (without tag and length, leading zero octet included).
    /// * `issuer_serial_sha256` is the SHA-256 digest of
    ///   `issuer_spki_sha256 || serial`.
    ///
    /// The digests are not checked here. An inconsistent key yields an
    /// arbitrary answer for a certificate that does not exist, so derive all
    /// three values from one validated certificate and its validated issuer.
    #[must_use]
    pub const fn new(
        issuer_spki_sha256: [u8; 32],
        serial: &'a [u8],
        issuer_serial_sha256: [u8; 32],
    ) -> Self {
        Self {
            issuer: issuer_spki_sha256,
            serial,
            query: issuer_serial_sha256,
        }
    }
}

/// A signed certificate timestamp whose signature the caller has verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrliteSct {
    pub(crate) log_id: [u8; 32],
    pub(crate) timestamp_ms: u64,
}

impl CrliteSct {
    /// Records a timestamp taken from a verified SCT.
    ///
    /// `log_id` is the SCT's log identifier (the SHA-256 digest of the log's
    /// public key) and `timestamp_ms` its timestamp in milliseconds since the
    /// Unix epoch (RFC 6962 section 3.2).
    ///
    /// Only pass values from an SCT whose signature over the certificate was
    /// verified with the key of a log the caller trusts. Coverage decisions
    /// rest on these values; see the [module documentation](self).
    #[must_use]
    pub const fn from_verified(log_id: [u8; 32], timestamp_ms: u64) -> Self {
        Self {
            log_id,
            timestamp_ms,
        }
    }
}

/// The answer of a single [`CrliteFilter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrliteFilterStatus {
    /// The certificate is covered and encoded as revoked.
    Revoked,
    /// The certificate is covered and encoded as not revoked.
    Good,
    /// The certificate is covered, but the filter has no data for its issuer.
    NotEnrolled,
    /// No supplied timestamp lies in the filter's coverage.
    NotCovered,
}

/// The answer of a [`CrliteSnapshot`], or of the absence of one.
///
/// Only [`Revoked`](Self::Revoked) and [`Good`](Self::Good) are statements
/// about the certificate. The other variants mean CRLite cannot answer, each
/// for a different reason, so a caller can apply its own fallback policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrliteStatus {
    /// A filter of the snapshot encodes the certificate as revoked.
    Revoked,
    /// A filter covers the certificate and none encodes it as revoked.
    Good,
    /// The certificate is covered, but no filter has data for its issuer.
    NotEnrolled,
    /// No supplied timestamp lies in the coverage of any filter.
    NotCovered,
    /// The snapshot has expired and does not encode the certificate as
    /// revoked.
    Expired,
    /// The snapshot's effective time is ahead of the verification clock.
    NotYetEffective,
    /// No snapshot is installed.
    Missing,
}
