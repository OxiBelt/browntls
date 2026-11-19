//! A validated full filter with its ordered deltas.

use alloc::vec::Vec;

use super::{
    CrliteError, CrliteFilter, CrliteFilterStatus, CrliteKey, CrliteLimit, CrliteLimits, CrliteSct,
    CrliteStatus,
};
use crate::UnixTime;

/// One encoded filter and the time its publisher made it effective.
#[derive(Clone, Copy, Debug)]
pub struct CrliteLayer<'a> {
    /// When the publisher made this filter effective, as stated by the
    /// authenticated distribution channel.
    pub effective: UnixTime,
    /// The filter in Clubcard encoding V3 or V4.
    pub clubcard: &'a [u8],
}

/// One delta filter and its position after the full filter.
#[derive(Clone, Copy, Debug)]
pub struct CrliteDelta<'a> {
    /// The position of this delta in the publisher's sequence of deltas for
    /// the full filter: 1 for the first delta, 2 for the next, and so on.
    /// The caller derives it from the authenticated distribution channel.
    pub number: u32,
    /// The delta filter and its effective time.
    pub layer: CrliteLayer<'a>,
}

/// Everything a [`CrliteSnapshot`] is built from.
///
/// All of it must come from a channel the caller has authenticated; see the
/// [module documentation](super).
#[derive(Clone, Copy, Debug)]
pub struct CrliteSnapshotSource<'a> {
    /// A number that grows with every snapshot the caller installs.
    pub generation: u64,
    /// The time from which the snapshot must no longer vouch for a
    /// certificate.
    pub expiry: UnixTime,
    /// The full filter.
    pub full: CrliteLayer<'a>,
    /// The delta filters that follow the full filter, in sequence: the
    /// delta numbered 1 first, without gaps.
    pub deltas: &'a [CrliteDelta<'a>],
    /// The number of the newest delta that the authenticated distribution
    /// channel lists for the full filter, or 0 if it lists none.
    ///
    /// The snapshot is rejected unless `deltas` ends with exactly this
    /// delta. Without it, a delta withheld from the end of the sequence
    /// would be indistinguishable from one not yet published.
    pub delta_tip: u32,
}

/// A full CRLite filter and its deltas, validated as one unit.
///
/// A snapshot is immutable, `Send` and `Sync`. To update, build a new
/// snapshot with a larger generation and replace the old one as a whole.
#[derive(Debug)]
pub struct CrliteSnapshot {
    generation: u64,
    expiry: UnixTime,
    effective: UnixTime,
    /// The full filter followed by the deltas, oldest first. Never empty.
    layers: Vec<CrliteFilter>,
}

impl CrliteSnapshot {
    /// Decodes every filter of `source` and validates the snapshot.
    ///
    /// Beyond the checks of [`CrliteFilter::decode`]:
    ///
    /// * the deltas must be numbered 1, 2, 3, ... in the order given, so a
    ///   delta missing from the middle, a repeated delta and a reordered
    ///   delta are all detected
    ///   ([`CrliteError::DeltaOutOfSequence`]);
    /// * the last delta must be the one numbered
    ///   [`CrliteSnapshotSource::delta_tip`], so a delta missing from the
    ///   end is detected ([`CrliteError::DeltaTipMismatch`]);
    /// * the effective times must increase strictly from the full filter
    ///   through the deltas;
    /// * the expiry must be later than the newest effective time.
    ///
    /// # Errors
    ///
    /// Returns the first violation found; nothing is retained on failure.
    pub fn new(
        source: &CrliteSnapshotSource<'_>,
        limits: &CrliteLimits,
    ) -> Result<Self, CrliteError> {
        if source.deltas.len() > limits.max_deltas {
            return Err(CrliteError::LimitExceeded(CrliteLimit::Deltas));
        }

        // Check completeness, order and sizes of all layers before decoding
        // any of them.
        for (expected, delta) in (1..).zip(source.deltas) {
            if usize::try_from(delta.number) != Ok(expected) {
                return Err(CrliteError::DeltaOutOfSequence);
            }
        }
        if usize::try_from(source.delta_tip) != Ok(source.deltas.len()) {
            return Err(CrliteError::DeltaTipMismatch);
        }
        let mut effective = source.full.effective;
        let mut total_len = source.full.clubcard.len();
        for delta in source.deltas {
            if delta.layer.effective <= effective {
                return Err(CrliteError::LayerOutOfOrder);
            }
            effective = delta.layer.effective;
            total_len = total_len.saturating_add(delta.layer.clubcard.len());
        }
        if source.expiry <= effective {
            return Err(CrliteError::ExpiryNotAfterEffective);
        }
        if total_len > limits.max_total_len {
            return Err(CrliteError::LimitExceeded(CrliteLimit::TotalLen));
        }

        let mut layers = Vec::new();
        layers
            .try_reserve_exact(source.deltas.len().saturating_add(1))
            .map_err(|_| CrliteError::AllocationFailed)?;
        layers.push(CrliteFilter::decode(source.full.clubcard, limits)?);
        for delta in source.deltas {
            layers.push(CrliteFilter::decode(delta.layer.clubcard, limits)?);
        }

        Ok(Self {
            generation: source.generation,
            expiry: source.expiry,
            effective,
            layers,
        })
    }

    /// The generation the snapshot was built with.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The time from which the snapshot no longer vouches for a certificate.
    #[must_use]
    pub const fn expiry(&self) -> UnixTime {
        self.expiry
    }

    /// The effective time of the newest filter in the snapshot.
    #[must_use]
    pub const fn effective(&self) -> UnixTime {
        self.effective
    }

    /// Number of delta filters in the snapshot, which is also the number of
    /// its newest delta ([`CrliteSnapshotSource::delta_tip`]).
    #[must_use]
    pub fn delta_count(&self) -> usize {
        self.layers.len().saturating_sub(1)
    }

    /// Whether `now` is at or past the expiry.
    #[must_use]
    pub fn is_expired(&self, now: UnixTime) -> bool {
        now >= self.expiry
    }

    /// Whether this snapshot has a strictly larger generation than `other`.
    #[must_use]
    pub const fn supersedes(&self, other: &Self) -> bool {
        self.generation > other.generation
    }

    /// Looks up one certificate in every filter of the snapshot.
    ///
    /// The answers of the filters combine by precedence:
    ///
    /// 1. [`CrliteStatus::Revoked`] if any filter encodes the certificate as
    ///    revoked. A later delta that calls the certificate good does not
    ///    override this, and neither does expiry: a revocation the publisher
    ///    once asserted stays asserted.
    /// 2. [`CrliteStatus::Expired`] if `now` is at or past the expiry.
    /// 3. [`CrliteStatus::Good`] if any filter covers the certificate and
    ///    has data for its issuer.
    /// 4. [`CrliteStatus::NotEnrolled`] if any filter covers the certificate.
    /// 5. [`CrliteStatus::NotCovered`] otherwise.
    ///
    /// # Time
    ///
    /// From the expiry on, the
    /// snapshot never answers [`CrliteStatus::Good`],
    /// [`CrliteStatus::NotEnrolled`] or [`CrliteStatus::NotCovered`]: stale
    /// data must not vouch for a certificate or look like a current gap.
    /// It still answers [`CrliteStatus::Revoked`], which is the conservative
    /// reading of data the caller authenticated.
    ///
    /// Before the snapshot's effective time, it reports an authenticated
    /// revocation or [`CrliteStatus::NotYetEffective`].
    ///
    /// Work is the work of [`CrliteFilter::status`] times the number of
    /// filters, which [`CrliteLimits::max_deltas`] bounds.
    #[must_use]
    pub fn status(&self, key: &CrliteKey<'_>, scts: &[CrliteSct], now: UnixTime) -> CrliteStatus {
        let mut good = false;
        let mut covered = false;
        for layer in &self.layers {
            match layer.status(key, scts) {
                CrliteFilterStatus::Revoked => return CrliteStatus::Revoked,
                CrliteFilterStatus::Good => good = true,
                CrliteFilterStatus::NotEnrolled => covered = true,
                CrliteFilterStatus::NotCovered => {}
            }
        }
        if self.is_expired(now) {
            CrliteStatus::Expired
        } else if now < self.effective {
            CrliteStatus::NotYetEffective
        } else if good {
            CrliteStatus::Good
        } else if covered {
            CrliteStatus::NotEnrolled
        } else {
            CrliteStatus::NotCovered
        }
    }

    /// [`Self::status`] of the installed snapshot, or
    /// [`CrliteStatus::Missing`] when there is none.
    #[must_use]
    pub fn status_of(
        snapshot: Option<&Self>,
        key: &CrliteKey<'_>,
        scts: &[CrliteSct],
        now: UnixTime,
    ) -> CrliteStatus {
        match snapshot {
            Some(snapshot) => snapshot.status(key, scts, now),
            None => CrliteStatus::Missing,
        }
    }
}
