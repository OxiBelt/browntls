//! Application-supplied replay decisions for external-PSK early data.

use core::fmt;

use browntls_pki::UnixTime;

use crate::crypto::hash::{Hash, Output};

/// An opaque, versioned key derived from a verified TLS 1.3 PSK binder.
///
/// The binder authenticates the effective ClientHello and PSK context.
/// The key omits other binders, transport addresses and the cutoff so that
/// changes to those inputs cannot create a new entry for a recorded offer.
pub struct ExternalPskReplayKey(Output);

impl ExternalPskReplayKey {
    pub(crate) fn new(hash: &dyn Hash, verified_binder: &[u8]) -> Self {
        let mut digest = hash.start();
        digest.update(b"browntls external PSK 0-RTT replay key v1\0");
        digest.update(verified_binder);
        Self(digest.finish())
    }
}

impl AsRef<[u8]> for ExternalPskReplayKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for ExternalPskReplayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalPskReplayKey")
            .finish_non_exhaustive()
    }
}

/// The outcome of an atomic replay-policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalPskReplayDecision {
    /// The key was absent and its mark is now committed.
    FirstUse,
    /// The key was already present, including an apparent digest collision.
    Duplicate,
    /// A reliable decision could not be made.
    Unavailable,
}

/// Application policy for accepting TLS 1.3 external-PSK 0-RTT.
///
/// Share a single authoritative replay namespace across all servers accepting
/// the same credential, using the same cutoff. Retain committed marks until
/// all such servers have passed that cutoff, accounting for clock skew.
/// Expire marks only once the corresponding acceptance period has ended.
/// Extending the period requires fresh PSK material, with old marks retained
/// through the old period. After state loss, decline early data for affected
/// credentials until they are replaced or their acceptance period ends.
///
/// Keep decisions bounded in time and storage. A full store, uncertain clock,
/// timeout, or indeterminate commit requires `Unavailable`. This policy
/// guards TLS acceptance and leaves application request deduplication to
/// the application.
pub trait ExternalPskReplayPolicy: fmt::Debug + Send + Sync {
    /// Commits a first-use mark atomically, before the exclusive cutoff.
    ///
    /// With shared state, at most one caller may get `FirstUse` for a key.
    /// Exact digest matches must always use the same record, even during
    /// changes to the cutoff or failures of individual server instances.
    fn check_and_mark(
        &self,
        key: &ExternalPskReplayKey,
        expires_at: UnixTime,
    ) -> ExternalPskReplayDecision;
}
