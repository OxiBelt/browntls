//! The revocation policy shared by the WebPKI server and client verifiers.
//!
//! A [`RevocationPolicy`] decides, for every certificate path the verifier
//! would otherwise accept, whether the certificates it covers are known not
//! to be revoked. It combines four sources of evidence:
//!
//! 1. the CRLs configured on the verifier, checked during path building as
//!    before;
//! 2. OCSP responses the peer stapled to its Certificate message;
//! 3. a CRLite snapshot installed by the application, whose coverage is
//!    decided from signed certificate timestamps verified against the CT
//!    logs installed with it ([`RevocationData`]);
//! 4. optionally, OCSP responses fetched during the handshake.
//!
//! # Decisions
//!
//! * The end-entity certificate is always covered. Intermediates are covered
//!   only with [`RevocationPolicy::check_full_chain`]. Trust anchors never are.
//! * Every local source is consulted for a covered certificate, and an
//!   authenticated "revoked" from any of them wins over "good" from another.
//! * A stapled response for a covered certificate must be well formed,
//!   authentic and about that certificate. Anything else fails the handshake
//!   with [`CertificateError::InvalidOcspResponse`], also in best-effort mode.
//!   A stapled response that is authentic but stale, or that reports the
//!   status "unknown", is not evidence.
//! * A certificate with the TLS feature extension for `status_request`
//!   (RFC 7633, "Must-Staple") must come with a stapled response that
//!   establishes its status. No other source satisfies that requirement.
//! * A path whose covered certificates all have fresh local evidence is
//!   preferred over one that needs a live query.
//! * Without complete evidence the default is to fail with
//!   [`CertificateError::UnknownRevocationStatus`]. With
//!   [`RevocationPolicy::best_effort`] the handshake continues and reports
//!   [`RevocationStatus::Indeterminate`].
//!
//! # Live queries
//!
//! [`RevocationPolicy::with_live_ocsp`] lets the verifier suspend certificate
//! authentication and ask for an OCSP response
//! ([`RevocationCheck::Pending`]). The policy only names candidate
//! responders (the certificate's authority information access URLs) and
//! builds the request. Authorizing a destination and transporting the request
//! is the caller's job. Nothing reports the certificate as verified while a
//! query is outstanding. The number of queries per handshake is bounded, and
//! an answer about a certificate is reused by every path that contains it.
//!
//! Responses to live queries are validated at the time read from the clock
//! given to [`RevocationPolicy::with_live_ocsp`], because the verification time
//! passed to the verifier predates the query.
//!
//! [`CertificateError::InvalidOcspResponse`]: crate::error::CertificateError::InvalidOcspResponse
//! [`CertificateError::UnknownRevocationStatus`]: crate::error::CertificateError::UnknownRevocationStatus
//! [`RevocationStatus::Indeterminate`]: super::RevocationStatus::Indeterminate
//! [`RevocationCheck::Pending`]: super::RevocationCheck::Pending

use core::fmt;

use crate::sync::Arc;
use crate::time_provider::TimeProvider;

mod data;
mod evaluate;
mod live;
mod sources;
#[cfg(test)]
mod tests;

#[cfg(feature = "std")]
pub use data::SharedRevocationData;
pub use data::{CtLogKey, RevocationData, RevocationDataError, RevocationDataSource};
pub(crate) use evaluate::{CrlConfig, PathRequest};

/// Default number of OCSP queries one handshake may issue.
const DEFAULT_LIVE_QUERIES: usize = 2;

/// Largest number of OCSP queries one handshake may be configured to issue:
/// one for each certificate of the longest path the verifier builds.
const MAX_LIVE_QUERIES: usize = 7;

/// One-shot digest functions the policy needs from a cryptography provider.
///
/// SHA-256 identifies issuers to the transport, CT logs and CRLite. SHA-1 is
/// needed for the OCSP certificate identifiers of RFC 5019 responders, where
/// it only names an issuer and is not relied on for collision resistance.
/// Without it, responses that use SHA-1 identifiers are unusable.
#[derive(Clone, Copy)]
pub struct RevocationDigests {
    /// SHA-256 of the input.
    pub sha256: fn(&[u8]) -> [u8; 32],
    /// SHA-1 of the input.
    pub sha1: Option<browntls_pki::ocsp::Sha1Fn>,
}

impl RevocationDigests {
    /// The digests of the built-in provider.
    #[cfg(feature = "native")]
    pub fn native() -> Self {
        Self {
            sha256: sources::digests::native_sha256,
            sha1: Some(sources::digests::native_sha1),
        }
    }

    /// The digests of the RustCrypto provider.
    #[cfg(feature = "rustcrypto")]
    pub fn rustcrypto() -> Self {
        Self {
            sha256: sources::digests::rustcrypto_sha256,
            sha1: Some(sources::digests::rustcrypto_sha1),
        }
    }
}

impl fmt::Debug for RevocationDigests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationDigests")
            .field("sha1", &self.sha1.is_some())
            .finish_non_exhaustive()
    }
}

/// How a WebPKI verifier establishes that certificates are not revoked.
///
/// The default is strict and covers the end-entity certificate: without
/// fresh, authenticated evidence that it is not revoked, verification fails.
/// See the [module documentation](self) for the sources and their order.
#[derive(Clone, Debug)]
pub struct RevocationPolicy {
    pub(crate) digests: RevocationDigests,
    pub(crate) full_chain: bool,
    pub(crate) best_effort: bool,
    pub(crate) data: Option<Arc<dyn RevocationDataSource>>,
    /// The clock for live OCSP responses; live queries are off without it.
    pub(crate) live_clock: Option<Arc<dyn TimeProvider>>,
    pub(crate) max_live_queries: usize,
}

impl RevocationPolicy {
    /// A strict policy for the end-entity certificate that uses the
    /// verifier's CRLs and stapled OCSP responses.
    pub fn new(digests: RevocationDigests) -> Self {
        Self {
            digests,
            full_chain: false,
            best_effort: false,
            data: None,
            live_clock: None,
            max_live_queries: DEFAULT_LIVE_QUERIES,
        }
    }

    /// Also requires a revocation status for every intermediate certificate
    /// of the path.
    pub fn check_full_chain(mut self) -> Self {
        self.full_chain = true;
        self
    }

    /// Accepts a certificate whose status no source could establish and
    /// reports [`RevocationStatus::Indeterminate`](super::RevocationStatus::Indeterminate).
    ///
    /// A revoked certificate, an invalid stapled response and a missing
    /// Must-Staple response still fail verification.
    pub fn best_effort(mut self) -> Self {
        self.best_effort = true;
        self
    }

    /// Consults the CRLite snapshot that `source` holds at the time of each
    /// verification.
    pub fn with_revocation_data(mut self, source: Arc<dyn RevocationDataSource>) -> Self {
        self.data = Some(source);
        self
    }

    /// Asks for OCSP responses during the handshake when local evidence is
    /// incomplete.
    ///
    /// `clock` supplies the time at which those responses are validated. A
    /// clock that reports no time makes every live response unusable.
    pub fn with_live_ocsp(mut self, clock: Arc<dyn TimeProvider>) -> Self {
        self.live_clock = Some(clock);
        self
    }

    /// Limits the live OCSP queries of one handshake to `max_queries`,
    /// between 1 and 7. The default is 2.
    pub fn with_max_live_queries(mut self, max_queries: usize) -> Self {
        self.max_live_queries = max_queries.clamp(1, MAX_LIVE_QUERIES);
        self
    }
}
