//! Certificate revocation policy and transport-independent OCSP queries.
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
//! [`RevocationStatus::Indeterminate`]: RevocationStatus::Indeterminate
//! [`RevocationCheck::Pending`]: RevocationCheck::Pending

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::conn::{Context, State};
use crate::enums::AlertDescription;
use crate::error::Error;

mod http;
pub(crate) mod policy;
#[cfg(feature = "std")]
mod staple;

pub use http::OcspHttpRequest;
#[cfg(feature = "std")]
pub use policy::SharedRevocationData;
pub use policy::{
    CtLogKey, RevocationData, RevocationDataError, RevocationDataSource, RevocationDigests,
    RevocationPolicy,
};
#[cfg(feature = "std")]
pub use staple::{ServerStapleResolver, StapleInstall, StapleQuery};

/// Stapled status and SCT data for one certificate as sent by the peer.
#[derive(Clone, Copy, Debug, Default)]
pub struct CertificateEvidence<'a> {
    /// DER-encoded OCSP response, if the peer supplied one.
    pub ocsp: Option<&'a [u8]>,
    /// TLS-encoded SCT list, if the peer supplied one.
    pub scts: Option<&'a [u8]>,
    /// The `extension_data` of the `transparency_info` extension (RFC 9162
    /// §6.5) that delivered this certificate's Certificate Transparency
    /// 2.0 items, if the peer sent one: a `TransItemList`, or empty or an
    /// empty list (`00 00`), which §6.5 allows. Only a server's end-entity
    /// entry carries it. The list is well formed but not verified.
    pub transparency_info: Option<&'a [u8]>,
}

/// Stapled evidence in Certificate message order, starting with the leaf.
///
/// An empty slice means that no evidence was supplied. Entries missing from
/// the end of the slice likewise carry no evidence.
pub type PeerEvidence<'a> = &'a [CertificateEvidence<'a>];

/// The result of the configured revocation policy for an authenticated peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RevocationStatus {
    /// Fresh, authenticated evidence satisfied the configured policy.
    Good,
    /// Evidence was incomplete and explicit best-effort policy allowed it.
    Indeterminate,
}

/// A certificate status request awaiting transport.
///
/// Responder URLs originate in the certificate. Authorize the destination
/// for this issuer before making a request, including the address dialed.
#[derive(Clone)]
pub struct RevocationQuery {
    id: u64,
    issuer_key_hash: [u8; 32],
    responder_urls: Vec<String>,
    request_der: Vec<u8>,
}

impl fmt::Debug for RevocationQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationQuery")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl RevocationQuery {
    fn new(issuer_key_hash: [u8; 32], responder_urls: Vec<String>, request_der: Vec<u8>) -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed) as u64,
            issuer_key_hash,
            responder_urls,
            request_der,
        }
    }

    /// Identifies this pending request. Use it only with its originating
    /// connection.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// SHA-256 of the verified issuer's DER SubjectPublicKeyInfo.
    pub fn issuer_key_hash(&self) -> &[u8; 32] {
        &self.issuer_key_hash
    }

    /// Certificate-provided HTTP or HTTPS responder URLs in certificate order.
    pub fn responder_urls(&self) -> &[String] {
        &self.responder_urls
    }

    /// The DER request to send to the authorized responder.
    pub fn request_der(&self) -> &[u8] {
        &self.request_der
    }
}

/// Transport result for the current OCSP request.
#[non_exhaustive]
pub enum RevocationResponse {
    /// The responder's raw DER body. The verifier authenticates it.
    Der(Vec<u8>),
    /// Authorization, transport, or a response deadline prevented the lookup.
    Unavailable,
}

impl fmt::Debug for RevocationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Der(bytes) => f.debug_struct("Der").field("len", &bytes.len()).finish(),
            Self::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// The outcome of certificate path verification with revocation evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum RevocationCheck {
    /// Authentication can proceed. The optional status is absent when no
    /// revocation policy reported a separate status.
    Complete(Option<RevocationStatus>),
    /// Authentication needs an additional response.
    Pending(Box<PendingRevocation>),
}

impl RevocationCheck {
    /// Creates a pending check that will consume exactly one transport result.
    ///
    /// Only verifiers should construct this. The handler must verify that any
    /// response is authorized, fresh, and bound to the certificate and issuer.
    pub fn pending(
        issuer_key_hash: [u8; 32],
        responder_urls: Vec<String>,
        request_der: Vec<u8>,
        verify: impl FnOnce(RevocationResponse) -> Result<Self, Error> + Send + Sync + 'static,
    ) -> Self {
        Self::Pending(Box::new(PendingRevocation {
            query: RevocationQuery::new(issuer_key_hash, responder_urls, request_der),
            verify: Box::new(verify),
        }))
    }
}

/// A verifier's outstanding request and the verification to run on completion.
pub struct PendingRevocation {
    query: RevocationQuery,
    verify: Box<dyn FnOnce(RevocationResponse) -> Result<RevocationCheck, Error> + Send + Sync>,
}

impl fmt::Debug for PendingRevocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRevocation")
            .field("query", &self.query)
            .finish_non_exhaustive()
    }
}

impl PendingRevocation {
    /// The query that the caller may transport.
    pub fn query(&self) -> &RevocationQuery {
        &self.query
    }

    /// Consumes the request and verifies the supplied result.
    pub fn resolve(self, response: RevocationResponse) -> Result<RevocationCheck, Error> {
        (self.verify)(response)
    }
}

/// Installs the remaining authentication step, suspending it if necessary.
pub(crate) fn finish_or_pause<Data, F>(
    cx: &mut Context<'_, Data>,
    check: RevocationCheck,
    finish: F,
) -> Result<Box<dyn State<Data>>, Error>
where
    F: FnOnce(
            &mut Context<'_, Data>,
            Option<RevocationStatus>,
        ) -> Result<Box<dyn State<Data>>, Error>
        + Send
        + Sync
        + 'static,
{
    match check {
        RevocationCheck::Complete(status) => finish(cx, status),
        RevocationCheck::Pending(pending) => {
            cx.common.pending_revocation = Some(pending);
            Ok(Box::new(WaitForRevocation(finish)))
        }
    }
}

struct WaitForRevocation<F>(F);

impl<Data, F> State<Data> for WaitForRevocation<F>
where
    F: FnOnce(
            &mut Context<'_, Data>,
            Option<RevocationStatus>,
        ) -> Result<Box<dyn State<Data>>, Error>
        + Send
        + Sync,
{
    fn handle(
        self: Box<Self>,
        cx: &mut Context<'_, Data>,
        _message: crate::msgs::message::Message<'_>,
    ) -> Result<Box<dyn State<Data>>, Error> {
        Err(cx.common.send_fatal_alert(
            AlertDescription::InternalError,
            Error::general("handshake input processed during revocation verification"),
        ))
    }

    fn resume_revocation(
        self: Box<Self>,
        cx: &mut Context<'_, Data>,
        status: Option<RevocationStatus>,
    ) -> Result<Box<dyn State<Data>>, Error> {
        (self.0)(cx, status)
    }
}

pub(crate) fn require_local(mut check: RevocationCheck) -> Result<Option<RevocationStatus>, Error> {
    loop {
        match check {
            RevocationCheck::Complete(status) => return Ok(status),
            RevocationCheck::Pending(pending) => {
                check = pending.resolve(RevocationResponse::Unavailable)?;
            }
        }
    }
}

pub(crate) fn leaf_evidence(evidence: PeerEvidence<'_>) -> CertificateEvidence<'_> {
    evidence.first().copied().unwrap_or_default()
}
