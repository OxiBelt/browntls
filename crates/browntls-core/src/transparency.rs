//! Certificate Transparency version 2.0 (RFC 9162) in TLS: the
//! `transparency_info` extension and the client's compliance policy.
//!
//! # Wire
//!
//! A client offers an empty `transparency_info` extension (§6.5) when its
//! certificate verifier asks for it
//! ([`ServerCertVerifier::requests_transparency_info`]) or when
//! [`ClientConfig::request_transparency_info`] is set, unless the verifier
//! accepts only raw public keys. A server answers with the `TransItemList`
//! configured on its credential
//! ([`CertifiedKey::set_transparency_info`]): in TLS 1.2 in the
//! ServerHello, in TLS 1.3 on the end entity's CertificateEntry, and only
//! during a full handshake. A resumed session carries no extension and its
//! certificate is not evaluated again: the evaluation of the full
//! handshake stands (§6.5). A TLS 1.2 ServerHello that resumes a session
//! and carries the extension is refused (§8.1.1).
//!
//! RFC 9162 §6.1 defines Certificate Transparency for server certificates
//! only: a server never asks for the extension in a CertificateRequest,
//! refuses it on a client's CertificateEntry, and a client ignores it in a
//! CertificateRequest.
//!
//! # Verification
//!
//! A WebPKI verifier with CT policy requires both `transparency_info` and
//! `status_request` in the effective ClientHello (§8.1.6). It reports
//! [`CertificateError::TransparencyOfferRequired`] if an offer is
//! incomplete or the caller supplies no verification context. A policy
//! wrapper forwards both the request hook and
//! [`ServerCertVerifier::verify_server_cert_with_context`].
//! Standalone evidence checks use [`LocalEvidence`].
//!
//! The client hands the received list to its verifier as
//! [`CertificateEvidence::transparency_info`] of the end entity. The
//! built-in [`WebPkiServerVerifier`] verifies Certificate Transparency 2.0
//! when built with
//! [`ServerCertVerifierBuilder::with_certificate_transparency`] and
//! [`CtV2Requirements`]: after the certificate path is validated, the
//! SCTs, signed tree heads and inclusion proofs of the three delivery
//! mechanisms of RFC 9162 §6 (the TLS extension, the `transparency_info`
//! single extension of a stapled OCSP response that authenticates for the
//! end entity, and the certificate's 1.3.101.75 extension) are verified
//! with [`CtV2Verifier`] against the configured logs, and the handshake
//! fails with [`CertificateError::InsufficientTransparency`] when too few
//! verified SCTs or distinct logs remain. What was verified is reported as
//! a [`TransparencyStatus`] by `peer_transparency_status` of
//! `ClientConnection` and [`UnbufferedClientConnection`].
//!
//! The raw list the server sent is available, unverified, from their
//! `peer_transparency_info` (with or without a policy), for applications
//! that verify it themselves with
//! [`pki_types::transparency`](crate::pki_types::transparency).
//!
//! [`ServerCertVerifier::requests_transparency_info`]: crate::client::danger::ServerCertVerifier::requests_transparency_info
//! [`ServerCertVerifier::verify_server_cert_with_context`]: crate::client::danger::ServerCertVerifier::verify_server_cert_with_context
//! [`LocalEvidence`]: crate::client::danger::ServerCertVerificationContext::LocalEvidence
//! [`ClientConfig::request_transparency_info`]: crate::ClientConfig::request_transparency_info
//! [`CertifiedKey::set_transparency_info`]: crate::sign::CertifiedKey::set_transparency_info
//! [`CertificateEvidence::transparency_info`]: crate::revocation::CertificateEvidence::transparency_info
//! [`WebPkiServerVerifier`]: crate::client::WebPkiServerVerifier
//! [`ServerCertVerifierBuilder::with_certificate_transparency`]: crate::client::ServerCertVerifierBuilder::with_certificate_transparency
//! [`CtV2Verifier`]: browntls_pki::transparency::CtV2Verifier
//! [`CertificateError::InsufficientTransparency`]: crate::CertificateError::InsufficientTransparency
//! [`CertificateError::TransparencyOfferRequired`]: crate::CertificateError::TransparencyOfferRequired
//! [`UnbufferedClientConnection`]: crate::client::UnbufferedClientConnection

use alloc::vec::Vec;

use browntls_pki::transparency::{CtV2Log, LogId, LogSignatureAlgorithm, TrustedTreeHead};
pub use browntls_pki::transparency::{CtV2Options, TransparencyError, TreeHead};

use crate::revocation::RevocationDigests;
use crate::webpki::VerifierBuilderError;

/// A Certificate Transparency 2.0 log a client trusts, owned: its log ID,
/// the contents of its `OBJECT IDENTIFIER` (RFC 9162 §4.4), its public key
/// as a DER `SubjectPublicKeyInfo` (P-256 or Ed25519, §10.2.2) and,
/// optionally, the window of SCT timestamps it is trusted for.
///
/// The ID and key are checked when the verifier is built
/// ([`ServerCertVerifierBuilder::build`](crate::client::ServerCertVerifierBuilder::build)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtV2LogConfig {
    log_id: Vec<u8>,
    spki: Vec<u8>,
    window: Option<(u64, u64)>,
}

impl CtV2LogConfig {
    /// A log with ID `log_id` and key `spki`, trusted for every SCT
    /// timestamp.
    pub fn new(log_id: impl Into<Vec<u8>>, spki: impl Into<Vec<u8>>) -> Self {
        Self {
            log_id: log_id.into(),
            spki: spki.into(),
            window: None,
        }
    }

    /// Trusts only SCTs whose timestamp, in milliseconds since the Unix
    /// epoch, is at least `from_ms` and less than `until_ms`, for example
    /// until the log was retired.
    #[must_use]
    pub fn with_timestamp_window(mut self, from_ms: u64, until_ms: u64) -> Self {
        self.window = Some((from_ms, until_ms));
        self
    }

    /// The log ID.
    pub fn log_id(&self) -> &[u8] {
        &self.log_id
    }

    /// The log's key in a form its encodings share, for telling logs
    /// apart: its signature algorithm and, for P-256, the point's
    /// x-coordinate (an uncompressed and a compressed point share it; a
    /// point and its negation, a different key, do too, which only makes
    /// the comparison stricter), for Ed25519 the key itself. A key is
    /// accepted as a complete `SubjectPublicKeyInfo` or as its contents
    /// (see [`CtV2Log::new`]); `None` for a key that is neither.
    pub(crate) fn key_fingerprint(&self) -> Option<(LogSignatureAlgorithm, &[u8])> {
        let algorithm = self.to_log().ok()?.signature_algorithm();
        let contents = match der_tlv(&self.spki) {
            Some((0x30, inner, [])) => inner,
            _ => &self.spki,
        };
        let (0x30, _, rest) = der_tlv(contents)? else {
            return None;
        };
        let (0x03, [0, key @ ..], []) = der_tlv(rest)? else {
            return None;
        };
        Some(match (algorithm, key) {
            (LogSignatureAlgorithm::EcdsaSecp256r1Sha256, [_, point @ ..]) => {
                (algorithm, point.get(..32)?)
            }
            _ => (algorithm, key),
        })
    }

    /// The borrowed log description `browntls-pki` verifies with.
    pub(crate) fn to_log(&self) -> Result<CtV2Log<'_>, TransparencyError> {
        let log = CtV2Log::new(&self.log_id, &self.spki)?;
        Ok(match self.window {
            Some((from_ms, until_ms)) => log.with_timestamp_window(from_ms, until_ms),
            None => log,
        })
    }
}

/// The tag, contents and remainder of the DER TLV `bytes` start with, for
/// lengths below 64 KiB (a log key is far shorter).
fn der_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&len, rest) = rest.split_first()?;
            (usize::from(len), rest)
        }
        0x82 => {
            let (len, rest) = rest.split_at_checked(2)?;
            (usize::from(u16::from_be_bytes([len[0], len[1]])), rest)
        }
        _ => return None,
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// A tree head of a log the application already trusts (for example one
/// it verified and checked for consistency), which inclusion proofs may be
/// verified against without a signed tree head in the delivered lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtV2TrustedTreeHead {
    /// The ID of the log the tree head is of.
    pub log_id: Vec<u8>,
    /// The tree head.
    pub tree_head: TreeHead,
}

impl CtV2TrustedTreeHead {
    pub(crate) fn to_trusted(&self) -> Result<TrustedTreeHead<'_>, TransparencyError> {
        Ok(TrustedTreeHead {
            log_id: LogId::new(&self.log_id)?,
            tree_head: self.tree_head,
        })
    }
}

/// What a client requires of a server certificate's Certificate
/// Transparency 2.0 evidence (RFC 9162 §8.1.6), for
/// [`ServerCertVerifierBuilder::with_certificate_transparency`](crate::client::ServerCertVerifierBuilder::with_certificate_transparency).
///
/// A certificate complies when at least [`Self::min_verified_scts`] SCTs
/// verified for it, from at least [`Self::min_distinct_logs`] distinct
/// logs. With [`Self::require_inclusion`], only SCTs whose inclusion in
/// their log was proven (§8.1.5) count. The defaults require one SCT.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CtV2Requirements {
    /// The trusted logs, each with its own ID and key: the verifier
    /// builder refuses two logs that share either.
    pub logs: Vec<CtV2LogConfig>,
    /// Tree heads the application trusts. One of a log not in
    /// [`Self::logs`] is not used.
    pub trusted_tree_heads: Vec<CtV2TrustedTreeHead>,
    /// How many SCTs must count. Default 1.
    pub min_verified_scts: usize,
    /// From how many distinct logs the counted SCTs must come. Default 1.
    pub min_distinct_logs: usize,
    /// Whether an SCT counts only with proven inclusion. Default `false`.
    pub require_inclusion: bool,
    /// Limits of one verification (per handshake).
    pub options: CtV2Options,
    /// SHA-256, from the crypto provider in use.
    pub digests: RevocationDigests,
}

impl CtV2Requirements {
    /// Requirements trusting `logs`, with the default thresholds and
    /// limits, hashing with the SHA-256 of `digests` (for example
    /// [`RevocationDigests::native`]).
    pub fn new(digests: RevocationDigests, logs: Vec<CtV2LogConfig>) -> Self {
        Self {
            logs,
            trusted_tree_heads: Vec::new(),
            min_verified_scts: 1,
            min_distinct_logs: 1,
            require_inclusion: false,
            options: CtV2Options::default(),
            digests,
        }
    }

    /// Checks every log and tree head, as the verifier builder does, and
    /// that no two logs share an ID or a key, however encoded
    /// ([`CtV2LogConfig::key_fingerprint`]).
    pub(crate) fn check(&self) -> Result<(), VerifierBuilderError> {
        let invalid = VerifierBuilderError::InvalidTransparencyLog;
        for (i, log) in self.logs.iter().enumerate() {
            log.to_log().map_err(invalid)?;
            let key = log
                .key_fingerprint()
                .ok_or(invalid(TransparencyError::MalformedLogKey))?;
            if self.logs[..i]
                .iter()
                .any(|other| other.log_id == log.log_id || other.key_fingerprint() == Some(key))
            {
                return Err(VerifierBuilderError::DuplicateTransparencyLog);
            }
        }
        for head in &self.trusted_tree_heads {
            head.to_trusted().map_err(invalid)?;
        }
        Ok(())
    }
}

/// The Certificate Transparency 2.0 evidence a verifier found for a
/// server certificate (RFC 9162 §8.1), over all delivery mechanisms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransparencyStatus {
    /// The distinct SCTs whose log signature verified.
    pub verified_scts: usize,
    /// The distinct logs of those SCTs.
    pub distinct_logs: usize,
    /// Those SCTs whose inclusion in their log was proven.
    pub inclusion_proven: usize,
}

impl TransparencyStatus {
    /// A status, for verifiers outside this crate.
    pub fn new(verified_scts: usize, distinct_logs: usize, inclusion_proven: usize) -> Self {
        Self {
            verified_scts,
            distinct_logs,
            inclusion_proven,
        }
    }
}
