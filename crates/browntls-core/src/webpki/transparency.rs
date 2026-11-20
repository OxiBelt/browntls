//! Certificate Transparency 2.0 (RFC 9162) compliance of a server
//! certificate, for [`WebPkiServerVerifier`](super::WebPkiServerVerifier).

use alloc::vec::Vec;

use browntls_pki::ocsp::{CertIdHashers, OcspIssuer, OcspPolicy, verify_response};
use browntls_pki::transparency::{CtV2Log, CtV2Policy, CtV2Verifier, TrustedTreeHead};
use browntls_pki::{
    Cert, CertRevocationList, CertificateDer, EndEntityCert, KeyUsage,
    SignatureVerificationAlgorithm, TrustAnchor, UnixTime, VerifiedPath,
};

use super::pki_error;
use crate::error::{CertificateError, Error};
use crate::revocation::{PeerEvidence, leaf_evidence};
use crate::transparency::{CtV2Requirements, TransparencyError, TransparencyStatus};

/// What one verification works with besides the certificates.
pub(super) struct Context<'a> {
    pub(super) requirements: &'a CtV2Requirements,
    pub(super) roots: &'a [TrustAnchor<'a>],
    pub(super) algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    /// CRLs that may clear a delegated OCSP responder.
    pub(super) crls: &'a [CertRevocationList<'static>],
}

fn invalid(error: TransparencyError) -> Error {
    CertificateError::InvalidTransparencyEvidence(error).into()
}

/// The issuer of the end entity of a validated path, whose key every
/// version 2 SCT signs the hash of (RFC 9162 §4.7): the path's first
/// intermediate, or its trust anchor.
pub(super) enum Issuer<'p> {
    Intermediate(&'p CertificateDer<'p>),
    Anchor(&'p TrustAnchor<'p>),
}

impl<'p> Issuer<'p> {
    pub(super) fn of(path: &VerifiedPath<'p>) -> Self {
        match path.intermediate_certificates().next() {
            Some(der) => Self::Intermediate(der),
            None => Self::Anchor(path.anchor()),
        }
    }
}

impl Context<'_> {
    /// Verifies the CT 2.0 evidence of `end_entity` and applies the
    /// requirements, for a caller that validated the path without learning
    /// which one validated.
    ///
    /// The path is validated again here, without revocation, to learn the
    /// end entity's issuer (see [`Issuer`]): an issuer that is not part of
    /// a validated path must not be used. A revocation policy may defer
    /// several candidate paths to a live query, so it yields no single
    /// path; this costs a second path building. Without a policy,
    /// [`Self::verify_issued`] takes the issuer of the path that validated.
    pub(super) fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<TransparencyStatus, Error> {
        let ee = EndEntityCert::try_from(end_entity).map_err(pki_error)?;
        let path = ee
            .verify_for_usage(
                self.algs,
                self.roots,
                intermediates,
                now,
                KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(pki_error)?;
        self.verify_issued(&Issuer::of(&path), end_entity, evidence, now)
    }

    /// Verifies the CT 2.0 evidence of `end_entity`, issued by `issuer` in
    /// a validated path, and applies the requirements.
    pub(super) fn verify_issued(
        &self,
        issuer: &Issuer<'_>,
        end_entity: &CertificateDer<'_>,
        evidence: PeerEvidence<'_>,
        now: UnixTime,
    ) -> Result<TransparencyStatus, Error> {
        let issuer_cert;
        let issuer_spki_der;
        let (issuer_spki, ocsp_issuer): (&[u8], _) = match issuer {
            Issuer::Intermediate(der) => {
                issuer_cert = Cert::try_from(*der).map_err(pki_error)?;
                issuer_spki_der = issuer_cert.subject_public_key_info();
                (
                    issuer_spki_der.as_ref(),
                    OcspIssuer::from_cert(&issuer_cert),
                )
            }
            Issuer::Anchor(anchor) => (
                anchor.subject_public_key_info.as_ref(),
                OcspIssuer::from_trust_anchor(anchor),
            ),
        };
        let leaf = Cert::try_from(end_entity).map_err(pki_error)?;

        let req = self.requirements;
        let logs = req
            .logs
            .iter()
            .map(|log| log.to_log())
            .collect::<Result<Vec<CtV2Log<'_>>, _>>()
            .map_err(invalid)?;
        let heads = req
            .trusted_tree_heads
            .iter()
            .map(|head| head.to_trusted())
            .collect::<Result<Vec<TrustedTreeHead<'_>>, _>>()
            .map_err(invalid)?;
        let policy = CtV2Policy {
            logs: &logs,
            trusted_tree_heads: &heads,
            supported_sig_algs: self.algs,
            sha256: req.digests.sha256,
            options: req.options.clone(),
        };
        let mut verifier = CtV2Verifier::new(&policy, &leaf, issuer_spki, now).map_err(invalid)?;

        // RFC 9162 §8.1.1: all three delivery mechanisms. Any error, a
        // malformed list as much as an exhausted budget, fails.
        verifier.verify_embedded().map_err(invalid)?;
        let evidence = leaf_evidence(evidence);
        if let Some(response) = evidence.ocsp.filter(|r| !r.is_empty()) {
            // Only a response that authenticates for this certificate is
            // a source (§7.1.1); any other contributes nothing here, and
            // its status is the revocation policy's concern.
            let crls: Vec<&CertRevocationList<'_>> = self.crls.iter().collect();
            let hashers = CertIdHashers {
                sha1: req.digests.sha1,
                sha256: Some(req.digests.sha256),
            };
            let mut ocsp_policy = OcspPolicy::stapled(self.algs, hashers, now);
            ocsp_policy.delegate_crls = &crls;
            if let Ok(verified) = verify_response(response, &leaf, &ocsp_issuer, &ocsp_policy)
                && let Some(list) = verified.transparency_info
            {
                verifier.verify_ocsp_response(list).map_err(invalid)?;
            }
        }
        if let Some(list) = evidence.transparency_info {
            verifier.verify_tls_extension(list).map_err(invalid)?;
        }

        let verified = verifier.verified();
        // Logs are told apart by key, not by configuration entry: an SCT's
        // signature does not cover its log ID, so the same key under two
        // IDs is one log. The builder refuses such twins already.
        let keys: Vec<_> = req.logs.iter().map(|log| log.key_fingerprint()).collect();
        let key_of = |index: usize| keys.get(index).copied().flatten();
        let mut logs_seen = Vec::new();
        let mut counted_logs = Vec::new();
        let mut counted_scts = 0;
        for sct in verified {
            let key = key_of(sct.log_index());
            if !logs_seen.contains(&key) {
                logs_seen.push(key);
            }
            if req.require_inclusion && sct.inclusion().is_none() {
                continue;
            }
            counted_scts += 1;
            if !counted_logs.contains(&key) {
                counted_logs.push(key);
            }
        }
        if counted_scts < req.min_verified_scts || counted_logs.len() < req.min_distinct_logs {
            return Err(CertificateError::InsufficientTransparency {
                counted_scts,
                distinct_logs: counted_logs.len(),
            }
            .into());
        }
        Ok(TransparencyStatus {
            verified_scts: verified.len(),
            distinct_logs: logs_seen.len(),
            inclusion_proven: verified
                .iter()
                .filter(|sct| sct.inclusion().is_some())
                .count(),
        })
    }
}
