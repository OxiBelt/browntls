//! Adapters from the policy to the evidence formats of `browntls-pki`.

use alloc::vec::Vec;

use browntls_pki::crl::CertRevocationList;
use browntls_pki::crlite::{CrliteKey, CrliteSct, CrliteStatus};
use browntls_pki::ocsp::{
    CertIdHashers, CertStatus, OcspError, OcspIssuer, OcspPolicy, VerifiedOcspStatus,
};
use browntls_pki::sct::{CtLog, CtPolicy, SctOptions, SctVerifier};
use browntls_pki::{Cert, CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};

use super::{RevocationData, RevocationDigests};

const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;

/// Plain digest functions of the providers, as `browntls-pki` takes them.
pub(super) mod digests {
    #[cfg(feature = "native")]
    pub(in super::super) fn native_sha256(data: &[u8]) -> [u8; 32] {
        use browntls_crypto::hash::{HashFunction, Sha256};
        let mut out = [0u8; 32];
        out.copy_from_slice(Sha256::digest(data).as_ref());
        out
    }

    #[cfg(feature = "rustcrypto")]
    pub(in super::super) fn rustcrypto_sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(data).into()
    }
}

/// The DER element `tag`, definite length, `contents`.
fn der_element(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = Vec::with_capacity(len.saturating_add(2 + size_of::<usize>()));
    out.push(tag);
    match u8::try_from(len) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let bytes = len.to_be_bytes();
            let significant = bytes.iter().skip_while(|byte| **byte == 0);
            // At most `size_of::<usize>()` octets, so the count fits.
            out.push(0x80 | u8::try_from(significant.clone().count()).unwrap_or(0x7f));
            out.extend(significant);
        }
    }
    out.extend_from_slice(contents);
    out
}

/// The issuer of a certificate in one candidate path.
pub(super) enum IssuerRef<'a> {
    /// The next certificate of the path.
    Cert(&'a Cert<'a>),
    /// The trust anchor that ends the path.
    Anchor(&'a TrustAnchor<'a>),
}

impl<'a> IssuerRef<'a> {
    fn ocsp_issuer(&self) -> OcspIssuer<'a> {
        match self {
            Self::Cert(cert) => OcspIssuer::from_cert(cert),
            Self::Anchor(anchor) => OcspIssuer::from_trust_anchor(anchor),
        }
    }

    /// The issuer's complete DER `SubjectPublicKeyInfo`.
    pub(super) fn spki_der(&self) -> Vec<u8> {
        match self {
            Self::Cert(cert) => cert.subject_public_key_info().as_ref().to_vec(),
            Self::Anchor(anchor) => {
                der_element(TAG_SEQUENCE, anchor.subject_public_key_info.as_ref())
            }
        }
    }

    pub(super) fn to_owned(&self) -> OwnedIssuer {
        match self {
            Self::Cert(cert) => OwnedIssuer::Cert(cert.der().into_owned()),
            Self::Anchor(anchor) => OwnedIssuer::Anchor((*anchor).to_owned()),
        }
    }
}

/// An issuer kept across a suspended verification.
pub(super) enum OwnedIssuer {
    Cert(CertificateDer<'static>),
    Anchor(TrustAnchor<'static>),
}

impl OwnedIssuer {
    /// Runs `f` with the issuer, or returns `None` if it no longer parses.
    pub(super) fn with<R>(&self, f: impl FnOnce(&IssuerRef<'_>) -> R) -> Option<R> {
        match self {
            Self::Cert(der) => {
                let cert = Cert::try_from(der).ok()?;
                Some(f(&IssuerRef::Cert(&cert)))
            }
            Self::Anchor(anchor) => Some(f(&IssuerRef::Anchor(anchor))),
        }
    }
}

/// What an OCSP response establishes about one certificate.
pub(super) enum OcspVerdict<'a> {
    /// Authentic, fresh and "good", with the SCT list it carries.
    Good { sct_list: Option<&'a [u8]> },
    /// Authentic and fresh, with no OCSP status for the certificate.
    Unknown { sct_list: Option<&'a [u8]> },
    /// Authentic and "revoked".
    Revoked,
    /// Not evidence, without being demonstrably wrong: stale, "unknown", or
    /// not verifiable with the digests and CRLs configured here.
    Unusable,
    /// Malformed, not authentic, or not about the certificate.
    Invalid,
}

fn hashers(digests: &RevocationDigests) -> CertIdHashers {
    CertIdHashers {
        sha1: digests.sha1,
        sha256: Some(digests.sha256),
    }
}

fn verdict<'a>(result: Result<VerifiedOcspStatus<'a>, OcspError>) -> OcspVerdict<'a> {
    match result {
        Ok(verified) => match verified.status {
            CertStatus::Good => OcspVerdict::Good {
                sct_list: verified.sct_list,
            },
            CertStatus::Revoked { .. } => OcspVerdict::Revoked,
            CertStatus::Unknown => OcspVerdict::Unknown {
                sct_list: verified.sct_list,
            },
        },
        Err(error) if error.is_stale() => OcspVerdict::Unusable,
        Err(
            OcspError::DigestUnavailable(_)
            | OcspError::DelegateRevocationUnknown
            | OcspError::ResponderUnsuccessful(_),
        ) => OcspVerdict::Unusable,
        Err(_) => OcspVerdict::Invalid,
    }
}

/// Everything needed to authenticate OCSP responses for one certificate.
pub(super) struct OcspContext<'a> {
    pub(super) digests: &'a RevocationDigests,
    pub(super) algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    /// CRLs that may clear a delegated responder certificate.
    pub(super) crls: &'a [&'a CertRevocationList<'a>],
    pub(super) now: UnixTime,
}

impl OcspContext<'_> {
    /// Judges a response the peer stapled for `cert`.
    pub(super) fn stapled<'r>(
        &self,
        response: &'r [u8],
        cert: &Cert<'_>,
        issuer: &IssuerRef<'_>,
    ) -> OcspVerdict<'r> {
        let mut policy = OcspPolicy::stapled(self.algs, hashers(self.digests), self.now);
        policy.delegate_crls = self.crls;
        verdict(browntls_pki::ocsp::verify_response(
            response,
            cert,
            &issuer.ocsp_issuer(),
            &policy,
        ))
    }

    /// Judges a response fetched for `cert` during the handshake.
    pub(super) fn fetched<'r>(
        &self,
        response: &'r [u8],
        cert: &Cert<'_>,
        issuer: &IssuerRef<'_>,
    ) -> OcspVerdict<'r> {
        let mut policy = OcspPolicy::fetched(self.algs, hashers(self.digests), self.now);
        policy.delegate_crls = self.crls;
        verdict(browntls_pki::ocsp::verify_response(
            response,
            cert,
            &issuer.ocsp_issuer(),
            &policy,
        ))
    }
}

/// An OCSP request for one certificate and where it may be sent.
pub(super) struct OcspQuery {
    pub(super) issuer_key_hash: [u8; 32],
    pub(super) request_der: Vec<u8>,
}

/// Builds the request for `cert`, with the SHA-1 identifier RFC 5019
/// responders require when SHA-1 is available.
pub(super) fn ocsp_query(
    digests: &RevocationDigests,
    cert: &Cert<'_>,
    issuer: &IssuerRef<'_>,
) -> Option<OcspQuery> {
    use browntls_pki::ocsp::{CertId, CertIdHash, encode_request};

    let hash = match digests.sha1 {
        Some(_) => CertIdHash::Sha1,
        None => CertIdHash::Sha256,
    };
    let spki = issuer.spki_der();
    let cert_id = CertId::new(hash, &hashers(digests), cert, &spki).ok()?;
    Some(OcspQuery {
        issuer_key_hash: (digests.sha256)(&spki),
        request_der: encode_request(&cert_id, None).ok()?,
    })
}

/// SCT lists delivered outside the certificate.
#[derive(Clone, Copy, Default)]
pub(super) struct DeliveredScts<'a> {
    /// From the TLS `signed_certificate_timestamp` extension.
    pub(super) tls: Option<&'a [u8]>,
    /// From an authenticated OCSP response, in TLS encoding.
    pub(super) ocsp: Option<&'a [u8]>,
}

/// Looks `cert` up in the CRLite snapshot of `data`.
///
/// Coverage is decided from the SCTs that verify against the CT logs of
/// `data`. Returns `Some(true)` for revoked, `Some(false)` for good and
/// `None` when the snapshot does not answer.
pub(super) fn crlite_revoked(
    data: &RevocationData,
    digests: &RevocationDigests,
    algs: &[&dyn SignatureVerificationAlgorithm],
    cert: &Cert<'_>,
    issuer: &IssuerRef<'_>,
    delivered: DeliveredScts<'_>,
    now: UnixTime,
) -> Result<Option<bool>, browntls_pki::Error> {
    let logs: Vec<CtLog<'_>> = data
        .ct_logs()
        .iter()
        .filter_map(|log| log.to_ct_log(digests).ok())
        .collect();
    let ct_policy = CtPolicy {
        logs: &logs,
        supported_sig_algs: algs,
        sha256: digests.sha256,
        options: SctOptions::default(),
    };
    let issuer_spki = issuer.spki_der();
    let Ok(mut verifier) = SctVerifier::new(&ct_policy, cert, Some(&issuer_spki), now) else {
        return Ok(None);
    };
    // A source that is malformed or over a limit contributes no timestamp.
    // The timestamps verified before a limit was reached remain usable.
    check_sct_budget(verifier.verify_embedded())?;
    if let Some(list) = delivered.tls {
        check_sct_budget(verifier.verify_tls_extension(list))?;
    }
    if let Some(list) = delivered.ocsp {
        check_sct_budget(verifier.verify_ocsp_extension(&der_element(TAG_OCTET_STRING, list)))?;
    }
    let scts: Vec<CrliteSct> = verifier
        .verified()
        .iter()
        .map(|sct| CrliteSct::from_verified(*sct.log_id(), sct.timestamp_ms()))
        .collect();

    let issuer_hash = (digests.sha256)(&issuer_spki);
    let serial = cert.serial();
    let mut issuer_serial = Vec::with_capacity(issuer_hash.len().saturating_add(serial.len()));
    issuer_serial.extend_from_slice(&issuer_hash);
    issuer_serial.extend_from_slice(serial);
    let key = CrliteKey::new(issuer_hash, serial, (digests.sha256)(&issuer_serial));
    Ok(match data.crlite().status(&key, &scts, now) {
        CrliteStatus::Revoked => Some(true),
        CrliteStatus::Good => Some(false),
        CrliteStatus::NotEnrolled
        | CrliteStatus::NotCovered
        | CrliteStatus::Expired
        | CrliteStatus::NotYetEffective
        | CrliteStatus::Missing => None,
    })
}

fn check_sct_budget(
    outcome: Result<browntls_pki::sct::SctReport, browntls_pki::sct::SctError>,
) -> Result<(), browntls_pki::Error> {
    use browntls_pki::sct::SctError::{
        ListTooLarge, SctTooLarge, SignatureBudgetExceeded, TooManyScts,
    };
    match outcome {
        Err(ListTooLarge | SctTooLarge | SignatureBudgetExceeded | TooManyScts) => {
            Err(browntls_pki::Error::MaximumSignatureChecksExceeded)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_element_lengths() {
        assert_eq!(der_element(0x04, &[1, 2]), [0x04, 0x02, 1, 2]);
        assert_eq!(der_element(0x30, &[0; 0x7f])[..2], [0x30, 0x7f]);
        assert_eq!(der_element(0x30, &[0; 0x80])[..3], [0x30, 0x81, 0x80]);
        assert_eq!(
            der_element(0x30, &[0; 0x1234])[..4],
            [0x30, 0x82, 0x12, 0x34]
        );
    }
}
