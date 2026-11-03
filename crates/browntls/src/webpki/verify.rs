//! Handshake signature verification and the algorithm table a provider supplies.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{
    CertificateDer, EndEntityCert, ServerName, SignatureVerificationAlgorithm, TrustAnchor,
    UnixTime,
};

use super::pki_error;
use crate::enums::SignatureScheme;
use crate::error::{Error, PeerMisbehaved};
use crate::verify::{DigitallySignedStruct, HandshakeSignatureValid};

/// The signature verification algorithms a provider offers, and how TLS
/// signature schemes map onto them.
#[derive(Clone, Copy)]
pub struct WebPkiSupportedAlgorithms {
    /// Every algorithm, used for certificate path signatures.
    pub all: &'static [&'static dyn SignatureVerificationAlgorithm],

    /// For each TLS scheme, the algorithms that verify it (several when one
    /// scheme covers several key sizes, e.g. ECDSA P-256 and P-384 with
    /// SHA-256).
    pub mapping: &'static [(
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    )],
}

impl WebPkiSupportedAlgorithms {
    /// The schemes in `mapping`, in order.
    pub fn supported_schemes(&self) -> Vec<SignatureScheme> {
        self.mapping.iter().map(|(scheme, _)| *scheme).collect()
    }

    /// The algorithms for `scheme`.
    fn convert_scheme(
        &self,
        scheme: SignatureScheme,
    ) -> Result<&[&'static dyn SignatureVerificationAlgorithm], Error> {
        self.mapping
            .iter()
            .find(|(s, _)| *s == scheme)
            .map(|(_, algs)| *algs)
            .ok_or_else(|| PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
    }

    /// Whether every algorithm claims FIPS validation.
    pub fn fips(&self) -> bool {
        self.all.iter().all(|alg| alg.fips())
            && self
                .mapping
                .iter()
                .all(|(_, algs)| algs.iter().all(|alg| alg.fips()))
    }
}

impl fmt::Debug for WebPkiSupportedAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPkiSupportedAlgorithms")
            .field("all", &self.all)
            .field("mapping", &self.supported_schemes())
            .finish()
    }
}

/// A certificate parsed far enough to verify signatures with its key.
#[derive(Debug)]
pub struct ParsedCertificate<'a>(pub(crate) EndEntityCert<'a>);

impl<'a> TryFrom<&'a CertificateDer<'a>> for ParsedCertificate<'a> {
    type Error = Error;

    fn try_from(value: &'a CertificateDer<'a>) -> Result<Self, Self::Error> {
        EndEntityCert::try_from(value).map(Self).map_err(pki_error)
    }
}

impl ParsedCertificate<'_> {
    /// The certificate's `SubjectPublicKeyInfo`.
    pub fn subject_public_key_info(&self) -> browntls_pki::SubjectPublicKeyInfoDer<'_> {
        self.0.subject_public_key_info()
    }
}

/// Verifies that `cert` is valid for `server_name`.
pub fn verify_server_name(
    cert: &ParsedCertificate<'_>,
    server_name: &ServerName<'_>,
) -> Result<(), Error> {
    cert.0
        .verify_is_valid_for_subject_name(server_name)
        .map_err(pki_error)
}

/// Verifies that `cert`, with `intermediates`, chains to one of `roots` at `now`
/// for server authentication.
pub fn verify_server_cert_signed_by_trust_anchor(
    cert: &ParsedCertificate<'_>,
    roots: &super::RootCertStore,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    verify_cert_for_usage(
        cert,
        &roots.roots,
        intermediates,
        now,
        supported_algs,
        browntls_pki::KeyUsage::server_auth(),
        None,
    )
}

pub(crate) fn verify_cert_for_usage(
    cert: &ParsedCertificate<'_>,
    roots: &[TrustAnchor<'_>],
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
    usage: browntls_pki::KeyUsage,
    revocation: Option<browntls_pki::RevocationOptions<'_>>,
) -> Result<(), Error> {
    cert.0
        .verify_for_usage(
            supported_algs,
            roots,
            intermediates,
            now,
            usage,
            revocation,
            None,
        )
        .map(|_| ())
        .map_err(pki_error)
}

/// Verifies a TLS 1.2 handshake signature over `message` with `cert`'s key.
pub fn verify_tls12_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    let possible_algs = supported_schemes.convert_scheme(dss.scheme)?;
    let cert = ParsedCertificate::try_from(cert)?;
    verify_sig_using_any_alg(&cert, possible_algs, message, dss.signature())
}

/// Verifies a TLS 1.3 handshake signature over `message` with `cert`'s key.
///
/// Schemes that TLS 1.3 forbids (RSA PKCS#1, SHA-1) are rejected before any
/// cryptography runs.
pub fn verify_tls13_signature(
    msg: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if !dss.scheme.supported_in_tls13() {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    let possible_algs = supported_schemes.convert_scheme(dss.scheme)?;
    let cert = ParsedCertificate::try_from(cert)?;
    verify_sig_using_any_alg(&cert, possible_algs, msg, dss.signature())
}

/// Verifies a TLS 1.3 handshake signature with a bare `SubjectPublicKeyInfo`
/// (RFC 7250 raw public keys, or a certificate's key extracted by the caller).
pub fn verify_tls13_signature_with_raw_key(
    msg: &[u8],
    spki: &browntls_pki::SubjectPublicKeyInfoDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if !dss.scheme.supported_in_tls13() {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    verify_sig_with_spki(
        spki.as_ref(),
        supported_schemes.convert_scheme(dss.scheme)?,
        msg,
        dss.signature(),
    )
}

/// Verifies a TLS 1.2 handshake signature with a bare `SubjectPublicKeyInfo`.
pub fn verify_tls12_signature_with_raw_key(
    msg: &[u8],
    spki: &browntls_pki::SubjectPublicKeyInfoDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    verify_sig_with_spki(
        spki.as_ref(),
        supported_schemes.convert_scheme(dss.scheme)?,
        msg,
        dss.signature(),
    )
}

/// Tries each algorithm whose `AlgorithmIdentifier` matches the key's.
fn verify_sig_with_spki(
    spki: &[u8],
    algs: &[&dyn SignatureVerificationAlgorithm],
    message: &[u8],
    sig: &[u8],
) -> Result<HandshakeSignatureValid, Error> {
    let (alg_id, key) = crate::x509::split_spki(spki)?;
    let mut matched_key_type = false;
    for alg in algs {
        if alg.public_key_alg_id().as_bytes() != alg_id {
            continue;
        }
        matched_key_type = true;
        if alg.verify_signature(key, message, sig).is_ok() {
            return Ok(HandshakeSignatureValid::assertion());
        }
    }
    Err(if matched_key_type {
        crate::error::CertificateError::BadSignature.into()
    } else {
        crate::error::CertificateError::UnsupportedSignatureAlgorithm.into()
    })
}

fn verify_sig_using_any_alg(
    cert: &ParsedCertificate<'_>,
    algs: &[&dyn SignatureVerificationAlgorithm],
    message: &[u8],
    sig: &[u8],
) -> Result<HandshakeSignatureValid, Error> {
    // Several algorithms may share one scheme (differing in key size); try each.
    let mut last = Error::from(crate::error::CertificateError::BadSignature);
    for alg in algs {
        match cert.0.verify_signature(*alg, message, sig) {
            Ok(()) => return Ok(HandshakeSignatureValid::assertion()),
            Err(browntls_pki::Error::UnsupportedSignatureAlgorithmForPublicKey) => {
                last = pki_error(browntls_pki::Error::UnsupportedSignatureAlgorithmForPublicKey);
            }
            Err(e) => return Err(pki_error(e)),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Dummy;

    impl SignatureVerificationAlgorithm for Dummy {
        fn verify_signature(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<(), browntls_pki::InvalidSignature> {
            Err(browntls_pki::InvalidSignature)
        }
        fn public_key_alg_id(&self) -> browntls_pki::AlgorithmIdentifier {
            browntls_pki::alg_id::ED25519
        }
        fn signature_alg_id(&self) -> browntls_pki::AlgorithmIdentifier {
            browntls_pki::alg_id::ED25519
        }
    }

    static DUMMY: Dummy = Dummy;
    static ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
        all: &[&DUMMY],
        mapping: &[(SignatureScheme::ED25519, &[&DUMMY])],
    };

    #[test]
    fn scheme_mapping() {
        assert_eq!(ALGS.supported_schemes(), [SignatureScheme::ED25519]);
        assert!(ALGS.convert_scheme(SignatureScheme::ED25519).is_ok());
        assert_eq!(
            ALGS.convert_scheme(SignatureScheme::RSA_PSS_SHA256)
                .unwrap_err(),
            Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)
        );
        assert!(!ALGS.fips());
        let dss = DigitallySignedStruct::new(SignatureScheme::RSA_PKCS1_SHA256, alloc::vec![1]);
        assert_eq!(
            verify_tls13_signature(&[], &CertificateDer::from_slice(&[]), &dss, &ALGS).unwrap_err(),
            Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)
        );
    }
}
