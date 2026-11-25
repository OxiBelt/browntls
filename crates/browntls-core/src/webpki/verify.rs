//! Handshake signature verification and the algorithm table a provider
//! supplies.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{
    CertificateDer, EndEntityCert, ReferenceIdentifier, ServerName, ServiceIdentity,
    SignatureVerificationAlgorithm, TrustAnchor, UnixTime,
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

/// Matches the leaf SANs against the caller's RFC 9525 reference set.
///
/// Authenticate the certificate path separately before using the result.
pub fn verify_server_identity<'a>(
    cert: &ParsedCertificate<'_>,
    identity: &'a ServiceIdentity,
) -> Result<&'a ReferenceIdentifier, Error> {
    cert.0.verify_service_identity(identity).map_err(pki_error)
}

/// Verifies that `cert`, with `intermediates`, chains to one of `roots` at
/// `now` for server authentication.
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
    .map(|_| ())
}

/// Validates `cert`'s path for `usage`; returns the path that validated.
pub(crate) fn verify_cert_for_usage<'p>(
    cert: &'p ParsedCertificate<'p>,
    roots: &'p [TrustAnchor<'_>],
    intermediates: &'p [CertificateDer<'p>],
    now: UnixTime,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
    usage: browntls_pki::KeyUsage,
    revocation: Option<browntls_pki::RevocationOptions<'_>>,
) -> Result<browntls_pki::VerifiedPath<'p>, Error> {
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
        .map_err(pki_error)
}

/// Verifies a TLS 1.2 handshake signature over `message` with `cert`'s key.
///
/// The ML-DSA schemes and the RFC 9963 legacy RSASSA-PKCS1-v1_5 schemes
/// are rejected before any cryptography runs, whatever `supported_schemes`
/// maps: they are specified for TLS 1.3 only (`draft-ietf-tls-mldsa-06`;
/// RFC 9963 §3).
pub fn verify_tls12_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme.is_tls13_only() {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    let possible_algs = supported_schemes.convert_scheme(dss.scheme)?;
    let cert = ParsedCertificate::try_from(cert)?;
    verify_sig_using_any_alg(&cert, possible_algs, message, dss.signature())
}

/// Verifies a TLS 1.3 handshake signature over `message` with `cert`'s key.
///
/// Schemes that TLS 1.3 forbids (RSA PKCS#1, SHA-1) are rejected before any
/// cryptography runs. So are the RFC 9963 legacy schemes
/// (`rsa_pkcs1_sha256_legacy` and the like), whatever `supported_schemes`
/// maps: only a client's `CertificateVerify` may use them, which
/// [`verify_tls13_client_signature`] verifies.
pub fn verify_tls13_signature(
    msg: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if !dss.scheme.supported_in_tls13() {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    let possible_algs = tls13_algs(dss.scheme, supported_schemes.convert_scheme(dss.scheme)?);
    let cert = ParsedCertificate::try_from(cert)?;
    verify_sig_using_any_alg(&cert, &possible_algs, msg, dss.signature())
}

/// Verifies the signature of a client's TLS 1.3 `CertificateVerify` over
/// `msg` with `cert`'s key: as [`verify_tls13_signature`], and also with
/// an RFC 9963 legacy scheme (`rsa_pkcs1_sha256_legacy`,
/// `rsa_pkcs1_sha384_legacy`, `rsa_pkcs1_sha512_legacy`) that
/// `supported_schemes` maps. No default table of this crate maps them: see
/// `SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY` of the providers.
///
/// This is for a [`ClientCertVerifier`](crate::verify::ClientCertVerifier)
/// (`WebPkiClientVerifier` uses it). RFC 9963 §3 defines the legacy
/// schemes for the client's `CertificateVerify` only: a server certificate
/// verifier must not call this, and a server accepts such a signature only
/// when its CertificateRequest listed the scheme, which the handshake
/// checks before it calls the verifier.
///
/// The legacy schemes are RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) with an
/// `rsaEncryption` key. The algorithms the providers map them to accept
/// only the exact encoding, `DigestInfo` with the NULL parameters
/// included (RFC 9963 §4).
pub fn verify_tls13_client_signature(
    msg: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if !dss.scheme.supported_in_tls13_client_auth() {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    let possible_algs = tls13_algs(dss.scheme, supported_schemes.convert_scheme(dss.scheme)?);
    let cert = ParsedCertificate::try_from(cert)?;
    verify_sig_using_any_alg(&cert, &possible_algs, msg, dss.signature())
}

/// RFC 9846 §4.3.3: in TLS 1.3 an ECDSA scheme names the curve as well as
/// the hash ("ecdsa_secp256r1_sha256" needs a P-256 key), unlike TLS 1.2
/// where any curve may be paired with any hash. So of the algorithms mapped
/// to an ECDSA scheme only those for its own curve may verify.
fn tls13_algs(
    scheme: SignatureScheme,
    algs: &[&'static dyn SignatureVerificationAlgorithm],
) -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    let curve = match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Some(browntls_pki::alg_id::ECDSA_P256),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Some(browntls_pki::alg_id::ECDSA_P384),
        SignatureScheme::ECDSA_NISTP521_SHA512 => Some(browntls_pki::alg_id::ECDSA_P521),
        _ => None,
    };
    algs.iter()
        .copied()
        .filter(|alg| curve.is_none_or(|curve| alg.public_key_alg_id() == curve))
        .collect()
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
        &tls13_algs(dss.scheme, supported_schemes.convert_scheme(dss.scheme)?),
        msg,
        dss.signature(),
    )
}

/// Verifies the signature of a client's TLS 1.3 `CertificateVerify` with
/// a bare `SubjectPublicKeyInfo` (RFC 7250 raw public keys): as
/// [`verify_tls13_signature_with_raw_key`], and also with an RFC 9963
/// legacy scheme that `supported_schemes` maps. See
/// [`verify_tls13_client_signature`], whose conditions apply. Not for the
/// key of a delegated credential (RFC 9345), which the legacy schemes do
/// not cover.
pub fn verify_tls13_client_signature_with_raw_key(
    msg: &[u8],
    spki: &browntls_pki::SubjectPublicKeyInfoDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if !dss.scheme.supported_in_tls13_client_auth() {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    verify_sig_with_spki(
        spki.as_ref(),
        &tls13_algs(dss.scheme, supported_schemes.convert_scheme(dss.scheme)?),
        msg,
        dss.signature(),
    )
}

/// Verifies a TLS 1.2 handshake signature with a bare `SubjectPublicKeyInfo`.
///
/// As [`verify_tls12_signature`], it rejects the ML-DSA schemes and the
/// RFC 9963 legacy schemes.
pub fn verify_tls12_signature_with_raw_key(
    msg: &[u8],
    spki: &browntls_pki::SubjectPublicKeyInfoDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme.is_tls13_only() {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    verify_sig_with_spki(
        spki.as_ref(),
        supported_schemes.convert_scheme(dss.scheme)?,
        msg,
        dss.signature(),
    )
}

/// Tries each algorithm whose `AlgorithmIdentifier` matches the key's
/// (byte for byte, or by the canonical form of `id-RSASSA-PSS` parameters:
/// `browntls_pki::AlgorithmIdentifier::matches_public_key`, as certificate
/// keys are matched).
fn verify_sig_with_spki(
    spki: &[u8],
    algs: &[&dyn SignatureVerificationAlgorithm],
    message: &[u8],
    sig: &[u8],
) -> Result<HandshakeSignatureValid, Error> {
    let (alg_id, key) = crate::x509::split_spki(spki)?;
    let mut matched_key_type = false;
    for alg in algs {
        if !alg.public_key_alg_id().matches_public_key(alg_id) {
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
    // Several algorithms may share one scheme (differing in key size); try
    // each.
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

#[cfg(all(test, any(feature = "native", feature = "rustcrypto")))]
mod rsa_pkcs1_legacy_tests;

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

    /// The ML-DSA schemes are TLS 1.3-only (`draft-ietf-tls-mldsa-06`): the
    /// TLS 1.2 helpers refuse them before the table or the key is looked
    /// at, even when a table maps them.
    #[test]
    fn tls12_refuses_ml_dsa_schemes_whatever_the_table_maps() {
        static WITH_ML_DSA: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
            all: &[&DUMMY],
            mapping: &[
                (SignatureScheme::ML_DSA_44, &[&DUMMY]),
                (SignatureScheme::ML_DSA_65, &[&DUMMY]),
                (SignatureScheme::ML_DSA_87, &[&DUMMY]),
                (SignatureScheme::ED25519, &[&DUMMY]),
            ],
        };
        let refused =
            Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme);
        let no_cert = CertificateDer::from_slice(&[]);
        let no_key = browntls_pki::SubjectPublicKeyInfoDer::from(&[][..]);
        // The code point decides: a constructed `Unknown` is ML-DSA too.
        for code in [0x0903, 0x0904, 0x0905, 0x0906, 0x0907] {
            assert_eq!(
                SignatureScheme::Unknown(code).is_ml_dsa(),
                (0x0904..=0x0906).contains(&code)
            );
        }
        let dss = DigitallySignedStruct::new(SignatureScheme::Unknown(0x0905), alloc::vec![1]);
        assert_eq!(
            verify_tls12_signature(&[], &no_cert, &dss, &WITH_ML_DSA).unwrap_err(),
            refused
        );
        for scheme in [
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ] {
            assert!(scheme.is_ml_dsa() && scheme.supported_in_tls13());
            let dss = DigitallySignedStruct::new(scheme, alloc::vec![1]);
            assert_eq!(
                verify_tls12_signature(&[], &no_cert, &dss, &WITH_ML_DSA).unwrap_err(),
                refused
            );
            assert_eq!(
                verify_tls12_signature_with_raw_key(&[], &no_key, &dss, &WITH_ML_DSA).unwrap_err(),
                refused
            );
            // TLS 1.3 gets as far as the (here unusable) certificate and key.
            assert_ne!(
                verify_tls13_signature(&[], &no_cert, &dss, &WITH_ML_DSA).unwrap_err(),
                refused
            );
            assert_ne!(
                verify_tls13_signature_with_raw_key(&[], &no_key, &dss, &WITH_ML_DSA).unwrap_err(),
                refused
            );
        }
        // A scheme of both versions is not refused at that point.
        let dss = DigitallySignedStruct::new(SignatureScheme::ED25519, alloc::vec![1]);
        assert_ne!(
            verify_tls12_signature(&[], &no_cert, &dss, &WITH_ML_DSA).unwrap_err(),
            refused
        );
        assert!(!SignatureScheme::ED25519.is_ml_dsa());
    }

    /// RFC 9846 §4.3.3: in TLS 1.3 each ECDSA scheme is verified only with
    /// its own curve, while TLS 1.2 keeps every curve the provider maps.
    fn check_tls13_ecdsa_curve_binding(algs: &WebPkiSupportedAlgorithms) {
        use browntls_pki::alg_id;
        for (scheme, curve) in [
            (SignatureScheme::ECDSA_NISTP256_SHA256, alg_id::ECDSA_P256),
            (SignatureScheme::ECDSA_NISTP384_SHA384, alg_id::ECDSA_P384),
            (SignatureScheme::ECDSA_NISTP521_SHA512, alg_id::ECDSA_P521),
        ] {
            let Ok(mapped) = algs.convert_scheme(scheme) else {
                continue;
            };
            assert!(!mapped.is_empty(), "{scheme:?}");
            let bound = tls13_algs(scheme, mapped);
            assert_eq!(bound.len(), 1, "{scheme:?}");
            assert_eq!(bound[0].public_key_alg_id(), curve, "{scheme:?}");
        }
        // Schemes without a curve are left alone.
        if let Ok(mapped) = algs.convert_scheme(SignatureScheme::ED25519) {
            assert_eq!(
                tls13_algs(SignatureScheme::ED25519, mapped).len(),
                mapped.len()
            );
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn tls13_ecdsa_curve_binding_native() {
        check_tls13_ecdsa_curve_binding(&crate::crypto::native::SUPPORTED_SIG_ALGS);
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn tls13_ecdsa_curve_binding_rustcrypto() {
        check_tls13_ecdsa_curve_binding(&crate::crypto::rustcrypto::SUPPORTED_SIG_ALGS);
    }
}
