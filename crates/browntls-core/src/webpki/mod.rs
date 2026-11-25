//! Certificate verification built on `browntls-pki`.

use core::fmt;

use crate::error::{CertRevocationListError, CertificateError, Error};

mod anchors;
mod client_verifier;
mod server_verifier;
mod transparency;
mod verify;

pub use anchors::RootCertStore;
pub use client_verifier::{ClientCertVerifierBuilder, WebPkiClientVerifier};
pub use server_verifier::{ServerCertVerifierBuilder, WebPkiServerVerifier};
pub use verify::{
    ParsedCertificate, WebPkiSupportedAlgorithms, verify_server_cert_signed_by_trust_anchor,
    verify_server_identity, verify_server_name, verify_tls12_signature,
    verify_tls12_signature_with_raw_key, verify_tls13_client_signature,
    verify_tls13_client_signature_with_raw_key, verify_tls13_signature,
    verify_tls13_signature_with_raw_key,
};

/// Why a verifier could not be built.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerifierBuilderError {
    /// The root store was empty.
    NoRootAnchors,
    /// A CRL could not be parsed.
    InvalidCrl(CertRevocationListError),
    /// A Certificate Transparency 2.0 log or trusted tree head of
    /// [`CtV2Requirements`](crate::transparency::CtV2Requirements) is
    /// invalid: a malformed log ID, or a key that is not a P-256 or
    /// Ed25519 `SubjectPublicKeyInfo`.
    InvalidTransparencyLog(browntls_pki::transparency::TransparencyError),
    /// Two Certificate Transparency 2.0 logs of
    /// [`CtV2Requirements`](crate::transparency::CtV2Requirements) share a
    /// log ID or a key. A version 2 SCT's signature does not cover its log
    /// ID (RFC 9162 §4.8), so one SCT could be presented under the ID of
    /// each log with its key and be counted for several distinct logs.
    DuplicateTransparencyLog,
}

impl From<CertRevocationListError> for VerifierBuilderError {
    fn from(value: CertRevocationListError) -> Self {
        Self::InvalidCrl(value)
    }
}

impl fmt::Display for VerifierBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRootAnchors => f.write_str("no root trust anchors were provided"),
            Self::InvalidCrl(e) => write!(f, "provided CRL could not be parsed: {e:?}"),
            Self::InvalidTransparencyLog(e) => {
                write!(f, "invalid Certificate Transparency 2.0 log: {e}")
            }
            Self::DuplicateTransparencyLog => {
                f.write_str("two Certificate Transparency 2.0 logs share an ID or a key")
            }
        }
    }
}

impl core::error::Error for VerifierBuilderError {}

/// Maps a `browntls-pki` error onto the library error type.
pub(crate) fn pki_error(error: browntls_pki::Error) -> Error {
    use browntls_pki::Error::*;
    match error {
        BadDer | BadDerTime | TrailingData | MalformedExtensions | ExtensionValueInvalid => {
            CertificateError::BadEncoding.into()
        }
        CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName => CertificateError::NotValidForName.into(),
        CertRevoked => CertificateError::Revoked.into(),
        UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),
        InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            CertificateError::UnsupportedSignatureAlgorithm.into()
        }
        InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature.into(),
        UnsupportedCrlSignatureAlgorithm | UnsupportedCrlSignatureAlgorithmForPublicKey => {
            CertRevocationListError::UnsupportedSignatureAlgorithm.into()
        }
        RequiredEkuNotFound | EmptyEkuExtension => CertificateError::InvalidPurpose.into(),
        UnsupportedCriticalExtension => CertificateError::UnhandledCriticalExtension.into(),
        other => CertificateError::Other(other_error(other)).into(),
    }
}

/// Maps a `browntls-pki` error from CRL parsing.
pub(crate) fn crl_error(e: browntls_pki::Error) -> CertRevocationListError {
    use browntls_pki::Error::*;
    match e {
        InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature,
        UnsupportedCrlSignatureAlgorithm | UnsupportedCrlSignatureAlgorithmForPublicKey => {
            CertRevocationListError::UnsupportedSignatureAlgorithm
        }
        InvalidCrlNumber => CertRevocationListError::InvalidCrlNumber,
        InvalidSerialNumber => CertRevocationListError::InvalidRevokedCertSerialNumber,
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl,
        MalformedExtensions | BadDer | BadDerTime => CertRevocationListError::ParseError,
        UnsupportedCriticalExtension => CertRevocationListError::UnsupportedCriticalExtension,
        UnsupportedCrlVersion => CertRevocationListError::UnsupportedCrlVersion,
        UnsupportedDeltaCrl => CertRevocationListError::UnsupportedDeltaCrl,
        UnsupportedIndirectCrl => CertRevocationListError::UnsupportedIndirectCrl,
        UnsupportedRevocationReason => CertRevocationListError::UnsupportedRevocationReason,
        other => CertRevocationListError::Other(other_error(other)),
    }
}

fn other_error(e: browntls_pki::Error) -> crate::error::OtherError {
    #[cfg(feature = "std")]
    {
        crate::error::OtherError(alloc::sync::Arc::new(e))
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = e;
        crate::error::OtherError()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_mapping() {
        assert_eq!(
            pki_error(browntls_pki::Error::UnknownIssuer),
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        );
        assert_eq!(
            pki_error(browntls_pki::Error::InvalidCrlSignatureForPublicKey),
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature)
        );
        assert_eq!(
            crl_error(browntls_pki::Error::BadDer),
            CertRevocationListError::ParseError
        );
        assert!(matches!(
            pki_error(browntls_pki::Error::MaximumPathDepthExceeded),
            Error::InvalidCertificate(CertificateError::Other(_))
        ));
        // RFC 9881 §5: a key usage that an ML-DSA key may not assert is a
        // key usage failure like `IssuerNotCertSigner`, kept in `Other` and
        // sent as a `certificate_unknown` alert.
        for e in [
            browntls_pki::Error::KeyUsageNotPermittedForPublicKey,
            browntls_pki::Error::IssuerNotCertSigner,
        ] {
            let Error::InvalidCertificate(cert_error) = pki_error(e.clone()) else {
                panic!("{e:?}");
            };
            assert!(matches!(cert_error, CertificateError::Other(_)), "{e:?}");
            assert_eq!(
                crate::enums::AlertDescription::from(cert_error),
                crate::enums::AlertDescription::CertificateUnknown
            );
        }
    }
}
