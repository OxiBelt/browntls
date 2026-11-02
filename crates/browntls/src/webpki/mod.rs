//! Certificate verification built on `browntls-pki`.

use core::fmt;

use crate::error::{CertRevocationListError, CertificateError, Error};

mod anchors;
mod verify;

pub use anchors::RootCertStore;
pub use verify::{
    ParsedCertificate, WebPkiSupportedAlgorithms, verify_server_cert_signed_by_trust_anchor,
    verify_server_name, verify_tls12_signature, verify_tls13_signature,
};

/// Why a verifier could not be built.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerifierBuilderError {
    /// The root store was empty.
    NoRootAnchors,
    /// A CRL could not be parsed.
    InvalidCrl(CertRevocationListError),
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
    }
}
