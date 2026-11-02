//! Certificate validation errors.

use core::fmt;

use crate::UnixTime;

/// An error from certificate parsing, path building or name validation.
///
/// Variants describe the first failure encountered; when path building tries
/// several candidate chains, the most specific error is reported.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Malformed DER.
    BadDer,
    /// A time field is malformed.
    BadDerTime,
    /// A CA certificate was presented as an end-entity certificate.
    CaUsedAsEndEntity,
    /// The certificate has expired.
    CertExpired {
        /// Validation time.
        time: UnixTime,
        /// `notAfter` of the certificate.
        not_after: UnixTime,
    },
    /// The certificate is not valid for the requested name.
    CertNotValidForName,
    /// The certificate is not yet valid.
    CertNotValidYet {
        /// Validation time.
        time: UnixTime,
        /// `notBefore` of the certificate.
        not_before: UnixTime,
    },
    /// The certificate has been revoked.
    CertRevoked,
    /// A CRL has expired (`nextUpdate` in the past) under a strict policy.
    CrlExpired {
        /// Validation time.
        time: UnixTime,
        /// `nextUpdate` of the CRL.
        next_update: UnixTime,
    },
    /// The EKU extension is present but empty.
    EmptyEkuExtension,
    /// An end-entity certificate was used as an issuer.
    EndEntityUsedAsCa,
    /// An extension value is invalid.
    ExtensionValueInvalid,
    /// `notBefore` is after `notAfter`.
    InvalidCertValidity,
    /// A CRL number is invalid.
    InvalidCrlNumber,
    /// An IP address name constraint has an invalid mask.
    InvalidNetworkMaskConstraint,
    /// A certificate serial number is invalid.
    InvalidSerialNumber,
    /// A CRL signature is invalid.
    InvalidCrlSignatureForPublicKey,
    /// A certificate signature is invalid.
    InvalidSignatureForPublicKey,
    /// An issuer's `KeyUsage` extension lacks `keyCertSign`.
    IssuerNotCertSigner,
    /// The CRL issuer is not allowed to sign CRLs.
    IssuerNotCrlSigner,
    /// A DNS identifier is malformed.
    MalformedDnsIdentifier,
    /// Extensions are malformed (e.g. duplicated).
    MalformedExtensions,
    /// A name constraint is malformed.
    MalformedNameConstraint,
    /// Name-constraint comparison budget exceeded.
    MaximumNameConstraintComparisonsExceeded,
    /// Path-building budget exceeded.
    MaximumPathBuildCallsExceeded,
    /// Maximum path depth exceeded.
    MaximumPathDepthExceeded,
    /// Signature-check budget exceeded.
    MaximumSignatureChecksExceeded,
    /// A name violates a name constraint.
    NameConstraintViolation,
    /// A `pathLenConstraint` was violated.
    PathLenConstraintViolated,
    /// The required extended key usage is absent.
    RequiredEkuNotFound,
    /// The signature algorithm in the certificate does not match the
    /// `TBSCertificate` signature field.
    SignatureAlgorithmMismatch,
    /// Trailing data after a DER structure.
    TrailingData,
    /// No path to a trust anchor was found.
    UnknownIssuer,
    /// Revocation status could not be determined under a strict policy.
    UnknownRevocationStatus,
    /// Unsupported certificate version (only v3 is accepted).
    UnsupportedCertVersion,
    /// An unsupported critical extension is present.
    UnsupportedCriticalExtension,
    /// An unsupported CRL issuing distribution point.
    UnsupportedCrlIssuingDistributionPoint,
    /// Unsupported CRL version (only v2 is accepted).
    UnsupportedCrlVersion,
    /// Delta CRLs are unsupported.
    UnsupportedDeltaCrl,
    /// Indirect CRLs are unsupported.
    UnsupportedIndirectCrl,
    /// Unsupported name type in a name constraint or SAN.
    UnsupportedNameType,
    /// Unsupported revocation reason.
    UnsupportedRevocationReason,
    /// CRLs partitioned by reason are unsupported.
    UnsupportedRevocationReasonsPartitioning,
    /// The CRL signature algorithm is not supported.
    UnsupportedCrlSignatureAlgorithm,
    /// The CRL signature algorithm is not supported for the issuer's key.
    UnsupportedCrlSignatureAlgorithmForPublicKey,
    /// The certificate signature algorithm is not supported.
    UnsupportedSignatureAlgorithm,
    /// The signature algorithm is not supported for the issuer's key type.
    UnsupportedSignatureAlgorithmForPublicKey,
}

impl Error {
    /// Of two errors met while exploring alternative paths, the one more
    /// useful to report.
    pub(crate) fn most_specific(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// Specificity ranking: higher ranks describe a problem with an otherwise
    /// plausible path; lower ranks describe inputs that could never be used.
    pub(crate) fn rank(&self) -> u32 {
        match self {
            Self::CertNotValidYet { .. } | Self::CertExpired { .. } => 290,
            Self::CertNotValidForName => 280,
            Self::CertRevoked | Self::UnknownRevocationStatus | Self::CrlExpired { .. } => 270,
            Self::InvalidCrlSignatureForPublicKey | Self::InvalidSignatureForPublicKey => 260,
            Self::SignatureAlgorithmMismatch => 250,
            Self::EmptyEkuExtension => 245,
            Self::RequiredEkuNotFound => 240,
            Self::NameConstraintViolation => 230,
            Self::PathLenConstraintViolated => 220,
            Self::CaUsedAsEndEntity | Self::EndEntityUsedAsCa | Self::IssuerNotCertSigner => 210,
            Self::IssuerNotCrlSigner => 200,

            Self::InvalidCertValidity => 190,
            Self::InvalidNetworkMaskConstraint => 180,
            Self::InvalidSerialNumber => 170,
            Self::InvalidCrlNumber => 160,

            Self::UnsupportedCrlSignatureAlgorithmForPublicKey
            | Self::UnsupportedSignatureAlgorithmForPublicKey => 150,
            Self::UnsupportedCrlSignatureAlgorithm | Self::UnsupportedSignatureAlgorithm => 140,
            Self::UnsupportedCriticalExtension | Self::UnsupportedCertVersion => 130,
            Self::UnsupportedCrlVersion => 120,
            Self::UnsupportedDeltaCrl => 110,
            Self::UnsupportedIndirectCrl => 100,
            Self::UnsupportedNameType => 95,
            Self::UnsupportedRevocationReason => 90,
            Self::UnsupportedRevocationReasonsPartitioning => 80,
            Self::UnsupportedCrlIssuingDistributionPoint => 70,
            Self::MaximumPathDepthExceeded => 61,

            Self::MalformedDnsIdentifier => 60,
            Self::MalformedNameConstraint => 50,
            Self::MalformedExtensions | Self::TrailingData => 40,
            Self::ExtensionValueInvalid => 30,
            Self::BadDerTime => 20,
            Self::BadDer => 10,

            // Budget errors end the search; the default error is the floor.
            Self::MaximumSignatureChecksExceeded
            | Self::MaximumPathBuildCallsExceeded
            | Self::MaximumNameConstraintComparisonsExceeded
            | Self::UnknownIssuer => 0,
        }
    }

    /// Whether the error exhausts a work budget and must stop path building.
    pub(crate) fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::MaximumSignatureChecksExceeded
                | Self::MaximumPathBuildCallsExceeded
                | Self::MaximumNameConstraintComparisonsExceeded
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranking() {
        assert_eq!(
            Error::UnknownIssuer.most_specific(Error::BadDer),
            Error::BadDer
        );
        assert_eq!(
            Error::BadDer.most_specific(Error::UnknownIssuer),
            Error::BadDer
        );
        assert_eq!(
            Error::NameConstraintViolation.most_specific(Error::CertRevoked),
            Error::CertRevoked
        );
        // Ties keep the earlier error.
        assert_eq!(
            Error::CaUsedAsEndEntity.most_specific(Error::EndEntityUsedAsCa),
            Error::CaUsedAsEndEntity
        );
        assert!(Error::MaximumSignatureChecksExceeded.is_fatal());
        assert!(!Error::UnknownIssuer.is_fatal());
    }
}
