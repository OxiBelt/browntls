//! Error types.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use browntls_pki::{ServerName, UnixTime};

use crate::enums::{AlertDescription, ContentType, HandshakeType};
use crate::msgs::handshake::KeyExchangeAlgorithm;
use crate::rand::GetRandomFailed;

/// The top-level error type.
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// A record of an unexpected content type arrived.
    InappropriateMessage {
        /// The content types that were acceptable.
        expect_types: Vec<ContentType>,
        /// The content type that arrived.
        got_type: ContentType,
    },

    /// A handshake message of an unexpected type arrived.
    InappropriateHandshakeMessage {
        /// The handshake message types that were acceptable.
        expect_types: Vec<HandshakeType>,
        /// The handshake message type that arrived.
        got_type: HandshakeType,
    },

    /// A message could not be decoded.
    InvalidMessage(InvalidMessage),

    /// The peer sent no certificates where one was required.
    NoCertificatesPresented,

    /// The configured server name type is not supported (e.g. an IP address with SNI).
    UnsupportedNameType,

    /// A record failed to decrypt.
    DecryptError,

    /// A record could not be encrypted (e.g. encryption not yet set up).
    EncryptError,

    /// The peer does not support a feature we require.
    PeerIncompatible(PeerIncompatible),

    /// The peer violated the protocol.
    PeerMisbehaved(PeerMisbehaved),

    /// The peer sent a fatal alert.
    AlertReceived(AlertDescription),

    /// A certificate was rejected.
    InvalidCertificate(CertificateError),

    /// A certificate revocation list was rejected.
    InvalidCertRevocationList(CertRevocationListError),

    /// A catch-all error with a message.
    General(String),

    /// The time source failed.
    FailedToGetCurrentTime,

    /// The random source failed.
    FailedToGetRandomBytes,

    /// An operation needing a completed handshake was attempted too early.
    HandshakeNotComplete,

    /// The peer sent a record larger than permitted.
    PeerSentOversizedRecord,

    /// ALPN negotiation found no common protocol.
    NoApplicationProtocol,

    /// `max_fragment_size` is outside the allowed range.
    BadMaxFragmentSize,

    /// The private key does not match the certificate.
    InconsistentKeys(InconsistentKeys),

    /// An error from a provider or other extension point.
    Other(OtherError),
}

/// Reasons a private key and certificate may not go together.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InconsistentKeys {
    /// The key's public half differs from the certificate's.
    KeyMismatch,
    /// The key does not expose its public half, so no check was possible.
    Unknown,
}

impl From<InconsistentKeys> for Error {
    fn from(e: InconsistentKeys) -> Self {
        Self::InconsistentKeys(e)
    }
}

/// A message was syntactically invalid.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidMessage {
    /// A certificate payload exceeded the size limit.
    CertificatePayloadTooLarge,
    /// A handshake payload exceeded the size limit.
    HandshakePayloadTooLarge,
    /// A ChangeCipherSpec body was not exactly `0x01`.
    InvalidCcs,
    /// An unknown record content type.
    InvalidContentType,
    /// An unknown certificate status type.
    InvalidCertificateStatusType,
    /// A malformed CertificateRequest.
    InvalidCertRequest,
    /// Malformed Diffie-Hellman parameters.
    InvalidDhParams,
    /// A payload that must be non-empty was empty.
    InvalidEmptyPayload,
    /// A malformed KeyUpdate.
    InvalidKeyUpdate,
    /// A malformed server name.
    InvalidServerName,
    /// A message exceeded a length bound.
    MessageTooLarge,
    /// A message ended early.
    MessageTooShort,
    /// A field was missing (names the field).
    MissingData(&'static str),
    /// A key exchange message was missing.
    MissingKeyExchange,
    /// No signature schemes were listed.
    NoSignatureSchemes,
    /// Data remained after a complete structure (names the structure).
    TrailingData(&'static str),
    /// A message of this type was not expected here.
    UnexpectedMessage(&'static str),
    /// An unknown protocol version.
    UnknownProtocolVersion,
    /// A compression method other than null.
    UnsupportedCompression,
    /// An EC curve type other than named curve.
    UnsupportedCurveType,
    /// A key exchange algorithm this library does not implement.
    UnsupportedKeyExchangeAlgorithm(KeyExchangeAlgorithm),
    /// An empty session ticket.
    EmptyTicketValue,
    /// A list that must be non-empty was empty (names the list).
    IllegalEmptyList(&'static str),
    /// A value that must be non-empty was empty.
    IllegalEmptyValue,
    /// An extension appeared twice.
    DuplicateExtension(u16),
    /// `pre_shared_key` was not the last ClientHello extension.
    PreSharedKeyIsNotFinalExtension,
    /// A HelloRetryRequest carried an extension that is not permitted there.
    UnknownHelloRetryRequestExtension,
    /// A certificate entry carried an extension we did not solicit.
    UnknownCertificateExtension,
    /// A certificate entry carried a recognised extension that RFC 9846
    /// §4.3 does not allow there.
    DisallowedCertificateExtension,
}

impl From<InvalidMessage> for Error {
    fn from(e: InvalidMessage) -> Self {
        Self::InvalidMessage(e)
    }
}

impl From<InvalidMessage> for AlertDescription {
    fn from(e: InvalidMessage) -> Self {
        match e {
            InvalidMessage::PreSharedKeyIsNotFinalExtension
            | InvalidMessage::DuplicateExtension(_) => Self::IllegalParameter,
            InvalidMessage::UnknownHelloRetryRequestExtension => Self::UnsupportedExtension,
            // RFC 9846 §4.3: recognised but not allowed in the message.
            InvalidMessage::DisallowedCertificateExtension => Self::IllegalParameter,
            // RFC 9846 §4.3: a response to an extension we never sent.
            InvalidMessage::UnknownCertificateExtension => Self::UnsupportedExtension,
            // RFC 5246 §6, RFC 8446 §5: an unknown record type.
            InvalidMessage::InvalidContentType => Self::UnexpectedMessage,
            // RFC 9846 §5: a change_cipher_spec record whose value is not
            // 0x01 MUST abort the handshake with unexpected_message.
            InvalidMessage::InvalidCcs => Self::UnexpectedMessage,
            _ => Self::DecodeError,
        }
    }
}

/// The peer violated the protocol in a way that is not a syntax error.
#[non_exhaustive]
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone)]
pub enum PeerMisbehaved {
    AttemptedDowngradeToTls12WhenTls13IsSupported,
    /// No longer produced: OCSP responses are accepted on any certificate
    /// entry (RFC 9846 §4.5.1).
    BadCertChainExtensions,
    CipherSuiteDifferedOnRetry,
    DisallowedCertificateRequestExtension,
    DisallowedEncryptedExtension,
    DisallowedHelloRetryRequestExtension,
    DisallowedNewSessionTicketExtension,
    DuplicateClientHelloExtensions,
    DuplicateEncryptedExtensions,
    EncryptThenMacWithAeadCipherSuite,
    InappropriateFallback,
    DuplicateHelloRetryRequestExtensions,
    DuplicateNewSessionTicketExtensions,
    DuplicateServerHelloExtensions,
    DuplicateServerNameTypes,
    EarlyDataAttemptedInSecondClientHello,
    EarlyDataExtensionWithoutResumption,
    EarlyDataOfferedWithVariedCipherSuite,
    HandshakeHashVariedAfterRetry,
    IllegalHelloRetryRequestWithEmptyCookie,
    IllegalHelloRetryRequestWithNoChanges,
    IllegalHelloRetryRequestWithOfferedGroup,
    IllegalHelloRetryRequestWithUnofferedCipherSuite,
    IllegalHelloRetryRequestWithUnofferedNamedGroup,
    IllegalHelloRetryRequestWithUnsupportedVersion,
    IllegalHelloRetryRequestWithWrongSessionId,
    IllegalCertificateRequestContext,
    IllegalClientHelloLegacyVersion,
    IllegalMiddleboxChangeCipherSpec,
    IllegalProtectedChangeCipherSpec,
    IllegalServerHelloLegacyVersion,
    IllegalTlsInnerPlaintext,
    IncorrectBinder,
    InvalidCertCompression,
    InvalidMaxEarlyDataSize,
    InvalidKeyShare,
    KeyEpochWithPendingFragment,
    KeyUpdateReceivedInQuicConnection,
    MessageInterleavedWithHandshakeMessage,
    MissingBinderInPskExtension,
    MissingKeyShare,
    MissingPskExtensionInSecondClientHello,
    MissingPskModesExtension,
    MissingQuicTransportParameters,
    OfferedDuplicateCertificateCompressions,
    OfferedDuplicateKeyShares,
    OfferedEarlyDataWithOldProtocolVersion,
    OfferedEmptyApplicationProtocol,
    OfferedIncorrectCompressions,
    PskExtensionMustBeLast,
    PskExtensionWithMismatchedIdsAndBinders,
    RefusedToFollowHelloRetryRequest,
    RejectedEarlyDataInterleavedWithHandshakeMessage,
    ResumptionAttemptedWithVariedEms,
    ResumptionOfferedWithVariedCipherSuite,
    ResumptionOfferedWithVariedEms,
    ResumptionOfferedWithIncompatibleCipherSuite,
    SelectedDifferentCipherSuiteAfterRetry,
    SelectedInvalidPsk,
    SelectedTls12UsingTls13VersionExtension,
    SelectedUnofferedApplicationProtocol,
    SelectedUnofferedCertCompression,
    SelectedUnofferedCipherSuite,
    SelectedUnofferedCompression,
    SelectedUnofferedKxGroup,
    SelectedUnofferedPsk,
    SelectedUnofferedVersion,
    SelectedUnusableCipherSuiteForVersion,
    ServerEchoedCompatibilitySessionId,
    ServerHelloMustOfferUncompressedEcPoints,
    ServerNameDifferedOnRetry,
    ServerNameMustContainOneHostName,
    SignedKxWithWrongAlgorithm,
    SignedHandshakeWithUnadvertisedSigScheme,
    TooManyEmptyFragments,
    TooManyKeyUpdateRequests,
    TooManyRenegotiationRequests,
    TooManyWarningAlertsReceived,
    TooMuchEarlyDataReceived,
    UnexpectedCleartextExtension,
    UnsolicitedCertExtension,
    UnsolicitedEncryptedExtension,
    UnsolicitedSctList,
    UnsolicitedServerHelloExtension,
    WrongGroupForKeyShare,
}

impl From<PeerMisbehaved> for Error {
    fn from(e: PeerMisbehaved) -> Self {
        Self::PeerMisbehaved(e)
    }
}

/// The peer lacks a capability we require, so no connection is possible.
#[non_exhaustive]
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone)]
pub enum PeerIncompatible {
    EcPointsExtensionRequired,
    EncryptThenMacExtensionRequired,
    ExtendedMasterSecretExtensionRequired,
    IncorrectCertificateTypeExtension,
    KeyShareExtensionRequired,
    NamedGroupsExtensionRequired,
    NoCertificateRequestSignatureSchemesInCommon,
    NoCipherSuitesInCommon,
    NoEcPointFormatsInCommon,
    NoKxGroupsInCommon,
    NoSignatureSchemesInCommon,
    NullCompressionRequired,
    SecureRenegotiationExtensionRequired,
    ServerDoesNotSupportTls12Or13,
    ServerSentHelloRetryRequestWithUnknownExtension,
    ServerTlsVersionIsDisabledByOurConfig,
    SignatureAlgorithmsExtensionRequired,
    SupportedVersionsExtensionRequired,
    Tls12NotOffered,
    Tls12NotOfferedOrEnabled,
    Tls13RequiredForQuic,
    UncompressedEcPointsRequired,
    UnsolicitedCertificateTypeExtension,
}

impl From<PeerIncompatible> for Error {
    fn from(e: PeerIncompatible) -> Self {
        Self::PeerIncompatible(e)
    }
}

/// Why a certificate was rejected.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateError {
    /// The certificate is malformed.
    BadEncoding,
    /// The certificate has expired.
    Expired,
    /// The certificate has expired, with the times involved.
    ExpiredContext {
        /// The validation time.
        time: UnixTime,
        /// The certificate's `notAfter`.
        not_after: UnixTime,
    },
    /// The certificate is not yet valid.
    NotValidYet,
    /// The certificate is not yet valid, with the times involved.
    NotValidYetContext {
        /// The validation time.
        time: UnixTime,
        /// The certificate's `notBefore`.
        not_before: UnixTime,
    },
    /// The certificate was revoked.
    Revoked,
    /// The certificate has an unknown critical extension.
    UnhandledCriticalExtension,
    /// No path to a trust anchor exists.
    UnknownIssuer,
    /// The revocation status could not be determined.
    UnknownRevocationStatus,
    /// The CRL covering the certificate has expired.
    ExpiredRevocationList,
    /// The CRL covering the certificate has expired, with the times involved.
    ExpiredRevocationListContext {
        /// The validation time.
        time: UnixTime,
        /// The CRL's `nextUpdate`.
        next_update: UnixTime,
    },
    /// A signature in the path is invalid.
    BadSignature,
    /// A signature algorithm in the path is not supported.
    UnsupportedSignatureAlgorithm,
    /// The certificate is not valid for the requested name.
    NotValidForName,
    /// The certificate is not valid for the requested name, with context.
    NotValidForNameContext {
        /// The requested name.
        expected: ServerName<'static>,
        /// The names the certificate is valid for.
        presented: Vec<String>,
    },
    /// The certificate is not valid for its intended purpose.
    InvalidPurpose,
    /// A stapled OCSP response is invalid.
    InvalidOcspResponse,
    /// An application-level verifier rejected the certificate.
    ApplicationVerificationFailure,
    /// Some other reason.
    Other(OtherError),
}

impl From<CertificateError> for AlertDescription {
    fn from(e: CertificateError) -> Self {
        use CertificateError::*;
        match e {
            BadEncoding
            | UnhandledCriticalExtension
            | NotValidForName
            | NotValidForNameContext { .. } => Self::BadCertificate,
            Expired | ExpiredContext { .. } | NotValidYet | NotValidYetContext { .. } => {
                Self::CertificateExpired
            }
            Revoked => Self::CertificateRevoked,
            UnknownIssuer
            | UnknownRevocationStatus
            | ExpiredRevocationList
            | ExpiredRevocationListContext { .. } => Self::UnknownCA,
            InvalidOcspResponse => Self::BadCertificateStatusResponse,
            BadSignature | UnsupportedSignatureAlgorithm => Self::DecryptError,
            InvalidPurpose => Self::UnsupportedCertificate,
            ApplicationVerificationFailure => Self::AccessDenied,
            Other(..) => Self::CertificateUnknown,
        }
    }
}

impl From<CertificateError> for Error {
    fn from(e: CertificateError) -> Self {
        Self::InvalidCertificate(e)
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpiredContext { time, not_after } => write!(
                f,
                "certificate expired: verification time {} (UNIX), not valid after {}",
                time.as_secs(),
                not_after.as_secs()
            ),
            Self::NotValidYetContext { time, not_before } => write!(
                f,
                "certificate not valid yet: verification time {} (UNIX), not valid before {}",
                time.as_secs(),
                not_before.as_secs()
            ),
            Self::ExpiredRevocationListContext { time, next_update } => write!(
                f,
                "certificate revocation list expired: verification time {} (UNIX), next update {}",
                time.as_secs(),
                next_update.as_secs()
            ),
            Self::NotValidForNameContext {
                expected,
                presented,
            } => {
                write!(f, "certificate not valid for name {expected}; ")?;
                match presented.as_slice() {
                    [] => f.write_str("it is not valid for any names"),
                    [one] => write!(f, "it is only valid for {one}"),
                    many => write!(f, "it is only valid for {}", many.join(", ")),
                }
            }
            other => write!(f, "{other:?}"),
        }
    }
}

/// Why a certificate revocation list was rejected.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum CertRevocationListError {
    /// The CRL signature is invalid.
    BadSignature,
    /// The CRL signature algorithm is unsupported.
    UnsupportedSignatureAlgorithm,
    /// The CRL number is invalid.
    InvalidCrlNumber,
    /// A revoked serial number is invalid.
    InvalidRevokedCertSerialNumber,
    /// The CRL issuer may not sign CRLs.
    IssuerInvalidForCrl,
    /// Some other reason.
    Other(OtherError),
    /// The CRL could not be parsed.
    ParseError,
    /// The CRL has an unsupported critical extension.
    UnsupportedCriticalExtension,
    /// The CRL is a delta CRL.
    UnsupportedDeltaCrl,
    /// The CRL is an indirect CRL.
    UnsupportedIndirectCrl,
    /// The CRL has an unsupported revocation reason.
    UnsupportedRevocationReason,
    /// The CRL version is unsupported.
    UnsupportedCrlVersion,
}

impl From<CertRevocationListError> for Error {
    fn from(e: CertRevocationListError) -> Self {
        Self::InvalidCertRevocationList(e)
    }
}

/// An error from outside the library (a provider, verifier, or resolver).
///
/// Equality is by pointer identity of the inner error when `std` is enabled.
#[derive(Debug, Clone)]
pub struct OtherError(
    /// The underlying error.
    #[cfg(feature = "std")]
    pub alloc::sync::Arc<dyn std::error::Error + Send + Sync>,
);

impl PartialEq<Self> for OtherError {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "std")]
        {
            alloc::sync::Arc::ptr_eq(&self.0, &other.0)
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = other;
            true
        }
    }
}

impl From<OtherError> for Error {
    fn from(value: OtherError) -> Self {
        Self::Other(value)
    }
}

impl fmt::Display for OtherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "std")]
        {
            write!(f, "{}", self.0)
        }
        #[cfg(not(feature = "std"))]
        {
            f.write_str("no further information available")
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OtherError {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InappropriateMessage {
                expect_types,
                got_type,
            } => write!(
                f,
                "received unexpected message: got {got_type:?} when expecting {}",
                join::<ContentType>(expect_types)
            ),
            Self::InappropriateHandshakeMessage {
                expect_types,
                got_type,
            } => write!(
                f,
                "received unexpected handshake message: got {got_type:?} when expecting {}",
                join::<HandshakeType>(expect_types)
            ),
            Self::InvalidMessage(e) => write!(f, "received corrupt message of type {e:?}"),
            Self::PeerIncompatible(e) => write!(f, "peer is incompatible: {e:?}"),
            Self::PeerMisbehaved(e) => write!(f, "peer misbehaved: {e:?}"),
            Self::AlertReceived(a) => write!(f, "received fatal alert: {a:?}"),
            Self::InvalidCertificate(e) => write!(f, "invalid peer certificate: {e}"),
            Self::InvalidCertRevocationList(e) => {
                write!(f, "invalid certificate revocation list: {e:?}")
            }
            Self::NoCertificatesPresented => f.write_str("peer sent no certificates"),
            Self::UnsupportedNameType => f.write_str("presented server name type wasn't supported"),
            Self::DecryptError => f.write_str("cannot decrypt peer's message"),
            Self::EncryptError => f.write_str("cannot encrypt message"),
            Self::PeerSentOversizedRecord => f.write_str("peer sent excess record size"),
            Self::HandshakeNotComplete => f.write_str("handshake not complete"),
            Self::NoApplicationProtocol => f.write_str("peer doesn't support any known protocol"),
            Self::FailedToGetCurrentTime => f.write_str("failed to get current time"),
            Self::FailedToGetRandomBytes => f.write_str("failed to get random bytes"),
            Self::BadMaxFragmentSize => {
                f.write_str("the supplied max_fragment_size was too small or large")
            }
            Self::InconsistentKeys(why) => write!(f, "keys may not be consistent: {why:?}"),
            Self::General(err) => write!(f, "unexpected error: {err}"),
            Self::Other(err) => write!(f, "other error: {err}"),
        }
    }
}

fn join<T: fmt::Debug>(items: &[T]) -> String {
    items
        .iter()
        .map(|x| format!("{x:?}"))
        .collect::<Vec<String>>()
        .join(" or ")
}

impl core::error::Error for Error {}

impl From<GetRandomFailed> for Error {
    fn from(_: GetRandomFailed) -> Self {
        Self::FailedToGetRandomBytes
    }
}

#[cfg(feature = "std")]
impl From<std::time::SystemTimeError> for Error {
    fn from(_: std::time::SystemTimeError) -> Self {
        Self::FailedToGetCurrentTime
    }
}

impl Error {
    pub(crate) fn general(msg: &str) -> Self {
        Self::General(String::from(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_informative() {
        let e = Error::InappropriateMessage {
            expect_types: alloc::vec![ContentType::Alert, ContentType::Handshake],
            got_type: ContentType::ApplicationData,
        };
        assert_eq!(
            format!("{e}"),
            "received unexpected message: got ApplicationData when expecting Alert or Handshake"
        );
        let e = Error::from(InvalidMessage::MissingData("x"));
        assert_eq!(
            format!("{e}"),
            "received corrupt message of type MissingData(\"x\")"
        );
        let e = Error::from(CertificateError::ExpiredContext {
            time: UnixTime::since_unix_epoch(core::time::Duration::from_secs(10)),
            not_after: UnixTime::since_unix_epoch(core::time::Duration::from_secs(5)),
        });
        assert_eq!(
            format!("{e}"),
            "invalid peer certificate: certificate expired: verification time 10 (UNIX), not valid after 5"
        );
        let e = Error::from(CertificateError::NotValidForNameContext {
            expected: ServerName::try_from("a.example").unwrap().to_owned(),
            presented: alloc::vec![String::from("b.example"), String::from("c.example")],
        });
        assert_eq!(
            format!("{e}"),
            "invalid peer certificate: certificate not valid for name a.example; it is only valid for b.example, c.example"
        );
    }

    #[test]
    fn alert_mapping() {
        assert_eq!(
            AlertDescription::from(InvalidMessage::DuplicateExtension(1)),
            AlertDescription::IllegalParameter
        );
        assert_eq!(
            AlertDescription::from(InvalidMessage::MessageTooShort),
            AlertDescription::DecodeError
        );
        assert_eq!(
            AlertDescription::from(CertificateError::Revoked),
            AlertDescription::CertificateRevoked
        );
        // RFC 9846 §5: a change_cipher_spec value other than 0x01.
        assert_eq!(
            AlertDescription::from(InvalidMessage::InvalidCcs),
            AlertDescription::UnexpectedMessage
        );
        // RFC 9846 §4.3: recognised but not allowed, versus unsolicited.
        assert_eq!(
            AlertDescription::from(InvalidMessage::DisallowedCertificateExtension),
            AlertDescription::IllegalParameter
        );
        assert_eq!(
            AlertDescription::from(InvalidMessage::UnknownCertificateExtension),
            AlertDescription::UnsupportedExtension
        );
    }

    #[test]
    fn general_error_code_point() {
        // RFC 9846 §6.2 / IANA: general_error(117).
        assert_eq!(u8::from(AlertDescription::GeneralError), 117);
        assert_eq!(
            AlertDescription::from(117u8),
            AlertDescription::GeneralError
        );
    }

    #[test]
    fn conversions() {
        assert_eq!(Error::from(GetRandomFailed), Error::FailedToGetRandomBytes);
        assert_eq!(
            Error::from(InconsistentKeys::KeyMismatch),
            Error::InconsistentKeys(InconsistentKeys::KeyMismatch)
        );
    }
}
