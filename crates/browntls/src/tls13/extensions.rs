//! Which extensions may appear in which TLS 1.3 handshake message.
//!
//! RFC 9846 §4.3 (Table 1) lists, for each extension marked "Recommended",
//! the messages it may appear in, and requires: "If an implementation
//! receives an extension which it recognizes and which is not specified for
//! the message in which it appears, it MUST abort the handshake with an
//! `illegal_parameter` alert." Extensions outside Table 1 follow the TLS 1.3
//! column of the IANA "TLS ExtensionType Values" registry; extensions
//! defined only for TLS 1.2 and earlier ("-" in that column) may appear in no
//! TLS 1.3 message except a ClientHello that also offers TLS 1.2.

use crate::msgs::enums::ExtensionType;

/// A TLS 1.3 handshake message that carries extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tls13Message {
    ClientHello,
    ServerHello,
    HelloRetryRequest,
    EncryptedExtensions,
    CertificateRequest,
    Certificate,
    NewSessionTicket,
}

/// Whether `ext` may appear in `msg` in TLS 1.3.
///
/// Returns `None` for an extension this crate does not recognise; an
/// unrecognised extension is never `illegal_parameter` (it is ignored, or it
/// is an unsolicited response, depending on the message).
pub(crate) fn allowed_in(ext: ExtensionType, msg: Tls13Message) -> Option<bool> {
    use ExtensionType as E;
    use Tls13Message::*;

    let allowed: &[Tls13Message] = match ext {
        // RFC 9846 Table 1.
        E::ServerName => &[ClientHello, EncryptedExtensions, CertificateRequest],
        E::StatusRequest => &[ClientHello, CertificateRequest, Certificate],
        E::EllipticCurves => &[ClientHello, EncryptedExtensions],
        E::SignatureAlgorithms => &[ClientHello, CertificateRequest],
        E::UseSRTP => &[ClientHello, EncryptedExtensions],
        E::Heartbeat => &[ClientHello, EncryptedExtensions],
        E::ALProtocolNegotiation => &[ClientHello, EncryptedExtensions],
        E::ClientCertificateType => &[ClientHello, EncryptedExtensions],
        E::ServerCertificateType => &[ClientHello, EncryptedExtensions],
        E::Padding => &[ClientHello],
        E::CompressCertificate => &[ClientHello, CertificateRequest],
        E::PreSharedKey => &[ClientHello, ServerHello],
        E::EarlyData => &[ClientHello, EncryptedExtensions, NewSessionTicket],
        E::SupportedVersions => &[ClientHello, ServerHello, HelloRetryRequest],
        E::Cookie => &[ClientHello, HelloRetryRequest],
        E::PSKKeyExchangeModes => &[ClientHello],
        E::CertificateAuthorities => &[ClientHello, CertificateRequest],
        E::OIDFilters => &[CertificateRequest],
        E::PostHandshakeAuth => &[ClientHello],
        E::SignatureAlgorithmsCert => &[ClientHello, CertificateRequest],
        E::KeyShare => &[ClientHello, ServerHello, HelloRetryRequest],
        E::TransportParameters => &[ClientHello, EncryptedExtensions],
        E::EncryptedClientHelloOuterExtensions => &[ClientHello],
        E::EncryptedClientHello => &[ClientHello, HelloRetryRequest, EncryptedExtensions],

        // Not "Recommended", so outside Table 1; IANA registry TLS 1.3 column.
        E::MaxFragmentLength => &[ClientHello, EncryptedExtensions],
        E::SCT => &[ClientHello, CertificateRequest, Certificate],
        E::TransportParametersDraft => &[ClientHello, EncryptedExtensions],

        // Defined for TLS 1.2 and earlier only ("-" in the TLS 1.3 column).
        E::ClientCertificateUrl
        | E::TrustedCAKeys
        | E::TruncatedHMAC
        | E::UserMapping
        | E::ClientAuthz
        | E::ServerAuthz
        | E::CertificateType
        | E::ECPointFormats
        | E::SRP
        | E::EncryptThenMac
        | E::ExtendedMasterSecret
        | E::SessionTicket
        | E::TicketEarlyDataInfo
        | E::NextProtocolNegotiation
        | E::ChannelId
        | E::RenegotiationInfo => &[ClientHello],

        E::Unknown(_) => return None,
    };
    Some(allowed.contains(&msg))
}

/// The first recognised extension in `received` that RFC 9846 §4.3 does
/// not allow in `msg`, if any. Such an extension MUST be answered with
/// `illegal_parameter`.
pub(crate) fn first_disallowed(
    received: impl IntoIterator<Item = ExtensionType>,
    msg: Tls13Message,
) -> Option<ExtensionType> {
    received
        .into_iter()
        .find(|ext| allowed_in(*ext, msg) == Some(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_1_samples() {
        use Tls13Message::*;
        assert_eq!(allowed_in(ExtensionType::KeyShare, ServerHello), Some(true));
        assert_eq!(
            allowed_in(ExtensionType::KeyShare, EncryptedExtensions),
            Some(false)
        );
        assert_eq!(
            allowed_in(ExtensionType::StatusRequest, Certificate),
            Some(true)
        );
        assert_eq!(
            allowed_in(ExtensionType::StatusRequest, EncryptedExtensions),
            Some(false)
        );
        assert_eq!(
            allowed_in(ExtensionType::EllipticCurves, EncryptedExtensions),
            Some(true)
        );
        assert_eq!(
            allowed_in(ExtensionType::EarlyData, NewSessionTicket),
            Some(true)
        );
        assert_eq!(
            allowed_in(ExtensionType::ServerName, ServerHello),
            Some(false)
        );
        assert_eq!(
            allowed_in(ExtensionType::Cookie, HelloRetryRequest),
            Some(true)
        );
        assert_eq!(allowed_in(ExtensionType::Cookie, ServerHello), Some(false));
        assert_eq!(
            allowed_in(ExtensionType::ExtendedMasterSecret, EncryptedExtensions),
            Some(false)
        );
        assert_eq!(
            allowed_in(ExtensionType::ExtendedMasterSecret, ClientHello),
            Some(true)
        );
        assert_eq!(
            allowed_in(ExtensionType::Unknown(0x1234), EncryptedExtensions),
            None
        );
    }

    #[test]
    fn first_disallowed_skips_unknown() {
        assert_eq!(
            first_disallowed(
                [
                    ExtensionType::Unknown(0xfafa),
                    ExtensionType::ALProtocolNegotiation,
                    ExtensionType::KeyShare,
                ],
                Tls13Message::EncryptedExtensions,
            ),
            Some(ExtensionType::KeyShare)
        );
        assert_eq!(
            first_disallowed(
                [ExtensionType::Unknown(0xfafa)],
                Tls13Message::EncryptedExtensions
            ),
            None
        );
    }
}
