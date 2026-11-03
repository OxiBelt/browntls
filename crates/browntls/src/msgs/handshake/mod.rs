//! Handshake messages (RFC 8446 §4, RFC 5246 §7.4).

mod certs;
mod extensions;
mod hello;
mod kx;
mod tickets;

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::CertificateDer;

pub(crate) use certs::{
    CertificateChain, CertificateEntry, CertificatePayloadTls13, CertificateRequestExtensions,
    CertificateRequestPayload, CertificateRequestPayloadTls13, CertificateStatus,
    CertificateStatusRequest, CompressedCertificatePayload,
};
pub(crate) use extensions::{
    ClientSessionTicket, KeyShareEntry, PresharedKeyBinder, PresharedKeyIdentity,
    PresharedKeyOffer, ProtocolName, ServerExtensions, ServerNamePayload,
};
pub(crate) use hello::{
    ClientExtensions, HelloRetryRequest, HelloRetryRequestExtensions, ServerHelloPayload,
};
pub use hello::{ClientHelloPayload, HandshakeMessagePayload};
pub(crate) use kx::{
    ClientEcdhParams, ServerEcdhParams, ServerKeyExchange, ServerKeyExchangeParams,
    ServerKeyExchangePayload,
};
pub(crate) use tickets::{
    NewSessionTicketExtensions, NewSessionTicketPayload, NewSessionTicketPayloadTls13,
};

use super::base::{Payload, PayloadU8, PayloadU16};
use super::codec::{Codec, Reader, u24};
use super::enums::KeyUpdateRequest;
use crate::enums::{CipherSuite, HandshakeType, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::verify::DigitallySignedStruct;
use crate::x509;

/// Handshake messages may be at most this many bytes.
pub(crate) const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

/// A certificate payload (chain or single certificate) may be at most this long.
pub(crate) const MAX_CERTIFICATE_SIZE_LIMIT: usize = 0x1_0000;

/// At most this many extensions are accepted in one extension block.
pub(crate) const MAX_EXTENSIONS: usize = 128;

enum_builder! {
    /// The TLS 1.2 key exchange algorithm families.
    #[repr(u8)]
    pub enum KeyExchangeAlgorithm {
        /// Finite-field Diffie-Hellman.
        DHE => 0x01,
        /// Elliptic-curve Diffie-Hellman.
        ECDHE => 0x02,
    }
}

pub(crate) static ALL_KEY_EXCHANGE_ALGORITHMS: &[KeyExchangeAlgorithm] =
    &[KeyExchangeAlgorithm::ECDHE, KeyExchangeAlgorithm::DHE];

/// The 32-byte `Random` field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Random(pub(crate) [u8; 32]);

impl Random {
    pub(crate) fn new(
        rng: &dyn crate::crypto::SecureRandom,
    ) -> Result<Self, crate::rand::GetRandomFailed> {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Codec<'_> for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let Some(bytes) = r.take(32) else {
            return Err(InvalidMessage::MissingData("Random"));
        };
        let mut opaque = [0u8; 32];
        opaque.copy_from_slice(bytes);
        Ok(Self(opaque))
    }
}

impl From<[u8; 32]> for Random {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Random {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::base::hex(f, &self.0)
    }
}

/// The downgrade sentinel for TLS 1.2 (RFC 8446 §4.1.3).
pub(crate) static DOWNGRADE_SENTINEL_TLS12: [u8; 8] =
    [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];

/// The downgrade sentinel for TLS 1.1 and below.
pub(crate) static DOWNGRADE_SENTINEL_TLS11: [u8; 8] =
    [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];

/// The `legacy_session_id` field: 0..=32 opaque bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct SessionId {
    len: usize,
    data: [u8; 32],
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::base::hex(f, self.as_ref())
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Codec<'_> for SessionId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Invariant: `len <= 32`.
        bytes.push(self.len as u8);
        bytes.extend_from_slice(self.as_ref());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = usize::from(u8::read(r)?);
        if len > 32 {
            return Err(InvalidMessage::TrailingData("SessionID"));
        }
        let Some(bytes) = r.take(len) else {
            return Err(InvalidMessage::MissingData("SessionID"));
        };
        let mut out = [0u8; 32];
        out[..len].copy_from_slice(bytes);
        Ok(Self { data: out, len })
    }
}

impl SessionId {
    pub(crate) fn random(
        rng: &dyn crate::crypto::SecureRandom,
    ) -> Result<Self, crate::rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        rng.fill(&mut data)?;
        Ok(Self { data, len: 32 })
    }

    pub(crate) fn empty() -> Self {
        Self {
            data: [0u8; 32],
            len: 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 32 {
            return None;
        }
        let mut data = [0u8; 32];
        data[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            data,
            len: bytes.len(),
        })
    }
}

/// An X.501 `Name` in DER form, as carried in `certificate_authorities`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistinguishedName(PayloadU16);

impl DistinguishedName {
    /// Wraps a DER-encoded `Name` (which must include its outer SEQUENCE).
    pub fn new(der: Vec<u8>) -> Self {
        Self(PayloadU16::new(der))
    }

    /// Wraps the contents of a `Name` (without the outer SEQUENCE) in a SEQUENCE.
    pub fn in_sequence(contents: &[u8]) -> Self {
        Self::new(x509::wrap_in_sequence(contents))
    }
}

impl AsRef<[u8]> for DistinguishedName {
    fn as_ref(&self) -> &[u8] {
        &self.0.0
    }
}

impl Codec<'_> for DistinguishedName {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let name = PayloadU16::read(r)?;
        if name.0.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self(name))
    }
}

impl<'a> Codec<'a> for CertificateDer<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        u24::from_usize(self.as_ref().len())
            .unwrap_or(u24(u24::MAX))
            .encode(bytes);
        bytes.extend_from_slice(self.as_ref());
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = usize::from(u24::read(r)?);
        if len > MAX_CERTIFICATE_SIZE_LIMIT {
            return Err(InvalidMessage::CertificatePayloadTooLarge);
        }
        let mut sub = r.sub(len)?;
        let body = sub.rest();
        if body.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self::from_slice(body))
    }
}

/// The body of a handshake message, by type.
#[derive(Debug)]
pub(crate) enum HandshakePayload<'a> {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    HelloRetryRequest(HelloRetryRequest),
    Certificate(CertificateChain<'a>),
    CertificateTls13(CertificatePayloadTls13<'a>),
    CompressedCertificate(CompressedCertificatePayload<'a>),
    ServerKeyExchange(ServerKeyExchangePayload),
    CertificateRequest(CertificateRequestPayload),
    CertificateRequestTls13(CertificateRequestPayloadTls13),
    CertificateVerify(DigitallySignedStruct),
    ServerHelloDone,
    EndOfEarlyData,
    ClientKeyExchange(Payload<'a>),
    NewSessionTicket(NewSessionTicketPayload),
    NewSessionTicketTls13(NewSessionTicketPayloadTls13),
    EncryptedExtensions(ServerExtensions),
    KeyUpdate(KeyUpdateRequest),
    Finished(Payload<'a>),
    CertificateStatus(CertificateStatus<'a>),
    MessageHash(Payload<'a>),
    Unknown((HandshakeType, Payload<'a>)),
}

impl<'a> HandshakePayload<'a> {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::HelloRequest | Self::ServerHelloDone | Self::EndOfEarlyData => {}
            Self::ClientHello(x) => x.encode(bytes),
            Self::ServerHello(x) => x.encode(bytes),
            Self::HelloRetryRequest(x) => x.encode(bytes),
            Self::Certificate(x) => x.encode(bytes),
            Self::CertificateTls13(x) => x.encode(bytes),
            Self::CompressedCertificate(x) => x.encode(bytes),
            Self::ServerKeyExchange(x) => x.encode(bytes),
            Self::ClientKeyExchange(x) => x.encode(bytes),
            Self::CertificateRequest(x) => x.encode(bytes),
            Self::CertificateRequestTls13(x) => x.encode(bytes),
            Self::CertificateVerify(x) => x.encode(bytes),
            Self::NewSessionTicket(x) => x.encode(bytes),
            Self::NewSessionTicketTls13(x) => x.encode(bytes),
            Self::EncryptedExtensions(x) => x.encode(bytes),
            Self::KeyUpdate(x) => x.encode(bytes),
            Self::Finished(x) => x.encode(bytes),
            Self::CertificateStatus(x) => x.encode(bytes),
            Self::MessageHash(x) => x.encode(bytes),
            Self::Unknown((_, x)) => x.encode(bytes),
        }
    }

    pub(crate) fn handshake_type(&self) -> HandshakeType {
        match self {
            Self::HelloRequest => HandshakeType::HelloRequest,
            Self::ClientHello(_) => HandshakeType::ClientHello,
            Self::ServerHello(_) => HandshakeType::ServerHello,
            Self::HelloRetryRequest(_) => HandshakeType::HelloRetryRequest,
            Self::Certificate(_) | Self::CertificateTls13(_) => HandshakeType::Certificate,
            Self::CompressedCertificate(_) => HandshakeType::CompressedCertificate,
            Self::ServerKeyExchange(_) => HandshakeType::ServerKeyExchange,
            Self::CertificateRequest(_) | Self::CertificateRequestTls13(_) => {
                HandshakeType::CertificateRequest
            }
            Self::CertificateVerify(_) => HandshakeType::CertificateVerify,
            Self::ServerHelloDone => HandshakeType::ServerHelloDone,
            Self::EndOfEarlyData => HandshakeType::EndOfEarlyData,
            Self::ClientKeyExchange(_) => HandshakeType::ClientKeyExchange,
            Self::NewSessionTicket(_) | Self::NewSessionTicketTls13(_) => {
                HandshakeType::NewSessionTicket
            }
            Self::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            Self::KeyUpdate(_) => HandshakeType::KeyUpdate,
            Self::Finished(_) => HandshakeType::Finished,
            Self::CertificateStatus(_) => HandshakeType::CertificateStatus,
            Self::MessageHash(_) => HandshakeType::MessageHash,
            Self::Unknown((t, _)) => *t,
        }
    }

    pub(crate) fn into_owned(self) -> HandshakePayload<'static> {
        use HandshakePayload::*;
        match self {
            HelloRequest => HelloRequest,
            ClientHello(x) => ClientHello(x),
            ServerHello(x) => ServerHello(x),
            HelloRetryRequest(x) => HelloRetryRequest(x),
            Certificate(x) => Certificate(x.into_owned()),
            CertificateTls13(x) => CertificateTls13(x.into_owned()),
            CompressedCertificate(x) => CompressedCertificate(x.into_owned()),
            ServerKeyExchange(x) => ServerKeyExchange(x),
            CertificateRequest(x) => CertificateRequest(x),
            CertificateRequestTls13(x) => CertificateRequestTls13(x),
            CertificateVerify(x) => CertificateVerify(x),
            ServerHelloDone => ServerHelloDone,
            EndOfEarlyData => EndOfEarlyData,
            ClientKeyExchange(x) => ClientKeyExchange(x.into_owned()),
            NewSessionTicket(x) => NewSessionTicket(x),
            NewSessionTicketTls13(x) => NewSessionTicketTls13(x),
            EncryptedExtensions(x) => EncryptedExtensions(x),
            KeyUpdate(x) => KeyUpdate(x),
            Finished(x) => Finished(x.into_owned()),
            CertificateStatus(x) => CertificateStatus(x.into_owned()),
            MessageHash(x) => MessageHash(x.into_owned()),
            Unknown((t, x)) => Unknown((t, x.into_owned())),
        }
    }
}

/// Reads the handshake payload for `typ` from `sub`, which holds exactly the
/// payload bytes. `vers` selects version-dependent formats.
pub(crate) fn read_payload<'a>(
    typ: HandshakeType,
    vers: ProtocolVersion,
    sub: &mut Reader<'a>,
) -> Result<HandshakePayload<'a>, InvalidMessage> {
    use HandshakePayload::*;
    let payload = match typ {
        HandshakeType::HelloRequest if sub.left() == 0 => HelloRequest,
        HandshakeType::ClientHello => ClientHello(ClientHelloPayload::read(sub)?),
        HandshakeType::ServerHello => match ServerHelloPayload::read(sub)? {
            hello::ServerHelloOrRetry::Hello(sh) => ServerHello(sh),
            hello::ServerHelloOrRetry::Retry(hrr) => HelloRetryRequest(hrr),
        },
        HandshakeType::Certificate if vers == ProtocolVersion::TLSv1_3 => {
            CertificateTls13(CertificatePayloadTls13::read(sub)?)
        }
        HandshakeType::Certificate => Certificate(CertificateChain::read(sub)?),
        HandshakeType::CompressedCertificate => {
            CompressedCertificate(CompressedCertificatePayload::read(sub)?)
        }
        HandshakeType::ServerKeyExchange => ServerKeyExchange(ServerKeyExchangePayload::read(sub)?),
        HandshakeType::ServerHelloDone if sub.left() == 0 => ServerHelloDone,
        HandshakeType::ClientKeyExchange => ClientKeyExchange(Payload::read(sub)),
        HandshakeType::CertificateRequest if vers == ProtocolVersion::TLSv1_3 => {
            CertificateRequestTls13(CertificateRequestPayloadTls13::read(sub)?)
        }
        HandshakeType::CertificateRequest => {
            CertificateRequest(CertificateRequestPayload::read(sub)?)
        }
        HandshakeType::CertificateVerify => CertificateVerify(DigitallySignedStruct::read(sub)?),
        HandshakeType::NewSessionTicket if vers == ProtocolVersion::TLSv1_3 => {
            NewSessionTicketTls13(NewSessionTicketPayloadTls13::read(sub)?)
        }
        HandshakeType::NewSessionTicket => NewSessionTicket(NewSessionTicketPayload::read(sub)?),
        HandshakeType::EncryptedExtensions => EncryptedExtensions(ServerExtensions::read(sub)?),
        HandshakeType::KeyUpdate => KeyUpdate(KeyUpdateRequest::read(sub)?),
        HandshakeType::EndOfEarlyData if sub.left() == 0 => EndOfEarlyData,
        HandshakeType::Finished => Finished(Payload::read(sub)),
        HandshakeType::CertificateStatus => CertificateStatus(certs::CertificateStatus::read(sub)?),
        HandshakeType::MessageHash => {
            // A MessageHash is a transcript-only construct and never appears on the wire.
            return Err(InvalidMessage::UnexpectedMessage("MessageHash"));
        }
        HandshakeType::HelloRetryRequest => {
            // A HelloRetryRequest is always encoded as a ServerHello (RFC 8446 §4.1.4).
            return Err(InvalidMessage::UnexpectedMessage("HelloRetryRequest"));
        }
        _ => Unknown((typ, Payload::read(sub))),
    };
    sub.expect_empty("HandshakeMessagePayload")?;
    Ok(payload)
}

/// Helper used by the suite-selection code: is `suite` offered by the peer?
pub(crate) fn cipher_suite_offered(offered: &[CipherSuite], suite: CipherSuite) -> bool {
    offered.contains(&suite)
}

/// Encodes a `u8`-prefixed payload for a client-facing protocol name list.
pub(crate) fn payload_u8(bytes: &[u8]) -> PayloadU8 {
    PayloadU8::new(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_bounds() {
        let sid = SessionId::from_slice(&[7; 32]).unwrap();
        assert_eq!(sid.get_encoding().len(), 33);
        assert_eq!(SessionId::read_bytes(&sid.get_encoding()).unwrap(), sid);
        assert!(SessionId::from_slice(&[0; 33]).is_none());
        assert_eq!(
            SessionId::read_bytes(&[33]),
            Err(InvalidMessage::TrailingData("SessionID"))
        );
        assert_eq!(
            SessionId::read_bytes(&[2, 1]),
            Err(InvalidMessage::MissingData("SessionID"))
        );
        assert!(SessionId::empty().is_empty());
    }

    #[test]
    fn certificate_der_codec() {
        let cert = CertificateDer::from_slice(&[1, 2, 3]);
        assert_eq!(cert.get_encoding(), [0, 0, 3, 1, 2, 3]);
        assert_eq!(
            CertificateDer::read_bytes(&[0, 0, 3, 1, 2, 3]).unwrap(),
            cert
        );
        assert_eq!(
            CertificateDer::read_bytes(&[0, 0, 0]),
            Err(InvalidMessage::IllegalEmptyValue)
        );
        assert_eq!(
            CertificateDer::read_bytes(&[0x01, 0, 1]),
            Err(InvalidMessage::CertificatePayloadTooLarge)
        );
    }

    #[test]
    fn distinguished_name_codec() {
        let dn = DistinguishedName::in_sequence(&[1, 2]);
        assert_eq!(dn.as_ref(), [0x30, 2, 1, 2]);
        assert_eq!(
            DistinguishedName::read_bytes(&dn.get_encoding()).unwrap(),
            dn
        );
        assert_eq!(
            DistinguishedName::read_bytes(&[0, 0]),
            Err(InvalidMessage::IllegalEmptyValue)
        );
    }

    #[test]
    fn random_codec() {
        let r = Random::from([3u8; 32]);
        assert_eq!(Random::read_bytes(&r.get_encoding()).unwrap(), r);
        assert_eq!(
            Random::read_bytes(&[0; 31]),
            Err(InvalidMessage::MissingData("Random"))
        );
    }
}
