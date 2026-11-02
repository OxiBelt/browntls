//! Extension payload building blocks and the extensions a server sends.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::DnsName;

use super::MAX_EXTENSIONS;
use crate::enums::{CertificateType, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::msgs::base::{Payload, PayloadU8, PayloadU16};
use crate::msgs::codec::{
    Codec, LengthPrefixedBuffer, ListLength, Reader, encode_vec_u8, read_list_prefix,
    read_nonempty_vec_u8,
};
use crate::msgs::enums::{ECPointFormat, ExtensionType, NamedGroup, ServerNameType};

/// Iterates over an extension block (`Extension extensions<..>`), calling
/// `handler` for each entry. Duplicate extension types and over-long blocks
/// are rejected before `handler` sees them.
pub(crate) fn read_extensions<'a>(
    r: &mut Reader<'a>,
    mut handler: impl FnMut(ExtensionType, &mut Reader<'a>) -> Result<(), InvalidMessage>,
) -> Result<Vec<ExtensionType>, InvalidMessage> {
    let mut seen = Vec::new();
    let mut sub = read_list_prefix(ListLength::U16, r)?;
    while sub.any_left() {
        if seen.len() >= MAX_EXTENSIONS {
            return Err(InvalidMessage::MessageTooLarge);
        }
        let typ = ExtensionType::read(&mut sub)?;
        if seen.contains(&typ) {
            return Err(InvalidMessage::DuplicateExtension(u16::from(typ)));
        }
        let len = usize::from(u16::read(&mut sub)?);
        let mut body = sub.sub(len)?;
        handler(typ, &mut body)?;
        body.expect_empty("extension")?;
        seen.push(typ);
    }
    Ok(seen)
}

/// Writes one extension: type, u16 length, body produced by `f`.
pub(crate) fn encode_extension(
    typ: ExtensionType,
    bytes: &mut Vec<u8>,
    f: impl FnOnce(&mut Vec<u8>),
) {
    typ.encode(bytes);
    let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
    f(nested.buf);
}

/// The `server_name` extension (RFC 6066 §3): exactly one `host_name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServerNamePayload<'a> {
    /// A single, syntactically valid DNS name.
    SingleDnsName(DnsName<'a>),
    /// The server's empty acknowledgement.
    Empty,
}

impl ServerNamePayload<'_> {
    pub(crate) fn into_owned(self) -> ServerNamePayload<'static> {
        match self {
            Self::SingleDnsName(d) => ServerNamePayload::SingleDnsName(d.to_owned()),
            Self::Empty => ServerNamePayload::Empty,
        }
    }

    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::SingleDnsName(name) => {
                let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
                ServerNameType::HostName.encode(list.buf);
                PayloadU16::encode_slice(name.as_ref().as_bytes(), list.buf);
            }
            Self::Empty => {}
        }
    }

    /// Parses the client's form: a non-empty list with exactly one host name.
    pub(crate) fn read_client(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut list = read_list_prefix(ListLength::U16, r)?;
        let mut name = None;
        while list.any_left() {
            let typ = ServerNameType::read(&mut list)?;
            let value = PayloadU16::read(&mut list)?;
            match typ {
                ServerNameType::HostName => {
                    if name.is_some() {
                        // RFC 6066 §3: at most one name of each type.
                        return Err(InvalidMessage::InvalidServerName);
                    }
                    let s = core::str::from_utf8(&value.0).map_err(|_| InvalidMessage::InvalidServerName)?;
                    let dns = DnsName::try_from(s).map_err(|_| InvalidMessage::InvalidServerName)?;
                    name = Some(dns.to_owned());
                }
                _ => {
                    // Unknown name types are ignored, as RFC 6066 permits.
                }
            }
        }
        match name {
            Some(name) => Ok(Self::SingleDnsName(name)),
            None => Err(InvalidMessage::InvalidServerName),
        }
    }
}

/// An ALPN protocol name: 1..=255 bytes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProtocolName(PayloadU8);

impl ProtocolName {
    pub(crate) fn as_ref(&self) -> &[u8] {
        &self.0.0
    }
}

impl From<Vec<u8>> for ProtocolName {
    fn from(v: Vec<u8>) -> Self {
        Self(PayloadU8::new(v))
    }
}

impl fmt::Debug for ProtocolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(self.as_ref()) {
            Ok(s) if !s.chars().any(char::is_control) => write!(f, "{s:?}"),
            _ => self.0.fmt(f),
        }
    }
}

impl Codec<'_> for ProtocolName {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let p = PayloadU8::read(r)?;
        if p.0.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self(p))
    }
}

/// A `KeyShareEntry` (RFC 8446 §4.2.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyShareEntry {
    pub(crate) group: NamedGroup,
    pub(crate) payload: PayloadU16,
}

impl KeyShareEntry {
    pub(crate) fn new(group: NamedGroup, payload: &[u8]) -> Self {
        Self {
            group,
            payload: PayloadU16::new(payload.to_vec()),
        }
    }
}

impl Codec<'_> for KeyShareEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.group.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let group = NamedGroup::read(r)?;
        let payload = PayloadU16::read(r)?;
        if payload.0.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self { group, payload })
    }
}

/// A `PskIdentity` (RFC 8446 §4.2.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PresharedKeyIdentity {
    pub(crate) identity: PayloadU16,
    pub(crate) obfuscated_ticket_age: u32,
}

impl PresharedKeyIdentity {
    pub(crate) fn new(identity: Vec<u8>, obfuscated_ticket_age: u32) -> Self {
        Self {
            identity: PayloadU16::new(identity),
            obfuscated_ticket_age,
        }
    }
}

impl Codec<'_> for PresharedKeyIdentity {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identity.encode(bytes);
        self.obfuscated_ticket_age.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let identity = PayloadU16::read(r)?;
        if identity.0.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self {
            identity,
            obfuscated_ticket_age: u32::read(r)?,
        })
    }
}

/// A `PskBinderEntry`: 32..=255 bytes of HMAC output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PresharedKeyBinder(pub(crate) PayloadU8);

impl PresharedKeyBinder {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(PayloadU8::new(bytes))
    }

    pub(crate) fn as_ref(&self) -> &[u8] {
        &self.0.0
    }
}

impl Codec<'_> for PresharedKeyBinder {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let p = PayloadU8::read(r)?;
        if p.0.len() < 32 {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self(p))
    }
}

/// The client's `pre_shared_key` extension body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PresharedKeyOffer {
    pub(crate) identities: Vec<PresharedKeyIdentity>,
    pub(crate) binders: Vec<PresharedKeyBinder>,
}

impl PresharedKeyOffer {
    pub(crate) fn new(id: PresharedKeyIdentity, binder: Vec<u8>) -> Self {
        Self {
            identities: alloc::vec![id],
            binders: alloc::vec![PresharedKeyBinder::new(binder)],
        }
    }

    /// The length of the encoded binders list, which the binder computation
    /// excludes from the transcript (RFC 8446 §4.2.11.2).
    pub(crate) fn binders_encoded_len(&self) -> usize {
        2 + self.binders.iter().map(|b| 1 + b.as_ref().len()).sum::<usize>()
    }
}

impl Codec<'_> for PresharedKeyOffer {
    fn encode(&self, bytes: &mut Vec<u8>) {
        crate::msgs::codec::encode_vec_u16(bytes, &self.identities);
        crate::msgs::codec::encode_vec_u16(bytes, &self.binders);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            identities: crate::msgs::codec::read_nonempty_vec_u16(r, "PskIdentities")?,
            binders: crate::msgs::codec::read_nonempty_vec_u16(r, "PskBinders")?,
        })
    }
}

/// The client's `session_ticket` extension (RFC 5077 §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ClientSessionTicket {
    /// An empty extension requesting a ticket.
    Request,
    /// A previously issued ticket.
    Offer(Payload<'static>),
}

/// The extensions a server may send in ServerHello or EncryptedExtensions.
///
/// Which of these are permitted in which message is decided by the handshake
/// state machine; the codec only guarantees well-formedness and uniqueness.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServerExtensions {
    pub(crate) server_name_ack: Option<()>,
    pub(crate) alpn: Option<ProtocolName>,
    pub(crate) ec_point_formats: Option<Vec<ECPointFormat>>,
    pub(crate) extended_master_secret: Option<()>,
    pub(crate) session_ticket_ack: Option<()>,
    pub(crate) status_request_ack: Option<()>,
    pub(crate) sct_list: Option<Payload<'static>>,
    pub(crate) renegotiation_info: Option<PayloadU8>,
    pub(crate) key_share: Option<KeyShareEntry>,
    pub(crate) pre_shared_key: Option<u16>,
    pub(crate) supported_versions: Option<ProtocolVersion>,
    pub(crate) early_data: Option<()>,
    pub(crate) transport_parameters: Option<Payload<'static>>,
    pub(crate) client_certificate_type: Option<CertificateType>,
    pub(crate) server_certificate_type: Option<CertificateType>,
    /// Extension types that were present but not understood, in order.
    pub(crate) unknown: Vec<ExtensionType>,
}

impl ServerExtensions {
    /// The types of every extension present, for unsolicited-extension checks.
    pub(crate) fn present_types(&self) -> Vec<ExtensionType> {
        let mut out = Vec::new();
        let mut add = |present: bool, typ: ExtensionType| {
            if present {
                out.push(typ);
            }
        };
        add(self.server_name_ack.is_some(), ExtensionType::ServerName);
        add(self.alpn.is_some(), ExtensionType::ALProtocolNegotiation);
        add(self.ec_point_formats.is_some(), ExtensionType::ECPointFormats);
        add(
            self.extended_master_secret.is_some(),
            ExtensionType::ExtendedMasterSecret,
        );
        add(self.session_ticket_ack.is_some(), ExtensionType::SessionTicket);
        add(self.status_request_ack.is_some(), ExtensionType::StatusRequest);
        add(self.sct_list.is_some(), ExtensionType::SCT);
        add(self.renegotiation_info.is_some(), ExtensionType::RenegotiationInfo);
        add(self.key_share.is_some(), ExtensionType::KeyShare);
        add(self.pre_shared_key.is_some(), ExtensionType::PreSharedKey);
        add(self.supported_versions.is_some(), ExtensionType::SupportedVersions);
        add(self.early_data.is_some(), ExtensionType::EarlyData);
        add(
            self.transport_parameters.is_some(),
            ExtensionType::TransportParameters,
        );
        add(
            self.client_certificate_type.is_some(),
            ExtensionType::ClientCertificateType,
        );
        add(
            self.server_certificate_type.is_some(),
            ExtensionType::ServerCertificateType,
        );
        out.extend(self.unknown.iter().copied());
        out
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.present_types().is_empty()
    }
}

impl Codec<'_> for ServerExtensions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        let out = &mut *list.buf;
        if self.server_name_ack.is_some() {
            encode_extension(ExtensionType::ServerName, out, |_| {});
        }
        if let Some(alpn) = &self.alpn {
            encode_extension(ExtensionType::ALProtocolNegotiation, out, |b| {
                crate::msgs::codec::encode_vec_u16(b, core::slice::from_ref(alpn));
            });
        }
        if let Some(formats) = &self.ec_point_formats {
            encode_extension(ExtensionType::ECPointFormats, out, |b| encode_vec_u8(b, formats));
        }
        if self.extended_master_secret.is_some() {
            encode_extension(ExtensionType::ExtendedMasterSecret, out, |_| {});
        }
        if self.session_ticket_ack.is_some() {
            encode_extension(ExtensionType::SessionTicket, out, |_| {});
        }
        if self.status_request_ack.is_some() {
            encode_extension(ExtensionType::StatusRequest, out, |_| {});
        }
        if let Some(sct) = &self.sct_list {
            encode_extension(ExtensionType::SCT, out, |b| sct.encode(b));
        }
        if let Some(ri) = &self.renegotiation_info {
            encode_extension(ExtensionType::RenegotiationInfo, out, |b| ri.encode(b));
        }
        if let Some(ks) = &self.key_share {
            encode_extension(ExtensionType::KeyShare, out, |b| ks.encode(b));
        }
        if let Some(psk) = &self.pre_shared_key {
            encode_extension(ExtensionType::PreSharedKey, out, |b| psk.encode(b));
        }
        if let Some(v) = &self.supported_versions {
            encode_extension(ExtensionType::SupportedVersions, out, |b| v.encode(b));
        }
        if self.early_data.is_some() {
            encode_extension(ExtensionType::EarlyData, out, |_| {});
        }
        if let Some(tp) = &self.transport_parameters {
            encode_extension(ExtensionType::TransportParameters, out, |b| tp.encode(b));
        }
        if let Some(ct) = &self.client_certificate_type {
            encode_extension(ExtensionType::ClientCertificateType, out, |b| ct.encode(b));
        }
        if let Some(ct) = &self.server_certificate_type {
            encode_extension(ExtensionType::ServerCertificateType, out, |b| ct.encode(b));
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();
        read_extensions(r, |typ, body| {
            match typ {
                ExtensionType::ServerName => out.server_name_ack = Some(()),
                ExtensionType::ALProtocolNegotiation => {
                    let mut names: Vec<ProtocolName> =
                        crate::msgs::codec::read_nonempty_vec_u16(body, "ProtocolNameList")?;
                    if names.len() != 1 {
                        return Err(InvalidMessage::TrailingData("ProtocolNameList"));
                    }
                    out.alpn = names.pop();
                }
                ExtensionType::ECPointFormats => {
                    out.ec_point_formats = Some(read_nonempty_vec_u8(body, "ECPointFormatList")?);
                }
                ExtensionType::ExtendedMasterSecret => out.extended_master_secret = Some(()),
                ExtensionType::SessionTicket => out.session_ticket_ack = Some(()),
                ExtensionType::StatusRequest => out.status_request_ack = Some(()),
                ExtensionType::SCT => out.sct_list = Some(Payload::read(body).into_owned()),
                ExtensionType::RenegotiationInfo => {
                    out.renegotiation_info = Some(PayloadU8::read(body)?);
                }
                ExtensionType::KeyShare => out.key_share = Some(KeyShareEntry::read(body)?),
                ExtensionType::PreSharedKey => out.pre_shared_key = Some(u16::read(body)?),
                ExtensionType::SupportedVersions => {
                    out.supported_versions = Some(ProtocolVersion::read(body)?);
                }
                ExtensionType::EarlyData => out.early_data = Some(()),
                ExtensionType::TransportParameters | ExtensionType::TransportParametersDraft => {
                    out.transport_parameters = Some(Payload::read(body).into_owned());
                }
                ExtensionType::ClientCertificateType => {
                    out.client_certificate_type = Some(CertificateType::read(body)?);
                }
                ExtensionType::ServerCertificateType => {
                    out.server_certificate_type = Some(CertificateType::read(body)?);
                }
                other => {
                    out.unknown.push(other);
                    body.rest();
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_loop_rejects_duplicates_and_overrun() {
        // two ServerName extensions
        let bytes = [0, 8, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = read_extensions(&mut Reader::init(&bytes), |_, _| Ok(())).unwrap_err();
        assert_eq!(err, InvalidMessage::DuplicateExtension(0));
        // body length overruns the block
        let bytes = [0, 4, 0, 0, 0, 5];
        let err = read_extensions(&mut Reader::init(&bytes), |_, _| Ok(())).unwrap_err();
        assert_eq!(err, InvalidMessage::MessageTooShort);
        // handler leaves bytes unread
        let bytes = [0, 5, 0, 0, 0, 1, 7];
        let err = read_extensions(&mut Reader::init(&bytes), |_, _| Ok(())).unwrap_err();
        assert_eq!(err, InvalidMessage::TrailingData("extension"));
    }

    #[test]
    fn server_name_payload() {
        let name = ServerNamePayload::SingleDnsName(DnsName::try_from("example.com").unwrap());
        let mut bytes = Vec::new();
        name.encode(&mut bytes);
        assert_eq!(
            bytes,
            [0, 14, 0, 0, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm']
        );
        let back = ServerNamePayload::read_client(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(back, name);
        // IP literal is not a valid host_name
        let bad = [0, 10, 0, 0, 7, b'1', b'.', b'2', b'.', b'3', b'.', b'4'];
        assert_eq!(
            ServerNamePayload::read_client(&mut Reader::init(&bad)),
            Err(InvalidMessage::InvalidServerName)
        );
        // two host names
        let mut two = Vec::new();
        two.extend([0, 12, 0, 0, 1, b'a', 0, 0, 1, b'b', 0, 0, 1, b'c']);
        assert_eq!(
            ServerNamePayload::read_client(&mut Reader::init(&two)),
            Err(InvalidMessage::InvalidServerName)
        );
        // no host name entry at all
        assert_eq!(
            ServerNamePayload::read_client(&mut Reader::init(&[0, 0])),
            Err(InvalidMessage::InvalidServerName)
        );
    }

    #[test]
    fn server_extensions_roundtrip() {
        let exts = ServerExtensions {
            server_name_ack: Some(()),
            alpn: Some(ProtocolName::from(b"h2".to_vec())),
            key_share: Some(KeyShareEntry::new(NamedGroup::X25519, &[1; 32])),
            pre_shared_key: Some(0),
            supported_versions: Some(ProtocolVersion::TLSv1_3),
            ..Default::default()
        };
        let enc = exts.get_encoding();
        let back = ServerExtensions::read_bytes(&enc).unwrap();
        assert_eq!(back, exts);
        assert_eq!(
            back.present_types(),
            [
                ExtensionType::ServerName,
                ExtensionType::ALProtocolNegotiation,
                ExtensionType::KeyShare,
                ExtensionType::PreSharedKey,
                ExtensionType::SupportedVersions
            ]
        );
        assert!(ServerExtensions::default().is_empty());
        assert_eq!(alloc::format!("{:?}", exts.alpn.unwrap()), "\"h2\"");
    }

    #[test]
    fn server_alpn_must_have_one_name() {
        // ALPN extension with two protocol names
        let bytes = [0, 10, 0, 0x10, 0, 6, 0, 4, 1, b'a', 1, b'b'];
        assert_eq!(
            ServerExtensions::read_bytes(&bytes),
            Err(InvalidMessage::TrailingData("ProtocolNameList"))
        );
    }

    #[test]
    fn binder_too_short() {
        assert_eq!(
            PresharedKeyBinder::read_bytes(&[2, 1, 2]),
            Err(InvalidMessage::IllegalEmptyValue)
        );
        let offer = PresharedKeyOffer::new(PresharedKeyIdentity::new(alloc::vec![1], 5), alloc::vec![0; 32]);
        assert_eq!(offer.binders_encoded_len(), 2 + 33);
        assert_eq!(PresharedKeyOffer::read_bytes(&offer.get_encoding()).unwrap(), offer);
    }
}
