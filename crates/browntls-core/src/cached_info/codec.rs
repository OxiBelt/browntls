//! The wire forms of RFC 7924: the ClientHello and ServerHello extension
//! bodies (§3) and the hash form of a replaced message (§4.1, §4.2).

use alloc::vec::Vec;

use super::{CachedInformationType, CachedInformationTypes, CachedObject};
use crate::enums::{HandshakeType, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::msgs::base::{Payload, PayloadU16};
use crate::msgs::codec::{Codec, LengthPrefixedBuffer, ListLength, Reader, read_list_prefix, u24};
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload, MAX_HANDSHAKE_SIZE};

/// The ClientHello `cached_info` body (RFC 7924 §3):
///
/// ```text
/// struct { CachedInformationType type; opaque hash_value<1..255>; }
///     CachedObject;
/// CachedObject cached_info<1..2^16-1>;
/// ```
///
/// Kept as the validated list contents: one allocation, however many
/// objects a peer lists. Types this crate does not implement are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientHelloCachedInfo {
    list: Vec<u8>,
}

impl ClientHelloCachedInfo {
    /// The extension offering `objects`, or `None` when there are none.
    pub(crate) fn from_objects<'a>(
        objects: impl IntoIterator<Item = &'a CachedObject>,
    ) -> Option<Self> {
        let mut list = Vec::new();
        for object in objects {
            list.push(object.typ().code());
            // A fingerprint is 32 bytes: within `hash_value<1..255>`.
            list.push(object.fingerprint().len() as u8);
            list.extend_from_slice(object.fingerprint());
        }
        (!list.is_empty()).then_some(Self { list })
    }

    /// The listed objects: type code point and hash value.
    pub(crate) fn entries(&self) -> impl Iterator<Item = (u8, &[u8])> {
        let mut r = Reader::init(&self.list);
        core::iter::from_fn(move || read_entry(&mut r).ok())
    }
}

/// Reads one `CachedObject` of the client form.
fn read_entry<'a>(r: &mut Reader<'a>) -> Result<(u8, &'a [u8]), InvalidMessage> {
    let typ = u8::read(r)?;
    let len = usize::from(u8::read(r)?);
    if len == 0 {
        return Err(InvalidMessage::IllegalEmptyValue);
    }
    let hash = r
        .take(len)
        .ok_or(InvalidMessage::MissingData("CachedObject"))?;
    Ok((typ, hash))
}

impl Codec<'_> for ClientHelloCachedInfo {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        nested.buf.extend_from_slice(&self.list);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut sub = read_list_prefix(ListLength::U16, r)?;
        let list = sub.rest();
        if list.is_empty() {
            return Err(InvalidMessage::IllegalEmptyList("CachedInformation"));
        }
        let mut check = Reader::init(list);
        while check.any_left() {
            read_entry(&mut check)?;
        }
        Ok(Self {
            list: list.to_vec(),
        })
    }
}

/// The ServerHello `cached_info` body (RFC 7924 §3): the acknowledged types,
/// `CachedObject cached_info<1..2^16-1>` with only a `type` each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerHelloCachedInfo {
    codes: Vec<u8>,
}

impl ServerHelloCachedInfo {
    /// The extension listing `types`, or `None` when there are none.
    pub(crate) fn from_types(types: CachedInformationTypes) -> Option<Self> {
        let codes: Vec<u8> = types.iter().map(CachedInformationType::code).collect();
        (!codes.is_empty()).then_some(Self { codes })
    }

    /// The listed type code points, in order, as sent.
    pub(crate) fn codes(&self) -> &[u8] {
        &self.codes
    }
}

impl Codec<'_> for ServerHelloCachedInfo {
    fn encode(&self, bytes: &mut Vec<u8>) {
        PayloadU16::new(self.codes.clone()).encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let codes = PayloadU16::read(r)?.0;
        if codes.is_empty() {
            return Err(InvalidMessage::IllegalEmptyList("CachedInformation"));
        }
        Ok(Self { codes })
    }
}

/// The hash value of a replaced message's body, `opaque
/// hash_value<1..255>` with nothing after it (RFC 7924 §4.1, §4.2).
pub(crate) fn read_hash_form(body: &[u8]) -> Result<&[u8], InvalidMessage> {
    let mut r = Reader::init(body);
    let len = usize::from(u8::read(&mut r)?);
    if len == 0 {
        return Err(InvalidMessage::IllegalEmptyValue);
    }
    let hash = r
        .take(len)
        .ok_or(InvalidMessage::MissingData("hash_value"))?;
    r.expect_empty("hash_value")?;
    Ok(hash)
}

/// The message of type `typ` replaced by `hash`: `opaque
/// hash_value<1..255>` (RFC 7924 §4.1, §4.2). `hash` is a fingerprint, so
/// it fits.
pub(crate) fn hash_form_message(
    typ: HandshakeType,
    hash: &[u8],
) -> HandshakeMessagePayload<'static> {
    let mut body = Vec::with_capacity(1 + hash.len());
    body.push(u8::try_from(hash.len()).unwrap_or(u8::MAX));
    body.extend_from_slice(hash);
    HandshakeMessagePayload(HandshakePayload::Unknown((typ, Payload::new(body))))
}

/// Reads one complete handshake message (`bytes` holds exactly one, as the
/// deframer delivers it), like [`HandshakeMessagePayload::read_version`].
///
/// A TLS 1.2 Certificate or CertificateRequest whose type `expect` holds
/// (the server acknowledged it, RFC 7924 §4) is kept as an opaque body, to
/// be read as a hash form by the state machine: such a message is never
/// parsed as a full one, and a full one sent in its place fails there.
pub(crate) fn read_handshake(
    bytes: &[u8],
    vers: ProtocolVersion,
    expect: CachedInformationTypes,
) -> Result<HandshakeMessagePayload<'_>, InvalidMessage> {
    let mut r = Reader::init(bytes);
    if expect.is_empty() || vers != ProtocolVersion::TLSv1_2 {
        return HandshakeMessagePayload::read_version(&mut r, vers);
    }
    let typ = HandshakeType::read(&mut r)?;
    let hash_form = CachedInformationType::ALL
        .into_iter()
        .any(|t| expect.contains(t) && t.handshake_type() == typ);
    if !hash_form {
        return HandshakeMessagePayload::read_version(&mut Reader::init(bytes), vers);
    }
    let len = u24::read(&mut r)?.0;
    if len > MAX_HANDSHAKE_SIZE {
        return Err(InvalidMessage::HandshakePayloadTooLarge);
    }
    let mut sub = r.sub(len as usize)?;
    Ok(HandshakeMessagePayload(HandshakePayload::Unknown((
        typ,
        Payload::Borrowed(sub.rest()),
    ))))
}
