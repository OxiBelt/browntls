//! TLS records (RFC 8446 §5.1) and the messages they carry.

use alloc::vec::Vec;
use core::fmt;

use super::alert::AlertMessagePayload;
use super::base::Payload;
use super::ccs::ChangeCipherSpecPayload;
use super::codec::{Codec, Reader};
use super::enums::{AlertLevel, KeyUpdateRequest};
use super::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::enums::{AlertDescription, ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage};

/// The record header: content type, version, length.
pub(crate) const HEADER_SIZE: usize = 1 + 2 + 2;

/// The maximum plaintext fragment (RFC 8446 §5.1).
pub(crate) const MAX_PLAINTEXT_LEN: usize = 16_384;

/// The maximum ciphertext expansion we accept: TLS 1.2 permits 2048 bytes
/// (RFC 5246 §6.2.3), which also covers TLS 1.3's 256.
pub(crate) const MAX_CIPHERTEXT_OVERHEAD: usize = 2048;

/// The largest record body we accept.
pub(crate) const MAX_WIRE_SIZE: usize = MAX_PLAINTEXT_LEN + MAX_CIPHERTEXT_OVERHEAD;

/// Plaintext to be sent, possibly in several non-contiguous chunks.
#[derive(Debug, Clone, Copy)]
pub enum OutboundChunks<'a> {
    /// One contiguous slice.
    Single(&'a [u8]),
    /// Several slices, logically concatenated, restricted to `start..end`.
    Multiple {
        /// The slices.
        chunks: &'a [&'a [u8]],
        /// The logical start offset.
        start: usize,
        /// The logical end offset.
        end: usize,
    },
}

impl<'a> OutboundChunks<'a> {
    /// Wraps `chunks`, flattening the trivial cases.
    pub fn new(chunks: &'a [&'a [u8]]) -> Self {
        match chunks {
            [] => Self::Single(&[]),
            [one] => Self::Single(one),
            many => Self::Multiple {
                chunks: many,
                start: 0,
                end: many.iter().map(|c| c.len()).sum(),
            },
        }
    }

    /// The total length.
    pub fn len(&self) -> usize {
        match self {
            Self::Single(c) => c.len(),
            Self::Multiple { start, end, .. } => end - start,
        }
    }

    /// Whether there is no data.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Splits at `mid` (which must be at most `len()`).
    pub fn split_at(&self, mid: usize) -> (Self, Self) {
        let mid = mid.min(self.len());
        match self {
            Self::Single(c) => {
                let (a, b) = c.split_at(mid);
                (Self::Single(a), Self::Single(b))
            }
            Self::Multiple { chunks, start, end } => (
                Self::Multiple {
                    chunks,
                    start: *start,
                    end: start + mid,
                },
                Self::Multiple {
                    chunks,
                    start: start + mid,
                    end: *end,
                },
            ),
        }
    }

    /// Appends the data to `vec`.
    pub fn copy_to_vec(&self, vec: &mut Vec<u8>) {
        match self {
            Self::Single(c) => vec.extend_from_slice(c),
            Self::Multiple { chunks, start, end } => {
                let mut offset = 0;
                for chunk in chunks.iter() {
                    let chunk_start = offset;
                    let chunk_end = offset + chunk.len();
                    offset = chunk_end;
                    if chunk_end <= *start {
                        continue;
                    }
                    if chunk_start >= *end {
                        break;
                    }
                    let from = start.saturating_sub(chunk_start);
                    let to = (*end - chunk_start).min(chunk.len());
                    vec.extend_from_slice(&chunk[from..to]);
                }
            }
        }
    }

    /// The data as a fresh vector.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.len());
        self.copy_to_vec(&mut v);
        v
    }
}

impl<'a> From<&'a [u8]> for OutboundChunks<'a> {
    fn from(c: &'a [u8]) -> Self {
        Self::Single(c)
    }
}

/// A buffer for an outgoing record body with the header space reserved.
pub struct PrefixedPayload(Vec<u8>);

impl PrefixedPayload {
    /// Reserves room for the header and `capacity` payload bytes.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut v = Vec::with_capacity(HEADER_SIZE + capacity);
        v.resize(HEADER_SIZE, 0);
        Self(v)
    }

    /// Appends `slice`.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice);
    }

    /// Appends `chunks`.
    pub fn extend_from_chunks(&mut self, chunks: &OutboundChunks<'_>) {
        chunks.copy_to_vec(&mut self.0);
    }

    /// Truncates the payload to `len` bytes.
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(HEADER_SIZE + len);
    }

    /// Resizes the payload to `len` bytes, zero-filling any new bytes.
    pub fn resize(&mut self, len: usize) {
        self.0.resize(HEADER_SIZE + len, 0);
    }

    /// The payload length (excluding the header).
    pub fn len(&self) -> usize {
        self.0.len() - HEADER_SIZE
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsRef<[u8]> for PrefixedPayload {
    /// The payload bytes.
    fn as_ref(&self) -> &[u8] {
        &self.0[HEADER_SIZE..]
    }
}

impl AsMut<[u8]> for PrefixedPayload {
    /// The payload bytes, mutably.
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[HEADER_SIZE..]
    }
}

impl From<&[u8]> for PrefixedPayload {
    fn from(content: &[u8]) -> Self {
        let mut p = Self::with_capacity(content.len());
        p.extend_from_slice(content);
        p
    }
}

impl fmt::Debug for PrefixedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::base::hex(f, self.as_ref())
    }
}

/// An outgoing record, encrypted or not, ready for the wire.
pub struct OutboundOpaqueMessage {
    /// The content type on the wire.
    pub typ: ContentType,
    /// The version on the wire.
    pub version: ProtocolVersion,
    /// The body.
    pub payload: PrefixedPayload,
}

impl OutboundOpaqueMessage {
    /// Assembles a record.
    pub fn new(typ: ContentType, version: ProtocolVersion, payload: PrefixedPayload) -> Self {
        Self {
            typ,
            version,
            payload,
        }
    }

    /// Writes the header and returns the complete record.
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = self.payload.0;
        let len = bytes.len() - HEADER_SIZE;
        bytes[0] = self.typ.into();
        bytes[1..3].copy_from_slice(&u16::from(self.version).to_be_bytes());
        // `len` is bounded by `MAX_WIRE_SIZE`, so it fits.
        bytes[3..5].copy_from_slice(&(len as u16).to_be_bytes());
        bytes
    }
}

impl fmt::Debug for OutboundOpaqueMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundOpaqueMessage")
            .field("typ", &self.typ)
            .field("version", &self.version)
            .field("len", &self.payload.len())
            .finish()
    }
}

/// The body of an incoming record, decrypted in place.
pub struct BorrowedPayload<'a>(&'a mut [u8]);

impl<'a> BorrowedPayload<'a> {
    /// The current length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Shrinks the body to `len` bytes.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.0.len() {
            return;
        }
        let taken = core::mem::take(&mut self.0);
        self.0 = &mut taken[..len];
    }

    /// Removes the first `n` bytes (TLS 1.2 explicit nonces).
    pub fn consume_prefix(&mut self, n: usize) {
        let taken = core::mem::take(&mut self.0);
        let n = n.min(taken.len());
        self.0 = &mut taken[n..];
    }

    /// The body as a plain slice.
    pub fn into_inner(self) -> &'a [u8] {
        self.0
    }
}

impl core::ops::Deref for BorrowedPayload<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl core::ops::DerefMut for BorrowedPayload<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl fmt::Debug for BorrowedPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::base::hex(f, self.0)
    }
}

/// An incoming record before decryption.
#[derive(Debug)]
pub struct InboundOpaqueMessage<'a> {
    /// The content type on the wire.
    pub typ: ContentType,
    /// The version on the wire.
    pub version: ProtocolVersion,
    /// The body.
    pub payload: BorrowedPayload<'a>,
}

impl<'a> InboundOpaqueMessage<'a> {
    /// Wraps a record body.
    pub fn new(typ: ContentType, version: ProtocolVersion, payload: &'a mut [u8]) -> Self {
        Self {
            typ,
            version,
            payload: BorrowedPayload(payload),
        }
    }

    /// Treats the body as plaintext.
    pub fn into_plain_message(self) -> InboundPlainMessage<'a> {
        InboundPlainMessage {
            typ: self.typ,
            version: self.version,
            payload: self.payload.into_inner(),
        }
    }

    /// Interprets a decrypted TLS 1.3 `TLSInnerPlaintext` (RFC 8446 §5.2):
    /// strips zero padding and extracts the real content type.
    pub fn into_tls13_unpadded_message(mut self) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut self.payload;
        let content_type_pos = payload
            .iter()
            .rposition(|b| *b != 0)
            .ok_or(crate::error::PeerMisbehaved::IllegalTlsInnerPlaintext)?;
        let typ = ContentType::from(payload[content_type_pos]);
        payload.truncate(content_type_pos);
        if matches!(typ, ContentType::Unknown(_)) {
            return Err(InvalidMessage::InvalidContentType.into());
        }
        if payload.is_empty() && typ != ContentType::ApplicationData {
            return Err(crate::error::PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }
        Ok(InboundPlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_3,
            payload: self.payload.into_inner(),
        })
    }
}

/// Parsed record header information.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordHeader {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) len: usize,
}

/// Why a record header was rejected or incomplete.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MessageError {
    TooShortForHeader,
    InvalidEmptyPayload,
    MessageTooLarge,
    InvalidContentType,
    UnknownProtocolVersion,
}

impl RecordHeader {
    /// Parses a record header from the start of `bytes`.
    pub(crate) fn read(bytes: &[u8]) -> Result<Self, MessageError> {
        let mut r = Reader::init(bytes);
        let typ = ContentType::read(&mut r).map_err(|_| MessageError::TooShortForHeader)?;
        let version = ProtocolVersion::read(&mut r).map_err(|_| MessageError::TooShortForHeader)?;
        let len = usize::from(u16::read(&mut r).map_err(|_| MessageError::TooShortForHeader)?);
        // Reject obviously-not-TLS traffic before anything else.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::InvalidContentType);
        }
        // Accept every TLS 1.x legacy record version (RFC 8446 §5.1 says
        // receivers MUST ignore the field) but nothing else.
        match u16::from(version) {
            0x0300..=0x03ff => {}
            _ => return Err(MessageError::UnknownProtocolVersion),
        }
        if len > MAX_WIRE_SIZE {
            return Err(MessageError::MessageTooLarge);
        }
        if len == 0 && typ != ContentType::ApplicationData {
            return Err(MessageError::InvalidEmptyPayload);
        }
        Ok(Self { typ, version, len })
    }
}

/// An incoming record after decryption.
#[derive(Debug)]
pub struct InboundPlainMessage<'a> {
    /// The content type.
    pub typ: ContentType,
    /// The version.
    pub version: ProtocolVersion,
    /// The body.
    pub payload: &'a [u8],
}

/// An outgoing record before encryption.
#[derive(Debug)]
pub struct OutboundPlainMessage<'a> {
    /// The content type.
    pub typ: ContentType,
    /// The version.
    pub version: ProtocolVersion,
    /// The body.
    pub payload: OutboundChunks<'a>,
}

impl OutboundPlainMessage<'_> {
    /// Frames the body as an unprotected record.
    pub fn to_unencrypted_opaque(&self) -> OutboundOpaqueMessage {
        let mut payload = PrefixedPayload::with_capacity(self.payload.len());
        payload.extend_from_chunks(&self.payload);
        OutboundOpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload,
        }
    }

    /// The record length on the wire if sent unencrypted.
    pub fn encoded_len(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }
}

/// An owned plaintext record.
#[derive(Clone, Debug)]
pub struct PlainMessage {
    /// The content type.
    pub typ: ContentType,
    /// The version.
    pub version: ProtocolVersion,
    /// The body.
    pub(crate) payload: Payload<'static>,
}

impl PlainMessage {
    /// Frames the body as an unprotected record.
    pub fn into_unencrypted_opaque(self) -> OutboundOpaqueMessage {
        OutboundOpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: PrefixedPayload::from(self.payload.bytes()),
        }
    }

    /// Borrows as an outgoing plaintext record.
    pub fn borrow_outbound(&self) -> OutboundPlainMessage<'_> {
        OutboundPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.bytes().into(),
        }
    }

    /// Borrows as an incoming plaintext record.
    pub fn borrow_inbound(&self) -> InboundPlainMessage<'_> {
        InboundPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.bytes(),
        }
    }

    /// The body.
    pub fn payload(&self) -> &[u8] {
        self.payload.bytes()
    }
}

/// The parsed body of a plaintext record.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // handshake messages dominate; values are short-lived
pub(crate) enum MessagePayload<'a> {
    /// An alert.
    Alert(AlertMessagePayload),
    /// A complete handshake message and its wire encoding.
    Handshake {
        /// The parsed message.
        parsed: HandshakeMessagePayload<'a>,
        /// Its encoding, for the transcript.
        encoded: Payload<'a>,
    },
    /// A ChangeCipherSpec.
    ChangeCipherSpec(ChangeCipherSpecPayload),
    /// Application data.
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    /// Appends the encoding to `bytes`.
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend(encoded.bytes()),
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    /// Wraps a handshake message, computing its encoding.
    pub(crate) fn handshake(parsed: HandshakeMessagePayload<'a>) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()),
            parsed,
        }
    }

    /// Parses `payload` of content type `typ` as a complete message.
    ///
    /// Handshake payloads must contain exactly one message; the deframer
    /// reassembles fragments before calling this.
    pub(crate) fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: &'a [u8],
    ) -> Result<Self, InvalidMessage> {
        let mut r = Reader::init(payload);
        match typ {
            ContentType::ApplicationData => Ok(Self::ApplicationData(Payload::Borrowed(payload))),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                let parsed = HandshakeMessagePayload::read_version(&mut r, vers)?;
                r.expect_empty("Handshake")?;
                Ok(Self::Handshake {
                    parsed,
                    encoded: Payload::Borrowed(payload),
                })
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            _ => Err(InvalidMessage::InvalidContentType),
        }
    }

    /// The content type of this payload.
    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake { .. } => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub(crate) fn into_owned(self) -> MessagePayload<'static> {
        match self {
            Self::Alert(x) => MessagePayload::Alert(x),
            Self::Handshake { parsed, encoded } => MessagePayload::Handshake {
                parsed: parsed.into_owned(),
                encoded: encoded.into_owned(),
            },
            Self::ChangeCipherSpec(x) => MessagePayload::ChangeCipherSpec(x),
            Self::ApplicationData(x) => MessagePayload::ApplicationData(x.into_owned()),
        }
    }
}

/// A plaintext message with its parsed payload.
#[derive(Debug)]
pub(crate) struct Message<'a> {
    /// The version.
    pub(crate) version: ProtocolVersion,
    /// The payload.
    pub(crate) payload: MessagePayload<'a>,
}

impl Message<'_> {
    /// Builds an alert.
    pub(crate) fn build_alert(level: AlertLevel, desc: AlertDescription) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    /// Builds a TLS 1.3 KeyUpdate.
    pub(crate) fn build_key_update(request: KeyUpdateRequest) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::KeyUpdate(request),
            )),
        }
    }

    pub(crate) fn into_owned(self) -> Message<'static> {
        Message {
            version: self.version,
            payload: self.payload.into_owned(),
        }
    }
}

impl<'a> TryFrom<InboundPlainMessage<'a>> for Message<'a> {
    type Error = InvalidMessage;

    fn try_from(plain: InboundPlainMessage<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

impl From<Message<'_>> for PlainMessage {
    fn from(msg: Message<'_>) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload.into_owned(),
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload::Owned(buf)
            }
        };
        Self {
            typ,
            version: msg.version,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks() {
        let data: [&[u8]; 3] = [&[1, 2], &[3], &[4, 5, 6]];
        let chunks = OutboundChunks::new(&data);
        assert_eq!(chunks.len(), 6);
        assert_eq!(chunks.to_vec(), [1, 2, 3, 4, 5, 6]);
        let (a, b) = chunks.split_at(3);
        assert_eq!(a.to_vec(), [1, 2, 3]);
        assert_eq!(b.to_vec(), [4, 5, 6]);
        let (c, d) = b.split_at(1);
        assert_eq!(c.to_vec(), [4]);
        assert_eq!(d.to_vec(), [5, 6]);
        assert!(OutboundChunks::new(&[]).is_empty());
        let (e, f) = OutboundChunks::Single(&[1, 2]).split_at(5);
        assert_eq!(e.len(), 2);
        assert!(f.is_empty());
    }

    #[test]
    fn record_encoding() {
        let plain = PlainMessage {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(alloc::vec![1, 0]),
        };
        let bytes = plain.into_unencrypted_opaque().encode();
        assert_eq!(bytes, [0x15, 3, 3, 0, 2, 1, 0]);
        let hdr = RecordHeader::read(&bytes).unwrap();
        assert_eq!(hdr.typ, ContentType::Alert);
        assert_eq!(hdr.len, 2);
    }

    #[test]
    fn header_validation() {
        assert_eq!(
            RecordHeader::read(&[0x16, 3]).unwrap_err(),
            MessageError::TooShortForHeader
        );
        assert_eq!(
            RecordHeader::read(&[0x99, 3, 3, 0, 1]).unwrap_err(),
            MessageError::InvalidContentType
        );
        assert_eq!(
            RecordHeader::read(&[0x16, 2, 0, 0, 1]).unwrap_err(),
            MessageError::UnknownProtocolVersion
        );
        assert_eq!(
            RecordHeader::read(&[0x16, 3, 3, 0x48, 1]).unwrap_err(),
            MessageError::MessageTooLarge
        );
        assert_eq!(
            RecordHeader::read(&[0x16, 3, 3, 0, 0]).unwrap_err(),
            MessageError::InvalidEmptyPayload
        );
        assert!(RecordHeader::read(&[0x17, 3, 3, 0, 0]).is_ok());
        assert!(RecordHeader::read(&[0x16, 3, 1, 0, 1]).is_ok());
    }

    #[test]
    fn tls13_unpadding() {
        let mut body = [1u8, 2, 3, 0x16, 0, 0];
        let m = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut body,
        );
        let plain = m.into_tls13_unpadded_message().unwrap();
        assert_eq!(plain.typ, ContentType::Handshake);
        assert_eq!(plain.payload, [1, 2, 3]);

        let mut all_zero = [0u8; 4];
        let m = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut all_zero,
        );
        assert!(m.into_tls13_unpadded_message().is_err());

        let mut empty_handshake = [0x16u8];
        let m = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut empty_handshake,
        );
        assert!(m.into_tls13_unpadded_message().is_err());

        let mut empty_app = [0x17u8, 0, 0];
        let m = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut empty_app,
        );
        let plain = m.into_tls13_unpadded_message().unwrap();
        assert!(plain.payload.is_empty());

        let mut unknown = [1u8, 0x99];
        let m = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut unknown,
        );
        assert_eq!(
            m.into_tls13_unpadded_message().unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidContentType)
        );
    }

    #[test]
    fn message_payload_parsing() {
        let alert =
            MessagePayload::new(ContentType::Alert, ProtocolVersion::TLSv1_2, &[2, 40]).unwrap();
        assert_eq!(alert.content_type(), ContentType::Alert);
        assert!(MessagePayload::new(ContentType::Alert, ProtocolVersion::TLSv1_2, &[2]).is_err());
        assert!(
            MessagePayload::new(ContentType::Heartbeat, ProtocolVersion::TLSv1_2, &[1]).is_err()
        );
        // two handshake messages in one payload are not a single message
        let hs = [0x0e, 0, 0, 0, 0x0e, 0, 0, 0];
        assert_eq!(
            MessagePayload::new(ContentType::Handshake, ProtocolVersion::TLSv1_2, &hs).unwrap_err(),
            InvalidMessage::TrailingData("Handshake")
        );
        let m = Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify);
        let plain = PlainMessage::from(m);
        assert_eq!(plain.payload(), [1, 0]);
        let ku = Message::build_key_update(KeyUpdateRequest::UpdateRequested);
        assert!(matches!(
            &ku.payload,
            MessagePayload::Handshake { parsed, .. } if parsed.typ() == crate::enums::HandshakeType::KeyUpdate
        ));
    }
}
