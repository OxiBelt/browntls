//! Turning bytes from the transport into records and complete handshake messages.
//!
//! [`DeframerVecBuffer`] holds raw bytes from the peer. [`MessageDeframer::pop`]
//! parses one record header at a time, decrypts the record in place with the
//! [`RecordLayer`], and either hands back a non-handshake record (as a range
//! into the buffer, discarded by the caller once processed) or appends
//! handshake fragments to an internal joiner until a whole handshake message
//! is available.

use alloc::vec::Vec;
use core::ops::Range;

use super::message::{
    HEADER_SIZE, InboundOpaqueMessage, MAX_WIRE_SIZE, MessageError, RecordHeader,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::codec::{Codec, Reader, u24};
use crate::msgs::handshake::MAX_HANDSHAKE_SIZE;
use crate::record_layer::RecordLayer;

/// The most raw bytes we will hold before the application must process them:
/// one maximum-size record plus its header.
const MAX_BUFFER: usize = MAX_WIRE_SIZE + HEADER_SIZE;

/// Raw bytes received from the peer and not yet consumed.
#[derive(Default, Debug)]
pub(crate) struct DeframerVecBuffer {
    buf: Vec<u8>,
    used: usize,
}

impl DeframerVecBuffer {
    /// The bytes available for parsing.
    pub(crate) fn filled(&self) -> &[u8] {
        &self.buf[..self.used]
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }

    /// Whether any unconsumed bytes remain.
    pub(crate) fn has_pending(&self) -> bool {
        self.used > 0
    }

    /// Drops the first `taken` bytes.
    pub(crate) fn discard(&mut self, taken: usize) {
        let taken = taken.min(self.used);
        if taken == 0 {
            return;
        }
        self.buf.copy_within(taken..self.used, 0);
        self.used -= taken;
    }

    /// Appends `bytes`, failing if the buffer limit would be exceeded.
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.used + bytes.len() > MAX_BUFFER {
            return Err(Error::general("received TLS data exceeds the buffer limit"));
        }
        if self.buf.len() < self.used + bytes.len() {
            self.buf.resize(self.used + bytes.len(), 0);
        }
        self.buf[self.used..self.used + bytes.len()].copy_from_slice(bytes);
        self.used += bytes.len();
        Ok(())
    }

    /// Reads from `rd` into the buffer; returns the number of bytes read.
    #[cfg(feature = "std")]
    pub(crate) fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        if self.used >= MAX_BUFFER {
            return Err(std::io::Error::other(
                "received TLS data exceeds the buffer limit; call process_new_packets()",
            ));
        }
        if self.buf.len() < MAX_BUFFER {
            self.buf.resize(MAX_BUFFER, 0);
        }
        let n = rd.read(&mut self.buf[self.used..])?;
        self.used += n;
        Ok(n)
    }

    /// Takes every unconsumed byte, leaving the buffer empty.
    pub(crate) fn take_all(&mut self) -> Vec<u8> {
        let out = self.filled().to_vec();
        self.used = 0;
        out
    }
}

/// Accumulates handshake fragments into whole messages.
#[derive(Default, Debug)]
pub(crate) struct HandshakeJoiner {
    buf: Vec<u8>,
}

impl HandshakeJoiner {
    /// The joiner may hold one maximum-size message plus one further record
    /// of fragments that arrived in the same record as its end.
    const MAX_BUFFERED: usize = MAX_HANDSHAKE_SIZE as usize + 4 + super::message::MAX_PLAINTEXT_LEN;

    fn push(&mut self, fragment: &[u8]) -> Result<(), Error> {
        if self.buf.len() + fragment.len() > Self::MAX_BUFFERED {
            return Err(InvalidMessage::HandshakePayloadTooLarge.into());
        }
        self.buf.extend_from_slice(fragment);
        self.check_declared_length()
    }

    /// Rejects a buffered header that declares an over-long message as soon as
    /// the header is complete, before more fragments are accumulated.
    fn check_declared_length(&self) -> Result<(), Error> {
        if self.buf.len() >= 4 {
            let declared = u24::read(&mut Reader::init(&self.buf[1..4]))
                .map(|l| l.0)
                .unwrap_or(0);
            if declared > MAX_HANDSHAKE_SIZE {
                return Err(InvalidMessage::HandshakePayloadTooLarge.into());
            }
        }
        Ok(())
    }

    /// The length of the first complete message, if one is buffered.
    fn complete_message_len(&self) -> Option<usize> {
        if self.buf.len() < 4 {
            return None;
        }
        let declared = u24::read(&mut Reader::init(&self.buf[1..4])).ok()?;
        let total = 4 + usize::from(declared);
        (self.buf.len() >= total).then_some(total)
    }

    /// Whether a partial message is buffered.
    pub(crate) fn has_partial(&self) -> bool {
        !self.buf.is_empty() && self.complete_message_len().is_none()
    }

    /// Whether anything at all is buffered.
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The buffered bytes.
    pub(crate) fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Drops the first `len` bytes (one processed message).
    pub(crate) fn consume(&mut self, len: usize) {
        self.buf.drain(..len.min(self.buf.len()));
    }
}

/// One unit of output from the deframer.
#[derive(Debug)]
pub(crate) enum Deframed {
    /// A complete handshake message occupies the first `len` bytes of the
    /// joiner; `version` is the record version it arrived under.
    Handshake {
        len: usize,
        version: ProtocolVersion,
    },
    /// A non-handshake record, decrypted in place within the buffer.
    Record {
        typ: ContentType,
        version: ProtocolVersion,
        plaintext: Range<usize>,
        /// Raw bytes to discard from the buffer once the record is processed.
        consumed: usize,
        want_close_before_decrypt: bool,
    },
}

/// Splits the byte stream into records and reassembles handshake messages.
#[derive(Default, Debug)]
pub(crate) struct MessageDeframer {
    last_error: Option<Error>,
    pub(crate) joiner: HandshakeJoiner,
}

impl MessageDeframer {
    /// Produces the next message, or `None` if more bytes are needed.
    ///
    /// Once an error is returned every later call returns the same error.
    pub(crate) fn pop(
        &mut self,
        record_layer: &mut RecordLayer,
        negotiated_version: Option<ProtocolVersion>,
        buffer: &mut DeframerVecBuffer,
    ) -> Result<Option<Deframed>, Error> {
        if let Some(err) = &self.last_error {
            return Err(err.clone());
        }
        self.pop_inner(record_layer, negotiated_version, buffer)
            .map_err(|err| {
                self.last_error = Some(err.clone());
                err
            })
    }

    fn pop_inner(
        &mut self,
        record_layer: &mut RecordLayer,
        negotiated_version: Option<ProtocolVersion>,
        buffer: &mut DeframerVecBuffer,
    ) -> Result<Option<Deframed>, Error> {
        loop {
            if let Some(len) = self.joiner.complete_message_len() {
                return Ok(Some(Deframed::Handshake {
                    len,
                    version: negotiated_version.unwrap_or(ProtocolVersion::TLSv1_2),
                }));
            }

            let header = match RecordHeader::read(buffer.filled()) {
                Ok(h) => h,
                Err(MessageError::TooShortForHeader | MessageError::TooShortForLength) => {
                    return Ok(None);
                }
                Err(MessageError::MessageTooLarge) => return Err(Error::PeerSentOversizedRecord),
                Err(MessageError::InvalidContentType) => {
                    return Err(InvalidMessage::InvalidContentType.into());
                }
                Err(MessageError::UnknownProtocolVersion) => {
                    return Err(InvalidMessage::UnknownProtocolVersion.into());
                }
                Err(MessageError::InvalidEmptyPayload) => {
                    return Err(InvalidMessage::InvalidEmptyPayload.into());
                }
            };
            let record_len = HEADER_SIZE + header.len;
            if buffer.filled().len() < record_len {
                return Ok(None);
            }

            let base = buffer.filled().as_ptr() as usize;
            let body = &mut buffer.filled_mut()[HEADER_SIZE..record_len];
            let msg = InboundOpaqueMessage::new(header.typ, header.version, body);

            // RFC 8446 §5: a TLS 1.3 peer may send an unprotected
            // ChangeCipherSpec for middlebox compatibility while we already
            // decrypt. It is not a ciphertext, so bypass the record cipher.
            let passthrough_ccs = header.typ == ContentType::ChangeCipherSpec
                && negotiated_version == Some(ProtocolVersion::TLSv1_3)
                && record_layer.is_decrypting();

            let decrypted = if passthrough_ccs {
                crate::record_layer::Decrypted {
                    want_close_before_decrypt: false,
                    plaintext: msg.into_plain_message(),
                }
            } else {
                match record_layer.decrypt_incoming(msg)? {
                    Some(d) => d,
                    None => {
                        // Dropped during trial decryption of rejected early data.
                        buffer.discard(record_len);
                        continue;
                    }
                }
            };

            let crate::record_layer::Decrypted {
                want_close_before_decrypt,
                plaintext,
            } = decrypted;
            let typ = plaintext.typ;
            let version = plaintext.version;
            let payload = plaintext.payload;
            let start = (payload.as_ptr() as usize).wrapping_sub(base);
            let range = start..start + payload.len();

            if typ == ContentType::Handshake {
                if payload.is_empty() {
                    // RFC 8446 §5.1: zero-length handshake fragments are forbidden.
                    return Err(InvalidMessage::InvalidEmptyPayload.into());
                }
                let fragment = payload.to_vec();
                self.joiner.push(&fragment)?;
                buffer.discard(record_len);
                if want_close_before_decrypt {
                    return Err(Error::general("record sequence number exhausted"));
                }
                continue;
            }

            if !self.joiner.is_empty() {
                // RFC 8446 §5.1: handshake messages must not be interleaved
                // with other record types.
                return Err(PeerMisbehaved::MessageInterleavedWithHandshakeMessage.into());
            }

            return Ok(Some(Deframed::Record {
                typ,
                version,
                plaintext: range,
                consumed: record_len,
                want_close_before_decrypt,
            }));
        }
    }

    /// Whether a partial handshake message is buffered.
    pub(crate) fn is_joining(&self) -> bool {
        self.joiner.has_partial()
    }

    /// Whether any handshake bytes are buffered.
    pub(crate) fn has_buffered_handshake(&self) -> bool {
        !self.joiner.is_empty()
    }
}

/// Feeds arbitrary bytes through the plaintext deframer; used by fuzz targets.
pub fn fuzz_deframer(data: &[u8]) {
    let mut buffer = DeframerVecBuffer::default();
    let mut rl = RecordLayer::new();
    let mut d = MessageDeframer::default();
    for chunk in data.chunks(MAX_BUFFER.max(1)) {
        if buffer.extend_from_slice(chunk).is_err() {
            return;
        }
        loop {
            match d.pop(&mut rl, None, &mut buffer) {
                Ok(Some(Deframed::Handshake { len, version })) => {
                    let bytes = &d.joiner.buffered()[..len];
                    let _ = crate::msgs::handshake::HandshakeMessagePayload::read_version(
                        &mut Reader::init(bytes),
                        version,
                    );
                    d.joiner.consume(len);
                }
                Ok(Some(Deframed::Record {
                    typ,
                    version,
                    plaintext,
                    consumed,
                    ..
                })) => {
                    let payload = &buffer.filled()[plaintext];
                    let _ = super::message::MessagePayload::new(typ, version, payload);
                    buffer.discard(consumed);
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::HandshakeType;
    use crate::msgs::handshake::HandshakeMessagePayload;

    fn pop_all(data: &[u8], chunk: usize) -> Result<Vec<Deframed>, Error> {
        let mut buffer = DeframerVecBuffer::default();
        let mut rl = RecordLayer::new();
        let mut d = MessageDeframer::default();
        let mut out = Vec::new();
        for piece in data.chunks(chunk) {
            buffer.extend_from_slice(piece).unwrap();
            loop {
                match d.pop(&mut rl, None, &mut buffer)? {
                    Some(Deframed::Handshake { len, version }) => {
                        let bytes = &d.joiner.buffered()[..len];
                        assert!(
                            HandshakeMessagePayload::read_version(
                                &mut Reader::init(bytes),
                                version
                            )
                            .is_ok()
                        );
                        out.push(Deframed::Handshake { len, version });
                        d.joiner.consume(len);
                    }
                    Some(r @ Deframed::Record { consumed, .. }) => {
                        buffer.discard(consumed);
                        out.push(r);
                    }
                    None => break,
                }
            }
        }
        Ok(out)
    }

    fn hs_record(payload: &[u8]) -> Vec<u8> {
        let mut v = alloc::vec![0x16, 3, 3];
        v.extend((payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn joins_fragmented_handshake_messages() {
        // ServerHelloDone (type 14, length 0) split over two records
        let mut data = hs_record(&[0x0e, 0]);
        data.extend(hs_record(&[0, 0]));
        for chunk in [1usize, 3, 100] {
            let out = pop_all(&data, chunk).unwrap();
            assert_eq!(out.len(), 1);
            assert!(matches!(out[0], Deframed::Handshake { len: 4, .. }));
        }
    }

    #[test]
    fn splits_coalesced_handshake_messages() {
        let data = hs_record(&[0x0e, 0, 0, 0, 0x0e, 0, 0, 0]);
        let out = pop_all(&data, 100).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn rejects_interleaving() {
        let mut data = hs_record(&[0x0e, 0]);
        data.extend([0x15, 3, 3, 0, 2, 1, 0]);
        assert_eq!(
            pop_all(&data, 100).unwrap_err(),
            Error::PeerMisbehaved(PeerMisbehaved::MessageInterleavedWithHandshakeMessage)
        );
    }

    #[test]
    fn rejects_oversized_handshake_early() {
        let data = hs_record(&[0x0b, 0x01, 0, 0, 1, 2, 3]);
        assert_eq!(
            pop_all(&data, 100).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge)
        );
    }

    #[test]
    fn rejects_bad_headers() {
        assert_eq!(
            pop_all(&[0x99, 3, 3, 0, 1, 0], 100).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidContentType)
        );
        assert_eq!(
            pop_all(&[0x16, 3, 3, 0x48, 1], 100).unwrap_err(),
            Error::PeerSentOversizedRecord
        );
        assert_eq!(
            pop_all(&[0x16, 3, 3, 0, 0], 100).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        );
        assert_eq!(
            pop_all(&[0x16, 1, 3, 0, 1, 0], 100).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion)
        );
    }

    #[test]
    fn errors_are_sticky() {
        let mut buffer = DeframerVecBuffer::default();
        let mut rl = RecordLayer::new();
        let mut d = MessageDeframer::default();
        buffer.extend_from_slice(&[0x99, 3, 3, 0, 1, 0]).unwrap();
        assert!(d.pop(&mut rl, None, &mut buffer).is_err());
        buffer.discard(6);
        buffer.extend_from_slice(&[0x15, 3, 3, 0, 2, 1, 0]).unwrap();
        assert!(d.pop(&mut rl, None, &mut buffer).is_err());
    }

    #[test]
    fn application_data_record_range() {
        let data = [0x17, 3, 3, 0, 3, 7, 8, 9];
        let out = pop_all(&data, 100).unwrap();
        match &out[0] {
            Deframed::Record {
                typ,
                plaintext,
                consumed,
                ..
            } => {
                assert_eq!(*typ, ContentType::ApplicationData);
                assert_eq!(*plaintext, 5..8);
                assert_eq!(*consumed, 8);
            }
            other => panic!("{other:?}"),
        }
        let _ = HandshakeType::Finished;
    }

    #[test]
    fn buffer_limit() {
        let mut buffer = DeframerVecBuffer::default();
        assert!(
            buffer
                .extend_from_slice(&alloc::vec![0u8; MAX_BUFFER])
                .is_ok()
        );
        assert!(buffer.extend_from_slice(&[0]).is_err());
        buffer.discard(MAX_BUFFER);
        assert!(!buffer.has_pending());
        assert!(buffer.extend_from_slice(&[1, 2]).is_ok());
        assert_eq!(buffer.take_all(), [1, 2]);
    }

    #[test]
    fn fuzz_entry_does_not_panic() {
        fuzz_deframer(&[]);
        fuzz_deframer(&[0x16, 3, 3, 0, 4, 0x0e, 0, 0, 0, 0x17, 3, 3, 0, 1, 0]);
        fuzz_deframer(&[0xff; 100]);
    }
}
