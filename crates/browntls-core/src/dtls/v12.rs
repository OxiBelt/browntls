//! DTLS 1.2 record adaptation. Cipher operations reuse the selected
//! provider; their explicit sequence input includes the epoch (RFC 6347
//! section 4.1.2 and RFC 7905 section 2).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::Range;

use super::cid::AuthenticatedRecord;
use super::replay::ReplayWindow;
use super::state::{Dtls, Incoming, WriteEpoch};
use super::wire::{self, RecordNumber};
use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter};
use crate::enums::{AlertDescription, ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage};
use crate::hash_hs::HandshakeHash;
use crate::msgs::enums::AlertLevel;
use crate::msgs::message::{
    InboundOpaqueMessage, MAX_PLAINTEXT_LEN, Message, MessagePayload, OutboundChunks,
    OutboundPlainMessage,
};

pub(super) struct State {
    pub(super) enc: Option<Box<dyn MessageEncrypter>>,
    dec: Option<Box<dyn MessageDecrypter>>,
    pub(super) read_active: bool,
    pub(super) ccs_pending: bool,
    pub(super) resuming: bool,
    limit: u64,
    failures: u64,
    window: ReplayWindow,
}

impl Default for State {
    fn default() -> Self {
        Self {
            enc: None,
            dec: None,
            read_active: false,
            ccs_pending: false,
            resuming: false,
            limit: 0,
            failures: 0,
            window: ReplayWindow::new(),
        }
    }
}

/// The unfragmented twelve-byte handshake header and body used by
/// Finished, EMS and CertificateVerify, independent of wire fragmentation.
pub(crate) fn canonical(encoded: &[u8], seq: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded.len() + 8);
    if encoded.len() < 4 {
        return out;
    }
    out.extend_from_slice(&encoded[..4]);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&[0; 3]);
    out.extend_from_slice(&encoded[1..4]);
    out.extend_from_slice(&encoded[4..]);
    out
}

impl crate::common_state::CommonState {
    /// Hash an outgoing TLS 1.2 message with the sequence it will be queued
    /// under. Queueing immediately follows this at each call site.
    pub(crate) fn hash_tls12(&self, transcript: &mut HandshakeHash, m: &Message<'_>) {
        match (&self.dtls, &m.payload) {
            (Some(dtls), MessagePayload::Handshake { encoded, .. }) => {
                transcript.add(&canonical(encoded.bytes(), dtls.out.next_send_seq()));
            }
            (None, _) => {
                transcript.add_message(m);
            }
            _ => {}
        }
    }
}

impl Dtls {
    pub(crate) fn set_v12_resuming(&mut self) {
        self.v12.resuming = true;
    }

    pub(crate) fn prepare_v12(
        &mut self,
        enc: Box<dyn MessageEncrypter>,
        dec: Box<dyn MessageDecrypter>,
        limit: u64,
    ) {
        self.v12.enc = Some(enc);
        self.v12.dec = Some(dec);
        self.v12.limit = limit.min(wire::MAX_SEQ);
    }

    pub(crate) fn activate_v12_write(&mut self) {
        self.write.push(WriteEpoch {
            epoch: 1,
            keys: None,
            next_seq: 0,
        });
    }

    pub(crate) fn activate_v12_read(&mut self) {
        self.v12.ccs_pending = false;
        self.v12.read_active = true;
    }

    pub(crate) fn take_v12_ccs(&mut self) -> bool {
        core::mem::take(&mut self.v12.ccs_pending)
    }

    pub(super) fn seal_v12(
        &mut self,
        out: &mut Vec<u8>,
        typ: ContentType,
        content: &[u8],
    ) -> Result<RecordNumber, Error> {
        let seq = self.write.last().ok_or(Error::EncryptError)?.next_seq;
        let cid = self.cid.outbound();
        if seq >= self.v12.limit || content.len() > MAX_PLAINTEXT_LEN - usize::from(!cid.is_empty())
        {
            return Err(Error::EncryptError);
        }
        // Consume the number even if the provider fails.
        self.write.last_mut().ok_or(Error::EncryptError)?.next_seq += 1;
        let message = OutboundPlainMessage {
            typ,
            version: ProtocolVersion::DTLSv1_2,
            payload: OutboundChunks::Single(content),
        };
        let enc = self.v12.enc.as_mut().ok_or(Error::EncryptError)?;
        let nonce = (1u64 << 48) | seq;
        let record = if cid.is_empty() {
            enc.encrypt(message, nonce)?
        } else {
            enc.encrypt_dtls12_cid(message, nonce, cid, 0)?
        };
        let body = record.payload.as_ref();
        let len = u16::try_from(body.len()).map_err(|_| Error::EncryptError)?;
        if cid.is_empty() {
            wire::put_plaintext_header(out, typ, ProtocolVersion::DTLSv1_2, 1, seq, len);
        } else {
            wire::put_v12_cid_header(out, seq, cid, len);
        }
        out.extend_from_slice(body);
        Ok(RecordNumber { epoch: 1, seq })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn read_v12(
        &mut self,
        typ: ContentType,
        version: ProtocolVersion,
        epoch: u16,
        seq: u64,
        datagram: &mut [u8],
        header: Range<usize>,
        cid: Option<Range<usize>>,
        body: Range<usize>,
        handshaking: bool,
    ) -> Result<Incoming, Error> {
        if epoch == 0 {
            if body.len() > 16_384 {
                return Ok(Incoming::Handled);
            }
            if typ == ContentType::ChangeCipherSpec
                && datagram[body.clone()] == [1]
                && !self.v12.read_active
                && handshaking
            {
                self.v12.ccs_pending = true;
                return Ok(Incoming::ChangeCipherSpec);
            }
            return self.read_plaintext(
                typ,
                RecordNumber { epoch: 0, seq },
                &datagram[body],
                handshaking,
            );
        }
        if epoch != 1
            || version != ProtocolVersion::DTLSv1_2
            || !self.v12.read_active
            || !self.v12.window.is_new(seq)
        {
            return Ok(Incoming::Handled);
        }
        let Some(dec) = &mut self.v12.dec else {
            return Ok(Incoming::Handled);
        };
        let record_end = body.end;
        let base_ptr = datagram.as_ptr() as usize;
        let (prefix, ciphertext) = datagram.split_at_mut(body.start);
        let id = cid.map(|r| &prefix[header.start + r.start..header.start + r.end]);
        let message = InboundOpaqueMessage::new(typ, version, &mut ciphertext[..body.len()]);
        let nonce = (u64::from(epoch) << 48) | seq;
        let opened = if let Some(id) = id {
            dec.decrypt_dtls12_cid(message, nonce, id)
        } else {
            dec.decrypt(message, nonce)
        };
        let plain = match opened {
            Ok(plain) => plain,
            Err(_) => {
                self.v12.failures = self.v12.failures.saturating_add(1);
                // The same conservative ceiling as the DTLS 1.3 adapter
                // for AES-GCM and ChaCha20-Poly1305 (RFC 9147 section 4.5.3).
                if dec.integrity_limit_reached() || self.v12.failures >= (1 << 36) {
                    return Err(Error::DecryptError);
                }
                return Ok(Incoming::Handled);
            }
        };
        // TLS 1.2 AEAD decryptors remove an explicit nonce from the front.
        let start = (plain.payload.as_ptr() as usize)
            .checked_sub(base_ptr)
            .ok_or(InvalidMessage::MessageTooShort)?;
        let len = plain.payload.len();
        let typ = plain.typ;
        if start < body.start
            || start.checked_add(len).is_none_or(|end| end > record_end)
            || len > 16_384
        {
            return Err(InvalidMessage::MessageTooShort.into());
        }
        self.v12.window.mark(seq);
        self.peer_authenticated = true;
        let number = RecordNumber { epoch: 1, seq };
        self.authenticated_record = Some(AuthenticatedRecord::new(
            header.start..body.end,
            number,
            id.unwrap_or_default().to_vec(),
        ));
        let content = &datagram[start..start + len];
        match typ {
            ContentType::ReturnRoutabilityCheck if self.rrc_negotiated && !handshaking => {
                if let Some(metadata) = &mut self.authenticated_record {
                    metadata.set_rrc_payload(start..start + len);
                }
                Ok(Incoming::Handled)
            }
            ContentType::Handshake => {
                self.read_handshake_fragments(content, number, true)?;
                Ok(Incoming::Handled)
            }
            ContentType::Alert => match content {
                [level, description] => Ok(Incoming::Alert(
                    AlertLevel::from(*level),
                    AlertDescription::from(*description),
                )),
                _ => Err(InvalidMessage::MessageTooShort.into()),
            },
            ContentType::ApplicationData if !handshaking => {
                // Authenticated application data acknowledges the final flight.
                self.out.flight_acknowledged_implicitly();
                Ok(Incoming::ApplicationData(start..start + len))
            }
            _ => Ok(Incoming::Handled),
        }
    }
}

/// Repeat the original ClientHello with a legacy cookie, preserving random,
/// extensions and key shares. The initial hello and HVR are not hashed.
pub(crate) fn retry_client_hello(
    common: &mut crate::common_state::CommonState,
    body: &[u8],
) -> Result<crate::hash_hs::HandshakeHashBuffer, Error> {
    use crate::msgs::base::PayloadU8;
    use crate::msgs::codec::Reader;
    use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
    let dtls = common
        .dtls
        .as_mut()
        .filter(|d| d.allows(ProtocolVersion::TLSv1_2))
        .ok_or_else(|| Error::General("unexpected HelloVerifyRequest".into()))?;
    if body.len() < 4
        || !matches!(&body[..2], [0xfe, 0xff] | [0xfe, 0xfd])
        || usize::from(body[2]) != body.len() - 3
    {
        return Err(InvalidMessage::MessageTooShort.into());
    }
    let parsed = HandshakeMessagePayload::read_dtls(
        &mut Reader::init(&dtls.client_hello),
        ProtocolVersion::TLSv1_2,
    )?;
    let HandshakePayload::ClientHello(mut hello) = parsed.0 else {
        return Err(InvalidMessage::MessageTooShort.into());
    };
    hello.legacy_cookie = Some(PayloadU8::new(body[3..].to_vec()));
    // A DTLS 1.2 retry must not carry TLS 1.3 PSK binders made over CH1.
    hello.extensions.preshared_key = None;
    hello.extensions.psk_modes = None;
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            hello,
        ))),
    };
    let mut buffer = crate::hash_hs::HandshakeHashBuffer::new();
    buffer.set_client_auth_enabled();
    buffer.add_message(&m);
    if let MessagePayload::Handshake { encoded, .. } = &m.payload {
        // The temporary borrow of the original hello ends before queueing.
        let encoded = encoded.bytes().to_vec();
        dtls.queue_handshake(&encoded);
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_header_is_unfragmented_and_preserves_message_sequence() {
        let encoded = [20, 0, 0, 3, 4, 5, 6];
        assert_eq!(
            canonical(&encoded, 0x1234),
            [20, 0, 0, 3, 0x12, 0x34, 0, 0, 0, 0, 0, 3, 4, 5, 6]
        );
        assert_eq!(
            canonical(&[14, 0, 0, 0], 2),
            [14, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0]
        );
    }
}
