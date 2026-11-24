//! DTLS 1.3 record protection (RFC 9147 §4): the keys of one epoch and
//! direction, sealing and opening `DTLSCiphertext` records, and record
//! number encryption (§4.2.3).
//!
//! The AEAD is used as QUIC uses it (RFC 9001 §5.3): the nonce is the IV
//! XORed with the 64-bit record sequence number, and the record header is
//! the associated data. The record number mask is the QUIC header
//! protection mask (RFC 9001 §5.4.3, §5.4.4) over the first sixteen bytes
//! of the ciphertext. So the [`quic::Algorithm`] of a cipher suite provides
//! both, keyed with the DTLS labels `key`, `iv` and `sn` under the `dtls13`
//! label prefix (RFC 9147 §5.9).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use super::LABEL_PREFIX;
use super::wire::{self, RecordNumber};
use crate::crypto::cipher::{AeadKey, Iv, NONCE_LEN};
use crate::crypto::tls13::OkmBlock;
use crate::enums::ContentType;
use crate::error::Error;
use crate::msgs::message::MAX_PLAINTEXT_LEN;
use crate::quic::{self, HeaderProtectionKey, PacketKey};
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::hkdf_expand_label_with_prefix;

/// RFC 9147 §4.2.3: the mask needs sixteen bytes of ciphertext, so shorter
/// records are padded by senders and rejected by receivers.
const MIN_CIPHERTEXT_LEN: usize = quic::SAMPLE_LEN;

/// RFC 9147 §4.5.3: the most records that may fail authentication under
/// one key for AES-GCM and ChaCha20-Poly1305. The provider's own figure
/// applies when it is lower (as for AES-CCM).
const MAX_INTEGRITY_LIMIT: u64 = 1 << 36;

/// The record protection keys of one epoch, for one direction.
pub(crate) struct RecordKeys {
    packet: Box<dyn PacketKey>,
    sn: Box<dyn HeaderProtectionKey>,
    confidentiality_limit: u64,
}

/// A record that [`RecordKeys::open`] deprotected.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Opened {
    /// The reconstructed record sequence number.
    pub(crate) seq: u64,
    pub(crate) typ: ContentType,
    /// The content within the record buffer passed to `open`.
    pub(crate) content: Range<usize>,
    /// Authenticated DTLSInnerPlaintext length, including the content type
    /// and any trailing zero padding.
    pub(crate) plaintext_len: usize,
}

impl RecordKeys {
    /// The keys `secret` (a traffic secret of `suite`) gives: `None` when
    /// the suite has no algorithm usable for DTLS record protection
    /// (TLS_AES_128_CCM_8_SHA256, RFC 9147 §4.5.3).
    pub(crate) fn derive(suite: &'static Tls13CipherSuite, secret: &OkmBlock) -> Option<Self> {
        let alg = suite.quic?;
        let expander = suite.hkdf_provider.expander_for_okm(secret);
        let key_len = alg.aead_key_len().min(AeadKey::MAX_LEN);
        let expand_key = |label: &[u8]| {
            let mut key = [0u8; AeadKey::MAX_LEN];
            hkdf_expand_label_with_prefix(
                &*expander,
                LABEL_PREFIX,
                label,
                &[],
                &mut key[..key_len],
            );
            let aead_key = AeadKey::new(&key[..key_len]);
            crate::crypto::zeroize_slice(&mut key);
            aead_key
        };
        let mut iv = [0u8; NONCE_LEN];
        hkdf_expand_label_with_prefix(&*expander, LABEL_PREFIX, b"iv", &[], &mut iv);
        let packet = alg.packet_key(expand_key(b"key"), Iv::new(iv));
        crate::crypto::zeroize_slice(&mut iv);
        Some(Self {
            packet,
            sn: alg.header_protection_key(expand_key(b"sn")),
            confidentiality_limit: suite.common.confidentiality_limit,
        })
    }

    /// How many records these keys may protect (RFC 9147 §4.5.3).
    pub(crate) fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    /// How many records may fail authentication under these keys before
    /// they must no longer be used (RFC 9147 §4.5.3).
    pub(crate) fn integrity_limit(&self) -> u64 {
        self.packet.integrity_limit().min(MAX_INTEGRITY_LIMIT)
    }

    /// The length of the record [`Self::seal`] makes of `content_len`
    /// bytes of content.
    pub(crate) fn sealed_len(&self, content_len: usize, cid_len: usize) -> usize {
        wire::unified_header_len(cid_len) + self.body_len(content_len)
    }

    /// The content one record can carry within `space` bytes, if any.
    pub(crate) fn content_room(&self, space: usize, cid_len: usize) -> Option<usize> {
        // Padding only ever applies to content shorter than the sample, so
        // the overhead of anything longer is the header, the type byte and
        // the tag.
        let overhead = wire::unified_header_len(cid_len) + 1 + self.packet.tag_len();
        let room = space.checked_sub(overhead)?;
        (self.sealed_len(room, cid_len) <= space).then_some(room)
    }

    fn body_len(&self, content_len: usize) -> usize {
        let tag_len = self.packet.tag_len();
        // content, content type, zero padding up to the sample, tag.
        (content_len + 1 + tag_len).max(MIN_CIPHERTEXT_LEN)
    }

    pub(super) fn max_ciphertext_len(&self) -> usize {
        self.body_len(MAX_PLAINTEXT_LEN)
    }

    /// Appends the `DTLSCiphertext` of `content` to `out`, with a 16-bit
    /// sequence number and a length in its header, and `cid` when not
    /// empty. On failure `out` is as it was.
    pub(crate) fn seal(
        &self,
        out: &mut Vec<u8>,
        number: RecordNumber,
        typ: ContentType,
        content: &[u8],
        cid: &[u8],
    ) -> Result<(), Error> {
        if content.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::EncryptError);
        }
        let tag_len = self.packet.tag_len();
        let body_len = self.body_len(content.len());
        let Ok(wire_len) = u16::try_from(body_len) else {
            return Err(Error::EncryptError);
        };
        if tag_len > quic::SAMPLE_LEN || number.seq > wire::MAX_SEQ {
            return Err(Error::EncryptError);
        }
        let start = out.len();
        let seq_at = wire::put_unified_header(out, number.epoch, number.seq, cid, wire_len);
        let body_at = out.len();
        out.extend_from_slice(content);
        out.push(u8::from(typ));
        out.resize(body_at + body_len - tag_len, 0);
        let (header, inner) = out[start..].split_at_mut(body_at - start);
        let tag = match self.packet.encrypt_in_place(number.seq, header, inner) {
            Ok(tag) => tag,
            Err(err) => {
                crate::crypto::zeroize_slice(&mut out[start..]);
                out.truncate(start);
                return Err(err);
            }
        };
        out.extend_from_slice(&tag.as_ref()[..tag_len]);
        match self.sn.mask(&out[body_at..body_at + MIN_CIPHERTEXT_LEN]) {
            Ok(mask) => {
                for (byte, mask) in out[seq_at].iter_mut().zip(mask) {
                    *byte ^= mask;
                }
                Ok(())
            }
            Err(err) => {
                out.truncate(start);
                Err(err)
            }
        }
    }

    /// Deprotects in place the `DTLSCiphertext` that fills `record`, whose
    /// header ends at `body.start` and whose (still encrypted) sequence
    /// number bytes are at `seq`, as [`wire::parse_record`] reports them.
    /// `expected` is the sequence number most likely to come next in the
    /// epoch (RFC 9147 §4.2.2).
    ///
    /// `None` when the record is not authentic under these keys or is
    /// malformed inside; the caller counts that against
    /// [`Self::integrity_limit`] and drops the record. `record` is then
    /// garbage.
    pub(crate) fn open(
        &self,
        record: &mut [u8],
        seq: Range<usize>,
        body: Range<usize>,
        expected: u64,
    ) -> Option<Opened> {
        if body.end != record.len()
            || body.len() > self.max_ciphertext_len()
            || seq.end > body.start
            || !(1..=2).contains(&seq.len())
        {
            return None;
        }
        let sample = record.get(body.start..body.start + MIN_CIPHERTEXT_LEN)?;
        let mask = self.sn.mask(sample).ok()?;
        let mut low = 0u64;
        for (byte, mask) in record[seq.clone()].iter_mut().zip(mask) {
            *byte ^= mask;
            low = (low << 8) | u64::from(*byte);
        }
        let number = reconstruct_seq(expected, low, 8 * seq.len() as u32);
        let (header, protected) = record.split_at_mut(body.start);
        let inner = self
            .packet
            .decrypt_in_place(number, header, protected)
            .ok()?;
        // DTLSInnerPlaintext: content, type, zero padding.
        let type_at = inner.iter().rposition(|byte| *byte != 0)?;
        let typ = ContentType::from(inner[type_at]);
        Some(Opened {
            seq: number,
            typ,
            content: body.start..body.start + type_at,
            plaintext_len: inner.len(),
        })
    }
}

impl fmt::Debug for RecordKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordKeys(..)")
    }
}

/// RFC 9147 §4.2.2: the full sequence number with the low `bits` bits
/// `low` that is numerically closest to `expected`.
pub(crate) fn reconstruct_seq(expected: u64, low: u64, bits: u32) -> u64 {
    let window = 1u64 << bits;
    let candidate = (expected & !(window - 1)) | (low & (window - 1));
    if candidate.saturating_add(window / 2) <= expected
        && let Some(above) = candidate.checked_add(window)
    {
        // Too far below: the sender has wrapped the low bits.
        above
    } else if candidate > expected.saturating_add(window / 2) && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

#[cfg(test)]
mod tests;
