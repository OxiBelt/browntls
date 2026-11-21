//! DTLS wire formats: record headers (RFC 9147 §4, RFC 6347 §4.1), the
//! handshake message header (RFC 9147 §5.2) and the ACK message (§7).
//!
//! Everything here is parsing and encoding of bytes an attacker controls or
//! observes; nothing is decrypted. A record that does not parse is reported
//! as `None`, and the caller drops the rest of its datagram (RFC 9147
//! §4.5.2).

use alloc::vec::Vec;
use core::ops::Range;

use crate::enums::{ContentType, ProtocolVersion};

/// The length of a `DTLSPlaintext` header, which is also the DTLS 1.2
/// record header: type, version, epoch, 48-bit sequence number, length.
pub(crate) const PLAINTEXT_HEADER_LEN: usize = 13;

/// The length of the header of a `DTLSHandshake` message or fragment.
pub(crate) const HANDSHAKE_HEADER_LEN: usize = 12;

/// The header of an unprotected TLS handshake message: type and length.
pub(crate) const TLS_HANDSHAKE_HEADER_LEN: usize = 4;

/// The largest record sequence number (48 bits on the wire in DTLS 1.2
/// and in `DTLSPlaintext`; RFC 9147 §4 keeps DTLS 1.3 senders below it
/// too).
pub(crate) const MAX_SEQ: u64 = (1 << 48) - 1;

/// The bytes of a serialized `RecordNumber` in an ACK (RFC 9147 §4, §7).
pub(crate) const RECORD_NUMBER_LEN: usize = 16;

const UNIFIED_FIXED_MASK: u8 = 0b1110_0000;
const UNIFIED_FIXED_BITS: u8 = 0b0010_0000;
const UNIFIED_CID: u8 = 0x10;
const UNIFIED_SEQ16: u8 = 0x08;
const UNIFIED_LENGTH: u8 = 0x04;
const UNIFIED_EPOCH: u8 = 0x03;

/// The unpacked epoch and sequence number of a record (RFC 9147 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RecordNumber {
    pub(crate) epoch: u64,
    pub(crate) seq: u64,
}

/// What a record header says, before any deprotection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Header {
    /// A legacy record header, including DTLS 1.2 with an optional CID.
    Plaintext {
        typ: ContentType,
        version: ProtocolVersion,
        epoch: u16,
        seq: u64,
        cid: Option<Range<usize>>,
    },
    /// The unified header of a `DTLSCiphertext` (RFC 9147 §4, figure 3).
    Unified {
        /// The low two bits of the epoch.
        epoch_bits: u8,
        /// Where the connection ID lies in the record, if the C bit is set.
        cid: Option<Range<usize>>,
        /// Where the one or two sequence number bytes lie; they are still
        /// encrypted (§4.2.3).
        seq: Range<usize>,
    },
}

/// A record found at the front of a datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) header: Header,
    /// The record body within the input: the fragment of a plaintext
    /// record, the `encrypted_record` of a ciphertext. The header is
    /// `0..body.start` and the next record starts at `body.end`.
    pub(crate) body: Range<usize>,
}

/// Parses the record at the front of `input` (what is left of a datagram).
///
/// `cid_len` is the length of the connection IDs this endpoint asked its
/// peer to use, zero when it negotiated none: the unified header does not
/// carry that length. A header with the C bit set while `cid_len` is zero
/// does not parse (RFC 9147 §9.1: without a negotiated CID such records are
/// rejected).
///
/// `None` means the bytes are not a record this endpoint can delimit, so
/// nothing after them in the datagram can be trusted either.
pub(crate) fn parse_record(input: &[u8], cid_len: usize) -> Option<Record> {
    let first = *input.first()?;
    if first & UNIFIED_FIXED_MASK == UNIFIED_FIXED_BITS {
        return parse_unified(input, first, cid_len);
    }
    // RFC 9147 §4.1: alert, handshake and ack are DTLSPlaintext; the other
    // types below are those of earlier versions with the same header.
    let typ = match ContentType::from(first) {
        typ @ (ContentType::ChangeCipherSpec
        | ContentType::Alert
        | ContentType::Handshake
        | ContentType::ApplicationData
        | ContentType::Tls12Cid
        | ContentType::Ack) => typ,
        _ => return None,
    };
    let header = input.get(..PLAINTEXT_HEADER_LEN)?;
    let version = ProtocolVersion::from(u16::from_be_bytes([header[1], header[2]]));
    let epoch = u16::from_be_bytes([header[3], header[4]]);
    let mut seq = [0u8; 8];
    seq[2..].copy_from_slice(&header[5..11]);
    let cid = if typ == ContentType::Tls12Cid {
        if cid_len == 0 || epoch == 0 || version != ProtocolVersion::DTLSv1_2 {
            return None;
        }
        Some(11..11usize.checked_add(cid_len)?)
    } else {
        None
    };
    let length_at = cid.as_ref().map_or(11, |range| range.end);
    let body_start = length_at.checked_add(2)?;
    let encoded_len: [u8; 2] = input.get(length_at..body_start)?.try_into().ok()?;
    let end = body_start.checked_add(usize::from(u16::from_be_bytes(encoded_len)))?;
    if input.len() < end {
        return None;
    }
    Some(Record {
        header: Header::Plaintext {
            typ,
            version,
            epoch,
            seq: u64::from_be_bytes(seq),
            cid,
        },
        body: body_start..end,
    })
}

fn parse_unified(input: &[u8], first: u8, cid_len: usize) -> Option<Record> {
    let mut at = 1usize;
    let cid = if first & UNIFIED_CID != 0 {
        if cid_len == 0 {
            return None;
        }
        let range = at..at.checked_add(cid_len)?;
        at = range.end;
        Some(range)
    } else {
        None
    };
    let seq_len = if first & UNIFIED_SEQ16 != 0 { 2 } else { 1 };
    let seq = at..at + seq_len;
    at = seq.end;
    let end = if first & UNIFIED_LENGTH != 0 {
        let len = input.get(at..at + 2)?;
        at += 2;
        at.checked_add(usize::from(u16::from_be_bytes([len[0], len[1]])))?
    } else {
        // RFC 9147 §4: without a length the record takes the rest of the
        // datagram.
        input.len()
    };
    if input.len() < end || end < at {
        return None;
    }
    Some(Record {
        header: Header::Unified {
            epoch_bits: first & UNIFIED_EPOCH,
            cid,
            seq,
        },
        body: at..end,
    })
}

/// Appends a `DTLSPlaintext` (or DTLS 1.2) record header. `seq` must not
/// exceed [`MAX_SEQ`]; its high 16 bits are not encoded.
pub(crate) fn put_plaintext_header(
    out: &mut Vec<u8>,
    typ: ContentType,
    version: ProtocolVersion,
    epoch: u16,
    seq: u64,
    len: u16,
) {
    put_legacy_header(out, typ, version, epoch, seq, &[], len);
}

#[cfg(feature = "tls12")]
pub(super) fn put_v12_cid_header(out: &mut Vec<u8>, seq: u64, cid: &[u8], len: u16) {
    put_legacy_header(
        out,
        ContentType::Tls12Cid,
        ProtocolVersion::DTLSv1_2,
        1,
        seq,
        cid,
        len,
    );
}

fn put_legacy_header(
    out: &mut Vec<u8>,
    typ: ContentType,
    version: ProtocolVersion,
    epoch: u16,
    seq: u64,
    cid: &[u8],
    len: u16,
) {
    out.push(u8::from(typ));
    out.extend_from_slice(&u16::from(version).to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes()[2..]);
    out.extend_from_slice(cid);
    out.extend_from_slice(&len.to_be_bytes());
}

/// The length of the unified header [`put_unified_header`] writes.
pub(crate) const fn unified_header_len(cid_len: usize) -> usize {
    1 + cid_len + 2 + 2
}

/// Appends the unified header this implementation sends: a 16-bit sequence
/// number and a length, so that records can follow one another in a
/// datagram, and the connection ID when `cid` is not empty. Returns where
/// the sequence number bytes were written (they are not yet encrypted).
pub(crate) fn put_unified_header(
    out: &mut Vec<u8>,
    epoch: u64,
    seq: u64,
    cid: &[u8],
    len: u16,
) -> Range<usize> {
    let mut first = UNIFIED_FIXED_BITS | UNIFIED_SEQ16 | UNIFIED_LENGTH;
    first |= (epoch & u64::from(UNIFIED_EPOCH)) as u8;
    if !cid.is_empty() {
        first |= UNIFIED_CID;
    }
    out.push(first);
    out.extend_from_slice(cid);
    let seq_at = out.len();
    out.extend_from_slice(&(seq as u16).to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    seq_at..seq_at + 2
}

/// The header of a `DTLSHandshake` message or fragment (RFC 9147 §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HandshakeHeader {
    /// The `HandshakeType` byte.
    pub(crate) typ: u8,
    /// The length of the whole message body.
    pub(crate) length: u32,
    pub(crate) message_seq: u16,
    pub(crate) fragment_offset: u32,
    pub(crate) fragment_length: u32,
}

impl HandshakeHeader {
    /// Reads the fragment at the front of `input`: its header, its bytes
    /// and what follows it in the record. `None` when it is truncated or
    /// reaches past the end of its message.
    pub(crate) fn read(input: &[u8]) -> Option<(Self, &[u8], &[u8])> {
        let header = input.get(..HANDSHAKE_HEADER_LEN)?;
        let u24 = |at: usize| u32::from_be_bytes([0, header[at], header[at + 1], header[at + 2]]);
        let this = Self {
            typ: header[0],
            length: u24(1),
            message_seq: u16::from_be_bytes([header[4], header[5]]),
            fragment_offset: u24(6),
            fragment_length: u24(9),
        };
        if this.fragment_offset.checked_add(this.fragment_length)? > this.length {
            return None;
        }
        let rest = &input[HANDSHAKE_HEADER_LEN..];
        let fragment = rest.get(..this.fragment_length as usize)?;
        Some((this, fragment, &rest[fragment.len()..]))
    }

    /// The twelve header bytes. The three 24-bit fields must fit 24 bits.
    pub(crate) fn encode(&self) -> [u8; HANDSHAKE_HEADER_LEN] {
        let length = self.length.to_be_bytes();
        let seq = self.message_seq.to_be_bytes();
        let offset = self.fragment_offset.to_be_bytes();
        let fragment = self.fragment_length.to_be_bytes();
        [
            self.typ,
            length[1],
            length[2],
            length[3],
            seq[0],
            seq[1],
            offset[1],
            offset[2],
            offset[3],
            fragment[1],
            fragment[2],
            fragment[3],
        ]
    }
}

/// Appends the body of an ACK message (RFC 9147 §7) for `numbers`, which
/// the caller keeps in increasing order and short enough for one record.
pub(crate) fn put_ack(out: &mut Vec<u8>, numbers: &[RecordNumber]) {
    let len = (numbers.len() * RECORD_NUMBER_LEN).min(usize::from(u16::MAX)) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    for number in numbers.iter().take(usize::from(len) / RECORD_NUMBER_LEN) {
        out.extend_from_slice(&number.epoch.to_be_bytes());
        out.extend_from_slice(&number.seq.to_be_bytes());
    }
}

/// The record numbers of an ACK body; `None` if it is malformed.
pub(crate) fn read_ack(body: &[u8]) -> Option<impl Iterator<Item = RecordNumber> + '_> {
    let (len, list) = body.split_first_chunk::<2>()?;
    if usize::from(u16::from_be_bytes(*len)) != list.len()
        || !list.len().is_multiple_of(RECORD_NUMBER_LEN)
    {
        return None;
    }
    Some(list.as_chunks::<RECORD_NUMBER_LEN>().0.iter().map(|chunk| {
        let (epoch, seq) = chunk.split_at(8);
        let word = |bytes: &[u8]| {
            let mut out = [0u8; 8];
            out.copy_from_slice(bytes);
            u64::from_be_bytes(out)
        };
        RecordNumber {
            epoch: word(epoch),
            seq: word(seq),
        }
    }))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn plaintext_header_round_trip() {
        let mut out = Vec::new();
        put_plaintext_header(
            &mut out,
            ContentType::Handshake,
            ProtocolVersion::DTLSv1_2,
            0,
            0x0000_0102_0304_0506,
            3,
        );
        assert_eq!(
            out,
            [22, 0xfe, 0xfd, 0, 0, 1, 2, 3, 4, 5, 6, 0, 3],
            "RFC 9147 figure 2"
        );
        out.extend_from_slice(&[7, 8, 9, 0xaa]);
        let record = parse_record(&out, 0).unwrap();
        assert_eq!(
            record.header,
            Header::Plaintext {
                typ: ContentType::Handshake,
                version: ProtocolVersion::DTLSv1_2,
                epoch: 0,
                seq: 0x0102_0304_0506,
                cid: None,
            }
        );
        assert_eq!(record.body, 13..16);
        // A record cut short does not parse, nor does a header alone.
        assert_eq!(parse_record(&out[..15], 0), None);
        assert_eq!(parse_record(&out[..12], 0), None);
        assert_eq!(parse_record(&[], 0), None);
    }

    #[test]
    fn demultiplexing_follows_rfc9147_figure_5() {
        let body = [0u8; 20];
        for first in 0..=255u8 {
            let mut record = vec![first, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20];
            if first & UNIFIED_FIXED_MASK == UNIFIED_FIXED_BITS && first & UNIFIED_LENGTH != 0 {
                // A unified header with a length: one or two sequence
                // number bytes, then the length of the body.
                let seq_len = if first & UNIFIED_SEQ16 != 0 { 2 } else { 1 };
                record.truncate(1 + seq_len);
                record.extend_from_slice(&[0, 20]);
            }
            record.extend_from_slice(&body);
            let parsed = parse_record(&record, 0);
            match first {
                20..=23 | 26 => assert!(
                    matches!(
                        parsed,
                        Some(Record {
                            header: Header::Plaintext { .. },
                            ..
                        })
                    ),
                    "{first}"
                ),
                // 0b001x_xxxx without the C bit.
                32..=47 => assert!(
                    matches!(
                        parsed,
                        Some(Record {
                            header: Header::Unified { cid: None, .. },
                            ..
                        })
                    ),
                    "{first}"
                ),
                // The C bit without a negotiated connection ID.
                48..=63 => assert_eq!(parsed, None, "{first}"),
                _ => assert_eq!(parsed, None, "{first}"),
            }
        }
    }

    #[test]
    fn unified_header_variants() {
        // Minimal: 8-bit sequence number, no length, epoch bits 3.
        let record = parse_record(&[0b0010_0011, 0x55, 1, 2, 3], 0).unwrap();
        assert_eq!(
            record.header,
            Header::Unified {
                epoch_bits: 3,
                cid: None,
                seq: 1..2,
            }
        );
        assert_eq!(record.body, 2..5);

        // Full: connection ID, 16-bit sequence number, length; a second
        // record follows.
        let mut out = Vec::new();
        let seq_at = put_unified_header(&mut out, 6, 0x1_2345, &[9, 8, 7], 2);
        assert_eq!(out, [0b0011_1110, 9, 8, 7, 0x23, 0x45, 0, 2]);
        assert_eq!(seq_at, 4..6);
        assert_eq!(out.len(), unified_header_len(3));
        out.extend_from_slice(&[0xee, 0xff, 0x2f]);
        let record = parse_record(&out, 3).unwrap();
        assert_eq!(
            record.header,
            Header::Unified {
                epoch_bits: 2,
                cid: Some(1..4),
                seq: 4..6,
            }
        );
        assert_eq!(record.body, 8..10);
        // The declared length must be there.
        assert_eq!(parse_record(&out[..9], 3), None);
        // Without a connection ID no bit is set for it.
        let mut out = Vec::new();
        put_unified_header(&mut out, 3, 1, &[], 0);
        assert_eq!(out, [0b0010_1111, 0, 1, 0, 0]);
        assert_eq!(parse_record(&out, 0).unwrap().body, 5..5);
    }

    #[test]
    fn handshake_header_round_trip_and_bounds() {
        let header = HandshakeHeader {
            typ: 1,
            length: 0x01_0203,
            message_seq: 0x0405,
            fragment_offset: 0x00_0010,
            fragment_length: 3,
        };
        let mut bytes = header.encode().to_vec();
        assert_eq!(bytes, [1, 1, 2, 3, 4, 5, 0, 0, 0x10, 0, 0, 3]);
        bytes.extend_from_slice(&[0xa, 0xb, 0xc, 0xd]);
        let (read, fragment, rest) = HandshakeHeader::read(&bytes).unwrap();
        assert_eq!(read, header);
        assert_eq!(fragment, [0xa, 0xb, 0xc]);
        assert_eq!(rest, [0xd]);
        // Truncated header or fragment.
        assert!(HandshakeHeader::read(&bytes[..11]).is_none());
        assert!(HandshakeHeader::read(&bytes[..14]).is_none());
        // A fragment reaching past the end of its message.
        let past = HandshakeHeader {
            length: 0x12,
            ..header
        };
        let mut bytes = past.encode().to_vec();
        bytes.extend_from_slice(&[0; 3]);
        assert!(HandshakeHeader::read(&bytes).is_none());
        // An empty message is one empty fragment.
        let empty = HandshakeHeader {
            typ: 14,
            length: 0,
            message_seq: 2,
            fragment_offset: 0,
            fragment_length: 0,
        };
        let bytes = empty.encode();
        let (read, fragment, rest) = HandshakeHeader::read(&bytes).unwrap();
        assert_eq!(read, empty);
        assert!(fragment.is_empty() && rest.is_empty());
    }

    #[test]
    fn ack_round_trip_and_malformed() {
        let numbers = [
            RecordNumber { epoch: 2, seq: 0 },
            RecordNumber {
                epoch: 2,
                seq: 0x0102_0304_0506_0708,
            },
        ];
        let mut out = Vec::new();
        put_ack(&mut out, &numbers);
        assert_eq!(out.len(), 2 + 32);
        assert_eq!(read_ack(&out).unwrap().collect::<Vec<_>>(), numbers);
        // An empty ACK (RFC 9147 §7.1) is valid.
        let mut empty = Vec::new();
        put_ack(&mut empty, &[]);
        assert_eq!(empty, [0, 0]);
        assert_eq!(read_ack(&empty).unwrap().count(), 0);
        // Wrong length prefix, partial record number, missing prefix.
        assert!(read_ack(&out[..out.len() - 1]).is_none());
        assert!(read_ack(&[0, 8, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(read_ack(&[0]).is_none());
    }
}
