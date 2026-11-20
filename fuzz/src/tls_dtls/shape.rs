//! Fuzzed datagrams shaped like DTLS records (RFC 9147 §4): plaintext
//! headers, unified headers with every flag combination, ACK bodies,
//! alerts and fragmented handshake headers, with lengths that are right or
//! fuzzed.

use crate::input::{Input, put_short_field};

/// Content types to put in a plaintext header; the last is fuzzed.
const TYPES: [u8; 6] = [22, 22, 21, 26, 23, 20];

/// Handshake types to put in a fragment header; others are fuzzed.
const HANDSHAKE_TYPES: [u8; 10] = [1, 2, 4, 6, 8, 11, 13, 15, 20, 24];

/// A datagram of one to four records, or raw bytes.
pub(super) fn datagram(input: &mut Input) -> Vec<u8> {
    let mut out = Vec::new();
    let records = 1 + input.choose(4);
    for _ in 0..records {
        match input.choose(6) {
            0 => out.extend_from_slice(input.short_field()),
            1 | 2 => plaintext(input, &mut out),
            3 => unified(input, &mut out),
            4 => {
                // An ACK record.
                let body = ack(input);
                put_plaintext(&mut out, 26, 0xfefd, 0, input.u16(), &body, None);
            }
            _ => {
                // Handshake fragments in epoch 0.
                let body = fragments(input);
                put_plaintext(&mut out, 22, 0xfefd, 0, input.u16(), &body, None);
            }
        }
    }
    out
}

fn u24(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes()[1..]);
}

fn put_plaintext(
    out: &mut Vec<u8>,
    typ: u8,
    version: u16,
    epoch: u16,
    seq: u16,
    body: &[u8],
    length: Option<u16>,
) {
    out.push(typ);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&seq.to_be_bytes());
    let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&length.unwrap_or(len).to_be_bytes());
    out.extend_from_slice(body);
}

/// A `DTLSPlaintext` record with a fuzz-chosen type, version, epoch,
/// body and (right or wrong) length.
fn plaintext(input: &mut Input, out: &mut Vec<u8>) {
    let typ = match input.choose(TYPES.len() + 1) {
        i if i < TYPES.len() => TYPES[i],
        _ => input.byte(),
    };
    let version = match input.choose(5) {
        0 => 0xfefc,
        1 => 0xfeff,
        2 => 0x0303,
        3 => input.u16(),
        _ => 0xfefd,
    };
    let epoch = if input.bool() { input.u16() } else { 0 };
    let seq = input.u16();
    let body = match input.choose(4) {
        0 => fragments(input),
        1 => ack(input),
        2 => input.bytes(2).to_vec(),
        _ => input.short_field().to_vec(),
    };
    let length = input.bool().then(|| input.u16());
    put_plaintext(out, typ, version, epoch, seq, &body, length);
}

/// A unified header (`0b001CSLEE`) with the low five bits fuzzed: a
/// connection ID when C is set, one or two sequence number bytes, a right
/// or wrong length when L is set, then the "ciphertext".
fn unified(input: &mut Input, out: &mut Vec<u8>) {
    let flags = input.byte() & 0x1f;
    out.push(0x20 | flags);
    if flags & 0x10 != 0 {
        out.extend_from_slice(input.short_field());
    }
    let seq = input.u16().to_be_bytes();
    if flags & 0x08 != 0 {
        out.extend_from_slice(&seq);
    } else {
        out.push(seq[1]);
    }
    let body = input.short_field();
    if flags & 0x04 != 0 {
        let len = if input.bool() {
            input.u16()
        } else {
            body.len() as u16
        };
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(body);
}

/// An ACK body: zero to three record numbers, with the right length or a
/// fuzzed one.
fn ack(input: &mut Input) -> Vec<u8> {
    let count = input.choose(4);
    let mut list = Vec::new();
    for _ in 0..count {
        let epoch = match input.choose(5) {
            4 => input.u64(),
            e => e as u64,
        };
        let seq = if input.bool() {
            input.u64()
        } else {
            u64::from(input.byte())
        };
        list.extend_from_slice(&epoch.to_be_bytes());
        list.extend_from_slice(&seq.to_be_bytes());
    }
    let len = if input.bool() {
        input.u16()
    } else {
        list.len() as u16
    };
    let mut body = len.to_be_bytes().to_vec();
    body.extend_from_slice(&list);
    body
}

/// One to three `DTLSHandshake` fragments: a fuzz-chosen type and message
/// sequence, and an offset and length that fit the message or not.
fn fragments(input: &mut Input) -> Vec<u8> {
    let mut out = Vec::new();
    let count = 1 + input.choose(3);
    for _ in 0..count {
        let typ = match input.choose(HANDSHAKE_TYPES.len() + 1) {
            i if i < HANDSHAKE_TYPES.len() => HANDSHAKE_TYPES[i],
            _ => input.byte(),
        };
        let message_seq = match input.choose(5) {
            4 => input.u16(),
            seq => seq as u16,
        };
        let data = input.short_field();
        let consistent = input.bool();
        let (length, offset, fragment_length) = if consistent {
            let extra = u32::from(input.u16());
            let offset = extra / 2;
            (data.len() as u32 + extra, offset, data.len() as u32)
        } else {
            (
                input.u32() & 0xff_ffff,
                input.u32() & 0xff_ffff,
                input.u32() & 0xff_ffff,
            )
        };
        out.push(typ);
        u24(&mut out, length);
        out.extend_from_slice(&message_seq.to_be_bytes());
        u24(&mut out, offset);
        u24(&mut out, fragment_length);
        out.extend_from_slice(data);
    }
    out
}

// ------------------------------------------------------------------ seeds

/// Seed bytes for [`datagram`]: a plaintext ClientHello fragment, an ACK,
/// an alert, and a unified record for the flag combination `flags`.
pub(super) fn seed(flags: u8) -> Vec<u8> {
    let mut seed = vec![3]; // four records
    // 1: plaintext handshake, DTLS 1.2 version, epoch 0, fragments
    seed.extend_from_slice(&[1, 0, 4, 0]);
    seed.extend_from_slice(&[0, 1]); // seq
    seed.push(0); // body: fragments
    seed.extend_from_slice(&[0, 0, 0]); // one ClientHello, message_seq 0
    put_short_field(&mut seed, b"\xfe\xfd fuzz client hello");
    seed.extend_from_slice(&[1, 0, 0x40]); // consistent, extra 0x40
    seed.push(0); // right length
    // 4: ACK of epoch 2 record 0
    seed.extend_from_slice(&[4, 1, 2, 0, 0, 0, 0, 3]);
    // 3: unified header with the given flags
    seed.extend_from_slice(&[3, flags]);
    if flags & 0x10 != 0 {
        put_short_field(&mut seed, &[1, 2, 3, 4]);
    }
    seed.extend_from_slice(&[0, 7]);
    put_short_field(&mut seed, &[0x5a; 24]);
    if flags & 0x04 != 0 {
        seed.push(0);
    }
    // 1: plaintext alert, epoch 0
    seed.extend_from_slice(&[1, 2, 4, 0, 0, 9, 2]);
    seed.extend_from_slice(&[2, 40]);
    seed.push(0);
    seed
}
