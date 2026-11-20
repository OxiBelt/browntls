//! TLS message codecs: handshake messages, records, compressed certificates.

use browntls_core::fuzzing;

use crate::take_byte;

/// Handshake message decoding (`fuzz_targets/handshake_message.rs`).
///
/// The first byte selects the protocol version (bit 0) and the framing
/// (bit 1): either the rest is a whole message with its header, or the
/// second byte picks a message type and the rest is that message's body, so
/// that each message decoder is reached directly.
pub fn handshake_message(mut data: &[u8]) {
    let mode = take_byte(&mut data);
    let tls13 = mode & 1 != 0;
    if mode & 2 == 0 {
        fuzzing::handshake_message(tls13, data);
    } else {
        let selector = take_byte(&mut data);
        fuzzing::handshake_body(selector, tls13, data);
    }
}

/// Record deframing (`fuzz_targets/deframer.rs`).
///
/// The first byte selects the mode: the rest is a byte stream for the
/// deframer (records, handshake reassembly, message decoding), or the
/// payload of one record of a chosen content type.
pub fn deframer(mut data: &[u8]) {
    let mode = take_byte(&mut data);
    if mode & 1 == 0 {
        fuzzing::deframer(data);
    } else {
        fuzzing::record_payload(mode >> 2, mode & 2 != 0, data);
    }
}

/// Certificate decompression, RFC 8879 (`fuzz_targets/cert_decompress.rs`).
///
/// The first byte selects the configured limit; the rest is the body of a
/// `CompressedCertificate` message (algorithm, declared length, data) for
/// the built-in zlib, Brotli and Zstandard decompressors.
pub fn cert_decompress(mut data: &[u8]) {
    let limit = match take_byte(&mut data) % 4 {
        0 => 64,
        1 => 4096,
        2 => browntls_core::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE,
        _ => usize::MAX,
    };
    fuzzing::compressed_certificate(limit, data);
}
