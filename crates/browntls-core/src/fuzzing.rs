//! Entry points for the fuzz targets in `fuzz/`.
//!
//! Compiled only with the `fuzzing` feature and not a supported API: the
//! functions reach codecs that are otherwise private, and may change or
//! disappear in any release. Each takes untrusted bytes and must return
//! without panicking whatever they are.

use alloc::vec::Vec;

use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{
    CertificatePayloadTls13, CompressedCertificatePayload, HandshakeMessagePayload,
};
use crate::msgs::message::MessagePayload;

/// Feeds `data` to the record deframer as a peer's byte stream: record
/// headers, handshake message reassembly, and decoding of every complete
/// message.
pub fn deframer(data: &[u8]) {
    crate::msgs::deframer::fuzz_deframer(data);
}

fn version(tls13: bool) -> ProtocolVersion {
    if tls13 {
        ProtocolVersion::TLSv1_3
    } else {
        ProtocolVersion::TLSv1_2
    }
}

/// Decodes `data` as one handshake message (type, 24-bit length, body) in
/// the TLS 1.3 or TLS 1.2 format.
///
/// A message that decodes must encode to something that decodes again, and
/// that second encoding must be stable.
pub fn handshake_message(tls13: bool, data: &[u8]) {
    let vers = version(tls13);
    let Ok(message) = HandshakeMessagePayload::read_version(&mut Reader::init(data), vers) else {
        return;
    };
    let mut first = Vec::new();
    message.encode(&mut first);
    let again = HandshakeMessagePayload::read_version(&mut Reader::init(&first), vers);
    assert!(
        again.is_ok(),
        "a decoded handshake message does not decode after encoding"
    );
    let Ok(again) = again else {
        return;
    };
    let mut second = Vec::new();
    again.encode(&mut second);
    assert!(first == second, "handshake message encoding is not stable");
}

/// The handshake message types with a dedicated decoder, plus one unknown
/// code point.
const HANDSHAKE_TYPES: &[HandshakeType] = &[
    HandshakeType::HelloRequest,
    HandshakeType::ClientHello,
    HandshakeType::ServerHello,
    HandshakeType::NewSessionTicket,
    HandshakeType::EndOfEarlyData,
    HandshakeType::HelloRetryRequest,
    HandshakeType::EncryptedExtensions,
    HandshakeType::Certificate,
    HandshakeType::ServerKeyExchange,
    HandshakeType::CertificateRequest,
    HandshakeType::ServerHelloDone,
    HandshakeType::CertificateVerify,
    HandshakeType::ClientKeyExchange,
    HandshakeType::Finished,
    HandshakeType::CertificateStatus,
    HandshakeType::KeyUpdate,
    HandshakeType::CompressedCertificate,
    HandshakeType::MessageHash,
    HandshakeType::Unknown(0x63),
];

/// Decodes `body` as the body of the handshake message type that `selector`
/// picks, so that every decoder is reached without the fuzzer having to
/// produce a matching header.
pub fn handshake_body(selector: u8, tls13: bool, body: &[u8]) {
    let typ = HANDSHAKE_TYPES[usize::from(selector) % HANDSHAKE_TYPES.len()];
    let Ok(len) = u32::try_from(body.len()) else {
        return;
    };
    if len > 0x00ff_ffff {
        return;
    }
    let mut message = Vec::with_capacity(4 + body.len());
    typ.encode(&mut message);
    message.extend_from_slice(&len.to_be_bytes()[1..]);
    message.extend_from_slice(body);
    handshake_message(tls13, &message);
}

/// Decodes `data` as the payload of one record of the content type that
/// `selector` picks (alert, change_cipher_spec, handshake, application data
/// or an unknown type).
pub fn record_payload(selector: u8, tls13: bool, data: &[u8]) {
    let typ = match selector % 5 {
        0 => ContentType::Alert,
        1 => ContentType::ChangeCipherSpec,
        2 => ContentType::Handshake,
        3 => ContentType::ApplicationData,
        _ => ContentType::Heartbeat,
    };
    if let Ok(payload) = MessagePayload::new(typ, version(tls13), data) {
        let mut encoded = Vec::new();
        payload.encode(&mut encoded);
        let _ = payload.into_owned();
    }
}

/// Decodes `data` as a `CompressedCertificate` body (RFC 8879 §4), expands it
/// with the built-in decompressors of this build under `limit`, and decodes
/// the Certificate message inside.
pub fn compressed_certificate(limit: usize, data: &[u8]) {
    let Ok(compressed) = CompressedCertificatePayload::read_bytes(data) else {
        return;
    };
    let declared = compressed.uncompressed_len as usize;
    let decompressors = crate::compress::default_cert_decompressors();
    if let Ok(body) = crate::compress::decompress_certificate(decompressors, limit, &compressed) {
        assert!(body.len() == declared && declared <= limit);
        assert!(body.len() <= crate::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE);
        let _ = CertificatePayloadTls13::read_bytes(&body);
    }
}
