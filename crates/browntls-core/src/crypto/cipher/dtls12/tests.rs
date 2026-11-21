//! Negative conformance cases, using locally sealed, independent fixtures.

use alloc::vec::Vec;

use super::*;
use crate::crypto::cipher::{AeadKey, Tls12AeadAlgorithm, make_tls12_aad};

pub(crate) const NUMBER: u64 = 0x1234_0102_0304_0506;
const CID: &[u8] = &[0x41, 0, 0x42];

/// Fixture nonce derivation, independent of the production nonce helpers.
pub(crate) fn fixture_nonce(explicit_len: usize) -> [u8; 12] {
    let mut nonce = [1; 12];
    if explicit_len == 8 {
        let explicit = u64::from_be_bytes([2; 8]).wrapping_add(NUMBER);
        nonce[4..].copy_from_slice(&explicit.to_be_bytes());
    } else {
        for (byte, number) in nonce[4..].iter_mut().zip(NUMBER.to_be_bytes()) {
            *byte ^= number;
        }
    }
    nonce
}

fn fixture_aad(inner_len: usize) -> Vec<u8> {
    // RFC 9146 §5.3: literal sentinel, type, CID count, type, version,
    // epoch and sequence, then CID and encoded-inner length. Do not call
    // the production AAD builder here.
    let mut aad = alloc::vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 25, 3, 25, 0xfe, 0xfd, 0x12, 0x34, 1, 2, 3,
        4, 5, 6, 0x41, 0, 0x42,
    ];
    aad.extend_from_slice(&(inner_len as u16).to_be_bytes());
    aad
}

fn message<'a>(body: &'a mut [u8]) -> InboundOpaqueMessage<'a> {
    InboundOpaqueMessage::new(ContentType::Tls12Cid, ProtocolVersion::DTLSv1_2, body)
}

/// Each provider calls these cases for AES-128, AES-256 and ChaCha, sealing
/// fixtures directly with its existing primitive and the supplied AAD.
pub(crate) fn reject_invalid_records(
    alg: &dyn Tls12AeadAlgorithm,
    fixture: impl Fn(&[u8], &[u8]) -> Vec<u8>,
) {
    let shape = alg.key_block_shape();
    let key = || AeadKey::from([9; 32]).with_length(shape.enc_key_len);
    let iv = alloc::vec![1; shape.fixed_iv_len];
    let mut dec = alg.decrypter(key(), &iv);
    let mut enc = alg.encrypter(key(), &iv, &[2; 8]);
    assert!(dec.supports_dtls12_cid());
    assert!(enc.supports_dtls12_cid());

    let inner = b"content\0\x17\0\0";
    let aad = fixture_aad(inner.len());
    let body = fixture(inner, &aad);

    // Every authenticated field, including both type bytes, CID count,
    // sentinel, epoch, sequence, CID and inner length, is indispensable.
    for i in 0..aad.len() {
        let mut altered = aad.clone();
        altered[i] ^= 1;
        let mut bad = fixture(inner, &altered);
        assert_eq!(
            dec.decrypt_dtls12_cid(message(&mut bad), NUMBER, CID)
                .unwrap_err(),
            Error::DecryptError,
            "accepted altered AAD byte {i}",
        );
    }
    // Structurally different AAD must not trigger draft-format or
    // zero-extended-AAD compatibility retries either.
    let mut missing_count = aad.clone();
    missing_count.remove(9);
    let no_sentinel = aad[8..].to_vec();
    let mut extended_aad = aad.clone();
    extended_aad.push(0);
    for altered in [missing_count, no_sentinel, extended_aad] {
        let mut bad = fixture(inner, &altered);
        assert_eq!(
            dec.decrypt_dtls12_cid(message(&mut bad), NUMBER, CID)
                .unwrap_err(),
            Error::DecryptError,
        );
    }
    // Explicit nonce (GCM), ciphertext and every tag byte are protected.
    for i in 0..body.len() {
        let mut bad = body.clone();
        bad[i] ^= 0x80;
        assert_eq!(
            dec.decrypt_dtls12_cid(message(&mut bad), NUMBER, CID)
                .unwrap_err(),
            Error::DecryptError,
        );
    }
    // No truncated tags, zero extension, or alternative length/tag parsing.
    for len in 0..body.len() {
        let mut bad = body[..len].to_vec();
        assert_eq!(
            dec.decrypt_dtls12_cid(message(&mut bad), NUMBER, CID)
                .unwrap_err(),
            Error::DecryptError,
        );
    }
    let mut extended = body.clone();
    extended.push(0);
    assert_eq!(
        dec.decrypt_dtls12_cid(message(&mut extended), NUMBER, CID)
            .unwrap_err(),
        Error::DecryptError,
    );
    for seq in [NUMBER ^ (1 << 48), NUMBER & 0xffff_ffff_ffff, NUMBER + 1] {
        let mut bad = body.clone();
        assert_eq!(
            dec.decrypt_dtls12_cid(message(&mut bad), seq, CID)
                .unwrap_err(),
            Error::DecryptError,
        );
    }
    for cid in [
        &[][..],
        &[0x41, 0, 0x43],
        &[0x41, 0],
        &[0x41, 0, 0x42, 0],
        &[0; 256],
    ] {
        let mut bad = body.clone();
        assert_eq!(
            dec.decrypt_dtls12_cid(message(&mut bad), NUMBER, cid)
                .unwrap_err(),
            Error::DecryptError,
        );
    }
    for version in [
        ProtocolVersion::TLSv1_2,
        ProtocolVersion::DTLSv1_0,
        ProtocolVersion::TLSv1_3,
    ] {
        let mut bad = body.clone();
        let msg = InboundOpaqueMessage::new(ContentType::Tls12Cid, version, &mut bad);
        assert_eq!(
            dec.decrypt_dtls12_cid(msg, NUMBER, CID).unwrap_err(),
            Error::DecryptError
        );
    }
    for typ in [
        ContentType::ApplicationData,
        ContentType::Handshake,
        ContentType::Unknown(0),
    ] {
        let mut bad = body.clone();
        let msg = InboundOpaqueMessage::new(typ, ProtocolVersion::DTLSv1_2, &mut bad);
        assert_eq!(
            dec.decrypt_dtls12_cid(msg, NUMBER, CID).unwrap_err(),
            Error::DecryptError
        );
    }

    // A valid tag over malformed inner bytes still must not expose plaintext.
    for invalid in [
        &[][..],
        &[0],
        &[0; 8],
        b"content\xff\0",
        b"content\x19\0",
        b"content\x1a",
        b"content\x1b",
        &[20, 0],
        &[21, 0],
        &[22, 0],
        &[24, 0],
    ] {
        let mut bad = fixture(invalid, &fixture_aad(invalid.len()));
        assert_eq!(
            dec.decrypt_dtls12_cid(message(&mut bad), NUMBER, CID)
                .unwrap_err(),
            Error::DecryptError,
        );
    }
    // Content itself fits, but content + type + padding exceeds 2^14.
    let mut oversized = alloc::vec![0; MAX_PLAINTEXT_LEN + 1];
    oversized[..MAX_PLAINTEXT_LEN - 1].fill(b'x');
    oversized[MAX_PLAINTEXT_LEN - 1] = 23;
    let mut bad = fixture(&oversized, &fixture_aad(oversized.len()));
    assert_eq!(
        dec.decrypt_dtls12_cid(message(&mut bad), NUMBER, CID)
            .unwrap_err(),
        Error::DecryptError,
    );

    // Neither side may retry the other authentication domain.
    for typ in [ContentType::Tls12Cid, ContentType::ApplicationData] {
        let old_aad = make_tls12_aad(NUMBER, typ, ProtocolVersion::DTLSv1_2, inner.len());
        let mut old = fixture(inner, &old_aad);
        assert_eq!(
            dec.decrypt_dtls12_cid(message(&mut old), NUMBER, CID)
                .unwrap_err(),
            Error::DecryptError,
        );
        let mut bad = body.clone();
        let msg = InboundOpaqueMessage::new(typ, ProtocolVersion::DTLSv1_2, &mut bad);
        assert_eq!(dec.decrypt(msg, NUMBER).unwrap_err(), Error::DecryptError);
    }

    // Exercise the actual CID encoder when constructing a fixture for
    // cross-domain and changed-sequence rejection; no network inputs.
    let produced = enc
        .encrypt_dtls12_cid(
            OutboundPlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::DTLSv1_2,
                payload: OutboundChunks::Single(b"handshake"),
            },
            NUMBER,
            CID,
            4,
        )
        .unwrap();
    let mut bad = produced.payload.as_ref().to_vec();
    assert_eq!(
        dec.decrypt_dtls12_cid(message(&mut bad), NUMBER ^ (1 << 48), CID)
            .unwrap_err(),
        Error::DecryptError,
    );
    let mut bad = produced.payload.as_ref().to_vec();
    assert_eq!(
        dec.decrypt(message(&mut bad), NUMBER).unwrap_err(),
        Error::DecryptError
    );

    let plain = |typ, version| OutboundPlainMessage {
        typ,
        version,
        payload: OutboundChunks::Single(b"content"),
    };
    for cid in [&[][..], &[0; 256]] {
        assert!(matches!(
            enc.encrypt_dtls12_cid(
                plain(ContentType::ApplicationData, ProtocolVersion::DTLSv1_2),
                NUMBER,
                cid,
                0
            ),
            Err(Error::EncryptError),
        ));
    }
    for typ in [
        ContentType::Tls12Cid,
        ContentType::Ack,
        ContentType::ReturnRoutabilityCheck,
        ContentType::Unknown(0),
        ContentType::Unknown(255),
    ] {
        assert!(matches!(
            enc.encrypt_dtls12_cid(plain(typ, ProtocolVersion::DTLSv1_2), NUMBER, CID, 0),
            Err(Error::EncryptError),
        ));
    }
    assert!(matches!(
        enc.encrypt_dtls12_cid(
            plain(ContentType::ApplicationData, ProtocolVersion::TLSv1_2),
            NUMBER,
            CID,
            0
        ),
        Err(Error::EncryptError),
    ));
    for padding in [MAX_PLAINTEXT_LEN, usize::MAX] {
        assert!(matches!(
            enc.encrypt_dtls12_cid(
                plain(ContentType::ApplicationData, ProtocolVersion::DTLSv1_2),
                NUMBER,
                CID,
                padding
            ),
            Err(Error::EncryptError),
        ));
    }
    let too_long = alloc::vec![0; MAX_PLAINTEXT_LEN];
    let too_long = OutboundPlainMessage {
        typ: ContentType::ApplicationData,
        version: ProtocolVersion::DTLSv1_2,
        payload: OutboundChunks::Single(&too_long),
    };
    assert!(matches!(
        enc.encrypt_dtls12_cid(too_long, NUMBER, CID, 0),
        Err(Error::EncryptError)
    ));
    // Missing chunk bytes cannot be silently extended with zeroes.
    for (start, end) in [(0, 10), (9, 8)] {
        let incomplete = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::DTLSv1_2,
            payload: OutboundChunks::Multiple {
                chunks: &[b"short"],
                start,
                end,
            },
        };
        assert!(matches!(
            enc.encrypt_dtls12_cid(incomplete, NUMBER, CID, 0),
            Err(Error::EncryptError)
        ));
    }
    for typ in [
        ContentType::ChangeCipherSpec,
        ContentType::Alert,
        ContentType::Handshake,
        ContentType::Heartbeat,
    ] {
        let empty = OutboundPlainMessage {
            typ,
            version: ProtocolVersion::DTLSv1_2,
            payload: OutboundChunks::Single(&[]),
        };
        assert!(matches!(
            enc.encrypt_dtls12_cid(empty, NUMBER, CID, 0),
            Err(Error::EncryptError)
        ));
    }
}
