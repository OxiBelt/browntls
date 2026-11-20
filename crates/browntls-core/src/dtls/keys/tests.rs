//! Tests of DTLS 1.3 record protection.

#![cfg(any(feature = "native", feature = "rustcrypto"))]

use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::dtls::wire::{Header, parse_record};
use crate::suites::SupportedCipherSuite;

fn suites() -> Vec<&'static Tls13CipherSuite> {
    let mut all: Vec<&SupportedCipherSuite> = Vec::new();
    #[cfg(feature = "native")]
    {
        use crate::crypto::native::cipher_suite as native;
        all.extend([
            &native::TLS13_AES_128_GCM_SHA256,
            &native::TLS13_AES_256_GCM_SHA384,
            &native::TLS13_CHACHA20_POLY1305_SHA256,
            &native::TLS13_AES_128_CCM_SHA256,
        ]);
    }
    #[cfg(feature = "rustcrypto")]
    {
        use crate::crypto::rustcrypto::cipher_suite as rustcrypto;
        all.extend([
            &rustcrypto::TLS13_AES_128_GCM_SHA256,
            &rustcrypto::TLS13_AES_256_GCM_SHA384,
            &rustcrypto::TLS13_CHACHA20_POLY1305_SHA256,
        ]);
    }
    all.into_iter().filter_map(|s| s.tls13()).collect()
}

fn secret(suite: &Tls13CipherSuite) -> OkmBlock {
    OkmBlock::new(&vec![0x42; suite.common.hash_provider.output_len()])
}

fn keys(suite: &'static Tls13CipherSuite) -> RecordKeys {
    RecordKeys::derive(suite, &secret(suite)).unwrap()
}

/// Seals `content` and returns the record with where its sequence number
/// bytes and body lie.
fn seal(
    keys: &RecordKeys,
    number: RecordNumber,
    content: &[u8],
) -> (Vec<u8>, Range<usize>, Range<usize>) {
    let mut out = Vec::new();
    keys.seal(&mut out, number, ContentType::Handshake, content, &[])
        .unwrap();
    assert_eq!(out.len(), keys.sealed_len(content.len(), 0));
    let record = parse_record(&out, 0).unwrap();
    assert_eq!(record.body.end, out.len());
    let Header::Unified {
        epoch_bits, seq, ..
    } = record.header
    else {
        panic!("not a unified header");
    };
    assert_eq!(u64::from(epoch_bits), number.epoch & 3);
    (out, seq, record.body)
}

#[test]
fn round_trip_every_suite() {
    for suite in suites() {
        let keys = keys(suite);
        for len in [0, 1, 2, 15, 16, 100, 1000] {
            let content: Vec<u8> = (0..len).map(|i| i as u8 | 1).collect();
            let number = RecordNumber {
                epoch: 2,
                seq: 0x1_2345,
            };
            let (mut record, seq, body) = seal(&keys, number, &content);
            // The body is padded to the sixteen bytes the mask samples.
            assert!(body.len() >= MIN_CIPHERTEXT_LEN);
            // The sequence number on the wire is masked.
            let opened = keys.open(&mut record, seq, body.clone(), 0x1_2340).unwrap();
            assert_eq!(opened.seq, number.seq);
            assert_eq!(opened.typ, ContentType::Handshake);
            assert_eq!(&record[opened.content], content.as_slice());
        }
    }
}

#[test]
fn tampering_is_detected() {
    for suite in suites() {
        let keys = keys(suite);
        let number = RecordNumber { epoch: 3, seq: 7 };
        let (record, seq, body) = seal(&keys, number, b"application data");
        for at in 0..record.len() {
            let mut tampered = record.clone();
            tampered[at] ^= 0x80;
            assert_eq!(
                keys.open(&mut tampered, seq.clone(), body.clone(), 7),
                None,
                "byte {at} of {:?}",
                suite.common.suite
            );
        }
        // A record that is too short for the mask sample is rejected.
        let mut short = record[..body.start + MIN_CIPHERTEXT_LEN - 1].to_vec();
        let end = short.len();
        assert_eq!(keys.open(&mut short, seq, body.start..end, 7), None);
    }
}

#[test]
fn keys_are_bound_to_the_secret_and_the_record_number() {
    for suite in suites() {
        let keys = keys(suite);
        let other = RecordKeys::derive(
            suite,
            &OkmBlock::new(&vec![0x43; suite.common.hash_provider.output_len()]),
        )
        .unwrap();
        let number = RecordNumber { epoch: 2, seq: 1 };
        let (record, seq, body) = seal(&keys, number, b"hello");
        assert_eq!(
            other.open(&mut record.clone(), seq.clone(), body.clone(), 1),
            None
        );
        // Reconstructed to a different sequence number (another 2^16
        // window), the nonce differs and authentication fails.
        assert_eq!(keys.open(&mut record.clone(), seq, body, 1 << 16), None);
    }
}

#[test]
fn providers_agree_byte_for_byte() {
    #[cfg(all(feature = "native", feature = "rustcrypto"))]
    {
        use crate::crypto::native::cipher_suite as native;
        use crate::crypto::rustcrypto::cipher_suite as rustcrypto;
        let pairs = [
            (
                &native::TLS13_AES_128_GCM_SHA256,
                &rustcrypto::TLS13_AES_128_GCM_SHA256,
            ),
            (
                &native::TLS13_AES_256_GCM_SHA384,
                &rustcrypto::TLS13_AES_256_GCM_SHA384,
            ),
            (
                &native::TLS13_CHACHA20_POLY1305_SHA256,
                &rustcrypto::TLS13_CHACHA20_POLY1305_SHA256,
            ),
        ];
        for (a, b) in pairs {
            let (a, b) = (a.tls13().unwrap(), b.tls13().unwrap());
            let number = RecordNumber {
                epoch: 4,
                seq: 0xfffe,
            };
            let (sealed_a, ..) = seal(&keys(a), number, b"same bytes");
            let (sealed_b, seq, body) = seal(&keys(b), number, b"same bytes");
            assert_eq!(sealed_a, sealed_b);
            assert!(
                keys(a)
                    .open(&mut sealed_a.clone(), seq, body, 0xffff)
                    .is_some()
            );
        }
    }
}

#[test]
fn ccm_8_is_not_usable() {
    #[cfg(feature = "native")]
    {
        let suite = crate::crypto::native::cipher_suite::TLS13_AES_128_CCM_8_SHA256
            .tls13()
            .unwrap();
        assert!(RecordKeys::derive(suite, &secret(suite)).is_none());
    }
}

#[test]
fn limits() {
    for suite in suites() {
        let keys = keys(suite);
        assert!(keys.integrity_limit() <= MAX_INTEGRITY_LIMIT);
        assert!(keys.integrity_limit() > 0);
        assert_eq!(
            keys.confidentiality_limit(),
            suite.common.confidentiality_limit
        );
    }
}

#[test]
fn content_room_fills_the_space() {
    for suite in suites() {
        let keys = keys(suite);
        for space in [0, 10, 21, 22, 40, 1200] {
            match keys.content_room(space, 0) {
                Some(room) => {
                    assert!(keys.sealed_len(room, 0) <= space);
                    assert!(keys.sealed_len(room + 1, 0) > space);
                }
                None => assert!(keys.sealed_len(0, 0) > space || space < 5),
            }
        }
    }
}

#[test]
fn sequence_numbers_beyond_48_bits_are_refused() {
    for suite in suites() {
        let keys = keys(suite);
        let mut out = vec![1, 2, 3];
        let number = RecordNumber {
            epoch: 2,
            seq: wire::MAX_SEQ + 1,
        };
        assert!(
            keys.seal(&mut out, number, ContentType::Alert, b"x", &[])
                .is_err()
        );
        assert_eq!(out, [1, 2, 3]);
    }
}

#[test]
fn reconstruction_picks_the_closest_number() {
    // 16 bits.
    assert_eq!(reconstruct_seq(0, 0, 16), 0);
    assert_eq!(reconstruct_seq(5, 3, 16), 3);
    assert_eq!(reconstruct_seq(0xfff0, 0x0002, 16), 0x1_0002);
    assert_eq!(reconstruct_seq(0x1_0002, 0xfff0, 16), 0xfff0);
    assert_eq!(reconstruct_seq(0x1_0000, 0x8001, 16), 0x8001);
    // No number below zero: the closest is in the first window.
    assert_eq!(reconstruct_seq(1, 0xffff, 16), 0xffff);
    // 8 bits.
    assert_eq!(reconstruct_seq(0x1fe, 0x01, 8), 0x201);
    assert_eq!(reconstruct_seq(0x201, 0xfe, 8), 0x1fe);
    assert_eq!(reconstruct_seq(0x280, 0x80, 8), 0x280);
    // The result never wraps past 2^64.
    assert_eq!(reconstruct_seq(u64::MAX, 0, 16), u64::MAX - 0xffff);
}
