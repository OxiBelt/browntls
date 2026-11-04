//! Differential tests of the native provider's record protection, hashes and
//! key derivation against the RustCrypto provider.
//!
//! AEADs are deterministic, so for the same key, IV, sequence number and
//! plaintext both providers must produce byte-identical records; each must
//! also decrypt the other's records and reject tampered ones.

#![cfg(all(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, OutboundChunks,
    OutboundPlainMessage,
};
use browntls::crypto::{native, rustcrypto};
use browntls::{ContentType, Error, ProtocolVersion, SupportedCipherSuite};

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    native::SECURE_RANDOM.fill(&mut out).unwrap();
    out
}

fn random_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    native::SECURE_RANDOM.fill(&mut out).unwrap();
    out
}

/// Each native suite with the RustCrypto suite of the same code point. The
/// RustCrypto provider implements every native suite except the AES-CCM
/// ones, whose primitive is compared with the RustCrypto `ccm` crate in
/// `browntls-crypto`'s tests instead.
fn suite_pairs() -> Vec<(SupportedCipherSuite, SupportedCipherSuite)> {
    let pairs: Vec<_> = native::ALL_CIPHER_SUITES
        .iter()
        .filter_map(|n| {
            let r = rustcrypto::ALL_CIPHER_SUITES
                .iter()
                .find(|r| r.suite() == n.suite());
            if r.is_none() {
                assert!(
                    matches!(
                        n.suite(),
                        browntls::CipherSuite::TLS13_AES_128_CCM_SHA256
                            | browntls::CipherSuite::TLS13_AES_128_CCM_8_SHA256
                    ),
                    "RustCrypto lacks {n:?}"
                );
            }
            Some((*n, *r?))
        })
        .collect();
    assert_eq!(pairs.len(), if cfg!(feature = "tls12") { 9 } else { 3 });
    pairs
}

/// Plaintext lengths covering empty, sub-block, block-boundary and maximal
/// records.
const LENGTHS: &[usize] = &[0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 1000, 4097, 16384];

fn encrypt(
    enc: &mut dyn MessageEncrypter,
    typ: ContentType,
    version: ProtocolVersion,
    payload: &[u8],
    seq: u64,
) -> Vec<u8> {
    let msg = OutboundPlainMessage {
        typ,
        version,
        payload: OutboundChunks::Single(payload),
    };
    let expected_len = enc.encrypted_payload_len(payload.len());
    let wire = enc.encrypt(msg, seq).unwrap().encode();
    assert_eq!(wire.len(), 5 + expected_len);
    wire
}

/// Decrypts a whole record (header included); returns the content type and
/// plaintext.
fn decrypt(
    dec: &mut dyn MessageDecrypter,
    wire: &[u8],
    seq: u64,
) -> Result<(ContentType, Vec<u8>), Error> {
    let mut buf = wire.to_vec();
    let typ = ContentType::from(buf[0]);
    let version = ProtocolVersion::from(u16::from_be_bytes([buf[1], buf[2]]));
    let msg = InboundOpaqueMessage::new(typ, version, &mut buf[5..]);
    dec.decrypt(msg, seq)
        .map(|plain| (plain.typ, plain.payload.to_vec()))
}

#[test]
fn tls13_records_are_identical_and_interoperate() {
    for (n, r) in suite_pairs() {
        let (Some(n), Some(r)) = (n.tls13(), r.tls13()) else {
            continue;
        };
        let name = n.common.suite;
        let (n, r) = (n.aead_alg, r.aead_alg);
        assert_eq!(n.key_len(), r.key_len());
        let key: [u8; 32] = random();
        let iv: [u8; 12] = random();
        let k = || AeadKey::from(key).with_length_for_test(n.key_len());

        let mut n_enc = n.encrypter(k(), Iv::new(iv));
        let mut r_enc = r.encrypter(k(), Iv::new(iv));
        let mut n_dec = n.decrypter(k(), Iv::new(iv));
        let mut r_dec = r.decrypter(k(), Iv::new(iv));

        for (i, len) in LENGTHS.iter().enumerate() {
            let seq = [0, 1, 2, 0xff, 0x1_0000_0000, u64::MAX - 1][i % 6].wrapping_add(i as u64);
            let typ = [
                ContentType::Handshake,
                ContentType::ApplicationData,
                ContentType::Alert,
            ][i % 3];
            let payload = random_vec(*len);
            let a = encrypt(&mut *n_enc, typ, ProtocolVersion::TLSv1_3, &payload, seq);
            let b = encrypt(&mut *r_enc, typ, ProtocolVersion::TLSv1_3, &payload, seq);
            assert_eq!(a, b, "{name:?} record differs for length {len}");
            if typ == ContentType::ApplicationData || !payload.is_empty() {
                assert_eq!(
                    decrypt(&mut *r_dec, &a, seq).unwrap(),
                    (typ, payload.clone())
                );
                assert_eq!(decrypt(&mut *n_dec, &b, seq).unwrap(), (typ, payload));
            }
        }
    }
}

#[test]
fn tls13_rejects_tampering_across_providers() {
    for (n, r) in suite_pairs() {
        let (Some(n), Some(r)) = (n.tls13(), r.tls13()) else {
            continue;
        };
        let (n, r) = (n.aead_alg, r.aead_alg);
        let key = AeadKey::from(random::<32>());
        let key_bytes: [u8; 32] = key.as_ref().try_into().unwrap();
        let iv: [u8; 12] = random();
        let k = || AeadKey::from(key_bytes).with_length_for_test(n.key_len());
        for (enc_alg, dec_alg) in [(n, r), (r, n)] {
            let mut enc = enc_alg.encrypter(k(), Iv::new(iv));
            let mut dec = dec_alg.decrypter(k(), Iv::new(iv));
            let wire = encrypt(
                &mut *enc,
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_3,
                b"attack at dawn",
                9,
            );
            for i in 5..wire.len() {
                let mut t = wire.clone();
                t[i] ^= 1 << (i % 8);
                assert_eq!(decrypt(&mut *dec, &t, 9).unwrap_err(), Error::DecryptError);
            }
            assert_eq!(
                decrypt(&mut *dec, &wire, 10).unwrap_err(),
                Error::DecryptError
            );
            assert_eq!(
                decrypt(&mut *dec, &wire[..wire.len() - 1], 9).unwrap_err(),
                Error::DecryptError
            );
            // A different key fails.
            let mut other = dec_alg.decrypter(
                AeadKey::from(random::<32>()).with_length_for_test(n.key_len()),
                Iv::new(iv),
            );
            assert_eq!(
                decrypt(&mut *other, &wire, 9).unwrap_err(),
                Error::DecryptError
            );
            assert_eq!(decrypt(&mut *dec, &wire, 9).unwrap().1, b"attack at dawn");
        }
    }
}

#[test]
fn tls13_extracted_keys_match() {
    for (n, r) in suite_pairs() {
        let (Some(n), Some(r)) = (n.tls13(), r.tls13()) else {
            continue;
        };
        let key: [u8; 32] = random();
        let iv: [u8; 12] = random();
        let len = n.aead_alg.key_len();
        let a = n
            .aead_alg
            .extract_keys(AeadKey::from(key).with_length_for_test(len), Iv::new(iv))
            .unwrap();
        let b = r
            .aead_alg
            .extract_keys(AeadKey::from(key).with_length_for_test(len), Iv::new(iv))
            .unwrap();
        assert_eq!(secrets(&a), secrets(&b));
        assert_eq!(secrets(&a).1, &key[..len]);
    }
}

fn secrets(s: &browntls::ConnectionTrafficSecrets) -> (&'static str, &[u8], &[u8]) {
    use browntls::ConnectionTrafficSecrets::*;
    match s {
        Aes128Gcm { key, iv } => ("aes128gcm", key.as_ref(), iv.as_ref()),
        Aes256Gcm { key, iv } => ("aes256gcm", key.as_ref(), iv.as_ref()),
        Chacha20Poly1305 { key, iv } => ("chacha20poly1305", key.as_ref(), iv.as_ref()),
        _ => panic!("unexpected variant"),
    }
}

#[cfg(feature = "tls12")]
mod tls12 {
    use super::*;
    use browntls::Tls12CipherSuite;
    use browntls::crypto::SupportedKxGroup;

    fn pairs() -> Vec<(&'static Tls12CipherSuite, &'static Tls12CipherSuite)> {
        suite_pairs()
            .into_iter()
            .filter_map(|(n, r)| match (n, r) {
                (SupportedCipherSuite::Tls12(n), SupportedCipherSuite::Tls12(r)) => Some((n, r)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn records_are_identical_and_interoperate() {
        let pairs = pairs();
        assert_eq!(pairs.len(), 6);
        for (n, r) in pairs {
            let (n, r) = (n.aead_alg, r.aead_alg);
            let shape = n.key_block_shape();
            let r_shape = r.key_block_shape();
            assert_eq!(
                (
                    shape.enc_key_len,
                    shape.fixed_iv_len,
                    shape.explicit_nonce_len
                ),
                (
                    r_shape.enc_key_len,
                    r_shape.fixed_iv_len,
                    r_shape.explicit_nonce_len
                )
            );
            let key: [u8; 32] = random();
            let k = || AeadKey::from(key).with_length_for_test(shape.enc_key_len);
            let iv = random_vec(shape.fixed_iv_len);
            let extra = random_vec(shape.explicit_nonce_len);

            let mut n_enc = n.encrypter(k(), &iv, &extra);
            let mut r_enc = r.encrypter(k(), &iv, &extra);
            let mut n_dec = n.decrypter(k(), &iv);
            let mut r_dec = r.decrypter(k(), &iv);

            for (i, len) in LENGTHS.iter().enumerate() {
                let seq = [0, 1, 7, 0xffff_ffff, u64::MAX - 20][i % 5].wrapping_add(i as u64);
                let typ = [ContentType::Handshake, ContentType::ApplicationData][i % 2];
                let payload = random_vec(*len);
                let a = encrypt(&mut *n_enc, typ, ProtocolVersion::TLSv1_2, &payload, seq);
                let b = encrypt(&mut *r_enc, typ, ProtocolVersion::TLSv1_2, &payload, seq);
                assert_eq!(a, b, "record differs for length {len}");
                assert_eq!(a[0], u8::from(typ));
                assert_eq!(
                    decrypt(&mut *r_dec, &a, seq).unwrap(),
                    (typ, payload.clone())
                );
                assert_eq!(decrypt(&mut *n_dec, &b, seq).unwrap(), (typ, payload));
            }
        }
    }

    #[test]
    fn rejects_tampering_across_providers() {
        for (n, r) in pairs() {
            let (n, r) = (n.aead_alg, r.aead_alg);
            let shape = n.key_block_shape();
            let key: [u8; 32] = random();
            let k = || AeadKey::from(key).with_length_for_test(shape.enc_key_len);
            let iv = random_vec(shape.fixed_iv_len);
            let extra = random_vec(shape.explicit_nonce_len);
            for (enc_alg, dec_alg) in [(n, r), (r, n)] {
                let mut enc = enc_alg.encrypter(k(), &iv, &extra);
                let mut dec = dec_alg.decrypter(k(), &iv);
                let wire = encrypt(
                    &mut *enc,
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    b"attack at dawn",
                    3,
                );
                for i in 0..wire.len() {
                    // Header bytes 3..5 (length) are not covered by the AAD
                    // directly; the decrypter derives the length from the body.
                    if (3..5).contains(&i) {
                        continue;
                    }
                    let mut t = wire.clone();
                    t[i] ^= 0x10;
                    // Bytes 0..3 change the content type / version in the AAD.
                    let result = decrypt(&mut *dec, &t, 3);
                    assert!(result.is_err(), "tampered byte {i} accepted");
                }
                assert!(decrypt(&mut *dec, &wire, 4).is_err());
                assert!(decrypt(&mut *dec, &wire[..wire.len() - 1], 3).is_err());
                assert!(decrypt(&mut *dec, &wire[..5 + shape.explicit_nonce_len], 3).is_err());
                assert_eq!(decrypt(&mut *dec, &wire, 3).unwrap().1, b"attack at dawn");
            }
        }
    }

    #[test]
    fn extracted_keys_match() {
        for (n, r) in pairs() {
            let shape = n.aead_alg.key_block_shape();
            let key: [u8; 32] = random();
            let iv = random_vec(shape.fixed_iv_len);
            let explicit = random_vec(shape.explicit_nonce_len);
            let k = || AeadKey::from(key).with_length_for_test(shape.enc_key_len);
            let a = n.aead_alg.extract_keys(k(), &iv, &explicit).unwrap();
            let b = r.aead_alg.extract_keys(k(), &iv, &explicit).unwrap();
            assert_eq!(secrets(&a), secrets(&b));
            let mut full_iv = iv.clone();
            full_iv.extend_from_slice(&explicit);
            assert_eq!(secrets(&a).2, &full_iv[..]);
        }
    }

    #[test]
    fn prf_outputs_match() {
        for (n, r) in pairs() {
            for len in [0, 1, 12, 32, 48, 104, 136, 200] {
                let secret = random_vec(48);
                let seed = random_vec(64);
                let mut a = vec![0u8; len];
                let mut b = vec![0u8; len];
                n.prf_provider
                    .for_secret(&mut a, &secret, b"key expansion", &seed);
                r.prf_provider
                    .for_secret(&mut b, &secret, b"key expansion", &seed);
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn prf_for_key_exchange_agrees_across_providers() {
        let groups: [(&dyn SupportedKxGroup, &dyn SupportedKxGroup); 4] = [
            (native::kx_group::X25519, rustcrypto::kx_group::X25519),
            (native::kx_group::SECP256R1, rustcrypto::kx_group::SECP256R1),
            (native::kx_group::SECP384R1, rustcrypto::kx_group::SECP384R1),
            (native::kx_group::SECP521R1, rustcrypto::kx_group::SECP521R1),
        ];
        for (n, r) in pairs() {
            for (ng, rg) in groups {
                let seed = random_vec(64);
                let client = ng.start().unwrap();
                let server = rg.start().unwrap();
                let client_pub = client.pub_key().to_vec();
                let server_pub = server.pub_key().to_vec();
                let mut a = [0u8; 48];
                let mut b = [0u8; 48];
                n.prf_provider
                    .for_key_exchange(&mut a, client, &server_pub, b"master secret", &seed)
                    .unwrap();
                r.prf_provider
                    .for_key_exchange(&mut b, server, &client_pub, b"master secret", &seed)
                    .unwrap();
                assert_eq!(a, b);
                // An invalid peer share is reported, not panicked on.
                let client = ng.start().unwrap();
                let mut out = [0u8; 48];
                assert!(
                    n.prf_provider
                        .for_key_exchange(&mut out, client, &[0u8; 3], b"master secret", &seed)
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn hashes_match() {
    for (n, r) in suite_pairs() {
        let (n, r) = (
            n.tls13().map(|s| s.common.hash_provider),
            r.tls13().map(|s| s.common.hash_provider),
        );
        let (Some(n), Some(r)) = (n, r) else { continue };
        assert_eq!(n.algorithm(), r.algorithm());
        assert_eq!(n.output_len(), r.output_len());
        for len in [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 1000] {
            let data = random_vec(len);
            assert_eq!(n.hash(&data).as_ref(), r.hash(&data).as_ref());
            let mut nc = n.start();
            let mut rc = r.start();
            for chunk in data.chunks(7) {
                nc.update(chunk);
                rc.update(chunk);
                assert_eq!(nc.fork_finish().as_ref(), rc.fork_finish().as_ref());
            }
            let forked = nc.fork();
            assert_eq!(forked.finish().as_ref(), r.hash(&data).as_ref());
            assert_eq!(nc.finish().as_ref(), rc.finish().as_ref());
        }
    }
    assert_eq!(native::hash::SHA512.hash(b"abc").as_ref().len(), 64);
}

#[test]
fn hkdf_outputs_match() {
    for (n, r) in suite_pairs() {
        let (Some(n), Some(r)) = (n.tls13(), r.tls13()) else {
            continue;
        };
        let (n, r) = (n.hkdf_provider, r.hkdf_provider);
        let salt = random_vec(48);
        let secret = random_vec(48);
        let info: [&[u8]; 3] = [b"\x00\x20", b"\x0dtls13 derived", b"\x20"];

        let pairs = [
            (n.extract_from_zero_ikm(None), r.extract_from_zero_ikm(None)),
            (
                n.extract_from_zero_ikm(Some(&salt)),
                r.extract_from_zero_ikm(Some(&salt)),
            ),
            (
                n.extract_from_secret(Some(&salt), &secret),
                r.extract_from_secret(Some(&salt), &secret),
            ),
            (
                n.extract_from_secret(None, &secret),
                r.extract_from_secret(None, &secret),
            ),
            (
                n.extract_from_secret(Some(&[]), &[]),
                r.extract_from_secret(Some(&[]), &[]),
            ),
        ];
        for (a, b) in pairs {
            assert_eq!(a.hash_len(), b.hash_len());
            let block_a = a.expand_block(&info);
            let block_b = b.expand_block(&info);
            assert_eq!(block_a.as_ref(), block_b.as_ref());
            for len in [0, 12, 16, 32, 33, 48, 64, 100, 255 * a.hash_len()] {
                let mut x = vec![0u8; len];
                let mut y = vec![0u8; len];
                a.expand_slice(&info, &mut x).unwrap();
                b.expand_slice(&info, &mut y).unwrap();
                assert_eq!(x, y);
            }
            let mut too_long = vec![0u8; 255 * a.hash_len() + 1];
            assert!(a.expand_slice(&info, &mut too_long).is_err());
            assert!(b.expand_slice(&info, &mut too_long).is_err());

            let c = n.expander_for_okm(&block_a);
            let d = r.expander_for_okm(&block_b);
            assert_eq!(
                c.expand_block(&[b"x"]).as_ref(),
                d.expand_block(&[b"x"]).as_ref()
            );
            assert_eq!(
                n.hmac_sign(&block_a, b"transcript").as_ref(),
                r.hmac_sign(&block_b, b"transcript").as_ref()
            );
        }
    }
}

#[test]
fn hkdf_kx_extract_agrees_across_providers() {
    let n = native::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .hkdf_provider;
    let r = rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .hkdf_provider;
    let client = native::kx_group::X25519MLKEM768.start().unwrap();
    let server = rustcrypto::kx_group::X25519MLKEM768
        .start_and_complete(client.pub_key())
        .unwrap();
    let salt = random_vec(32);
    let a = n
        .extract_from_kx_shared_secret(Some(&salt), client, &server.pub_key)
        .unwrap();
    let b = r.extract_from_secret(Some(&salt), server.secret.secret_bytes());
    assert_eq!(
        a.expand_block(&[b"k"]).as_ref(),
        b.expand_block(&[b"k"]).as_ref()
    );
}

/// `AeadKey::with_length` is crate-private; rebuild a truncated key instead.
trait WithLength {
    fn with_length_for_test(self, len: usize) -> AeadKey;
}

impl WithLength for AeadKey {
    fn with_length_for_test(self, len: usize) -> AeadKey {
        AeadKey::new(&self.as_ref()[..len])
    }
}
