//! HPKE (RFC 9180) tests: behaviour on bad input and differential tests
//! against the `hpke` crate, which also cover DHKEM(P-384) and HKDF-SHA384
//! (the RFC publishes no vectors for either). The RFC's known-answer vectors
//! run as unit tests (`src/hpke/tests.rs`), since they need the
//! derandomised sender that is not public API.
#![cfg(feature = "alloc")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::hpke::{Aead, Kdf, Kem, PrivateKey, Suite};
use browntls_crypto::rand::OsRng;

#[test]
fn open_failure_does_not_advance_sequence() {
    let suite = Suite::new(Kem::DhX25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
    let sk = suite.kem.generate_key_pair(&OsRng).unwrap();
    let (enc, mut s) = suite
        .setup_sender(sk.public_key(), b"info", &OsRng)
        .unwrap();
    let mut r = suite.setup_recipient(enc.as_bytes(), &sk, b"info").unwrap();
    let mut ct = s.seal(b"aad", b"hello").unwrap();
    ct[0] ^= 1;
    assert_eq!(r.open(b"aad", &ct).err(), Some(Error::DecryptFailed));
    assert_eq!(r.sequence_number(), 0);
    ct[0] ^= 1;
    assert_eq!(r.open(b"aad", &ct).unwrap(), b"hello");
    assert_eq!(r.sequence_number(), 1);
    assert_eq!(r.open(b"aad", &[0; 15]).err(), Some(Error::DecryptFailed));
}

#[test]
fn wrong_kem_and_bad_inputs_are_rejected() {
    let suite = Suite::new(Kem::DhP256HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
    let x = Kem::DhX25519HkdfSha256.generate_key_pair(&OsRng).unwrap();
    assert_eq!(
        suite.setup_sender(x.public_key(), b"", &OsRng).err(),
        Some(Error::InvalidKey)
    );
    assert_eq!(
        suite.setup_recipient(&[4; 65], &x, b"").err(),
        Some(Error::InvalidKey)
    );
    let p = suite.kem.generate_key_pair(&OsRng).unwrap();
    // Not a point on P-256.
    assert_eq!(
        suite.setup_recipient(&[4; 65], &p, b"").err(),
        Some(Error::InvalidKey)
    );
    assert_eq!(
        suite.setup_recipient(&[4; 64], &p, b"").err(),
        Some(Error::InvalidKey)
    );
    // Scalars outside [1, n - 1].
    assert!(PrivateKey::from_bytes(Kem::DhP256HkdfSha256, &[0; 32]).is_err());
    assert!(PrivateKey::from_bytes(Kem::DhP256HkdfSha256, &[0xff; 32]).is_err());
    assert!(PrivateKey::from_bytes(Kem::DhP384HkdfSha384, &[0; 48]).is_err());
    // Export length limit: 255 * Nh.
    let (_, s) = suite.setup_sender(p.public_key(), b"", &OsRng).unwrap();
    let mut ok = vec![0u8; 255 * 32];
    s.export(b"", &mut ok).unwrap();
    let mut too_long = vec![0u8; 255 * 32 + 1];
    assert_eq!(s.export(b"", &mut too_long), Err(Error::InvalidLength));
    // DeriveKeyPair needs at least Nsk bytes of input keying material.
    assert_eq!(
        Kem::DhP256HkdfSha256.derive_key_pair(&[1; 31]).err(),
        Some(Error::InvalidLength)
    );
}

#[test]
fn identifiers_round_trip() {
    for kem in Kem::ALL {
        assert_eq!(Kem::from_id(kem.id()), Some(kem));
    }
    for kdf in Kdf::ALL {
        assert_eq!(Kdf::from_id(kdf.id()), Some(kdf));
    }
    for aead in Aead::ALL {
        assert_eq!(Aead::from_id(aead.id()), Some(aead));
    }
    assert_eq!(Kem::from_id(0x0041), None);
    assert_eq!(Kdf::from_id(0x0011), None);
    assert_eq!(Aead::from_id(0x0004), None);
}

mod differential {
    use super::*;
    use hpke::{Deserializable, OpModeR, OpModeS, Serializable};

    /// Our sender to their recipient and back, for one suite.
    fn check<A, F, K>(suite: Suite)
    where
        A: hpke::aead::Aead,
        F: hpke::kdf::Kdf,
        K: hpke::Kem,
    {
        let name = format!("{suite:?}");
        for round in 0u8..8 {
            let ikm: Vec<u8> = (0..suite.kem.private_key_len())
                .map(|i| (i as u8).wrapping_mul(31) ^ round)
                .collect();
            let info = [b"browntls hpke ".as_slice(), &[round]].concat();
            let aad = [round; 7];
            let msg = vec![round ^ 0x5a; 64 + usize::from(round)];

            // Key derivation agrees.
            let ours = suite.kem.derive_key_pair(&ikm).unwrap();
            let (their_sk, their_pk) = K::derive_keypair(&ikm);
            assert_eq!(
                ours.public_key().as_bytes(),
                &their_pk.to_bytes()[..],
                "{name}"
            );

            // Ours -> theirs.
            let (enc, mut s) = suite
                .setup_sender(ours.public_key(), &info, &OsRng)
                .unwrap();
            let their_enc = K::EncappedKey::from_bytes(enc.as_bytes()).unwrap();
            let mut r =
                hpke::setup_receiver::<A, F, K>(&OpModeR::Base, &their_sk, &their_enc, &info)
                    .unwrap();
            let mut a = [0u8; 40];
            let mut b = [0u8; 40];
            s.export(b"ctx", &mut a).unwrap();
            r.export(b"ctx", &mut b).unwrap();
            assert_eq!(a, b, "{name} export");
            if suite.aead != Aead::ExportOnly {
                for _ in 0..3 {
                    let ct = s.seal(&aad, &msg).unwrap();
                    assert_eq!(r.open(&ct, &aad).unwrap(), msg, "{name}");
                }
            }

            // Theirs -> ours.
            let (their_enc, mut s) =
                hpke::setup_sender::<A, F, K>(&OpModeS::Base, &their_pk, &info).unwrap();
            let mut r = suite
                .setup_recipient(&their_enc.to_bytes(), &ours, &info)
                .unwrap();
            s.export(b"ctx", &mut a).unwrap();
            r.export(b"ctx", &mut b).unwrap();
            assert_eq!(a, b, "{name} export");
            if suite.aead != Aead::ExportOnly {
                for _ in 0..3 {
                    let ct = s.seal(&msg, &aad).unwrap();
                    assert_eq!(r.open(&aad, &ct).unwrap(), msg, "{name}");
                }
            }
        }
    }

    macro_rules! for_aeads {
        ($kem:ident, $their_kem:ty, $kdf:ident, $their_kdf:ty) => {
            check::<hpke::aead::AesGcm128, $their_kdf, $their_kem>(Suite::new(
                Kem::$kem,
                Kdf::$kdf,
                Aead::Aes128Gcm,
            ));
            check::<hpke::aead::AesGcm256, $their_kdf, $their_kem>(Suite::new(
                Kem::$kem,
                Kdf::$kdf,
                Aead::Aes256Gcm,
            ));
            check::<hpke::aead::ChaCha20Poly1305, $their_kdf, $their_kem>(Suite::new(
                Kem::$kem,
                Kdf::$kdf,
                Aead::ChaCha20Poly1305,
            ));
            check::<hpke::aead::ExportOnlyAead, $their_kdf, $their_kem>(Suite::new(
                Kem::$kem,
                Kdf::$kdf,
                Aead::ExportOnly,
            ));
        };
    }

    macro_rules! for_kdfs {
        ($kem:ident, $their_kem:ty) => {
            for_aeads!($kem, $their_kem, HkdfSha256, hpke::kdf::HkdfSha256);
            for_aeads!($kem, $their_kem, HkdfSha384, hpke::kdf::HkdfSha384);
            for_aeads!($kem, $their_kem, HkdfSha512, hpke::kdf::HkdfSha512);
        };
    }

    #[test]
    fn x25519() {
        for_kdfs!(DhX25519HkdfSha256, hpke::kem::X25519HkdfSha256);
    }

    #[test]
    fn p256() {
        for_kdfs!(DhP256HkdfSha256, hpke::kem::DhP256HkdfSha256);
    }

    #[test]
    fn p384() {
        for_kdfs!(DhP384HkdfSha384, hpke::kem::DhP384HkdfSha384);
    }

    #[test]
    fn p521() {
        for_kdfs!(DhP521HkdfSha512, hpke::kem::DhP521HkdfSha512);
    }
}
