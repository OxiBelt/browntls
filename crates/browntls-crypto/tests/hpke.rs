//! HPKE (RFC 9180) tests: behaviour on bad input and differential tests
//! against the `hpke` crate in base and PSK modes, which also cover
//! DHKEM(P-384) and HKDF-SHA384 (the RFC publishes no vectors for either).
//! The RFC's known-answer vectors run as unit tests (`src/hpke/tests.rs`),
//! since they need the derandomised sender that is not public API.
#![cfg(feature = "alloc")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::hpke::{Aead, Kdf, Kem, MIN_PSK_LEN, Mode, PrivateKey, Psk, Suite};
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

#[test]
fn psk_inputs_are_checked() {
    let key = [7u8; MIN_PSK_LEN];
    assert_eq!(
        Psk::new(&key[..MIN_PSK_LEN - 1], b"id").err(),
        Some(Error::InvalidLength)
    );
    assert_eq!(Psk::new(&key, b"").err(), Some(Error::InvalidLength));
    assert_eq!(Psk::new(b"", b"").err(), Some(Error::InvalidLength));
    let psk = Psk::new(&key, b"id").unwrap();
    assert_eq!(psk.id(), b"id");
    // Neither the key nor the identifier shows up in the debug form.
    assert_eq!(format!("{psk:?}"), "Psk(..)");
    assert_eq!(Mode::from_id(0x00), Some(Mode::Base));
    assert_eq!(Mode::from_id(0x01), Some(Mode::Psk));
    assert_eq!(Mode::from_id(0x04), None);
    for mode in Mode::ALL {
        assert_eq!(Mode::from_id(mode.id()), Some(mode));
    }
}

/// A PSK context opens only what a sender with the same key, identifier
/// and mode sealed; a mismatch is found at the first `open`, never at
/// setup, and costs no sequence number.
#[test]
fn psk_mismatches_fail_to_open() {
    let suite = Suite::new(Kem::DhX25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
    let sk = suite.kem.generate_key_pair(&OsRng).unwrap();
    let key = [0x42u8; 32];
    let other_key = [0x43u8; 32];
    let psk = Psk::new(&key, b"alice").unwrap();
    let (enc, mut s) = suite
        .setup_sender_psk(sk.public_key(), b"info", &psk, &OsRng)
        .unwrap();
    assert_eq!(s.mode(), Mode::Psk);
    let ct = s.seal(b"aad", b"hello").unwrap();
    let wrong = [
        Psk::new(&other_key, b"alice").unwrap(),
        Psk::new(&key, b"bob").unwrap(),
    ];
    for bad in &wrong {
        let mut r = suite
            .setup_recipient_psk(enc.as_bytes(), &sk, b"info", bad)
            .unwrap();
        assert_eq!(r.open(b"aad", &ct).err(), Some(Error::DecryptFailed));
        assert_eq!(r.sequence_number(), 0);
    }
    // A base-mode recipient of a PSK-mode message, and the reverse.
    let mut base = suite.setup_recipient(enc.as_bytes(), &sk, b"info").unwrap();
    assert_eq!(base.open(b"aad", &ct).err(), Some(Error::DecryptFailed));
    let (enc_b, mut sb) = suite
        .setup_sender(sk.public_key(), b"info", &OsRng)
        .unwrap();
    let ct_b = sb.seal(b"aad", b"hello").unwrap();
    let mut r = suite
        .setup_recipient_psk(enc_b.as_bytes(), &sk, b"info", &psk)
        .unwrap();
    assert_eq!(r.open(b"aad", &ct_b).err(), Some(Error::DecryptFailed));
    // Exports differ too.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    sb.export(b"", &mut a).unwrap();
    r.export(b"", &mut b).unwrap();
    assert_ne!(a, b);
    // The right key opens it.
    let mut r = suite
        .setup_recipient_psk(enc.as_bytes(), &sk, b"info", &psk)
        .unwrap();
    assert_eq!(r.open(b"aad", &ct).unwrap(), b"hello");
    // Key and suite checks are those of base mode.
    let p = Kem::DhP256HkdfSha256.generate_key_pair(&OsRng).unwrap();
    assert_eq!(
        suite
            .setup_sender_psk(p.public_key(), b"", &psk, &OsRng)
            .err(),
        Some(Error::InvalidKey)
    );
    assert_eq!(
        suite.setup_recipient_psk(&[0; 32], &p, b"", &psk).err(),
        Some(Error::InvalidKey)
    );
}

mod differential {
    use super::*;
    use hpke::{Deserializable, OpModeR, OpModeS, Serializable};

    /// The modes checked against the oracle.
    const MODES: [Mode; 2] = [Mode::Base, Mode::Psk];

    /// Our sender to their recipient and back, for one suite, in every mode.
    fn check<A, F, K>(suite: Suite)
    where
        A: hpke::aead::Aead,
        F: hpke::kdf::Kdf,
        K: hpke::Kem,
    {
        for mode in MODES {
            check_mode::<A, F, K>(suite, mode);
        }
    }

    fn check_mode<A, F, K>(suite: Suite, mode: Mode)
    where
        A: hpke::aead::Aead,
        F: hpke::kdf::Kdf,
        K: hpke::Kem,
    {
        let name = format!("{suite:?} {mode:?}");
        for round in 0u8..8 {
            // A PSK of 32 to 39 bytes and an identifier per round.
            let psk_key: Vec<u8> = (0..32 + round).map(|i| i ^ 0xa5 ^ round).collect();
            let psk_id = [b"browntls psk ".as_slice(), &[round]].concat();
            let psk = Psk::new(&psk_key, &psk_id).unwrap();
            let bundle = hpke::PskBundle::new(&psk_key, &psk_id).unwrap();
            let (their_mode_r, their_mode_s) = match mode {
                Mode::Base => (OpModeR::Base, OpModeS::Base),
                Mode::Psk => (OpModeR::Psk(bundle), OpModeS::Psk(bundle)),
                _ => unreachable!(),
            };
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
            let (enc, mut s) = match mode {
                Mode::Base => suite.setup_sender(ours.public_key(), &info, &OsRng),
                _ => suite.setup_sender_psk(ours.public_key(), &info, &psk, &OsRng),
            }
            .unwrap();
            assert_eq!(s.mode(), mode, "{name}");
            let their_enc = K::EncappedKey::from_bytes(enc.as_bytes()).unwrap();
            let mut r =
                hpke::setup_receiver::<A, F, K>(&their_mode_r, &their_sk, &their_enc, &info)
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
                hpke::setup_sender::<A, F, K>(&their_mode_s, &their_pk, &info).unwrap();
            let their_enc = their_enc.to_bytes();
            let mut r = match mode {
                Mode::Base => suite.setup_recipient(&their_enc, &ours, &info),
                _ => suite.setup_recipient_psk(&their_enc, &ours, &info, &psk),
            }
            .unwrap();
            assert_eq!(r.mode(), mode, "{name}");
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
