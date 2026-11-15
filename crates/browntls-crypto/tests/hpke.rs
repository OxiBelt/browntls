//! HPKE (RFC 9180) tests: the RFC's base-mode test vectors and differential
//! tests against the `hpke` crate, which also cover DHKEM(P-384) and
//! HKDF-SHA384 (the RFC publishes no vectors for either).
//!
//! `data/hpke/rfc9180_base.json` is the base-mode subset of `test-vectors.json`
//! from the CFRG HPKE draft repository (commit
//! `5f503c564da00b0687b3de75f1dfbdfc4079ad31`, the vectors of RFC 9180
//! Appendix A) for the suites this crate supports, keeping encryptions 0, 1, 2
//! and the last one (sequence number 256) of each.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::hpke::{Aead, Kdf, Kem, PrivateKey, PublicKey, Suite};
use browntls_crypto::rand::OsRng;
use serde::Deserialize;

#[derive(Deserialize)]
struct Encryption {
    seq: u64,
    aad: String,
    pt: String,
    ct: String,
}

#[derive(Deserialize)]
struct Export {
    exporter_context: String,
    #[serde(rename = "L")]
    len: usize,
    exported_value: String,
}

#[derive(Deserialize)]
struct Vector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename = "ikmR")]
    ikm_r: String,
    #[serde(rename = "ikmE")]
    ikm_e: String,
    #[serde(rename = "skRm")]
    sk_rm: String,
    #[serde(rename = "skEm")]
    sk_em: String,
    #[serde(rename = "pkRm")]
    pk_rm: String,
    #[serde(rename = "pkEm")]
    pk_em: String,
    enc: String,
    encryptions: Vec<Encryption>,
    exports: Vec<Export>,
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// The serialized private key, compared after the clamping that RFC 9180
/// §7.1.2 requires of `SerializePrivateKey` for X25519 and X448.
fn serialized(sk: &PrivateKey) -> Vec<u8> {
    let mut out = vec![0u8; 66];
    let n = sk.write_bytes(&mut out).unwrap();
    out.truncate(n);
    out
}

fn clamp(kem: Kem, mut k: Vec<u8>) -> Vec<u8> {
    match kem {
        Kem::DhX25519HkdfSha256 => {
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;
        }
        Kem::DhX448HkdfSha512 => {
            k[0] &= 252;
            k[55] |= 128;
        }
        _ => {}
    }
    k
}

#[test]
fn rfc9180_base_mode_vectors() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("data/hpke/rfc9180_base.json")).unwrap();
    assert_eq!(vectors.len(), 32);
    for v in vectors {
        assert_eq!(v.mode, 0);
        let suite = Suite::from_ids(v.kem_id, v.kdf_id, v.aead_id).unwrap();
        let name = format!("{suite:?}");
        let kem = suite.kem;

        // DeriveKeyPair for both key pairs.
        let sk_r = kem.derive_key_pair(&h(&v.ikm_r)).unwrap();
        assert_eq!(sk_r.public_key().as_bytes(), h(&v.pk_rm), "{name} pkR");
        assert_eq!(serialized(&sk_r), clamp(kem, h(&v.sk_rm)), "{name} skR");
        let sk_e = kem.derive_key_pair(&h(&v.ikm_e)).unwrap();
        assert_eq!(sk_e.public_key().as_bytes(), h(&v.pk_em), "{name} pkE");
        assert_eq!(serialized(&sk_e), clamp(kem, h(&v.sk_em)), "{name} skE");

        // DeserializePrivateKey agrees with DeriveKeyPair.
        let sk_r2 = PrivateKey::from_bytes(kem, &h(&v.sk_rm)).unwrap();
        assert_eq!(sk_r2.public_key().as_bytes(), h(&v.pk_rm), "{name}");

        let info = h(&v.info);
        let pk_r = PublicKey::from_bytes(kem, &h(&v.pk_rm)).unwrap();
        let (enc, mut sender) = suite
            .setup_sender_derandomized(&pk_r, &info, &h(&v.ikm_e))
            .unwrap();
        assert_eq!(enc.as_bytes(), h(&v.enc), "{name} enc");
        let mut recipient = suite.setup_recipient(&h(&v.enc), &sk_r2, &info).unwrap();

        for e in &v.encryptions {
            // Advance the sender to the vector's sequence number.
            while sender.sequence_number() < e.seq {
                sender.seal(b"", b"").unwrap();
            }
            let ct = sender.seal(&h(&e.aad), &h(&e.pt)).unwrap();
            assert_eq!(ct, h(&e.ct), "{name} seq {}", e.seq);
            if recipient.sequence_number() == e.seq {
                let pt = recipient.open(&h(&e.aad), &ct).unwrap();
                assert_eq!(pt, h(&e.pt), "{name} seq {}", e.seq);
            }
        }
        if suite.aead == Aead::ExportOnly {
            assert_eq!(sender.seal(b"", b"x").err(), Some(Error::Unsupported));
            assert_eq!(
                recipient.open(b"", &[0; 16]).err(),
                Some(Error::Unsupported)
            );
        }

        for x in &v.exports {
            let mut a = vec![0u8; x.len];
            let mut b = vec![0u8; x.len];
            sender.export(&h(&x.exporter_context), &mut a).unwrap();
            recipient.export(&h(&x.exporter_context), &mut b).unwrap();
            assert_eq!(a, h(&x.exported_value), "{name} export");
            assert_eq!(b, a, "{name} export");
        }
    }
}

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
