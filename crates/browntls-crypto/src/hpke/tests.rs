//! RFC 9180 Appendix A known-answer tests.
//!
//! `tests/data/hpke/rfc9180_base.json`, `rfc9180_psk.json` and
//! `rfc9180_auth.json` are the subsets for the base mode, the PSK mode and
//! the two authenticated modes of `test-vectors.json` from the CFRG HPKE
//! draft repository (commit `5f503c564da00b0687b3de75f1dfbdfc4079ad31`, the
//! vectors of RFC 9180 Appendix A; SHA-256 of the file `61fc662f01996cd0
//! 6d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`) for the suites this
//! crate supports, keeping encryptions 0, 1, 2 and the last one (sequence
//! number 256) of each.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use serde::Deserialize;

#[cfg(feature = "key-log")]
use super::KemSharedSecret;
use super::labeled::Secret;
use super::{Aead, Kem, Mode, PrivateKey, Psk, PublicKey, RecipientContext, Suite};
use crate::Error;

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
    #[serde(rename = "ikmS", default)]
    ikm_s: Option<String>,
    #[serde(rename = "skSm", default)]
    sk_sm: Option<String>,
    #[serde(rename = "pkSm", default)]
    pk_sm: Option<String>,
    #[serde(default)]
    psk: Option<String>,
    #[serde(default)]
    psk_id: Option<String>,
    enc: String,
    shared_secret: String,
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
        serde_json::from_str(include_str!("../../tests/data/hpke/rfc9180_base.json")).unwrap();
    assert_eq!(vectors.len(), 32);
    for v in &vectors {
        assert_eq!(v.mode, 0);
        check_vector(v);
    }
}

#[test]
fn rfc9180_psk_mode_vectors() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../../tests/data/hpke/rfc9180_psk.json")).unwrap();
    assert_eq!(vectors.len(), 32);
    for v in &vectors {
        assert_eq!(v.mode, 1);
        check_vector(v);
    }
}

#[test]
fn rfc9180_auth_mode_vectors() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../../tests/data/hpke/rfc9180_auth.json")).unwrap();
    assert_eq!(vectors.len(), 64);
    assert_eq!(vectors.iter().filter(|v| v.mode == 2).count(), 32);
    assert_eq!(vectors.iter().filter(|v| v.mode == 3).count(), 32);
    for v in &vectors {
        check_vector(v);
    }
}

/// Checks one vector: key derivation, the sender's `enc` and KEM shared
/// secret, every listed encryption in both directions, and the exports.
fn check_vector(v: &Vector) {
    let suite = Suite::from_ids(v.kem_id, v.kdf_id, v.aead_id).unwrap();
    let mode = Mode::from_id(v.mode).unwrap();
    let name = format!("{suite:?} {mode:?}");
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
    let psk_bytes = v.psk.as_deref().map(h);
    let psk_id = v.psk_id.as_deref().map(h);
    let psk = match (&psk_bytes, &psk_id) {
        (Some(k), Some(id)) => Some(Psk::new(k, id).unwrap()),
        (None, None) => None,
        _ => panic!("{name}: psk without psk_id"),
    };
    assert_eq!(psk.is_some(), mode.uses_psk(), "{name}");

    // The sender's key pair, in the authenticated modes.
    let sk_s = v
        .ikm_s
        .as_deref()
        .map(|ikm| kem.derive_key_pair(&h(ikm)).unwrap());
    assert_eq!(sk_s.is_some(), mode.uses_sender_key(), "{name}");
    let pk_s = sk_s.as_ref().map(|sk| {
        let pk_sm = h(v.pk_sm.as_deref().unwrap());
        assert_eq!(sk.public_key().as_bytes(), pk_sm, "{name} pkS");
        let sk_sm = h(v.sk_sm.as_deref().unwrap());
        assert_eq!(serialized(sk), clamp(kem, sk_sm.clone()), "{name} skS");
        let from_bytes = PrivateKey::from_bytes(kem, &sk_sm).unwrap();
        assert_eq!(from_bytes.public_key().as_bytes(), pk_sm, "{name}");
        PublicKey::from_bytes(kem, &pk_sm).unwrap()
    });

    let pk_r = PublicKey::from_bytes(kem, &h(&v.pk_rm)).unwrap();
    let mut kem_secret = Secret::zeroed(0);
    let (enc, mut sender) = suite
        .setup_sender_derandomized(
            &pk_r,
            &info,
            &h(&v.ikm_e),
            psk.as_ref(),
            sk_s.as_ref(),
            &mut kem_secret,
        )
        .unwrap();
    assert_eq!(sender.mode(), mode, "{name}");
    assert_eq!(enc.as_bytes(), h(&v.enc), "{name} enc");
    let shared_secret = h(&v.shared_secret);
    assert_eq!(shared_secret.len(), kem.shared_secret_len(), "{name}");
    assert_eq!(kem_secret.as_bytes(), shared_secret, "{name} sender");
    kem_secret.clear();
    assert!(kem_secret.as_bytes().is_empty());
    let enc = h(&v.enc);
    let mut recipient = recipient_for(suite, &enc, &sk_r2, &info, psk.as_ref(), pk_s.as_ref());
    assert_eq!(recipient.mode(), mode, "{name}");
    // The logging entry point hands out the vector's `shared_secret` and a
    // context that agrees with the ordinary one (base mode only: the key
    // log is for ECH, which uses no other mode).
    #[cfg(feature = "key-log")]
    if mode == Mode::Base {
        let mut kem_secret = KemSharedSecret::new();
        let logged = suite
            .setup_recipient_with_kem_secret(&enc, &sk_r2, &info, &mut kem_secret)
            .unwrap();
        assert_eq!(kem_secret.as_bytes(), shared_secret, "{name} recipient");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        recipient.export(b"key-log", &mut a).unwrap();
        logged.export(b"key-log", &mut b).unwrap();
        assert_eq!(a, b, "{name} contexts");
    }

    for e in &v.encryptions {
        // Advance both contexts to the vector's sequence number.
        while sender.sequence_number() < e.seq {
            let filler = sender.seal(b"", b"").unwrap();
            recipient.open(b"", &filler).unwrap();
        }
        let ct = sender.seal(&h(&e.aad), &h(&e.pt)).unwrap();
        assert_eq!(ct, h(&e.ct), "{name} seq {}", e.seq);
        let pt = recipient.open(&h(&e.aad), &ct).unwrap();
        assert_eq!(pt, h(&e.pt), "{name} seq {}", e.seq);
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

/// The public recipient setup for the mode the inputs select.
fn recipient_for(
    suite: Suite,
    enc: &[u8],
    sk_r: &PrivateKey,
    info: &[u8],
    psk: Option<&Psk<'_>>,
    pk_s: Option<&PublicKey>,
) -> RecipientContext {
    match (psk, pk_s) {
        (None, None) => suite.setup_recipient(enc, sk_r, info),
        (Some(psk), None) => suite.setup_recipient_psk(enc, sk_r, info, psk),
        (None, Some(pk_s)) => suite.setup_recipient_auth(enc, sk_r, info, pk_s),
        (Some(psk), Some(pk_s)) => suite.setup_recipient_auth_psk(enc, sk_r, info, psk, pk_s),
    }
    .unwrap()
}

/// The public logging entry points agree with each other and with the
/// ordinary ones, for every KEM: the sender's secret is the recipient's, it
/// has the KEM's `Nsecret` length, it is not what the context exports, and
/// a failed setup leaves the caller's buffer empty.
#[cfg(feature = "key-log")]
#[test]
fn kem_secret_entry_points_agree() {
    use super::Kdf;
    use crate::rand::OsRng;

    for kem in Kem::ALL {
        let suite = Suite::new(kem, Kdf::HkdfSha256, Aead::Aes128Gcm);
        let sk_r = kem.generate_key_pair(&OsRng).unwrap();
        let pk_r = sk_r.public_key();
        let info = b"key-log test";
        let mut sent = KemSharedSecret::new();
        assert!(sent.as_bytes().is_empty());
        let (enc, mut sender) = suite
            .setup_sender_with_kem_secret(pk_r, info, &OsRng, &mut sent)
            .unwrap();
        let mut received = KemSharedSecret::default();
        let mut recipient = suite
            .setup_recipient_with_kem_secret(enc.as_bytes(), &sk_r, info, &mut received)
            .unwrap();
        assert_eq!(sent.as_bytes(), received.as_bytes(), "{kem:?}");
        assert_eq!(sent.as_bytes().len(), kem.shared_secret_len(), "{kem:?}");
        assert_ne!(sent.as_bytes(), vec![0u8; kem.shared_secret_len()]);

        let ct = sender.seal(b"aad", b"plaintext").unwrap();
        assert_eq!(recipient.open(b"aad", &ct).unwrap(), b"plaintext");
        // An ordinary recipient reaches the same context from `enc`.
        let mut plain = suite.setup_recipient(enc.as_bytes(), &sk_r, info).unwrap();
        assert_eq!(plain.open(b"aad", &ct).unwrap(), b"plaintext");

        let mut exported = vec![0u8; kem.shared_secret_len()];
        sender.export(b"", &mut exported).unwrap();
        assert_ne!(sent.as_bytes(), exported, "{kem:?} exporter output");

        assert_eq!(format!("{sent:?}"), "KemSharedSecret(..)");

        // A second setup to the same key replaces the secret with another.
        let first = sent.as_bytes().to_vec();
        suite
            .setup_sender_with_kem_secret(pk_r, info, &OsRng, &mut sent)
            .unwrap();
        assert_ne!(sent.as_bytes(), first, "{kem:?}");

        // A setup that fails leaves no earlier secret behind: a key of
        // another KEM for the sender, a malformed `enc` for the recipient.
        let other = Kem::ALL.into_iter().find(|k| *k != kem).unwrap();
        let foreign = other.generate_key_pair(&OsRng).unwrap();
        assert_eq!(
            suite
                .setup_sender_with_kem_secret(foreign.public_key(), info, &OsRng, &mut sent)
                .err(),
            Some(Error::InvalidKey)
        );
        assert!(sent.as_bytes().is_empty(), "{kem:?}");
        assert!(
            suite
                .setup_recipient_with_kem_secret(&[0u8; 3], &sk_r, info, &mut received)
                .is_err()
        );
        assert!(received.as_bytes().is_empty(), "{kem:?}");
    }
}
