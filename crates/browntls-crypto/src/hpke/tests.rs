//! RFC 9180 Appendix A base-mode known-answer tests.
//!
//! `tests/data/hpke/rfc9180_base.json` is the base-mode subset of
//! `test-vectors.json` from the CFRG HPKE draft repository (commit
//! `5f503c564da00b0687b3de75f1dfbdfc4079ad31`, the vectors of RFC 9180
//! Appendix A) for the suites this crate supports, keeping encryptions 0, 1, 2
//! and the last one (sequence number 256) of each.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use serde::Deserialize;

use super::{Aead, Kem, PrivateKey, PublicKey, Suite};
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
        serde_json::from_str(include_str!("../../tests/data/hpke/rfc9180_base.json")).unwrap();
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
}
