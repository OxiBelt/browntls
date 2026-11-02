#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_lossless
)]
//! Wycheproof vectors for P-256 / P-384 / P-521 ECDH and ECDSA.
//!
//! Files (Apache-2.0, from the C2SP/wycheproof `testvectors_v1` set):
//! `ecdh_secp{256r1,384r1,521r1}_test.json` (SPKI-encoded peer keys, including
//! compressed points, explicit curve parameters, wrong curves, invalid-curve
//! attacks and malformed ASN.1), `ecdsa_secp256r1_sha256_test.json`,
//! `ecdsa_secp384r1_sha384_test.json`, `ecdsa_secp521r1_sha512_test.json` and
//! the cross-hash `ecdsa_secp256r1_sha512_test.json`.

use browntls_crypto::hash::HashAlgorithm;
use browntls_crypto::nist::{p256, p384, p521};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/wycheproof/");
    let data = std::fs::read(format!("{path}{name}")).expect("vector file present");
    serde_json::from_slice(&data).expect("valid JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

/// Normalises a Wycheproof private key (an unsigned integer of any length) to
/// the fixed big-endian scalar encoding, or `None` when it does not fit.
fn fixed_scalar(private: &[u8], len: usize) -> Option<Vec<u8>> {
    let skip = private.iter().take_while(|&&b| b == 0).count();
    let mag = &private[skip..];
    if mag.len() > len {
        return None;
    }
    let mut out = vec![0u8; len - mag.len()];
    out.extend_from_slice(mag);
    Some(out)
}

fn sha(name: &str) -> HashAlgorithm {
    match name {
        "SHA-224" => HashAlgorithm::Sha224,
        "SHA-256" => HashAlgorithm::Sha256,
        "SHA-384" => HashAlgorithm::Sha384,
        "SHA-512" => HashAlgorithm::Sha512,
        "SHA3-256" => HashAlgorithm::Sha3_256,
        "SHA3-384" => HashAlgorithm::Sha3_384,
        "SHA3-512" => HashAlgorithm::Sha3_512,
        other => panic!("unexpected hash {other}"),
    }
}

macro_rules! wycheproof_curve {
    ($curve:ident, $ecdh_file:literal, $ecdh_test:ident, $ecdsa_test:ident, [$($ecdsa_file:literal),*]) => {
        #[test]
        fn $ecdh_test() {
            let doc = load($ecdh_file);
            assert_eq!(doc["algorithm"], "ECDH");
            let mut valid = 0usize;
            let mut invalid = 0usize;
            let mut acceptable_ok = 0usize;
            let mut acceptable_rejected = 0usize;
            for group in doc["testGroups"].as_array().unwrap() {
                assert_eq!(group["encoding"], "asn");
                for t in group["tests"].as_array().unwrap() {
                    let id = t["tcId"].as_u64().unwrap();
                    let comment = t["comment"].as_str().unwrap_or("");
                    let result = t["result"].as_str().unwrap();
                    let public = hex(&t["public"]);
                    let private = hex(&t["private"]);
                    let shared = hex(&t["shared"]);
                    let outcome = (|| -> Result<Vec<u8>, browntls_crypto::Error> {
                        let peer = $curve::PublicKey::from_spki_der(&public)?;
                        let d = fixed_scalar(&private, $curve::FIELD_LEN)
                            .ok_or(browntls_crypto::Error::InvalidKey)?;
                        let sk = $curve::SecretKey::from_bytes(&d)?;
                        Ok(sk.diffie_hellman(&peer)?.to_vec())
                    })();
                    match (result, outcome) {
                        ("valid", Ok(got)) => {
                            assert_eq!(got, shared, "tcId {id} ({comment}): wrong shared secret");
                            valid += 1;
                        }
                        ("valid", Err(e)) => panic!("tcId {id} ({comment}): rejected valid case: {e}"),
                        ("invalid", Ok(_)) => panic!("tcId {id} ({comment}): accepted invalid case"),
                        ("invalid", Err(_)) => invalid += 1,
                        ("acceptable", Ok(got)) => {
                            assert_eq!(got, shared, "tcId {id} ({comment}): wrong shared secret");
                            acceptable_ok += 1;
                        }
                        ("acceptable", Err(_)) => acceptable_rejected += 1,
                        (other, _) => panic!("tcId {id}: unknown result {other}"),
                    }
                }
            }
            assert_eq!(
                valid + invalid + acceptable_ok + acceptable_rejected,
                doc["numberOfTests"].as_u64().unwrap() as usize
            );
            assert!(valid > 100 && invalid > 0, "unexpected distribution");
            eprintln!(
                "{}: {valid} valid, {invalid} invalid, {acceptable_ok} acceptable accepted, \
                 {acceptable_rejected} acceptable rejected",
                $ecdh_file
            );
        }

        #[test]
        fn $ecdsa_test() {
            for file in [$($ecdsa_file),*] {
                let doc = load(file);
                assert_eq!(doc["algorithm"], "ECDSA");
                let mut valid = 0usize;
                let mut invalid = 0usize;
                for group in doc["testGroups"].as_array().unwrap() {
                    let hash = sha(group["sha"].as_str().unwrap());
                    let pk_bytes = hex(&group["publicKey"]["uncompressed"]);
                    let pk = $curve::PublicKey::from_sec1_bytes(&pk_bytes).expect("valid public key");
                    let pk_der = $curve::PublicKey::from_spki_der(&hex(&group["publicKeyDer"]))
                        .expect("valid SPKI");
                    assert_eq!(pk, pk_der);
                    assert_eq!(pk.to_uncompressed().as_slice(), pk_bytes.as_slice());
                    for t in group["tests"].as_array().unwrap() {
                        let id = t["tcId"].as_u64().unwrap();
                        let comment = t["comment"].as_str().unwrap_or("");
                        let msg = hex(&t["msg"]);
                        let sig = hex(&t["sig"]);
                        let ok = $curve::verify(&pk, hash, &msg, &sig).is_ok();
                        match t["result"].as_str().unwrap() {
                            "valid" => {
                                assert!(ok, "{file} tcId {id} ({comment}): rejected valid signature");
                                // The fixed form must round-trip and verify too.
                                let parsed = $curve::Signature::from_der(&sig).unwrap();
                                assert_eq!(parsed.as_der(), sig.as_slice(), "non-canonical DER accepted");
                                $curve::verify_fixed(&pk, hash, &msg, parsed.fixed()).unwrap();
                                let digest = browntls_crypto::hash::DynHash::digest(hash, &msg);
                                $curve::verify_prehashed(&pk, digest.as_ref(), &sig).unwrap();
                                valid += 1;
                            }
                            "invalid" => {
                                assert!(!ok, "{file} tcId {id} ({comment}): accepted invalid signature");
                                invalid += 1;
                            }
                            other => panic!("tcId {id}: unknown result {other}"),
                        }
                    }
                }
                assert_eq!(valid + invalid, doc["numberOfTests"].as_u64().unwrap() as usize);
                assert!(valid > 50 && invalid > 200, "unexpected distribution in {file}");
                eprintln!("{file}: {valid} valid, {invalid} invalid");
            }
        }
    };
}

wycheproof_curve!(
    p256,
    "ecdh_secp256r1_test.json",
    ecdh_p256,
    ecdsa_p256,
    [
        "ecdsa_secp256r1_sha256_test.json",
        "ecdsa_secp256r1_sha512_test.json"
    ]
);
wycheproof_curve!(
    p384,
    "ecdh_secp384r1_test.json",
    ecdh_p384,
    ecdsa_p384,
    ["ecdsa_secp384r1_sha384_test.json"]
);
wycheproof_curve!(
    p521,
    "ecdh_secp521r1_test.json",
    ecdh_p521,
    ecdsa_p521,
    ["ecdsa_secp521r1_sha512_test.json"]
);

/// Compressed points from the ECDH files must decode to the same key as their
/// uncompressed form (covers both parities on every curve).
#[test]
fn compressed_points_roundtrip() {
    macro_rules! check {
        ($curve:ident, $file:literal) => {
            let doc = load($file);
            let mut seen = 0;
            for group in doc["testGroups"].as_array().unwrap() {
                for t in group["tests"].as_array().unwrap() {
                    let flags = t["flags"].as_array().unwrap();
                    if !flags
                        .iter()
                        .any(|f| f == "CompressedPoint" || f == "CompressedPublic")
                    {
                        continue;
                    }
                    if t["result"] == "invalid" {
                        continue;
                    }
                    let spki = hex(&t["public"]);
                    let pk = $curve::PublicKey::from_spki_der(&spki).expect("compressed point");
                    let unc = pk.to_uncompressed();
                    let back = $curve::PublicKey::from_sec1_bytes(&unc).unwrap();
                    assert_eq!(pk, back);
                    // Rebuild the compressed form and decode it again.
                    let mut comp = vec![2 | (unc[unc.len() - 1] & 1)];
                    comp.extend_from_slice(&unc[1..1 + $curve::FIELD_LEN]);
                    assert_eq!($curve::PublicKey::from_sec1_bytes(&comp).unwrap(), pk);
                    seen += 1;
                }
            }
            assert!(seen > 0, "no compressed points in {}", $file);
        };
    }
    check!(p256, "ecdh_secp256r1_test.json");
    check!(p384, "ecdh_secp384r1_test.json");
    check!(p521, "ecdh_secp521r1_test.json");
}
