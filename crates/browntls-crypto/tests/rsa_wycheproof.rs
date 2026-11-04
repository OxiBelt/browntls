//! Wycheproof RSASSA-PKCS1-v1_5 and RSASSA-PSS verification vectors.
//!
//! Files live in `tests/data/wycheproof/` (Apache-2.0, from the C2SP
//! `testvectors_v1` directory).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Acceleration, Algorithm, Policy};
use browntls_crypto::hash::HashAlgorithm;
use browntls_crypto::rsa::{RsaPublicKey, verify_pkcs1v15, verify_pss};
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    algorithm: String,
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(rename = "keySize")]
    key_size: usize,
    #[serde(rename = "publicKey")]
    public_key: PublicKey,
    #[serde(rename = "publicKeyDer")]
    public_key_der: String,
    sha: String,
    mgf: Option<String>,
    #[serde(rename = "mgfSha")]
    mgf_sha: Option<String>,
    #[serde(rename = "sLen")]
    s_len: Option<usize>,
    tests: Vec<Case>,
}

#[derive(Deserialize)]
struct PublicKey {
    modulus: String,
    #[serde(rename = "publicExponent")]
    public_exponent: String,
}

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(default)]
    comment: String,
    msg: String,
    sig: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

fn load(name: &str) -> File {
    let path = format!(
        "{}/tests/data/wycheproof/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn hash_algorithm(name: &str) -> HashAlgorithm {
    match name {
        "SHA-224" => HashAlgorithm::Sha224,
        "SHA-256" => HashAlgorithm::Sha256,
        "SHA-384" => HashAlgorithm::Sha384,
        "SHA-512" => HashAlgorithm::Sha512,
        "SHA3-256" => HashAlgorithm::Sha3_256,
        "SHA3-384" => HashAlgorithm::Sha3_384,
        "SHA3-512" => HashAlgorithm::Sha3_512,
        other => panic!("unsupported hash {other}"),
    }
}

enum Scheme {
    Pkcs1,
    Pss,
}

fn run(name: &str, scheme: Scheme) {
    let file = load(name);
    match scheme {
        Scheme::Pkcs1 => assert_eq!(file.algorithm, "RSASSA-PKCS1-v1_5"),
        Scheme::Pss => assert_eq!(file.algorithm, "RSASSA-PSS"),
    }
    let mut total = 0;
    let mut accepted_acceptable = 0;
    let mut rejected_acceptable = Vec::new();
    for group in &file.groups {
        let hash = hash_algorithm(&group.sha);
        if let Scheme::Pss = scheme {
            assert_eq!(group.mgf.as_deref(), Some("MGF1"));
            assert_eq!(group.mgf_sha.as_deref(), Some(group.sha.as_str()));
            assert_eq!(group.s_len, Some(hash.output_len()));
        }
        let spki = hex::decode(&group.public_key_der).unwrap();
        let key = RsaPublicKey::from_spki_der(&spki).unwrap();
        let n = hex::decode(&group.public_key.modulus).unwrap();
        let e = hex::decode(&group.public_key.public_exponent).unwrap();
        let key2 = RsaPublicKey::from_components(&n, &e).unwrap();
        assert_eq!(key.n_be(), key2.n_be());
        assert_eq!(key.e_be(), key2.e_be());
        assert_eq!(key.modulus_bits(), group.key_size);
        assert_eq!(key.modulus_len_bytes(), group.key_size / 8);
        // Re-encoding yields the RSAPublicKey inside the SPKI.
        let mut der = [0u8; 1100];
        let n_der = key.to_pkcs1_der(&mut der).unwrap();
        assert!(spki.ends_with(&der[..n_der]));

        for case in &group.tests {
            total += 1;
            let msg = hex::decode(&case.msg).unwrap();
            let sig = hex::decode(&case.sig).unwrap();
            let result = match scheme {
                Scheme::Pkcs1 => verify_pkcs1v15(&key, hash, &msg, &sig),
                Scheme::Pss => verify_pss(&key, hash, &msg, &sig),
            };
            let label = format!(
                "{name} tcId {} ({}; flags {:?})",
                case.tc_id, case.comment, case.flags
            );
            match case.result.as_str() {
                "valid" => assert_eq!(result, Ok(()), "{label}"),
                "invalid" => assert_eq!(result, Err(Error::InvalidSignature), "{label}"),
                "acceptable" => {
                    if result.is_ok() {
                        accepted_acceptable += 1;
                    } else {
                        rejected_acceptable.push(label);
                    }
                }
                other => panic!("unknown result {other}"),
            }
        }
    }
    assert_eq!(total, file.number_of_tests);
    // Legacy encodings (for example a missing NULL in the DigestInfo) are
    // rejected by this strict implementation; record what happened.
    assert_eq!(
        accepted_acceptable, 0,
        "no 'acceptable' case should be accepted"
    );
    println!("{name}: {total} cases, rejected acceptable: {rejected_acceptable:?}");
}

#[test]
fn pkcs1_2048_sha256() {
    run("rsa_signature_2048_sha256_test.json", Scheme::Pkcs1);
}

#[test]
fn pkcs1_3072_sha384() {
    run("rsa_signature_3072_sha384_test.json", Scheme::Pkcs1);
}

#[test]
fn pkcs1_4096_sha512() {
    run("rsa_signature_4096_sha512_test.json", Scheme::Pkcs1);
}

#[test]
fn pss_2048_sha256() {
    run("rsa_pss_2048_sha256_mgf1_32_test.json", Scheme::Pss);
}

#[test]
fn pss_3072_sha256() {
    run("rsa_pss_3072_sha256_mgf1_32_test.json", Scheme::Pss);
}

#[test]
fn pss_4096_sha512() {
    run("rsa_pss_4096_sha512_mgf1_64_test.json", Scheme::Pss);
}

/// Every file again under each RSA backend this CPU offers (keys parsed
/// after the policy change keep that backend). The policy is process-wide;
/// the other tests in this binary give the same results under any backend.
#[test]
fn all_files_under_every_backend() {
    let mut seen = Vec::new();
    for policy in [
        Policy::PREFERRED,
        Policy::new(Acceleration::None, Acceleration::Preferred),
        Policy::NONE,
    ] {
        accel::set_policy(Algorithm::Rsa, policy).unwrap();
        let backend = accel::status(Algorithm::Rsa).backend;
        if seen.contains(&backend) {
            continue;
        }
        seen.push(backend);
        println!("backend {backend}");
        for (name, scheme) in [
            ("rsa_signature_2048_sha256_test.json", Scheme::Pkcs1),
            ("rsa_signature_3072_sha384_test.json", Scheme::Pkcs1),
            ("rsa_signature_4096_sha512_test.json", Scheme::Pkcs1),
            ("rsa_pss_2048_sha256_mgf1_32_test.json", Scheme::Pss),
            ("rsa_pss_3072_sha256_mgf1_32_test.json", Scheme::Pss),
            ("rsa_pss_4096_sha512_mgf1_64_test.json", Scheme::Pss),
        ] {
            run(name, scheme);
        }
    }
    accel::set_policy(Algorithm::Rsa, Policy::PREFERRED).unwrap();
}
