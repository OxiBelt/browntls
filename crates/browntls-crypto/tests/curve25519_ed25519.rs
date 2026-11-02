//! Ed25519 tests: RFC 8032 §7.1 vectors, Wycheproof, RFC 8410 PKCS#8 and
//! differential tests against `ed25519-dalek`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::curve25519::ed25519::{SigningKey, VerifyingKey};
use browntls_crypto::rand::{OsRng, SecureRandom};
use ed25519_dalek::{Signer as _, Verifier as _};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

#[test]
fn rfc8032_section_7_1() {
    // (secret key, public key, message, signature): TEST 1, 2, 3, SHA(abc).
    let cases = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ];
    for (sk, pk, msg, sig) in cases {
        let key = SigningKey::from_seed(&h32(sk));
        let vk = key.verifying_key();
        assert_eq!(hex::encode(vk.as_bytes()), pk);
        let msg = h(msg);
        let s = key.sign(&msg);
        assert_eq!(hex::encode(s), sig);
        let vk2 = VerifyingKey::from_bytes(&h32(pk)).unwrap();
        assert_eq!(vk, vk2);
        vk2.verify(&msg, &s).unwrap();
        let mut bad = s;
        bad[63] ^= 0x01;
        assert_eq!(vk2.verify(&msg, &bad), Err(Error::InvalidSignature));
        assert!(vk2.verify(b"other message", &s).is_err());
    }
}

#[derive(serde::Deserialize)]
struct EddsaFile {
    #[serde(rename = "testGroups")]
    groups: Vec<EddsaGroup>,
}

#[derive(serde::Deserialize)]
struct EddsaGroup {
    #[serde(rename = "publicKey")]
    public_key: EddsaKey,
    tests: Vec<EddsaTest>,
}

#[derive(serde::Deserialize)]
struct EddsaKey {
    curve: String,
    pk: String,
}

#[derive(serde::Deserialize)]
struct EddsaTest {
    #[serde(rename = "tcId")]
    id: u32,
    msg: String,
    sig: String,
    result: String,
    flags: Vec<String>,
}

#[test]
fn wycheproof_ed25519() {
    let file: EddsaFile = serde_json::from_str(include_str!("data/wycheproof/ed25519_test.json"))
        .expect("parse ed25519_test.json");
    let (mut valid, mut invalid, mut acc_ok, mut acc_rej) = (0, 0, 0, 0);
    for g in &file.groups {
        assert_eq!(g.public_key.curve, "edwards25519");
        let pk = h(&g.public_key.pk);
        let vk = VerifyingKey::from_slice(&pk);
        for t in &g.tests {
            let msg = h(&t.msg);
            let sig = h(&t.sig);
            let accepted = match (&vk, <[u8; 64]>::try_from(sig.as_slice())) {
                (Ok(vk), Ok(sig)) => vk.verify(&msg, &sig).is_ok(),
                _ => false,
            };
            match t.result.as_str() {
                "valid" => {
                    assert!(accepted, "valid tc {} rejected ({:?})", t.id, t.flags);
                    valid += 1;
                }
                "invalid" => {
                    assert!(!accepted, "invalid tc {} accepted ({:?})", t.id, t.flags);
                    invalid += 1;
                }
                "acceptable" => {
                    // Policy: small-order keys are rejected outright; for
                    // mixed-order keys the cofactorless equation decides.
                    if t.flags.iter().any(|f| f == "SmallOrderPublicKey") {
                        assert!(!accepted, "tc {}", t.id);
                    }
                    if accepted {
                        acc_ok += 1;
                    } else {
                        acc_rej += 1;
                    }
                }
                r => panic!("unknown result {r}"),
            }
        }
    }
    eprintln!(
        "wycheproof ed25519: {valid} valid, {invalid} invalid, acceptable {acc_ok} accepted / {acc_rej} rejected"
    );
    assert_eq!(valid + invalid + acc_ok + acc_rej, 210);
}

const RFC8410_V1: &str = "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842";
const RFC8410_V2: &str = "3072020101300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842a01f301d060a2a864886f70d01090914310f0c0d437572646c652043686169727381210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";
const RFC8410_SEED: &str = "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842";
const RFC8410_PUB: &str = "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";

/// Builds a v2 OneAsymmetricKey with the given public key (no attributes).
fn pkcs8_v2(seed: &[u8; 32], public: &[u8; 32]) -> Vec<u8> {
    let mut v = h("3051020101300506032b657004220420");
    v.extend_from_slice(seed);
    v.extend_from_slice(&[0x81, 0x21, 0x00]);
    v.extend_from_slice(public);
    v
}

#[test]
fn pkcs8_rfc8410() {
    let k1 = SigningKey::from_pkcs8_der(&h(RFC8410_V1)).unwrap();
    assert_eq!(hex::encode(k1.seed()), RFC8410_SEED);
    assert_eq!(hex::encode(k1.verifying_key().as_bytes()), RFC8410_PUB);
    assert_eq!(hex::encode(*k1.to_pkcs8_der()), RFC8410_V1);
    let k2 = SigningKey::from_pkcs8_der(&h(RFC8410_V2)).unwrap();
    assert_eq!(k2.verifying_key(), k1.verifying_key());

    let seed = h32(RFC8410_SEED);
    let public = h32(RFC8410_PUB);
    SigningKey::from_pkcs8_der(&pkcs8_v2(&seed, &public)).unwrap();
    // v2 without a public key is accepted.
    let mut v2_nopub = h(RFC8410_V1);
    v2_nopub[4] = 1;
    SigningKey::from_pkcs8_der(&v2_nopub).unwrap();

    let reject = |der: &[u8]| SigningKey::from_pkcs8_der(der).map(|_| ());
    // Mismatched v2 public key.
    let mut wrong = public;
    wrong[0] ^= 1;
    assert_eq!(reject(&pkcs8_v2(&seed, &wrong)), Err(Error::InvalidKey));
    // v1 must not carry a public key.
    let mut v1_pub = pkcs8_v2(&seed, &public);
    v1_pub[4] = 0;
    assert!(reject(&v1_pub).is_err());
    // Unsupported version.
    let mut v3 = h(RFC8410_V1);
    v3[4] = 2;
    assert!(reject(&v3).is_err());
    // X25519 OID (1.3.101.110) is rejected.
    let mut x = h(RFC8410_V1);
    x[11] = 0x6e;
    assert_eq!(reject(&x), Err(Error::InvalidKey));
    // Parameters present in the AlgorithmIdentifier.
    let with_null = h(
        "3030020100300706032b65700500 04220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
            .replace(' ', "")
            .as_str(),
    );
    assert!(reject(&with_null).is_err());
    // Wrong private key length, trailing data, truncation, bad public key bits.
    let short = h(
        "302d020100300506032b65700421041fd4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f447558",
    );
    assert!(reject(&short).is_err());
    let mut trailing = h(RFC8410_V1);
    trailing.push(0);
    assert!(reject(&trailing).is_err());
    let v1 = h(RFC8410_V1);
    for n in 0..v1.len() {
        assert!(reject(&v1[..n]).is_err());
    }
    let mut unused_bits = pkcs8_v2(&seed, &public);
    unused_bits[50] = 1;
    assert!(reject(&unused_bits).is_err());
}

#[test]
fn verifying_key_validation() {
    // Identity and other small-order points are rejected.
    let mut ident = [0u8; 32];
    ident[0] = 1;
    assert_eq!(VerifyingKey::from_bytes(&ident), Err(Error::InvalidKey));
    assert!(
        VerifyingKey::from_bytes(&h32(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        ))
        .is_err()
    );
    // Non-canonical y (y = p + 1 encodes the identity non-canonically).
    assert!(
        VerifyingKey::from_bytes(&h32(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        ))
        .is_err()
    );
    // Not on the curve.
    let mut two = [0u8; 32];
    two[0] = 2;
    assert!(VerifyingKey::from_bytes(&two).is_err());
    assert!(VerifyingKey::from_slice(&[0u8; 31]).is_err());
}

#[test]
fn differential_vs_dalek() {
    let rng = OsRng;
    for i in 0..200usize {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed).unwrap();
        let mut msg = vec![0u8; i * 7 % 300];
        rng.fill(&mut msg).unwrap();

        let ours = SigningKey::from_seed(&seed);
        let theirs = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk = ours.verifying_key();
        let dvk = theirs.verifying_key();
        assert_eq!(vk.as_bytes(), dvk.as_bytes());

        let sig = ours.sign(&msg);
        let dsig = theirs.sign(&msg);
        assert_eq!(sig, dsig.to_bytes());
        vk.verify(&msg, &sig).unwrap();

        // Random corruption: our decision must match dalek's verify_strict.
        let mut bad = sig;
        let pos = i % 64;
        bad[pos] ^= 1 << (i % 8);
        let ours_ok = vk.verify(&msg, &bad).is_ok();
        let dalek_ok = dvk
            .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&bad))
            .is_ok();
        assert_eq!(ours_ok, dalek_ok);
        assert!(!ours_ok);

        // Malleated S + L must be rejected (dalek also rejects).
        let mut mall = sig;
        let l = h("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let mut carry = 0u16;
        for j in 0..32 {
            let t = u16::from(mall[32 + j]) + u16::from(l[j]) + carry;
            mall[32 + j] = t as u8;
            carry = t >> 8;
        }
        assert!(vk.verify(&msg, &mall).is_err());
        assert!(
            dvk.verify(&msg, &ed25519_dalek::Signature::from_bytes(&mall))
                .is_err()
        );

        // Random public keys: our acceptance matches dalek's decoding plus
        // small-order rejection (non-canonical encodings, which dalek may
        // accept, occur with negligible probability for random bytes).
        let mut pk = [0u8; 32];
        rng.fill(&mut pk).unwrap();
        let dalek_ok = ed25519_dalek::VerifyingKey::from_bytes(&pk).is_ok_and(|k| !k.is_weak());
        assert_eq!(VerifyingKey::from_bytes(&pk).is_ok(), dalek_ok);
    }
}

#[test]
fn generate_sign_verify() {
    let k = SigningKey::generate(&OsRng).unwrap();
    let sig = k.sign(b"hello");
    k.verifying_key().verify(b"hello", &sig).unwrap();
    let k2 = SigningKey::from_pkcs8_der(&*k.to_pkcs8_der()).unwrap();
    assert_eq!(k2.sign(b"hello"), sig);
    assert!(format!("{k:?}").starts_with("SigningKey"));
    let failing = browntls_crypto::rand::FixedRng::new(&[]);
    assert!(SigningKey::generate(&failing).is_err());
}

#[test]
#[ignore = "throughput measurement; run with --release --ignored --nocapture"]
fn throughput() {
    use std::hint::black_box;
    use std::time::Instant;
    // Best of several rounds, to reduce noise on shared machines.
    fn report(name: &str, mut f: impl FnMut()) {
        let mut best = f64::MAX;
        for _ in 0..10 {
            let t = Instant::now();
            for _ in 0..500 {
                f();
            }
            best = best.min(t.elapsed().as_secs_f64() * 1e6 / 500.0);
        }
        eprintln!("{name}: {:.0} ops/s ({best:.1} us/op)", 1e6 / best);
    }
    let key = SigningKey::from_seed(&[7u8; 32]);
    let vk = key.verifying_key();
    let msg = [0x5au8; 64];
    let sig = key.sign(&msg);
    report("ed25519 sign", || {
        black_box(key.sign(black_box(&msg)));
    });
    report("ed25519 verify", || {
        vk.verify(black_box(&msg), &sig).unwrap();
    });
    let dkey = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let dvk = dkey.verifying_key();
    let dsig = dkey.sign(&msg);
    report("ed25519-dalek sign (reference)", || {
        black_box(dkey.sign(black_box(&msg)));
    });
    report("ed25519-dalek verify (reference)", || {
        dvk.verify(black_box(&msg), &dsig).unwrap();
    });
}
