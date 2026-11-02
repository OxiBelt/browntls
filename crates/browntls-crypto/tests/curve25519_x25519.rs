//! X25519 tests: RFC 7748 vectors, Wycheproof, and differential tests against
//! `x25519-dalek` for every backend available at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::curve25519::x25519::{
    BASEPOINT, Backend, PrivateKey, x25519, x25519_base, x25519_with_backend,
};
use browntls_crypto::rand::{OsRng, SecureRandom};

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn backends() -> Vec<Backend> {
    let v: Vec<Backend> = Backend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect();
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| eprintln!("x25519 backends: {v:?} (best: {:?})", Backend::best()));
    v
}

/// Every implementation path for a variable-base X25519.
fn all_x25519(k: &[u8; 32], u: &[u8; 32]) -> Vec<[u8; 32]> {
    let mut out = vec![x25519(k, u)];
    for b in backends() {
        out.push(x25519_with_backend(b, k, u).unwrap());
    }
    out
}

#[test]
fn rfc7748_section_5_2() {
    let cases = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for (k, u, out) in cases {
        for got in all_x25519(&h32(k), &h32(u)) {
            assert_eq!(hex::encode(got), out);
        }
    }
}

fn iterate(backend: Backend, n: u32) -> [u8; 32] {
    let mut k = BASEPOINT;
    let mut u = BASEPOINT;
    for _ in 0..n {
        let r = x25519_with_backend(backend, &k, &u).unwrap();
        u = k;
        k = r;
    }
    k
}

#[test]
fn rfc7748_iterations_1_and_1000() {
    for b in backends() {
        assert_eq!(
            hex::encode(iterate(b, 1)),
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        );
        assert_eq!(
            hex::encode(iterate(b, 1000)),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        );
    }
}

#[test]
#[ignore = "slow: 1,000,000 ladder iterations per backend"]
fn rfc7748_iterations_1000000() {
    for b in backends() {
        assert_eq!(
            hex::encode(iterate(b, 1_000_000)),
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
        );
    }
}

#[test]
fn rfc7748_section_6_1() {
    let a = PrivateKey::from_bytes(&h32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let b = PrivateKey::from_bytes(&h32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let pa = a.public_key();
    let pb = b.public_key();
    assert_eq!(
        hex::encode(pa),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(pb),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
    for got in all_x25519(a.as_bytes(), &BASEPOINT) {
        assert_eq!(got, pa);
    }
    let k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assert_eq!(hex::encode(a.diffie_hellman(&pb).unwrap()), k);
    assert_eq!(hex::encode(b.diffie_hellman(&pa).unwrap()), k);
}

#[derive(serde::Deserialize)]
struct XdhFile {
    #[serde(rename = "testGroups")]
    groups: Vec<XdhGroup>,
}

#[derive(serde::Deserialize)]
struct XdhGroup {
    curve: String,
    tests: Vec<XdhTest>,
}

#[derive(serde::Deserialize)]
struct XdhTest {
    #[serde(rename = "tcId")]
    id: u32,
    public: String,
    private: String,
    shared: String,
    result: String,
}

#[test]
fn wycheproof_x25519() {
    let file: XdhFile = serde_json::from_str(include_str!("data/wycheproof/x25519_test.json"))
        .expect("parse x25519_test.json");
    let mut n = 0;
    for g in &file.groups {
        assert_eq!(g.curve, "curve25519");
        for t in &g.tests {
            let public = hex::decode(&t.public).unwrap();
            let private = hex::decode(&t.private).unwrap();
            let shared = hex::decode(&t.shared).unwrap();
            // All vectors in this file have 32-byte inputs; "acceptable" ones
            // (twist points, non-canonical or low-order u) still define the
            // output exactly per RFC 7748.
            assert!(
                matches!(t.result.as_str(), "valid" | "acceptable"),
                "tc {}",
                t.id
            );
            let (pk, sk): ([u8; 32], [u8; 32]) =
                (public.try_into().unwrap(), private.try_into().unwrap());
            for got in all_x25519(&sk, &pk) {
                assert_eq!(got.as_slice(), shared.as_slice(), "tc {}", t.id);
            }
            let dh = PrivateKey::from_bytes(&sk).diffie_hellman(&pk);
            if shared.iter().all(|&b| b == 0) {
                assert_eq!(dh, Err(Error::KeyAgreementFailed), "tc {}", t.id);
            } else {
                assert_eq!(dh.unwrap().as_slice(), shared.as_slice(), "tc {}", t.id);
            }
            n += 1;
        }
    }
    assert_eq!(n, 518);
}

fn edge_u_values() -> Vec<[u8; 32]> {
    let p = h32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    let mut v = vec![[0u8; 32], BASEPOINT, p, [0xff; 32]];
    let mut one = [0u8; 32];
    one[0] = 1;
    v.push(one);
    for delta in [1u8, 2, 18, 19, 20, 37, 38] {
        let mut x = p;
        x[0] = x[0].wrapping_add(delta); // p + delta, low byte wrapping for delta > 18
        v.push(x);
        let mut y = p;
        y[0] = y[0].wrapping_sub(delta); // p - delta
        v.push(y);
    }
    let mut top = [0u8; 32];
    top[31] = 0x80;
    v.push(top);
    let mut msb_set = BASEPOINT;
    msb_set[31] |= 0x80;
    v.push(msb_set);
    v
}

#[test]
fn differential_vs_dalek() {
    let rng = OsRng;
    let mut us = edge_u_values();
    for _ in 0..200 {
        let mut u = [0u8; 32];
        rng.fill(&mut u).unwrap();
        us.push(u);
    }
    for (i, u) in us.iter().enumerate() {
        let mut k = [0u8; 32];
        rng.fill(&mut k).unwrap();
        if i == 0 {
            k = [0; 32];
        } else if i == 1 {
            k = [0xff; 32];
        }
        let want = x25519_dalek::x25519(k, *u);
        for got in all_x25519(&k, u) {
            assert_eq!(got, want, "k={} u={}", hex::encode(k), hex::encode(u));
        }
        let pub_want = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(k));
        assert_eq!(x25519_base(&k), *pub_want.as_bytes());
        assert_eq!(
            PrivateKey::from_bytes(&k).public_key(),
            *pub_want.as_bytes()
        );
    }
}

#[test]
fn generate_and_agree() {
    let a = PrivateKey::generate(&OsRng).unwrap();
    let b = PrivateKey::generate(&OsRng).unwrap();
    assert_eq!(
        a.diffie_hellman(&b.public_key()).unwrap(),
        b.diffie_hellman(&a.public_key()).unwrap()
    );
    assert_eq!(a.diffie_hellman(&[0u8; 32]), Err(Error::KeyAgreementFailed));
    assert!(PrivateKey::from_slice(&[0u8; 31]).is_err());
    assert_eq!(format!("{a:?}"), "x25519::PrivateKey { .. }");
    let failing = browntls_crypto::rand::FixedRng::new(&[0u8; 8]);
    assert_eq!(
        PrivateKey::generate(&failing).map(|_| ()),
        Err(Error::RandomFailure)
    );
}

#[test]
#[ignore = "throughput measurement; run with --release --ignored --nocapture"]
fn throughput() {
    use std::time::Instant;
    // Best of several interleaved rounds, to reduce noise on shared machines.
    fn best_us(rounds: u32, n: u32, mut f: impl FnMut()) -> f64 {
        let mut best = f64::MAX;
        for _ in 0..rounds {
            let t = Instant::now();
            for _ in 0..n {
                f();
            }
            best = best.min(t.elapsed().as_secs_f64() * 1e6 / f64::from(n));
        }
        best
    }
    let k = [0x42u8; 32];
    let mut u = BASEPOINT;
    for b in backends() {
        let us = best_us(10, 500, || u = x25519_with_backend(b, &k, &u).unwrap());
        eprintln!("x25519 {b:?}: {:.0} ops/s ({us:.1} us/op)", 1e6 / us);
    }
    let us = best_us(10, 500, || u = x25519_dalek::x25519(k, u));
    eprintln!(
        "x25519-dalek (reference): {:.0} ops/s ({us:.1} us/op)",
        1e6 / us
    );
    let us = best_us(10, 1000, || u = x25519_base(&u));
    eprintln!("x25519_base: {:.0} ops/s ({us:.1} us/op)", 1e6 / us);
    std::hint::black_box(u);
}
