//! Throughput benchmark in the style of `openssl speed`.
//!
//! ```text
//! cargo run --release -p browntls-crypto --example speed -- [--policy P] [--seconds S]
//! ```
//!
//! `P` is `preferred` (default), `none` (portable only), `no-simd` or
//! `no-dedicated`; see `browntls_crypto::accel`. Output lines are
//! tab-separated:
//!
//! ```text
//! bytes <algorithm> <message length> <bytes per second>
//! ops   <algorithm> <operation>      <operations per second>
//! ```
//!
//! Measurement mirrors `openssl speed -elapsed`: single thread, wall-clock
//! time, AEADs sealed TLS-style (fresh call with nonce, 13-byte AAD and tag
//! per message, like `-aead`), hashes computed one-shot per message, ECDSA
//! over a pre-hashed digest with hedged nonces, Ed25519 over a 20-byte
//! message, RSA PKCS #1 v1.5 over SHA-256.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use browntls_crypto::accel::{self, Acceleration, Policy};
use browntls_crypto::aead::Aead;
use browntls_crypto::chacha::ChaCha20Poly1305;
use browntls_crypto::curve25519::{ed25519, x25519};
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm};
use browntls_crypto::hash::{HashAlgorithm, HashFunction, Sha3_256, Sha256, Sha512};
use browntls_crypto::mlkem::{DecapsulationKey, MlKem768};
use browntls_crypto::nist::{p256, p384};
use browntls_crypto::rand::OsRng;
use browntls_crypto::rsa::RsaPrivateKey;

/// Message lengths for hashes (as `openssl speed -evp`).
const LENGTHS: [usize; 6] = [16, 64, 256, 1024, 8192, 16384];
/// Record lengths for AEADs (as `openssl speed -aead`, TLS-like).
const AEAD_LENGTHS: [usize; 6] = [2, 31, 136, 1024, 8192, 16384];

/// Runs `f` repeatedly for about `budget` and returns calls per second.
fn rate(budget: Duration, mut f: impl FnMut()) -> f64 {
    // Warm up caches, branch predictors and lazily initialised state.
    for _ in 0..8 {
        f();
    }
    let mut calls = 0u64;
    let mut batch = 1u64;
    let start = Instant::now();
    loop {
        for _ in 0..batch {
            f();
        }
        calls += batch;
        let elapsed = start.elapsed();
        if elapsed >= budget {
            return calls as f64 / elapsed.as_secs_f64();
        }
        batch = (batch * 2).min(1 << 16);
    }
}

fn bytes_line(alg: &str, len: usize, calls_per_sec: f64) {
    println!("bytes\t{alg}\t{len}\t{:.0}", calls_per_sec * len as f64);
}

fn ops_line(alg: &str, op: &str, per_sec: f64) {
    println!("ops\t{alg}\t{op}\t{per_sec:.1}");
}

fn aead<A: Aead>(name: &str, key: &[u8], budget: Duration) {
    let cipher = A::new(key).unwrap();
    let aad = [0x17u8; 13];
    for len in AEAD_LENGTHS {
        let mut buf = vec![0u8; len];
        let mut nonce = [0u8; 12];
        let r = rate(budget, || {
            nonce[11] = nonce[11].wrapping_add(1);
            black_box(
                cipher
                    .seal_in_place(&nonce, black_box(&aad), black_box(&mut buf))
                    .unwrap(),
            );
        });
        bytes_line(name, len, r);
    }
}

fn hash<H: HashFunction>(name: &str, budget: Duration) {
    for len in LENGTHS {
        let buf = vec![0x5au8; len];
        let r = rate(budget, || {
            black_box(H::digest(black_box(&buf)));
        });
        bytes_line(name, len, r);
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut policy = Policy::PREFERRED;
    let mut seconds = 1.0f64;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--policy" => {
                policy = match args.next().as_deref() {
                    Some("preferred") => Policy::PREFERRED,
                    Some("none") => Policy::NONE,
                    Some("no-simd") => Policy::new(Acceleration::None, Acceleration::Preferred),
                    Some("no-dedicated") => {
                        Policy::new(Acceleration::Preferred, Acceleration::None)
                    }
                    other => panic!("unknown policy {other:?}"),
                }
            }
            "--seconds" => seconds = args.next().unwrap().parse().unwrap(),
            other => panic!("unknown argument {other}"),
        }
    }
    accel::set_policy_all(policy).unwrap();
    let budget = Duration::from_secs_f64(seconds);

    for s in accel::status_all() {
        println!("# {s}");
    }

    // Symmetric primitives.
    aead::<Aes128Gcm>("AES-128-GCM", &[1; 16], budget);
    aead::<Aes256Gcm>("AES-256-GCM", &[2; 32], budget);
    aead::<ChaCha20Poly1305>("ChaCha20-Poly1305", &[3; 32], budget);
    hash::<Sha256>("SHA-256", budget);
    hash::<Sha512>("SHA-512", budget);
    hash::<Sha3_256>("SHA3-256", budget);

    // X25519: one Diffie-Hellman derivation (as `openssl speed ecdhx25519`).
    let peer = x25519::x25519_base(&[9; 32]);
    ops_line(
        "X25519",
        "derive",
        rate(budget, || {
            black_box(x25519::x25519(black_box(&[7; 32]), &peer));
        }),
    );

    // Ed25519 over a 20-byte message (as `openssl speed ed25519`).
    let ed = ed25519::SigningKey::from_seed(&[4; 32]);
    let msg = [0x42u8; 20];
    let sig = ed.sign(&msg);
    let vk = ed.verifying_key();
    ops_line(
        "Ed25519",
        "sign",
        rate(budget, || {
            black_box(ed.sign(&msg));
        }),
    );
    ops_line(
        "Ed25519",
        "verify",
        rate(budget, || vk.verify(&msg, &sig).unwrap()),
    );

    // ECDSA over a pre-hashed digest and ECDH (as `openssl speed ecdsapN` /
    // `ecdhpN`).
    macro_rules! nist {
        ($m:ident, $name:literal, $hash:expr, $digest_len:literal) => {{
            let sk = $m::SecretKey::from_bytes(&[5; $m::FIELD_LEN]).unwrap();
            let pk = sk.public_key();
            let signer =
                $m::SigningKey::new($m::SecretKey::from_bytes(&[6; $m::FIELD_LEN]).unwrap());
            let vk = signer.verifying_key();
            let digest = [0x33u8; $digest_len];
            let sig = signer.sign_prehashed($hash, &digest, Some(&OsRng)).unwrap();
            ops_line(
                $name,
                "sign",
                rate(budget, || {
                    black_box(signer.sign_prehashed($hash, &digest, Some(&OsRng)).unwrap());
                }),
            );
            ops_line(
                $name,
                "verify",
                rate(budget, || {
                    $m::verify_prehashed(&vk, &digest, sig.as_der()).unwrap();
                }),
            );
            let other = $m::SecretKey::from_bytes(&[8; $m::FIELD_LEN]).unwrap();
            ops_line(
                $name,
                "ecdh",
                rate(budget, || {
                    black_box(other.diffie_hellman(&pk).unwrap());
                }),
            );
        }};
    }
    nist!(p256, "P-256", HashAlgorithm::Sha256, 32);
    nist!(p384, "P-384", HashAlgorithm::Sha384, 48);

    // RSA PKCS #1 v1.5 with SHA-256 (as `openssl speed rsaN`).
    for bits in [2048usize, 3072] {
        let key = RsaPrivateKey::generate(bits, &OsRng).unwrap();
        let public = key.public_key();
        let name = format!("RSA-{bits}");
        let mut sig = vec![0u8; key.modulus_len_bytes()];
        let n = key
            .sign_pkcs1v15(HashAlgorithm::Sha256, &msg, &mut sig)
            .unwrap();
        sig.truncate(n);
        let mut out = vec![0u8; key.modulus_len_bytes()];
        ops_line(
            &name,
            "sign",
            rate(budget, || {
                black_box(
                    key.sign_pkcs1v15(HashAlgorithm::Sha256, &msg, &mut out)
                        .unwrap(),
                );
            }),
        );
        ops_line(
            &name,
            "verify",
            rate(budget, || {
                browntls_crypto::rsa::verify_pkcs1v15(public, HashAlgorithm::Sha256, &msg, &sig)
                    .unwrap();
            }),
        );
    }

    // ML-KEM-768 (no OpenSSL 3.0 counterpart).
    ops_line(
        "ML-KEM-768",
        "keygen",
        rate(budget, || {
            black_box(DecapsulationKey::<MlKem768>::generate(&OsRng).unwrap());
        }),
    );
    let (dk, ek) = DecapsulationKey::<MlKem768>::generate(&OsRng).unwrap();
    let (ct, _) = ek.encapsulate(&OsRng).unwrap();
    ops_line(
        "ML-KEM-768",
        "encaps",
        rate(budget, || {
            black_box(ek.encapsulate(&OsRng).unwrap());
        }),
    );
    ops_line(
        "ML-KEM-768",
        "decaps",
        rate(budget, || {
            black_box(dk.decapsulate(ct.as_ref()).unwrap());
        }),
    );
}
