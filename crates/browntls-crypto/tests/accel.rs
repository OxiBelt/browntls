//! Acceleration policy: `Required` / `Preferred` / `None` and status reports.
//!
//! The policy is process-wide, so everything runs in one test function to
//! avoid races with other tests (each integration test file is its own
//! process).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Acceleration, Algorithm};
use browntls_crypto::aead::Aead as _;
use browntls_crypto::chacha::ChaCha20Poly1305;
use browntls_crypto::curve25519::x25519;
use browntls_crypto::gcm::Aes256Gcm;
use browntls_crypto::hash::{HashAlgorithm, HashFunction as _, Sha256, Sha512, Shake128};
use browntls_crypto::mlkem::{DecapsulationKey, MlKem768};
use browntls_crypto::nist::p256;
use browntls_crypto::rand::OsRng;
use browntls_crypto::rsa::RsaPrivateKey;

/// Outputs of every policy-controlled algorithm on fixed inputs.
fn fingerprint(rsa: &RsaPrivateKey) -> Vec<Vec<u8>> {
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 31 + 7) as u8).collect();
    let mut out = vec![
        Sha256::digest(&data).to_vec(),
        Sha512::digest(&data).to_vec(),
    ];

    let mut shake = [0u8; 300];
    Shake128::digest_into(&data, &mut shake);
    out.push(shake.to_vec());

    let mut buf = data.clone();
    let tag = Aes256Gcm::new(&[7; 32])
        .unwrap()
        .seal_in_place(&[1; 12], b"aad", &mut buf)
        .unwrap();
    out.push(buf);
    out.push(tag.to_vec());

    let mut buf = data.clone();
    let tag = ChaCha20Poly1305::new(&[9; 32])
        .unwrap()
        .seal_in_place(&[2; 12], b"aad", &mut buf)
        .unwrap();
    out.push(buf);
    out.push(tag.to_vec());

    out.push(x25519::x25519(&[5; 32], &x25519::BASEPOINT).to_vec());

    let a = p256::SecretKey::from_bytes(&[3; 32]).unwrap();
    let b = p256::SecretKey::from_bytes(&[4; 32]).unwrap();
    out.push(a.diffie_hellman(&b.public_key()).unwrap().to_vec());

    // ML-KEM matrix expansion uses the four-way Keccak.
    let (dk, ek) = DecapsulationKey::<MlKem768>::generate_deterministic(&[1; 32], &[2; 32]);
    let (ct, ss) = ek.encapsulate_deterministic(&[3; 32]);
    assert_eq!(dk.decapsulate(ct.as_ref()).unwrap(), ss);
    out.push(ct.as_ref().to_vec());
    out.push(ss.to_vec());

    // PKCS #1 v1.5 signatures are deterministic despite blinding.
    let mut sig = vec![0u8; rsa.modulus_len_bytes()];
    let n = rsa
        .sign_pkcs1v15(HashAlgorithm::Sha256, &data, &mut sig)
        .unwrap();
    sig.truncate(n);
    out.push(sig);
    out
}

#[test]
fn acceleration_policies() {
    let rsa = RsaPrivateKey::generate(2048, &OsRng).unwrap();

    // Default: every algorithm prefers acceleration and uses it when present.
    for s in accel::status_all() {
        println!("{s}");
        assert_eq!(s.policy, Acceleration::Preferred);
        assert_eq!(s.accelerated, s.hardware_available, "{s}");
    }
    let preferred = fingerprint(&rsa);

    // None: portable code everywhere, identical results.
    accel::set_policy_all(Acceleration::None).unwrap();
    assert_eq!(accel::accelerated().count(), 0);
    for s in accel::status_all() {
        assert_eq!(s.policy, Acceleration::None);
        assert_eq!(s.backend, "portable");
    }
    assert_eq!(fingerprint(&rsa), preferred);

    // Per-algorithm override on top of a global policy.
    accel::set_policy(Algorithm::Aes, Acceleration::Preferred).unwrap();
    let aes = accel::status(Algorithm::Aes);
    assert_eq!(aes.accelerated, aes.hardware_available);
    assert!(
        accel::accelerated().all(|s| s.algorithm == Algorithm::Aes),
        "only AES may be accelerated"
    );
    assert_eq!(fingerprint(&rsa), preferred);

    // Required: accepted exactly where hardware exists, and then accelerated.
    accel::set_policy_all(Acceleration::Preferred).unwrap();
    for alg in Algorithm::ALL {
        let hw = accel::status(alg).hardware_available;
        match accel::set_policy(alg, Acceleration::Required) {
            Ok(()) => {
                assert!(hw, "{alg}");
                let s = accel::status(alg);
                assert_eq!(s.policy, Acceleration::Required);
                assert!(s.accelerated, "{s}");
            }
            Err(e) => {
                assert_eq!(e, Error::Unsupported);
                assert!(!hw, "{alg}");
                // A refused request leaves the previous policy in place.
                assert_eq!(accel::policy(alg), Acceleration::Preferred);
            }
        }
    }
    assert_eq!(fingerprint(&rsa), preferred);

    // Required for everything succeeds only if every family is accelerated.
    accel::set_policy_all(Acceleration::Preferred).unwrap();
    let all_hw = accel::status_all().iter().all(|s| s.hardware_available);
    assert_eq!(
        accel::set_policy_all(Acceleration::Required).is_ok(),
        all_hw
    );
    if !all_hw {
        assert!(
            Algorithm::ALL
                .iter()
                .all(|&a| accel::policy(a) == Acceleration::Preferred)
        );
    }

    // Configuration strings.
    assert_eq!("none".parse(), Ok(Acceleration::None));
    assert_eq!("Required".parse(), Ok(Acceleration::Required));
    assert_eq!("prefered".parse(), Ok(Acceleration::Preferred));

    accel::set_policy_all(Acceleration::Preferred).unwrap();
}
