//! Acceleration policies per kind (SIMD / dedicated instructions) and
//! status reports.
//!
//! The policy is process-wide, so everything runs in one test function to
//! avoid races with other tests (each integration test file is its own
//! process).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Acceleration, Algorithm, Kind, Policy};
use browntls_crypto::aead::Aead as _;
use browntls_crypto::chacha::ChaCha20Poly1305;
use browntls_crypto::curve25519::x25519;
use browntls_crypto::gcm::Aes256Gcm;
use browntls_crypto::hash::{HashAlgorithm, HashFunction as _, Sha1, Sha256, Sha512, Shake128};
use browntls_crypto::mlkem::{DecapsulationKey, MlKem768};
use browntls_crypto::nist::p256;
use browntls_crypto::rand::OsRng;
use browntls_crypto::rsa::RsaPrivateKey;

const LEVELS: [Acceleration; 3] = [
    Acceleration::Required,
    Acceleration::Preferred,
    Acceleration::None,
];

/// Outputs of every policy-controlled algorithm on fixed inputs.
fn fingerprint(rsa: &RsaPrivateKey) -> Vec<Vec<u8>> {
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 31 + 7) as u8).collect();
    let mut out = vec![
        Sha1::digest(&data).to_vec(),
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

/// Every algorithm's selected backend obeys its policy.
fn assert_policies_obeyed() {
    for s in accel::status_all() {
        assert!(s.policy.permits(s.uses), "{s}");
        assert!(s.uses.simd <= s.available.simd, "{s}");
        assert!(s.uses.dedicated <= s.available.dedicated, "{s}");
    }
}

#[test]
fn acceleration_policies_per_kind() {
    let rsa = RsaPrivateKey::generate(2048, &OsRng).unwrap();

    // Default: both kinds preferred; anything available is used.
    for s in accel::status_all() {
        println!("{s}");
        assert_eq!(s.policy, Policy::PREFERRED);
        assert_eq!(s.accelerated(), s.available.any(), "{s}");
    }
    let baseline = fingerprint(&rsa);

    // Every global combination of levels: accepted ones are obeyed and give
    // identical results; refused ones change nothing.
    for simd in LEVELS {
        for dedicated in LEVELS {
            let policy = Policy::new(simd, dedicated);
            accel::set_policy_all(Policy::PREFERRED).unwrap();
            match accel::set_policy_all(policy) {
                Ok(()) => {
                    assert!(Algorithm::ALL.iter().all(|&a| accel::policy(a) == policy));
                    assert_policies_obeyed();
                    assert_eq!(fingerprint(&rsa), baseline, "{policy}");
                }
                Err(e) => {
                    assert_eq!(e, Error::Unsupported);
                    assert!(
                        Algorithm::ALL
                            .iter()
                            .all(|&a| accel::policy(a) == Policy::PREFERRED)
                    );
                    // Some family cannot satisfy it on its own either.
                    let refused = Algorithm::ALL.iter().filter(|&&a| {
                        let r = accel::set_policy(a, policy);
                        accel::set_policy(a, Policy::PREFERRED).unwrap();
                        r.is_err()
                    });
                    assert!(refused.count() > 0, "{policy}");
                }
            }
        }
    }

    // Per algorithm: a required kind is honoured exactly when it is offered.
    accel::set_policy_all(Policy::PREFERRED).unwrap();
    for alg in Algorithm::ALL {
        for kind in Kind::ALL {
            let offered = accel::status(alg).available.get(kind);
            let r = accel::set_kind(alg, kind, Acceleration::Required);
            assert_eq!(r.is_ok(), offered, "{alg} {kind}");
            if r.is_ok() {
                assert!(accel::status(alg).uses.get(kind), "{alg} {kind}");
            } else {
                assert_eq!(accel::policy(alg), Policy::PREFERRED);
            }
            accel::set_policy(alg, Policy::PREFERRED).unwrap();
        }
    }

    // Disable one kind everywhere: the other kind is still used where a
    // backend relies on it alone.
    for kind in Kind::ALL {
        accel::set_policy_all(Policy::PREFERRED).unwrap();
        accel::set_kind_all(kind, Acceleration::None).unwrap();
        assert_eq!(accel::accelerated_by(kind).count(), 0, "{kind}");
        assert_policies_obeyed();
        assert_eq!(fingerprint(&rsa), baseline, "{kind} disabled");
        for s in accel::status_all() {
            println!("{kind} none -> {s}");
        }
    }

    // Whole-policy updates are atomic: concurrent readers never observe a
    // mix of the old and new global policy. The writer keeps going until
    // every reader has started, so each one overlaps with updates however
    // the threads are scheduled.
    {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        const READERS: usize = 3;
        accel::set_policy_all(Policy::PREFERRED).unwrap();
        let stop = AtomicBool::new(false);
        let started = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let readers: Vec<_> = (0..READERS)
                .map(|_| {
                    scope.spawn(|| {
                        let mut seen = 0u64;
                        loop {
                            let all = accel::status_all();
                            let first = all[0].policy;
                            assert!(all.iter().all(|s| s.policy == first), "torn read");
                            if seen == 0 {
                                started.fetch_add(1, Ordering::Relaxed);
                            }
                            seen += 1;
                            if stop.load(Ordering::Relaxed) {
                                return seen;
                            }
                        }
                    })
                })
                .collect();
            let mut i = 0u64;
            while i < 20_000 || started.load(Ordering::Relaxed) < READERS {
                let p = if i.is_multiple_of(2) {
                    Policy::NONE
                } else {
                    Policy::PREFERRED
                };
                accel::set_policy_all(p).unwrap();
                i += 1;
            }
            stop.store(true, Ordering::Relaxed);
            for r in readers {
                assert!(r.join().unwrap() > 0);
            }
        });
    }

    // Configuration strings.
    assert_eq!("none".parse(), Ok(Acceleration::None));
    assert_eq!("Required".parse(), Ok(Acceleration::Required));
    assert_eq!("prefered".parse(), Ok(Acceleration::Preferred));

    accel::set_policy_all(Policy::PREFERRED).unwrap();
}
