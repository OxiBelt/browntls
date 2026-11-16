//! Load-aware routing of key exchange and signature operations
//! (`accel::load`): the NIST curves, ML-KEM and RSA signatures.
//!
//! Routing state and policies are process-wide, so everything runs in one
//! test function (each integration test file is its own process). RSA keys
//! are generated at run time; nothing secret is committed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use browntls_crypto::Error;
use browntls_crypto::accel::load::{self, Config, Phase, StreamStatus};
use browntls_crypto::accel::{self, Acceleration, Algorithm, Policy};
use browntls_crypto::hash::HashAlgorithm;
use browntls_crypto::mlkem::{
    self, DecapsulationKey, EncapsulationKey, MlKem512, MlKem768, MlKem1024, ParameterSet,
};
use browntls_crypto::rand::{FixedRng, OsRng};
use browntls_crypto::rsa::{
    MAX_PKCS1_PRIVATE_KEY_DER_LEN, RsaPrivateKey, verify_pkcs1v15, verify_pss,
};

/// The routed families and the names of their streams, in lane order.
const STREAMS: [(Algorithm, &[&str]); 5] = [
    (Algorithm::P256, &CURVE_STREAMS),
    (Algorithm::P384, &CURVE_STREAMS),
    (Algorithm::P521, &CURVE_STREAMS),
    (
        Algorithm::MlKem,
        &[
            "keygen (512)",
            "encaps (512)",
            "decaps (512)",
            "keygen (768)",
            "encaps (768)",
            "decaps (768)",
            "keygen (1024)",
            "encaps (1024)",
            "decaps (1024)",
        ],
    ),
    (
        Algorithm::Rsa,
        &[
            "sign (2048-bit key)",
            "sign (3072-bit key)",
            "sign (4096-bit key)",
        ],
    ),
];

/// One stream per kind of operation of a curve.
const CURVE_STREAMS: [&str; 4] = ["public key", "ECDH", "ECDSA sign", "ECDSA verify"];

/// The RSA key sizes that have a stream, in lane order.
const RSA_BITS: [usize; 3] = [2048, 3072, 4096];

type Work = Box<dyn Fn() -> Vec<u8> + Send + Sync>;

/// One routed stream with deterministic work for it.
struct Case {
    alg: Algorithm,
    lane: usize,
    /// For messages, e.g. `"P-256 ECDH"`.
    label: String,
    /// Whether the operations belong to a key that remembers the backend it
    /// was created with (such a key is not routed under another policy).
    keyed: bool,
    /// A few successful operations of the stream's kind and nothing else
    /// that is routed; returns everything they computed.
    work: Work,
    /// Operations of the stream's kind that fail.
    failures: Box<dyn Fn() + Send + Sync>,
    /// `work` through keys with an explicit backend, where those exist.
    pinned: Option<Work>,
    /// Successful operations of the stream's kind whose cost is another
    /// one than the stream's, where those exist: they are routed like the
    /// others but not timed.
    untimed: Option<Box<dyn Fn() + Send + Sync>>,
}

impl Case {
    fn status(&self) -> StreamStatus {
        load::status(self.alg, self.lane).unwrap()
    }

    /// Forgets the statistics, then fixes `percent` of the stream's calls on
    /// `alternate`.
    fn fix(&self, alternate: usize, percent: u8) -> StreamStatus {
        restart(Config::DEFAULT);
        load::set_fixed(self.alg, self.lane, alternate, percent).unwrap();
        let s = self.status();
        assert_eq!((s.phase, s.shifted_percent), (Phase::Fixed, percent), "{s}");
        assert!(s.alternate.is_some_and(|a| a != s.primary), "{s}");
        s
    }

    /// The measured costs of the primary and of the alternate.
    fn costs(&self) -> (Option<u64>, Option<u64>) {
        let s = self.status();
        (s.primary_cost, s.alternate_cost)
    }
}

/// Forgets every stream's statistics and shares.
fn restart(config: Config) {
    load::disable();
    load::enable(config).unwrap();
}

fn message(i: usize) -> Vec<u8> {
    format!("message number {i} of the routed operations").into_bytes()
}

/// The four streams of one curve.
macro_rules! curve_cases {
    ($cases:expr, $curve:ident, $alg:expr) => {{
        use browntls_crypto::nist::$curve as c;
        const OPS: usize = 4;
        let alg: Algorithm = $alg;
        // The top byte keeps the scalar below the group order (the top byte
        // of P-521 holds a single bit).
        fn scalar(i: usize) -> [u8; c::FIELD_LEN] {
            let mut s: [u8; c::FIELD_LEN] = core::array::from_fn(|j| (i * 29 + j * 7 + 1) as u8);
            s[0] = 1;
            s
        }
        let keys: Vec<c::SecretKey> = (0..OPS)
            .map(|i| c::SecretKey::from_bytes(&scalar(i)).unwrap())
            .collect();
        let peers: Vec<c::PublicKey> = keys.iter().rev().map(|k| k.public_key()).collect();
        let signer = c::SigningKey::new(keys[0].clone());
        let public = signer.verifying_key();
        let signatures: Vec<c::Signature> = (0..OPS)
            .map(|i| signer.sign_deterministic(c::TLS_HASH, &message(i)).unwrap())
            .collect();

        $cases.push(Case {
            alg,
            lane: 0,
            label: format!("{alg} public key"),
            keyed: false,
            work: Box::new(|| {
                (0..OPS)
                    .flat_map(|i| {
                        let key = c::SecretKey::from_bytes(&scalar(i)).unwrap();
                        key.public_key().to_uncompressed()
                    })
                    .collect()
            }),
            // A scalar outside [1, n - 1] is refused before any multiplication.
            failures: Box::new(|| {
                for bad in [&[0u8; c::FIELD_LEN][..], &[0xff; c::FIELD_LEN], &[1; 5]] {
                    assert_eq!(c::SecretKey::from_bytes(bad).err(), Some(Error::InvalidKey));
                }
            }),
            pinned: None,
            untimed: None,
        });
        $cases.push(Case {
            alg,
            lane: 1,
            label: format!("{alg} ECDH"),
            keyed: false,
            work: {
                let (keys, peers) = (keys.clone(), peers.clone());
                Box::new(move || {
                    keys.iter()
                        .zip(&peers)
                        .flat_map(|(key, peer)| key.diffie_hellman(peer).unwrap())
                        .collect()
                })
            },
            // A point that is not on the curve never becomes a peer key, so
            // it does not reach the multiplication.
            failures: {
                let peers = peers.clone();
                Box::new(move || {
                    let mut off_curve = peers[0].to_uncompressed();
                    off_curve[c::UNCOMPRESSED_LEN - 1] ^= 1;
                    assert_eq!(
                        c::PublicKey::from_sec1_bytes(&off_curve),
                        Err(Error::InvalidKey)
                    );
                    assert!(c::PublicKey::from_sec1_bytes(&[0]).is_err());
                    assert!(c::PublicKey::from_sec1_bytes(&off_curve[..7]).is_err());
                })
            },
            pinned: None,
            untimed: None,
        });
        $cases.push(Case {
            alg,
            lane: 2,
            label: format!("{alg} ECDSA sign"),
            keyed: false,
            work: {
                let signer = signer.clone();
                Box::new(move || {
                    (0..OPS)
                        .flat_map(|i| {
                            let sig = signer.sign_deterministic(c::TLS_HASH, &message(i));
                            sig.unwrap().fixed().to_vec()
                        })
                        .collect()
                })
            },
            failures: {
                let signer = signer.clone();
                Box::new(move || {
                    assert_eq!(
                        signer.sign_prehashed(c::TLS_HASH, &[0; 7], None).err(),
                        Some(Error::InvalidLength)
                    );
                })
            },
            pinned: None,
            // With another hash than the curve's own the nonce derivation
            // costs differently. Each curve meets a shorter or a longer
            // hash here, and a SHA-3 one.
            untimed: {
                let others: Vec<(HashAlgorithm, c::Signature)> = [
                    HashAlgorithm::Sha256,
                    HashAlgorithm::Sha384,
                    HashAlgorithm::Sha512,
                    HashAlgorithm::Sha3_256,
                ]
                .into_iter()
                .filter(|hash| *hash != c::TLS_HASH)
                .map(|hash| (hash, signer.sign_deterministic(hash, b"other").unwrap()))
                .collect();
                Some(Box::new(move || {
                    for (hash, sig) in &others {
                        assert_eq!(signer.sign_deterministic(*hash, b"other").unwrap(), *sig);
                    }
                }))
            },
        });
        $cases.push(Case {
            alg,
            lane: 3,
            label: format!("{alg} ECDSA verify"),
            keyed: false,
            work: {
                let signatures = signatures.clone();
                Box::new(move || {
                    let mut accepted = Vec::new();
                    for (i, sig) in signatures.iter().enumerate() {
                        let msg = message(i);
                        c::verify(&public, c::TLS_HASH, &msg, sig.as_der()).unwrap();
                        c::verify_fixed(&public, c::TLS_HASH, &msg, sig.fixed()).unwrap();
                        accepted.extend_from_slice(sig.fixed());
                    }
                    accepted
                })
            },
            // Rejected signatures: over another message and with a changed
            // `s` (both run the whole verification), out of range and
            // malformed (both return early).
            failures: Box::new(move || {
                for (i, sig) in signatures.iter().enumerate() {
                    let msg = message(i);
                    let rejected = Err(Error::InvalidSignature);
                    assert_eq!(
                        c::verify(&public, c::TLS_HASH, b"another message", sig.as_der()),
                        rejected
                    );
                    let mut forged = *sig.fixed();
                    forged[c::SIGNATURE_FIXED_LEN - 1] ^= 1;
                    assert_eq!(
                        c::verify_fixed(&public, c::TLS_HASH, &msg, &forged),
                        rejected
                    );
                    let zero = [0u8; c::SIGNATURE_FIXED_LEN];
                    assert_eq!(c::verify_fixed(&public, c::TLS_HASH, &msg, &zero), rejected);
                    assert_eq!(c::verify(&public, c::TLS_HASH, &msg, &[0x30, 0]), rejected);
                }
            }),
            pinned: None,
            untimed: None,
        });
    }};
}

/// The three streams of one ML-KEM parameter set (`set` counts them).
fn mlkem_cases<P: ParameterSet>(cases: &mut Vec<Case>, set: usize) {
    const OPS: usize = 4;
    fn seed(i: usize) -> [u8; mlkem::SEED_LEN] {
        core::array::from_fn(|j| (i * 17 + j * 3 + 1) as u8)
    }
    fn coins(i: usize) -> [u8; 32] {
        core::array::from_fn(|j| (i * 5 + j * 11 + 2) as u8)
    }
    /// What a generated key pair is, byte for byte.
    fn encoded<P: ParameterSet>(dk: &DecapsulationKey<P>) -> Vec<u8> {
        let mut out = dk.encapsulation_key().as_bytes().to_vec();
        out.extend_from_slice(dk.to_bytes().as_ref());
        out.extend_from_slice(dk.seed().unwrap());
        out
    }
    fn encapsulated<P: ParameterSet>(ek: &EncapsulationKey<P>) -> Vec<u8> {
        (0..OPS)
            .flat_map(|i| {
                let (ct, shared) = ek.encapsulate_deterministic(&coins(i));
                [ct.as_ref(), &shared[..]].concat()
            })
            .collect()
    }
    /// The secrets of every ciphertext and of a damaged copy of each, which
    /// implicit rejection answers with another secret at the same cost.
    fn decapsulated<P: ParameterSet>(
        dk: &DecapsulationKey<P>,
        ciphertexts: &[(P::Ciphertext, [u8; 32])],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for (ct, shared) in ciphertexts {
            let secret = dk.decapsulate(ct.as_ref()).unwrap();
            assert_eq!(&secret, shared);
            let mut damaged = *ct;
            damaged.as_mut()[0] ^= 1;
            let rejected = dk.decapsulate(damaged.as_ref()).unwrap();
            assert_ne!(rejected, secret);
            out.extend_from_slice(&secret);
            out.extend_from_slice(&rejected);
        }
        out
    }

    let alg = Algorithm::MlKem;
    let own = mlkem::Backend::detect();
    let dk = Arc::new(DecapsulationKey::<P>::from_seed(&seed(0)));
    let ek = dk.encapsulation_key().clone();
    assert_eq!((dk.backend(), ek.backend()), (own, own));
    let pinned_dk = Arc::new(DecapsulationKey::<P>::from_seed_with_backend(&seed(0), own).unwrap());
    let pinned_ek = ek.clone().with_backend(own).unwrap();
    let ciphertexts: Arc<Vec<(P::Ciphertext, [u8; 32])>> = Arc::new(
        (0..OPS)
            .map(|i| pinned_ek.encapsulate_deterministic(&coins(i)))
            .collect(),
    );

    cases.push(Case {
        alg,
        lane: 3 * set,
        label: format!("{} keygen", P::NAME),
        keyed: false,
        work: Box::new(|| {
            (0..OPS)
                .flat_map(|i| {
                    let s = seed(i);
                    let (d, z) = s.split_at(32);
                    let (dk, ek) = DecapsulationKey::<P>::generate_deterministic(
                        d.try_into().unwrap(),
                        z.try_into().unwrap(),
                    );
                    // The key belongs to the backend the policy selects,
                    // wherever routing had it computed.
                    let own = mlkem::Backend::detect();
                    assert_eq!((dk.backend(), ek.backend()), (own, own));
                    encoded(&dk)
                })
                .collect()
        }),
        // Key generation from a seed cannot fail; parsing a key is not routed.
        failures: Box::new(|| {
            assert_eq!(
                DecapsulationKey::<P>::from_bytes(&[0; 9]).err(),
                Some(Error::InvalidLength)
            );
        }),
        pinned: Some(Box::new(|| {
            (0..OPS)
                .flat_map(|i| {
                    let own = mlkem::Backend::detect();
                    let dk = DecapsulationKey::<P>::from_seed_with_backend(&seed(i), own).unwrap();
                    encoded(&dk)
                })
                .collect()
        })),
        untimed: None,
    });
    cases.push(Case {
        alg,
        lane: 3 * set + 1,
        label: format!("{} encaps", P::NAME),
        keyed: true,
        work: {
            let ek = ek.clone();
            Box::new(move || encapsulated(&ek))
        },
        // Encapsulation cannot fail; a malformed key is refused when parsed.
        failures: {
            let ek = ek.clone();
            Box::new(move || {
                assert_eq!(
                    EncapsulationKey::<P>::from_bytes(&ek.as_bytes()[1..]).err(),
                    Some(Error::InvalidLength)
                );
                let mut unreduced = ek.as_bytes().to_vec();
                unreduced[..2].fill(0xff);
                assert_eq!(
                    EncapsulationKey::<P>::from_bytes(&unreduced).err(),
                    Some(Error::InvalidKey)
                );
            })
        },
        pinned: Some(Box::new(move || encapsulated(&pinned_ek))),
        untimed: None,
    });
    cases.push(Case {
        alg,
        lane: 3 * set + 2,
        label: format!("{} decaps", P::NAME),
        keyed: true,
        work: {
            let (dk, ciphertexts) = (dk.clone(), ciphertexts.clone());
            Box::new(move || decapsulated(&dk, &ciphertexts))
        },
        failures: {
            let (dk, ciphertexts) = (dk.clone(), ciphertexts.clone());
            Box::new(move || {
                let ct = ciphertexts[0].0.as_ref();
                for wrong in [&ct[1..], &[], &[ct, &[0]].concat()] {
                    assert_eq!(dk.decapsulate(wrong), Err(Error::InvalidLength));
                }
            })
        },
        pinned: Some(Box::new(move || decapsulated(&pinned_dk, &ciphertexts))),
        untimed: None,
    });
}

/// The stream of each RSA key size, with keys loaded from `ders`.
fn rsa_cases(cases: &mut Vec<Case>, ders: &[Vec<u8>]) {
    /// A PKCS #1 v1.5 and a PSS signature. The first is deterministic (the
    /// blinding does not show in the result), the second is with a fixed
    /// source for its salt and blinding entropy.
    fn signatures(key: &RsaPrivateKey) -> Vec<u8> {
        let k = key.modulus_len_bytes();
        let mut out = vec![0u8; 2 * k];
        let (pkcs1, pss) = out.split_at_mut(k);
        let msg = message(k);
        key.sign_pkcs1v15(HashAlgorithm::Sha256, &msg, pkcs1)
            .unwrap();
        verify_pkcs1v15(key.public_key(), HashAlgorithm::Sha256, &msg, pkcs1).unwrap();
        let random = [0x5a; 48 + 32];
        key.sign_pss(HashAlgorithm::Sha384, &msg, &FixedRng::new(&random), pss)
            .unwrap();
        verify_pss(key.public_key(), HashAlgorithm::Sha384, &msg, pss).unwrap();
        out
    }

    for (lane, (bits, der)) in RSA_BITS.into_iter().zip(ders).enumerate() {
        let key = Arc::new(RsaPrivateKey::from_pkcs1_der(der).unwrap());
        assert_eq!(key.modulus_bits(), bits);
        cases.push(Case {
            alg: Algorithm::Rsa,
            lane,
            label: format!("RSA-{bits} sign"),
            keyed: true,
            work: {
                let key = key.clone();
                Box::new(move || signatures(&key))
            },
            // A signature that does not fit its buffer is refused before
            // the private-key operation.
            failures: Box::new(move || {
                let mut short = vec![0u8; key.modulus_len_bytes() - 1];
                assert_eq!(
                    key.sign_pkcs1v15(HashAlgorithm::Sha256, b"m", &mut short),
                    Err(Error::InvalidLength)
                );
                assert_eq!(
                    key.sign_pss(HashAlgorithm::Sha256, b"m", &OsRng, &mut short),
                    Err(Error::InvalidLength)
                );
            }),
            pinned: None,
            untimed: None,
        });
    }
}

/// A case for every routed stream, in the order of [`STREAMS`], with keys
/// created now: under the policies and the routing configuration in force.
fn cases(rsa_ders: &[Vec<u8>]) -> Vec<Case> {
    let mut cases = Vec::new();
    curve_cases!(cases, p256, Algorithm::P256);
    curve_cases!(cases, p384, Algorithm::P384);
    curve_cases!(cases, p521, Algorithm::P521);
    mlkem_cases::<MlKem512>(&mut cases, 0);
    mlkem_cases::<MlKem768>(&mut cases, 1);
    mlkem_cases::<MlKem1024>(&mut cases, 2);
    rsa_cases(&mut cases, rsa_ders);
    let streams: Vec<(Algorithm, usize)> = STREAMS
        .iter()
        .flat_map(|(alg, names)| (0..names.len()).map(|lane| (*alg, lane)))
        .collect();
    let covered: Vec<(Algorithm, usize)> = cases.iter().map(|c| (c.alg, c.lane)).collect();
    assert_eq!(covered, streams, "one case per routed stream");
    cases
}

fn set_policies(policy: Policy) {
    for (alg, _) in STREAMS {
        accel::set_policy(alg, policy).unwrap();
    }
}

#[test]
fn load_aware_key_exchange_and_signature_routing() {
    // The routed streams, by name. They exist whatever the CPU offers.
    for (alg, names) in STREAMS {
        assert_eq!(load::lanes(alg), names.len(), "{alg}");
        for (lane, name) in names.iter().enumerate() {
            let s = load::status(alg, lane).unwrap();
            assert_eq!((s.algorithm, s.lane), (alg, lane));
            assert_eq!((s.name, s.unit), (*name, "op"), "{alg} lane {lane}");
        }
        assert_eq!(load::status(alg, names.len()), None);
    }
    assert_eq!(load::config(), None);
    let primaries = STREAMS.map(|(alg, _)| accel::status(alg).backend);
    let primary = |alg: Algorithm| {
        let family = STREAMS.iter().position(|(a, _)| *a == alg).unwrap();
        primaries[family]
    };

    let rsa_ders: Vec<Vec<u8>> = RSA_BITS
        .iter()
        .map(|&bits| {
            let key = RsaPrivateKey::generate(bits, &OsRng).unwrap();
            let mut der = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
            let len = key.to_pkcs1_der(&mut der).unwrap();
            der.truncate(len);
            der
        })
        .collect();

    // What every stream computes, without routing.
    let cases = cases(&rsa_ders);
    let baselines: Vec<Vec<u8>> = cases.iter().map(|c| (c.work)()).collect();
    for (c, baseline) in cases.iter().zip(&baselines) {
        assert!(!baseline.is_empty(), "{}", c.label);
        if let Some(pinned) = &c.pinned {
            assert_eq!(&pinned(), baseline, "{}", c.label);
        }
        (c.failures)();
        let s = c.status();
        assert_eq!(s.primary_cost, None, "nothing is timed while disabled");
        assert_eq!(
            load::set_fixed(c.alg, c.lane, 0, 50),
            Err(Error::Unsupported)
        );
    }

    // Enabled and steady: the same results, and every operation is timed.
    load::enable(Config::DEFAULT).unwrap();
    for (c, baseline) in cases.iter().zip(&baselines) {
        assert_eq!(&(c.work)(), baseline, "{}", c.label);
        let s = c.status();
        println!("{s}");
        assert!(s.primary_cost.is_some(), "{s}");
        assert_eq!(s.primary, primary(c.alg), "{s}");
        // The portable code follows every accelerated backend, and nothing
        // follows the portable code.
        assert_eq!(s.alternates > 0, accel::status(c.alg).accelerated(), "{s}");
        assert_eq!(
            load::set_fixed(c.alg, c.lane, s.alternates, 50),
            Err(Error::Unsupported)
        );
    }

    // Operations that fail, operations of keys with an explicit backend
    // and operations of another cost than their stream's are not timed.
    restart(Config::DEFAULT);
    for (c, baseline) in cases.iter().zip(&baselines) {
        for _ in 0..4 {
            (c.failures)();
        }
        if let Some(pinned) = &c.pinned {
            assert_eq!(&pinned(), baseline, "{}", c.label);
        }
        if let Some(untimed) = &c.untimed {
            untimed();
        }
        assert_eq!(c.costs(), (None, None), "{}", c.label);
    }

    // Fixed shares on every alternate. The statistics show where the
    // operations ran: all of them on the alternate at 100%, none at 0%, on
    // both in between; the results are the same wherever they ran.
    for (c, baseline) in cases.iter().zip(&baselines) {
        for alternate in 0..c.status().alternates {
            for percent in [100, 50, 1, 0] {
                let fixed = c.fix(alternate, percent);
                assert_eq!(&(c.work)(), baseline, "{fixed}");
                match percent {
                    100 => {
                        let (primary, alternate) = c.costs();
                        assert!(primary.is_none() && alternate.is_some(), "{}", c.status());
                    }
                    0 => {
                        let (primary, alternate) = c.costs();
                        assert!(primary.is_some() && alternate.is_none(), "{}", c.status());
                    }
                    50 => {
                        // Which calls move is random: half of them.
                        let both = |c: &Case| matches!(c.costs(), (Some(_), Some(_)));
                        for _ in 0..64 {
                            if both(c) {
                                break;
                            }
                            assert_eq!(&(c.work)(), baseline, "{fixed}");
                        }
                        assert!(both(c), "{}", c.status());
                    }
                    _ => {}
                }
                println!("{}: {}", c.label, c.status());
            }
            // With every call fixed on the alternate, a failed operation
            // is not timed there either, a key with an explicit backend
            // stays on that backend, and an operation of another cost
            // gives the same result untimed: the alternate's cost is not
            // measured.
            c.fix(alternate, 100);
            for _ in 0..4 {
                (c.failures)();
            }
            if let Some(pinned) = &c.pinned {
                assert_eq!(&pinned(), baseline, "{}", c.label);
            }
            if let Some(untimed) = &c.untimed {
                untimed();
            }
            assert_eq!(c.costs(), (None, None), "{}", c.status());
        }
        load::clear_fixed(c.alg, c.lane);
        assert_eq!(c.status().phase, Phase::Steady);
    }

    // Without the portable backend as an alternate, the accelerated ones
    // that remain still take the operations.
    restart(Config {
        portable: false,
        ..Config::DEFAULT
    });
    for (c, baseline) in cases.iter().zip(&baselines) {
        let alternates = c.status().alternates;
        for alternate in 0..alternates {
            load::set_fixed(c.alg, c.lane, alternate, 100).unwrap();
            assert_ne!(c.status().alternate, Some("portable"));
            assert_eq!(&(c.work)(), baseline, "{}", c.status());
            assert!(c.costs().1.is_some(), "{}", c.status());
        }
        if alternates == 0 {
            assert_eq!(
                load::set_fixed(c.alg, c.lane, 0, 100),
                Err(Error::Unsupported)
            );
            assert_eq!(&(c.work)(), baseline, "{}", c.status());
        }
    }
    restart(Config::DEFAULT);

    // A policy that leaves only the portable code removes the alternates:
    // a share fixed before is ignored, the results stay the same, and the
    // share is in force again under the policy it was made for.
    for c in &cases {
        if c.status().alternates > 0 {
            load::set_fixed(c.alg, c.lane, 0, 100).unwrap();
        }
    }
    set_policies(Policy::NONE);
    for (c, baseline) in cases.iter().zip(&baselines) {
        let s = c.status();
        assert_eq!((s.primary, s.alternates), ("portable", 0), "{s}");
        if primary(c.alg) != "portable" {
            assert_eq!((s.phase, s.alternate), (Phase::Steady, None), "{s}");
        }
        assert_eq!(
            load::set_fixed(c.alg, c.lane, 0, 50),
            Err(Error::Unsupported)
        );
        assert_eq!(&(c.work)(), baseline, "{s}");
        assert_eq!(c.status().alternate_cost, None, "{s}");
    }
    set_policies(Policy::PREFERRED);
    for c in &cases {
        let s = c.status();
        if s.alternates > 0 {
            assert_eq!((s.phase, s.shifted_percent), (Phase::Fixed, 100), "{s}");
        }
    }

    // Other policies. A call that selects its backend per call follows the
    // new policy at once. A key keeps the backend it was created with: where
    // the policy now selects another one, the key is not routed (its
    // operations are not even timed), while a key created under the policy
    // is, to every alternate the policy leaves.
    let mut last = None;
    for policy in [
        Policy::new(Acceleration::None, Acceleration::Preferred),
        Policy::new(Acceleration::Preferred, Acceleration::None),
        Policy::NONE,
    ] {
        set_policies(policy);
        let fresh = self::cases(&rsa_ders);
        restart(Config::DEFAULT);
        for ((old, new), baseline) in cases.iter().zip(&fresh).zip(&baselines) {
            let changed = accel::status(old.alg).backend != primary(old.alg);
            let left_alone = changed && old.keyed;
            assert_eq!(&(old.work)(), baseline, "{} under {policy}", old.label);
            let s = old.status();
            assert_eq!(s.primary, accel::status(old.alg).backend, "{s}");
            assert_eq!(s.primary_cost.is_none(), left_alone, "{policy}: {s}");
            assert_eq!(&(new.work)(), baseline, "{} under {policy}", new.label);
            assert!(new.status().primary_cost.is_some(), "{policy}: {s}");
            for alternate in 0..s.alternates {
                new.fix(alternate, 100);
                assert_eq!(&(old.work)(), baseline, "{} under {policy}", old.label);
                if left_alone {
                    assert_eq!(old.costs(), (None, None), "{policy}: {}", old.status());
                }
                assert_eq!(&(new.work)(), baseline, "{} under {policy}", new.label);
                let (primary, alternate) = new.costs();
                assert!(primary.is_none() && alternate.is_some(), "{}", new.status());
                println!("{} under {policy}: {}", new.label, new.status());
            }
            restart(Config::DEFAULT);
        }
        last = Some(fresh);
    }
    // Back under the default policy, the keys created under the last one
    // (portable code only) are the ones left alone.
    set_policies(Policy::PREFERRED);
    let portable_keys = last.unwrap();
    for ((new, old), baseline) in cases.iter().zip(&portable_keys).zip(&baselines) {
        let left_alone = old.keyed && primary(old.alg) != "portable";
        for alternate in 0..new.status().alternates {
            new.fix(alternate, 100);
            assert_eq!(&(old.work)(), baseline, "{}", old.label);
            if left_alone {
                assert_eq!(old.costs(), (None, None), "{}", old.status());
            }
        }
    }
    restart(Config::DEFAULT);

    // Concurrent use: threads running every operation while shares change,
    // and while routing is switched off and on, compute the same results.
    // The shares keep changing until every worker has completed several
    // rounds under them.
    {
        const WORKERS: usize = 4;
        const ROUNDS_EACH: usize = 3;
        let stop = AtomicBool::new(false);
        let rounds = [const { AtomicUsize::new(0) }; WORKERS];
        let alternates: Vec<usize> = cases.iter().map(|c| c.status().alternates).collect();
        std::thread::scope(|scope| {
            for done in &rounds {
                let (stop, cases, baselines) = (&stop, &cases, &baselines);
                scope.spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        for (c, baseline) in cases.iter().zip(baselines) {
                            assert_eq!(&(c.work)(), baseline, "{}", c.label);
                            if let Some(pinned) = &c.pinned {
                                assert_eq!(&pinned(), baseline, "{}", c.label);
                            }
                            if let Some(untimed) = &c.untimed {
                                untimed();
                            }
                            (c.failures)();
                        }
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            let mut i = 0usize;
            while rounds
                .iter()
                .any(|r| r.load(Ordering::Relaxed) < ROUNDS_EACH)
            {
                for (c, &alternates) in cases.iter().zip(&alternates) {
                    if alternates > 0 {
                        let percent = ((i + c.lane) % 101) as u8;
                        let _ = load::set_fixed(c.alg, c.lane, i % alternates, percent);
                    }
                    if (i + c.lane).is_multiple_of(97) {
                        load::clear_fixed(c.alg, c.lane);
                    }
                }
                if i % 500 == 499 {
                    restart(Config {
                        portable: i % 1000 == 499,
                        ..Config::DEFAULT
                    });
                }
                i += 1;
                std::thread::yield_now();
            }
            stop.store(true, Ordering::Relaxed);
        });
    }

    // Disabling forgets shares and statistics, and everything still
    // computes the same.
    load::enable(Config::DEFAULT).unwrap();
    for c in &cases {
        if c.status().alternates > 0 {
            load::set_fixed(c.alg, c.lane, 0, 100).unwrap();
        }
    }
    load::disable();
    assert_eq!(load::config(), None);
    for (c, baseline) in cases.iter().zip(&baselines) {
        assert_eq!(&(c.work)(), baseline, "{}", c.label);
        let s = c.status();
        assert_eq!(
            (s.phase, s.shifted_percent, s.primary_cost, s.baseline_cost),
            (Phase::Steady, 0, None, None),
            "{s}"
        );
    }
}
