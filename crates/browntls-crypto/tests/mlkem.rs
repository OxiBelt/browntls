//! ML-KEM integration tests: differential against the RustCrypto `ml-kem`
//! crate on every available backend, Wycheproof vectors, key-validation
//! negative tests and an ignored throughput test.
#![allow(clippy::unwrap_used, clippy::panic, clippy::cast_possible_truncation)]

use browntls_crypto::Error;
use browntls_crypto::mlkem::{
    Backend, DecapsulationKey, EncapsulationKey, MlKem512, MlKem768, MlKem1024, ParameterSet,
};
use browntls_crypto::rand::{FixedRng, OsRng};
use ml_kem::{Decapsulate, KeyExport};
use serde_json::Value;

/// splitmix64 (test data only).
struct TestRng(u64);

impl TestRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.next() as u8;
        }
        out
    }
}

fn backends() -> Vec<Backend> {
    let v: Vec<_> = Backend::available().collect();
    eprintln!("ML-KEM backends under test: {v:?}");
    v
}

macro_rules! differential {
    ($name:ident, $ours:ty, $theirs:ty, $iters:expr) => {
        #[test]
        fn $name() {
            let mut rng = TestRng(0x6d6c_6b65_6d00 + <$ours>::K as u64);
            let backends = backends();
            for iter in 0..$iters {
                let mut seed: [u8; 64] = rng.bytes();
                let mut m: [u8; 32] = rng.bytes();
                if iter == 0 {
                    seed = [0; 64];
                    m = [0; 32];
                } else if iter == 1 {
                    seed = [0xff; 64];
                    m = [0xff; 32];
                }
                let rc_dk = ml_kem::DecapsulationKey::<$theirs>::from_seed(seed.into());
                let rc_ek = rc_dk.encapsulation_key().clone();
                let rc_ek_bytes = rc_ek.to_bytes();
                #[allow(deprecated)]
                let rc_dk_bytes = ml_kem::ExpandedKeyEncoding::to_expanded_bytes(&rc_dk);
                let (rc_ct, rc_ss) = rc_ek.encapsulate_deterministic(&m.into());

                // Tampered and random ciphertexts (implicit rejection).
                let mut bad_cts = Vec::new();
                for _ in 0..4 {
                    let mut bad = rc_ct.to_vec();
                    let pos = (rng.next() as usize) % bad.len();
                    bad[pos] ^= 1 << (rng.next() % 8);
                    bad_cts.push(bad);
                }
                bad_cts.push((0..rc_ct.len()).map(|_| rng.next() as u8).collect());
                let mut last = rc_ct.to_vec();
                *last.last_mut().unwrap() ^= 0x80;
                bad_cts.push(last);
                let rc_rejects: Vec<_> = bad_cts
                    .iter()
                    .map(|c| rc_dk.decapsulate_slice(c).unwrap())
                    .collect();

                for &b in &backends {
                    let dk = DecapsulationKey::<$ours>::from_seed_with_backend(&seed, b).unwrap();
                    assert_eq!(dk.backend(), b);
                    assert_eq!(dk.seed(), Some(&seed));
                    let ek = dk.encapsulation_key();
                    assert_eq!(ek.as_bytes(), rc_ek_bytes.as_slice(), "{b:?} ek");
                    assert_eq!(dk.to_bytes().as_ref(), rc_dk_bytes.as_slice(), "{b:?} dk");

                    let (ct, ss) = ek.encapsulate_deterministic(&m);
                    assert_eq!(ct.as_ref(), rc_ct.as_slice(), "{b:?} ct");
                    assert_eq!(ss.as_slice(), rc_ss.as_slice(), "{b:?} ss");
                    assert_eq!(dk.decapsulate(&ct).unwrap(), ss);

                    for (bad, rc_k) in bad_cts.iter().zip(&rc_rejects) {
                        let k = dk.decapsulate(bad).unwrap();
                        assert_eq!(k.as_slice(), rc_k.as_slice(), "{b:?} reject");
                        assert_ne!(k, ss);
                    }

                    // Expanded-key and public-key parsing round trips.
                    let dk2 = DecapsulationKey::<$ours>::from_bytes(dk.to_bytes().as_ref())
                        .unwrap()
                        .with_backend(b)
                        .unwrap();
                    assert_eq!(dk2.seed(), None);
                    assert_eq!(dk2.decapsulate(&ct).unwrap(), ss);
                    assert_eq!(
                        dk2.decapsulate(&bad_cts[0]).unwrap().as_slice(),
                        rc_rejects[0].as_slice()
                    );
                    let ek2 = EncapsulationKey::<$ours>::from_bytes(ek.as_bytes())
                        .unwrap()
                        .with_backend(b)
                        .unwrap();
                    assert_eq!(&ek2, ek);
                    assert_eq!(ek2.encapsulate_deterministic(&m), (ct, ss));

                    let (dk3, ek3) = DecapsulationKey::<$ours>::generate_deterministic(
                        seed[..32].try_into().unwrap(),
                        seed[32..].try_into().unwrap(),
                    );
                    assert_eq!(ek3.as_bytes(), ek.as_bytes());
                    assert_eq!(dk3.to_bytes().as_ref(), dk.to_bytes().as_ref());
                }
            }

            // Randomised round trips in both directions.
            for &b in &backends {
                let (dk, ek) = DecapsulationKey::<$ours>::generate(&OsRng).unwrap();
                let (dk, ek) = (dk.with_backend(b).unwrap(), ek.with_backend(b).unwrap());
                let rc_dk =
                    ml_kem::DecapsulationKey::<$theirs>::from_seed((*dk.seed().unwrap()).into());
                let (ct, ss) = ek.encapsulate(&OsRng).unwrap();
                assert_eq!(
                    rc_dk.decapsulate_slice(&ct).unwrap().as_slice(),
                    ss.as_slice()
                );
                let rc_ek = rc_dk.encapsulation_key();
                let (rc_ct, rc_ss) = rc_ek.encapsulate_deterministic(&rng.bytes::<32>().into());
                assert_eq!(dk.decapsulate(&rc_ct).unwrap().as_slice(), rc_ss.as_slice());
            }
        }
    };
}

differential!(differential_mlkem512, MlKem512, ml_kem::MlKem512, 40);
differential!(differential_mlkem768, MlKem768, ml_kem::MlKem768, 40);
differential!(differential_mlkem1024, MlKem1024, ml_kem::MlKem1024, 40);

// ---------------------------------------------------------------------------
// Wycheproof.
// ---------------------------------------------------------------------------

fn load(name: &str) -> Value {
    let path = format!(
        "{}/tests/data/wycheproof/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn tests_of(v: &Value) -> impl Iterator<Item = &Value> {
    v["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap())
}

fn hex_field(t: &Value, k: &str) -> Vec<u8> {
    hex::decode(t[k].as_str().unwrap_or("")).unwrap()
}

fn is_valid(t: &Value) -> bool {
    match t["result"].as_str().unwrap() {
        "valid" => true,
        "invalid" => false,
        other => panic!("unexpected result {other}"),
    }
}

/// `mlkem_*_test.json`: seed -> ek, decapsulation (incl. implicit rejection).
fn wycheproof_decaps<P: ParameterSet>(file: &str) {
    let v = load(file);
    let mut count = 0;
    for b in backends() {
        for t in tests_of(&v) {
            let seed = hex_field(t, "seed");
            let c = hex_field(t, "c");
            let Ok(seed) = <[u8; 64]>::try_from(seed.as_slice()) else {
                assert!(!is_valid(t), "tcId {}", t["tcId"]);
                continue;
            };
            let dk = DecapsulationKey::<P>::from_seed_with_backend(&seed, b).unwrap();
            assert_eq!(
                dk.encapsulation_key().as_bytes(),
                hex_field(t, "ek"),
                "tcId {}",
                t["tcId"]
            );
            match dk.decapsulate(&c) {
                Ok(k) => {
                    assert!(is_valid(t), "tcId {}", t["tcId"]);
                    assert_eq!(k.as_slice(), hex_field(t, "K"), "tcId {}", t["tcId"]);
                }
                Err(e) => {
                    assert_eq!(e, Error::InvalidLength);
                    assert!(!is_valid(t), "tcId {}", t["tcId"]);
                }
            }
            count += 1;
        }
    }
    assert!(count > 100);
}

/// `mlkem_*_encaps_test.json`: ek validation and deterministic encapsulation.
fn wycheproof_encaps<P: ParameterSet>(file: &str) {
    let v = load(file);
    let mut count = 0;
    for b in backends() {
        for t in tests_of(&v) {
            let ek = hex_field(t, "ek");
            match EncapsulationKey::<P>::from_bytes(&ek) {
                Err(_) => assert!(!is_valid(t), "tcId {}", t["tcId"]),
                Ok(ek) => {
                    assert!(is_valid(t), "tcId {}", t["tcId"]);
                    let ek = ek.with_backend(b).unwrap();
                    let m: [u8; 32] = hex_field(t, "m").try_into().unwrap();
                    let (c, k) = ek.encapsulate_deterministic(&m);
                    assert_eq!(c.as_ref(), hex_field(t, "c"), "tcId {}", t["tcId"]);
                    assert_eq!(k.as_slice(), hex_field(t, "K"), "tcId {}", t["tcId"]);
                }
            }
            count += 1;
        }
    }
    assert!(count > 100);
}

/// `mlkem_*_semi_expanded_decaps_test.json`: expanded-key validation.
fn wycheproof_expanded<P: ParameterSet>(file: &str) {
    let v = load(file);
    for b in backends() {
        for t in tests_of(&v) {
            let id = &t["tcId"];
            let result = DecapsulationKey::<P>::from_bytes(&hex_field(t, "dk"))
                .and_then(|dk| dk.with_backend(b))
                .and_then(|dk| {
                    assert_eq!(dk.encapsulation_key().as_bytes(), hex_field(t, "ek"));
                    dk.decapsulate(&hex_field(t, "c"))
                });
            match result {
                Ok(k) => {
                    assert!(is_valid(t), "tcId {id}");
                    assert_eq!(k.as_slice(), hex_field(t, "K"), "tcId {id}");
                }
                Err(_) => assert!(!is_valid(t), "tcId {id}"),
            }
        }
    }
}

#[test]
fn wycheproof_mlkem512() {
    wycheproof_decaps::<MlKem512>("mlkem_512_test.json");
    wycheproof_encaps::<MlKem512>("mlkem_512_encaps_test.json");
    wycheproof_expanded::<MlKem512>("mlkem_512_semi_expanded_decaps_test.json");
}

#[test]
fn wycheproof_mlkem768() {
    wycheproof_decaps::<MlKem768>("mlkem_768_test.json");
    wycheproof_encaps::<MlKem768>("mlkem_768_encaps_test.json");
    wycheproof_expanded::<MlKem768>("mlkem_768_semi_expanded_decaps_test.json");
}

#[test]
fn wycheproof_mlkem1024() {
    wycheproof_decaps::<MlKem1024>("mlkem_1024_test.json");
    wycheproof_encaps::<MlKem1024>("mlkem_1024_encaps_test.json");
    wycheproof_expanded::<MlKem1024>("mlkem_1024_semi_expanded_decaps_test.json");
}

// ---------------------------------------------------------------------------
// Key validation and API edge cases.
// ---------------------------------------------------------------------------

/// Sets the 12-bit coefficient `i` of an encoded vector to `val`.
fn set12(bytes: &mut [u8], i: usize, val: u16) {
    let off = 3 * (i / 2);
    if i.is_multiple_of(2) {
        bytes[off] = val as u8;
        bytes[off + 1] = (bytes[off + 1] & 0xf0) | (val >> 8) as u8;
    } else {
        bytes[off + 1] = (bytes[off + 1] & 0x0f) | ((val & 0xf) << 4) as u8;
        bytes[off + 2] = (val >> 4) as u8;
    }
}

fn validation<P: ParameterSet>() {
    let (dk, ek) = DecapsulationKey::<P>::generate_deterministic(&[1; 32], &[2; 32]);
    let good = ek.as_bytes().to_vec();
    let ncoeffs = 256 * P::K;
    for i in [0, 1, 2, 255, 256, 257, ncoeffs - 2, ncoeffs - 1] {
        for (val, ok) in [
            (3328u16, true),
            (0, true),
            (3329, false),
            (3330, false),
            (4095, false),
        ] {
            let mut b = good.clone();
            set12(&mut b, i, val);
            let r = EncapsulationKey::<P>::from_bytes(&b);
            assert_eq!(r.is_ok(), ok, "coefficient {i} = {val}");
            if !ok {
                assert_eq!(r.unwrap_err(), Error::InvalidKey);
                // The same corruption inside an expanded decapsulation key.
                let mut d = dk.to_bytes().as_ref().to_vec();
                d[384 * P::K..384 * P::K + good.len()].copy_from_slice(&b);
                assert_eq!(
                    DecapsulationKey::<P>::from_bytes(&d).unwrap_err(),
                    Error::InvalidKey
                );
            }
        }
    }
    // rho is not range checked.
    let mut b = good.clone();
    b[384 * P::K..].fill(0xff);
    assert!(EncapsulationKey::<P>::from_bytes(&b).is_ok());

    for len in [0, good.len() - 1, good.len() + 1] {
        let mut b = good.clone();
        b.resize(len, 0);
        assert_eq!(
            EncapsulationKey::<P>::from_bytes(&b).unwrap_err(),
            Error::InvalidLength
        );
    }

    // Expanded decapsulation key: hash check and length check.
    let dk_bytes = dk.to_bytes().as_ref().to_vec();
    assert_eq!(dk_bytes.len(), P::DECAPSULATION_KEY_LEN);
    let h_off = 768 * P::K + 32;
    for pos in [h_off, h_off + 31, 384 * P::K + 5] {
        let mut d = dk_bytes.clone();
        d[pos] ^= 1;
        assert_eq!(
            DecapsulationKey::<P>::from_bytes(&d).unwrap_err(),
            Error::InvalidKey
        );
    }
    for len in [0, dk_bytes.len() - 1, dk_bytes.len() + 1] {
        let mut d = dk_bytes.clone();
        d.resize(len, 0);
        assert_eq!(
            DecapsulationKey::<P>::from_bytes(&d).unwrap_err(),
            Error::InvalidLength
        );
    }
    // dk_pke coefficients >= q are reduced (not rejected), as in FIPS 203.
    let parsed = DecapsulationKey::<P>::from_bytes(&dk_bytes).unwrap();
    assert_eq!(parsed.to_bytes().as_ref(), dk_bytes.as_slice());

    // Ciphertext length checks.
    let (ct, ss) = ek.encapsulate(&OsRng).unwrap();
    assert_eq!(ct.as_ref().len(), P::CIPHERTEXT_LEN);
    assert_eq!(ss.len(), P::SHARED_SECRET_LEN);
    for len in [0, P::CIPHERTEXT_LEN - 1, P::CIPHERTEXT_LEN + 1] {
        let mut c = ct.as_ref().to_vec();
        c.resize(len, 0);
        assert_eq!(dk.decapsulate(&c).unwrap_err(), Error::InvalidLength);
    }
    assert_eq!(dk.decapsulate(ct.as_ref()).unwrap(), ss);

    // Failing randomness sources propagate errors.
    assert_eq!(
        DecapsulationKey::<P>::generate(&FixedRng::new(&[0; 63])).unwrap_err(),
        Error::RandomFailure
    );
    assert_eq!(
        ek.encapsulate(&FixedRng::new(&[0; 31])).unwrap_err(),
        Error::RandomFailure
    );
    // FixedRng-driven generation equals deterministic generation.
    let mut s = [1u8; 64];
    s[32..].fill(2);
    let (dk2, ek2) = DecapsulationKey::<P>::generate(&FixedRng::new(&s)).unwrap();
    assert_eq!(ek2, ek);
    assert_eq!(dk2.to_bytes().as_ref(), dk_bytes.as_slice());
    assert_eq!(
        ek.encapsulate(&FixedRng::new(&[9; 32])).unwrap(),
        ek.encapsulate_deterministic(&[9; 32])
    );
}

#[test]
fn key_validation() {
    validation::<MlKem512>();
    validation::<MlKem768>();
    validation::<MlKem1024>();
}

#[test]
fn constants_and_backends() {
    assert_eq!(MlKem512::ENCAPSULATION_KEY_LEN, 800);
    assert_eq!(MlKem512::DECAPSULATION_KEY_LEN, 1632);
    assert_eq!(MlKem512::CIPHERTEXT_LEN, 768);
    assert_eq!(MlKem768::ENCAPSULATION_KEY_LEN, 1184);
    assert_eq!(MlKem768::DECAPSULATION_KEY_LEN, 2400);
    assert_eq!(MlKem768::CIPHERTEXT_LEN, 1088);
    assert_eq!(MlKem1024::ENCAPSULATION_KEY_LEN, 1568);
    assert_eq!(MlKem1024::DECAPSULATION_KEY_LEN, 3168);
    assert_eq!(MlKem1024::CIPHERTEXT_LEN, 1568);
    assert_eq!(MlKem768::SHARED_SECRET_LEN, 32);
    assert_eq!(
        <MlKem1024 as ParameterSet>::CIPHERTEXT_LEN,
        MlKem1024::CIPHERTEXT_LEN
    );

    let dk = DecapsulationKey::<MlKem768>::from_seed(&[3; 64]);
    assert_eq!(dk.backend(), Backend::detect());
    for b in Backend::ALL {
        let r = DecapsulationKey::<MlKem768>::from_seed_with_backend(&[3; 64], b);
        if b.is_available() {
            assert!(r.is_ok());
        } else {
            assert_eq!(r.unwrap_err(), Error::Unsupported);
            let ek = dk.encapsulation_key().clone();
            assert_eq!(ek.with_backend(b).unwrap_err(), Error::Unsupported);
        }
    }
    let dbg = format!("{dk:?}");
    assert!(dbg.contains("ML-KEM-768") && !dbg.contains("s_hat"));
}

// ---------------------------------------------------------------------------
// Throughput (`cargo test --release -p browntls-crypto --test mlkem -- --ignored --nocapture`).
// ---------------------------------------------------------------------------

fn bench<P: ParameterSet>(b: Backend) {
    use std::time::{Duration, Instant};
    fn rate(mut f: impl FnMut()) -> f64 {
        let budget = Duration::from_millis(300);
        let start = Instant::now();
        let mut n = 0u64;
        while start.elapsed() < budget {
            for _ in 0..16 {
                f();
            }
            n += 16;
        }
        n as f64 / start.elapsed().as_secs_f64()
    }
    let seed = [7u8; 64];
    let dk = DecapsulationKey::<P>::from_seed_with_backend(&seed, b).unwrap();
    let ek = dk.encapsulation_key().clone();
    let (ct, _) = ek.encapsulate_deterministic(&[5; 32]);
    let kg = rate(|| {
        std::hint::black_box(DecapsulationKey::<P>::from_seed_with_backend(
            std::hint::black_box(&seed),
            b,
        ))
        .ok();
    });
    let enc = rate(|| {
        std::hint::black_box(ek.encapsulate_deterministic(std::hint::black_box(&[5; 32])));
    });
    let dec = rate(|| {
        std::hint::black_box(dk.decapsulate(std::hint::black_box(ct.as_ref())).ok());
    });
    println!(
        "{:<12} {:<9} keygen {:>8.0}/s  encaps {:>8.0}/s  decaps {:>8.0}/s",
        P::NAME,
        format!("{b:?}"),
        kg,
        enc,
        dec
    );
}

#[test]
#[ignore = "throughput measurement"]
fn throughput() {
    for b in backends() {
        bench::<MlKem512>(b);
        bench::<MlKem768>(b);
        bench::<MlKem1024>(b);
    }
}
