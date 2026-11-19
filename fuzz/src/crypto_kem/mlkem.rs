//! ML-KEM-512/768/1024 operations of the `crypto_kem` target, checked
//! against the RustCrypto `ml-kem` crate, across the arithmetic backends
//! and with load-aware routing.

use browntls_crypto::accel::Algorithm;
use browntls_crypto::mlkem::{MlKem512, MlKem768, MlKem1024};

use super::{
    OP_MLKEM_DECAPS, OP_MLKEM_DK, OP_MLKEM_EK, OP_MLKEM_ENCAPS, OP_MLKEM_KEYGEN, OP_MLKEM_POLICY,
    OP_MLKEM_TAMPER, exact,
};
use crate::crypto_hash::with_fixed_share;
use crate::input::Input;

/// The ML-KEM modulus.
const Q: u16 = 3329;

/// Load-aware routing moves ML-KEM operations to another backend and never
/// changes them: with a fuzzed share of the calls of every stream (key
/// generation, encapsulation and decapsulation of each parameter set) fixed
/// on a fuzzed alternate, `f` returns `want`, which was computed without
/// routing.
fn check_routed<T: PartialEq + core::fmt::Debug>(
    input: &mut Input<'_>,
    want: &T,
    f: impl FnOnce() -> T,
) {
    let (alternate, percent) = (input.byte(), input.byte());
    let routed = with_fixed_share(Algorithm::MlKem, alternate, percent, f);
    assert_eq!(&routed, want, "ML-KEM with load-aware routing");
}

/// The 12-bit coefficient `i` of a ByteEncode_12 string.
fn get12(bytes: &[u8], i: usize) -> u16 {
    let off = 3 * (i / 2);
    let (a, b, c) = (
        u16::from(bytes[off]),
        u16::from(bytes[off + 1]),
        u16::from(bytes[off + 2]),
    );
    if i.is_multiple_of(2) {
        a | (b & 0x0f) << 8
    } else {
        b >> 4 | c << 4
    }
}

/// Sets the 12-bit coefficient `i` of a ByteEncode_12 string.
fn set12(bytes: &mut [u8], i: usize, val: u16) {
    let off = 3 * (i / 2);
    let [lo, hi] = (val & 0xfff).to_le_bytes();
    if i.is_multiple_of(2) {
        bytes[off] = lo;
        bytes[off + 1] = (bytes[off + 1] & 0xf0) | hi;
    } else {
        bytes[off + 1] = (bytes[off + 1] & 0x0f) | (lo << 4);
        bytes[off + 2] = ((val & 0xfff) >> 4).to_le_bytes()[0];
    }
}

/// Whether every 12-bit coefficient of the `k` polynomials in `polys` is
/// below q.
fn reduced(polys: &[u8], k: usize) -> bool {
    (0..256 * k).all(|i| get12(polys, i) < Q)
}

/// Applies up to four fuzzed 12-bit coefficient writes to the first `k`
/// polynomials of `bytes`.
fn mutate_coefficients(input: &mut Input<'_>, bytes: &mut [u8], k: usize) {
    for _ in 0..input.choose(5) {
        let i = usize::from(input.u16()) % (256 * k);
        set12(bytes, i, input.u16());
    }
}

/// Fuzzed byte flips and a fuzzed length change.
fn mutate_bytes(input: &mut Input<'_>, bytes: &mut Vec<u8>) {
    for _ in 0..input.choose(4) {
        let pos = usize::from(input.u16()) % bytes.len().max(1);
        let flip = input.byte();
        if let Some(b) = bytes.get_mut(pos) {
            *b ^= flip;
        }
    }
    match input.choose(4) {
        1 => {
            let n = input.choose(3);
            bytes.truncate(bytes.len().saturating_sub(n + 1));
        }
        2 => bytes.push(input.byte()),
        _ => {}
    }
}

/// One module per ML-KEM parameter set, each checked against the matching
/// `ml-kem` type.
macro_rules! mlkem {
    ($module:ident, $ours:ty, $theirs:ty) => {
        pub(super) mod $module {
            use browntls_crypto::Error;
            use browntls_crypto::accel::{self, Acceleration, Algorithm, Policy, Uses};
            use browntls_crypto::mlkem::{
                Backend, DecapsulationKey, EncapsulationKey, ParameterSet, SEED_LEN,
                SHARED_SECRET_LEN,
            };
            use browntls_crypto::rand::{FixedRng, OsRng};
            use ml_kem::{Decapsulate as _, KeyExport as _, TryKeyInit as _};

            use super::*;

            type Ours = $ours;
            type Dk = DecapsulationKey<Ours>;
            type Ek = EncapsulationKey<Ours>;
            type RcDk = ml_kem::DecapsulationKey<$theirs>;
            type RcEk = ml_kem::EncapsulationKey<$theirs>;

            const NAME: &str = <Ours as ParameterSet>::NAME;
            const K: usize = <Ours as ParameterSet>::K;
            const EK_LEN: usize = <Ours as ParameterSet>::ENCAPSULATION_KEY_LEN;
            const DK_LEN: usize = <Ours as ParameterSet>::DECAPSULATION_KEY_LEN;
            const CT_LEN: usize = <Ours as ParameterSet>::CIPHERTEXT_LEN;

            pub(in crate::crypto_kem) fn op(op: u8, input: &mut Input<'_>) {
                match op {
                    OP_MLKEM_KEYGEN => keygen(input),
                    OP_MLKEM_ENCAPS => encaps(input),
                    OP_MLKEM_DECAPS => decaps(input),
                    OP_MLKEM_TAMPER => tamper(input),
                    OP_MLKEM_EK => parse_ek(input),
                    OP_MLKEM_DK => parse_dk(input),
                    OP_MLKEM_POLICY => policy(input),
                    _ => os_rng(),
                }
            }

            fn oracle(seed: &[u8; SEED_LEN]) -> RcDk {
                RcDk::from_seed((*seed).into())
            }

            #[allow(deprecated)]
            fn oracle_expanded(dk: &RcDk) -> Vec<u8> {
                ml_kem::ExpandedKeyEncoding::to_expanded_bytes(dk).to_vec()
            }

            fn oracle_decaps(dk: &RcDk, ct: &[u8]) -> [u8; SHARED_SECRET_LEN] {
                dk.decapsulate_slice(ct)
                    .expect("ciphertext length checked")
                    .into()
            }

            /// Every key-generation path from a fuzzed seed gives the
            /// oracle's key.
            fn keygen(input: &mut Input<'_>) {
                let seed: [u8; SEED_LEN] = input.array();
                let dk = Dk::from_seed(&seed);
                assert_eq!(dk.backend(), Backend::detect());
                assert_eq!(dk.seed(), Some(&seed));
                let ek = dk.encapsulation_key();
                assert_eq!(ek.backend(), dk.backend());
                assert_eq!(ek.to_bytes().as_ref(), ek.as_bytes());
                assert_eq!(ek.as_bytes().len(), EK_LEN);
                let dk_bytes = dk.to_bytes();
                assert_eq!(dk_bytes.as_ref().len(), DK_LEN);

                let rc = oracle(&seed);
                assert_eq!(
                    ek.as_bytes(),
                    rc.encapsulation_key().to_bytes().as_slice(),
                    "{NAME} ek"
                );
                assert_eq!(
                    dk_bytes.as_ref(),
                    oracle_expanded(&rc).as_slice(),
                    "{NAME} dk"
                );

                let d: [u8; 32] = seed[..32].try_into().expect("32 bytes");
                let z: [u8; 32] = seed[32..].try_into().expect("32 bytes");
                let (dk2, ek2) = Dk::generate_deterministic(&d, &z);
                assert_eq!(&ek2, ek);
                assert_eq!(dk2.to_bytes().as_ref(), dk_bytes.as_ref());
                assert_eq!(dk2.seed(), Some(&seed));

                for b in Backend::ALL {
                    match Dk::from_seed_with_backend(&seed, b) {
                        Ok(dk3) => {
                            assert!(b.is_available());
                            assert_eq!(dk3.backend(), b);
                            assert_eq!(dk3.encapsulation_key(), ek, "{NAME} {b:?}");
                            assert_eq!(dk3.to_bytes().as_ref(), dk_bytes.as_ref());
                        }
                        Err(e) => {
                            assert!(!b.is_available());
                            assert_eq!(e, Error::Unsupported);
                        }
                    }
                }

                // The random source supplies exactly the 64 seed bytes.
                let take = if input.bool() {
                    input.choose(SEED_LEN)
                } else {
                    SEED_LEN
                };
                match Dk::generate(&FixedRng::new(&seed[..take])) {
                    Ok((dk4, ek4)) => {
                        assert_eq!(take, SEED_LEN);
                        assert_eq!(&ek4, ek);
                        assert_eq!(dk4.encapsulation_key(), ek);
                        assert_eq!(dk4.to_bytes().as_ref(), dk_bytes.as_ref());
                    }
                    Err(e) => {
                        assert!(take < SEED_LEN);
                        assert_eq!(e, Error::RandomFailure);
                    }
                }

                // With routing: the same key, which still belongs to the
                // backend the policy selects.
                let want = (ek.clone(), dk_bytes.as_ref().to_vec(), Backend::detect());
                check_routed(input, &want, || {
                    let dk = Dk::from_seed(&seed);
                    let bytes = dk.to_bytes().as_ref().to_vec();
                    (dk.encapsulation_key().clone(), bytes, dk.backend())
                });
            }

            /// Encapsulation with fuzzed randomness agrees with the oracle
            /// and across backends, and decapsulates to the same secret.
            fn encaps(input: &mut Input<'_>) {
                let seed: [u8; SEED_LEN] = input.array();
                let m: [u8; 32] = input.array();
                let dk = Dk::from_seed(&seed);
                let ek = dk.encapsulation_key().clone();
                let (ct, ss) = ek.encapsulate_deterministic(&m);
                assert_eq!(ct.as_ref().len(), CT_LEN);

                let rc = oracle(&seed);
                let (rc_ct, rc_ss) = rc.encapsulation_key().encapsulate_deterministic(&m.into());
                assert_eq!(ct.as_ref(), rc_ct.as_slice(), "{NAME} ct");
                assert_eq!(ss.as_slice(), rc_ss.as_slice(), "{NAME} ss");
                assert_eq!(dk.decapsulate(ct.as_ref()), Ok(ss));

                for b in Backend::available() {
                    let ek_b = ek.clone().with_backend(b).expect("available backend");
                    assert_eq!(ek_b.backend(), b);
                    assert_eq!(ek_b.encapsulate_deterministic(&m), (ct, ss), "{NAME} {b:?}");
                    let dk_b = Dk::from_seed_with_backend(&seed, b).expect("available backend");
                    assert_eq!(dk_b.decapsulate(ct.as_ref()), Ok(ss), "{NAME} {b:?}");
                }

                // The random source supplies exactly `m`.
                let take = if input.bool() { input.choose(32) } else { 32 };
                match ek.encapsulate(&FixedRng::new(&m[..take])) {
                    Ok(out) => {
                        assert_eq!(take, 32);
                        assert_eq!(out, (ct, ss));
                    }
                    Err(e) => {
                        assert!(take < 32);
                        assert_eq!(e, Error::RandomFailure);
                    }
                }

                // With routing, through the key and through one with an
                // explicit backend (which is not routed).
                let pinned = ek.clone().with_backend(ek.backend()).expect("own backend");
                let want = ((ct, ss), (ct, ss), Ok(ss));
                check_routed(input, &want, || {
                    (
                        ek.encapsulate_deterministic(&m),
                        pinned.encapsulate_deterministic(&m),
                        dk.decapsulate(ct.as_ref()),
                    )
                });
            }

            /// Decapsulation of fuzzed ciphertexts of any length.
            fn decaps(input: &mut Input<'_>) {
                let seed: [u8; SEED_LEN] = input.array();
                let ct = if input.bool() {
                    exact(input, CT_LEN)
                } else {
                    input.field().to_vec()
                };
                let dk = Dk::from_seed(&seed);
                let result = dk.decapsulate(&ct);
                // With routing: the same secret or the same error, also
                // from a key with an explicit backend (which is not routed).
                let pinned = Dk::from_seed_with_backend(&seed, dk.backend()).expect("own backend");
                check_routed(input, &(result, result), || {
                    (dk.decapsulate(&ct), pinned.decapsulate(&ct))
                });
                if ct.len() != CT_LEN {
                    assert_eq!(result, Err(Error::InvalidLength));
                    return;
                }
                let k = result.expect("right length");
                assert_eq!(k, oracle_decaps(&oracle(&seed), &ct), "{NAME} decaps");
                for b in Backend::available() {
                    let dk_b = Dk::from_seed_with_backend(&seed, b).expect("available backend");
                    assert_eq!(dk_b.decapsulate(&ct), Ok(k), "{NAME} {b:?}");
                }
            }

            /// A genuine ciphertext with fuzzed bit flips is implicitly
            /// rejected: a key unlike the real one, equal to the oracle's.
            fn tamper(input: &mut Input<'_>) {
                let seed: [u8; SEED_LEN] = input.array();
                let m: [u8; 32] = input.array();
                let dk = Dk::from_seed(&seed);
                let (ct, ss) = dk.encapsulation_key().encapsulate_deterministic(&m);
                let mut bad = ct.as_ref().to_vec();
                for _ in 0..=input.choose(4) {
                    let pos = usize::from(input.u16()) % CT_LEN;
                    bad[pos] ^= 1 << (input.byte() % 8);
                }
                let k = dk.decapsulate(&bad).expect("right length");
                assert_eq!(k, oracle_decaps(&oracle(&seed), &bad), "{NAME} rejection");
                if bad == ct.as_ref() {
                    assert_eq!(k, ss);
                } else {
                    assert_ne!(k, ss, "{NAME}: tampered ciphertext accepted");
                }
                // Implicit rejection gives the same key with routing.
                check_routed(input, &Ok(k), || dk.decapsulate(&bad));
            }

            /// Encapsulation-key validation (FIPS 203 §7.2).
            fn parse_ek(input: &mut Input<'_>) {
                let mut bytes = match input.choose(3) {
                    0 => input.field().to_vec(),
                    mode => {
                        let seed: [u8; SEED_LEN] = input.array();
                        let mut b = Dk::from_seed(&seed).encapsulation_key().as_bytes().to_vec();
                        mutate_coefficients(input, &mut b, K);
                        if mode == 2 {
                            mutate_bytes(input, &mut b);
                        }
                        b
                    }
                };
                if input.bool() && bytes.len() == EK_LEN {
                    // rho is not range checked.
                    let fill = input.byte();
                    bytes[384 * K..].fill(fill);
                }
                let result = Ek::from_bytes(&bytes);
                if bytes.len() != EK_LEN {
                    assert_eq!(result.err(), Some(Error::InvalidLength));
                    return;
                }
                let valid = reduced(&bytes[..384 * K], K);
                let rc = RcEk::new_from_slice(&bytes);
                assert_eq!(
                    rc.is_ok(),
                    valid,
                    "{NAME}: oracle disagrees with the modulus check"
                );
                let ek = match result {
                    Ok(ek) => ek,
                    Err(e) => {
                        assert!(!valid, "{NAME}: valid encapsulation key rejected");
                        assert_eq!(e, Error::InvalidKey);
                        return;
                    }
                };
                assert!(valid, "{NAME}: unreduced encapsulation key accepted");
                let rc = rc.expect("valid");
                assert_eq!(ek.as_bytes(), bytes.as_slice());
                assert_eq!(ek.to_bytes().as_ref(), bytes.as_slice());
                assert_eq!(ek.backend(), Backend::detect());
                assert_eq!(Ek::from_bytes(&bytes).as_ref(), Ok(&ek));

                let m: [u8; 32] = input.array();
                let (ct, ss) = ek.encapsulate_deterministic(&m);
                let (rc_ct, rc_ss) = rc.encapsulate_deterministic(&m.into());
                assert_eq!(ct.as_ref(), rc_ct.as_slice(), "{NAME} ct");
                assert_eq!(ss.as_slice(), rc_ss.as_slice(), "{NAME} ss");
                for b in Backend::ALL {
                    match ek.clone().with_backend(b) {
                        Ok(ek_b) => {
                            assert_eq!(ek_b.backend(), b);
                            assert_eq!(
                                ek_b.encapsulate_deterministic(&m),
                                (ct, ss),
                                "{NAME} {b:?}"
                            );
                        }
                        Err(e) => {
                            assert!(!b.is_available());
                            assert_eq!(e, Error::Unsupported);
                        }
                    }
                }
                // A parsed key is routed like a generated one.
                check_routed(input, &(ct, ss), || ek.encapsulate_deterministic(&m));
            }

            /// Expanded decapsulation-key validation (FIPS 203 §7.3) and
            /// decapsulation with the parsed key.
            fn parse_dk(input: &mut Input<'_>) {
                let bytes = match input.choose(3) {
                    0 => input.field().to_vec(),
                    mode => {
                        let seed: [u8; SEED_LEN] = input.array();
                        let mut b = Dk::from_seed(&seed).to_bytes().as_ref().to_vec();
                        if input.bool() {
                            // Unreduced dk_pke coefficients.
                            mutate_coefficients(input, &mut b, K);
                        }
                        if mode == 2 {
                            mutate_bytes(input, &mut b);
                        }
                        b
                    }
                };
                let result = Dk::from_bytes(&bytes);
                if bytes.len() != DK_LEN {
                    assert_eq!(result.err(), Some(Error::InvalidLength));
                    return;
                }
                #[allow(deprecated)]
                let rc = RcDk::from_expanded(bytes.as_slice().try_into().expect("length checked"));
                let ek_bytes = &bytes[384 * K..384 * K + EK_LEN];
                let dk = match result {
                    Ok(dk) => dk,
                    Err(e) => {
                        assert_eq!(e, Error::InvalidKey);
                        assert!(rc.is_err(), "{NAME}: oracle accepts a rejected key");
                        return;
                    }
                };
                let rc = rc.expect("oracle rejects an accepted key");
                assert!(reduced(&ek_bytes[..384 * K], K));
                assert_eq!(dk.seed(), None);
                assert_eq!(dk.backend(), Backend::detect());
                assert_eq!(dk.encapsulation_key().as_bytes(), ek_bytes);

                // The encoding is exact when dk_pke is reduced, and stable
                // after one round trip otherwise.
                let encoded = dk.to_bytes();
                let dk_pke_reduced = reduced(&bytes[..384 * K], K);
                assert_eq!(encoded.as_ref() == bytes.as_slice(), dk_pke_reduced);
                let dk2 = Dk::from_bytes(encoded.as_ref()).expect("own encoding");
                assert_eq!(dk2.to_bytes().as_ref(), encoded.as_ref());

                let ct = exact(input, CT_LEN);
                let k = dk.decapsulate(&ct).expect("right length");
                assert_eq!(k, oracle_decaps(&rc, &ct), "{NAME} decaps");
                assert_eq!(dk2.decapsulate(&ct), Ok(k));
                let m: [u8; 32] = input.array();
                let (ct2, _) = dk.encapsulation_key().encapsulate_deterministic(&m);
                let k2 = dk.decapsulate(ct2.as_ref()).expect("right length");
                assert_eq!(k2, oracle_decaps(&rc, ct2.as_ref()), "{NAME} decaps");
                for b in Backend::ALL {
                    let parsed = Dk::from_bytes(&bytes).expect("accepted above");
                    match parsed.with_backend(b) {
                        Ok(dk_b) => {
                            assert_eq!(dk_b.backend(), b);
                            assert_eq!(dk_b.decapsulate(&ct), Ok(k), "{NAME} {b:?}");
                            assert_eq!(dk_b.decapsulate(ct2.as_ref()), Ok(k2), "{NAME} {b:?}");
                        }
                        Err(e) => {
                            assert!(!b.is_available());
                            assert_eq!(e, Error::Unsupported);
                        }
                    }
                }
                // A parsed key is routed like a generated one.
                check_routed(input, &(Ok(k), Ok(k2)), || {
                    (dk.decapsulate(&ct), dk.decapsulate(ct2.as_ref()))
                });
            }

            /// The ML-KEM acceleration policy selects the backend that
            /// `Backend::detect` and new keys report, and results do not
            /// depend on it.
            fn policy(input: &mut Input<'_>) {
                const LEVELS: [Acceleration; 3] = [
                    Acceleration::Required,
                    Acceleration::Preferred,
                    Acceleration::None,
                ];
                let policy = Policy::new(*input.pick(&LEVELS), *input.pick(&LEVELS));
                let seed: [u8; SEED_LEN] = input.array();
                let m: [u8; 32] = input.array();

                assert_eq!(
                    Backend::detect(),
                    Backend::available().next().expect("portable")
                );
                assert!(Backend::Portable.is_available());
                for b in Backend::ALL {
                    assert_eq!(b.is_available(), Backend::available().any(|a| a == b));
                }
                let reference = Dk::from_seed(&seed);
                let (ct, ss) = reference.encapsulation_key().encapsulate_deterministic(&m);

                let set = accel::set_policy(Algorithm::MlKem, policy);
                let status = accel::status(Algorithm::MlKem);
                let detected = Backend::detect();
                if set.is_ok() {
                    assert_eq!(accel::policy(Algorithm::MlKem), policy);
                    assert!(policy.permits(status.uses));
                    let expected = Backend::available().find(|b| {
                        policy.permits(if *b == Backend::Portable {
                            Uses::PORTABLE
                        } else {
                            Uses::SIMD
                        })
                    });
                    assert_eq!(Some(detected), expected, "{policy}");
                } else {
                    assert_eq!(accel::policy(Algorithm::MlKem), Policy::PREFERRED);
                }
                assert_eq!(status.backend == "portable", detected == Backend::Portable);
                let dk = Dk::from_seed(&seed);
                assert_eq!(dk.backend(), detected);
                accel::set_policy(Algorithm::MlKem, Policy::PREFERRED).expect("always satisfiable");
                assert_eq!(
                    dk.encapsulation_key().encapsulate_deterministic(&m),
                    (ct, ss)
                );
                assert_eq!(dk.decapsulate(ct.as_ref()), Ok(ss));
            }

            /// A round trip with operating-system randomness.
            fn os_rng() {
                let (dk, ek) = Dk::generate(&OsRng).expect("OS randomness");
                assert_eq!(dk.encapsulation_key(), &ek);
                let seed = *dk.seed().expect("generated from a seed");
                let (ct, ss) = ek.encapsulate(&OsRng).expect("OS randomness");
                assert_eq!(dk.decapsulate(ct.as_ref()), Ok(ss));
                assert_eq!(oracle_decaps(&oracle(&seed), ct.as_ref()), ss);
            }
        }
    };
}

mlkem!(mlkem512, MlKem512, ml_kem::MlKem512);
mlkem!(mlkem768, MlKem768, ml_kem::MlKem768);
mlkem!(mlkem1024, MlKem1024, ml_kem::MlKem1024);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coefficient_helpers_round_trip() {
        let mut b = vec![0u8; 384];
        for (i, v) in [(0usize, 3328u16), (1, 3329), (254, 4095), (255, 7)] {
            set12(&mut b, i, v);
            assert_eq!(get12(&b, i), v);
        }
        assert!(!reduced(&b, 1));
        set12(&mut b, 1, 0);
        set12(&mut b, 254, 0);
        assert!(reduced(&b, 1));
    }
}
