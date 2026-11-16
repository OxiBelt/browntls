//! `browntls-crypto`: ML-KEM (`mlkem`) and finite-field Diffie-Hellman
//! (`ffdhe`).
//!
//! The input is a program of up to [`MAX_OPS`] operations, each an op byte
//! followed by its arguments (a parameter-set or group byte, seeds, fuzzed
//! ciphertexts, keys, exponents and peer values). Every public function of
//! both modules is reached:
//!
//! - ML-KEM-512/768/1024: key generation from fuzzed seeds and encapsulation
//!   with fuzzed randomness agree with the RustCrypto `ml-kem` oracle and
//!   across every available arithmetic backend (portable and AVX2/NEON/RVV);
//!   decapsulation of fuzzed and tampered ciphertexts (implicit rejection)
//!   agrees with the oracle; encapsulation-key and expanded decapsulation-key
//!   parsing accept exactly what the FIPS 203 checks (computed here
//!   independently and by the oracle) accept; the acceleration policy picks
//!   the backend it claims to.
//! - FFDHE: peer public values (fuzzed, and 0, 1, p - 1, p, too long, too
//!   short) are validated exactly as `1 < Y < p - 1` with the right length;
//!   `g^x` and `Y^x` agree with `num-bigint` and between the portable and the
//!   accelerated Montgomery kernels; agreement is symmetric; failures leave
//!   the output buffer untouched.
//!
//! Exponentiations are expensive, so each input has a budget of them (in
//! units of one ffdhe2048 exponentiation) that keeps an input to a few
//! milliseconds: full checks run in ffdhe2048 and ffdhe3072, `g^x` alone in
//! ffdhe4096, and ffdhe6144/8192 get validation and every cheap path but no
//! exponentiation (the crate's own tests exponentiate in every group).
//! ML-KEM operations are capped likewise.

use browntls_crypto::Error;
use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::ffdhe::{self, Group};
use browntls_crypto::mlkem::{MlKem512, MlKem768, MlKem1024};
use browntls_crypto::rand::{FixedRng, OsRng};
use num_bigint::BigUint;

use crate::input::{Input, put_field};

/// Operations per input.
const MAX_OPS: usize = 32;
/// ML-KEM operations per input (each runs several key generations).
const MAX_MLKEM_OPS: u32 = 2;
/// FFDHE exponentiation budget per input, in ffdhe2048 units.
const FFDHE_BUDGET: u32 = 6;

const OP_MLKEM_KEYGEN: u8 = 0;
const OP_MLKEM_ENCAPS: u8 = 1;
const OP_MLKEM_DECAPS: u8 = 2;
const OP_MLKEM_TAMPER: u8 = 3;
const OP_MLKEM_EK: u8 = 4;
const OP_MLKEM_DK: u8 = 5;
const OP_MLKEM_POLICY: u8 = 6;
const OP_MLKEM_OS_RNG: u8 = 7;
const OP_FFDHE_VALIDATE: u8 = 8;
const OP_FFDHE_EXPONENT: u8 = 9;
const OP_FFDHE_AGREE: u8 = 10;
const OP_FFDHE_GENERATE: u8 = 11;
const OPS: usize = 12;

/// The ML-KEM modulus.
const Q: u16 = 3329;

/// Per-input limits on the expensive operations.
struct Budget {
    mlkem: u32,
    ffdhe: u32,
}

impl Budget {
    fn mlkem(&mut self) -> bool {
        let ok = self.mlkem > 0;
        self.mlkem = self.mlkem.saturating_sub(1);
        ok
    }

    /// Takes `n` exponentiations in `group` from the budget, if affordable.
    fn ffdhe(&mut self, group: Group, n: u32) -> bool {
        let cost = n * exp_cost(group);
        if cost <= self.ffdhe {
            self.ffdhe -= cost;
            true
        } else {
            false
        }
    }
}

/// Rough cost of one exponentiation relative to ffdhe2048: quadratic in the
/// modulus, linear in the exponent.
fn exp_cost(group: Group) -> u32 {
    let modulus = u32::try_from(group.prime_bits() / 1024).unwrap_or(8);
    let exponent = u32::try_from(group.exponent_bits() / 64).unwrap_or(7);
    (modulus * modulus * exponent).div_ceil(16)
}

/// The `crypto_kem` fuzz target.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    let mut budget = Budget {
        mlkem: MAX_MLKEM_OPS,
        ffdhe: FFDHE_BUDGET,
    };
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        let op = u8::try_from(input.choose(OPS)).unwrap_or(0);
        if op <= OP_MLKEM_OS_RNG {
            let set = input.choose(3);
            if !budget.mlkem() {
                continue;
            }
            match set {
                0 => mlkem512::op(op, &mut input),
                1 => mlkem768::op(op, &mut input),
                _ => mlkem1024::op(op, &mut input),
            }
        } else {
            ffdhe_op(op, &mut input, &mut budget);
        }
    }
    // Ops restore the policies they change; this is a backstop.
    for alg in [Algorithm::MlKem, Algorithm::Rsa] {
        accel::set_policy(alg, Policy::PREFERRED).expect("PREFERRED is always satisfiable");
    }
}

/// `len` bytes from the input, zero-padded.
fn exact(input: &mut Input<'_>, len: usize) -> Vec<u8> {
    let mut out = input.bytes(len).to_vec();
    out.resize(len, 0);
    out
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
        mod $module {
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

            pub(super) fn op(op: u8, input: &mut Input<'_>) {
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

fn prime(group: Group) -> BigUint {
    BigUint::from_bytes_be(group.prime_be())
}

/// `v` big-endian, left-padded to `len` bytes (longer if `v` needs it).
fn be_padded(v: &BigUint, len: usize) -> Vec<u8> {
    let raw = v.to_bytes_be();
    let mut out = vec![0u8; len.max(raw.len())];
    let at = out.len() - raw.len();
    out[at..].copy_from_slice(&raw);
    out
}

/// Checks the group's constant accessors against each other and RFC 7919.
fn check_group(group: Group) {
    let p = group.prime_be();
    assert_eq!(p.len(), group.element_len());
    assert_eq!(group.element_len() * 8, group.prime_bits());
    assert_eq!(&p[..8], &[0xff; 8]);
    assert_eq!(&p[p.len() - 8..], &[0xff; 8]);
    assert!(group.min_exponent_bits() >= 2 * group.security_bits());
    assert!(group.exponent_bits() >= group.min_exponent_bits());
    assert!(group.exponent_bits() < group.min_exponent_bits() + 64);
    assert_eq!(group.exponent_bits() % 64, 0);
    assert_eq!(group.exponent_len() * 8, group.exponent_bits());
    assert!(group.exponent_len() <= ffdhe::MAX_EXPONENT_LEN);
    assert!(group.element_len() <= ffdhe::MAX_ELEMENT_LEN);
    assert_eq!(group.name(), format!("ffdhe{}", group.prime_bits()));
}

/// A peer value for `group`: fuzzed bytes, or a boundary value (0, 2,
/// p - 2, p, 2^bits - 1) moved by a small fuzzed offset (reaching 1,
/// p - 1, p + 1 ...), with an optional length error.
fn peer_value(input: &mut Input<'_>, group: Group) -> Vec<u8> {
    let len = group.element_len();
    let p = prime(group);
    let mut bytes = match input.choose(4) {
        0 => exact(input, len),
        1 => input.field().to_vec(),
        _ => {
            let base = match input.choose(5) {
                0 => BigUint::from(0u8),
                1 => &p - 2u8,
                2 => p.clone(),
                3 => (BigUint::from(1u8) << group.prime_bits()) - 1u8,
                _ => BigUint::from(2u8),
            };
            let delta = BigUint::from(input.byte() % 4);
            let v = if input.bool() {
                base + delta
            } else if base >= delta {
                base - delta
            } else {
                base
            };
            be_padded(&v, len)
        }
    };
    match input.choose(8) {
        0 => bytes.insert(0, 0),
        1 if !bytes.is_empty() => {
            bytes.remove(0);
        }
        _ => {}
    }
    bytes
}

/// Whether `peer` is a valid public value: the right length and in
/// `(1, p - 1)`.
fn peer_valid(group: Group, peer: &[u8]) -> bool {
    let y = BigUint::from_bytes_be(peer);
    peer.len() == group.element_len() && y > BigUint::from(1u8) && y < prime(group) - 1u8
}

/// A private exponent: fuzzed bytes of the right or a fuzzed length, or a
/// small value.
fn exponent(input: &mut Input<'_>, group: Group) -> Vec<u8> {
    let len = group.exponent_len();
    match input.choose(4) {
        0 => input.field().to_vec(),
        1 => {
            let mut e = vec![0u8; len];
            e[len - 1] = input.byte() % 4;
            e
        }
        _ => exact(input, len),
    }
}

fn public_key(key: &ffdhe::PrivateKey) -> Vec<u8> {
    let mut out = vec![0u8; key.group().element_len()];
    key.public_key(&mut out).expect("right length");
    out
}

/// `f` with the RSA Montgomery kernels restricted to portable code.
fn portable<T>(f: impl FnOnce() -> T) -> T {
    accel::set_policy(Algorithm::Rsa, Policy::NONE).expect("portable is always available");
    let out = f();
    accel::set_policy(Algorithm::Rsa, Policy::PREFERRED).expect("always satisfiable");
    out
}

fn ffdhe_op(op: u8, input: &mut Input<'_>, budget: &mut Budget) {
    let group = *input.pick(&Group::ALL);
    check_group(group);
    let len = group.element_len();
    match op {
        OP_FFDHE_VALIDATE => {
            let peer = peer_value(input, group);
            let result = group.validate_public_key(&peer);
            assert_eq!(
                result.is_ok(),
                peer_valid(group, &peer),
                "{} peer of {} bytes",
                group.name(),
                peer.len()
            );
            if let Err(e) = result {
                assert_eq!(e, Error::InvalidKey);
            }
        }
        OP_FFDHE_EXPONENT => {
            let e = exponent(input, group);
            let x = BigUint::from_bytes_be(&e);
            let key = match ffdhe::PrivateKey::from_exponent_be(group, &e) {
                Ok(key) => {
                    assert_eq!(e.len(), group.exponent_len());
                    assert!(x >= BigUint::from(2u8));
                    key
                }
                Err(err) => {
                    assert_eq!(err, Error::InvalidKey);
                    assert!(e.len() != group.exponent_len() || x < BigUint::from(2u8));
                    return;
                }
            };
            assert_eq!(key.group(), group);
            for wrong in [len - 1, len + 1, 0] {
                let mut out = vec![0u8; wrong];
                assert_eq!(key.public_key(&mut out), Err(Error::InvalidLength));
                assert_eq!(
                    key.diffie_hellman(&[2], &mut out),
                    Err(Error::InvalidLength)
                );
            }
            // Each exponentiation (ours, the oracle's, the portable
            // kernel's) is taken from the budget separately, so the largest
            // groups still run g^x.
            if !budget.ffdhe(group, 1) {
                return;
            }
            let y = public_key(&key);
            assert_eq!(group.validate_public_key(&y), Ok(()));
            if budget.ffdhe(group, 1) {
                let expected = BigUint::from(ffdhe::GENERATOR).modpow(&x, &prime(group));
                assert_eq!(y, be_padded(&expected, len), "{} g^x", group.name());
            }
            if budget.ffdhe(group, 1) {
                assert_eq!(
                    portable(|| public_key(&key)),
                    y,
                    "{} portable vs accelerated",
                    group.name()
                );
            }
        }
        OP_FFDHE_AGREE => {
            let ea = exact(input, group.exponent_len());
            let Ok(a) = ffdhe::PrivateKey::from_exponent_be(group, &ea) else {
                return;
            };
            if input.bool() {
                // A genuine exchange is symmetric.
                let eb = exact(input, group.exponent_len());
                let Ok(b) = ffdhe::PrivateKey::from_exponent_be(group, &eb) else {
                    return;
                };
                if !budget.ffdhe(group, 4) {
                    return;
                }
                let (ya, yb) = (public_key(&a), public_key(&b));
                let (mut za, mut zb) = (vec![0u8; len], vec![0u8; len]);
                a.diffie_hellman(&yb, &mut za).expect("valid peer");
                b.diffie_hellman(&ya, &mut zb).expect("valid peer");
                assert_eq!(za, zb, "{} agreement is not symmetric", group.name());
                return;
            }
            let peer = peer_value(input, group);
            let compare_portable = input.bool();
            let mut out = vec![0xa5u8; len];
            if !peer_valid(group, &peer) {
                assert_eq!(a.diffie_hellman(&peer, &mut out), Err(Error::InvalidKey));
                assert!(out.iter().all(|&b| b == 0xa5), "output written on error");
                return;
            }
            if !budget.ffdhe(group, 1) {
                return;
            }
            let result = a.diffie_hellman(&peer, &mut out);
            if budget.ffdhe(group, 1) {
                let p = prime(group);
                let z = BigUint::from_bytes_be(&peer).modpow(&BigUint::from_bytes_be(&ea), &p);
                let degenerate = z <= BigUint::from(1u8) || z == &p - 1u8;
                if degenerate {
                    assert_eq!(result, Err(Error::KeyAgreementFailed));
                } else {
                    assert_eq!(result, Ok(()));
                    assert_eq!(out, be_padded(&z, len), "{} Y^x", group.name());
                }
            }
            match result {
                Ok(()) => {}
                Err(e) => {
                    assert_eq!(e, Error::KeyAgreementFailed);
                    assert!(out.iter().all(|&b| b == 0xa5), "output written on error");
                }
            }
            if compare_portable && budget.ffdhe(group, 1) {
                let mut out2 = vec![0xa5u8; len];
                let result2 = portable(|| a.diffie_hellman(&peer, &mut out2));
                assert_eq!(result2, result);
                assert_eq!(out2, out, "{} portable vs accelerated", group.name());
            }
        }
        _ => {
            // Generation draws exactly exponent_len bytes and sets the top bit.
            let n = group.exponent_len();
            let mut bytes = input.field().to_vec();
            bytes.truncate(n + 8);
            match ffdhe::PrivateKey::generate(group, &FixedRng::new(&bytes)) {
                Err(e) => {
                    assert_eq!(e, Error::RandomFailure);
                    assert!(bytes.len() < n);
                }
                Ok(key) => {
                    assert!(bytes.len() >= n);
                    assert_eq!(key.group(), group);
                    let mut e = bytes[..n].to_vec();
                    e[0] |= 0x80;
                    let same = ffdhe::PrivateKey::from_exponent_be(group, &e).expect("top bit set");
                    if budget.ffdhe(group, 2) {
                        assert_eq!(public_key(&key), public_key(&same));
                    }
                }
            }
            if input.bool() && budget.ffdhe(group, 1) {
                let key = ffdhe::PrivateKey::generate(group, &OsRng).expect("OS randomness");
                assert_eq!(group.validate_public_key(&public_key(&key)), Ok(()));
            }
        }
    }
}

/// Starting inputs for `crypto_kem`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    let seed: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
    let m: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(11) ^ 0xc3).collect();
    for set in 0..3u8 {
        let op = |op: u8| [op, set];
        // key generation with a full and a short random source
        seeds.push([&op(OP_MLKEM_KEYGEN)[..], &seed, &[0]].concat());
        seeds.push([&op(OP_MLKEM_KEYGEN)[..], &seed, &[1, 17]].concat());
        // encapsulation with a full and a short random source
        seeds.push([&op(OP_MLKEM_ENCAPS)[..], &seed, &m, &[0]].concat());
        seeds.push([&op(OP_MLKEM_ENCAPS)[..], &seed, &m, &[1, 5]].concat());
        // fuzzed ciphertexts: the right length, and a short one
        seeds.push([&op(OP_MLKEM_DECAPS)[..], &seed, &[1], &m].concat());
        let mut short = [&op(OP_MLKEM_DECAPS)[..], &seed, &[0]].concat();
        put_field(&mut short, &m);
        seeds.push(short);
        // a tampered ciphertext
        seeds.push([&op(OP_MLKEM_TAMPER)[..], &seed, &m, &[1, 0, 7, 3, 1, 0, 9]].concat());
        // encapsulation keys: genuine with rho refilled (not range checked),
        // unreduced coefficient, length error, raw
        seeds.push([&op(OP_MLKEM_EK)[..], &[1], &seed, &[0, 1, 0xff], &m].concat());
        seeds.push([&op(OP_MLKEM_EK)[..], &[1], &seed, &[1, 0, 9, 0x0d, 0x01, 0]].concat());
        seeds.push([&op(OP_MLKEM_EK)[..], &[2], &seed, &[0, 0, 1, 2]].concat());
        let mut raw = [&op(OP_MLKEM_EK)[..], &[0]].concat();
        put_field(&mut raw, &[0u8; 800]);
        seeds.push(raw);
        // expanded decapsulation keys: genuine, unreduced dk_pke, a byte
        // flipped in the hash, raw
        seeds.push([&op(OP_MLKEM_DK)[..], &[1], &seed, &[0], &m, &m].concat());
        seeds.push(
            [
                &op(OP_MLKEM_DK)[..],
                &[1],
                &seed,
                &[1, 1, 0, 3, 0xff, 0xff],
                &m,
            ]
            .concat(),
        );
        let flip = [0x40, 0x09, 0x40, 0x09];
        seeds.push(
            [
                &op(OP_MLKEM_DK)[..],
                &[2],
                &seed,
                &[0, 1],
                &flip,
                &[0x55, 0],
            ]
            .concat(),
        );
        seeds.push([&op(OP_MLKEM_DK)[..], &[0, 0, 3, 1, 2, 3]].concat());
        // policies and operating-system randomness
        // Required SIMD, portable only, the default
        let (simd, dedicated) = [(0, 1), (2, 2), (1, 1)][usize::from(set)];
        seeds.push([&op(OP_MLKEM_POLICY)[..], &[simd, dedicated], &seed, &m].concat());
        seeds.push(op(OP_MLKEM_OS_RNG).to_vec());
    }

    // Every group: accessors, boundary peers, invalid exponents and a short
    // random source (no exponentiation).
    for g in 0..5u8 {
        for base in 0..5u8 {
            for (up, delta) in [(0u8, 0u8), (1, 1), (0, 1)] {
                seeds.push(vec![OP_FFDHE_VALIDATE, g, 2, base, delta, up, 2]);
            }
        }
        seeds.push(vec![OP_FFDHE_VALIDATE, g, 2, 4, 0, 1, 0]);
        seeds.push(vec![OP_FFDHE_VALIDATE, g, 2, 4, 0, 1, 1]);
        seeds.push(vec![OP_FFDHE_VALIDATE, g, 0, 0x11, 0x22]);
        let mut fuzzed = vec![OP_FFDHE_VALIDATE, g, 1];
        put_field(&mut fuzzed, &[0x11; 9]);
        seeds.push(fuzzed);
        seeds.push(vec![OP_FFDHE_EXPONENT, g, 1, 1]);
        seeds.push(vec![OP_FFDHE_EXPONENT, g, 0, 0, 2, 7, 7]);
        seeds.push(vec![OP_FFDHE_GENERATE, g, 0, 3, 1, 2, 3, 0]);
    }
    // ffdhe2048 exponentiations: g^x, a genuine exchange, fuzzed and
    // degenerate peers, generation.
    let x: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(29) ^ 0x93).collect();
    let y: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(13) ^ 0x3c).collect();
    seeds.push([&[OP_FFDHE_EXPONENT, 0, 2][..], &x].concat());
    seeds.push(vec![OP_FFDHE_EXPONENT, 0, 1, 2]);
    seeds.push([&[OP_FFDHE_AGREE, 0][..], &x, &[1], &y].concat());
    seeds.push([&[OP_FFDHE_AGREE, 0][..], &x, &[0, 0], &y, &[2, 1]].concat());
    seeds.push([&[OP_FFDHE_AGREE, 0][..], &x, &[0, 2, 4, 0, 1, 2, 1]].concat());
    seeds.push([&[OP_FFDHE_AGREE, 0][..], &x, &[0, 2, 1, 1, 0, 2, 0]].concat());
    seeds.push([&[OP_FFDHE_AGREE, 0][..], &x, &[0, 2, 0, 1, 1, 2, 0]].concat());
    let mut generate = vec![OP_FFDHE_GENERATE, 0];
    put_field(&mut generate, &y);
    generate.push(1);
    seeds.push(generate);
    // g^x in the larger groups the budget allows.
    for g in [1u8, 2] {
        let x = vec![0x77u8; Group::ALL[usize::from(g)].exponent_len()];
        seeds.push([&[OP_FFDHE_EXPONENT, g, 2][..], &x].concat());
    }
    seeds
}

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

    #[test]
    fn exponentiation_costs() {
        assert_eq!(exp_cost(Group::Ffdhe2048), 1);
        // A full g^x check fits in ffdhe2048 and ffdhe3072, and g^x alone
        // in ffdhe4096.
        assert!(3 * exp_cost(Group::Ffdhe2048) <= FFDHE_BUDGET);
        assert!(2 * exp_cost(Group::Ffdhe3072) <= FFDHE_BUDGET);
        assert!(exp_cost(Group::Ffdhe4096) <= FFDHE_BUDGET);
    }
}
