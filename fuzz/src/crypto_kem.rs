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
//!   the backend it claims to. Key generation, encapsulation and
//!   decapsulation are repeated with load-aware routing (`accel::load`)
//!   sending a fuzzed share of the calls to a fuzzed alternate backend (the
//!   last two argument bytes of each operation) and must give what they gave
//!   without routing, also through keys with an explicit backend, which are
//!   never routed.
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

mod ffdhe;
mod mlkem;

use browntls_crypto::accel::{self, Algorithm, Policy};
use browntls_crypto::ffdhe::Group;

use self::ffdhe::ffdhe_op;
use self::mlkem::{mlkem512, mlkem768, mlkem1024};
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
        // The same operations with load-aware routing: every call on the
        // first alternate backend, half of the calls, a few of them. The
        // routing bytes follow the operation's other arguments, so the
        // ciphertexts are of full length here.
        let ct_len = [768usize, 1088, 1568][usize::from(set)];
        seeds.push([&op(OP_MLKEM_KEYGEN)[..], &seed, &[0], &[0, 100]].concat());
        seeds.push([&op(OP_MLKEM_ENCAPS)[..], &seed, &m, &[0], &[0, 100]].concat());
        seeds.push([&op(OP_MLKEM_ENCAPS)[..], &seed, &m, &[0], &[1, 50]].concat());
        let mut routed = [&op(OP_MLKEM_DECAPS)[..], &seed, &[0]].concat();
        put_field(&mut routed, &vec![0x5a; ct_len]);
        routed.extend_from_slice(&[0, 100]);
        seeds.push(routed);
        let mut short = [&op(OP_MLKEM_DECAPS)[..], &seed, &[0]].concat();
        put_field(&mut short, &m);
        short.extend_from_slice(&[0, 100]);
        seeds.push(short);
        let flips = [1, 0, 7, 3, 1, 0, 9];
        seeds.push([&op(OP_MLKEM_TAMPER)[..], &seed, &m, &flips, &[0, 100]].concat());
        seeds.push([&op(OP_MLKEM_TAMPER)[..], &seed, &m, &flips, &[0, 3]].concat());
        seeds.push(
            [
                &op(OP_MLKEM_EK)[..],
                &[1],
                &seed,
                &[0, 1, 0xff],
                &m,
                &[0, 100],
            ]
            .concat(),
        );
        seeds.push(
            [
                &op(OP_MLKEM_DK)[..],
                &[1],
                &seed,
                &[0],
                &vec![0x3c; ct_len],
                &m,
                &[0, 100],
            ]
            .concat(),
        );
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
    fn exponentiation_costs() {
        assert_eq!(exp_cost(Group::Ffdhe2048), 1);
        // A full g^x check fits in ffdhe2048 and ffdhe3072, and g^x alone
        // in ffdhe4096.
        assert!(3 * exp_cost(Group::Ffdhe2048) <= FFDHE_BUDGET);
        assert!(2 * exp_cost(Group::Ffdhe3072) <= FFDHE_BUDGET);
        assert!(exp_cost(Group::Ffdhe4096) <= FFDHE_BUDGET);
    }
}
