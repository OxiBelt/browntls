//! `browntls-crypto`: ML-DSA (`mldsa`, FIPS 204) at the 44, 65 and 87
//! parameter sets.
//!
//! The input is a program of up to [`MAX_OPS`] operations, each an op byte
//! followed by a parameter-set byte and its arguments (seeds, messages,
//! contexts, signatures, keys and flips). Every public function of the
//! module is reached, and:
//!
//! - Key generation from a fuzzed seed gives the public key and the
//!   expanded private key of the RustCrypto `ml-dsa` oracle; `generate`
//!   draws exactly the 32-byte seed from its random source and fails with
//!   it; the encodings of both keys round-trip.
//! - Signing with a fuzzed seed, message, context (up to 255 bytes) and
//!   `rnd` is byte for byte the oracle's `ML-DSA.Sign_internal` (`rnd = 0`
//!   for `sign_deterministic`); the signatures verify with both, and a
//!   flipped signature byte, another message or another context verifies
//!   with neither. A 256-byte context and a failing random source are
//!   refused. A key reloaded from its expanded encoding signs identically.
//! - Verification of a fuzzed or genuine-then-mutated signature under a
//!   fuzzed or genuine public key, message and context agrees with the
//!   oracle's verdict; a key of the wrong length is refused.
//! - `from_expanded_bytes` of a genuine expanded key with fuzzed flips
//!   accepts exactly when only `K` (bytes 32..64, which nothing binds)
//!   changed; any accepted expanded key derives the oracle's public key and
//!   signs as the oracle does with the same bytes.
//!
//! Signing is the expensive part, so each input has a budget in units of
//! about one ML-DSA-87 key generation.

mod keys;
mod oracle;

use browntls_crypto::Error;
use browntls_crypto::mldsa::{MlDsa44, MlDsa65, MlDsa87, ParameterSet};
use browntls_crypto::rand::SecureRandom;

use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 16;
/// Cost budget per input.
const BUDGET: u32 = 24;

const OP_KEYGEN: u8 = 0;
const OP_SIGN: u8 = 1;
const OP_VERIFY: u8 = 2;
const OP_EXPANDED: u8 = 3;
const OPS: usize = 4;

/// Cost of each operation against [`BUDGET`], in [`OPS`] order.
const COST: [u32; OPS] = [3, 12, 3, 4];

/// A parameter set with its oracle.
pub(crate) trait Set: ParameterSet + oracle::Oracle {}

impl<T: ParameterSet + oracle::Oracle> Set for T {}

/// The `crypto_mldsa` fuzz target.
pub fn run(data: &[u8]) {
    let mut input = Input::new(data);
    let mut budget = BUDGET;
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        let op = u8::try_from(input.choose(OPS)).unwrap_or(0);
        let cost = COST[usize::from(op)];
        if cost > budget {
            break;
        }
        budget -= cost;
        match input.choose(3) {
            0 => set_op::<MlDsa44>(op, &mut input),
            1 => set_op::<MlDsa65>(op, &mut input),
            _ => set_op::<MlDsa87>(op, &mut input),
        }
    }
}

fn set_op<P: Set>(op: u8, input: &mut Input<'_>) {
    match op {
        OP_KEYGEN => keys::keygen_op::<P>(input),
        OP_SIGN => keys::sign_op::<P>(input),
        OP_VERIFY => keys::verify_op::<P>(input),
        _ => keys::expanded_op::<P>(input),
    }
}

/// `len` bytes from the input, zero-padded.
fn exact(input: &mut Input<'_>, len: usize) -> Vec<u8> {
    let mut out = input.bytes(len).to_vec();
    out.resize(len, 0);
    out
}

/// Flips bytes of `bytes`: a count (0 to 3), then for each a 16-bit
/// position and a byte to XOR in (made odd, so never zero).
fn flip(input: &mut Input<'_>, bytes: &mut [u8]) {
    for _ in 0..input.choose(4) {
        let at = usize::from(input.u16());
        let x = input.byte() | 1;
        if !bytes.is_empty() {
            let at = at % bytes.len();
            bytes[at] ^= x;
        }
    }
}

/// Returns a fixed 32-byte value, and checks that 32 bytes are asked for.
struct Fixed([u8; 32]);

impl SecureRandom for Fixed {
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        assert_eq!(dest.len(), 32, "ML-DSA draws 32 bytes at a time");
        dest.copy_from_slice(&self.0);
        Ok(())
    }
}

/// A random source that always fails.
struct Failing;

impl SecureRandom for Failing {
    fn fill(&self, _dest: &mut [u8]) -> Result<(), Error> {
        Err(Error::RandomFailure)
    }
}

/// Starting inputs for `crypto_mldsa`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    let seed: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
    let rnd: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(11) ^ 0xc3).collect();
    let field = |bytes: &[u8]| {
        let mut out = Vec::new();
        put_field(&mut out, bytes);
        out
    };
    let short = |bytes: &[u8]| {
        let mut out = Vec::new();
        put_short_field(&mut out, bytes);
        out
    };
    for set in 0..3u8 {
        let (pk_len, sk_len, sig_len) =
            [(1312, 2560, 2420), (1952, 4032, 3309), (2592, 4896, 4627)][usize::from(set)];
        let op = |op: u8| [op, set];
        // key generation, with wrong key lengths
        seeds.push([&op(OP_KEYGEN)[..], &seed, &[0, 0]].concat());
        seeds.push([&op(OP_KEYGEN)[..], &[0; 32], &[0x05, 0x21]].concat());
        // signing: empty context, a context, the longest context
        seeds.push(
            [
                &op(OP_SIGN)[..],
                &seed,
                &field(b"message"),
                &[0],
                &rnd,
                &[0, 7, 1, 9],
            ]
            .concat(),
        );
        seeds.push(
            [
                &op(OP_SIGN)[..],
                &seed,
                &field(&[0x33; 300]),
                &short(b"context"),
                &rnd,
                &[1, 2, 3, 4],
            ]
            .concat(),
        );
        seeds.push(
            [
                &op(OP_SIGN)[..],
                &seed,
                &field(b""),
                &short(&[0xa5; 255]),
                &rnd,
                &[0, 0, 0, 0],
            ]
            .concat(),
        );
        // verification: genuine key and signature, untouched and flipped;
        // fuzzed signature of the right length; fuzzed key; short key
        let genuine = [
            &op(OP_VERIFY)[..],
            &[0],
            &seed,
            &field(b"m"),
            &short(b"c"),
            &[0],
        ]
        .concat();
        seeds.push([&genuine[..], &[0]].concat());
        seeds.push([&genuine[..], &[1, 0, 10, 4]].concat());
        seeds.push([&op(OP_VERIFY)[..], &[0], &seed, &field(b"m"), &[0, 1], &rnd].concat());
        seeds.push(
            [
                &op(OP_VERIFY)[..],
                &[1],
                &vec![0x11; pk_len],
                &field(b"m"),
                &[0, 2],
                &field(&rnd),
            ]
            .concat(),
        );
        let mut fuzzed_key = [&op(OP_VERIFY)[..], &[2]].concat();
        fuzzed_key.extend(field(&vec![0x11; pk_len]));
        fuzzed_key.extend([&field(b"m")[..], &[0, 1], &vec![0x22; sig_len]].concat());
        seeds.push(fuzzed_key);
        seeds.push([&op(OP_VERIFY)[..], &[2], &field(&[1, 2, 3])].concat());
        // expanded keys: raw of the right and a wrong length; genuine,
        // flipped in K, in rho, in t0, twice at one place
        seeds.push([&op(OP_EXPANDED)[..], &[0], &field(&[7; 40])].concat());
        seeds.push([&op(OP_EXPANDED)[..], &[1], &vec![0x42; sk_len]].concat());
        for flips in [
            &[0u8][..],
            &[1, 0, 40, 0x80],
            &[1, 0, 3, 1],
            &[1, 0x09, 0xf0, 2],
            &[2, 0, 70, 4, 0, 70, 4],
        ] {
            seeds.push([&op(OP_EXPANDED)[..], &[2], &seed, flips, &short(b"msg")].concat());
        }
    }
    // Several operations in one input.
    seeds.push(
        [
            &[OP_KEYGEN, 0][..],
            &seed,
            &[0, 0],
            &[OP_KEYGEN, 2],
            &seed,
            &[0, 0],
        ]
        .concat(),
    );
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every seed runs, and the seeds fit the budget (one operation each,
    /// apart from the last).
    #[test]
    fn seeds_run_within_the_budget() {
        let seeds = seeds();
        for seed in &seeds {
            run(seed);
        }
        assert!(COST.iter().all(|&c| c <= BUDGET));
        assert!(2 * COST[usize::from(OP_KEYGEN)] <= BUDGET);
    }
}
