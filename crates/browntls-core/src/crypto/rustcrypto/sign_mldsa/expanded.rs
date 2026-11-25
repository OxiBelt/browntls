//! Checks of an ML-DSA expanded private key (FIPS 204 Algorithm 24,
//! `skEncode`) before the `ml-dsa` crate decodes it.
//!
//! The crate has no checked decoder: its deprecated
//! `ExpandedSigningKey::from_expanded` panics on an `s1` or `s2`
//! coefficient outside `[-eta, eta]` and keeps whatever `t0` and `tr` the
//! encoding holds. [`public_key`] makes the checks of the native provider
//! (`browntls_crypto::mldsa`), so that both accept the same keys:
//!
//! * every `s1` and `s2` coefficient is in `[-eta, eta]`;
//! * `t0` is the low part of `t = A s1 + s2`, with `A` expanded from `rho`
//!   (FIPS 204 Algorithm 6, ML-DSA.KeyGen_internal, lines 3, 5 and 6);
//! * `tr` is the hash of the public key that `rho` and the high part of
//!   `t` encode (line 9).
//!
//! The signing seed `K` is independent of the rest of the key and cannot
//! be checked.
//!
//! The arithmetic on `s1`, `s2` and `t` (secret) has no branch, memory
//! access or division that depends on their values: the products are
//! 64-bit multiplications (constant-time on the targets this project
//! tests, not on every processor), the reductions are shifts,
//! multiplications by constants and masks, every check runs to completion
//! and only the final accept or reject depends on the secrets. The masks
//! and the accumulated result pass through a value barrier
//! ([`core::hint::black_box`]), as in the native provider, to discourage
//! the compiler from turning them into branches; that is a best-effort
//! hint and the generated code has not been inspected. The matrix `A` is
//! public (rejection sampling from `rho`). The secret temporaries are
//! wiped. For ML-DSA-87 on an x86-64 host the checks needed under 16 KiB
//! of stack in an optimised build and about 44 KiB in an unoptimised one.

use alloc::vec::Vec;
use core::hint::black_box;

use shake::{ExtendableOutput, Shake128, Shake256, Update, XofReader};
use zeroize::Zeroizing;

/// The degree of the polynomials.
const N: usize = 256;
/// The modulus `q = 2^23 - 2^13 + 1`.
const Q: u32 = 8_380_417;
/// The number of low bits of `t` kept in `t0` (`d`).
const D: u32 = 13;
/// The 512th root of unity `zeta`.
const ZETA: u32 = 1753;
/// `256^-1 mod q`.
const INVERSE_N: u32 = 8_347_681;
/// The largest `l` (ML-DSA-87).
const MAX_L: usize = 7;
/// The lengths of `rho`, `K` and `tr`, which start an expanded key.
const RHO_LEN: usize = 32;
const K_LEN: usize = 32;
const TR_LEN: usize = 64;
/// The length of an encoded polynomial of `t1` (10 bits a coefficient).
const T1_LEN: usize = N * 10 / 8;
/// The length of an encoded polynomial of `t0` (`d` bits a coefficient).
const T0_LEN: usize = N * D as usize / 8;
/// The SHAKE128 rate: 56 candidate coefficients a block.
const SHAKE128_RATE: usize = 168;

/// A polynomial with coefficients in `[0, q)`.
type Poly = [u32; N];

/// What the checks need of a parameter set (FIPS 204 Table 1).
pub(super) struct ParameterSet {
    k: u8,
    l: u8,
    eta: u32,
}

pub(super) const ML_DSA_44: ParameterSet = ParameterSet { k: 4, l: 4, eta: 2 };
pub(super) const ML_DSA_65: ParameterSet = ParameterSet { k: 6, l: 5, eta: 4 };
pub(super) const ML_DSA_87: ParameterSet = ParameterSet { k: 8, l: 7, eta: 2 };

impl ParameterSet {
    /// The bits of a packed `s1` or `s2` coefficient: `bitlen(2 eta)`.
    const fn eta_bits(&self) -> u32 {
        (2 * self.eta).ilog2() + 1
    }

    /// The length of an encoded polynomial of `s1` or `s2`.
    const fn s_len(&self) -> usize {
        N * self.eta_bits() as usize / 8
    }

    /// The length of an expanded private key (Table 2).
    const fn private_key_len(&self) -> usize {
        RHO_LEN
            + K_LEN
            + TR_LEN
            + (self.l as usize + self.k as usize) * self.s_len()
            + self.k as usize * T0_LEN
    }
}

/// `a - q` if `a >= q`, else `a`, for `a < 2 q`.
const fn reduce_once(a: u32) -> u32 {
    let t = a.wrapping_sub(Q);
    // The top bit of `t` is set exactly when `a < q`. The barrier keeps
    // the mask from becoming a select, which may compile to a branch.
    t.wrapping_add(Q & black_box((t >> 31).wrapping_neg()))
}

/// `a mod q` for `a < 2^46`: each fold replaces the bits from 2^23 up by
/// their value modulo `q` (`2^23 = 2^13 - 1`), leaving less than `2^36 +
/// 2^23`, then less than `2^27`, then less than `2^23 + 2^17`.
const fn reduce(a: u64) -> u32 {
    const fn fold(a: u64) -> u64 {
        (a >> 23) * ((1 << 13) - 1) + (a & ((1 << 23) - 1))
    }
    reduce_once(fold(fold(fold(a))) as u32)
}

const fn add(a: u32, b: u32) -> u32 {
    reduce_once(a + b)
}

const fn sub(a: u32, b: u32) -> u32 {
    reduce_once(a + Q - b)
}

const fn mul(a: u32, b: u32) -> u32 {
    reduce(a as u64 * b as u64)
}

/// `zeta^BitRev8(k) mod q` for `k` in `0..256` (FIPS 204 §7.5 and
/// Appendix B).
const ZETAS: Poly = {
    let mut powers = [1; N];
    let mut i = 1;
    while i < N {
        powers[i] = mul(powers[i - 1], ZETA);
        i += 1;
    }
    let mut zetas = [0; N];
    let mut k = 0;
    while k < N {
        zetas[k] = powers[(k as u8).reverse_bits() as usize];
        k += 1;
    }
    zetas
};

/// FIPS 204 Algorithm 41, NTT, in place.
fn ntt(w: &mut Poly) {
    let mut m = 0;
    let mut len = N / 2;
    while len >= 1 {
        for block in w.chunks_exact_mut(2 * len) {
            m += 1;
            let (low, high) = block.split_at_mut(len);
            for (a, b) in low.iter_mut().zip(high) {
                let t = mul(ZETAS[m], *b);
                *b = sub(*a, t);
                *a = add(*a, t);
            }
        }
        len /= 2;
    }
}

/// FIPS 204 Algorithm 42, NTT^-1, in place.
fn inverse_ntt(w: &mut Poly) {
    let mut m = N;
    let mut len = 1;
    while len < N {
        for block in w.chunks_exact_mut(2 * len) {
            m -= 1;
            let (low, high) = block.split_at_mut(len);
            for (a, b) in low.iter_mut().zip(high) {
                let t = *a;
                *a = add(t, *b);
                *b = mul(Q - ZETAS[m], sub(t, *b));
            }
        }
        len *= 2;
    }
    for c in w {
        *c = mul(INVERSE_N, *c);
    }
}

/// The element in row `r` and column `s` of the matrix `A` in the NTT
/// domain: FIPS 204 Algorithm 32, ExpandA, with Algorithm 30, RejNTTPoly.
/// Public data; the time taken depends on `rho`.
fn expand_a(rho: &[u8], r: u8, s: u8) -> Poly {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[s, r]);
    let mut reader = xof.finalize_xof();
    let mut poly = [0; N];
    let mut filled = 0;
    let mut block = [0; SHAKE128_RATE];
    while filled < N {
        reader.read(&mut block);
        for b in block.as_chunks::<3>().0 {
            // Algorithm 14, CoeffFromThreeBytes.
            let z = u32::from_le_bytes([b[0], b[1], b[2] & 0x7f, 0]);
            if z < Q && filled < N {
                poly[filled] = z;
                filled += 1;
            }
        }
    }
    poly
}

/// Reads 256 little-endian values of `bits` bits (at most 13) from `bytes`
/// (FIPS 204 Algorithm 18, SimpleBitUnpack, without its bound).
fn unpack(bytes: &[u8], bits: u32, out: &mut Poly) {
    let mut bytes = bytes.iter();
    let (mut acc, mut have) = (0u32, 0);
    for c in out {
        while have < bits {
            acc |= u32::from(bytes.next().copied().unwrap_or(0)) << have;
            have += 8;
        }
        *c = acc & ((1 << bits) - 1);
        acc >>= bits;
        have -= bits;
    }
}

/// Decodes a polynomial of `s1` or `s2` (FIPS 204 Algorithm 19, BitUnpack,
/// with `a = b = eta`): each coefficient `eta - v` modulo `q`, for the
/// packed value `v`. Returns a non-zero value if any `v` is above `2 eta`,
/// which is a coefficient below `-eta`.
fn unpack_eta(bytes: &[u8], set: &ParameterSet, out: &mut Poly) -> u32 {
    unpack(bytes, set.eta_bits(), out);
    let mut bad = 0;
    for c in out {
        bad |= black_box((2 * set.eta).wrapping_sub(*c) >> 31);
        *c = reduce_once(Q + set.eta - *c);
    }
    bad
}

/// Appends a polynomial of `t1` (FIPS 204 Algorithm 16, SimpleBitPack,
/// with `b = 2^10 - 1`).
fn pack_t1(t1: &Poly, out: &mut Vec<u8>) {
    for c in t1.as_chunks::<4>().0 {
        let v =
            u64::from(c[0]) | u64::from(c[1]) << 10 | u64::from(c[2]) << 20 | u64::from(c[3]) << 30;
        out.extend_from_slice(&v.to_le_bytes()[..5]);
    }
}

/// The parts of an expanded private key that the checks read: all but `K`.
struct Parts<'a> {
    rho: &'a [u8],
    tr: &'a [u8],
    s1: &'a [u8],
    s2: &'a [u8],
    t0: &'a [u8],
}

fn split<'a>(set: &ParameterSet, sk: &'a [u8]) -> Option<Parts<'a>> {
    if sk.len() != set.private_key_len() {
        return None;
    }
    let (rho, rest) = sk.split_at(RHO_LEN);
    let (tr, rest) = rest[K_LEN..].split_at(TR_LEN);
    let (s1, rest) = rest.split_at(usize::from(set.l) * set.s_len());
    let (s2, t0) = rest.split_at(usize::from(set.k) * set.s_len());
    Some(Parts {
        rho,
        tr,
        s1,
        s2,
        t0,
    })
}

/// Computes `t = A s1 + s2` from the parts of an expanded key (FIPS 204
/// Algorithm 6, lines 3, 5 and 6). Each row of `t0` is passed to `row`
/// with its index, every coefficient as BitPack encodes it (`2^(d-1) -
/// t0`); the result is the public key (Algorithm 22, `pkEncode`), and a
/// value that is non-zero if any coefficient of `s1` or `s2` is out of
/// range.
fn derive(
    set: &ParameterSet,
    key: &Parts<'_>,
    mut row: impl FnMut(usize, &Poly),
) -> (Vec<u8>, u32) {
    let mut bad = 0;
    let mut s1_hat = Zeroizing::new([[0; N]; MAX_L]);
    for (s1_hat, bytes) in s1_hat.iter_mut().zip(key.s1.chunks_exact(set.s_len())) {
        bad |= unpack_eta(bytes, set, s1_hat);
        ntt(s1_hat);
    }

    let mut public_key = Vec::with_capacity(RHO_LEN + usize::from(set.k) * T1_LEN);
    public_key.extend_from_slice(key.rho);
    let mut t = Zeroizing::new([0; N]);
    let mut s2 = Zeroizing::new([0; N]);
    for (r, bytes) in (0..set.k).zip(key.s2.chunks_exact(set.s_len())) {
        // t = NTT^-1(A_hat[r] . NTT(s1)) + s2[r].
        t.fill(0);
        for (s, s1_hat) in (0..set.l).zip(s1_hat.iter()) {
            let a_hat = expand_a(key.rho, r, s);
            for ((t, a), s1) in t.iter_mut().zip(a_hat).zip(s1_hat) {
                *t = add(*t, mul(a, *s1));
            }
        }
        inverse_ntt(&mut t);
        bad |= unpack_eta(bytes, set, &mut s2);

        let mut t1 = [0; N];
        for ((t, s2), t1) in t.iter_mut().zip(&*s2).zip(&mut t1) {
            let sum = add(*t, *s2);
            // FIPS 204 Algorithm 35, Power2Round: t = high 2^d + low with
            // low in (-2^(d-1), 2^(d-1)].
            let high = (sum + (1 << (D - 1)) - 1) >> D;
            *t = (1 << (D - 1)) + (high << D) - sum;
            *t1 = high;
        }
        row(usize::from(r), &t);
        pack_t1(&t1, &mut public_key);
    }
    (public_key, bad)
}

/// `tr = H(pk, 64)` (FIPS 204 Algorithm 6, line 9).
fn hash_public_key(public_key: &[u8]) -> [u8; TR_LEN] {
    let mut hash = Shake256::default();
    hash.update(public_key);
    let mut tr = [0; TR_LEN];
    hash.finalize_xof().read(&mut tr);
    tr
}

/// Checks the expanded private key `sk` of `set` as the module
/// documentation describes and returns the public key it implies, or
/// `None` if a check fails. After `Some`, `ml-dsa` decodes `sk` without
/// panicking.
pub(super) fn public_key(set: &ParameterSet, sk: &[u8]) -> Option<Vec<u8>> {
    let key = split(set, sk)?;
    // Non-zero once any check has failed.
    let mut differs = 0;
    let mut stored = Zeroizing::new([0; N]);
    let (public_key, bad) = derive(set, &key, |r, t0| {
        unpack(&key.t0[r * T0_LEN..][..T0_LEN], D, &mut stored);
        for (stored, t0) in stored.iter().zip(t0) {
            differs |= stored ^ t0;
        }
    });
    for (stored, tr) in key.tr.iter().zip(hash_public_key(&public_key)) {
        differs |= u32::from(stored ^ tr);
    }
    (black_box(bad | differs) == 0).then_some(public_key)
}

#[cfg(test)]
mod tests;
