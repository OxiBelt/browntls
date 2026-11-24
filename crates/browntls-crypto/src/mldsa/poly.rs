//! Arithmetic in `R_q = Z_q[X]/(X^256 + 1)` with `q = 8380417`: reductions,
//! the number-theoretic transform and its inverse (FIPS 204 Algorithms 41 and
//! 42), and pointwise multiplication in the NTT domain (Algorithm 45).
//!
//! This is the portable scalar backend. Coefficients are signed 32-bit
//! values. Montgomery reduction uses `R = 2^32`; the forward NTT keeps its
//! input in the plain domain and the inverse NTT multiplies by `R^2 / 256` so
//! that `invntt(ntt(a) * ntt(b))` with one Montgomery multiplication per
//! coefficient yields the plain product. NTT-domain coefficients are in the
//! FIPS 204 (bit-reversed) order, so a SIMD backend can be added behind the
//! same functions later.
//!
//! Every function is branch-free and uses no data-dependent memory index;
//! division and remainder never appear on coefficient values.

use crate::zeroize::Zeroize;

/// Number of coefficients.
pub(crate) const N: usize = 256;
/// The modulus `q`.
pub(crate) const Q: i32 = 8_380_417;
/// Dropped bits of `t` (`d`).
pub(crate) const D: u32 = 13;
/// `q^-1 mod 2^32` (as a signed value).
const QINV: i32 = 58_728_449;
/// `R^2 / 256 mod q` with `R = 2^32`: final scaling of the inverse NTT.
const INVNTT_F: i32 = 41_978;
/// The primitive 512th root of unity `zeta` (FIPS 204 §7.5).
const ZETA: u64 = 1753;

/// A polynomial; the meaning (plain or NTT domain) and the coefficient
/// range depend on context and are stated where it matters.
#[derive(Clone, Copy)]
pub(crate) struct Poly(pub(crate) [i32; N]);

impl Poly {
    pub(crate) const ZERO: Self = Self([0; N]);
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Zeroises every polynomial of a vector.
pub(crate) fn zeroize_vec(v: &mut [Poly]) {
    for p in v {
        p.zeroize();
    }
}

const fn pow_mod(base: u64, mut e: u64) -> u64 {
    let q = Q as u64;
    let mut r = 1;
    let mut b = base % q;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % q;
        }
        b = b * b % q;
        e >>= 1;
    }
    r
}

const fn bitrev8(i: usize) -> u64 {
    let mut r = 0;
    let mut k = 0;
    while k < 8 {
        r |= ((i >> k) & 1) << (7 - k);
        k += 1;
    }
    r as u64
}

/// `zeta^bitrev8(i) * 2^32 mod q`, centred in `(-q/2, q/2]` (entry 0 is
/// unused and kept at zero, as in the reference implementation).
pub(crate) const ZETAS: [i32; N] = {
    let mut t = [0i32; N];
    let q = Q as u64;
    let mut i = 1;
    while i < N {
        let m = (pow_mod(ZETA, bitrev8(i)) << 32) % q;
        t[i] = if m > q / 2 { m as i32 - Q } else { m as i32 };
        i += 1;
    }
    t
};

/// Montgomery reduction: for `|a| < 2^31 q` returns `r = a 2^-32 mod q` with
/// `|r| < q`.
#[inline]
pub(crate) fn mont_reduce(a: i64) -> i32 {
    // Truncation keeps the low 32 bits, as Montgomery reduction requires.
    let t = (a as i32).wrapping_mul(QINV);
    ((a - i64::from(t) * i64::from(Q)) >> 32) as i32
}

/// Reduction for `|a| <= 2^31 - 2^22 - 1`: returns `r = a mod q` with
/// `|r| <= 6283008`.
#[inline]
pub(crate) fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// The sign mask of `a` (`-1` if `a < 0`, otherwise `0`) behind a value
/// barrier. Every mask that selects between values derived from secrets
/// comes from here: without the barrier LLVM canonicalises `(x >> 31) & c`
/// into a select, which it may then lower to a conditional branch (observed
/// for an earlier form of `Decompose` on x86-64, and the default for
/// selects on riscv64gc without Zicond). `black_box` is a best-effort
/// hint, not a security guarantee: it discourages the transformation, and
/// the module documentation records what was inspected.
#[inline(always)]
pub(crate) fn sign_mask(a: i32) -> i32 {
    core::hint::black_box(a >> 31)
}

/// Adds `q` to a negative `a` (for `-q <= a < q`, returns `a mod q` in
/// `[0, q)`).
#[inline]
pub(crate) fn caddq(a: i32) -> i32 {
    a + (sign_mask(a) & Q)
}

/// The representative of `a` in `[0, q)` (same input range as
/// [`reduce32`]).
#[inline]
pub(crate) fn freeze(a: i32) -> i32 {
    caddq(reduce32(a))
}

/// The representative of `a` in `[-(q - 1) / 2, (q - 1) / 2]` (`a mod+- q`;
/// same input range as [`reduce32`]).
#[inline]
pub(crate) fn centre(a: i32) -> i32 {
    let a = freeze(a);
    a - (sign_mask((Q - 1) / 2 - a) & Q)
}

/// `-1` if `|a| >= bound`, otherwise `0`, for a centred `a` and a positive
/// `bound`; branch-free.
#[inline]
pub(crate) fn abs_ge(a: i32, bound: i32) -> i32 {
    let sign = sign_mask(a);
    let abs = a - (sign & (a << 1));
    (bound - 1 - abs) >> 31
}

/// `-1` if any coefficient of `p` (centred) has `|c| >= bound`, otherwise
/// `0`. Scans every coefficient; only the combined bit depends on the data.
pub(crate) fn norm_ge(p: &Poly, bound: i32) -> i32 {
    p.0.iter().fold(0, |acc, &c| acc | abs_ge(c, bound))
}

/// Forward NTT in place (FIPS 204 Algorithm 41). Input `|a| < q`
/// (or slightly more: each layer adds less than `q`); output `|a| < 9q`.
pub(crate) fn ntt(a: &mut Poly) {
    let a = &mut a.0;
    let mut k = 0;
    let mut len = 128;
    while len > 0 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = i64::from(ZETAS[k]);
            for j in start..start + len {
                let t = mont_reduce(zeta * i64::from(a[j + len]));
                a[j + len] = a[j] - t;
                a[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT in place, multiplied by the Montgomery factor `2^32`
/// (FIPS 204 Algorithm 42 combined with the conversion out of the
/// Montgomery domain of [`pointwise_acc`]). Input `|a| < q`; output
/// `|a| < q`.
pub(crate) fn invntt_tomont(a: &mut Poly) {
    let a = &mut a.0;
    let mut k = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -i64::from(ZETAS[k]);
            for j in start..start + len {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = mont_reduce(zeta * i64::from(t - a[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in a.iter_mut() {
        *c = mont_reduce(i64::from(INVNTT_F) * i64::from(*c));
    }
}

/// `acc += a * b 2^-32` coefficient-wise (NTT domain, FIPS 204 Algorithm
/// 45). Inputs `|a|, |b| < 9q`; each product term is in `(-q, q)`.
#[inline]
pub(crate) fn pointwise_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    for ((r, &x), &y) in acc.0.iter_mut().zip(a.0.iter()).zip(b.0.iter()) {
        *r += mont_reduce(i64::from(x) * i64::from(y));
    }
}

/// `out = a * b 2^-32` coefficient-wise (NTT domain).
#[inline]
pub(crate) fn pointwise(out: &mut Poly, a: &Poly, b: &Poly) {
    for ((r, &x), &y) in out.0.iter_mut().zip(a.0.iter()).zip(b.0.iter()) {
        *r = mont_reduce(i64::from(x) * i64::from(y));
    }
}

/// Applies [`reduce32`] to every coefficient.
pub(crate) fn reduce(a: &mut Poly) {
    for c in a.0.iter_mut() {
        *c = reduce32(*c);
    }
}

/// Applies [`freeze`] to every coefficient.
pub(crate) fn freeze_poly(a: &mut Poly) {
    for c in a.0.iter_mut() {
        *c = freeze(*c);
    }
}
