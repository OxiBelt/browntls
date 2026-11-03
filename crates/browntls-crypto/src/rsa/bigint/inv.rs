//! Constant-time modular inversion modulo an odd number (Bernstein–Yang
//! "safegcd" divsteps).
//!
//! The algorithm follows the constant-time variant of libsecp256k1's
//! `modinv64` generalised to any length up to [`HALF_LIMBS`] 64-bit limbs:
//! values are held in signed 62-bit limbs; each batch runs 62 branch-free
//! divsteps on the low 64 bits of `f` and `g`, producing a 2×2 transition
//! matrix scaled by `2^62`, which is then applied to the full `f`, `g` and
//! to the Bézout coefficients `d`, `e` (kept modulo `m` with a Montgomery-style
//! division by `2^62`).
//!
//! # Iteration count
//!
//! Divsteps start at `δ = 1`. For an odd `f` and `0 <= g < 2^b` with
//! `f < 2^b` (so `f^2 + 4 g^2 <= 5 · 2^(2b)`), Bernstein and Yang ("Fast
//! constant-time gcd computation and modular inversion", 2019, theorem 11.2)
//! prove that `⌊(49 b + 57) / 17⌋` divsteps (for `b >= 46`) reach `g = 0`
//! and `f = ±gcd(f, g)`. Here `b = 64 · len` (public), rounded up to whole
//! batches of 62; extra divsteps after `g = 0` leave `f` and `d` unchanged.
//!
//! # Timing
//!
//! Loop counts depend only on the limb count; every conditional is an
//! arithmetic mask passed through [`core::hint::black_box`]; table indices
//! are public. Multiplications are `i64 × i64 → i128`, which compile to
//! fixed-latency multiply instructions on the supported 64-bit targets.

use core::hint::black_box;

use super::HALF_LIMBS;
use crate::zeroize::Zeroize;

/// Mask of the low 62 bits.
const M62: u64 = u64::MAX >> 2;

/// Signed 62-bit limbs needed for [`HALF_LIMBS`] 64-bit limbs with headroom
/// for a sign and the factor-of-two range of `d` and `e`.
const CAP62: usize = limbs62(HALF_LIMBS);

/// Number of signed 62-bit limbs used for a `len`-limb modulus: enough for
/// `64 len + 3` bits, so that values in `(-2 m, 2 m)` fit with the top limb
/// well inside `i64`.
const fn limbs62(len: usize) -> usize {
    (64 * len + 3).div_ceil(62)
}

/// Number of 62-divstep batches for `len`-limb inputs (see the module
/// documentation for the bound).
const fn batches(len: usize) -> usize {
    let b = 64 * len;
    let steps = (49 * b + 57) / 17;
    steps.div_ceil(62)
}

/// Transition matrix `[[u, v], [q, r]]` scaled by `2^62`.
#[derive(Clone, Copy)]
struct Trans {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// Sign-extends a limb stored as `u64` (two's complement) to `i128`.
#[inline(always)]
fn wide(x: u64) -> i128 {
    i128::from(x as i64)
}

/// Converts `x` (64-bit limbs) into `out.len()` signed 62-bit limbs (all
/// non-negative). Constant time.
fn to_signed62(out: &mut [u64], x: &[u64]) {
    for (i, o) in out.iter_mut().enumerate() {
        let bit = 62 * i;
        let limb = bit / 64;
        let shift = bit % 64;
        let lo = x.get(limb).copied().unwrap_or(0) >> shift;
        let hi = if shift > 2 {
            x.get(limb + 1).copied().unwrap_or(0) << (64 - shift)
        } else {
            0
        };
        *o = (lo | hi) & M62;
    }
}

/// Converts normalised signed 62-bit limbs (each in `[0, 2^62)`, value below
/// `2^(64 out.len())`) back to 64-bit limbs. Constant time.
fn from_signed62(out: &mut [u64], x: &[u64]) {
    out.fill(0);
    for (i, &v) in x.iter().enumerate() {
        let bit = 62 * i;
        let limb = bit / 64;
        let shift = bit % 64;
        if limb < out.len() {
            out[limb] |= v << shift;
        }
        if shift > 2 && limb + 1 < out.len() {
            out[limb + 1] |= v >> (64 - shift);
        }
    }
}

/// Runs 62 divsteps on the low words `f0` (odd) and `g0` of each of `N`
/// independent problems (interleaved, so that their serial dependency chains
/// overlap), updating `delta` and returning the transition matrices scaled
/// by `2^62`.
///
/// Each divstep is, with `δ > 0` and `g` odd: `(δ, f, g) ← (1 - δ, g,
/// (g - f) / 2)`; otherwise `(δ, f, g) ← (1 + δ, f, (g + (g mod 2) f) / 2)`.
/// The matrix tracks `2^i [f, g] = [[u, v], [q, r]] [f0, g0]` modulo `2^64`;
/// its entries stay in `[-2^62, 2^62]` (each row's absolute sum at most
/// doubles per step).
#[inline(always)]
fn divsteps_62<const N: usize>(delta: &mut [i64; N], f0: [u64; N], g0: [u64; N]) -> [Trans; N] {
    let (mut u, mut v, mut q, mut r) = ([1u64; N], [0u64; N], [0u64; N], [1u64; N]);
    let (mut f, mut g) = (f0, g0);
    let mut d = *delta;
    for _ in 0..62 {
        for c in 0..N {
            debug_assert_eq!(f[c] & 1, 1);
            // c1: δ > 0 (|δ| is far below 2^62, so the negation cannot
            // overflow).
            let c1 = black_box((d[c].wrapping_neg() >> 63) as u64);
            // c2: g odd.
            let c2 = black_box((g[c] & 1).wrapping_neg());
            // x, y, z: f, u, v negated when δ > 0.
            let x = (f[c] ^ c1).wrapping_sub(c1);
            let y = (u[c] ^ c1).wrapping_sub(c1);
            let z = (v[c] ^ c1).wrapping_sub(c1);
            // g += ±f when g is odd (g - f in the swap case, g + f otherwise).
            g[c] = g[c].wrapping_add(x & c2);
            q[c] = q[c].wrapping_add(y & c2);
            r[c] = r[c].wrapping_add(z & c2);
            // Swap case (δ > 0 and g odd): f ← old g (= f + (g - f)), δ ← -δ.
            let m = c1 & c2;
            d[c] = (d[c] ^ m as i64).wrapping_sub(m as i64).wrapping_add(1);
            f[c] = f[c].wrapping_add(g[c] & m);
            u[c] = u[c].wrapping_add(q[c] & m);
            v[c] = v[c].wrapping_add(r[c] & m);
            // g is even now: halve it, and double the f row instead of
            // halving the g row of the matrix.
            g[c] >>= 1;
            u[c] <<= 1;
            v[c] <<= 1;
        }
    }
    *delta = d;
    core::array::from_fn(|c| Trans {
        u: u[c] as i64,
        v: v[c] as i64,
        q: q[c] as i64,
        r: r[c] as i64,
    })
}

/// `[f, g] ← t [f, g] / 2^62` (exact division). Limbs below the top are
/// kept in `[0, 2^62)`; the top limb carries the sign.
fn update_fg(f: &mut [u64], g: &mut [u64], t: Trans) {
    let n = f.len();
    let (u, v, q, r) = (
        i128::from(t.u),
        i128::from(t.v),
        i128::from(t.q),
        i128::from(t.r),
    );
    let mut cf = u * wide(f[0]) + v * wide(g[0]);
    let mut cg = q * wide(f[0]) + r * wide(g[0]);
    debug_assert_eq!(cf as u64 & M62, 0);
    debug_assert_eq!(cg as u64 & M62, 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..n {
        cf += u * wide(f[i]) + v * wide(g[i]);
        cg += q * wide(f[i]) + r * wide(g[i]);
        f[i - 1] = cf as u64 & M62;
        g[i - 1] = cg as u64 & M62;
        cf >>= 62;
        cg >>= 62;
    }
    f[n - 1] = cf as u64;
    g[n - 1] = cg as u64;
}

/// `[d, e] ← (t [d, e] + m [md, me]) / 2^62` with `md`, `me` chosen to make
/// the division exact and to keep `d`, `e` in `(-2 m, m)` (libsecp256k1's
/// `update_de_62` argument carries over unchanged: it only uses
/// `|u| + |v| <= 2^62` and `|q| + |r| <= 2^62`).
fn update_de(d: &mut [u64], e: &mut [u64], t: Trans, m: &[u64], m_inv62: u64) {
    let n = d.len();
    let sd = black_box(d[n - 1] as i64 >> 63);
    let se = black_box(e[n - 1] as i64 >> 63);
    let mut md = (t.u & sd).wrapping_add(t.v & se);
    let mut me = (t.q & sd).wrapping_add(t.r & se);
    let (u, v, q, r) = (
        i128::from(t.u),
        i128::from(t.v),
        i128::from(t.q),
        i128::from(t.r),
    );
    let mut cd = u * wide(d[0]) + v * wide(e[0]);
    let mut ce = q * wide(d[0]) + r * wide(e[0]);
    md = md.wrapping_sub((m_inv62.wrapping_mul(cd as u64).wrapping_add(md as u64) & M62) as i64);
    me = me.wrapping_sub((m_inv62.wrapping_mul(ce as u64).wrapping_add(me as u64) & M62) as i64);
    let (md128, me128) = (i128::from(md), i128::from(me));
    cd += wide(m[0]) * md128;
    ce += wide(m[0]) * me128;
    debug_assert_eq!(cd as u64 & M62, 0);
    debug_assert_eq!(ce as u64 & M62, 0);
    cd >>= 62;
    ce >>= 62;
    for i in 1..n {
        cd += u * wide(d[i]) + v * wide(e[i]) + wide(m[i]) * md128;
        ce += q * wide(d[i]) + r * wide(e[i]) + wide(m[i]) * me128;
        d[i - 1] = cd as u64 & M62;
        e[i - 1] = ce as u64 & M62;
        cd >>= 62;
        ce >>= 62;
    }
    d[n - 1] = cd as u64;
    e[n - 1] = ce as u64;
}

/// Propagates carries so that every limb but the top one is in `[0, 2^62)`.
fn carry62(x: &mut [u64]) {
    let n = x.len();
    for i in 0..n - 1 {
        x[i + 1] = x[i + 1].wrapping_add((x[i] as i64 >> 62) as u64);
        x[i] &= M62;
    }
}

/// Adds `m` to `x` when `x` is negative (constant time).
fn add_if_negative(x: &mut [u64], m: &[u64]) {
    let neg = black_box((x[x.len() - 1] as i64 >> 63) as u64);
    for (a, &b) in x.iter_mut().zip(m) {
        *a = a.wrapping_add(b & neg);
    }
}

/// Maps `d` in `(-2 m, m)` to `sign · d mod m` in `[0, m)`, where `sign` is
/// the sign of `f_top` (libsecp256k1's `normalize_62`).
fn normalize(d: &mut [u64], f_top: u64, m: &[u64]) {
    // (-2m, m) -> (-m, m).
    add_if_negative(d, m);
    let neg = black_box((f_top as i64 >> 63) as u64);
    for a in d.iter_mut() {
        *a = (*a ^ neg).wrapping_sub(neg);
    }
    carry62(d);
    // (-m, m) -> [0, m).
    add_if_negative(d, m);
    carry62(d);
}

/// `m0^-1 mod 2^64` for odd `m0` (Newton iteration).
fn inv_word(m0: u64) -> u64 {
    let mut inv = m0;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    }
    inv
}

/// `out = x^-1 mod m` for an odd modulus `m` of `len <= HALF_LIMBS` limbs and
/// any `x < 2^(64 len)` with `gcd(x, m) = 1`; `out` is fully reduced.
///
/// If `gcd(x, m) != 1` the output is unspecified (but below `m`); callers
/// that cannot rule this out must check the result. Constant time in `x` and
/// `m`; the running time depends only on `len`.
///
/// # Panics
///
/// Panics if the lengths differ, are zero or exceed [`HALF_LIMBS`] (lengths
/// are public parameters).
pub(crate) fn mod_inverse(out: &mut [u64], x: &[u64], m: &[u64]) {
    mod_inverse_n::<1>([out], [x], [m]);
}

/// Two independent [`mod_inverse`] problems of the same length, computed
/// together (about the cost of one: their divstep chains run interleaved).
///
/// # Panics
///
/// As [`mod_inverse`], and if the two lengths differ.
pub(crate) fn mod_inverse_pair(out: [&mut [u64]; 2], x: [&[u64]; 2], m: [&[u64]; 2]) {
    mod_inverse_n::<2>(out, x, m);
}

#[inline(never)]
fn mod_inverse_n<const N: usize>(out: [&mut [u64]; N], x: [&[u64]; N], m: [&[u64]; N]) {
    let len = m[0].len();
    assert!((1..=HALF_LIMBS).contains(&len));
    for c in 0..N {
        assert!(m[c].len() == len && x[c].len() == len && out[c].len() == len);
        debug_assert_eq!(m[c][0] & 1, 1);
    }
    let n = limbs62(len);

    let mut mm = [[0u64; CAP62]; N];
    let mut f = [[0u64; CAP62]; N];
    let mut g = [[0u64; CAP62]; N];
    let mut d = [[0u64; CAP62]; N];
    let mut e = [[0u64; CAP62]; N];
    let mut m_inv62 = [0u64; N];
    for c in 0..N {
        to_signed62(&mut mm[c][..n], m[c]);
        f[c] = mm[c];
        to_signed62(&mut g[c][..n], x[c]);
        e[c][0] = 1;
        m_inv62[c] = inv_word(m[c][0]) & M62;
    }
    let mut delta = [1i64; N];

    for _ in 0..batches(len) {
        let t = divsteps_62::<N>(
            &mut delta,
            core::array::from_fn(|c| f[c][0]),
            core::array::from_fn(|c| g[c][0]),
        );
        for c in 0..N {
            update_de(
                &mut d[c][..n],
                &mut e[c][..n],
                t[c],
                &mm[c][..n],
                m_inv62[c],
            );
            update_fg(&mut f[c][..n], &mut g[c][..n], t[c]);
        }
    }
    // g = 0 and f = ±1 now (for coprime inputs), and d = ±x^-1 mod m.
    for (c, o) in out.into_iter().enumerate() {
        normalize(&mut d[c][..n], f[c][n - 1], &mm[c][..n]);
        from_signed62(o, &d[c][..n]);
    }

    for c in 0..N {
        mm[c].zeroize();
        f[c].zeroize();
        g[c].zeroize();
        d[c].zeroize();
        e[c].zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::bigint::{self, mont::Kernel, mont::Mont};
    use std::vec;
    use std::vec::Vec;

    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed >> 12;
        *seed ^= *seed << 25;
        *seed ^= *seed >> 27;
        seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// `(x * y) mod m` with the schoolbook product and `ct_mod`.
    fn mul_mod(x: &[u64], y: &[u64], m: &[u64]) -> Vec<u64> {
        let mut prod = vec![0u64; 2 * m.len()];
        bigint::mul(&mut prod, x, y);
        let mut r = vec![0u64; m.len()];
        bigint::ct_mod(&mut r, &prod, m);
        r
    }

    fn one(len: usize) -> Vec<u64> {
        let mut v = vec![0u64; len];
        v[0] = 1;
        v
    }

    /// Variable-time binary gcd (test oracle).
    fn gcd_is_one(a: &[u64], b: &[u64]) -> bool {
        let (mut a, mut b) = (a.to_vec(), b.to_vec());
        let zero = |v: &[u64]| v.iter().all(|&l| l == 0);
        if zero(&a) {
            return b == one(b.len());
        }
        while a[0] & 1 == 0 {
            bigint::shr1(&mut a);
        }
        while !zero(&b) {
            while b[0] & 1 == 0 {
                bigint::shr1(&mut b);
            }
            if bigint::ct_lt(&b, &a).declassify() {
                core::mem::swap(&mut a, &mut b);
            }
            let tmp = b.clone();
            bigint::sub(&mut b, &tmp, &a);
        }
        a == one(a.len())
    }

    fn mersenne(bits: usize) -> Vec<u64> {
        let len = bits.div_ceil(64);
        let mut p = vec![u64::MAX; len];
        if bits % 64 != 0 {
            p[len - 1] = (1u64 << (bits % 64)) - 1;
        }
        p
    }

    /// Fermat inverse with the existing constant-time exponentiation.
    fn fermat_inverse(x: &[u64], p: &[u64]) -> Vec<u64> {
        let len = p.len();
        let ctx = Mont::<HALF_LIMBS>::new(p, Kernel::Soft).unwrap();
        let mut xm = vec![0u64; len];
        ctx.to_mont(&mut xm, x);
        let mut e = p.to_vec();
        bigint::sub_word(&mut e, 2);
        let mut r = vec![0u64; len];
        ctx.exp_ct(&mut r, &xm, &e);
        let mut out = vec![0u64; len];
        ctx.demont(&mut out, &r);
        out
    }

    #[test]
    fn signed62_roundtrip() {
        let mut seed = 3u64;
        for len in 1..=HALF_LIMBS {
            let x: Vec<u64> = (0..len).map(|_| rng(&mut seed)).collect();
            let mut s = vec![0u64; limbs62(len)];
            to_signed62(&mut s, &x);
            assert!(s.iter().all(|&l| (0..1 << 62).contains(&l)));
            let mut back = vec![0u64; len];
            from_signed62(&mut back, &s);
            assert_eq!(back, x, "len {len}");
        }
    }

    #[test]
    fn batch_counts() {
        // 1024-bit inputs need 2954 divsteps (48 batches of 62).
        assert_eq!(batches(16), 48);
        assert_eq!(limbs62(16), 17);
        assert_eq!(CAP62, 67);
    }

    #[test]
    fn matches_definition_on_random_odd_moduli() {
        let mut seed = 0x5eed_1234_abcd_0001u64;
        // Every limb count up to 24, then the RSA half sizes up to 4096 bits.
        let lens: Vec<usize> = (1..=24).chain([32, 33, 48, 63, 64]).collect();
        for len in lens {
            let iters = if len > 32 { 3 } else { 8 };
            for it in 0..iters {
                let mut m: Vec<u64> = (0..len).map(|_| rng(&mut seed)).collect();
                match it % 3 {
                    0 => m[len - 1] |= 1 << 63,
                    1 => m[len - 1] = 1 + (m[len - 1] >> 40),
                    _ => {}
                }
                m[0] |= 1;
                if m == one(len) {
                    continue;
                }
                let x: Vec<u64> = (0..len).map(|_| rng(&mut seed)).collect();
                let mut inv = vec![0u64; len];
                mod_inverse(&mut inv, &x, &m);
                assert!(bigint::ct_lt(&inv, &m).declassify(), "len {len}");
                let mut xr = vec![0u64; len];
                bigint::ct_mod(&mut xr, &x, &m);
                if gcd_is_one(&xr, &m) {
                    assert_eq!(mul_mod(&xr, &inv, &m), one(len), "len {len} it {it}");
                }
            }
        }
    }

    #[test]
    fn matches_fermat_on_primes() {
        // Mersenne primes, and the edge inputs 1, 2, p - 1, p - 2, 2^k and
        // all-ones values below p.
        let mut seed = 77u64;
        for bits in [61usize, 127, 521, 607, 1279, 2203, 2281, 3217] {
            let p = mersenne(bits);
            let len = p.len();
            let mut cases: Vec<Vec<u64>> = Vec::new();
            cases.push(one(len));
            let mut two = one(len);
            two[0] = 2;
            cases.push(two);
            let mut pm1 = p.clone();
            bigint::sub_word(&mut pm1, 1);
            cases.push(pm1.clone());
            bigint::sub_word(&mut pm1, 1);
            cases.push(pm1);
            let mut pow = vec![0u64; len];
            pow[len / 2] = 1 << 17;
            cases.push(pow);
            let mut x = p.clone();
            x[0] ^= 0xff;
            cases.push(x);
            for _ in 0..3 {
                let mut x: Vec<u64> = (0..len).map(|_| rng(&mut seed)).collect();
                x[len - 1] &= p[len - 1] >> 1;
                cases.push(x);
            }
            for x in &cases {
                let mut inv = vec![0u64; len];
                mod_inverse(&mut inv, x, &p);
                assert_eq!(inv, fermat_inverse(x, &p), "bits {bits}");
                assert_eq!(mul_mod(x, &inv, &p), one(len));
            }
        }
    }

    #[test]
    fn pair_matches_single() {
        let mut seed = 0xabcd_u64;
        for len in [1usize, 2, 7, 16, 17, 24, 32, 48, 64] {
            for _ in 0..3 {
                let ms: Vec<Vec<u64>> = (0..2)
                    .map(|_| {
                        let mut m: Vec<u64> = (0..len).map(|_| rng(&mut seed)).collect();
                        m[0] |= 1;
                        m
                    })
                    .collect();
                let xs: Vec<Vec<u64>> = (0..2)
                    .map(|_| (0..len).map(|_| rng(&mut seed)).collect())
                    .collect();
                let mut single = [vec![0u64; len], vec![0u64; len]];
                for c in 0..2 {
                    mod_inverse(&mut single[c], &xs[c], &ms[c]);
                }
                let mut pair = [vec![0u64; len], vec![0u64; len]];
                let [p0, p1] = &mut pair;
                mod_inverse_pair([p0, p1], [&xs[0], &xs[1]], [&ms[0], &ms[1]]);
                assert_eq!(pair, single, "len {len}");
            }
        }
    }

    #[test]
    fn unreduced_inputs_and_tiny_moduli() {
        // x >= m (but below 2^(64 len)) is accepted; m = 3, 5, ... with one
        // limb exercise the shortest paths.
        for m0 in [3u64, 5, 7, 0xffff_ffff_ffff_ffc5, u64::MAX] {
            for x0 in [1u64, 2, 4, 1 << 63, u64::MAX - 1] {
                let m = [m0];
                let x = [x0];
                let mut inv = [0u64];
                mod_inverse(&mut inv, &x, &m);
                let xr = u128::from(x0) % u128::from(m0);
                if gcd_is_one(&[xr as u64], &m) {
                    assert_eq!(xr * u128::from(inv[0]) % u128::from(m0), 1, "{m0} {x0}");
                }
            }
        }
    }
}
