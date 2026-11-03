//! Constant-time modular inversion for odd moduli below `2^256` by the
//! Bernstein–Yang "safegcd" algorithm ("Fast constant-time gcd computation and
//! modular inversion", TCHES 2019), in the half-delta ("hddivstep") variant
//! and signed 62-bit limb layout described by Pieter Wuille for
//! libsecp256k1 (`doc/safegcd_implementation.md`).
//!
//! The input is processed in 10 batches of 59 division steps. For moduli and
//! inputs below `2^256`, 590 hddivsteps always suffice to reach `g = 0` (the
//! bound derived in Bernstein–Yang and in §5 of `safegcd_implementation.md`;
//! relied on here, not re-proved), so the number of batches is fixed
//! and the operation sequence never depends on the input. Every data-dependent
//! choice is a mask that passes through [`barrier`].
//!
//! Numbers are five signed limbs `v[0] + v[1] 2^62 + ... + v[4] 2^248`; limbs
//! 0..3 are in `[0, 2^62)` in normalised form and the top limb carries the sign.

use super::mont::barrier;

/// Low 62 bits.
const M62: u64 = u64::MAX >> 2;

/// A modulus in signed-62 form with `m^-1 mod 2^62`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Modulus {
    m: [i64; 5],
    inv62: u64,
}

impl Modulus {
    /// Prepares an odd modulus `m < 2^256`.
    pub(crate) const fn new(m: &[u64; 4]) -> Self {
        assert!(m[0] & 1 == 1, "modulus must be odd");
        // Newton iteration for m^-1 mod 2^64.
        let mut inv = 1u64;
        let mut i = 0;
        while i < 6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
            i += 1;
        }
        Self {
            m: to_signed62(m),
            inv62: inv & M62,
        }
    }
}

/// Splits 256 bits into five 62-bit limbs (the top one holds 8 bits).
#[inline]
const fn to_signed62(a: &[u64; 4]) -> [i64; 5] {
    [
        (a[0] & M62) as i64,
        (((a[0] >> 62) | (a[1] << 2)) & M62) as i64,
        (((a[1] >> 60) | (a[2] << 4)) & M62) as i64,
        (((a[2] >> 58) | (a[3] << 6)) & M62) as i64,
        (a[3] >> 56) as i64,
    ]
}

/// Joins normalised limbs (each in `[0, 2^62)`, value below `2^256`).
#[inline]
#[allow(clippy::cast_sign_loss)]
fn from_signed62(v: &[i64; 5]) -> [u64; 4] {
    let v = v.map(|x| x as u64);
    [
        v[0] | (v[1] << 62),
        (v[1] >> 2) | (v[2] << 60),
        (v[2] >> 4) | (v[3] << 58),
        (v[3] >> 6) | (v[4] << 56),
    ]
}

/// The transition matrix of a batch, scaled by `2^62`.
struct Matrix {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// 59 hddivsteps on the low limbs `f0`, `g0`; returns the new `zeta`
/// (`-(delta + 1/2)`) and the transition matrix.
#[inline]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn divsteps_59(mut zeta: i64, f0: u64, g0: u64) -> (i64, Matrix) {
    // The matrix starts as 8 * identity so that it ends scaled by 2^62; the
    // entries are signed values in [-2^62, 2^62] held as two's complement.
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g) = (f0, g0);
    for _ in 3..62 {
        // mask1: zeta < 0; mask2: g odd.
        let mask1 = barrier((zeta >> 63) as u64);
        let mask2 = barrier((g & 1).wrapping_neg());
        // Conditionally negated f, u, v.
        let x = (f ^ mask1).wrapping_sub(mask1);
        let y = (u ^ mask1).wrapping_sub(mask1);
        let z = (v ^ mask1).wrapping_sub(mask1);
        // Conditionally add them to g, q, r.
        g = g.wrapping_add(x & mask2);
        q = q.wrapping_add(y & mask2);
        r = r.wrapping_add(z & mask2);
        // Swap case: zeta < 0 and g odd.
        let mask1 = mask1 & mask2;
        // zeta becomes -zeta - 2 (swap) or zeta - 1.
        zeta = (zeta ^ mask1 as i64).wrapping_sub(1);
        // Conditionally add the new g, q, r to f, u, v.
        f = f.wrapping_add(g & mask1);
        u = u.wrapping_add(q & mask1);
        v = v.wrapping_add(r & mask1);
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    (
        zeta,
        Matrix {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

/// `[d, e] = (t [d, e] + m [md, me]) / 2^62` with `md`, `me` chosen to make
/// the division exact and keep `d`, `e` in `(-2m, m)`.
#[inline]
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
fn update_de(d: &mut [i64; 5], e: &mut [i64; 5], t: &Matrix, m: &Modulus) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    // Start with [u, q] if d is negative, plus [v, r] if e is negative.
    let sd = barrier((d[4] >> 63) as u64) as i64;
    let se = barrier((e[4] >> 63) as u64) as i64;
    let mut md = (u & sd) + (v & se);
    let mut me = (q & sd) + (r & se);
    let mut cd = i128::from(u) * i128::from(d[0]) + i128::from(v) * i128::from(e[0]);
    let mut ce = i128::from(q) * i128::from(d[0]) + i128::from(r) * i128::from(e[0]);
    // Correct md, me so that the low 62 bits of the sums vanish.
    md -= (m.inv62.wrapping_mul(cd as u64).wrapping_add(md as u64) & M62) as i64;
    me -= (m.inv62.wrapping_mul(ce as u64).wrapping_add(me as u64) & M62) as i64;
    cd += i128::from(m.m[0]) * i128::from(md);
    ce += i128::from(m.m[0]) * i128::from(me);
    debug_assert_eq!(cd as u64 & M62, 0);
    debug_assert_eq!(ce as u64 & M62, 0);
    cd >>= 62;
    ce >>= 62;
    for i in 1..5 {
        cd += i128::from(u) * i128::from(d[i])
            + i128::from(v) * i128::from(e[i])
            + i128::from(m.m[i]) * i128::from(md);
        ce += i128::from(q) * i128::from(d[i])
            + i128::from(r) * i128::from(e[i])
            + i128::from(m.m[i]) * i128::from(me);
        d[i - 1] = (cd as u64 & M62) as i64;
        e[i - 1] = (ce as u64 & M62) as i64;
        cd >>= 62;
        ce >>= 62;
    }
    d[4] = cd as i64;
    e[4] = ce as i64;
}

/// `[f, g] = t [f, g] / 2^62` (exact).
#[inline]
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
fn update_fg(f: &mut [i64; 5], g: &mut [i64; 5], t: &Matrix) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mut cf = i128::from(u) * i128::from(f[0]) + i128::from(v) * i128::from(g[0]);
    let mut cg = i128::from(q) * i128::from(f[0]) + i128::from(r) * i128::from(g[0]);
    debug_assert_eq!(cf as u64 & M62, 0);
    debug_assert_eq!(cg as u64 & M62, 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..5 {
        cf += i128::from(u) * i128::from(f[i]) + i128::from(v) * i128::from(g[i]);
        cg += i128::from(q) * i128::from(f[i]) + i128::from(r) * i128::from(g[i]);
        f[i - 1] = (cf as u64 & M62) as i64;
        g[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f[4] = cf as i64;
    g[4] = cg as i64;
}

/// Brings `r` from `(-2m, m)` to `[0, m)`, negating it first when `sign < 0`.
#[inline]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn normalize(r: &mut [i64; 5], sign: i64, m: &Modulus) {
    let propagate = |r: &mut [i64; 5]| {
        for i in 0..4 {
            r[i + 1] += r[i] >> 62;
            r[i] &= M62 as i64;
        }
    };
    let cond_add = barrier((r[4] >> 63) as u64) as i64;
    for (x, mi) in r.iter_mut().zip(&m.m) {
        *x += mi & cond_add;
    }
    let cond_negate = barrier((sign >> 63) as u64) as i64;
    for x in r.iter_mut() {
        *x = (*x ^ cond_negate) - cond_negate;
    }
    propagate(r);
    let cond_add = barrier((r[4] >> 63) as u64) as i64;
    for (x, mi) in r.iter_mut().zip(&m.m) {
        *x += mi & cond_add;
    }
    propagate(r);
}

/// `x^-1 mod m` for `x < m` in constant time; `0` maps to `0`.
pub(crate) fn invert(x: &[u64; 4], m: &Modulus) -> [u64; 4] {
    let mut d = [0i64; 5];
    let mut e = [1i64, 0, 0, 0, 0];
    let mut f = m.m;
    let mut g = to_signed62(x);
    let mut zeta = -1i64;
    for _ in 0..10 {
        #[allow(clippy::cast_sign_loss)]
        let (z, t) = divsteps_59(zeta, f[0] as u64, g[0] as u64);
        zeta = z;
        update_de(&mut d, &mut e, &t, m);
        update_fg(&mut f, &mut g, &t);
    }
    debug_assert_eq!(g, [0; 5]);
    // f = +-1 (or +-m for x = 0, where d = 0); d holds +-x^-1.
    normalize(&mut d, f[4], m);
    from_signed62(&d)
}

#[cfg(test)]
mod tests {
    use super::super::mont;
    use super::*;

    const P256_P: [u64; 4] =
        mont::from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    const P256_N: [u64; 4] =
        mont::from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    /// Checks `x * invert(x) = 1 mod m` (plain domain, via Montgomery
    /// multiplication by `R^2`) on edge and random inputs.
    fn check(m: &[u64; 4], seed: u64) {
        let modulus = Modulus::new(m);
        let m_inv = mont::neg_inv(m[0]);
        let r2 = mont::r2_mod(m);
        let mul = |a: &[u64; 4], b: &[u64; 4]| {
            // a * b mod m = mont(mont(a, b), R^2).
            mont::mont_mul(&mont::mont_mul(a, b, m, m_inv), &r2, m, m_inv)
        };
        let one = [1, 0, 0, 0];
        let mut inputs = std::vec![
            one,
            [2, 0, 0, 0],
            [3, 0, 0, 0],
            mont::sub(m, &one).0,
            mont::sub(m, &[2, 0, 0, 0]).0,
            [u64::MAX, 0, 0, 0],
            [0, 0, 0, 1],
            [0, 0, 0, 1 << 63],
            mont::shr_small(m, 1),
            mont::r_mod(m),
            r2,
        ];
        let mut s = seed;
        for _ in 0..2000 {
            let v = [
                xorshift(&mut s),
                xorshift(&mut s),
                xorshift(&mut s),
                xorshift(&mut s),
            ];
            if mont::lt(&v, m) != 0 && mont::is_zero(&v) == 0 {
                inputs.push(v);
            }
            // Low-weight values exercise long runs of even g.
            let w = [xorshift(&mut s) & 0xff, 0, 0, 0];
            if mont::is_zero(&w) == 0 {
                inputs.push(w);
            }
        }
        for x in &inputs {
            let y = invert(x, &modulus);
            assert!(mont::lt(&y, m) != 0, "unreduced inverse of {x:x?}");
            assert_eq!(mul(x, &y), one, "x = {x:x?}");
        }
        assert_eq!(invert(&[0; 4], &modulus), [0; 4]);
    }

    #[test]
    fn inverts_modulo_p256_prime() {
        check(&P256_P, 0x1357_9bdf_2468_ace0);
    }

    #[test]
    fn inverts_modulo_p256_order() {
        check(&P256_N, 0x0f0e_0d0c_0b0a_0908);
    }

    #[test]
    fn matches_fermat() {
        let m = &P256_N;
        let modulus = Modulus::new(m);
        let m_inv = mont::neg_inv(m[0]);
        let one = mont::r_mod(m);
        let exp = mont::sub(m, &[2, 0, 0, 0]).0;
        let mut s = 99;
        for _ in 0..50 {
            let x = [
                xorshift(&mut s),
                xorshift(&mut s),
                xorshift(&mut s),
                xorshift(&mut s) >> 1,
            ];
            // Fermat in the Montgomery domain on x R^-1 ... compare plainly:
            // pow(x R, n - 2) = x^-1 R, and from_mont gives x^-1.
            let r2 = mont::r2_mod(m);
            let xm = mont::to_mont(&x, m, m_inv, &r2);
            let fermat = mont::from_mont(&mont::pow_pubexp(&xm, &exp, m, m_inv, &one), m, m_inv);
            assert_eq!(invert(&x, &modulus), fermat);
        }
    }
}
