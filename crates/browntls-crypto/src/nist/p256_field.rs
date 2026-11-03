//! Portable P-256 field multiplication specialised to
//! `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`.
//!
//! The same algorithm as the x86-64 BMI2/ADX kernel (`p256_x86`): the full
//! 512-bit product, then four
//! Montgomery rounds that use `-p^-1 = 1 mod 2^64`, so the quotient of a round
//! is its low limb `q`, and `q * p` contributes only `q * 2^32` at limb 1 and
//! `q * p[3]` at limb 3. The result is below `2p` and is reduced by one masked
//! subtraction. Operation sequence and memory accesses are independent of the
//! operands.
//!
//! A dedicated squaring (cross products once, doubled) measured no faster
//! than this multiplication in portable code on x86-64, so squaring uses it.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

use super::curve::Fe;
use super::mont::{self, adc, mac, sbb};

/// `p[1] = 2^32 - 1`.
const P1: u64 = 0x0000_0000_ffff_ffff;
/// `p[3] = 2^64 - 2^32 + 1`.
const P3: u64 = 0xffff_ffff_0000_0001;

/// One reduction round on the window `(q, w1, w2, w3)`; returns the window
/// `(w1', w2', w3', top)` of `(window + q p) / 2^64`, which fits four limbs.
#[inline(always)]
fn round(q: u64, w1: u64, w2: u64, w3: u64) -> (u64, u64, u64, u64) {
    let (w1, c) = adc(w1, q << 32, 0);
    let (w2, c) = adc(w2, q >> 32, c);
    let prod = (q as u128) * (P3 as u128);
    let (w3, c) = adc(w3, prod as u64, c);
    (w1, w2, w3, ((prod >> 64) as u64) + c)
}

/// Montgomery reduction of a 512-bit `t` (`t < p 2^256`) to `t 2^-256 mod p`,
/// fully reduced.
#[inline(always)]
fn reduce(t: &[u64; 8]) -> Fe<4> {
    let (a, b, c, d) = round(t[0], t[1], t[2], t[3]);
    let (a, b, c, d) = round(a, b, c, d);
    let (a, b, c, d) = round(a, b, c, d);
    let (a, b, c, d) = round(a, b, c, d);
    // (a, b, c, d) + high half, below 2p.
    let (r0, k) = adc(a, t[4], 0);
    let (r1, k) = adc(b, t[5], k);
    let (r2, k) = adc(c, t[6], k);
    let (r3, top) = adc(d, t[7], k);
    let (s0, bw) = sbb(r0, u64::MAX, 0);
    let (s1, bw) = sbb(r1, P1, bw);
    let (s2, bw) = sbb(r2, 0, bw);
    let (s3, bw) = sbb(r3, P3, bw);
    let (_, bw) = sbb(top, 0, bw);
    // Keep r when the whole value borrowed (r < p).
    let keep = mont::barrier(bw.wrapping_neg());
    mont::select(keep, &[r0, r1, r2, r3], &[s0, s1, s2, s3])
}

/// Montgomery multiplication `a b 2^-256 mod p` for `a, b < p`.
#[inline]
pub(crate) fn mul(a: &Fe<4>, b: &Fe<4>) -> Fe<4> {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut c = 0;
        for j in 0..4 {
            let (lo, hi) = mac(t[i + j], a[j], b[i], c);
            t[i + j] = lo;
            c = hi;
        }
        t[i + 4] = c;
    }
    reduce(&t)
}

#[cfg(test)]
mod tests {
    use super::super::curve::{Curve, fe_mul_soft};
    use super::super::params::P256;
    use super::*;

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    /// Edge values (0, 1, p - 1, p - 2, limbs at their extremes) and random
    /// elements below `p` agree with the generic CIOS multiplication.
    #[test]
    fn matches_generic_montgomery() {
        let p = P256::P;
        let one = [1u64, 0, 0, 0];
        let mut v = std::vec![
            [0u64; 4],
            one,
            [2, 0, 0, 0],
            mont::sub(&p, &one).0,
            mont::sub(&p, &[2, 0, 0, 0]).0,
            P256::ONE,
            P256::R2,
            [u64::MAX, u64::MAX, u64::MAX, 0],
            [u64::MAX, 0, 0, P3 - 1],
            [0, 0, 0, P3 - 1],
            [0, P1, 0, 0],
            [u64::MAX, P1, 0, 0],
            [u64::MAX, u64::MAX - 1, u64::MAX, P3 - 1],
            [u64::MAX, P1 - 1, 0, P3],
            [1 << 63, 1 << 63, 1 << 63, 1 << 63],
        ];
        let mut seed = 0x243f_6a88_85a3_08d3;
        while v.len() < 250 {
            let x = [
                xorshift(&mut seed),
                xorshift(&mut seed),
                xorshift(&mut seed),
                xorshift(&mut seed),
            ];
            if mont::lt(&x, &p) != 0 {
                v.push(x);
            }
        }
        for a in &v {
            assert!(mont::lt(a, &p) != 0);
            for b in &v {
                assert_eq!(
                    mul(a, b),
                    fe_mul_soft::<P256, 4>(a, b),
                    "a = {a:x?} b = {b:x?}"
                );
            }
        }
    }
}
