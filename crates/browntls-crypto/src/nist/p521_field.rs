//! P-521 field arithmetic specialised to the Mersenne prime `p = 2^521 - 1`.
//!
//! Elements stay in the Montgomery form of the generic code (`x R mod p`,
//! `R = 2^576`), so every curve constant and table is shared with it. Because
//! `2^521 = 1 (mod p)`, the Montgomery factor is `R^-1 = 2^-576 = 2^-55`, and
//! a Montgomery multiplication is the plain product followed by
//!
//! 1. a fold of the bits above 2^521 onto the low 521 bits, with the single
//!    conditional subtraction of `p` done as an add-one-and-test, and
//! 2. a rotation right by 55 bits within 521 bits, which multiplies by
//!    `2^-55` modulo `2^521 - 1`.
//!
//! No quotient digits and no multiplications by `p` are needed: the 81 limb
//! products of the schoolbook multiplication are the only multiplications,
//! half of what word-by-word Montgomery multiplication takes. Addition and
//! subtraction use the same add-one-and-test instead of a comparison with
//! `p`. All steps are fixed sequences of shifts, additions and masks.

use super::curve::Fe;
use super::mont::{adc, sbb};
use super::wide;

/// Mask of the nine bits of the top limb.
const TOP: u64 = 0x1ff;

/// `s - (1 - carry)` masked to 521 bits, where `carry` is bit 521 of `s`.
///
/// For `s = x + 1` with `x < 2p` this is `x mod p`, fully reduced: if bit 521
/// is clear, `x <= p - 1` and the result is `s - 1 = x`; if it is set,
/// `x >= p` and clearing it gives `x + 1 - 2^521 = x - p <= p - 1`. (For
/// `x = 2p`, the largest value nine limbs of 521 bits can sum to, the result
/// would be `p`, hence the bound.)
#[inline(always)]
fn finish(mut s: [u64; 9]) -> Fe<9> {
    let mut b = 1 - (s[8] >> 9);
    s[8] &= TOP;
    for x in &mut s {
        (*x, b) = sbb(*x, 0, b);
    }
    s
}

/// Reduces a product `t <= (2^521 - 1)^2` to `t * 2^-576 mod p`, fully
/// reduced.
///
/// The bound holds for the product of any two values below `2^521`, so the
/// operands of a multiplication need only have a top limb below `2^9`. (Any
/// `t < 2^1042` is reduced below `2^521`, but `t = 2^1042 - 1` gives `p`
/// rather than zero.)
#[inline(always)]
pub(crate) fn reduce(t: &[u64; 18]) -> Fe<9> {
    // lo = t mod 2^521 is at most p and hi = t >> 521 is at most
    // p - 1 (t <= 2^1042 - 2^522 + 1), and t = lo + hi (mod p).
    // s = lo + hi + 1 <= 2p has no carry out of nine limbs, and
    // lo + hi < 2p is what `finish` needs.
    let mut s = [0u64; 9];
    let mut c = 1;
    for i in 0..9 {
        let lo = if i == 8 { t[8] & TOP } else { t[i] };
        let hi = (t[8 + i] >> 9) | (t[9 + i] << 55);
        (s[i], c) = adc(lo, hi, c);
    }
    let f = finish(s);
    // Rotate right by 55 within 521 bits: bits 55..521 move down, and the low
    // 55 bits move to bits 466..521 (466 = 7 * 64 + 18). A rotation maps
    // canonical values to canonical values (only the all-ones pattern, p
    // itself, is not canonical).
    let low = f[0] & ((1 << 55) - 1);
    let mut r = [0u64; 9];
    for i in 0..8 {
        r[i] = (f[i] >> 55) | (f[i + 1] << 9);
    }
    r[7] |= low << 18;
    r[8] = low >> 46;
    r
}

/// `a + b mod p` for `a, b < p`.
#[inline]
pub(crate) fn add(a: &Fe<9>, b: &Fe<9>) -> Fe<9> {
    let mut s = [0u64; 9];
    let mut c = 1;
    for i in 0..9 {
        (s[i], c) = adc(a[i], b[i], c);
    }
    finish(s)
}

/// `a - b mod p` for `a, b < p`.
#[inline]
pub(crate) fn sub(a: &Fe<9>, b: &Fe<9>) -> Fe<9> {
    let mut d = [0u64; 9];
    let mut bw = 0;
    for i in 0..9 {
        (d[i], bw) = sbb(a[i], b[i], bw);
    }
    // A borrow means d = a - b + 2^576: subtracting one more and keeping 521
    // bits gives a - b + 2^521 - 1 = a - b + p.
    for x in &mut d {
        (*x, bw) = sbb(*x, 0, bw);
    }
    d[8] &= TOP;
    d
}

/// Montgomery multiplication `a b 2^-576 mod p` for `a, b < 2^521`.
#[inline]
pub(crate) fn mul(a: &Fe<9>, b: &Fe<9>) -> Fe<9> {
    reduce(&wide::mul::<9, 18>(a, b))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::curve::{Curve, fe_mul_soft};
    use super::super::mont;
    use super::super::params::P521;
    use super::*;

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    /// Edge values and random elements below `p`.
    pub(crate) fn inputs() -> std::vec::Vec<Fe<9>> {
        let p = P521::P;
        let limb = |i: usize, v: u64| {
            let mut x = [0u64; 9];
            x[i] = v;
            x
        };
        let one = limb(0, 1);
        let mut v = std::vec![
            [0u64; 9],
            one,
            limb(0, 2),
            mont::sub(&p, &one).0,
            mont::sub(&p, &limb(0, 2)).0,
            P521::ONE,
            P521::R2,
            // 2^55 - 1 and 2^55: the rotated-out bits and the first kept bit.
            limb(0, (1 << 55) - 1),
            limb(0, 1 << 55),
            limb(0, u64::MAX),
            limb(7, u64::MAX),
            limb(8, TOP),
            limb(8, 1),
            limb(8, 0x100),
            // 2^520 + 2^519 + ... with alternating limbs.
            [u64::MAX, 0, u64::MAX, 0, u64::MAX, 0, u64::MAX, 0, 0xff],
            [0, u64::MAX, 0, u64::MAX, 0, u64::MAX, 0, u64::MAX, 0x100],
            [
                1 << 63,
                1 << 63,
                1 << 63,
                1 << 63,
                1 << 63,
                1 << 63,
                1 << 63,
                1 << 63,
                0x155
            ],
        ];
        let mut seed = 0x452821e638d01377u64;
        while v.len() < 160 {
            let mut x: Fe<9> = core::array::from_fn(|_| xorshift(&mut seed));
            x[8] &= TOP;
            if mont::lt(&x, &p) != 0 {
                v.push(x);
            }
        }
        v
    }

    #[test]
    fn matches_generic_montgomery() {
        let v = inputs();
        for a in &v {
            assert!(mont::lt(a, &P521::P) != 0);
            for b in &v {
                assert_eq!(
                    mul(a, b),
                    fe_mul_soft::<P521, 9>(a, b),
                    "a = {a:x?} b = {b:x?}"
                );
            }
        }
    }

    #[test]
    fn addition_and_subtraction_match_generic() {
        let p = P521::P;
        let v = inputs();
        for a in &v {
            for b in &v {
                assert_eq!(add(a, b), mont::add_mod(a, b, &p), "a = {a:x?} b = {b:x?}");
                assert_eq!(sub(a, b), mont::sub_mod(a, b, &p), "a = {a:x?} b = {b:x?}");
            }
        }
    }

    /// Operands in `[p, 2^521)` (only `p` itself) and the largest product
    /// reduce to canonical values.
    #[test]
    fn non_canonical_operands_reduce_fully() {
        let p = P521::P;
        assert_eq!(mul(&p, &p), [0; 9]);
        assert_eq!(mul(&p, &P521::ONE), [0; 9]);
        let pm1 = mont::sub(&p, &[1, 0, 0, 0, 0, 0, 0, 0, 0]).0;
        assert_eq!(mul(&p, &pm1), [0; 9]);
        // (p - 1)^2 = 1 (mod p), so the Montgomery product is 2^-576 = 2^466.
        let mut want = [0u64; 9];
        want[7] = 1 << 18;
        assert_eq!(mul(&pm1, &pm1), want);
    }
}
