//! Arithmetic in GF(p), `p = 2^448 - 2^224 - 1` (RFC 7748 §4.2), with eight
//! 56-bit limbs (portable backend).
//!
//! An element is `sum(l[i] * 2^(56 i))`. A limb is exactly seven bytes, so
//! the 56-byte little-endian encoding of RFC 7748 §5 and RFC 8032 §5.2.2 maps
//! byte-aligned onto the limbs. Reduction uses `2^448 = 2^224 + 1 (mod p)`:
//! a product column at weight `2^(56 (k + 8))` is added to columns `k` and
//! `k + 4`.
//!
//! Every operation is branch-free and uses only additions, shifts, masks and
//! 64x64->128-bit multiplications, which are constant time on all supported
//! targets (x86-64 `mul`, aarch64 `mul`/`umulh`, riscv64 `mul`/`mulhu`).
//!
//! # Limb bounds
//!
//! A *reduced* element has every limb below `2^56 + 2^13`. `mul`, `square`,
//! `sub`, `neg`, `mul_small` and the constructors return reduced elements.
//! `add` does not reduce: the sum of two reduced elements has limbs below
//! `2^58`. `mul` and `square` accept limbs below `2^59` (sums of up to four
//! reduced elements): every column of the 15-column product is then a sum of
//! at most 20 products below `2^118` after folding, so below `2^123`, and the
//! carries fit comfortably in `u128`. `sub` accepts a minuend with limbs below
//! `2^63` and a subtrahend with limbs below `2^58` (it adds `8p`, whose limbs
//! are at least `2^59 - 16`). `to_bytes`, `ct_eq` and the predicates accept
//! limbs below `2^63`.

use crate::ct::{self, Choice};

const MASK56: u64 = (1 << 56) - 1;

/// `p` in 56-bit limbs: every limb `2^56 - 1` except limb 4, `2^56 - 2`.
const P: [u64; 8] = [
    MASK56,
    MASK56,
    MASK56,
    MASK56,
    MASK56 - 1,
    MASK56,
    MASK56,
    MASK56,
];

/// Returns the all-zeros / all-ones mask of `c` behind an optimisation
/// barrier, so that masked selects are not lowered to branches (see
/// `curve25519::field::opaque_mask`).
#[inline(always)]
pub(crate) fn opaque_mask(c: Choice) -> u64 {
    core::hint::black_box(c.mask())
}

/// `dst = src` where `mask` is all ones; unchanged where it is zero.
#[inline(always)]
pub(crate) fn cmov_u64(mask: u64, dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= mask & (*d ^ *s);
    }
}

/// Swaps `a` and `b` where `mask` is all ones (RFC 7748 §5 `cswap`).
#[inline(always)]
pub(crate) fn cswap_u64(mask: u64, a: &mut [u64], b: &mut [u64]) {
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = mask & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

/// A field element, not necessarily fully reduced.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe(pub(crate) [u64; 8]);

impl Fe {
    pub(crate) const ZERO: Self = Self([0; 8]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);

    /// Carries every limb into the next, folding the top carry into limbs 0
    /// and 4. Accepts limbs below `2^63`; returns limbs below `2^56 + 2^8`.
    #[inline(always)]
    fn weak_reduce(mut l: [u64; 8]) -> Self {
        let c: [u64; 8] = core::array::from_fn(|i| l[i] >> 56);
        for x in &mut l {
            *x &= MASK56;
        }
        for i in 0..7 {
            l[i + 1] += c[i];
        }
        l[0] += c[7];
        l[4] += c[7];
        Self(l)
    }

    /// Loads 56 little-endian bytes. The value may be non-canonical (`>= p`);
    /// RFC 7748 §5 requires X448 to accept such u-coordinates as if reduced.
    pub(crate) fn from_bytes(b: &[u8; 56]) -> Self {
        let mut l = [0u64; 8];
        for (li, chunk) in l.iter_mut().zip(b.as_chunks::<7>().0) {
            let mut w = [0u8; 8];
            w[..7].copy_from_slice(chunk);
            *li = u64::from_le_bytes(w);
        }
        Self(l)
    }

    /// Returns the fully reduced limbs (`0 <= value < p`, every limb below
    /// `2^56`).
    fn canonical(self) -> [u64; 8] {
        let mut l = self.0;
        // Carry so every limb is below 2^56 and fold the top carry: the
        // value is then below 2^448 + 2^6 (2^224 + 1) < 2p.
        let mut c = 0u64;
        for x in &mut l {
            *x += c;
            c = *x >> 56;
            *x &= MASK56;
        }
        l[0] += c;
        l[4] += c;
        // Subtract p with a signed carry; the final carry is 0 if the value
        // was >= p and -1 otherwise.
        let mut s = 0i64;
        for (x, pi) in l.iter_mut().zip(P) {
            s += *x as i64 - pi as i64;
            *x = (s as u64) & MASK56;
            s >>= 56;
        }
        // Add p back where the subtraction went negative.
        let mask = core::hint::black_box(s as u64);
        let mut c = 0u64;
        for (x, pi) in l.iter_mut().zip(P) {
            c += *x + (pi & mask);
            *x = c & MASK56;
            c >>= 56;
        }
        l
    }

    /// Returns the canonical little-endian encoding.
    pub(crate) fn to_bytes(self) -> [u8; 56] {
        let l = self.canonical();
        let mut out = [0u8; 56];
        for (chunk, li) in out.as_chunks_mut::<7>().0.iter_mut().zip(l) {
            chunk.copy_from_slice(&li.to_le_bytes()[..7]);
        }
        out
    }

    #[inline(always)]
    pub(crate) fn add(&self, b: &Self) -> Self {
        Self(core::array::from_fn(|i| self.0[i] + b.0[i]))
    }

    #[inline(always)]
    pub(crate) fn sub(&self, b: &Self) -> Self {
        // Adds 8p (limbs 2^59 - 8, and 2^59 - 16 at index 4) so that no limb
        // underflows for subtrahend limbs below 2^58.
        Self::weak_reduce(core::array::from_fn(|i| (self.0[i] + 8 * P[i]) - b.0[i]))
    }

    #[inline(always)]
    pub(crate) fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Carries eight 128-bit column sums (each below `2^124`) into a reduced
    /// element.
    #[inline(always)]
    fn carry_wide(mut c: [u128; 8]) -> Self {
        let mut out = [0u64; 8];
        for i in 0..7 {
            c[i + 1] += c[i] >> 56;
            out[i] = (c[i] as u64) & MASK56;
        }
        out[7] = (c[7] as u64) & MASK56;
        // The carry out of limb 7 has weight 2^448 = 2^224 + 1; it is below
        // 2^68, so adding it to limbs 0 and 4 carries at most 2^12 onward.
        let t = c[7] >> 56;
        let t0 = u128::from(out[0]) + t;
        out[0] = (t0 as u64) & MASK56;
        out[1] += (t0 >> 56) as u64;
        let t4 = u128::from(out[4]) + t;
        out[4] = (t4 as u64) & MASK56;
        out[5] += (t4 >> 56) as u64;
        Self(out)
    }

    /// Folds the 15 product columns into 8 (`2^448 = 2^224 + 1`), from the
    /// top so that columns 8..10 receive their share before being folded.
    #[inline(always)]
    fn reduce_wide(mut c: [u128; 15]) -> Self {
        for k in (8..15).rev() {
            let t = c[k];
            c[k - 8] += t;
            c[k - 4] += t;
        }
        let mut lo = [0u128; 8];
        lo.copy_from_slice(&c[..8]);
        Self::carry_wide(lo)
    }

    #[inline(always)]
    pub(crate) fn mul(&self, b: &Self) -> Self {
        let a = &self.0;
        let b = &b.0;
        let mut c = [0u128; 15];
        for i in 0..8 {
            for j in 0..8 {
                c[i + j] += m(a[i], b[j]);
            }
        }
        Self::reduce_wide(c)
    }

    #[inline(always)]
    pub(crate) fn square(&self) -> Self {
        let a = &self.0;
        let mut c = [0u128; 15];
        for i in 0..8 {
            c[2 * i] += m(a[i], a[i]);
            let d = a[i] * 2;
            for j in (i + 1)..8 {
                c[i + j] += m(d, a[j]);
            }
        }
        Self::reduce_wide(c)
    }

    /// Returns `self^(2^k)` for `k >= 1`.
    #[inline]
    pub(crate) fn square_n(&self, k: u32) -> Self {
        let mut x = self.square();
        for _ in 1..k {
            x = x.square();
        }
        x
    }

    /// Multiplies by a small constant `k < 2^17`.
    #[inline(always)]
    pub(crate) fn mul_small(&self, k: u32) -> Self {
        let k = u64::from(k);
        Self::carry_wide(core::array::from_fn(|i| m(self.0[i], k)))
    }

    /// Returns `self^((p - 3) / 4) = self^(2^446 - 2^222 - 1)`.
    ///
    /// The exponent is 223 ones, a zero and 222 ones; the chain builds
    /// `x^(2^n - 1)` for n = 2, 3, 6, 12, 24, 30, 48, 96, 192, 222, 223.
    pub(crate) fn pow_p34(&self) -> Self {
        let x = *self;
        let x2 = x.square().mul(&x);
        let x3 = x2.square().mul(&x);
        let x6 = x3.square_n(3).mul(&x3);
        let x12 = x6.square_n(6).mul(&x6);
        let x24 = x12.square_n(12).mul(&x12);
        let x30 = x24.square_n(6).mul(&x6);
        let x48 = x24.square_n(24).mul(&x24);
        let x96 = x48.square_n(48).mul(&x48);
        let x192 = x96.square_n(96).mul(&x96);
        let x222 = x192.square_n(30).mul(&x30);
        let x223 = x222.square().mul(&x);
        x223.square_n(223).mul(&x222)
    }

    /// Returns `self^(p - 2) = (self^((p - 3) / 4))^4 * self`, the inverse
    /// (RFC 8032 §5.2.1); zero maps to zero.
    pub(crate) fn invert(&self) -> Self {
        self.pow_p34().square_n(2).mul(self)
    }

    /// Constant-time equality of the canonical encodings.
    pub(crate) fn ct_eq(&self, other: &Self) -> Choice {
        ct::eq_bytes(&self.to_bytes(), &other.to_bytes())
    }

    pub(crate) fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// `TRUE` if the canonical value is odd (the sign bit of RFC 8032
    /// §5.2.2).
    pub(crate) fn is_odd(&self) -> Choice {
        Choice::from_bit(self.canonical()[0] & 1)
    }

    /// Replaces `self` with `other` when `c` is `TRUE`.
    #[inline(always)]
    pub(crate) fn conditional_assign(&mut self, other: &Self, c: Choice) {
        cmov_u64(opaque_mask(c), &mut self.0, &other.0);
    }

    #[inline(always)]
    pub(crate) fn conditional_swap(a: &mut Self, b: &mut Self, c: Choice) {
        cswap_u64(opaque_mask(c), &mut a.0, &mut b.0);
    }

    #[inline]
    pub(crate) fn conditional_negate(&mut self, c: Choice) {
        let n = self.neg();
        self.conditional_assign(&n, c);
    }

    /// The candidate square root of `u / v` of RFC 8032 §5.2.3 step 2,
    /// `x = u^3 v (u^5 v^3)^((p - 3) / 4)`, and whether `v x^2 = u` (step 3).
    ///
    /// Returns `(TRUE, x)` when `u / v` is a square (with `x = 0` for
    /// `u = 0`) and `(FALSE, garbage)` otherwise, including `v = 0` with
    /// `u != 0`.
    pub(crate) fn sqrt_ratio(u: &Self, v: &Self) -> (Choice, Self) {
        let u2 = u.square();
        let u3 = u2.mul(u);
        let u5 = u3.mul(&u2);
        let v3 = v.square().mul(v);
        let x = u3.mul(v).mul(&u5.mul(&v3).pow_p34());
        let ok = v.mul(&x.square()).ct_eq(u);
        (ok, x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(x: u64) -> Fe {
        Fe::weak_reduce([x, 0, 0, 0, 0, 0, 0, 0])
    }

    fn p_bytes() -> [u8; 56] {
        // p = 2^448 - 2^224 - 1: bytes 0..27 are 0xff, byte 28 is 0xfe,
        // bytes 29..55 are 0xff (RFC 7748 §4.2).
        let mut b = [0xffu8; 56];
        b[28] = 0xfe;
        b
    }

    /// A slow reference: the little-endian integer `b` reduced mod p by
    /// repeated subtraction of p (b < 2^448 < 2p, so at most once).
    fn reference_reduce(b: &[u8; 56]) -> [u8; 56] {
        let p = p_bytes();
        let ge = b.iter().rev().cmp(p.iter().rev()) != core::cmp::Ordering::Less;
        if !ge {
            return *b;
        }
        let mut out = [0u8; 56];
        let mut borrow = 0i16;
        for i in 0..56 {
            let d = i16::from(b[i]) - i16::from(p[i]) - borrow;
            borrow = i16::from(d < 0);
            out[i] = (d + 256 * borrow) as u8;
        }
        out
    }

    #[test]
    fn modulus_limbs_match_the_rfc() {
        assert_eq!(Fe(P).0, Fe::from_bytes(&p_bytes()).0);
        // p encodes to zero, p + 1 to one, 2^448 - 1 to 2^224.
        assert_eq!(Fe::from_bytes(&p_bytes()).to_bytes(), [0; 56]);
        // p - 255 is canonical.
        let mut b = p_bytes();
        b[0] = 0;
        assert_eq!(Fe::from_bytes(&b).to_bytes(), b);
        // 2^448 - 1 = p + 2^224 encodes as 2^224.
        let all = [0xffu8; 56];
        let mut two224 = [0u8; 56];
        two224[28] = 1;
        assert_eq!(Fe::from_bytes(&all).to_bytes(), two224);
        assert_eq!(reference_reduce(&all), two224);
        // p + 1 = 2^448 - 2^224 (bytes 0..27 zero, 28..55 0xff) encodes as 1.
        let one: [u8; 56] = core::array::from_fn(|i| u8::from(i == 0));
        let mut p_plus_one = [0u8; 56];
        p_plus_one[28..].fill(0xff);
        assert_eq!(Fe::from_bytes(&p_plus_one).to_bytes(), one);
        assert_eq!(reference_reduce(&p_plus_one), one);
    }

    #[test]
    fn encoding_reduces_non_canonical_values() {
        let mut st = 0x0123_4567_89ab_cdefu64;
        for _ in 0..200 {
            let mut b = [0u8; 56];
            for x in &mut b {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                *x = (st >> 56) as u8;
            }
            // Bias towards the top of the range so that values >= p occur.
            b[28..].fill(0xff);
            assert_eq!(Fe::from_bytes(&b).to_bytes(), reference_reduce(&b));
        }
    }

    #[test]
    fn arithmetic_identities() {
        let x = fe(123_456_789);
        assert_eq!(x.mul(&x.invert()).to_bytes(), Fe::ONE.to_bytes());
        assert_eq!(Fe::ZERO.invert().to_bytes(), [0; 56]);
        assert_eq!(x.sub(&x).to_bytes(), [0; 56]);
        assert_eq!(x.add(&x.neg()).to_bytes(), [0; 56]);
        // -1 is not a square (p = 3 mod 4); 4 is.
        let (ok, _) = Fe::sqrt_ratio(&Fe::ONE.neg(), &Fe::ONE);
        assert!(!ok.declassify());
        let (ok, r) = Fe::sqrt_ratio(&fe(4), &Fe::ONE);
        assert!(ok.declassify());
        assert_eq!(r.square().to_bytes(), fe(4).to_bytes());
        let (ok, r) = Fe::sqrt_ratio(&Fe::ZERO, &fe(7));
        assert!(ok.declassify() && r.is_zero().declassify());
        let (ok, _) = Fe::sqrt_ratio(&Fe::ONE, &Fe::ZERO);
        assert!(!ok.declassify());
        // u / v with v != 1: sqrt(9/4)^2 = 9/4.
        let (ok, r) = Fe::sqrt_ratio(&fe(9), &fe(4));
        assert!(ok.declassify());
        assert_eq!(r.square().mul(&fe(4)).to_bytes(), fe(9).to_bytes());
    }

    #[test]
    fn square_and_mul_small_match_mul_at_maximal_limbs() {
        let mut x = fe(0xdead_beef);
        for _ in 0..200 {
            // Sum of four reduced elements: limbs close to 2^58.
            let big = x.add(&x).add(&x.add(&x));
            assert_eq!(big.square().to_bytes(), big.mul(&big).to_bytes());
            assert_eq!(
                big.mul_small(39_081).to_bytes(),
                big.mul(&fe(39_081)).to_bytes()
            );
            // A subtrahend that is the sum of two reduced elements.
            let two = x.add(&x);
            assert_eq!(
                big.sub(&two).to_bytes(),
                x.add(&x).to_bytes(),
                "4x - 2x = 2x"
            );
            x = x.square().add(&Fe::ONE);
        }
        // All limbs at the documented maxima.
        let max = Fe([(1 << 59) - 1; 8]);
        let reduced = Fe::from_bytes(&max.to_bytes());
        assert_eq!(max.mul(&max).to_bytes(), reduced.mul(&reduced).to_bytes());
        assert_eq!(max.square().to_bytes(), reduced.square().to_bytes());
    }

    #[test]
    fn predicates() {
        assert!(Fe::ONE.is_odd().declassify());
        assert!(!fe(2).is_odd().declassify());
        // p - 1 is even, so -1 is even.
        assert!(!Fe::ONE.neg().is_odd().declassify());
        let mut a = fe(5);
        let mut b = fe(9);
        Fe::conditional_swap(&mut a, &mut b, Choice::TRUE);
        assert_eq!(a.to_bytes(), fe(9).to_bytes());
        Fe::conditional_swap(&mut a, &mut b, Choice::FALSE);
        assert_eq!(a.to_bytes(), fe(9).to_bytes());
        a.conditional_negate(Choice::TRUE);
        assert_eq!(a.add(&fe(9)).to_bytes(), [0; 56]);
    }
}
