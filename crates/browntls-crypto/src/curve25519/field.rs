//! Arithmetic in GF(2^255 - 19) with five 51-bit limbs (portable backend).
//!
//! Every operation is branch-free and uses only additions, shifts, masks and
//! 64x64->128-bit multiplications, which are constant time on all supported
//! targets (x86-64 `mul`, aarch64 `mul`/`umulh`, riscv64 `mul`/`mulhu`).
//!
//! # Limb bounds
//!
//! A *reduced* element has every limb below `2^51 + 2^13`. `mul`, `square`,
//! `sub`, `neg`, `mul_small` and the constructors return reduced elements.
//! `add` does not reduce: the sum of two reduced elements has limbs below
//! `2^52 + 2^14`. `mul`/`square` accept limbs up to `2^54` (sums of up to
//! eight reduced elements); `sub` accepts a subtrahend with limbs up to `2^55`.

use crate::ct::{self, Choice};

const MASK51: u64 = (1 << 51) - 1;

/// Returns the all-zeros / all-ones mask of `c` behind an optimisation
/// barrier.
///
/// `ct::Choice` hides only the input *bit* from the optimiser, so LLVM still
/// knows its mask is 0 or -1 and was observed (aarch64, release) to turn a
/// masked 8-way table scan into secret-dependent branches and loads. Hiding
/// the mask itself prevents that; every conditional move in this module
/// family goes through this function.
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

/// Swaps `a` and `b` where `mask` is all ones.
#[inline(always)]
pub(crate) fn cswap_u64(mask: u64, a: &mut [u64], b: &mut [u64]) {
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = mask & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// A field element `sum(l[i] * 2^(51 i))`, not necessarily fully reduced.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

impl Fe {
    pub(crate) const ZERO: Self = Self([0; 5]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0]);
    /// The Edwards curve constant `d = -121665 / 121666`.
    pub(crate) const D: Self = Self([
        0x34dca135978a3,
        0x1a8283b156ebd,
        0x5e7a26001c029,
        0x739c663a03cbb,
        0x52036cee2b6ff,
    ]);
    /// `2d`.
    pub(crate) const D2: Self = Self([
        0x69b9426b2f159,
        0x35050762add7a,
        0x3cf44c0038052,
        0x6738cc7407977,
        0x2406d9dc56dff,
    ]);
    /// A square root of -1 (`2^((p-1)/4)`).
    pub(crate) const SQRT_M1: Self = Self([
        0x61b274a0ea0b0,
        0x0d5a5fc8f189d,
        0x7ef5e9cbd0c60,
        0x78595a6804c9e,
        0x2b8324804fc1d,
    ]);

    /// Carries every limb into the next, folding the top carry back times 19.
    /// Accepts any limbs; returns limbs below `2^51 + 2^13 * 19`.
    #[inline(always)]
    fn weak_reduce(mut l: [u64; 5]) -> Self {
        let c0 = l[0] >> 51;
        let c1 = l[1] >> 51;
        let c2 = l[2] >> 51;
        let c3 = l[3] >> 51;
        let c4 = l[4] >> 51;
        l[0] &= MASK51;
        l[1] &= MASK51;
        l[2] &= MASK51;
        l[3] &= MASK51;
        l[4] &= MASK51;
        l[0] += c4 * 19;
        l[1] += c0;
        l[2] += c1;
        l[3] += c2;
        l[4] += c3;
        Self(l)
    }

    /// Loads 32 little-endian bytes, ignoring the most significant bit
    /// (RFC 7748 §5, RFC 8032 §5.1.3). The value may be non-canonical (`>= p`).
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Self {
        let w = |i: usize| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(x)
        };
        Self([
            w(0) & MASK51,
            (w(6) >> 3) & MASK51,
            (w(12) >> 6) & MASK51,
            (w(19) >> 1) & MASK51,
            (w(24) >> 12) & MASK51,
        ])
    }

    /// Returns the canonical (fully reduced) little-endian encoding.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut l = Self::weak_reduce(self.0).0;
        // q = 1 iff value >= p, computed as the carry out of value + 19.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK51;
        l[2] += l[1] >> 51;
        l[1] &= MASK51;
        l[3] += l[2] >> 51;
        l[2] &= MASK51;
        l[4] += l[3] >> 51;
        l[3] &= MASK51;
        l[4] &= MASK51;
        let words = [
            l[0] | (l[1] << 51),
            (l[1] >> 13) | (l[2] << 38),
            (l[2] >> 26) | (l[3] << 25),
            (l[3] >> 39) | (l[4] << 12),
        ];
        let mut out = [0u8; 32];
        for (chunk, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *chunk = w.to_le_bytes();
        }
        out
    }

    #[inline(always)]
    pub(crate) fn add(&self, b: &Self) -> Self {
        let a = &self.0;
        let b = &b.0;
        Self([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
    }

    #[inline(always)]
    pub(crate) fn sub(&self, b: &Self) -> Self {
        // Add 16p so that no limb underflows for subtrahend limbs below 2^55.
        let a = &self.0;
        let b = &b.0;
        Self::weak_reduce([
            (a[0] + 0x007f_ffff_ffff_fed0) - b[0],
            (a[1] + 0x007f_ffff_ffff_fff0) - b[1],
            (a[2] + 0x007f_ffff_ffff_fff0) - b[2],
            (a[3] + 0x007f_ffff_ffff_fff0) - b[3],
            (a[4] + 0x007f_ffff_ffff_fff0) - b[4],
        ])
    }

    #[inline(always)]
    pub(crate) fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Carries a 5-term 128-bit product accumulator into a reduced element.
    #[inline(always)]
    fn carry_wide(mut c: [u128; 5]) -> Self {
        // Each c[i] < 2^115 for inputs below 2^54, so every carry fits a u64
        // and the folded top carry times 19 stays below 2^64.
        let mut out = [0u64; 5];
        c[1] += c[0] >> 51;
        out[0] = (c[0] as u64) & MASK51;
        c[2] += c[1] >> 51;
        out[1] = (c[1] as u64) & MASK51;
        c[3] += c[2] >> 51;
        out[2] = (c[2] as u64) & MASK51;
        c[4] += c[3] >> 51;
        out[3] = (c[3] as u64) & MASK51;
        let carry = (c[4] >> 51) as u64;
        out[4] = (c[4] as u64) & MASK51;
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK51;
        Self(out)
    }

    #[inline(always)]
    pub(crate) fn mul(&self, b: &Self) -> Self {
        let a = &self.0;
        let b = &b.0;
        let b1 = b[1] * 19;
        let b2 = b[2] * 19;
        let b3 = b[3] * 19;
        let b4 = b[4] * 19;
        Self::carry_wide([
            m(a[0], b[0]) + m(a[4], b1) + m(a[3], b2) + m(a[2], b3) + m(a[1], b4),
            m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2) + m(a[3], b3) + m(a[2], b4),
            m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3) + m(a[3], b4),
            m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4),
            m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]),
        ])
    }

    #[inline(always)]
    pub(crate) fn square(&self) -> Self {
        let a = &self.0;
        let a3_19 = a[3] * 19;
        let a4_19 = a[4] * 19;
        let d0 = a[0] * 2;
        let d1 = a[1] * 2;
        Self::carry_wide([
            m(a[0], a[0]) + 2 * (m(a[1], a4_19) + m(a[2], a3_19)),
            m(a[3], a3_19) + m(d0, a[1]) + 2 * m(a[2], a4_19),
            m(a[1], a[1]) + m(d0, a[2]) + 2 * m(a[4], a3_19),
            m(a[4], a4_19) + m(d0, a[3]) + m(d1, a[2]),
            m(a[2], a[2]) + m(d0, a[4]) + m(d1, a[3]),
        ])
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
        let a = &self.0;
        Self::carry_wide([m(a[0], k), m(a[1], k), m(a[2], k), m(a[3], k), m(a[4], k)])
    }

    /// Returns `(self^(2^250 - 1), self^11)`.
    fn pow22501(&self) -> (Self, Self) {
        let t0 = self.square(); // 2
        let t1 = t0.square_n(2); // 8
        let t2 = self.mul(&t1); // 9
        let t3 = t0.mul(&t2); // 11
        let t4 = t3.square(); // 22
        let t5 = t2.mul(&t4); // 2^5 - 1
        let t6 = t5.square_n(5);
        let t7 = t6.mul(&t5); // 2^10 - 1
        let t8 = t7.square_n(10);
        let t9 = t8.mul(&t7); // 2^20 - 1
        let t10 = t9.square_n(20);
        let t11 = t10.mul(&t9); // 2^40 - 1
        let t12 = t11.square_n(10);
        let t13 = t12.mul(&t7); // 2^50 - 1
        let t14 = t13.square_n(50);
        let t15 = t14.mul(&t13); // 2^100 - 1
        let t16 = t15.square_n(100);
        let t17 = t16.mul(&t15); // 2^200 - 1
        let t18 = t17.square_n(50);
        let t19 = t18.mul(&t13); // 2^250 - 1
        (t19, t3)
    }

    /// Returns `self^(p - 2)`, the inverse (zero maps to zero).
    pub(crate) fn invert(&self) -> Self {
        let (t19, t3) = self.pow22501();
        t19.square_n(5).mul(&t3) // 2^255 - 32 + 11 = p - 2
    }

    /// Returns `self^((p - 5) / 8) = self^(2^252 - 3)`.
    fn pow_p58(&self) -> Self {
        let (t19, _) = self.pow22501();
        t19.square_n(2).mul(self)
    }

    /// Constant-time equality of the canonical encodings.
    pub(crate) fn ct_eq(&self, other: &Self) -> Choice {
        ct::eq_bytes(&self.to_bytes(), &other.to_bytes())
    }

    /// `TRUE` if the canonical encoding is odd ("negative" in RFC 8032).
    pub(crate) fn is_negative(&self) -> Choice {
        Choice::from_bit(u64::from(self.to_bytes()[0] & 1))
    }

    pub(crate) fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
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

    /// Computes a square root of `u / v`.
    ///
    /// Returns `(TRUE, +sqrt(u/v))` when `u/v` is a square (with `(TRUE, 0)`
    /// for `u = 0`), and `(FALSE, garbage)` otherwise, including `v = 0` with
    /// `u != 0`. The returned root is non-negative.
    pub(crate) fn sqrt_ratio(u: &Self, v: &Self) -> (Choice, Self) {
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut r = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
        let check = v.mul(&r.square());
        let neg_u = u.neg();
        let correct = check.ct_eq(u);
        let flipped = check.ct_eq(&neg_u);
        let flipped_i = check.ct_eq(&neg_u.mul(&Self::SQRT_M1));
        let r_prime = r.mul(&Self::SQRT_M1);
        r.conditional_assign(&r_prime, flipped.or(flipped_i));
        let neg = r.is_negative();
        r.conditional_negate(neg);
        (correct.or(flipped), r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe_from_u64(x: u64) -> Fe {
        Fe::weak_reduce([x, 0, 0, 0, 0])
    }

    #[test]
    fn invert_and_encode() {
        let x = fe_from_u64(123_456_789);
        let one = x.mul(&x.invert());
        assert_eq!(one.to_bytes(), Fe::ONE.to_bytes());
        // p encodes to zero; p + 1 to one.
        let mut pb = [0xffu8; 32];
        pb[0] = 0xed;
        pb[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&pb).to_bytes(), [0; 32]);
        pb[0] = 0xee;
        assert_eq!(Fe::from_bytes(&pb).to_bytes(), Fe::ONE.to_bytes());
        // sqrt(-1)^2 = -1
        let m1 = Fe::SQRT_M1.square();
        assert_eq!(m1.to_bytes(), Fe::ONE.neg().to_bytes());
        // d * -121666 = 121665
        let lhs = Fe::D.mul(&fe_from_u64(121_666)).neg();
        assert_eq!(lhs.to_bytes(), fe_from_u64(121_665).to_bytes());
        assert_eq!(Fe::D.add(&Fe::D).to_bytes(), Fe::D2.to_bytes());
    }

    #[test]
    fn square_matches_mul() {
        let mut x = fe_from_u64(0xdead_beef);
        for _ in 0..200 {
            // Stress near-maximal limbs: sum of 8 reduced elements.
            let big = x.add(&x).add(&x.add(&x)).add(&x.add(&x).add(&x.add(&x)));
            assert_eq!(big.square().to_bytes(), big.mul(&big).to_bytes());
            assert_eq!(
                big.mul_small(121_665).to_bytes(),
                big.mul(&fe_from_u64(121_665)).to_bytes()
            );
            x = x.square().add(&Fe::ONE);
        }
    }

    #[test]
    fn sqrt_ratio_cases() {
        let four = fe_from_u64(4);
        let (ok, r) = Fe::sqrt_ratio(&four, &Fe::ONE);
        assert!(ok.declassify());
        assert_eq!(r.to_bytes(), fe_from_u64(2).to_bytes());
        let (ok, r) = Fe::sqrt_ratio(&Fe::ZERO, &Fe::ONE);
        assert!(ok.declassify() && r.is_zero().declassify());
        let (ok, _) = Fe::sqrt_ratio(&Fe::ONE, &Fe::ZERO);
        assert!(!ok.declassify());
        // 2 is a non-square mod p.
        let (ok, _) = Fe::sqrt_ratio(&fe_from_u64(2), &Fe::ONE);
        assert!(!ok.declassify());
        // -1 is a square.
        let (ok, r) = Fe::sqrt_ratio(&Fe::ONE.neg(), &Fe::ONE);
        assert!(ok.declassify());
        assert_eq!(r.square().to_bytes(), Fe::ONE.neg().to_bytes());
    }
}
