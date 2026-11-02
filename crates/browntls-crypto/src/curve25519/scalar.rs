//! Arithmetic modulo the prime group order
//! `L = 2^252 + 27742317777372353535851937790883648493`.
//!
//! Scalars use five 52-bit limbs and Montgomery multiplication with
//! `R = 2^260`. All operations are constant time.

use crate::zeroize::{Zeroize, zeroize_u64};

const MASK52: u64 = (1 << 52) - 1;

/// `L` in 52-bit limbs.
const L: [u64; 5] = [
    0x2631a5cf5d3ed,
    0xdea2f79cd6581,
    0x000000014def9,
    0x0000000000000,
    0x0100000000000,
];
/// `-L^-1 mod 2^52`.
const LFACTOR: u64 = 0x51da312547e1b;
/// `R mod L` with `R = 2^260`.
const R: [u64; 5] = [
    0xf48bd6721e6ed,
    0x3bab5ac67e45a,
    0xfffffeb35e51b,
    0xfffffffffffff,
    0x00fffffffffff,
];
/// `R^2 mod L`.
const RR: [u64; 5] = [
    0x9d265e952d13b,
    0xd63c715bea69f,
    0x5be65cb687604,
    0x3dceec73d217f,
    0x009411b7c309a,
];
/// Little-endian encoding of `L`.
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// An integer modulo `L` (always fully reduced when produced by this module).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scalar(pub(crate) [u64; 5]);

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        zeroize_u64(&mut self.0);
    }
}

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

fn load_words<const N: usize>(b: &[u8]) -> [u64; N] {
    let mut w = [0u64; N];
    for (wi, chunk) in w.iter_mut().zip(b.as_chunks::<8>().0) {
        *wi = u64::from_le_bytes(*chunk);
    }
    w
}

/// Returns `true` iff the 32-byte little-endian integer `s` is below `L`
/// (RFC 8032 §5.1.7 canonical `S`). Constant time.
pub(crate) fn is_canonical(s: &[u8; 32]) -> bool {
    let a: [u64; 4] = load_words(s);
    let l: [u64; 4] = load_words(&L_BYTES);
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(l[i]);
        let (_, b2) = d.overflowing_sub(borrow);
        borrow = u64::from(b1 | b2);
    }
    // borrow == 1 iff s < L.
    crate::ct::Choice::from_bit(borrow).declassify()
}

impl Scalar {
    /// Unpacks a 256-bit little-endian integer into limbs (not reduced).
    #[cfg(test)]
    fn unpack(b: &[u8; 32]) -> Self {
        let w: [u64; 4] = load_words(b);
        Self([
            w[0] & MASK52,
            ((w[0] >> 52) | (w[1] << 12)) & MASK52,
            ((w[1] >> 40) | (w[2] << 24)) & MASK52,
            ((w[2] >> 28) | (w[3] << 36)) & MASK52,
            w[3] >> 16,
        ])
    }

    /// Reduces a 256-bit little-endian integer modulo `L`.
    pub(crate) fn from_bytes_mod_order(b: &[u8; 32]) -> Self {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(b);
        let s = Self::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        s
    }

    /// Reduces a 512-bit little-endian integer (e.g. a SHA-512 output) modulo `L`.
    pub(crate) fn from_bytes_mod_order_wide(b: &[u8; 64]) -> Self {
        let w: [u64; 8] = load_words(b);
        let lo = Self([
            w[0] & MASK52,
            ((w[0] >> 52) | (w[1] << 12)) & MASK52,
            ((w[1] >> 40) | (w[2] << 24)) & MASK52,
            ((w[2] >> 28) | (w[3] << 36)) & MASK52,
            ((w[3] >> 16) | (w[4] << 48)) & MASK52,
        ]);
        let hi = Self([
            (w[4] >> 4) & MASK52,
            ((w[4] >> 56) | (w[5] << 8)) & MASK52,
            ((w[5] >> 44) | (w[6] << 20)) & MASK52,
            ((w[6] >> 32) | (w[7] << 32)) & MASK52,
            w[7] >> 20,
        ]);
        // lo * R / R + hi * R^2 / R = lo + hi * 2^260 (mod L).
        let lo = Self::montgomery_mul(&lo, &Self(R));
        let hi = Self::montgomery_mul(&hi, &Self(RR));
        hi.add(&lo)
    }

    /// Canonical little-endian encoding.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let s = &self.0;
        let words = [
            s[0] | (s[1] << 52),
            (s[1] >> 12) | (s[2] << 40),
            (s[2] >> 24) | (s[3] << 28),
            (s[3] >> 36) | (s[4] << 16),
        ];
        let mut out = [0u8; 32];
        for (chunk, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *chunk = w.to_le_bytes();
        }
        out
    }

    /// `a - b mod L` for `a, b < 2^260` with `a - b` in `[-L, L)`.
    fn sub(&self, b: &Self) -> Self {
        let mut d = [0u64; 5];
        let mut borrow = 0u64;
        for ((di, ai), bi) in d.iter_mut().zip(self.0).zip(b.0) {
            borrow = ai.wrapping_sub(bi + (borrow >> 63));
            *di = borrow & MASK52;
        }
        // Add L back if the difference was negative. The mask is hidden from
        // the optimiser, which otherwise turns this into a branch (observed
        // on aarch64).
        let mask = core::hint::black_box(((borrow >> 63) ^ 1).wrapping_sub(1));
        let mut carry = 0u64;
        for (di, li) in d.iter_mut().zip(L) {
            carry = (carry >> 52) + *di + (li & mask);
            *di = carry & MASK52;
        }
        Self(d)
    }

    /// `a + b mod L` for `a, b < L`.
    pub(crate) fn add(&self, b: &Self) -> Self {
        let mut s = [0u64; 5];
        let mut carry = 0u64;
        for ((si, ai), bi) in s.iter_mut().zip(self.0).zip(b.0) {
            carry = ai + bi + (carry >> 52);
            *si = carry & MASK52;
        }
        Self(s).sub(&Self(L))
    }

    #[inline(always)]
    fn mul_internal(a: &Self, b: &Self) -> [u128; 9] {
        let mut z = [0u128; 9];
        for i in 0..5 {
            for j in 0..5 {
                z[i + j] += m(a.0[i], b.0[j]);
            }
        }
        z
    }

    /// Computes `x / R mod L` for `x < R * L`.
    #[inline(always)]
    fn montgomery_reduce(x: &[u128; 9]) -> Self {
        let mut n = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..5 {
            let mut sum = carry + x[i];
            for j in 0..i {
                sum += m(n[j], L[i - j]);
            }
            n[i] = (sum as u64).wrapping_mul(LFACTOR) & MASK52;
            carry = (sum + m(n[i], L[0])) >> 52;
        }
        let mut r = [0u64; 5];
        for i in 5..9 {
            let mut sum = carry + x[i];
            for j in (i - 4)..5 {
                sum += m(n[j], L[i - j]);
            }
            r[i - 5] = (sum as u64) & MASK52;
            carry = sum >> 52;
        }
        r[4] = carry as u64;
        // r < 2L; subtract L once if needed.
        Self(r).sub(&Self(L))
    }

    fn montgomery_mul(a: &Self, b: &Self) -> Self {
        Self::montgomery_reduce(&Self::mul_internal(a, b))
    }

    /// `a * b mod L` for `a, b < L`.
    pub(crate) fn mul(&self, b: &Self) -> Self {
        let ab_over_r = Self::montgomery_mul(self, b);
        Self::montgomery_mul(&ab_over_r, &Self(RR))
    }

    /// `a * b + c mod L` for reduced inputs.
    pub(crate) fn mul_add(a: &Self, b: &Self, c: &Self) -> Self {
        a.mul(b).add(c)
    }

    #[cfg(test)]
    fn from_canonical_unchecked(b: &[u8; 32]) -> Self {
        Self::unpack(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Slow reference: reduce a little-endian integer modulo L by binary long
    /// division (shift-and-subtract) over 64-bit words.
    fn reference_mod_l(bytes: &[u8]) -> [u8; 32] {
        let lw: [u64; 4] = load_words(&L_BYTES);
        let mut r = [0u64; 5]; // running remainder < 2L < 2^254
        for byte in bytes.iter().rev() {
            for bit in (0..8).rev() {
                // r = 2r + bit
                let mut carry = u64::from((byte >> bit) & 1);
                for w in r.iter_mut() {
                    let nc = *w >> 63;
                    *w = (*w << 1) | carry;
                    carry = nc;
                }
                // if r >= L: r -= L
                let mut t = [0u64; 5];
                let mut borrow = 0u64;
                for i in 0..5 {
                    let li = if i < 4 { lw[i] } else { 0 };
                    let (d1, b1) = r[i].overflowing_sub(li);
                    let (d2, b2) = d1.overflowing_sub(borrow);
                    t[i] = d2;
                    borrow = u64::from(b1 | b2);
                }
                if borrow == 0 {
                    r = t;
                }
            }
        }
        let mut out = [0u8; 32];
        for (chunk, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(r) {
            *chunk = w.to_le_bytes();
        }
        out
    }

    fn rand_bytes<const N: usize>(state: &mut u64) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (*state >> 56) as u8;
        }
        out
    }

    #[test]
    fn wide_reduction_matches_reference() {
        let mut st = 1u64;
        let mut cases = std::vec![[0u8; 64], [0xff; 64]];
        let mut l2 = [0u8; 64];
        l2[..32].copy_from_slice(&L_BYTES);
        cases.push(l2);
        for _ in 0..300 {
            cases.push(rand_bytes::<64>(&mut st));
        }
        for c in &cases {
            assert_eq!(
                Scalar::from_bytes_mod_order_wide(c).to_bytes(),
                reference_mod_l(c)
            );
        }
        for _ in 0..100 {
            let b = rand_bytes::<32>(&mut st);
            assert_eq!(
                Scalar::from_bytes_mod_order(&b).to_bytes(),
                reference_mod_l(&b)
            );
        }
    }

    #[test]
    fn mul_add_matches_reference() {
        let mut st = 7u64;
        let mut lm1 = L_BYTES;
        lm1[0] -= 1;
        let mut vals = std::vec![[0u8; 32], lm1];
        for _ in 0..100 {
            vals.push(reference_mod_l(&rand_bytes::<32>(&mut st)));
        }
        for w in vals.windows(3) {
            let (a, b, c) = (
                Scalar::from_canonical_unchecked(&w[0]),
                Scalar::from_canonical_unchecked(&w[1]),
                Scalar::from_canonical_unchecked(&w[2]),
            );
            let got = Scalar::mul_add(&a, &b, &c).to_bytes();
            // Reference: compute a*b + c as a 64-byte integer, then reduce.
            let mut prod = [0u64; 9];
            let aw: [u64; 4] = load_words(&w[0]);
            let bw: [u64; 4] = load_words(&w[1]);
            let cw: [u64; 4] = load_words(&w[2]);
            for i in 0..4 {
                let mut carry = 0u128;
                for j in 0..4 {
                    let t = m(aw[i], bw[j]) + u128::from(prod[i + j]) + carry;
                    prod[i + j] = t as u64;
                    carry = t >> 64;
                }
                prod[i + 4] = carry as u64;
            }
            let mut carry = 0u128;
            for i in 0..9 {
                let t = u128::from(prod[i]) + u128::from(if i < 4 { cw[i] } else { 0 }) + carry;
                prod[i] = t as u64;
                carry = t >> 64;
            }
            let mut bytes = [0u8; 72];
            for (chunk, x) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(prod) {
                *chunk = x.to_le_bytes();
            }
            assert_eq!(got, reference_mod_l(&bytes));
        }
    }

    #[test]
    fn canonical_check() {
        assert!(is_canonical(&[0; 32]));
        assert!(!is_canonical(&L_BYTES));
        let mut lm1 = L_BYTES;
        lm1[0] -= 1;
        assert!(is_canonical(&lm1));
        assert!(!is_canonical(&[0xff; 32]));
        let mut lp1 = L_BYTES;
        lp1[0] += 1;
        assert!(!is_canonical(&lp1));
    }
}
