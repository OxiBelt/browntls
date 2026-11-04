//! Arithmetic modulo the prime group order of edwards448 (RFC 7748 §4.2,
//! RFC 8032 §5.2)
//! `L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885`.
//!
//! Scalars use eight 56-bit limbs and Montgomery multiplication with
//! `R = 2^448`. All operations are constant time.

use crate::zeroize::{Zeroize, zeroize_u64};

const MASK56: u64 = (1 << 56) - 1;

/// `L` in 56-bit limbs.
const L: [u64; 8] = [
    0x78c292ab5844f3,
    0xc2728dc58f5523,
    0x49aed63690216c,
    0x7cca23e9c44edb,
    0xffffffffffffff,
    0xffffffffffffff,
    0xffffffffffffff,
    0x3fffffffffffff,
];
/// `-L^-1 mod 2^56`.
const LFACTOR: u64 = 0xbd440fae918bc5;
/// `R mod L` with `R = 2^448`.
const R1: [u64; 8] = [
    0x1cf5b5529eec34,
    0xf635c8e9c2ab72,
    0xd944a725bf7a4c,
    0x0cd77058eec492,
    0x00000000000002,
    0,
    0,
    0,
];
/// `R^2 mod L`.
const R2: [u64; 8] = [
    0x539257049b9b60,
    0x2c4bc1b195d9e3,
    0x2388ea18597af3,
    0x5ee4d8380d66de,
    0xc47c44ae17cf72,
    0x70af1a9cc14ba3,
    0x292052bcb7e4d0,
    0x3402a939f823b7,
];
/// `R^3 mod L`.
const R3: [u64; 8] = [
    0xdb79e25f9b74ed,
    0x33584f61d63662,
    0x8b5fa7496432d5,
    0x878dfcda3e0d0c,
    0x54b842178769ed,
    0x736de4c71af867,
    0xf1ed66e7f42bab,
    0x0d30a4f69d3af5,
];

/// An integer modulo `L` (always fully reduced when produced by this module).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scalar(pub(crate) [u64; 8]);

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        zeroize_u64(&mut self.0);
    }
}

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

/// Unpacks 56 little-endian bytes into eight 56-bit limbs.
fn limbs(b: &[u8]) -> [u64; 8] {
    let mut l = [0u64; 8];
    for (li, chunk) in l.iter_mut().zip(b.as_chunks::<7>().0) {
        let mut w = [0u8; 8];
        w[..7].copy_from_slice(chunk);
        *li = u64::from_le_bytes(w);
    }
    l
}

/// Returns `true` iff the 57-byte little-endian integer `s` is below `L`
/// (the canonical `S` of RFC 8032 §5.2.7 step 1). Constant time.
pub(crate) fn is_canonical(s: &[u8; 57]) -> bool {
    let a = limbs(&s[..56]);
    let mut borrow = 0u64;
    for (ai, li) in a.iter().zip(L) {
        borrow = ai.wrapping_sub(li + borrow) >> 63;
    }
    // borrow == 1 iff s[..56] < L; the top byte must be zero.
    let lt = crate::ct::Choice::from_bit(borrow);
    let top_zero = crate::ct::is_zero_u64(u64::from(s[56]));
    lt.and(top_zero).declassify()
}

impl Scalar {
    #[cfg(test)]
    pub(crate) const ZERO: Self = Self([0; 8]);

    /// Reduces a 114-byte little-endian integer (a SHAKE256 output of RFC 8032
    /// §5.2.6) modulo `L`.
    ///
    /// The input is split as `lo + mid * 2^448 + hi * 2^896` and reduced as
    /// `lo R / R + mid R^2 / R + hi R^3 / R`.
    pub(crate) fn from_bytes_mod_order_wide(b: &[u8; 114]) -> Self {
        let lo = Self(limbs(&b[..56]));
        let mid = Self(limbs(&b[56..112]));
        let hi = Self([
            u64::from(b[112]) | (u64::from(b[113]) << 8),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        let lo = Self::montgomery_mul(&lo, &Self(R1));
        let mid = Self::montgomery_mul(&mid, &Self(R2));
        let hi = Self::montgomery_mul(&hi, &Self(R3));
        lo.add(&mid).add(&hi)
    }

    /// Reduces a 57-byte little-endian integer modulo `L`.
    pub(crate) fn from_bytes_mod_order(b: &[u8; 57]) -> Self {
        let mut wide = [0u8; 114];
        wide[..57].copy_from_slice(b);
        let s = Self::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        s
    }

    /// Canonical 57-byte little-endian encoding (the top byte is zero).
    pub(crate) fn to_bytes(self) -> [u8; 57] {
        let mut out = [0u8; 57];
        for (chunk, li) in out[..56].as_chunks_mut::<7>().0.iter_mut().zip(self.0) {
            chunk.copy_from_slice(&li.to_le_bytes()[..7]);
        }
        out
    }

    /// `a - b mod L` for `a, b < 2^448` with `a - b` in `[-L, L)`.
    fn sub(&self, b: &Self) -> Self {
        let mut d = [0u64; 8];
        let mut borrow = 0u64;
        for ((di, ai), bi) in d.iter_mut().zip(self.0).zip(b.0) {
            borrow = ai.wrapping_sub(bi + (borrow >> 63));
            *di = borrow & MASK56;
        }
        // Add L back if the difference was negative; the mask is hidden from
        // the optimiser, which could otherwise branch on it.
        let mask = core::hint::black_box(((borrow >> 63) ^ 1).wrapping_sub(1));
        let mut carry = 0u64;
        for (di, li) in d.iter_mut().zip(L) {
            carry = (carry >> 56) + *di + (li & mask);
            *di = carry & MASK56;
        }
        Self(d)
    }

    /// `a + b mod L` for `a, b < L`.
    pub(crate) fn add(&self, b: &Self) -> Self {
        let mut s = [0u64; 8];
        let mut carry = 0u64;
        for ((si, ai), bi) in s.iter_mut().zip(self.0).zip(b.0) {
            carry = ai + bi + (carry >> 56);
            *si = carry & MASK56;
        }
        // a + b < 2L < 2^447, so no carry leaves the top limb.
        Self(s).sub(&Self(L))
    }

    #[inline(always)]
    fn mul_internal(a: &Self, b: &Self) -> [u128; 15] {
        let mut z = [0u128; 15];
        for i in 0..8 {
            for j in 0..8 {
                z[i + j] += m(a.0[i], b.0[j]);
            }
        }
        z
    }

    /// Computes `x / R mod L` for `x < R * L`.
    #[inline(always)]
    fn montgomery_reduce(x: &[u128; 15]) -> Self {
        let mut n = [0u64; 8];
        let mut carry = 0u128;
        for i in 0..8 {
            let mut sum = carry + x[i];
            for j in 0..i {
                sum += m(n[j], L[i - j]);
            }
            n[i] = (sum as u64).wrapping_mul(LFACTOR) & MASK56;
            carry = (sum + m(n[i], L[0])) >> 56;
        }
        let mut r = [0u64; 8];
        for i in 8..15 {
            let mut sum = carry + x[i];
            for j in (i - 7)..8 {
                sum += m(n[j], L[i - j]);
            }
            r[i - 8] = (sum as u64) & MASK56;
            carry = sum >> 56;
        }
        r[7] = carry as u64;
        // r = (x + n L) / R < 2L; subtract L once if needed.
        Self(r).sub(&Self(L))
    }

    fn montgomery_mul(a: &Self, b: &Self) -> Self {
        Self::montgomery_reduce(&Self::mul_internal(a, b))
    }

    /// `a * b mod L` for `a, b < L`.
    pub(crate) fn mul(&self, b: &Self) -> Self {
        let mut ab_over_r = Self::montgomery_mul(self, b);
        let ab = Self::montgomery_mul(&ab_over_r, &Self(R2));
        ab_over_r.zeroize();
        ab
    }

    /// `a * b + c mod L` for reduced inputs. The product is wiped: in Ed448
    /// signing it is `k s`, from which the public `k` reveals `s`.
    pub(crate) fn mul_add(a: &Self, b: &Self, c: &Self) -> Self {
        let mut ab = a.mul(b);
        let sum = ab.add(c);
        ab.zeroize();
        sum
    }

    /// Unpacks a canonical 57-byte encoding without reduction (tests only).
    #[cfg(test)]
    fn from_canonical_unchecked(b: &[u8; 57]) -> Self {
        Self(limbs(&b[..56]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `L` as printed in RFC 8032 Table 2 and RFC 7748 §4.2, little endian.
    fn l_bytes() -> [u8; 57] {
        // 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
        let c = dec_to_le("13818066809895115352007386748515426880336692474882178609894547503885");
        let mut two446 = [0u8; 57];
        two446[55] = 0x40;
        sub_le(&two446, &c)
    }

    fn dec_to_le(s: &str) -> [u8; 57] {
        let mut out = [0u8; 57];
        for ch in s.bytes() {
            let mut carry = u32::from(ch - b'0');
            for b in &mut out {
                let v = u32::from(*b) * 10 + carry;
                *b = v as u8;
                carry = v >> 8;
            }
            assert_eq!(carry, 0);
        }
        out
    }

    fn sub_le(a: &[u8; 57], b: &[u8; 57]) -> [u8; 57] {
        let mut out = [0u8; 57];
        let mut borrow = 0i16;
        for i in 0..57 {
            let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
            borrow = i16::from(d < 0);
            out[i] = (d + 256 * borrow) as u8;
        }
        assert_eq!(borrow, 0);
        out
    }

    /// Slow reference: reduces a little-endian integer modulo L by binary long
    /// division (shift and subtract) over bytes.
    fn reference_mod_l(bytes: &[u8]) -> [u8; 57] {
        let l = l_bytes();
        let mut r = [0u8; 58];
        for byte in bytes.iter().rev() {
            for bit in (0..8).rev() {
                let mut carry = (byte >> bit) & 1;
                for x in &mut r {
                    let nc = *x >> 7;
                    *x = (*x << 1) | carry;
                    carry = nc;
                }
                let mut t = [0u8; 58];
                let mut borrow = 0i16;
                for i in 0..58 {
                    let li = if i < 57 { l[i] } else { 0 };
                    let d = i16::from(r[i]) - i16::from(li) - borrow;
                    borrow = i16::from(d < 0);
                    t[i] = (d + 256 * borrow) as u8;
                }
                if borrow == 0 {
                    r = t;
                }
            }
        }
        let mut out = [0u8; 57];
        out.copy_from_slice(&r[..57]);
        out
    }

    fn rand_bytes<const N: usize>(state: &mut u64) -> [u8; N] {
        let mut out = [0u8; N];
        for b in &mut out {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (*state >> 56) as u8;
        }
        out
    }

    #[test]
    fn constants_match_the_rfc() {
        let l = l_bytes();
        assert_eq!(Scalar(L).to_bytes(), l);
        // RFC 7748 §4.2 writes the same order as
        // 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d.
        let c = hex_to_le("8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d");
        let mut two446 = [0u8; 57];
        two446[55] = 0x40;
        assert_eq!(sub_le(&two446, &c), l);
        // LFACTOR * L = -1 mod 2^56.
        assert_eq!(LFACTOR.wrapping_mul(L[0]) & MASK56, MASK56);
        // R, R^2, R^3 mod L.
        let mut r = [0u8; 57];
        r[56] = 1;
        assert_eq!(Scalar(R1).to_bytes(), reference_mod_l(&r));
        let mut r2 = [0u8; 113];
        r2[112] = 1;
        assert_eq!(Scalar(R2).to_bytes(), reference_mod_l(&r2));
        let mut r3 = [0u8; 169];
        r3[168] = 1;
        assert_eq!(Scalar(R3).to_bytes(), reference_mod_l(&r3));
    }

    fn hex_to_le(s: &str) -> [u8; 57] {
        let be = hex::decode(s).unwrap();
        let mut out = [0u8; 57];
        for (o, b) in out.iter_mut().zip(be.iter().rev()) {
            *o = *b;
        }
        out
    }

    #[test]
    fn wide_reduction_matches_reference() {
        let mut st = 1u64;
        let mut cases = std::vec![[0u8; 114], [0xff; 114]];
        let mut l2 = [0u8; 114];
        l2[..57].copy_from_slice(&l_bytes());
        cases.push(l2);
        for _ in 0..200 {
            cases.push(rand_bytes::<114>(&mut st));
        }
        for c in &cases {
            assert_eq!(
                Scalar::from_bytes_mod_order_wide(c).to_bytes(),
                reference_mod_l(c)
            );
        }
        for _ in 0..100 {
            let b = rand_bytes::<57>(&mut st);
            assert_eq!(
                Scalar::from_bytes_mod_order(&b).to_bytes(),
                reference_mod_l(&b)
            );
        }
    }

    #[test]
    fn mul_add_matches_reference() {
        let mut st = 7u64;
        let mut lm1 = l_bytes();
        lm1[0] -= 1;
        let mut vals = std::vec![[0u8; 57], lm1];
        for _ in 0..60 {
            vals.push(reference_mod_l(&rand_bytes::<57>(&mut st)));
        }
        for w in vals.windows(3) {
            let (a, b, c) = (
                Scalar::from_canonical_unchecked(&w[0]),
                Scalar::from_canonical_unchecked(&w[1]),
                Scalar::from_canonical_unchecked(&w[2]),
            );
            let got = Scalar::mul_add(&a, &b, &c).to_bytes();
            // Reference: a * b + c as a 115-byte integer, then reduce.
            let mut prod = [0u32; 115];
            for i in 0..57 {
                for j in 0..57 {
                    prod[i + j] += u32::from(w[0][i]) * u32::from(w[1][j]);
                }
            }
            for i in 0..57 {
                prod[i] += u32::from(w[2][i]);
            }
            let mut bytes = [0u8; 115];
            let mut carry = 0u32;
            for i in 0..115 {
                let v = prod[i] + carry;
                bytes[i] = v as u8;
                carry = v >> 8;
            }
            assert_eq!(carry, 0);
            assert_eq!(got, reference_mod_l(&bytes));
        }
    }

    #[test]
    fn canonical_check() {
        let l = l_bytes();
        assert!(is_canonical(&[0; 57]));
        assert!(!is_canonical(&l));
        let mut lm1 = l;
        lm1[0] -= 1;
        assert!(is_canonical(&lm1));
        let mut lp1 = l;
        lp1[0] += 1;
        assert!(!is_canonical(&lp1));
        assert!(!is_canonical(&[0xff; 57]));
        let mut top = [0u8; 57];
        top[56] = 1;
        assert!(!is_canonical(&top));
        let mut two446 = [0u8; 57];
        two446[55] = 0x40;
        assert!(!is_canonical(&two446));
    }
}
