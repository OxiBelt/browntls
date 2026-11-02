//! Constant-time helpers.
//!
//! These functions avoid data-dependent branches and memory accesses. They
//! route values through [`core::hint::black_box`] so the optimizer cannot
//! reintroduce branches it would otherwise derive from known bit patterns.
//! `black_box` is a best-effort barrier, not a formal guarantee; generated code
//! for secret-dependent paths should still be reviewed.

use core::hint::black_box;

/// A secret boolean represented as `0` or `1`, never branched on directly.
#[derive(Clone, Copy, Debug)]
pub struct Choice(u8);

impl Choice {
    /// The false value.
    pub const FALSE: Self = Self(0);
    /// The true value.
    pub const TRUE: Self = Self(1);

    /// Builds a choice from a value that must be `0` or `1`.
    #[inline]
    #[must_use]
    pub fn from_bit(bit: u8) -> Self {
        debug_assert!(bit <= 1);
        Self(black_box(bit & 1))
    }

    /// Returns `u64::MAX` when true and `0` when false.
    #[inline]
    #[must_use]
    pub fn mask_u64(self) -> u64 {
        0u64.wrapping_sub(u64::from(black_box(self.0)))
    }

    /// Returns `u32::MAX` when true and `0` when false.
    #[inline]
    #[must_use]
    pub fn mask_u32(self) -> u32 {
        0u32.wrapping_sub(u32::from(black_box(self.0)))
    }

    /// Returns `0xff` when true and `0` when false.
    #[inline]
    #[must_use]
    pub fn mask_u8(self) -> u8 {
        0u8.wrapping_sub(black_box(self.0))
    }

    /// Logical AND.
    #[inline]
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Logical OR.
    #[inline]
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Logical NOT.
    #[inline]
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Self {
        Self(self.0 ^ 1)
    }

    /// Declassifies the choice. Only call this once the result is public.
    #[inline]
    #[must_use]
    pub fn declassify(self) -> bool {
        black_box(self.0) == 1
    }
}

/// Returns true when `x == 0`.
#[inline]
#[must_use]
pub fn is_zero_u64(x: u64) -> Choice {
    // (x | -x) has its top bit set iff x != 0.
    let nonzero = (x | x.wrapping_neg()) >> 63;
    #[allow(clippy::cast_possible_truncation)]
    Choice::from_bit((nonzero ^ 1) as u8)
}

/// Returns true when `a == b`.
#[inline]
#[must_use]
pub fn eq_u64(a: u64, b: u64) -> Choice {
    is_zero_u64(a ^ b)
}

/// Returns true when `a < b` (unsigned).
#[inline]
#[must_use]
pub fn lt_u64(a: u64, b: u64) -> Choice {
    // Borrow out of a - b, computed without branches.
    let borrow = ((!a & b) | (!(a ^ b) & a.wrapping_sub(b))) >> 63;
    #[allow(clippy::cast_possible_truncation)]
    Choice::from_bit(borrow as u8)
}

/// Returns `a` when `choice` is true, otherwise `b`.
#[inline]
#[must_use]
pub fn select_u64(choice: Choice, a: u64, b: u64) -> u64 {
    let m = choice.mask_u64();
    (a & m) | (b & !m)
}

/// Returns `a` when `choice` is true, otherwise `b`.
#[inline]
#[must_use]
pub fn select_u32(choice: Choice, a: u32, b: u32) -> u32 {
    let m = choice.mask_u32();
    (a & m) | (b & !m)
}

/// Swaps `a` and `b` when `choice` is true.
#[inline]
pub fn swap_u64(choice: Choice, a: &mut u64, b: &mut u64) {
    let t = choice.mask_u64() & (*a ^ *b);
    *a ^= t;
    *b ^= t;
}

/// Overwrites `dst` with `src` when `choice` is true.
///
/// # Panics
///
/// Panics if the slices differ in length; lengths are public.
#[inline]
pub fn assign_bytes(choice: Choice, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    let m = choice.mask_u8();
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= m & (*d ^ *s);
    }
}

/// Compares two byte strings in time that depends only on their lengths.
#[must_use]
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    is_zero_u64(u64::from(black_box(acc))).declassify()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparisons() {
        let samples = [
            0u64,
            1,
            2,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            u64::MAX,
        ];
        for &a in &samples {
            assert_eq!(is_zero_u64(a).declassify(), a == 0);
            for &b in &samples {
                assert_eq!(eq_u64(a, b).declassify(), a == b);
                assert_eq!(lt_u64(a, b).declassify(), a < b, "{a} < {b}");
                assert_eq!(select_u64(Choice::TRUE, a, b), a);
                assert_eq!(select_u64(Choice::FALSE, a, b), b);
            }
        }
    }

    #[test]
    fn bytes() {
        assert!(bytes_eq(b"abc", b"abc"));
        assert!(!bytes_eq(b"abc", b"abd"));
        assert!(!bytes_eq(b"abc", b"ab"));
        let mut d = [1u8, 2, 3];
        assign_bytes(Choice::FALSE, &mut d, &[9, 9, 9]);
        assert_eq!(d, [1, 2, 3]);
        assign_bytes(Choice::TRUE, &mut d, &[9, 9, 9]);
        assert_eq!(d, [9, 9, 9]);
    }
}
