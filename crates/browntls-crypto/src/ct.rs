//! Constant-time helpers.
//!
//! These helpers avoid secret-dependent branches and memory accesses at the
//! source level and use [`core::hint::black_box`] as an optimisation barrier so
//! the compiler does not re-introduce branches. They are not a substitute for
//! reviewing generated code on each supported target.

use core::hint::black_box;

/// A secret boolean represented as an all-zeros or all-ones mask.
#[derive(Clone, Copy, Debug)]
pub struct Choice(u64);

impl Choice {
    /// The `false` value.
    pub const FALSE: Self = Self(0);
    /// The `true` value.
    pub const TRUE: Self = Self(u64::MAX);

    /// Builds a choice from a bit (`0` or `1`). Other values are reduced to
    /// their least significant bit.
    #[inline]
    #[must_use]
    pub fn from_bit(bit: u64) -> Self {
        // The barrier must cover the mask itself: hiding only the input bit
        // still lets the optimiser infer that the mask is 0 or !0 and lower
        // masked selects into branches or conditional loads.
        Self(black_box((bit & 1).wrapping_neg()))
    }

    /// Returns the all-zeros / all-ones mask.
    #[inline]
    #[must_use]
    pub fn mask(self) -> u64 {
        self.0
    }

    /// Declassifies the choice. Only call when the result is public.
    #[inline]
    #[must_use]
    pub fn declassify(self) -> bool {
        black_box(self.0) != 0
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
}

impl core::ops::Not for Choice {
    type Output = Self;

    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// Returns `TRUE` when `x == 0`.
#[inline]
#[must_use]
pub fn is_zero_u64(x: u64) -> Choice {
    // (x | -x) has its top bit set iff x != 0.
    let nz = (x | x.wrapping_neg()) >> 63;
    Choice::from_bit(nz ^ 1)
}

/// Returns `TRUE` when `a == b`.
#[inline]
#[must_use]
pub fn eq_u64(a: u64, b: u64) -> Choice {
    is_zero_u64(a ^ b)
}

/// Returns `TRUE` when `a < b` (unsigned).
#[inline]
#[must_use]
pub fn lt_u64(a: u64, b: u64) -> Choice {
    let (_, borrow) = a.overflowing_sub(b);
    Choice::from_bit(u64::from(black_box(borrow)))
}

/// Selects `a` when `c` is `TRUE`, otherwise `b`.
#[inline]
#[must_use]
pub fn select_u64(c: Choice, a: u64, b: u64) -> u64 {
    b ^ (c.mask() & (a ^ b))
}

/// Selects `a` when `c` is `TRUE`, otherwise `b` (byte variant).
#[inline]
#[must_use]
pub fn select_u8(c: Choice, a: u8, b: u8) -> u8 {
    // Truncation keeps the low byte of the mask, which is 0x00 or 0xff.
    #[allow(clippy::cast_possible_truncation)]
    let m = c.mask() as u8;
    b ^ (m & (a ^ b))
}

/// Overwrites `dst` with `src` when `c` is `TRUE`; leaves it unchanged
/// otherwise. Both slices must have equal length.
///
/// # Panics
///
/// Panics if the lengths differ (a programming error, not data dependent).
#[inline]
pub fn conditional_copy(c: Choice, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src) {
        *d = select_u8(c, *s, *d);
    }
}

/// Swaps `a` and `b` when `c` is `TRUE`.
#[inline]
pub fn conditional_swap_u64(c: Choice, a: &mut [u64], b: &mut [u64]) {
    debug_assert_eq!(a.len(), b.len());
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = c.mask() & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// Compares two byte strings in time that depends only on their lengths.
#[inline]
#[must_use]
pub fn eq_bytes(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice::FALSE;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= black_box(x ^ y);
    }
    is_zero_u64(u64::from(acc))
}

/// Constant-time equality returning a plain `bool`, for public results such as
/// MAC verification outcomes.
#[inline]
#[must_use]
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    eq_bytes(a, b).declassify()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        assert!(is_zero_u64(0).declassify());
        assert!(!is_zero_u64(1).declassify());
        assert!(!is_zero_u64(u64::MAX).declassify());
        assert!(eq_u64(7, 7).declassify());
        assert!(lt_u64(1, 2).declassify());
        assert!(!lt_u64(2, 2).declassify());
        assert_eq!(select_u64(Choice::TRUE, 1, 2), 1);
        assert_eq!(select_u64(Choice::FALSE, 1, 2), 2);
        assert!(eq(b"abc", b"abc"));
        assert!(!eq(b"abc", b"abd"));
        assert!(!eq(b"abc", b"ab"));
        let mut d = [0u8; 3];
        conditional_copy(Choice::FALSE, &mut d, b"xyz");
        assert_eq!(&d, &[0; 3]);
        conditional_copy(Choice::TRUE, &mut d, b"xyz");
        assert_eq!(&d, b"xyz");
    }
}
