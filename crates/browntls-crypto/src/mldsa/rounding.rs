//! Rounding (FIPS 204 §7.4, Algorithms 35 to 40): `Power2Round`,
//! `Decompose`, `HighBits`, `LowBits`, `MakeHint` and `UseHint`.
//!
//! Every input is the representative in `[0, q)`. `Decompose` divides by
//! `2 gamma2` with a multiply-shift (the reference implementation's
//! constants), never with `/` or `%`, because during signing its input
//! depends on the secret mask `y` and on `s2`. Its two conditional
//! corrections take their masks from [`sign_mask`], a best-effort value
//! barrier that discourages the compiler from turning them into branches.
//! Only [`use_hint`], which runs during verification on public data,
//! branches.

use super::poly::{D, Q, sign_mask};

/// `(q - 1) / 88`, the `gamma2` of ML-DSA-44.
pub(crate) const GAMMA2_88: i32 = (Q - 1) / 88;
/// `(q - 1) / 32`, the `gamma2` of ML-DSA-65 and ML-DSA-87.
pub(crate) const GAMMA2_32: i32 = (Q - 1) / 32;

/// `Power2Round(r)` (Algorithm 35): `(r1, r0)` with `r = r1 2^d + r0` and
/// `r0` in `(-2^(d-1), 2^(d-1)]`.
#[inline]
pub(crate) fn power2round(r: i32) -> (i32, i32) {
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    (r1, r - (r1 << D))
}

/// `Decompose(r)` (Algorithm 36) for `gamma2` in `{GAMMA2_88, GAMMA2_32}`:
/// `(r1, r0)` with `r = r1 2 gamma2 + r0 mod q`, `r0` in `(-gamma2, gamma2]`,
/// except that `r - r0 = q - 1` yields `r1 = 0` and `r0 - 1`.
#[inline]
pub(crate) fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    // ceil(r / 128), then a fixed-point multiply that rounds to the nearest
    // multiple of 2 gamma2 / 128 (exact for every r in [0, q)).
    let mut r1 = (r + 127) >> 7;
    if gamma2 == GAMMA2_32 {
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        // (q - 1) / (2 gamma2) = 16 wraps to 0.
        r1 &= 15;
    } else {
        debug_assert!(gamma2 == GAMMA2_88);
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        // (q - 1) / (2 gamma2) = 44 wraps to 0.
        r1 ^= sign_mask(43 - r1) & r1;
    }
    let mut r0 = r - r1 * 2 * gamma2;
    // Centre: r0 > (q - 1) / 2 means the wrapped case, r0 - q.
    r0 -= sign_mask((Q - 1) / 2 - r0) & Q;
    (r1, r0)
}

/// `HighBits(r)` (Algorithm 37).
#[inline]
pub(crate) fn high_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

/// `LowBits(r)` (Algorithm 38). Signing takes `r0` from [`decompose`]
/// directly.
#[cfg(test)]
pub(crate) fn low_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).1
}

/// `MakeHint(z, r)` (Algorithm 39) given `r` and `r + z`, both in `[0, q)`:
/// `1` if their high bits differ, otherwise `0`; branch-free.
#[inline]
pub(crate) fn make_hint(r: i32, r_plus_z: i32, gamma2: i32) -> i32 {
    let diff = high_bits(r, gamma2) ^ high_bits(r_plus_z, gamma2);
    // diff is small and non-negative: (diff | -diff) has its sign bit set
    // iff diff != 0.
    ((diff | diff.wrapping_neg()) >> 31) & 1
}

/// `UseHint(h, r)` (Algorithm 40). Public data only (verification).
#[inline]
pub(crate) fn use_hint(h: bool, r: i32, gamma2: i32) -> i32 {
    let (r1, r0) = decompose(r, gamma2);
    if !h {
        return r1;
    }
    let m = (Q - 1) / (2 * gamma2);
    if r0 > 0 {
        if r1 == m - 1 { 0 } else { r1 + 1 }
    } else if r1 == 0 {
        m - 1
    } else {
        r1 - 1
    }
}
