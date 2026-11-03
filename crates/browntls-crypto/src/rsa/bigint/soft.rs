//! Portable Montgomery multiplication (CIOS, 64-bit limbs via `u128`).
//!
//! [`mont_mul`] is the portable kernel: a whole multiplication with both row
//! passes of each step fused into one sweep. [`step`] is the two-pass
//! single-step form kept as the reference the per-step kernels mirror.
//!
//! One step processes a single limb `b_i` of the multiplier against the
//! accumulator window `w` (`len + 2` limbs): it adds `a * b_i`, then adds the
//! multiple of the modulus that clears the lowest limb. The caller advances
//! the window by one limb afterwards, which implements the division by 2^64
//! without copying. See [`super::mont`] for the loop and the bounds that make
//! the final result fit in `len + 1` limbs.
//!
//! Constant time: fixed loop counts, no data-dependent branches.

/// `w[0..len] += a[0..len] * b_i`, then `w[0..len] += m * (w[0] * m0inv)`,
/// propagating carries into `w[len]` and `w[len + 1]`.
#[inline]
pub(crate) fn step(w: &mut [u64], a: &[u64], bi: u64, m: &[u64], m0inv: u64) {
    let len = a.len();
    debug_assert!(len >= 1 && m.len() == len && w.len() == len + 2);

    let mut carry = 0u64;
    for j in 0..len {
        let t = u128::from(w[j]) + u128::from(a[j]) * u128::from(bi) + u128::from(carry);
        w[j] = t as u64;
        carry = (t >> 64) as u64;
    }
    let (s, o) = w[len].overflowing_add(carry);
    w[len] = s;
    w[len + 1] = u64::from(o);

    let mm = w[0].wrapping_mul(m0inv);
    let t = u128::from(w[0]) + u128::from(mm) * u128::from(m[0]);
    debug_assert_eq!(t as u64, 0);
    let mut carry = (t >> 64) as u64;
    for j in 1..len {
        let t = u128::from(w[j]) + u128::from(mm) * u128::from(m[j]) + u128::from(carry);
        w[j] = t as u64;
        carry = (t >> 64) as u64;
    }
    // `w[0]` is now zero by construction; the caller drops it by advancing
    // the window. Mark it explicitly so the invariant is visible.
    w[0] = 0;
    let (s, o) = w[len].overflowing_add(carry);
    w[len] = s;
    // The accumulator is below 2^(64 len + 66), so this cannot overflow.
    w[len + 1] = w[len + 1].wrapping_add(u64::from(o));
}

/// Whole CIOS multiplication with both row passes fused into one sweep:
/// `t[0..=len] = (a b + M m) / 2^(64 len)` (below `2 m`, top limb 0 or 1)
/// for `t` of `len + 1` limbs, which must be zero on entry.
///
/// Per limb `b_i`: `mm = (t_0 + a_0 b_i) m0inv`, then for each `j` the
/// two products are added with separate carry words (`t_j + a_j b_i + c_a`
/// and its low word `+ m_j mm + c_m`), and the sum is stored one limb lower.
/// Each `u128` sum is below `2^128` (`(2^64 - 1)^2 + 2 (2^64 - 1)`).
/// Constant time.
pub(crate) fn mont_mul(t: &mut [u64], a: &[u64], b: &[u64], m: &[u64], m0inv: u64) {
    let len = a.len();
    debug_assert!(len >= 1 && b.len() == len && m.len() == len && t.len() == len + 1);
    for &bi in b {
        let p = u128::from(t[0]) + u128::from(a[0]) * u128::from(bi);
        let mm = (p as u64).wrapping_mul(m0inv);
        let q = u128::from(p as u64) + u128::from(mm) * u128::from(m[0]);
        debug_assert_eq!(q as u64, 0);
        let mut ca = (p >> 64) as u64;
        let mut cm = (q >> 64) as u64;
        for j in 1..len {
            let p = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + u128::from(ca);
            ca = (p >> 64) as u64;
            let q = u128::from(p as u64) + u128::from(mm) * u128::from(m[j]) + u128::from(cm);
            cm = (q >> 64) as u64;
            t[j - 1] = q as u64;
        }
        let s = u128::from(t[len]) + u128::from(ca) + u128::from(cm);
        t[len - 1] = s as u64;
        t[len] = (s >> 64) as u64;
    }
}
