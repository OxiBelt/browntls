//! Portable Montgomery multiplication step (CIOS, 64-bit limbs via `u128`).
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
