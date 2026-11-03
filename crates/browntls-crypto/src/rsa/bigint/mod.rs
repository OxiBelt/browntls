//! Fixed-capacity multi-precision integers for RSA.
//!
//! Values are little-endian arrays of 64-bit limbs. Every routine operates on
//! slices whose lengths are decided by *public* parameters (the key size), so
//! loop counts never depend on secret values. Routines documented as
//! constant time contain no secret-dependent branches or memory indices; the
//! few variable-time helpers are named `*_vartime` and are only used on public
//! data or during key generation.
//!
//! The limb-level helpers here are deliberately simple; the hot path is the
//! Montgomery multiplication in [`mont`].

pub(crate) mod inv;
pub(crate) mod mont;
pub(crate) mod soft;
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

use core::hint::black_box;

use crate::Error;
use crate::ct::{self, Choice};

/// Largest supported modulus (8192 bits) in limbs.
pub(crate) const MAX_LIMBS: usize = 128;
/// Capacity for CRT halves (each prime of an 8192-bit key is 4096 bits).
pub(crate) const HALF_LIMBS: usize = MAX_LIMBS / 2;

/// Loads a big-endian byte string into `out` (zero padded). Leading zero bytes
/// are accepted; the value must fit in `out.len()` limbs.
///
/// Runs in time depending only on `bytes.len()` and `out.len()`.
pub(crate) fn from_be_bytes(out: &mut [u64], bytes: &[u8]) -> Result<(), Error> {
    out.fill(0);
    let cap = out.len() * 8;
    if bytes.len() > cap {
        // Allow (and ignore) leading zero bytes beyond the capacity.
        let extra = bytes.len() - cap;
        let mut nonzero = 0u8;
        for &b in &bytes[..extra] {
            nonzero |= b;
        }
        if nonzero != 0 {
            return Err(Error::InvalidLength);
        }
        return from_be_bytes(out, &bytes[extra..]);
    }
    for (i, &b) in bytes.iter().rev().enumerate() {
        out[i / 8] |= u64::from(b) << (8 * (i % 8));
    }
    Ok(())
}

/// Writes `limbs` as a big-endian byte string filling `out` exactly.
///
/// # Panics
///
/// Panics if the value does not fit in `out.len()` bytes (callers size the
/// output from the public modulus length, so this is not reachable from
/// untrusted input).
pub(crate) fn to_be_bytes(limbs: &[u64], out: &mut [u8]) {
    let n = out.len();
    for (i, o) in out.iter_mut().rev().enumerate() {
        let limb = limbs.get(i / 8).copied().unwrap_or(0);
        *o = (limb >> (8 * (i % 8))) as u8;
    }
    // Any limb byte beyond `out` must be zero.
    let mut spill = 0u64;
    for (i, &l) in limbs.iter().enumerate() {
        for k in 0..8 {
            if i * 8 + k >= n {
                spill |= (l >> (8 * k)) & 0xff;
            }
        }
    }
    assert_eq!(spill, 0, "value does not fit in the output buffer");
}

/// Bit length of a value (variable time; use on public values only).
pub(crate) fn bit_len_vartime(limbs: &[u64]) -> usize {
    for (i, &l) in limbs.iter().enumerate().rev() {
        if l != 0 {
            return i * 64 + (64 - l.leading_zeros() as usize);
        }
    }
    0
}

/// Number of limbs needed for `bits` bits.
pub(crate) const fn limbs_for_bits(bits: usize) -> usize {
    bits.div_ceil(64)
}

/// `TRUE` when every limb is zero (constant time).
pub(crate) fn is_zero(a: &[u64]) -> Choice {
    let mut acc = 0u64;
    for &l in a {
        acc |= l;
    }
    ct::is_zero_u64(acc)
}

/// `TRUE` when `a == b` (constant time; equal lengths required).
pub(crate) fn ct_eq(a: &[u64], b: &[u64]) -> Choice {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = 0u64;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    ct::is_zero_u64(acc)
}

/// `TRUE` when `a < b` (constant time; equal lengths required).
pub(crate) fn ct_lt(a: &[u64], b: &[u64]) -> Choice {
    debug_assert_eq!(a.len(), b.len());
    let mut borrow = 0u64;
    for (x, y) in a.iter().zip(b) {
        let (d, b1) = x.overflowing_sub(*y);
        let (_, b2) = d.overflowing_sub(borrow);
        borrow = u64::from(b1 | b2);
    }
    Choice::from_bit(borrow)
}

/// `out = a - b`, returning the borrow (0 or 1). Constant time.
pub(crate) fn sub(out: &mut [u64], a: &[u64], b: &[u64]) -> u64 {
    debug_assert!(out.len() == a.len() && a.len() == b.len());
    let mut borrow = 0u64;
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        let (d, b1) = x.overflowing_sub(*y);
        let (d, b2) = d.overflowing_sub(borrow);
        *o = d;
        borrow = u64::from(b1 | b2);
    }
    borrow
}

/// `out = a + b`, returning the carry (0 or 1). Constant time.
pub(crate) fn add(out: &mut [u64], a: &[u64], b: &[u64]) -> u64 {
    debug_assert!(out.len() == a.len() && a.len() == b.len());
    let mut carry = 0u64;
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        let (s, c1) = x.overflowing_add(*y);
        let (s, c2) = s.overflowing_add(carry);
        *o = s;
        carry = u64::from(c1 | c2);
    }
    carry
}

/// `a += b` in place, returning the carry. Constant time.
pub(crate) fn add_assign(a: &mut [u64], b: &[u64]) -> u64 {
    let mut carry = 0u64;
    for (x, y) in a.iter_mut().zip(b) {
        let (s, c1) = x.overflowing_add(*y);
        let (s, c2) = s.overflowing_add(carry);
        *x = s;
        carry = u64::from(c1 | c2);
    }
    carry
}

/// Adds the single limb `w` to `a`, returning the carry. Constant time.
pub(crate) fn add_word(a: &mut [u64], w: u64) -> u64 {
    let mut carry = w;
    for x in a.iter_mut() {
        let (s, c) = x.overflowing_add(carry);
        *x = s;
        carry = u64::from(c);
    }
    carry
}

/// Subtracts the single limb `w` from `a`, returning the borrow. Constant time.
pub(crate) fn sub_word(a: &mut [u64], w: u64) -> u64 {
    let mut borrow = w;
    for x in a.iter_mut() {
        let (d, b) = x.overflowing_sub(borrow);
        *x = d;
        borrow = u64::from(b);
    }
    borrow
}

/// `a = c ? b : a` (constant time).
pub(crate) fn assign_if(a: &mut [u64], c: Choice, b: &[u64]) {
    // The barrier hides the 0 / !0 shape of the mask from the optimiser so
    // that it cannot turn the selects into branches or conditional loads.
    let m = black_box(c.mask());
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= m & (*x ^ y);
    }
}

/// Reduces `a` (with an optional extra high bit `hi`, so the value is
/// `hi * 2^(64 n) + a` and less than `2 m`) into `[0, m)` by one conditional
/// subtraction. Constant time.
pub(crate) fn cond_sub_mod(a: &mut [u64], hi: u64, m: &[u64]) {
    let mut tmp = [0u64; MAX_LIMBS];
    cond_sub_mod_with(a, hi, m, &mut tmp[..a.len()]);
}

/// [`cond_sub_mod`] with caller-provided scratch of `a.len()` limbs (avoids
/// zero-filling a fresh buffer in the multiplication hot path).
pub(crate) fn cond_sub_mod_with(a: &mut [u64], hi: u64, m: &[u64], tmp: &mut [u64]) {
    let borrow = sub(tmp, a, m);
    // Subtract when the value is >= m: either the high bit is set or no borrow.
    let keep_diff = ct::is_zero_u64(hi).and(Choice::from_bit(borrow));
    assign_if(a, !keep_diff, tmp);
}

/// `out = (a + b) mod m` for `a, b < m`. Constant time.
pub(crate) fn mod_add(out: &mut [u64], a: &[u64], b: &[u64], m: &[u64]) {
    let carry = add(out, a, b);
    cond_sub_mod(out, carry, m);
}

/// `out = (a - b) mod m` for `a, b < m`. Constant time.
pub(crate) fn mod_sub(out: &mut [u64], a: &[u64], b: &[u64], m: &[u64]) {
    let borrow = sub(out, a, b);
    let mut tmp = [0u64; MAX_LIMBS];
    let tmp = &mut tmp[..out.len()];
    add(tmp, out, m);
    assign_if(out, Choice::from_bit(borrow), tmp);
}

/// Shifts left by one bit, returning the bit shifted out. Constant time.
pub(crate) fn shl1(a: &mut [u64]) -> u64 {
    let mut carry = 0u64;
    for x in a.iter_mut() {
        let next = *x >> 63;
        *x = (*x << 1) | carry;
        carry = next;
    }
    carry
}

/// Shifts right by one bit, returning the bit shifted out. Constant time.
pub(crate) fn shr1(a: &mut [u64]) -> u64 {
    let mut carry = 0u64;
    for x in a.iter_mut().rev() {
        let next = *x & 1;
        *x = (*x >> 1) | (carry << 63);
        carry = next;
    }
    carry
}

/// Returns bit `i` of `a` (0 or 1); `i` must be a public index.
pub(crate) fn bit(a: &[u64], i: usize) -> u64 {
    (a[i / 64] >> (i % 64)) & 1
}

/// Returns the `w`-bit window ending just below bit `top` (bits
/// `top-w .. top`, `w <= 64`, `top % w == 0`, `top <= 64 * a.len()`).
pub(crate) fn window(a: &[u64], top: usize, w: usize) -> u64 {
    let lo = top - w;
    let limb = lo / 64;
    let shift = lo % 64;
    let mut v = a[limb] >> shift;
    if shift + w > 64 && limb + 1 < a.len() {
        v |= a[limb + 1] << (64 - shift);
    }
    v & ((1u64 << w) - 1)
}

/// Schoolbook product `out = a * b` (`out.len() == a.len() + b.len()`).
/// Constant time.
pub(crate) fn mul(out: &mut [u64], a: &[u64], b: &[u64]) {
    debug_assert_eq!(out.len(), a.len() + b.len());
    out.fill(0);
    for (i, &bi) in b.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &aj) in a.iter().enumerate() {
            let t = u128::from(out[i + j]) + u128::from(aj) * u128::from(bi) + u128::from(carry);
            out[i + j] = t as u64;
            carry = (t >> 64) as u64;
        }
        out[i + a.len()] = carry;
    }
}

/// `out = a * w` (`out.len() == a.len() + 1`). Constant time.
pub(crate) fn mul_word(out: &mut [u64], a: &[u64], w: u64) {
    debug_assert_eq!(out.len(), a.len() + 1);
    let mut carry = 0u64;
    for (o, &x) in out.iter_mut().zip(a) {
        let t = u128::from(x) * u128::from(w) + u128::from(carry);
        *o = t as u64;
        carry = (t >> 64) as u64;
    }
    out[a.len()] = carry;
}

/// `out = x mod m` for any non-zero `m` (even moduli included), by
/// restoring shift-subtract division over every bit of `x`.
///
/// Constant time in the values; the cost is `64 * x.len()` iterations of
/// `m.len()`-limb work, so this is reserved for key loading and generation.
pub(crate) fn ct_mod(out: &mut [u64], x: &[u64], m: &[u64]) {
    debug_assert_eq!(out.len(), m.len());
    out.fill(0);
    let mut diff = [0u64; MAX_LIMBS];
    let diff = &mut diff[..m.len()];
    for i in (0..x.len() * 64).rev() {
        // out = 2*out + bit; the shifted-out bit acts as a 65th bit.
        let hi = shl1(out);
        out[0] |= bit(x, i);
        let borrow = sub(diff, out, m);
        let ge = ct::is_zero_u64(hi).and(Choice::from_bit(borrow));
        assign_if(out, !ge, diff);
    }
}

/// Divides `x` in place by the single limb `w`, returning the remainder.
///
/// Variable time (hardware division): key generation only.
pub(crate) fn div_rem_word_vartime(x: &mut [u64], w: u64) -> u64 {
    debug_assert!(w != 0);
    let mut rem = 0u64;
    for limb in x.iter_mut().rev() {
        let cur = (u128::from(rem) << 64) | u128::from(*limb);
        *limb = (cur / u128::from(w)) as u64;
        rem = (cur % u128::from(w)) as u64;
    }
    rem
}

/// Remainder of `x` modulo the single limb `w` (variable time; key
/// generation only).
pub(crate) fn rem_word_vartime(x: &[u64], w: u64) -> u64 {
    let mut rem = 0u64;
    for &limb in x.iter().rev() {
        let cur = (u128::from(rem) << 64) | u128::from(limb);
        rem = (cur % u128::from(w)) as u64;
    }
    rem
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn rng(seed: &mut u64) -> u64 {
        // xorshift64*
        *seed ^= *seed >> 12;
        *seed ^= *seed << 25;
        *seed ^= *seed >> 27;
        seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    #[test]
    fn byte_conversion_roundtrip() {
        let mut limbs = [0u64; 4];
        from_be_bytes(&mut limbs, &[0, 0, 1, 2, 3]).unwrap();
        assert_eq!(limbs, [0x0001_0203, 0, 0, 0]);
        let mut out = [0u8; 9];
        to_be_bytes(&limbs, &mut out);
        assert_eq!(out, [0, 0, 0, 0, 0, 0, 1, 2, 3]);
        // Leading zeros beyond the capacity are tolerated.
        let mut small = [0u64; 1];
        from_be_bytes(&mut small, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff]).unwrap();
        assert_eq!(small, [0xff]);
        assert!(from_be_bytes(&mut small, &[1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert_eq!(bit_len_vartime(&[0, 1]), 65);
        assert_eq!(bit_len_vartime(&[0, 0]), 0);
    }

    #[test]
    fn compare_add_sub() {
        let a = [5u64, 1];
        let b = [u64::MAX, 0];
        assert!(ct_lt(&b, &a).declassify());
        assert!(!ct_lt(&a, &b).declassify());
        assert!(!ct_lt(&a, &a).declassify());
        let mut s = [0u64; 2];
        assert_eq!(add(&mut s, &a, &b), 0);
        assert_eq!(s, [4, 2]);
        let mut d = [0u64; 2];
        assert_eq!(sub(&mut d, &s, &b), 0);
        assert_eq!(d, a);
        assert_eq!(sub(&mut d, &b, &a), 1);
        let mut x = [u64::MAX, u64::MAX];
        assert_eq!(add_word(&mut x, 1), 1);
        assert_eq!(x, [0, 0]);
        assert_eq!(sub_word(&mut x, 1), 1);
        assert_eq!(x, [u64::MAX, u64::MAX]);
    }

    #[test]
    fn shifts_and_windows() {
        let mut a = [1u64 << 63, 0];
        assert_eq!(shl1(&mut a), 0);
        assert_eq!(a, [0, 1]);
        assert_eq!(shr1(&mut a), 0);
        assert_eq!(a, [1 << 63, 0]);
        assert_eq!(shr1(&mut a), 0);
        let v = [0xfedc_ba98_7654_3210u64, 0x0123_4567_89ab_cdef];
        assert_eq!(window(&v, 4, 4), 0);
        assert_eq!(window(&v, 8, 4), 1);
        assert_eq!(window(&v, 64, 4), 0xf);
        assert_eq!(window(&v, 68, 4), 0xf);
        assert_eq!(window(&v, 128, 4), 0);
        assert_eq!(window(&v, 72, 8), 0xef);
        assert_eq!(bit(&v, 64), 1);
        assert_eq!(bit(&v, 65), 1);
        assert_eq!(bit(&v, 66), 1);
        assert_eq!(bit(&v, 67), 1);
        assert_eq!(bit(&v, 68), 0);
    }

    #[test]
    fn mul_matches_u128() {
        let mut seed = 0x1234_5678_9abc_def1u64;
        for _ in 0..200 {
            let a = rng(&mut seed);
            let b = rng(&mut seed);
            let mut out = [0u64; 2];
            mul(&mut out, &[a], &[b]);
            let p = u128::from(a) * u128::from(b);
            assert_eq!(out, [p as u64, (p >> 64) as u64]);
            mul_word(&mut out, &[a], b);
            assert_eq!(out, [p as u64, (p >> 64) as u64]);
        }
    }

    #[test]
    fn ct_mod_recovers_remainder() {
        // x = q*m + r with r < m must reduce to r, for odd and even m.
        let mut seed = 0x0bad_cafe_dead_beefu64;
        for len in [1usize, 2, 3, 5, 8] {
            for _ in 0..8 {
                let mut m = vec![0u64; len];
                let mut q = vec![0u64; len];
                let mut r = vec![0u64; len];
                for i in 0..len {
                    m[i] = rng(&mut seed);
                    q[i] = rng(&mut seed);
                    r[i] = rng(&mut seed);
                }
                m[len - 1] |= 1 << 63;
                r[len - 1] >>= 1; // r < m
                let mut x = vec![0u64; 2 * len];
                mul(&mut x, &q, &m);
                let mut rr = r.clone();
                rr.resize(2 * len, 0);
                assert_eq!(add_assign(&mut x, &rr), 0);
                let mut out = vec![0u64; len];
                ct_mod(&mut out, &x, &m);
                assert_eq!(out, r);
            }
        }
    }

    #[test]
    fn word_division() {
        let mut x = [0x1234_5678_9abc_def0u64, 0x0fed_cba9_8765_4321];
        let v = (u128::from(x[1]) << 64) | u128::from(x[0]);
        let rem = div_rem_word_vartime(&mut x, 65537);
        assert_eq!(u128::from(rem), v % 65537);
        assert_eq!((u128::from(x[1]) << 64) | u128::from(x[0]), v / 65537);
        assert_eq!(
            rem_word_vartime(&[v as u64, (v >> 64) as u64], 1000),
            (v % 1000) as u64
        );
    }

    #[test]
    fn modular_add_sub() {
        let m = [7u64, 0, 1];
        let a = [6u64, 0, 1];
        let b = [3u64, 0, 0];
        let mut out = [0u64; 3];
        mod_add(&mut out, &a, &b, &m);
        assert_eq!(out, [2, 0, 0]);
        mod_sub(&mut out, &b, &a, &m);
        assert_eq!(out, [4, 0, 0]);
        mod_sub(&mut out, &a, &b, &m);
        assert_eq!(out, [3, 0, 1]);
    }
}
