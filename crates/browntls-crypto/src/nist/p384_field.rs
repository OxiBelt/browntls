//! P-384 field multiplication specialised to
//! `p = 2^384 - 2^128 - 2^96 + 2^32 - 1`.
//!
//! The full 768-bit product is followed by six Montgomery rounds on its low
//! half. Since `-p^-1 = 2^32 + 1 (mod 2^64)`, the quotient digit of a round is
//! `q = w0 + (w0 << 32)`, and with `p = 2^384 - k`,
//! `k = 2^128 + 2^96 - 2^32 + 1`, adding `q p` to the six-limb window means
//! subtracting the four-limb `q k` (two multiplications by constants; its low
//! limb cancels `w0`) and placing `q` minus the borrow on top. The window
//! never grows beyond six limbs. The high half of the product is added
//! afterwards and the result (below `2p`) is reduced by one masked
//! subtraction. Operation sequence and memory accesses are independent of the
//! operands.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

use super::curve::{Curve, Fe};
use super::mont::{self, adc, sbb};
use super::params::P384;
use super::wide;

/// Low limb of `k = 2^384 - p`: `2^64 - 2^32 + 1`.
const K0: u64 = 0xffff_ffff_0000_0001;
/// Middle limb of `k`: `2^32 - 1` (the top limb is `1`).
const K1: u64 = 0x0000_0000_ffff_ffff;

/// One reduction round: `(window + q p) / 2^64` for the window `w`.
#[inline(always)]
fn round(w: [u64; 6]) -> [u64; 6] {
    let q = w[0].wrapping_add(w[0] << 32);
    // q k = (c0, c1, c2, c3) with c0 = w[0] and c3 a single bit.
    let p0 = (q as u128) * (K0 as u128);
    let p1 = (q as u128) * (K1 as u128);
    let (c1, k) = adc((p0 >> 64) as u64, p1 as u64, 0);
    let (c2, c3) = adc((p1 >> 64) as u64, q, k);
    // window - q k + q 2^384, shifted down one limb. The borrow out of the
    // fifth limb is at most q (q = 0 means q k = 0 and no borrow).
    let (d1, b) = sbb(w[1], c1, 0);
    let (d2, b) = sbb(w[2], c2, b);
    let (d3, b) = sbb(w[3], c3, b);
    let (d4, b) = sbb(w[4], 0, b);
    let (d5, b) = sbb(w[5], 0, b);
    [d1, d2, d3, d4, d5, q - b]
}

/// Montgomery reduction of `t < p 2^384` to `t 2^-384 mod p`, fully reduced.
#[inline(always)]
pub(crate) fn reduce(t: &[u64; 12]) -> Fe<6> {
    let mut w = [t[0], t[1], t[2], t[3], t[4], t[5]];
    for _ in 0..6 {
        w = round(w);
    }
    // w <= p; adding the high half (below p) gives a value below 2p.
    let mut r = [0u64; 6];
    let mut c = 0;
    for i in 0..6 {
        (r[i], c) = adc(w[i], t[6 + i], c);
    }
    let (d, borrow) = mont::sub(&r, &P384::P);
    // Keep r when the 385-bit value is below p (no carry and a borrow).
    let reduced = mont::barrier((c | (borrow ^ 1)).wrapping_neg());
    mont::select(reduced, &d, &r)
}

/// Montgomery multiplication `a b 2^-384 mod p` for `a, b < p`.
#[inline]
pub(crate) fn mul(a: &Fe<6>, b: &Fe<6>) -> Fe<6> {
    reduce(&wide::mul::<6, 12>(a, b))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::curve::fe_mul_soft;
    use super::*;

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    /// Edge values and random elements below `p`.
    pub(crate) fn inputs() -> std::vec::Vec<Fe<6>> {
        let p = P384::P;
        let limb = |i: usize, v: u64| {
            let mut x = [0u64; 6];
            x[i] = v;
            x
        };
        let one = limb(0, 1);
        let mut v = std::vec![
            [0u64; 6],
            one,
            limb(0, 2),
            mont::sub(&p, &one).0,
            mont::sub(&p, &limb(0, 2)).0,
            P384::ONE,
            P384::R2,
            // Quotient digits 0, all ones, and with a carry into bit 32.
            limb(0, u64::MAX),
            limb(0, 0xffff_ffff),
            limb(0, 1 << 32),
            limb(0, K0),
            limb(1, K1),
            limb(5, u64::MAX - 1),
            [u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0],
            [0, 0, 0, 0, 0, u64::MAX],
            [K1, 0, 0, 0, 0, u64::MAX],
            [1 << 63; 6],
            [u64::MAX, 0, u64::MAX, 0, u64::MAX, 0],
            [0, u64::MAX, 0, u64::MAX, 0, u64::MAX],
        ];
        let mut seed = 0x13198a2e03707344u64;
        while v.len() < 200 {
            let x: Fe<6> = core::array::from_fn(|_| xorshift(&mut seed));
            if mont::lt(&x, &p) != 0 {
                v.push(x);
            }
        }
        v
    }

    #[test]
    fn matches_generic_montgomery() {
        let v = inputs();
        for a in &v {
            assert!(mont::lt(a, &P384::P) != 0);
            for b in &v {
                assert_eq!(
                    mul(a, b),
                    fe_mul_soft::<P384, 6>(a, b),
                    "a = {a:x?} b = {b:x?}"
                );
            }
        }
    }
}
