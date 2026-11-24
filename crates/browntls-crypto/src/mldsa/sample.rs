//! Pseudorandom sampling (FIPS 204 §7.3): `RejNTTPoly` (one entry of
//! `ExpandA`), `RejBoundedPoly` (one entry of `ExpandS`), `ExpandMask` and
//! `SampleInBall`.
//!
//! Side channels: `RejNTTPoly` samples the public matrix `A` and may branch
//! freely. `RejBoundedPoly` and `SampleInBall` consume a data-dependent
//! number of XOF bytes, and `RejBoundedPoly` branches on whether a nibble is
//! accepted; the accepted values themselves are computed and stored without
//! secret-dependent branches or indices (`SampleInBall` reads and writes
//! through masked scans of all 256 positions with opaque masks; see
//! [`sample_in_ball`]). By the rejection-sampling argument
//! the rejection pattern is independent of the accepted values, so the
//! timing reveals nothing about them. `ExpandMask` is straight-line code.

use super::encode::unpack_bits;
use super::poly::{N, Poly, Q};
use crate::hash::{Shake128, Shake256};
use crate::zeroize::Zeroizing;

/// `RejNTTPoly(rho || s || r)` (Algorithm 30): the entry `A[r][s]` of the
/// public matrix `A`, in the NTT domain, coefficients in `[0, q)`.
pub(crate) fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8, out: &mut Poly) {
    let mut h = Shake128::new();
    h.update(rho);
    h.update(&[s, r]);
    let mut xof = h.finalize_xof();
    // 168 bytes (the SHAKE128 rate) are 56 three-byte candidates.
    let mut buf = [0u8; 168];
    let mut j = 0;
    while j < N {
        xof.read(&mut buf);
        for c in buf.as_chunks::<3>().0 {
            // CoeffFromThreeBytes (Algorithm 14).
            let z = u32::from(c[0]) | (u32::from(c[1]) << 8) | ((u32::from(c[2]) & 0x7f) << 16);
            if z < Q as u32 && j < N {
                out.0[j] = z as i32;
                j += 1;
            }
        }
    }
}

/// `CoeffFromHalfByte(b)` (Algorithm 15) for a nibble `b`: `(value, ok)`
/// with `ok = 1` when `b` is accepted. Branch-free; `b mod 5` is a
/// multiply-shift.
#[inline]
fn coeff_from_half_byte(b: u32, eta: usize) -> (i32, u32) {
    if eta == 2 {
        // For b < 16, (205 b) >> 10 = floor(b / 5).
        let m5 = b - 5 * ((205 * b) >> 10);
        (2 - m5 as i32, (b.wrapping_sub(15) >> 31) & 1)
    } else {
        (4 - b as i32, (b.wrapping_sub(9) >> 31) & 1)
    }
}

/// `RejBoundedPoly(rho' || IntegerToBytes(nonce, 2))` (Algorithm 31): a
/// polynomial with coefficients in `[-eta, eta]` (secret).
pub(crate) fn rej_bounded_poly(rho_prime: &[u8; 64], nonce: u16, eta: usize, out: &mut Poly) {
    let mut h = Shake256::new();
    h.update(rho_prime);
    h.update(&nonce.to_le_bytes());
    let mut xof = h.finalize_xof();
    let mut buf = Zeroizing([0u8; 136]);
    let mut j = 0;
    while j < N {
        xof.read(&mut buf.0);
        for &byte in buf.iter() {
            for nibble in [u32::from(byte & 15), u32::from(byte >> 4)] {
                let (value, ok) = coeff_from_half_byte(nibble, eta);
                // Branching on acceptance reveals only which nibbles were
                // rejected, which is independent of the accepted values.
                if ok == 1 && j < N {
                    out.0[j] = value;
                    j += 1;
                }
            }
        }
    }
}

/// One polynomial of `ExpandMask(rho'', kappa)` (Algorithm 34): the
/// coefficients `gamma1 - v` of `BitUnpack(H(rho'' || IntegerToBytes(nonce,
/// 2)), gamma1 - 1, gamma1)`, in `[-gamma1 + 1, gamma1]` (secret).
pub(crate) fn expand_mask_poly(
    rho2: &[u8; 64],
    nonce: u16,
    gamma1: i32,
    bits: usize,
    out: &mut Poly,
) {
    let mut h = Shake256::new();
    h.update(rho2);
    h.update(&nonce.to_le_bytes());
    // At most 32 * 20 = 640 bytes.
    let mut buf = Zeroizing([0u8; 640]);
    let buf = &mut buf.0[..32 * bits];
    h.finalize_xof().read(buf);
    unpack_bits(buf, bits, out);
    for c in out.0.iter_mut() {
        *c = gamma1 - *c;
    }
}

/// `SampleInBall(c~)` (Algorithm 29): the challenge with `tau` coefficients
/// `+-1` and the rest zero.
///
/// The Fisher-Yates swap target `j` is chosen by rejection (`j <= i`); the
/// number of bytes consumed leaks, the accepted `j` does not. For each `i`
/// the swap computes a mask for every one of the 256 positions (all-ones at
/// `j`), passes the whole mask array through [`core::hint::black_box`] (a
/// best-effort barrier, not a guarantee) so that the optimiser is not
/// shown that the masks are one-hot, and then reads
/// `c_j` and writes the sign with masked selects over all 256 positions.
/// Positions above `i` are zero and never equal `j`, so scanning the fixed
/// range gives the same result as scanning `0..=i`, with no loop tail whose
/// length depends on `i`. Not inlined, so that its code can be inspected.
#[inline(never)]
pub(crate) fn sample_in_ball(ctilde: &[u8], tau: usize, c: &mut Poly) {
    let mut h = Shake256::new();
    h.update(ctilde);
    let mut xof = h.finalize_xof();
    let mut buf = Zeroizing([0u8; 136]);
    xof.read(&mut buf.0);
    let mut signs = Zeroizing([u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ])]);
    let mut masks = Zeroizing([0i32; N]);
    let mut pos = 8;
    *c = Poly::ZERO;
    for i in N - tau..N {
        let j = loop {
            if pos == buf.len() {
                xof.read(&mut buf.0);
                pos = 0;
            }
            let b = usize::from(buf[pos]);
            pos += 1;
            if b <= i {
                break b as i32;
            }
        };
        // (-1)^h[i + tau - 256], taking the sign bits in order.
        let sign = 1 - 2 * (signs[0] & 1) as i32;
        signs[0] >>= 1;
        for (m, k) in masks.0.iter_mut().enumerate() {
            *k = eq_mask(m as i32, j);
        }
        // Value barrier (best effort): the masks are meant to be opaque
        // afterwards, to discourage turning selects on them back into
        // branches or indexed accesses.
        let masks = core::hint::black_box(&mut masks.0);
        // c_i <- c_j, read with a masked scan.
        let mut cj = 0;
        for (&v, &k) in c.0.iter().zip(masks.iter()) {
            cj |= v & k;
        }
        c.0[i] = cj;
        // c_j <- sign, written with a masked scan.
        for (v, &k) in c.0.iter_mut().zip(masks.iter()) {
            *v = (*v & !k) | (sign & k);
        }
    }
}

/// `-1` if `a == b`, otherwise `0` (for `0 <= a, b < 2^31`).
#[inline]
fn eq_mask(a: i32, b: i32) -> i32 {
    let d = a ^ b;
    !((d | d.wrapping_neg()) >> 31)
}
