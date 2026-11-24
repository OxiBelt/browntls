//! Byte encodings (FIPS 204 §7.1 and §7.2): bit packing, `w1Encode`,
//! `HintBitPack` / `HintBitUnpack` and the layout of public keys, expanded
//! private keys and signatures.
//!
//! Bit packing is straight-line code (its loop structure depends only on
//! the public bit width), so it is used for secret polynomials too. Hint
//! packing runs on an accepted signature only and hint unpacking on public
//! signatures; both may branch.

use super::params::{ParameterSet, ctilde_len, eta_bits, w1_bits, z_bits};
use super::poly::{N, Poly};

/// Packs `f(c)` for every coefficient `c` of `p` as a `bits`-bit
/// little-endian integer (`IntegerToBits`, least significant bit first).
/// `out.len()` must be `32 * bits`; `f(c)` must be below `2^bits`.
#[inline]
fn pack_with(p: &Poly, bits: usize, out: &mut [u8], f: impl Fn(i32) -> u32) {
    let mut acc: u64 = 0;
    let mut n = 0;
    let mut o = 0;
    for &c in p.0.iter() {
        acc |= u64::from(f(c)) << n;
        n += bits;
        while n >= 8 {
            // Truncation takes the low byte.
            out[o] = acc as u8;
            acc >>= 8;
            n -= 8;
            o += 1;
        }
    }
}

/// `SimpleBitPack(p, 2^bits - 1)` (Algorithm 16) for coefficients in
/// `[0, 2^bits)`.
pub(crate) fn pack_bits(p: &Poly, bits: usize, out: &mut [u8]) {
    pack_with(p, bits, out, |c| c as u32);
}

/// `BitPack(p, a, b)` (Algorithm 17) for coefficients in `[-a, b]`: packs
/// `b - c` with `bits = bitlen(a + b)`.
pub(crate) fn pack_offset(p: &Poly, b: i32, bits: usize, out: &mut [u8]) {
    pack_with(p, bits, out, |c| (b - c) as u32);
}

/// Unpacks 256 `bits`-bit integers (`SimpleBitUnpack`, Algorithm 18; the
/// caller applies the `b - v` of `BitUnpack`, Algorithm 19).
/// `input.len()` must be `32 * bits`.
pub(crate) fn unpack_bits(input: &[u8], bits: usize, out: &mut Poly) {
    let mask = (1u64 << bits) - 1;
    let mut acc: u64 = 0;
    let mut n = 0;
    let mut bytes = input.iter();
    for c in out.0.iter_mut() {
        while n < bits {
            acc |= u64::from(bytes.next().copied().unwrap_or(0)) << n;
            n += 8;
        }
        // At most 20 bits.
        *c = (acc & mask) as i32;
        acc >>= bits;
        n -= bits;
    }
}

/// `BitUnpack(input, a, b)`: coefficients `b - v`.
pub(crate) fn unpack_offset(input: &[u8], b: i32, bits: usize, out: &mut Poly) {
    unpack_bits(input, bits, out);
    for c in out.0.iter_mut() {
        *c = b - *c;
    }
}

/// `HintBitPack(h)` (Algorithm 20). `out.len()` is `omega + k`; the number of
/// hints must not exceed `omega`.
pub(crate) fn hint_pack<const K: usize>(h: &[[u8; N]; K], omega: usize, out: &mut [u8]) {
    out.fill(0);
    let mut index = 0;
    for (i, row) in h.iter().enumerate() {
        for (j, &bit) in row.iter().enumerate() {
            if bit != 0 && index < omega {
                // j < 256.
                out[index] = j as u8;
                index += 1;
            }
        }
        // index <= omega <= 80.
        out[omega + i] = index as u8;
    }
}

/// `HintBitUnpack(y)` (Algorithm 21) with its strict checks: per-row counts
/// must be non-decreasing and at most `omega`, indices strictly increasing
/// within a row, and unused index bytes zero. Returns `false` for a
/// malformed encoding. Public data only.
pub(crate) fn hint_unpack<const K: usize>(y: &[u8], omega: usize, h: &mut [[u8; N]; K]) -> bool {
    if y.len() != omega + K {
        return false;
    }
    *h = [[0; N]; K];
    let mut index = 0;
    for (i, row) in h.iter_mut().enumerate() {
        let end = usize::from(y[omega + i]);
        if end < index || end > omega {
            return false;
        }
        let first = index;
        while index < end {
            if index > first && y[index - 1] >= y[index] {
                return false;
            }
            row[usize::from(y[index])] = 1;
            index += 1;
        }
    }
    y[index..omega].iter().all(|&b| b == 0)
}

/// Byte offsets of the expanded private key
/// `rho || K || tr || s1 || s2 || t0` (`skEncode`, Algorithm 24).
pub(crate) struct SkLayout {
    /// Bytes per packed `s1` / `s2` polynomial.
    pub(crate) s_len: usize,
    /// Start of `s1`.
    pub(crate) s1: usize,
    /// Start of `s2`.
    pub(crate) s2: usize,
    /// Start of `t0`.
    pub(crate) t0: usize,
}

/// Bytes per packed `t0` polynomial (13 bits per coefficient).
pub(crate) const T0_LEN: usize = 416;
/// Bytes per packed `t1` polynomial (10 bits per coefficient).
pub(crate) const T1_LEN: usize = 320;

pub(crate) const fn sk_layout<P: ParameterSet>() -> SkLayout {
    let s_len = 32 * eta_bits::<P>();
    let s1 = 128;
    let s2 = s1 + P::L * s_len;
    SkLayout {
        s_len,
        s1,
        s2,
        t0: s2 + P::K * s_len,
    }
}

/// Byte offsets of a signature `c~ || z || h` (`sigEncode`, Algorithm 26):
/// the start of `z`, bytes per packed `z` polynomial, the start of `h`.
pub(crate) const fn sig_layout<P: ParameterSet>() -> (usize, usize, usize) {
    let z = ctilde_len::<P>();
    let z_len = 32 * z_bits::<P>();
    (z, z_len, z + P::L * z_len)
}

/// Bytes of one `w1Encode` polynomial (Algorithm 28).
pub(crate) const fn w1_len<P: ParameterSet>() -> usize {
    32 * w1_bits::<P>()
}
