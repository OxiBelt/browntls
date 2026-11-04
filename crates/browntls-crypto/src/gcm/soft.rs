//! Portable constant-time GHASH.
//!
//! Follows BearSSL's `ghash_ctmul64` (Thomas Pornin): carry-less 64×64-bit
//! multiplication is emulated with four masked integer multiplications whose
//! "holes" absorb the carries (the only column that can overflow is the last
//! one, whose carry falls off the 64-bit word), and the high half of each
//! product is obtained by multiplying the bit-reversed operands. Integer
//! multiplication is constant time on every supported CPU, and nothing is
//! indexed by secret data.
//!
//! Field elements are handled in the bit-reflected form implied by GCM's byte
//! order: `y1` holds the first eight bytes big-endian, `y0` the last eight.

use crate::zeroize::zeroize_u64;

/// Precomputed hash key material: `h0`, `h1`, their bit reversals and the
/// Karatsuba sums.
pub(crate) struct Key {
    h: [u64; 6],
}

impl Drop for Key {
    fn drop(&mut self) {
        zeroize_u64(&mut self.h);
    }
}

#[inline]
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Low 64 bits of the carry-less product of `x` and `y`.
#[inline]
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let x0 = x & M0;
    let x1 = x & M1;
    let x2 = x & M2;
    let x3 = x & M3;
    let y0 = y & M0;
    let y1 = y & M1;
    let y2 = y & M2;
    let y3 = y & M3;
    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

#[inline]
fn rev64(x: u64) -> u64 {
    x.reverse_bits()
}

impl Key {
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        let h1 = be64(&h[..8]);
        let h0 = be64(&h[8..]);
        let h0r = rev64(h0);
        let h1r = rev64(h1);
        Self {
            h: [h0, h1, h0r, h1r, h0 ^ h1, h0r ^ h1r],
        }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into the accumulator `y`.
    pub(crate) fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        let [h0, h1, h0r, h1r, h2, h2r] = self.h;
        let mut y1 = be64(&y[..8]);
        let mut y0 = be64(&y[8..]);
        for block in blocks.as_chunks::<16>().0 {
            y1 ^= be64(&block[..8]);
            y0 ^= be64(&block[8..]);

            let y0r = rev64(y0);
            let y1r = rev64(y1);
            let y2 = y0 ^ y1;
            let y2r = y0r ^ y1r;

            let z0 = bmul64(y0, h0);
            let z1 = bmul64(y1, h1);
            let mut z2 = bmul64(y2, h2);
            let mut z0h = bmul64(y0r, h0r);
            let mut z1h = bmul64(y1r, h1r);
            let mut z2h = bmul64(y2r, h2r);
            z2 ^= z0 ^ z1;
            z2h ^= z0h ^ z1h;
            z0h = rev64(z0h) >> 1;
            z1h = rev64(z1h) >> 1;
            z2h = rev64(z2h) >> 1;

            // 256-bit product, least significant limb first.
            let mut v0 = z0;
            let mut v1 = z0h ^ z2;
            let mut v2 = z1 ^ z2h;
            let mut v3 = z1h;

            // Multiply by x (the reflected product is short by one bit), then
            // reduce modulo x^128 + x^127 + x^126 + x^121 + 1.
            v3 = (v3 << 1) | (v2 >> 63);
            v2 = (v2 << 1) | (v1 >> 63);
            v1 = (v1 << 1) | (v0 >> 63);
            v0 <<= 1;

            v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
            v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
            v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
            v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

            y0 = v2;
            y1 = v3;
        }
        y[..8].copy_from_slice(&y1.to_be_bytes());
        y[8..].copy_from_slice(&y0.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference carry-less multiplication (bit-serial).
    fn clmul_ref(x: u64, y: u64) -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for i in 0..64 {
            if (y >> i) & 1 == 1 {
                lo ^= x << i;
                if i > 0 {
                    hi ^= x >> (64 - i);
                }
            }
        }
        (lo, hi)
    }

    #[test]
    fn bmul64_matches_reference() {
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let x = s;
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let y = s;
            let (lo, hi) = clmul_ref(x, y);
            assert_eq!(bmul64(x, y), lo);
            assert_eq!(rev64(bmul64(rev64(x), rev64(y))) >> 1, hi);
        }
        assert_eq!(bmul64(u64::MAX, u64::MAX), clmul_ref(u64::MAX, u64::MAX).0);
    }
}
