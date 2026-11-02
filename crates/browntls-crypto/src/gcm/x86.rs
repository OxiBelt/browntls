//! x86-64 GHASH with PCLMULQDQ.
//!
//! The computation runs in the POLYVAL representation (RFC 8452 Appendix A):
//! every block is byte-reversed so that GCM's bit-reflected field element
//! becomes an ordinary little-endian polynomial, and the hash key is
//! pre-multiplied by `x` so that a Montgomery-style reduction by `x^128`
//! (two carry-less multiplications by `0xc2 << 56`) yields exactly the GHASH
//! product. Eight blocks are multiplied by `H^8 .. H^1` with Karatsuba (three
//! multiplications per block) and the 256-bit products are summed before a
//! single reduction.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use crate::cpu::features;
use crate::zeroize::zeroize_bytes;

/// Precomputed powers of the hash key.
///
/// A value can only be constructed by [`Key::new`], which checks that
/// PCLMULQDQ and SSE4.1 are present; this invariant makes the
/// `#[target_feature]` calls sound.
pub(crate) struct Key {
    /// `h[i]` holds `H^(8 - i)` in POLYVAL form.
    pub(super) h: [[u8; 16]; 8],
    /// `hx[i]` holds the XOR of both 64-bit halves of `h[i]` in its low half
    /// (Karatsuba middle operand).
    pub(super) hx: [[u8; 16]; 8],
}

impl Drop for Key {
    fn drop(&mut self) {
        for b in self.h.iter_mut().chain(self.hx.iter_mut()) {
            zeroize_bytes(b);
        }
    }
}

impl Key {
    /// Precomputes the key powers from the GCM hash subkey `h`.
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        let f = features();
        assert!(
            f.x86_pclmulqdq() && f.x86_sse41(),
            "PCLMULQDQ backend selected without CPU support"
        );
        let h1 = super::polyval_key(h);
        // SAFETY: PCLMULQDQ and SSE4.1 support was just verified.
        unsafe { powers_impl(&h1) }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into the accumulator `y`.
    pub(crate) fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        // SAFETY: `Key::new` verified PCLMULQDQ and SSE4.1 support.
        unsafe { update_impl(self, y, blocks) }
    }
}

#[inline]
#[target_feature(enable = "sse2")]
pub(super) fn load(b: &[u8; 16]) -> __m128i {
    // SAFETY: `b` references 16 readable bytes; the unaligned load reads
    // exactly those bytes.
    unsafe { _mm_loadu_si128(b.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "sse2")]
pub(super) fn store(b: &mut [u8; 16], v: __m128i) {
    // SAFETY: `b` is an exclusive reference to 16 writable bytes; the
    // unaligned store writes exactly those bytes.
    unsafe { _mm_storeu_si128(b.as_mut_ptr().cast(), v) }
}

/// Mask for `pshufb` that reverses the sixteen bytes of a register.
#[inline]
#[target_feature(enable = "ssse3")]
pub(super) fn bswap_mask() -> __m128i {
    _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
}

/// Swaps the two 64-bit halves.
#[inline]
#[target_feature(enable = "sse2")]
pub(super) fn swap_halves(x: __m128i) -> __m128i {
    _mm_shuffle_epi32(x, 0x4E)
}

/// Accumulates the three Karatsuba partial products of `x * h` into
/// `(lo, mid, hi)`; `hx` is the pre-XORed middle operand of `h`.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
pub(super) fn karatsuba(x: __m128i, h: __m128i, hx: __m128i, acc: &mut [__m128i; 3]) {
    let xx = _mm_xor_si128(x, swap_halves(x));
    acc[0] = _mm_xor_si128(acc[0], _mm_clmulepi64_si128(x, h, 0x00));
    acc[1] = _mm_xor_si128(acc[1], _mm_clmulepi64_si128(xx, hx, 0x00));
    acc[2] = _mm_xor_si128(acc[2], _mm_clmulepi64_si128(x, h, 0x11));
}

/// Combines the Karatsuba accumulators into the 256-bit product and reduces
/// it by `x^128` modulo `x^128 + x^127 + x^126 + x^121 + 1`.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
pub(super) fn reduce(acc: [__m128i; 3]) -> __m128i {
    let [lo, mid, hi] = acc;
    let mid = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
    let lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    let hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
    #[allow(clippy::cast_possible_wrap)]
    let poly = _mm_set_epi64x(0xc200_0000_0000_0000u64 as i64, 0);
    // Two Montgomery steps of 64 bits each (Gueron): clear the low qword,
    // then the next one; what remains above x^128 is the result.
    let t = _mm_clmulepi64_si128(lo, poly, 0x10);
    let lo = _mm_xor_si128(swap_halves(lo), t);
    let t = _mm_clmulepi64_si128(lo, poly, 0x10);
    let lo = _mm_xor_si128(swap_halves(lo), t);
    _mm_xor_si128(hi, lo)
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
fn mul(a: __m128i, b: __m128i) -> __m128i {
    let mut acc = [_mm_setzero_si128(); 3];
    karatsuba(a, b, _mm_xor_si128(b, swap_halves(b)), &mut acc);
    reduce(acc)
}

#[target_feature(enable = "pclmulqdq,sse4.1")]
fn powers_impl(h1: &[u8; 16]) -> Key {
    let h1v = load(h1);
    let mut pow = [h1v; 8];
    for i in 1..8 {
        pow[i] = mul(pow[i - 1], h1v);
    }
    let mut key = Key {
        h: [[0; 16]; 8],
        hx: [[0; 16]; 8],
    };
    for i in 0..8 {
        let p = pow[7 - i];
        store(&mut key.h[i], p);
        store(&mut key.hx[i], _mm_xor_si128(p, swap_halves(p)));
    }
    key
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse4.1")]
pub(super) fn load_powers(key: &Key) -> ([__m128i; 8], [__m128i; 8]) {
    (
        core::array::from_fn(|i| load(&key.h[i])),
        core::array::from_fn(|i| load(&key.hx[i])),
    )
}

/// Multiplies `n <= 8` blocks by `H^n .. H^1`, adds `acc` to the first and
/// returns the reduced sum.
#[inline]
#[target_feature(enable = "pclmulqdq,sse4.1")]
pub(super) fn ghash_blocks(
    h: &[__m128i; 8],
    hx: &[__m128i; 8],
    mask: __m128i,
    mut acc: __m128i,
    blocks: &[[u8; 16]],
) -> __m128i {
    let n = blocks.len();
    debug_assert!(n <= 8);
    let mut sum = [_mm_setzero_si128(); 3];
    for (i, blk) in blocks.iter().enumerate() {
        let x = _mm_xor_si128(_mm_shuffle_epi8(load(blk), mask), acc);
        acc = _mm_setzero_si128();
        karatsuba(x, h[8 - n + i], hx[8 - n + i], &mut sum);
    }
    reduce(sum)
}

#[target_feature(enable = "pclmulqdq,sse4.1")]
fn update_impl(key: &Key, y: &mut [u8; 16], blocks: &[u8]) {
    let mask = bswap_mask();
    let (h, hx) = load_powers(key);
    let mut acc = _mm_shuffle_epi8(load(y), mask);
    let blocks = blocks.as_chunks::<16>().0;
    let (groups, rest) = blocks.as_chunks::<8>();
    for g in groups {
        acc = ghash_blocks(&h, &hx, mask, acc, g);
    }
    if !rest.is_empty() {
        acc = ghash_blocks(&h, &hx, mask, acc, rest);
    }
    store(y, _mm_shuffle_epi8(acc, mask));
}
