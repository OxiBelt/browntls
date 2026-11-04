//! x86-64 GHASH with VPCLMULQDQ on YMM registers: two blocks per register,
//! eight blocks per reduction using the same `H^8 .. H^1` powers as the XMM
//! backend; the per-lane 256-bit sums are folded together before one
//! reduction. Tails reuse the (inlined, VEX-encoded) XMM helpers.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use super::x86;
use crate::cpu::{Features, features};

/// Returns whether the CPU can run this backend: VPCLMULQDQ with AVX2 on
/// top of the XMM requirements.
pub(crate) fn supported(f: Features) -> bool {
    f.x86_vpclmulqdq() && f.x86_avx2() && f.x86_pclmulqdq() && f.x86_sse41()
}

/// Precomputed key powers for the YMM backend.
///
/// A value can only be constructed by [`Key::new`], which checks
/// [`supported`]; this invariant makes the `#[target_feature]` calls sound.
pub(crate) struct Key {
    inner: x86::Key,
}

impl Key {
    /// Precomputes the key powers from the GCM hash subkey `h`.
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        assert!(
            supported(features()),
            "VPCLMULQDQ backend selected without CPU support"
        );
        Self {
            inner: x86::Key::new(h),
        }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into the accumulator `y`.
    pub(crate) fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        // SAFETY: `Key::new` verified VPCLMULQDQ, AVX2, PCLMULQDQ and SSE4.1
        // support.
        unsafe { update_impl(&self.inner, y, blocks) }
    }
}

#[inline]
#[target_feature(enable = "avx")]
fn load256(b: &[[u8; 16]; 2]) -> __m256i {
    // SAFETY: `b` references 32 readable bytes; the unaligned load reads
    // exactly those bytes.
    unsafe { _mm256_loadu_si256(b.as_ptr().cast()) }
}

#[target_feature(enable = "vpclmulqdq,avx2,pclmulqdq,sse4.1")]
fn update_impl(key: &x86::Key, y: &mut [u8; 16], blocks: &[u8]) {
    let mask128 = x86::bswap_mask();
    let mask = _mm256_broadcastsi128_si256(mask128);
    let (h, hx) = x86::load_powers(key);
    // Lane 0 (low) of register `i` multiplies block `2i` by `H^(8-2i)`, lane 1
    // multiplies block `2i+1` by `H^(7-2i)`.
    let h256: [__m256i; 4] = core::array::from_fn(|i| _mm256_set_m128i(h[2 * i + 1], h[2 * i]));
    let hx256: [__m256i; 4] = core::array::from_fn(|i| _mm256_set_m128i(hx[2 * i + 1], hx[2 * i]));
    let mut acc = _mm_shuffle_epi8(x86::load(y), mask128);

    let blocks = blocks.as_chunks::<16>().0;
    let (groups, rest) = blocks.as_chunks::<8>();
    for g in groups {
        let pairs = g.as_chunks::<2>().0;
        let mut sum = [_mm256_setzero_si256(); 3];
        let mut carry = _mm256_zextsi128_si256(acc);
        for (pair, (h, hx)) in pairs.iter().zip(h256.iter().zip(&hx256)) {
            let x = _mm256_xor_si256(_mm256_shuffle_epi8(load256(pair), mask), carry);
            carry = _mm256_setzero_si256();
            let xx = _mm256_xor_si256(x, _mm256_shuffle_epi32(x, 0x4E));
            sum[0] = _mm256_xor_si256(sum[0], _mm256_clmulepi64_epi128(x, *h, 0x00));
            sum[1] = _mm256_xor_si256(sum[1], _mm256_clmulepi64_epi128(xx, *hx, 0x00));
            sum[2] = _mm256_xor_si256(sum[2], _mm256_clmulepi64_epi128(x, *h, 0x11));
        }
        let fold =
            |v: __m256i| _mm_xor_si128(_mm256_castsi256_si128(v), _mm256_extracti128_si256(v, 1));
        acc = x86::reduce([fold(sum[0]), fold(sum[1]), fold(sum[2])]);
    }
    if !rest.is_empty() {
        acc = x86::ghash_blocks(&h, &hx, mask128, acc, rest);
    }
    x86::store(y, _mm_shuffle_epi8(acc, mask128));
}
