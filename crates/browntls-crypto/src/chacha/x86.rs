//! x86-64 ChaCha20 (AVX2: 8 and 4 blocks; AVX-512: 16 blocks) and the
//! BMI2/ADX build of the radix-2^64 Poly1305 code.
//!
//! The ChaCha state is word-sliced: vector `x[i]` holds word `i` of 4, 8 or 16
//! consecutive blocks, one block per 32-bit lane. After the rounds the words
//! are transposed back into block order with unpack/permute shuffles.
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m128i, __m256i, __m512i, _mm_add_epi32, _mm_loadu_si128, _mm_or_si128, _mm_set1_epi32,
    _mm_setr_epi8, _mm_setr_epi32, _mm_shuffle_epi8, _mm_slli_epi32, _mm_srli_epi32,
    _mm_storeu_si128, _mm_unpackhi_epi32, _mm_unpackhi_epi64, _mm_unpacklo_epi32,
    _mm_unpacklo_epi64, _mm_xor_si128, _mm256_add_epi32, _mm256_broadcastsi128_si256,
    _mm256_loadu_si256, _mm256_or_si256, _mm256_permute2x128_si256, _mm256_set1_epi32,
    _mm256_setr_epi32, _mm256_shuffle_epi8, _mm256_slli_epi32, _mm256_srli_epi32,
    _mm256_storeu_si256, _mm256_unpackhi_epi32, _mm256_unpackhi_epi64, _mm256_unpacklo_epi32,
    _mm256_unpacklo_epi64, _mm256_xor_si256, _mm512_add_epi32, _mm512_loadu_si512,
    _mm512_rol_epi32, _mm512_set1_epi32, _mm512_setr_epi32, _mm512_shuffle_i32x4,
    _mm512_storeu_si512, _mm512_unpackhi_epi32, _mm512_unpackhi_epi64, _mm512_unpacklo_epi32,
    _mm512_unpacklo_epi64, _mm512_xor_si512,
};

use super::poly1305::State;
use super::soft::{self, BLOCK};
use crate::cpu::features;
use crate::zeroize::Zeroize;

/// Reinterprets a state word as the signed lane type the intrinsics take.
#[inline(always)]
fn lane(w: u32) -> i32 {
    i32::from_ne_bytes(w.to_ne_bytes())
}

/// Byte-shuffle masks for the 16- and 8-bit left rotations of each 32-bit lane.
#[target_feature(enable = "avx2")]
#[inline]
fn rot_masks() -> (__m128i, __m128i) {
    (
        _mm_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13),
        _mm_setr_epi8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14),
    )
}

mod xmm {
    use super::{
        __m128i, _mm_add_epi32, _mm_or_si128, _mm_shuffle_epi8, _mm_slli_epi32, _mm_srli_epi32,
        _mm_xor_si128, rot_masks,
    };

    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn add(a: __m128i, b: __m128i) -> __m128i {
        _mm_add_epi32(a, b)
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn xor(a: __m128i, b: __m128i) -> __m128i {
        _mm_xor_si128(a, b)
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn r16(a: __m128i) -> __m128i {
        _mm_shuffle_epi8(a, rot_masks().0)
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn r12(a: __m128i) -> __m128i {
        _mm_or_si128(_mm_slli_epi32::<12>(a), _mm_srli_epi32::<20>(a))
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn r8(a: __m128i) -> __m128i {
        _mm_shuffle_epi8(a, rot_masks().1)
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn r7(a: __m128i) -> __m128i {
        _mm_or_si128(_mm_slli_epi32::<7>(a), _mm_srli_epi32::<25>(a))
    }
}

mod ymm {
    use super::{
        __m256i, _mm256_add_epi32, _mm256_broadcastsi128_si256, _mm256_or_si256,
        _mm256_shuffle_epi8, _mm256_slli_epi32, _mm256_srli_epi32, _mm256_xor_si256, rot_masks,
    };

    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn add(a: __m256i, b: __m256i) -> __m256i {
        _mm256_add_epi32(a, b)
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn xor(a: __m256i, b: __m256i) -> __m256i {
        _mm256_xor_si256(a, b)
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn r16(a: __m256i) -> __m256i {
        _mm256_shuffle_epi8(a, _mm256_broadcastsi128_si256(rot_masks().0))
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn r12(a: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32::<12>(a), _mm256_srli_epi32::<20>(a))
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn r8(a: __m256i) -> __m256i {
        _mm256_shuffle_epi8(a, _mm256_broadcastsi128_si256(rot_masks().1))
    }
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) fn r7(a: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32::<7>(a), _mm256_srli_epi32::<25>(a))
    }
}

mod zmm {
    use super::{__m512i, _mm512_add_epi32, _mm512_rol_epi32, _mm512_xor_si512};

    #[target_feature(enable = "avx512f")]
    #[inline]
    pub(super) fn add(a: __m512i, b: __m512i) -> __m512i {
        _mm512_add_epi32(a, b)
    }
    #[target_feature(enable = "avx512f")]
    #[inline]
    pub(super) fn xor(a: __m512i, b: __m512i) -> __m512i {
        _mm512_xor_si512(a, b)
    }
    #[target_feature(enable = "avx512f")]
    #[inline]
    pub(super) fn r16(a: __m512i) -> __m512i {
        _mm512_rol_epi32::<16>(a)
    }
    #[target_feature(enable = "avx512f")]
    #[inline]
    pub(super) fn r12(a: __m512i) -> __m512i {
        _mm512_rol_epi32::<12>(a)
    }
    #[target_feature(enable = "avx512f")]
    #[inline]
    pub(super) fn r8(a: __m512i) -> __m512i {
        _mm512_rol_epi32::<8>(a)
    }
    #[target_feature(enable = "avx512f")]
    #[inline]
    pub(super) fn r7(a: __m512i) -> __m512i {
        _mm512_rol_epi32::<7>(a)
    }
}

/// Four blocks of keystream; `out[4 * j + g]` holds words `4g..4g+4` of block `j`.
#[target_feature(enable = "avx2")]
fn core4(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [__m128i; 16] {
    use xmm::{add, r7, r8, r12, r16, xor};
    let init = soft::initial_state(key, counter, nonce);
    let mut s = [_mm_set1_epi32(0); 16];
    for (v, w) in s.iter_mut().zip(init) {
        *v = _mm_set1_epi32(lane(w));
    }
    s[12] = _mm_add_epi32(s[12], _mm_setr_epi32(0, 1, 2, 3));
    let mut x = s;
    chacha_rounds!(x, add, xor, r16, r12, r8, r7);
    let mut out = x;
    for g in 0..4 {
        let v: [__m128i; 4] = core::array::from_fn(|i| add(x[4 * g + i], s[4 * g + i]));
        let t0 = _mm_unpacklo_epi32(v[0], v[1]);
        let t1 = _mm_unpackhi_epi32(v[0], v[1]);
        let t2 = _mm_unpacklo_epi32(v[2], v[3]);
        let t3 = _mm_unpackhi_epi32(v[2], v[3]);
        out[g] = _mm_unpacklo_epi64(t0, t2);
        out[4 + g] = _mm_unpackhi_epi64(t0, t2);
        out[8 + g] = _mm_unpacklo_epi64(t1, t3);
        out[12 + g] = _mm_unpackhi_epi64(t1, t3);
    }
    out
}

/// Eight blocks of keystream; `out[2 * j + h]` holds words `8h..8h+8` of block `j`.
#[target_feature(enable = "avx2")]
fn core8(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [__m256i; 16] {
    use ymm::{add, r7, r8, r12, r16, xor};
    let init = soft::initial_state(key, counter, nonce);
    let mut s = [_mm256_set1_epi32(0); 16];
    for (v, w) in s.iter_mut().zip(init) {
        *v = _mm256_set1_epi32(lane(w));
    }
    s[12] = _mm256_add_epi32(s[12], _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
    let mut x = s;
    chacha_rounds!(x, add, xor, r16, r12, r8, r7);
    let mut out = x;
    for h in 0..2 {
        let v: [__m256i; 8] = core::array::from_fn(|i| add(x[8 * h + i], s[8 * h + i]));
        // Per 128-bit half: interleave words pairwise, then in fours.
        let t0 = _mm256_unpacklo_epi32(v[0], v[1]);
        let t1 = _mm256_unpackhi_epi32(v[0], v[1]);
        let t2 = _mm256_unpacklo_epi32(v[2], v[3]);
        let t3 = _mm256_unpackhi_epi32(v[2], v[3]);
        let t4 = _mm256_unpacklo_epi32(v[4], v[5]);
        let t5 = _mm256_unpackhi_epi32(v[4], v[5]);
        let t6 = _mm256_unpacklo_epi32(v[6], v[7]);
        let t7 = _mm256_unpackhi_epi32(v[6], v[7]);
        // u[m] (low half) = words 0..4 of block m, (high half) of block m + 4.
        let u = [
            _mm256_unpacklo_epi64(t0, t2),
            _mm256_unpackhi_epi64(t0, t2),
            _mm256_unpacklo_epi64(t1, t3),
            _mm256_unpackhi_epi64(t1, t3),
        ];
        let w = [
            _mm256_unpacklo_epi64(t4, t6),
            _mm256_unpackhi_epi64(t4, t6),
            _mm256_unpacklo_epi64(t5, t7),
            _mm256_unpackhi_epi64(t5, t7),
        ];
        for m in 0..4 {
            out[2 * m + h] = _mm256_permute2x128_si256::<0x20>(u[m], w[m]);
            out[2 * (m + 4) + h] = _mm256_permute2x128_si256::<0x31>(u[m], w[m]);
        }
    }
    out
}

/// Sixteen blocks of keystream; `out[j]` holds block `j`.
#[target_feature(enable = "avx512f")]
fn core16(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [__m512i; 16] {
    use zmm::{add, r7, r8, r12, r16, xor};
    let init = soft::initial_state(key, counter, nonce);
    let mut s = [_mm512_set1_epi32(0); 16];
    for (v, w) in s.iter_mut().zip(init) {
        *v = _mm512_set1_epi32(lane(w));
    }
    s[12] = _mm512_add_epi32(
        s[12],
        _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    );
    let mut x = s;
    chacha_rounds!(x, add, xor, r16, r12, r8, r7);
    for (v, i) in x.iter_mut().zip(s) {
        *v = add(*v, i);
    }
    // Step 1: within each 128-bit lane k, u[g][m] holds words 4g..4g+4 of
    // block 4k + m.
    let mut u = [[_mm512_set1_epi32(0); 4]; 4];
    for g in 0..4 {
        let v = &x[4 * g..4 * g + 4];
        let t0 = _mm512_unpacklo_epi32(v[0], v[1]);
        let t1 = _mm512_unpackhi_epi32(v[0], v[1]);
        let t2 = _mm512_unpacklo_epi32(v[2], v[3]);
        let t3 = _mm512_unpackhi_epi32(v[2], v[3]);
        u[g] = [
            _mm512_unpacklo_epi64(t0, t2),
            _mm512_unpackhi_epi64(t0, t2),
            _mm512_unpacklo_epi64(t1, t3),
            _mm512_unpackhi_epi64(t1, t3),
        ];
    }
    // Step 2: transpose the 4x4 matrix of 128-bit lanes for each m.
    let mut out = x;
    for m in 0..4 {
        let x0 = _mm512_shuffle_i32x4::<0x44>(u[0][m], u[1][m]);
        let x1 = _mm512_shuffle_i32x4::<0xee>(u[0][m], u[1][m]);
        let x2 = _mm512_shuffle_i32x4::<0x44>(u[2][m], u[3][m]);
        let x3 = _mm512_shuffle_i32x4::<0xee>(u[2][m], u[3][m]);
        out[m] = _mm512_shuffle_i32x4::<0x88>(x0, x2);
        out[4 + m] = _mm512_shuffle_i32x4::<0xdd>(x0, x2);
        out[8 + m] = _mm512_shuffle_i32x4::<0x88>(x1, x3);
        out[12 + m] = _mm512_shuffle_i32x4::<0xdd>(x1, x3);
    }
    out
}

#[target_feature(enable = "avx2")]
fn xor4(ks: &[__m128i; 16], data: &mut [u8; 4 * BLOCK]) {
    for (k, c) in ks.iter().zip(data.as_chunks_mut::<16>().0) {
        // SAFETY: `c` is a valid 16-byte buffer; unaligned load.
        let d = unsafe { _mm_loadu_si128(c.as_ptr().cast()) };
        let x = _mm_xor_si128(d, *k);
        // SAFETY: as above; unaligned store.
        unsafe { _mm_storeu_si128(c.as_mut_ptr().cast(), x) };
    }
}

#[target_feature(enable = "avx2")]
fn xor8(ks: &[__m256i; 16], data: &mut [u8; 8 * BLOCK]) {
    for (k, c) in ks.iter().zip(data.as_chunks_mut::<32>().0) {
        // SAFETY: `c` is a valid 32-byte buffer; unaligned load.
        let d = unsafe { _mm256_loadu_si256(c.as_ptr().cast()) };
        let x = _mm256_xor_si256(d, *k);
        // SAFETY: as above; unaligned store.
        unsafe { _mm256_storeu_si256(c.as_mut_ptr().cast(), x) };
    }
}

#[target_feature(enable = "avx512f")]
fn xor16(ks: &[__m512i; 16], data: &mut [u8; 16 * BLOCK]) {
    for (k, c) in ks.iter().zip(data.as_chunks_mut::<64>().0) {
        // SAFETY: `c` is a valid 64-byte buffer; unaligned load.
        let d = unsafe { _mm512_loadu_si512(c.as_ptr().cast()) };
        let x = _mm512_xor_si512(d, *k);
        // SAFETY: as above; unaligned store.
        unsafe { _mm512_storeu_si512(c.as_mut_ptr().cast(), x) };
    }
}

/// XORs a final chunk shorter than eight blocks: more than four blocks use
/// [`core8`], more than one [`core4`], and at most one block the portable
/// code.
#[target_feature(enable = "avx2")]
fn xor_tail(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    debug_assert!(data.len() < 8 * BLOCK);
    if data.len() > 4 * BLOCK {
        let mut buf = [0u8; 8 * BLOCK];
        xor8(&core8(key, counter, nonce), &mut buf);
        soft::xor_in_place(data, &buf);
        buf.zeroize();
    } else if data.len() > BLOCK {
        let mut buf = [0u8; 4 * BLOCK];
        xor4(&core4(key, counter, nonce), &mut buf);
        soft::xor_in_place(data, &buf);
        buf.zeroize();
    } else {
        soft::xor(key, counter, nonce, data);
    }
}

#[target_feature(enable = "avx2")]
fn xor_avx2_inner(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    let (chunks, tail) = data.as_chunks_mut::<{ 8 * BLOCK }>();
    let mut ctr = counter;
    for c in chunks {
        xor8(&core8(key, ctr, nonce), c);
        ctr = ctr.wrapping_add(8);
    }
    xor_tail(key, ctr, nonce, tail);
}

#[target_feature(enable = "avx512f,avx2")]
fn xor_avx512_inner(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    let (chunks, tail) = data.as_chunks_mut::<{ 16 * BLOCK }>();
    let mut ctr = counter;
    for c in chunks {
        xor16(&core16(key, ctr, nonce), c);
        ctr = ctr.wrapping_add(16);
    }
    if tail.len() > 8 * BLOCK {
        let mut buf = [0u8; 16 * BLOCK];
        xor16(&core16(key, ctr, nonce), &mut buf);
        soft::xor_in_place(tail, &buf);
        buf.zeroize();
    } else {
        xor_avx2_inner(key, ctr, nonce, tail);
    }
}

/// AVX2 ChaCha20; falls back to the portable code without x86-64-v3.
pub(super) fn xor_avx2(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    if features().x86_v3() {
        // SAFETY: AVX2 support (with OS YMM state) was detected at run time.
        unsafe { xor_avx2_inner(key, counter, nonce, data) }
    } else {
        soft::xor(key, counter, nonce, data);
    }
}

/// AVX-512 ChaCha20; falls back to AVX2 without AVX-512.
pub(super) fn xor_avx512(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    let f = features();
    if f.x86_v3() && f.x86_avx512() {
        // SAFETY: AVX-512F and AVX2 support (with OS ZMM/YMM state) were
        // detected at run time.
        unsafe { xor_avx512_inner(key, counter, nonce, data) }
    } else {
        xor_avx2(key, counter, nonce, data);
    }
}

#[target_feature(enable = "bmi2,adx")]
fn poly1305_blocks_bmi2_inner(state: &mut State, data: &[u8]) {
    state.blocks(data, 1);
}

/// Poly1305 block function compiled for BMI2 (`MULX`) and ADX.
pub(super) fn poly1305_blocks_bmi2(state: &mut State, data: &[u8]) {
    let f = features();
    if f.x86_bmi2() && f.x86_adx() {
        // SAFETY: BMI2 and ADX support was detected at run time.
        unsafe { poly1305_blocks_bmi2_inner(state, data) }
    } else {
        state.blocks(data, 1);
    }
}
