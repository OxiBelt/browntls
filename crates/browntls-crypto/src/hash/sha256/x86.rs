//! SHA-256 with the x86-64 SHA extensions (`SHA256RNDS2`, `SHA256MSG1`,
//! `SHA256MSG2`).
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi32,
    _mm_set_epi64x, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
    _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_storeu_si128,
};

use super::{K, soft};
use crate::cpu::{self, Features};

pub(super) fn available(f: Features) -> bool {
    f.x86_sha() && f.x86_ssse3() && f.x86_sse41()
}

pub(super) fn v3_available(f: Features) -> bool {
    f.x86_v3()
}

/// Compresses `blocks` with the x86-64-v3 code (AVX2 message schedule for
/// two blocks at a time, BMI2 scalar rounds), or with [`soft`] if
/// unavailable.
pub(super) fn compress_v3(state: &mut [u32; 8], blocks: &[u8]) {
    if v3_available(cpu::features()) {
        // SAFETY: AVX2, BMI1 and BMI2 (x86-64-v3) were detected at run time.
        unsafe { v3::compress(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}

/// Compresses `blocks` with SHA-NI, or with [`soft`] if unavailable.
pub(super) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    if available(cpu::features()) {
        // SAFETY: SHA, SSSE3 and SSE4.1 were detected at run time.
        unsafe { compress_sha(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}

/// `K[4i..4i+4]` as a vector (element 0 = `K[4i]`).
#[target_feature(enable = "sse2")]
#[inline]
fn k4(i: usize) -> __m128i {
    _mm_set_epi32(
        K[4 * i + 3].cast_signed(),
        K[4 * i + 2].cast_signed(),
        K[4 * i + 1].cast_signed(),
        K[4 * i].cast_signed(),
    )
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn compress_sha(state: &mut [u32; 8], blocks: &[u8]) {
    // Byte-swaps each 32-bit word (big-endian message words).
    let bswap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);

    let [s_lo, s_hi] = state.as_chunks_mut::<4>().0 else {
        return;
    };
    // SAFETY: `s_lo` is 16 readable bytes; unaligned loads are allowed.
    let dcba = unsafe { _mm_loadu_si128(s_lo.as_ptr().cast()) };
    // SAFETY: `s_hi` is 16 readable bytes.
    let hgfe = unsafe { _mm_loadu_si128(s_hi.as_ptr().cast()) };
    // SHA256RNDS2 wants {A,B,E,F} and {C,D,G,H} (element 3 first).
    let cdab = _mm_shuffle_epi32::<0xB1>(dcba);
    let efgh = _mm_shuffle_epi32::<0x1B>(hgfe);
    let mut abef = _mm_alignr_epi8::<8>(cdab, efgh);
    let mut cdgh = _mm_blend_epi16::<0xF0>(efgh, cdab);

    for block in blocks.as_chunks::<64>().0 {
        let abef_save = abef;
        let cdgh_save = cdgh;
        let words = block.as_chunks::<16>().0;
        let mut w: [__m128i; 4] = core::array::from_fn(|i| {
            // SAFETY: `words[i]` is 16 readable bytes.
            let m = unsafe { _mm_loadu_si128(words[i].as_ptr().cast()) };
            _mm_shuffle_epi8(m, bswap)
        });

        // Quad-round `i` processes W[4i..4i+4] (held in `w[i % 4]`) and
        // advances the message schedule for later quads.
        macro_rules! quad {
            ($i:literal, $cur:literal, $next:literal, $prev:literal) => {
                let mut wk = _mm_add_epi32(w[$cur], k4($i));
                cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                if $i >= 3 && $i <= 14 {
                    // W[4(i+1)..] = msg2(msg1-part + W[4i-3..4i+1], W[4i..]).
                    let t = _mm_alignr_epi8::<4>(w[$cur], w[$prev]);
                    w[$next] = _mm_add_epi32(w[$next], t);
                    w[$next] = _mm_sha256msg2_epu32(w[$next], w[$cur]);
                }
                wk = _mm_shuffle_epi32::<0x0E>(wk);
                abef = _mm_sha256rnds2_epu32(abef, cdgh, wk);
                if $i >= 1 && $i <= 12 {
                    w[$prev] = _mm_sha256msg1_epu32(w[$prev], w[$cur]);
                }
            };
        }
        quad!(0, 0, 1, 3);
        quad!(1, 1, 2, 0);
        quad!(2, 2, 3, 1);
        quad!(3, 3, 0, 2);
        quad!(4, 0, 1, 3);
        quad!(5, 1, 2, 0);
        quad!(6, 2, 3, 1);
        quad!(7, 3, 0, 2);
        quad!(8, 0, 1, 3);
        quad!(9, 1, 2, 0);
        quad!(10, 2, 3, 1);
        quad!(11, 3, 0, 2);
        quad!(12, 0, 1, 3);
        quad!(13, 1, 2, 0);
        quad!(14, 2, 3, 1);
        quad!(15, 3, 0, 2);

        abef = _mm_add_epi32(abef, abef_save);
        cdgh = _mm_add_epi32(cdgh, cdgh_save);
    }

    let feba = _mm_shuffle_epi32::<0x1B>(abef);
    let dchg = _mm_shuffle_epi32::<0xB1>(cdgh);
    let dcba = _mm_blend_epi16::<0xF0>(feba, dchg);
    let hgfe = _mm_alignr_epi8::<8>(dchg, feba);
    // SAFETY: `s_lo` is 16 writable bytes; unaligned stores are allowed.
    unsafe { _mm_storeu_si128(s_lo.as_mut_ptr().cast(), dcba) };
    // SAFETY: `s_hi` is 16 writable bytes.
    unsafe { _mm_storeu_si128(s_hi.as_mut_ptr().cast(), hgfe) };
}

mod v3 {
    use core::arch::x86_64::{
        __m256i, _mm_loadu_si128, _mm_storeu_si128, _mm256_add_epi32, _mm256_alignr_epi8,
        _mm256_blend_epi32, _mm256_broadcastsi128_si256, _mm256_castsi128_si256,
        _mm256_castsi256_si128, _mm256_extracti128_si256, _mm256_inserti128_si256, _mm256_or_si256,
        _mm256_setr_epi8, _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_shuffle_epi32,
        _mm256_slli_epi32, _mm256_srli_epi32, _mm256_xor_si256,
    };

    use super::super::{K, soft};

    #[target_feature(enable = "avx2,bmi1,bmi2")]
    pub(super) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
        let mut chunks = blocks.as_chunks::<64>().0;
        let mut wk = [[0u32; 64]; 2];
        while let Some((b0, rest)) = chunks.split_first() {
            // Schedule two blocks at once (a single last block is scheduled
            // twice and the duplicate discarded).
            let (b1, rest, two) = match rest.split_first() {
                Some((b1, rest)) => (b1, rest, true),
                None => (b0, rest, false),
            };
            schedule(b0, b1, &mut wk);
            soft::rounds(state, &wk[0]);
            if two {
                soft::rounds(state, &wk[1]);
            }
            chunks = rest;
        }
        // The schedule is derived from the (possibly secret) message.
        crate::zeroize::zeroize_u32(wk.as_flattened_mut());
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn ror<const R: i32, const L: i32>(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_srli_epi32::<R>(x), _mm256_slli_epi32::<L>(x))
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn sig0(x: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(ror::<7, 25>(x), ror::<18, 14>(x)),
            _mm256_srli_epi32::<3>(x),
        )
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn sig1(x: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(ror::<17, 15>(x), ror::<19, 13>(x)),
            _mm256_srli_epi32::<10>(x),
        )
    }

    /// Computes `W[t] + K[t]` for blocks `b0` (into `wk[0]`) and `b1` (into
    /// `wk[1]`). Vector `x[k]` holds `W[4k..4k+4]` of `b0` in its low 128-bit
    /// half and of `b1` in its high half.
    #[target_feature(enable = "avx2")]
    fn schedule(b0: &[u8; 64], b1: &[u8; 64], wk: &mut [[u32; 64]; 2]) {
        let bswap = _mm256_setr_epi8(
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10,
            9, 8, 15, 14, 13, 12,
        );
        let (c0, c1) = (b0.as_chunks::<16>().0, b1.as_chunks::<16>().0);
        let mut x = [_mm256_setzero_si256(); 16];
        for k in 0..4 {
            // SAFETY: `c0[k]` and `c1[k]` are 16 readable bytes each.
            let lo = unsafe { _mm_loadu_si128(c0[k].as_ptr().cast()) };
            // SAFETY: as above.
            let hi = unsafe { _mm_loadu_si128(c1[k].as_ptr().cast()) };
            let v = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(lo), hi);
            x[k] = _mm256_shuffle_epi8(v, bswap);
        }
        for k in 4..16 {
            // W[t-15..t-12] and W[t-7..t-4] for t = 4k.
            let w15 = _mm256_alignr_epi8::<4>(x[k - 3], x[k - 4]);
            let w7 = _mm256_alignr_epi8::<4>(x[k - 1], x[k - 2]);
            let p = _mm256_add_epi32(_mm256_add_epi32(x[k - 4], sig0(w15)), w7);
            // Words 0, 1: add sig1(W[t-2]), sig1(W[t-1]).
            let s1 = sig1(_mm256_shuffle_epi32::<0xEE>(x[k - 1]));
            let p = _mm256_blend_epi32::<0x33>(p, _mm256_add_epi32(p, s1));
            // Words 2, 3: add sig1(W[t]), sig1(W[t+1]) just computed.
            let s1 = sig1(_mm256_shuffle_epi32::<0x44>(p));
            x[k] = _mm256_blend_epi32::<0xCC>(p, _mm256_add_epi32(p, s1));
        }
        let [wk0, wk1] = wk;
        let quads = wk0
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(wk1.as_chunks_mut::<4>().0)
            .zip(K.as_chunks::<4>().0);
        for (((d0, d1), kq), xk) in quads.zip(x) {
            // SAFETY: `kq` is 16 readable bytes.
            let kv = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(kq.as_ptr().cast()) });
            let v = _mm256_add_epi32(xk, kv);
            let (lo, hi) = (_mm256_castsi256_si128(v), _mm256_extracti128_si256::<1>(v));
            // SAFETY: `d0` is 16 writable bytes.
            unsafe { _mm_storeu_si128(d0.as_mut_ptr().cast(), lo) };
            // SAFETY: `d1` is 16 writable bytes.
            unsafe { _mm_storeu_si128(d1.as_mut_ptr().cast(), hi) };
        }
    }
}
