//! SHA-512 for x86-64-v3: AVX2 message schedule for two blocks at a time,
//! scalar rounds compiled with BMI2 (`RORX`) and BMI1 (`ANDN`).
//!
//! The x86 SHA512 extension (`VSHA512RNDS2` etc.) is not implemented: it
//! could not be executed on the available hardware or emulator.
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m256i, _mm_loadu_si128, _mm_storeu_si128, _mm256_add_epi64, _mm256_alignr_epi8,
    _mm256_broadcastsi128_si256, _mm256_castsi128_si256, _mm256_castsi256_si128,
    _mm256_extracti128_si256, _mm256_inserti128_si256, _mm256_or_si256, _mm256_setr_epi8,
    _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_slli_epi64, _mm256_srli_epi64,
    _mm256_xor_si256,
};

use super::{K, soft};
use crate::cpu::{self, Features};

pub(super) fn available(f: Features) -> bool {
    f.x86_v3()
}

/// Compresses `blocks` with the x86-64-v3 code, or with [`soft`] if
/// unavailable.
pub(super) fn compress(state: &mut [u64; 8], blocks: &[u8]) {
    if available(cpu::features()) {
        // SAFETY: AVX2, BMI1 and BMI2 (x86-64-v3) were detected at run time.
        unsafe { compress_v3(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
fn compress_v3(state: &mut [u64; 8], blocks: &[u8]) {
    let mut chunks = blocks.as_chunks::<128>().0;
    let mut wk = [[0u64; 80]; 2];
    while let Some((b0, rest)) = chunks.split_first() {
        // Schedule two blocks at once (the single last block is scheduled
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
    crate::zeroize::zeroize_u64(wk.as_flattened_mut());
}

#[target_feature(enable = "avx2")]
#[inline]
fn ror<const R: i32, const L: i32>(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_srli_epi64::<R>(x), _mm256_slli_epi64::<L>(x))
}

#[target_feature(enable = "avx2")]
#[inline]
fn sig0(x: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(ror::<1, 63>(x), ror::<8, 56>(x)),
        _mm256_srli_epi64::<7>(x),
    )
}

#[target_feature(enable = "avx2")]
#[inline]
fn sig1(x: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(ror::<19, 45>(x), ror::<61, 3>(x)),
        _mm256_srli_epi64::<6>(x),
    )
}

/// Computes `W[t] + K[t]` for blocks `b0` (into `wk[0]`) and `b1` (into
/// `wk[1]`). Vector `x[k]` holds `W[2k], W[2k+1]` of `b0` in its low 128-bit
/// half and of `b1` in its high half.
#[target_feature(enable = "avx2")]
fn schedule(b0: &[u8; 128], b1: &[u8; 128], wk: &mut [[u64; 80]; 2]) {
    let bswap = _mm256_setr_epi8(
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13,
        12, 11, 10, 9, 8,
    );
    let (c0, c1) = (b0.as_chunks::<16>().0, b1.as_chunks::<16>().0);
    let mut x = [_mm256_setzero_si256(); 40];
    for k in 0..8 {
        // SAFETY: `c0[k]` and `c1[k]` are 16 readable bytes each.
        let lo = unsafe { _mm_loadu_si128(c0[k].as_ptr().cast()) };
        // SAFETY: as above.
        let hi = unsafe { _mm_loadu_si128(c1[k].as_ptr().cast()) };
        let v = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(lo), hi);
        x[k] = _mm256_shuffle_epi8(v, bswap);
    }
    for k in 8..40 {
        let w15 = _mm256_alignr_epi8::<8>(x[k - 7], x[k - 8]);
        let w7 = _mm256_alignr_epi8::<8>(x[k - 3], x[k - 4]);
        x[k] = _mm256_add_epi64(
            _mm256_add_epi64(x[k - 8], sig0(w15)),
            _mm256_add_epi64(w7, sig1(x[k - 1])),
        );
    }
    let [wk0, wk1] = wk;
    let pairs = wk0
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(wk1.as_chunks_mut::<2>().0)
        .zip(K.as_chunks::<2>().0);
    for (((d0, d1), kp), xk) in pairs.zip(x) {
        // SAFETY: `kp` is 16 readable bytes.
        let kv = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(kp.as_ptr().cast()) });
        let v = _mm256_add_epi64(xk, kv);
        let (lo, hi) = (_mm256_castsi256_si128(v), _mm256_extracti128_si256::<1>(v));
        // SAFETY: `d0` is 16 writable bytes.
        unsafe { _mm_storeu_si128(d0.as_mut_ptr().cast(), lo) };
        // SAFETY: `d1` is 16 writable bytes.
        unsafe { _mm_storeu_si128(d1.as_mut_ptr().cast(), hi) };
    }
}
