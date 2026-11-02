//! x86-64 VAES backend: two blocks per YMM register, eight registers
//! (sixteen blocks) per iteration. Tails use the XMM AES-NI helpers, which
//! are inlined here and therefore VEX-encoded (no SSE/AVX transition).
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use super::RoundKeys;
use super::x86;
use crate::cpu::features;

/// Round keys for the VAES backend.
///
/// A value can only be constructed by [`Key::new`], which checks that VAES,
/// AVX2, AES-NI and SSE4.1 are present; this invariant makes the
/// `#[target_feature]` calls below sound.
pub(crate) struct Key {
    rk: RoundKeys,
}

impl Key {
    pub(crate) fn new(rk: RoundKeys) -> Self {
        let f = features();
        assert!(
            f.x86_vaes() && f.x86_avx2() && f.x86_aes() && f.x86_sse41(),
            "VAES backend selected without CPU support"
        );
        Self { rk }
    }

    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        // SAFETY: `Key::new` verified VAES, AVX2, AES-NI and SSE4.1 support.
        unsafe { encrypt_blocks_impl(&self.rk, blocks) }
    }

    pub(crate) fn ctr32_xor(&self, ctr: &[u8; 16], in_out: &mut [u8]) {
        // SAFETY: `Key::new` verified VAES, AVX2, AES-NI and SSE4.1 support.
        unsafe { ctr32_xor_impl(&self.rk, ctr, in_out) }
    }
}

#[inline]
#[target_feature(enable = "avx")]
fn load256(b: &[[u8; 16]; 2]) -> __m256i {
    // SAFETY: `b` references 32 readable bytes; the unaligned load reads
    // exactly those bytes.
    unsafe { _mm256_loadu_si256(b.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "avx")]
fn store256(b: &mut [[u8; 16]; 2], v: __m256i) {
    // SAFETY: `b` is an exclusive reference to 32 writable bytes; the
    // unaligned store writes exactly those bytes.
    unsafe { _mm256_storeu_si256(b.as_mut_ptr().cast(), v) }
}

#[inline]
#[target_feature(enable = "vaes,avx2,aes,sse4.1")]
fn load_keys256(keys: &[__m128i; 15]) -> [__m256i; 15] {
    core::array::from_fn(|i| _mm256_broadcastsi128_si256(keys[i]))
}

/// Encrypts sixteen blocks (two per register), interleaving the rounds.
#[inline]
#[target_feature(enable = "vaes,avx2,aes,sse4.1")]
fn encrypt16(keys: &[__m256i; 15], rounds: usize, b: &mut [__m256i; 8]) {
    for x in b.iter_mut() {
        *x = _mm256_xor_si256(*x, keys[0]);
    }
    for k in &keys[1..rounds] {
        for x in b.iter_mut() {
            *x = _mm256_aesenc_epi128(*x, *k);
        }
    }
    for x in b.iter_mut() {
        *x = _mm256_aesenclast_epi128(*x, keys[rounds]);
    }
}

#[target_feature(enable = "vaes,avx2,aes,sse4.1")]
fn encrypt_blocks_impl(rk: &RoundKeys, blocks: &mut [[u8; 16]]) {
    let keys = x86::load_keys(rk);
    let keys256 = load_keys256(&keys);
    let (groups, rest) = blocks.as_chunks_mut::<16>();
    for g in groups {
        let pairs = g.as_chunks_mut::<2>().0;
        let mut b: [__m256i; 8] = core::array::from_fn(|i| load256(&pairs[i]));
        encrypt16(&keys256, rk.rounds, &mut b);
        for (dst, v) in pairs.iter_mut().zip(b) {
            store256(dst, v);
        }
    }
    x86::encrypt_blocks_impl(rk, rest);
}

#[target_feature(enable = "vaes,avx2,aes,sse4.1")]
fn ctr32_xor_impl(rk: &RoundKeys, ctr: &[u8; 16], in_out: &mut [u8]) {
    let keys = x86::load_keys(rk);
    let keys256 = load_keys256(&keys);
    let base128 = x86::load(ctr);
    let base = _mm256_broadcastsi128_si256(base128);
    let mut counter = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
    // Byte-swap within each 32-bit lane (only lane 3 of each half is used).
    let bswap32 = _mm256_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5,
        6, 7, 0, 1, 2, 3,
    );
    let two = _mm256_set_epi32(2, 0, 0, 0, 2, 0, 0, 0);

    let (blocks, rest) = in_out.as_chunks_mut::<16>();
    let (groups, tail) = blocks.as_chunks_mut::<16>();
    for g in groups {
        #[allow(clippy::cast_possible_wrap)]
        let mut cv = _mm256_set_epi32(
            counter.wrapping_add(1) as i32,
            0,
            0,
            0,
            counter as i32,
            0,
            0,
            0,
        );
        let mut b = [_mm256_setzero_si256(); 8];
        for x in &mut b {
            *x = _mm256_blend_epi32(base, _mm256_shuffle_epi8(cv, bswap32), 0x88);
            cv = _mm256_add_epi32(cv, two);
        }
        counter = counter.wrapping_add(16);
        encrypt16(&keys256, rk.rounds, &mut b);
        let pairs = g.as_chunks_mut::<2>().0;
        for (dst, v) in pairs.iter_mut().zip(b) {
            store256(dst, _mm256_xor_si256(load256(dst), v));
        }
    }
    // Up to fifteen whole blocks remain: two XMM batches at most.
    let (tail8, tail_rest) = tail.as_chunks_mut::<8>();
    for g in tail8 {
        x86::ctr32_xor_tail(&keys, rk.rounds, base128, counter, g, &mut []);
        counter = counter.wrapping_add(8);
    }
    x86::ctr32_xor_tail(&keys, rk.rounds, base128, counter, tail_rest, rest);
}
