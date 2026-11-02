//! x86-64 AES-NI backend (XMM registers, eight independent blocks per
//! iteration so that the `aesenc` pipeline stays full).
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use super::RoundKeys;
use crate::cpu::features;

/// Round keys for the AES-NI backend.
///
/// A value can only be constructed by [`Key::new`], which checks that AES-NI
/// and SSE4.1 are present; this invariant makes the `#[target_feature]` calls
/// below sound.
pub(crate) struct Key {
    rk: RoundKeys,
}

impl Key {
    pub(crate) fn new(rk: RoundKeys) -> Self {
        let f = features();
        assert!(
            f.x86_aes() && f.x86_sse41(),
            "AES-NI backend selected without CPU support"
        );
        Self { rk }
    }

    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        // SAFETY: `Key::new` verified AES-NI and SSE4.1 support.
        unsafe { encrypt_blocks_impl(&self.rk, blocks) }
    }

    pub(crate) fn ctr32_xor(&self, ctr: &[u8; 16], in_out: &mut [u8]) {
        // SAFETY: `Key::new` verified AES-NI and SSE4.1 support.
        unsafe { ctr32_xor_impl(&self.rk, ctr, in_out) }
    }
}

#[inline]
#[target_feature(enable = "sse2")]
pub(super) fn load(b: &[u8; 16]) -> __m128i {
    // SAFETY: `b` references 16 readable bytes and the unaligned load reads
    // exactly those bytes.
    unsafe { _mm_loadu_si128(b.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "sse2")]
pub(super) fn store(b: &mut [u8; 16], v: __m128i) {
    // SAFETY: `b` is an exclusive reference to 16 writable bytes and the
    // unaligned store writes exactly those bytes.
    unsafe { _mm_storeu_si128(b.as_mut_ptr().cast(), v) }
}

#[inline]
#[target_feature(enable = "aes,sse4.1")]
pub(super) fn load_keys(rk: &RoundKeys) -> [__m128i; 15] {
    let mut keys = [_mm_setzero_si128(); 15];
    for (k, bytes) in keys.iter_mut().zip(&rk.rk) {
        *k = load(bytes);
    }
    keys
}

/// Encrypts eight blocks, interleaving the rounds.
#[inline]
#[target_feature(enable = "aes,sse4.1")]
pub(super) fn encrypt8(keys: &[__m128i; 15], rounds: usize, b: &mut [__m128i; 8]) {
    for x in b.iter_mut() {
        *x = _mm_xor_si128(*x, keys[0]);
    }
    for k in &keys[1..rounds] {
        for x in b.iter_mut() {
            *x = _mm_aesenc_si128(*x, *k);
        }
    }
    for x in b.iter_mut() {
        *x = _mm_aesenclast_si128(*x, keys[rounds]);
    }
}

/// Builds the counter block with big-endian `counter` in the last four bytes.
#[inline]
#[target_feature(enable = "sse4.1")]
pub(super) fn counter_block(base: __m128i, counter: u32) -> __m128i {
    // Lane 3 is little-endian, so byte-swap the big-endian counter.
    #[allow(clippy::cast_possible_wrap)]
    let lane = counter.swap_bytes() as i32;
    _mm_insert_epi32(base, lane, 3)
}

#[target_feature(enable = "aes,sse4.1")]
pub(super) fn encrypt_blocks_impl(rk: &RoundKeys, blocks: &mut [[u8; 16]]) {
    let keys = load_keys(rk);
    let (groups, rest) = blocks.as_chunks_mut::<8>();
    for g in groups {
        let mut b: [__m128i; 8] = core::array::from_fn(|i| load(&g[i]));
        encrypt8(&keys, rk.rounds, &mut b);
        for (dst, v) in g.iter_mut().zip(b) {
            store(dst, v);
        }
    }
    if !rest.is_empty() {
        // Fewer than eight blocks: still run them together.
        let mut b = [_mm_setzero_si128(); 8];
        for (v, src) in b.iter_mut().zip(rest.iter()) {
            *v = load(src);
        }
        encrypt8(&keys, rk.rounds, &mut b);
        for (dst, v) in rest.iter_mut().zip(b) {
            store(dst, v);
        }
    }
}

/// CTR keystream application for a tail of fewer than eight blocks plus an
/// optional partial block; `counter` is the counter of the first tail block.
#[inline]
#[target_feature(enable = "aes,sse4.1")]
pub(super) fn ctr32_xor_tail(
    keys: &[__m128i; 15],
    rounds: usize,
    base: __m128i,
    counter: u32,
    blocks: &mut [[u8; 16]],
    rest: &mut [u8],
) {
    if blocks.is_empty() && rest.is_empty() {
        return;
    }
    #[allow(clippy::cast_possible_truncation)]
    let mut b: [__m128i; 8] =
        core::array::from_fn(|i| counter_block(base, counter.wrapping_add(i as u32)));
    encrypt8(keys, rounds, &mut b);
    for (dst, v) in blocks.iter_mut().zip(&b) {
        store(dst, _mm_xor_si128(load(dst), *v));
    }
    if !rest.is_empty() {
        let mut ks = [0u8; 16];
        store(&mut ks, b[blocks.len()]);
        for (x, k) in rest.iter_mut().zip(ks) {
            *x ^= k;
        }
    }
}

#[target_feature(enable = "aes,sse4.1")]
pub(super) fn ctr32_xor_impl(rk: &RoundKeys, ctr: &[u8; 16], in_out: &mut [u8]) {
    let keys = load_keys(rk);
    let base = load(ctr);
    let mut counter = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
    let (blocks, rest) = in_out.as_chunks_mut::<16>();
    let (groups, tail) = blocks.as_chunks_mut::<8>();
    for g in groups {
        #[allow(clippy::cast_possible_truncation)]
        let mut b: [__m128i; 8] =
            core::array::from_fn(|i| counter_block(base, counter.wrapping_add(i as u32)));
        counter = counter.wrapping_add(8);
        encrypt8(&keys, rk.rounds, &mut b);
        for (dst, v) in g.iter_mut().zip(b) {
            store(dst, _mm_xor_si128(load(dst), v));
        }
    }
    ctr32_xor_tail(&keys, rk.rounds, base, counter, tail, rest);
}
