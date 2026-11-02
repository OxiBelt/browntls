//! aarch64 AES backend (FEAT_AES: `aese` + `aesmc`), eight independent
//! blocks per iteration.
#![allow(unsafe_code)]

use core::arch::aarch64::*;

use super::RoundKeys;
use crate::cpu::features;

/// Round keys for the Armv8 Cryptographic Extension backend.
///
/// A value can only be constructed by [`Key::new`], which checks that FEAT_AES
/// is present; this invariant makes the `#[target_feature]` calls sound.
pub(crate) struct Key {
    rk: RoundKeys,
}

impl Key {
    pub(crate) fn new(rk: RoundKeys) -> Self {
        assert!(
            features().arm_aes(),
            "ARM AES backend selected without CPU support"
        );
        Self { rk }
    }

    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        // SAFETY: `Key::new` verified FEAT_AES (which implies NEON) support.
        unsafe { encrypt_blocks_impl(&self.rk, blocks) }
    }

    pub(crate) fn ctr32_xor(&self, ctr: &[u8; 16], in_out: &mut [u8]) {
        // SAFETY: `Key::new` verified FEAT_AES (which implies NEON) support.
        unsafe { ctr32_xor_impl(&self.rk, ctr, in_out) }
    }
}

#[inline]
#[target_feature(enable = "aes")]
fn load(b: &[u8; 16]) -> uint8x16_t {
    // SAFETY: `b` references 16 readable bytes; `vld1q_u8` reads exactly
    // those bytes and has no alignment requirement.
    unsafe { vld1q_u8(b.as_ptr()) }
}

#[inline]
#[target_feature(enable = "aes")]
fn store(b: &mut [u8; 16], v: uint8x16_t) {
    // SAFETY: `b` is an exclusive reference to 16 writable bytes; `vst1q_u8`
    // writes exactly those bytes.
    unsafe { vst1q_u8(b.as_mut_ptr(), v) }
}

#[inline]
#[target_feature(enable = "aes")]
fn load_keys(rk: &RoundKeys) -> [uint8x16_t; 15] {
    let mut keys = [vdupq_n_u8(0); 15];
    for (k, bytes) in keys.iter_mut().zip(&rk.rk) {
        *k = load(bytes);
    }
    keys
}

/// Encrypts eight blocks, interleaving the rounds. `aese` performs
/// AddRoundKey + SubBytes + ShiftRows, `aesmc` MixColumns.
#[inline]
#[target_feature(enable = "aes")]
fn encrypt8(keys: &[uint8x16_t; 15], rounds: usize, b: &mut [uint8x16_t; 8]) {
    for k in &keys[..rounds - 1] {
        for x in b.iter_mut() {
            *x = vaesmcq_u8(vaeseq_u8(*x, *k));
        }
    }
    for x in b.iter_mut() {
        *x = veorq_u8(vaeseq_u8(*x, keys[rounds - 1]), keys[rounds]);
    }
}

/// Builds the counter block with big-endian `counter` in the last four bytes.
#[inline]
#[target_feature(enable = "aes")]
fn counter_block(base: uint8x16_t, counter: u32) -> uint8x16_t {
    vreinterpretq_u8_u32(vsetq_lane_u32::<3>(
        counter.swap_bytes(),
        vreinterpretq_u32_u8(base),
    ))
}

#[target_feature(enable = "aes")]
fn encrypt_blocks_impl(rk: &RoundKeys, blocks: &mut [[u8; 16]]) {
    let keys = load_keys(rk);
    let (groups, rest) = blocks.as_chunks_mut::<8>();
    for g in groups {
        let mut b: [uint8x16_t; 8] = core::array::from_fn(|i| load(&g[i]));
        encrypt8(&keys, rk.rounds, &mut b);
        for (dst, v) in g.iter_mut().zip(b) {
            store(dst, v);
        }
    }
    if !rest.is_empty() {
        let mut b = [vdupq_n_u8(0); 8];
        for (v, src) in b.iter_mut().zip(rest.iter()) {
            *v = load(src);
        }
        encrypt8(&keys, rk.rounds, &mut b);
        for (dst, v) in rest.iter_mut().zip(b) {
            store(dst, v);
        }
    }
}

#[target_feature(enable = "aes")]
fn ctr32_xor_impl(rk: &RoundKeys, ctr: &[u8; 16], in_out: &mut [u8]) {
    let keys = load_keys(rk);
    let base = load(ctr);
    let mut counter = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
    let (blocks, rest) = in_out.as_chunks_mut::<16>();
    let (groups, tail) = blocks.as_chunks_mut::<8>();
    for g in groups {
        #[allow(clippy::cast_possible_truncation)]
        let mut b: [uint8x16_t; 8] =
            core::array::from_fn(|i| counter_block(base, counter.wrapping_add(i as u32)));
        counter = counter.wrapping_add(8);
        encrypt8(&keys, rk.rounds, &mut b);
        for (dst, v) in g.iter_mut().zip(b) {
            store(dst, veorq_u8(load(dst), v));
        }
    }
    if !tail.is_empty() || !rest.is_empty() {
        #[allow(clippy::cast_possible_truncation)]
        let mut b: [uint8x16_t; 8] =
            core::array::from_fn(|i| counter_block(base, counter.wrapping_add(i as u32)));
        encrypt8(&keys, rk.rounds, &mut b);
        for (dst, v) in tail.iter_mut().zip(&b) {
            store(dst, veorq_u8(load(dst), *v));
        }
        if !rest.is_empty() {
            let mut ks = [0u8; 16];
            store(&mut ks, b[tail.len()]);
            for (x, k) in rest.iter_mut().zip(ks) {
                *x ^= k;
            }
        }
    }
}
