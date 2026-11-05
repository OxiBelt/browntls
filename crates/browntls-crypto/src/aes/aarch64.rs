//! aarch64 AES backend (FEAT_AES: `aese` + `aesmc`), eight independent
//! blocks per iteration.
//!
//! Decryption (`aesd` + `aesimc`) uses the equivalent inverse cipher (FIPS
//! 197 §5.3.5), whose middle round keys are passed through InvMixColumns.
//! CBC decryption is parallel and runs eight blocks per iteration; CBC
//! encryption is inherently serial and runs one block at a time.
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

    pub(crate) fn cbc_encrypt(&self, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
        // SAFETY: `Key::new` verified FEAT_AES (which implies NEON) support.
        unsafe { cbc_encrypt_impl(&self.rk, iv, blocks) }
    }
}

/// Decryption round keys for the equivalent inverse cipher:
/// `dk[0] = rk[Nr]`, `dk[i] = InvMixColumns(rk[Nr - i])` for `0 < i < Nr`
/// and `dk[Nr] = rk[0]`.
///
/// A value can only be constructed by [`DecKey::new`], which checks that
/// FEAT_AES is present; this invariant makes the `#[target_feature]` calls
/// sound.
pub(crate) struct DecKey {
    dk: RoundKeys,
}

impl DecKey {
    pub(crate) fn new(rk: &RoundKeys) -> Self {
        assert!(
            features().arm_aes(),
            "ARM AES backend selected without CPU support"
        );
        let mut dk = RoundKeys {
            rk: [[0u8; 16]; 15],
            rounds: rk.rounds,
        };
        // SAFETY: FEAT_AES support was verified above.
        unsafe { inverse_key_schedule(rk, &mut dk) };
        Self { dk }
    }

    pub(crate) fn cbc_decrypt(&self, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
        // SAFETY: `DecKey::new` verified FEAT_AES (which implies NEON)
        // support.
        unsafe { cbc_decrypt_impl(&self.dk, iv, blocks) }
    }
}

#[target_feature(enable = "aes")]
fn inverse_key_schedule(rk: &RoundKeys, dk: &mut RoundKeys) {
    let n = rk.rounds;
    dk.rk[0] = rk.rk[n];
    for i in 1..n {
        store(&mut dk.rk[i], vaesimcq_u8(load(&rk.rk[n - i])));
    }
    dk.rk[n] = rk.rk[0];
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

/// Decrypts eight blocks with the equivalent inverse cipher, interleaving
/// the rounds. `aesd` performs AddRoundKey + InvShiftRows + InvSubBytes,
/// `aesimc` InvMixColumns.
#[inline]
#[target_feature(enable = "aes")]
fn decrypt8(dk: &[uint8x16_t; 15], rounds: usize, b: &mut [uint8x16_t; 8]) {
    for k in &dk[..rounds - 1] {
        for x in b.iter_mut() {
            *x = vaesimcq_u8(vaesdq_u8(*x, *k));
        }
    }
    for x in b.iter_mut() {
        *x = veorq_u8(vaesdq_u8(*x, dk[rounds - 1]), dk[rounds]);
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

/// CBC encryption (SP 800-38A §6.2), one block at a time.
#[target_feature(enable = "aes")]
fn cbc_encrypt_impl(rk: &RoundKeys, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
    let keys = load_keys(rk);
    let rounds = rk.rounds;
    let mut prev = load(iv);
    for block in blocks {
        let mut x = veorq_u8(load(block), prev);
        for k in &keys[..rounds - 1] {
            x = vaesmcq_u8(vaeseq_u8(x, *k));
        }
        x = veorq_u8(vaeseq_u8(x, keys[rounds - 1]), keys[rounds]);
        store(block, x);
        prev = x;
    }
}

/// CBC decryption (SP 800-38A §6.2), eight blocks per iteration. The
/// ciphertext of each group stays in registers until the group's plaintext
/// is written, so the operation works in place.
#[target_feature(enable = "aes")]
fn cbc_decrypt_impl(dk: &RoundKeys, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
    let keys = load_keys(dk);
    let rounds = dk.rounds;
    let mut prev = load(iv);
    let (groups, rest) = blocks.as_chunks_mut::<8>();
    for g in groups {
        let c: [uint8x16_t; 8] = core::array::from_fn(|i| load(&g[i]));
        let mut b = c;
        decrypt8(&keys, rounds, &mut b);
        store(&mut g[0], veorq_u8(b[0], prev));
        for i in 1..8 {
            store(&mut g[i], veorq_u8(b[i], c[i - 1]));
        }
        prev = c[7];
    }
    if !rest.is_empty() {
        let mut c = [vdupq_n_u8(0); 8];
        for (v, src) in c.iter_mut().zip(rest.iter()) {
            *v = load(src);
        }
        let mut b = c;
        decrypt8(&keys, rounds, &mut b);
        for (i, dst) in rest.iter_mut().enumerate() {
            let p = if i == 0 { prev } else { c[i - 1] };
            store(dst, veorq_u8(b[i], p));
        }
    }
}
