//! aarch64 Advanced SIMD (NEON) ChaCha20: four word-sliced blocks per step
//! and a row-oriented single-block path for short tails.
//!
//! Little-endian only (the lane reinterpretations assume it); the module is
//! not compiled for big-endian targets.
#![allow(unsafe_code)]

use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u32, vextq_u32, vld1q_u8, vld1q_u32,
    vreinterpretq_u8_u32, vreinterpretq_u16_u32, vreinterpretq_u32_u8, vreinterpretq_u32_u16,
    vreinterpretq_u32_u64, vreinterpretq_u64_u32, vrev32q_u16, vshlq_n_u32, vsriq_n_u32, vst1q_u8,
    vtrn1q_u32, vtrn1q_u64, vtrn2q_u32, vtrn2q_u64,
};

use super::soft::{self, BLOCK};
use crate::cpu::features;
use crate::zeroize::Zeroize;

#[target_feature(enable = "neon")]
#[inline]
fn add(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    vaddq_u32(a, b)
}
#[target_feature(enable = "neon")]
#[inline]
fn xor(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    veorq_u32(a, b)
}
#[target_feature(enable = "neon")]
#[inline]
fn r16(a: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(a)))
}
#[target_feature(enable = "neon")]
#[inline]
fn r12(a: uint32x4_t) -> uint32x4_t {
    vsriq_n_u32::<20>(vshlq_n_u32::<12>(a), a)
}
#[target_feature(enable = "neon")]
#[inline]
fn r8(a: uint32x4_t) -> uint32x4_t {
    vsriq_n_u32::<24>(vshlq_n_u32::<8>(a), a)
}
#[target_feature(enable = "neon")]
#[inline]
fn r7(a: uint32x4_t) -> uint32x4_t {
    vsriq_n_u32::<25>(vshlq_n_u32::<7>(a), a)
}

#[target_feature(enable = "neon")]
#[inline]
fn load_words(w: &[u32; 4]) -> uint32x4_t {
    // SAFETY: `w` points to four readable `u32`s.
    unsafe { vld1q_u32(w.as_ptr()) }
}

#[target_feature(enable = "neon")]
#[inline]
fn xor_store(ks: uint32x4_t, c: &mut [u8; 16]) {
    // SAFETY: `c` points to 16 readable bytes.
    let d = unsafe { vld1q_u8(c.as_ptr()) };
    let x = vreinterpretq_u8_u32(veorq_u32(vreinterpretq_u32_u8(d), ks));
    // SAFETY: `c` points to 16 writable bytes.
    unsafe { vst1q_u8(c.as_mut_ptr(), x) };
}

/// Four blocks of keystream; `out[4 * j + g]` holds words `4g..4g+4` of block `j`.
#[target_feature(enable = "neon")]
#[inline]
fn core4(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [uint32x4_t; 16] {
    let init = soft::initial_state(key, counter, nonce);
    let mut s = [vdupq_n_u32(0); 16];
    for (v, w) in s.iter_mut().zip(init) {
        *v = vdupq_n_u32(w);
    }
    s[12] = vaddq_u32(s[12], load_words(&[0, 1, 2, 3]));
    let mut x = s;
    chacha_rounds!(x, add, xor, r16, r12, r8, r7);
    let mut out = x;
    for g in 0..4 {
        let v: [uint32x4_t; 4] = core::array::from_fn(|i| add(x[4 * g + i], s[4 * g + i]));
        let t0 = vtrn1q_u32(v[0], v[1]);
        let t1 = vtrn2q_u32(v[0], v[1]);
        let t2 = vtrn1q_u32(v[2], v[3]);
        let t3 = vtrn2q_u32(v[2], v[3]);
        let (t0, t1, t2, t3) = (
            vreinterpretq_u64_u32(t0),
            vreinterpretq_u64_u32(t1),
            vreinterpretq_u64_u32(t2),
            vreinterpretq_u64_u32(t3),
        );
        out[g] = vreinterpretq_u32_u64(vtrn1q_u64(t0, t2));
        out[4 + g] = vreinterpretq_u32_u64(vtrn1q_u64(t1, t3));
        out[8 + g] = vreinterpretq_u32_u64(vtrn2q_u64(t0, t2));
        out[12 + g] = vreinterpretq_u32_u64(vtrn2q_u64(t1, t3));
    }
    out
}

/// One block, row oriented: `x[r]` is row `r` of the 4x4 state.
#[target_feature(enable = "neon")]
#[inline]
fn core1(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [uint32x4_t; 4] {
    let init = soft::initial_state(key, counter, nonce);
    let s: [uint32x4_t; 4] =
        core::array::from_fn(|r| load_words(init[4 * r..4 * r + 4].try_into().unwrap_or(&[0; 4])));
    let [mut a, mut b, mut c, mut d] = s;
    macro_rules! qr {
        () => {
            a = add(a, b);
            d = r16(xor(d, a));
            c = add(c, d);
            b = r12(xor(b, c));
            a = add(a, b);
            d = r8(xor(d, a));
            c = add(c, d);
            b = r7(xor(b, c));
        };
    }
    for _ in 0..10 {
        qr!();
        b = vextq_u32::<1>(b, b);
        c = vextq_u32::<2>(c, c);
        d = vextq_u32::<3>(d, d);
        qr!();
        b = vextq_u32::<3>(b, b);
        c = vextq_u32::<2>(c, c);
        d = vextq_u32::<1>(d, d);
    }
    [add(a, s[0]), add(b, s[1]), add(c, s[2]), add(d, s[3])]
}

#[target_feature(enable = "neon")]
fn xor4(ks: &[uint32x4_t; 16], data: &mut [u8; 4 * BLOCK]) {
    for (k, c) in ks.iter().zip(data.as_chunks_mut::<16>().0) {
        xor_store(*k, c);
    }
}

#[target_feature(enable = "neon")]
fn xor1(ks: &[uint32x4_t; 4], data: &mut [u8; BLOCK]) {
    for (k, c) in ks.iter().zip(data.as_chunks_mut::<16>().0) {
        xor_store(*k, c);
    }
}

#[target_feature(enable = "neon")]
fn xor_neon_inner(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    let (chunks, tail) = data.as_chunks_mut::<{ 4 * BLOCK }>();
    let mut ctr = counter;
    for c in chunks {
        xor4(&core4(key, ctr, nonce), c);
        ctr = ctr.wrapping_add(4);
    }
    if tail.len() > 2 * BLOCK {
        let mut buf = [0u8; 4 * BLOCK];
        xor4(&core4(key, ctr, nonce), &mut buf);
        soft::xor_in_place(tail, &buf);
        buf.zeroize();
        return;
    }
    let (blocks, rest) = tail.as_chunks_mut::<BLOCK>();
    for b in blocks {
        xor1(&core1(key, ctr, nonce), b);
        ctr = ctr.wrapping_add(1);
    }
    if !rest.is_empty() {
        let mut buf = [0u8; BLOCK];
        xor1(&core1(key, ctr, nonce), &mut buf);
        soft::xor_in_place(rest, &buf);
        buf.zeroize();
    }
}

/// NEON ChaCha20; falls back to the portable code when NEON use is disabled.
pub(super) fn xor_neon(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    if features().arm_neon() {
        // SAFETY: Advanced SIMD support was detected (it is architecturally
        // mandatory; this only honours `browntls_force_soft`).
        unsafe { xor_neon_inner(key, counter, nonce, data) };
    } else {
        soft::xor(key, counter, nonce, data);
    }
}
