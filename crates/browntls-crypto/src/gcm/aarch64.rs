//! aarch64 GHASH with FEAT_PMULL (`pmull`/`pmull2`).
//!
//! Same construction as the x86-64 backend: POLYVAL representation
//! (byte-reversed blocks, key pre-multiplied by `x`), Karatsuba with
//! precomputed `H^8 .. H^1`, a single Montgomery-style reduction per eight
//! blocks using carry-less multiplication by `0xc2 << 56`.
#![allow(unsafe_code)]

use core::arch::aarch64::*;

use crate::cpu::features;
use crate::zeroize::zeroize_bytes;

/// Precomputed powers of the hash key.
///
/// A value can only be constructed by [`Key::new`], which checks that
/// FEAT_AES/FEAT_PMULL are present; this invariant makes the
/// `#[target_feature]` calls sound.
pub(crate) struct Key {
    /// `h[i]` holds `H^(8 - i)` in POLYVAL form.
    h: [[u8; 16]; 8],
    /// `hx[i]` holds the XOR of both 64-bit halves of `h[i]` in its low half.
    hx: [[u8; 16]; 8],
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
        assert!(
            features().arm_aes(),
            "PMULL backend selected without CPU support"
        );
        let h1 = super::polyval_key(h);
        // SAFETY: FEAT_AES/FEAT_PMULL support was just verified.
        unsafe { powers_impl(&h1) }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into the accumulator `y`.
    pub(crate) fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        // SAFETY: `Key::new` verified FEAT_AES/FEAT_PMULL support.
        unsafe { update_impl(self, y, blocks) }
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

/// Reverses all sixteen bytes.
#[inline]
#[target_feature(enable = "aes")]
fn bswap(x: uint8x16_t) -> uint8x16_t {
    let r = vrev64q_u8(x);
    vextq_u8::<8>(r, r)
}

/// Swaps the two 64-bit halves.
#[inline]
#[target_feature(enable = "aes")]
fn swap_halves(x: uint8x16_t) -> uint8x16_t {
    vextq_u8::<8>(x, x)
}

#[inline]
#[target_feature(enable = "aes")]
fn lane0(x: uint8x16_t) -> u64 {
    vgetq_lane_p64::<0>(vreinterpretq_p64_u8(x))
}

/// Carry-less product of the low halves.
#[inline]
#[target_feature(enable = "aes")]
fn mul_lo(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    vreinterpretq_u8_p128(vmull_p64(lane0(a), lane0(b)))
}

/// Carry-less product of the high halves.
#[inline]
#[target_feature(enable = "aes")]
fn mul_hi(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    vreinterpretq_u8_p128(vmull_high_p64(
        vreinterpretq_p64_u8(a),
        vreinterpretq_p64_u8(b),
    ))
}

/// Accumulates the three Karatsuba partial products of `x * h`.
#[inline]
#[target_feature(enable = "aes")]
fn karatsuba(x: uint8x16_t, h: uint8x16_t, hx: uint8x16_t, acc: &mut [uint8x16_t; 3]) {
    let xx = veorq_u8(x, swap_halves(x));
    acc[0] = veorq_u8(acc[0], mul_lo(x, h));
    acc[1] = veorq_u8(acc[1], mul_lo(xx, hx));
    acc[2] = veorq_u8(acc[2], mul_hi(x, h));
}

/// Combines the Karatsuba accumulators and reduces by `x^128` modulo
/// `x^128 + x^127 + x^126 + x^121 + 1`.
#[inline]
#[target_feature(enable = "aes")]
fn reduce(acc: [uint8x16_t; 3]) -> uint8x16_t {
    let [lo, mid, hi] = acc;
    let zero = vdupq_n_u8(0);
    let mid = veorq_u8(mid, veorq_u8(lo, hi));
    let lo = veorq_u8(lo, vextq_u8::<8>(zero, mid)); // lo ^= mid << 64
    let hi = veorq_u8(hi, vextq_u8::<8>(mid, zero)); // hi ^= mid >> 64
    let poly: u64 = 0xc200_0000_0000_0000;
    let t = vreinterpretq_u8_p128(vmull_p64(lane0(lo), poly));
    let lo = veorq_u8(swap_halves(lo), t);
    let t = vreinterpretq_u8_p128(vmull_p64(lane0(lo), poly));
    let lo = veorq_u8(swap_halves(lo), t);
    veorq_u8(hi, lo)
}

#[inline]
#[target_feature(enable = "aes")]
fn mul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let mut acc = [vdupq_n_u8(0); 3];
    karatsuba(a, b, veorq_u8(b, swap_halves(b)), &mut acc);
    reduce(acc)
}

#[target_feature(enable = "aes")]
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
        store(&mut key.hx[i], veorq_u8(p, swap_halves(p)));
    }
    key
}

/// Multiplies `n <= 8` blocks by `H^n .. H^1`, adds `acc` to the first and
/// returns the reduced sum.
#[inline]
#[target_feature(enable = "aes")]
fn ghash_blocks(
    h: &[uint8x16_t; 8],
    hx: &[uint8x16_t; 8],
    mut acc: uint8x16_t,
    blocks: &[[u8; 16]],
) -> uint8x16_t {
    let n = blocks.len();
    debug_assert!(n <= 8);
    let mut sum = [vdupq_n_u8(0); 3];
    for (i, blk) in blocks.iter().enumerate() {
        let x = veorq_u8(bswap(load(blk)), acc);
        acc = vdupq_n_u8(0);
        karatsuba(x, h[8 - n + i], hx[8 - n + i], &mut sum);
    }
    reduce(sum)
}

#[target_feature(enable = "aes")]
fn update_impl(key: &Key, y: &mut [u8; 16], blocks: &[u8]) {
    let h: [uint8x16_t; 8] = core::array::from_fn(|i| load(&key.h[i]));
    let hx: [uint8x16_t; 8] = core::array::from_fn(|i| load(&key.hx[i]));
    let mut acc = bswap(load(y));
    let blocks = blocks.as_chunks::<16>().0;
    let (groups, rest) = blocks.as_chunks::<8>();
    for g in groups {
        acc = ghash_blocks(&h, &hx, acc, g);
    }
    if !rest.is_empty() {
        acc = ghash_blocks(&h, &hx, acc, rest);
    }
    store(y, bswap(acc));
}
