//! x86-64 VAES backend on ZMM registers: four blocks per register, eight
//! registers (32 blocks) per iteration. Tails of fewer than 32 blocks are
//! encrypted in one to eight registers and applied with byte-masked loads
//! and stores, so a partial final block needs no copy.
//!
//! The building blocks (`load_keys`, `Counter`, `rounds`) are shared with
//! the fused AES-GCM path in [`crate::gcm`].
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use super::RoundKeys;
use super::x86;
use crate::cpu::{Features, features};

/// Returns whether the CPU can run this backend: AVX-512 F/BW/VL with OS
/// support for ZMM state, VAES (which then covers the ZMM encoding) and the
/// XMM baseline the shared helpers rely on.
pub(crate) fn supported(f: Features) -> bool {
    f.x86_avx512() && f.x86_vaes() && f.x86_avx2() && f.x86_aes() && f.x86_sse41()
}

/// Round keys for the ZMM VAES backend.
///
/// A value can only be constructed by [`Key::new`], which checks
/// [`supported`]; this invariant makes the `#[target_feature]` calls sound.
pub(crate) struct Key {
    rk: RoundKeys,
}

impl Key {
    pub(crate) fn new(rk: RoundKeys) -> Self {
        assert!(
            supported(features()),
            "AVX-512 VAES backend selected without CPU support"
        );
        Self { rk }
    }

    /// The round keys, for the fused AES-GCM path.
    pub(crate) fn round_keys(&self) -> &RoundKeys {
        &self.rk
    }

    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        // SAFETY: `Key::new` verified AVX-512 F/BW/VL, VAES, AVX2, AES-NI and
        // SSE4.1 support.
        unsafe { encrypt_blocks_impl(&self.rk, blocks) }
    }

    pub(crate) fn ctr32_xor(&self, ctr: &[u8; 16], in_out: &mut [u8]) {
        // SAFETY: `Key::new` verified AVX-512 F/BW/VL, VAES, AVX2, AES-NI and
        // SSE4.1 support.
        unsafe { ctr32_xor_impl(&self.rk, ctr, in_out) }
    }
}

/// Calls `$f::<N, ...>($args)` with `N` the register count `$regs` (1 to 8)
/// and `...` any further generic arguments given as `$f::<...>`.
macro_rules! dispatch_regs {
    ($regs:expr, $($f:ident)::+ ::<$($g:ident),*>($($arg:expr),* $(,)?)) => {
        dispatch_regs!(@call $regs, [$($f)::+], [$($g),*], [$($arg),*])
    };
    ($regs:expr, $($f:ident)::+ ($($arg:expr),* $(,)?)) => {
        dispatch_regs!(@call $regs, [$($f)::+], [], [$($arg),*])
    };
    (@call $regs:expr, [$($f:ident)::+], [$($g:ident),*], [$($arg:expr),*]) => {
        match $regs {
            1 => $($f)::+::<1, $($g),*>($($arg),*),
            2 => $($f)::+::<2, $($g),*>($($arg),*),
            3 => $($f)::+::<3, $($g),*>($($arg),*),
            4 => $($f)::+::<4, $($g),*>($($arg),*),
            5 => $($f)::+::<5, $($g),*>($($arg),*),
            6 => $($f)::+::<6, $($g),*>($($arg),*),
            7 => $($f)::+::<7, $($g),*>($($arg),*),
            8 => $($f)::+::<8, $($g),*>($($arg),*),
            // Callers pass 1..=8 (tails are under 512 bytes); any other count
            // would silently skip data in the zipped loops, so stop instead.
            _ => unreachable!("register count out of range"),
        }
    };
}
pub(crate) use dispatch_regs;

#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn load(b: &[[u8; 16]; 4]) -> __m512i {
    // SAFETY: `b` references 64 readable bytes; the unaligned load reads
    // exactly those bytes.
    unsafe { _mm512_loadu_si512(b.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn store(b: &mut [[u8; 16]; 4], v: __m512i) {
    // SAFETY: `b` is an exclusive reference to 64 writable bytes; the
    // unaligned store writes exactly those bytes.
    unsafe { _mm512_storeu_si512(b.as_mut_ptr().cast(), v) }
}

/// The byte mask selecting the first `len <= 64` bytes of a register.
#[inline]
pub(crate) fn byte_mask(len: usize) -> __mmask64 {
    debug_assert!(len <= 64);
    if len >= 64 { !0 } else { (1u64 << len) - 1 }
}

/// Loads `b.len() <= 64` bytes into the low bytes of a register, zero
/// padded.
#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
pub(crate) fn load_partial(b: &[u8]) -> __m512i {
    // SAFETY: the masked load only touches the bytes selected by the mask,
    // which are exactly the `b.len()` readable bytes of `b`.
    unsafe { _mm512_maskz_loadu_epi8(byte_mask(b.len()), b.as_ptr().cast()) }
}

/// Stores the low `b.len() <= 64` bytes of `v` into `b`.
#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
pub(crate) fn store_partial(b: &mut [u8], v: __m512i) {
    // SAFETY: the masked store only writes the bytes selected by the mask,
    // which are exactly the `b.len()` bytes of the exclusive reference `b`.
    unsafe { _mm512_mask_storeu_epi8(b.as_mut_ptr().cast(), byte_mask(b.len()), v) }
}

/// Broadcasts every round key to the four lanes of a register.
#[inline]
#[target_feature(enable = "avx512f,aes,sse4.1")]
pub(crate) fn load_keys(rk: &RoundKeys) -> [__m512i; 15] {
    let keys = x86::load_keys(rk);
    core::array::from_fn(|i| _mm512_broadcast_i32x4(keys[i]))
}

/// Runs rounds `1..=rounds` on registers whose round-0 key has already been
/// XORed in, interleaving the registers.
#[inline]
#[target_feature(enable = "vaes,avx512f")]
pub(crate) fn rounds<const N: usize>(keys: &[__m512i; 15], rounds: usize, b: &mut [__m512i; N]) {
    for k in &keys[1..rounds] {
        for x in b.iter_mut() {
            *x = _mm512_aesenc_epi128(*x, *k);
        }
    }
    for x in b.iter_mut() {
        *x = _mm512_aesenclast_epi128(*x, keys[rounds]);
    }
}

/// Generator of GCM counter blocks, four per register, with round key 0
/// already applied.
pub(crate) struct Counter {
    /// The little-endian block counters in dword 3 of each lane; the other
    /// dwords are zero.
    le: __m512i,
    /// Bytes 0..12 of the counter block XOR round key 0 in every lane, with
    /// dword 3 holding only the round key.
    base: __m512i,
    /// `pshufb` control that byte-swaps dword 3 and zeroes the rest.
    swap: __m512i,
    four: __m512i,
}

impl Counter {
    /// Starts at counter block `ctr`; `key0` is the broadcast round key 0.
    #[inline]
    #[target_feature(enable = "avx512f,avx512bw,sse4.1")]
    pub(crate) fn new(ctr: &[u8; 16], key0: __m512i) -> Self {
        let c = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
        let base = _mm512_xor_si512(
            _mm512_broadcast_i32x4(x86::counter_block(x86::load(ctr), 0)),
            key0,
        );
        #[allow(clippy::cast_possible_wrap)]
        let lane = |i: u32| c.wrapping_add(i) as i32;
        let le = _mm512_set_epi32(
            lane(3),
            0,
            0,
            0,
            lane(2),
            0,
            0,
            0,
            lane(1),
            0,
            0,
            0,
            lane(0),
            0,
            0,
            0,
        );
        let swap = _mm512_broadcast_i32x4(_mm_set_epi8(
            12, 13, 14, 15, -128, -128, -128, -128, -128, -128, -128, -128, -128, -128, -128, -128,
        ));
        let four = _mm512_set_epi32(4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0);
        Self {
            le,
            base,
            swap,
            four,
        }
    }

    /// The next four counter blocks XOR round key 0.
    #[inline]
    #[target_feature(enable = "avx512f,avx512bw")]
    pub(crate) fn next(&mut self) -> __m512i {
        let blocks = _mm512_xor_si512(_mm512_shuffle_epi8(self.le, self.swap), self.base);
        self.le = _mm512_add_epi32(self.le, self.four);
        blocks
    }

    /// `N` registers of keystream for the next `4 * N` blocks.
    #[inline]
    #[target_feature(enable = "vaes,avx512f,avx512bw")]
    pub(crate) fn keystream<const N: usize>(
        &mut self,
        keys: &[__m512i; 15],
        nr: usize,
    ) -> [__m512i; N] {
        let mut b: [__m512i; N] = core::array::from_fn(|_| self.next());
        rounds(keys, nr, &mut b);
        b
    }
}

/// XORs keystream for `in_out` (1 to 511 bytes) in place, using exactly `N`
/// registers (`64 * (N - 1) < in_out.len() <= 64 * N`).
#[inline]
#[target_feature(enable = "vaes,avx512f,avx512bw")]
fn ctr_tail<const N: usize>(keys: &[__m512i; 15], nr: usize, ctr: &mut Counter, in_out: &mut [u8]) {
    debug_assert_eq!(in_out.len().div_ceil(64), N);
    let ks = ctr.keystream::<N>(keys, nr);
    for (chunk, k) in in_out.chunks_mut(64).zip(ks) {
        store_partial(chunk, _mm512_xor_si512(load_partial(chunk), k));
    }
}

#[target_feature(enable = "vaes,avx512f,avx512bw,avx512vl,avx2,aes,sse4.1")]
fn ctr32_xor_impl(rk: &RoundKeys, ctr: &[u8; 16], in_out: &mut [u8]) {
    let keys = load_keys(rk);
    let mut counter = Counter::new(ctr, keys[0]);
    let (groups, tail) = in_out.as_chunks_mut::<512>();
    for g in groups {
        let ks = counter.keystream::<8>(&keys, rk.rounds);
        let quads = g.as_chunks_mut::<16>().0.as_chunks_mut::<4>().0;
        for (quad, k) in quads.iter_mut().zip(ks) {
            store(quad, _mm512_xor_si512(load(quad), k));
        }
    }
    let regs = tail.len().div_ceil(64);
    if regs > 0 {
        dispatch_regs!(regs, ctr_tail(&keys, rk.rounds, &mut counter, tail));
    }
}

/// Encrypts `blocks` (1 to 31 of them) in place in exactly `N` registers
/// (`4 * (N - 1) < blocks.len() <= 4 * N`).
#[inline]
#[target_feature(enable = "vaes,avx512f,avx512bw")]
fn ecb_tail<const N: usize>(keys: &[__m512i; 15], nr: usize, blocks: &mut [[u8; 16]]) {
    debug_assert_eq!(blocks.len().div_ceil(4), N);
    let bytes = blocks.as_flattened_mut();
    let mut b: [__m512i; N] = [_mm512_setzero_si512(); N];
    for (x, chunk) in b.iter_mut().zip(bytes.chunks(64)) {
        *x = _mm512_xor_si512(load_partial(chunk), keys[0]);
    }
    rounds(keys, nr, &mut b);
    for (chunk, x) in bytes.chunks_mut(64).zip(b) {
        store_partial(chunk, x);
    }
}

#[target_feature(enable = "vaes,avx512f,avx512bw,avx512vl,avx2,aes,sse4.1")]
fn encrypt_blocks_impl(rk: &RoundKeys, blocks: &mut [[u8; 16]]) {
    let keys = load_keys(rk);
    let (groups, rest) = blocks.as_chunks_mut::<32>();
    for g in groups {
        let quads = g.as_chunks_mut::<4>().0;
        let mut b: [__m512i; 8] =
            core::array::from_fn(|i| _mm512_xor_si512(load(&quads[i]), keys[0]));
        rounds(&keys, rk.rounds, &mut b);
        for (dst, v) in quads.iter_mut().zip(b) {
            store(dst, v);
        }
    }
    let regs = rest.len().div_ceil(4);
    if regs > 0 {
        dispatch_regs!(regs, ecb_tail(&keys, rk.rounds, rest));
    }
}
