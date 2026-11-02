//! aarch64 four-way Keccak-f\[1600\]: two instances per Q register (two
//! passes), with Advanced SIMD or the Armv8.2 SHA3 instructions.
#![allow(unsafe_code)]

use core::arch::aarch64::{
    uint64x2_t, vbcaxq_u64, vbicq_u64, vdupq_n_u64, veor3q_u64, veorq_u64, vld1q_u64, vrax1q_u64,
    vshlq_n_u64, vsriq_n_u64, vst1q_u64, vxarq_u64,
};

use super::{Lanes, StateX4, permute, soft};
use crate::cpu::{self, Features};

pub(super) fn neon_available(f: Features) -> bool {
    f.arm_neon()
}

pub(super) fn sha3_available(f: Features) -> bool {
    f.arm_neon() && f.arm_sha3()
}

// SAFETY (all `unsafe` blocks in the `Lanes` impls below): `Neon` and `Sha3`
// values only exist inside `permute_neon` / `permute_sha3`, whose
// `#[target_feature]` attributes enable the instructions used, and which are
// only entered after run-time detection of those features.

/// Two Keccak lanes in a Q register, Advanced SIMD only.
#[derive(Clone, Copy)]
struct Neon(uint64x2_t);

#[target_feature(enable = "neon")]
#[inline]
fn rol_neon<const L: i32, const R: i32>(x: uint64x2_t) -> uint64x2_t {
    // SRI keeps the top R bits of `x << L` and inserts `x >> R` below them.
    vsriq_n_u64::<R>(vshlq_n_u64::<L>(x), x)
}

#[target_feature(enable = "neon")]
#[inline]
fn chi_neon(a: uint64x2_t, b: uint64x2_t, c: uint64x2_t) -> uint64x2_t {
    veorq_u64(a, vbicq_u64(c, b))
}

#[target_feature(enable = "neon")]
#[inline]
fn xor_rc_neon(a: uint64x2_t, rc: u64) -> uint64x2_t {
    veorq_u64(a, vdupq_n_u64(rc))
}

impl Lanes for Neon {
    #[inline(always)]
    fn xor(self, b: Self) -> Self {
        // SAFETY: see above (NEON).
        Self(unsafe { veorq_u64(self.0, b.0) })
    }
    #[inline(always)]
    fn rol<const L: i32, const R: i32>(self) -> Self {
        // SAFETY: see above (NEON).
        Self(unsafe { rol_neon::<L, R>(self.0) })
    }
    #[inline(always)]
    fn chi(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: see above (NEON).
        Self(unsafe { chi_neon(a.0, b.0, c.0) })
    }
    #[inline(always)]
    fn xor_rc(self, rc: u64) -> Self {
        // SAFETY: see above (NEON).
        Self(unsafe { xor_rc_neon(self.0, rc) })
    }
}

/// Two Keccak lanes in a Q register, using `EOR3`, `RAX1`, `XAR` and `BCAX`.
#[derive(Clone, Copy)]
struct Sha3(uint64x2_t);

#[target_feature(enable = "neon,sha3")]
#[inline]
fn xor5_sha3(
    a: uint64x2_t,
    b: uint64x2_t,
    c: uint64x2_t,
    d: uint64x2_t,
    e: uint64x2_t,
) -> uint64x2_t {
    veor3q_u64(veor3q_u64(a, b, c), d, e)
}

impl Lanes for Sha3 {
    #[inline(always)]
    fn xor(self, b: Self) -> Self {
        // SAFETY: see above (NEON).
        Self(unsafe { veorq_u64(self.0, b.0) })
    }
    #[inline(always)]
    fn xor5(a: Self, b: Self, c: Self, d: Self, e: Self) -> Self {
        // SAFETY: see above (SHA3).
        Self(unsafe { xor5_sha3(a.0, b.0, c.0, d.0, e.0) })
    }
    #[inline(always)]
    fn rol<const L: i32, const R: i32>(self) -> Self {
        // SAFETY: see above (NEON).
        Self(unsafe { rol_neon::<L, R>(self.0) })
    }
    #[inline(always)]
    fn theta_d(c_prev: Self, c_next: Self) -> Self {
        // RAX1: c_prev ^ rol(c_next, 1).
        // SAFETY: see above (SHA3).
        Self(unsafe { vrax1q_u64(c_prev.0, c_next.0) })
    }
    #[inline(always)]
    fn xor_rol<const L: i32, const R: i32>(a: Self, d: Self) -> Self {
        // XAR rotates right: rol by L == ror by R.
        // SAFETY: see above (SHA3).
        Self(unsafe { vxarq_u64::<R>(a.0, d.0) })
    }
    #[inline(always)]
    fn chi(a: Self, b: Self, c: Self) -> Self {
        // BCAX: a ^ (c & !b).
        // SAFETY: see above (SHA3).
        Self(unsafe { vbcaxq_u64(a.0, c.0, b.0) })
    }
    #[inline(always)]
    fn xor_rc(self, rc: u64) -> Self {
        // SAFETY: see above (NEON).
        Self(unsafe { xor_rc_neon(self.0, rc) })
    }
}

macro_rules! x2_kernel {
    ($name:ident, $lane:ident, $features:literal) => {
        /// Permutes instances `2*half` and `2*half + 1` of `s` (`half` is 0
        /// or 1).
        #[target_feature(enable = $features)]
        fn $name(s: &mut StateX4, half: usize) {
            let o = 2 * (half & 1);
            let mut a: [$lane; 25] = core::array::from_fn(|i| {
                let src: &[u64; 2] = s[i][o..].first_chunk().unwrap_or(&[0; 2]);
                // SAFETY: `src` is 16 readable bytes.
                $lane(unsafe { vld1q_u64(src.as_ptr()) })
            });
            permute(&mut a);
            for (lane, v) in s.iter_mut().zip(a) {
                if let Some(dst) = lane[o..].first_chunk_mut::<2>() {
                    // SAFETY: `dst` is 16 writable bytes.
                    unsafe { vst1q_u64(dst.as_mut_ptr(), v.0) };
                }
            }
        }
    };
}

x2_kernel!(permute_neon, Neon, "neon");
x2_kernel!(permute_sha3, Sha3, "neon,sha3");

/// Four-way permutation with Advanced SIMD.
pub(super) fn keccak_f1600_x4_neon(s: &mut StateX4) {
    if neon_available(cpu::features()) {
        // SAFETY: Advanced SIMD is available (checked at run time).
        unsafe { permute_neon(s, 0) };
        // SAFETY: as above.
        unsafe { permute_neon(s, 1) };
    } else {
        soft::keccak_f1600_x4(s);
    }
}

/// Four-way permutation with the SHA3 extension.
pub(super) fn keccak_f1600_x4_sha3(s: &mut StateX4) {
    if sha3_available(cpu::features()) {
        // SAFETY: FEAT_SHA3 and Advanced SIMD were detected at run time.
        unsafe { permute_sha3(s, 0) };
        // SAFETY: as above.
        unsafe { permute_sha3(s, 1) };
    } else {
        soft::keccak_f1600_x4(s);
    }
}
