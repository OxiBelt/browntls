//! x86-64 Keccak-f\[1600\] backends: BMI scalar, AVX2 and AVX-512VL four-way.
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m256i, _mm256_andnot_si256, _mm256_loadu_si256, _mm256_or_si256, _mm256_rol_epi64,
    _mm256_set1_epi64x, _mm256_slli_epi64, _mm256_srli_epi64, _mm256_storeu_si256,
    _mm256_ternarylogic_epi64, _mm256_xor_si256,
};

use super::{Lanes, StateX4, permute, soft};
use crate::cpu::{self, Features};

pub(super) fn bmi_available(f: Features) -> bool {
    // x86-64-v3 includes BMI1 and BMI2.
    f.x86_v3()
}

pub(super) fn avx2_available(f: Features) -> bool {
    f.x86_avx2()
}

pub(super) fn avx512_available(f: Features) -> bool {
    f.x86_avx512()
}

#[target_feature(enable = "bmi1,bmi2")]
fn permute_bmi(state: &mut [u64; 25]) {
    permute(state);
}

/// Scalar permutation compiled with `ANDN`/`RORX`.
pub(super) fn keccak_f1600_bmi(state: &mut [u64; 25]) {
    if bmi_available(cpu::features()) {
        // SAFETY: BMI1 and BMI2 were detected at run time.
        unsafe { permute_bmi(state) }
    } else {
        soft::keccak_f1600(state);
    }
}

/// Four Keccak lanes in a YMM register, using AVX2 only.
#[derive(Clone, Copy)]
struct Avx2(__m256i);

#[target_feature(enable = "avx2")]
#[inline]
fn rol_avx2<const L: i32, const R: i32>(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi64::<L>(x), _mm256_srli_epi64::<R>(x))
}

#[target_feature(enable = "avx2")]
#[inline]
fn chi_avx2(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
    _mm256_xor_si256(a, _mm256_andnot_si256(b, c))
}

#[target_feature(enable = "avx2")]
#[inline]
fn xor_rc_avx2(a: __m256i, rc: u64) -> __m256i {
    _mm256_xor_si256(a, _mm256_set1_epi64x(rc.cast_signed()))
}

// SAFETY (all `unsafe` blocks in the `Lanes` impls below): `Avx2` and
// `Avx512` values only exist inside `permute_avx2` / `permute_avx512`, whose
// `#[target_feature]` attributes enable the instructions used, and which are
// only entered after run-time detection of those features.
impl Lanes for Avx2 {
    #[inline(always)]
    fn xor(self, b: Self) -> Self {
        // SAFETY: see above (AVX2).
        Self(unsafe { _mm256_xor_si256(self.0, b.0) })
    }
    #[inline(always)]
    fn rol<const L: i32, const R: i32>(self) -> Self {
        // SAFETY: see above (AVX2).
        Self(unsafe { rol_avx2::<L, R>(self.0) })
    }
    #[inline(always)]
    fn chi(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: see above (AVX2).
        Self(unsafe { chi_avx2(a.0, b.0, c.0) })
    }
    #[inline(always)]
    fn xor_rc(self, rc: u64) -> Self {
        // SAFETY: see above (AVX2).
        Self(unsafe { xor_rc_avx2(self.0, rc) })
    }
}

/// Four Keccak lanes in a YMM register, using AVX-512VL `VPROLQ` and
/// `VPTERNLOGQ`.
#[derive(Clone, Copy)]
struct Avx512(__m256i);

/// Three-input XOR (`VPTERNLOGQ` truth table 0x96).
#[target_feature(enable = "avx512f,avx512vl")]
#[inline]
fn xor5_avx512(a: __m256i, b: __m256i, c: __m256i, d: __m256i, e: __m256i) -> __m256i {
    let t = _mm256_ternarylogic_epi64::<0x96>(a, b, c);
    _mm256_ternarylogic_epi64::<0x96>(t, d, e)
}

/// `a ^ (!b & c)` (`VPTERNLOGQ` truth table 0xD2).
#[target_feature(enable = "avx512f,avx512vl")]
#[inline]
fn chi_avx512(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
    _mm256_ternarylogic_epi64::<0xD2>(a, b, c)
}

impl Lanes for Avx512 {
    #[inline(always)]
    fn xor(self, b: Self) -> Self {
        // SAFETY: see above (AVX2).
        Self(unsafe { _mm256_xor_si256(self.0, b.0) })
    }
    #[inline(always)]
    fn xor5(a: Self, b: Self, c: Self, d: Self, e: Self) -> Self {
        // SAFETY: see above (AVX-512F/VL).
        Self(unsafe { xor5_avx512(a.0, b.0, c.0, d.0, e.0) })
    }
    #[inline(always)]
    fn rol<const L: i32, const R: i32>(self) -> Self {
        // SAFETY: see above (AVX-512F/VL).
        Self(unsafe { _mm256_rol_epi64::<L>(self.0) })
    }
    #[inline(always)]
    fn chi(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: see above (AVX-512F/VL).
        Self(unsafe { chi_avx512(a.0, b.0, c.0) })
    }
    #[inline(always)]
    fn xor_rc(self, rc: u64) -> Self {
        // SAFETY: see above (AVX2).
        Self(unsafe { xor_rc_avx2(self.0, rc) })
    }
}

macro_rules! x4_kernel {
    ($name:ident, $lane:ident, $features:literal) => {
        #[target_feature(enable = $features)]
        fn $name(s: &mut StateX4) {
            let mut a: [$lane; 25] = core::array::from_fn(|i| {
                // SAFETY: `s[i]` is 32 readable bytes; unaligned loads are
                // allowed.
                $lane(unsafe { _mm256_loadu_si256(s[i].as_ptr().cast()) })
            });
            permute(&mut a);
            for (dst, v) in s.iter_mut().zip(a) {
                // SAFETY: `dst` is 32 writable bytes; unaligned stores are
                // allowed.
                unsafe { _mm256_storeu_si256(dst.as_mut_ptr().cast(), v.0) };
            }
        }
    };
}

x4_kernel!(permute_avx2, Avx2, "avx2");
x4_kernel!(permute_avx512, Avx512, "avx2,avx512f,avx512vl");

/// Four-way permutation with AVX2.
pub(super) fn keccak_f1600_x4_avx2(s: &mut StateX4) {
    if avx2_available(cpu::features()) {
        // SAFETY: AVX2 (with OS YMM state) was detected at run time.
        unsafe { permute_avx2(s) }
    } else {
        soft::keccak_f1600_x4(s);
    }
}

/// Four-way permutation with AVX-512VL.
pub(super) fn keccak_f1600_x4_avx512(s: &mut StateX4) {
    if avx512_available(cpu::features()) {
        // SAFETY: AVX-512F/VL/BW/DQ (with OS ZMM state) were detected at run
        // time.
        unsafe { permute_avx512(s) }
    } else {
        soft::keccak_f1600_x4(s);
    }
}
