//! x86-64 AVX2 Poly1305: four interleaved accumulators in radix 2^26.
//!
//! For `n = 4k` blocks `m_0..m_{n-1}` and incoming accumulator `h`, lane `j`
//! accumulates blocks `j, j + 4, ...` with Horner steps by `r^4`; a final
//! multiplication of lane `j` by `r^(4 - j)` and a horizontal sum yield
//! `h r^n + sum m_i r^(n - i)`, exactly what `n` scalar steps produce. Limbs
//! stay below 2^27 between steps, `5 r_i < 2^29`, so every 32x32-bit product
//! sum fits in 64 bits. `VPMULUDQ` runs in data-independent time.
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m256i, _mm256_add_epi64, _mm256_and_si256, _mm256_loadu_si256, _mm256_or_si256,
    _mm256_permute4x64_epi64, _mm256_set1_epi64x, _mm256_setr_epi64x, _mm256_slli_epi64,
    _mm256_srli_epi64, _mm256_storeu_si256, _mm256_unpackhi_epi64, _mm256_unpacklo_epi64,
};

use super::poly1305::{BLOCK, State};
use crate::cpu::features;
use crate::zeroize::Zeroize;

/// Minimum input for the vector path; shorter inputs use scalar code, which
/// is faster below roughly 1 KiB because of the power precomputation and
/// final lane folding.
pub(super) const MIN_LEN: usize = 1024;

const M26: u64 = (1 << 26) - 1;

/// Splits a value `< 2^131` held as `[lo, hi, top]` into five 26-bit limbs
/// (the last limb takes the excess bits).
fn to_limbs(h: [u64; 3]) -> [u64; 5] {
    let [h0, h1, h2] = h;
    [
        h0 & M26,
        (h0 >> 26) & M26,
        ((h0 >> 52) | (h1 << 12)) & M26,
        (h1 >> 14) & M26,
        (h1 >> 40) | (h2 << 24),
    ]
}

/// Folds limbs `< 2^32` back into a partially reduced `[lo, hi, top]` with
/// `top <= 4`.
fn from_limbs(l: [u64; 5]) -> [u64; 3] {
    let mut l = l;
    for i in 0..4 {
        l[i + 1] += l[i] >> 26;
        l[i] &= M26;
    }
    let c = l[4] >> 26;
    l[4] &= M26;
    l[0] += c * 5;
    l[1] += l[0] >> 26;
    l[0] &= M26;
    // l0, l2, l3, l4 < 2^26 and l1 < 2^27: assemble with additions.
    let lo = u128::from(l[0])
        + (u128::from(l[1]) << 26)
        + (u128::from(l[2]) << 52)
        + (u128::from(l[3]) << 78);
    let (lo, carry) = lo.overflowing_add(u128::from(l[4] & 0xff_ffff) << 104);
    [
        lo as u64,
        (lo >> 64) as u64,
        (l[4] >> 24) + u64::from(carry),
    ]
}

/// Fully reduces a partially reduced accumulator modulo 2^130 - 5.
fn full_reduce(h: [u64; 3]) -> [u64; 3] {
    let [h0, h1, h2] = h;
    let t = u128::from(h0) + 5;
    let g0 = t as u64;
    let t = u128::from(h1) + (t >> 64);
    let g1 = t as u64;
    let g2 = h2 + (t >> 64) as u64;
    let mask = ((g2 >> 2) & 1).wrapping_neg();
    [
        h0 ^ (mask & (h0 ^ g0)),
        h1 ^ (mask & (h1 ^ g1)),
        h2 ^ (mask & (h2 ^ (g2 & 3))),
    ]
}

/// Five limbs of four lanes.
type Vec5 = [__m256i; 5];

#[target_feature(enable = "avx2")]
#[inline]
fn splat(l: &[u64; 5]) -> Vec5 {
    core::array::from_fn(|i| _mm256_set1_epi64x(l[i] as i64))
}

#[target_feature(enable = "avx2")]
#[inline]
fn times5(r: &Vec5) -> Vec5 {
    core::array::from_fn(|i| _mm256_add_epi64(r[i], _mm256_slli_epi64::<2>(r[i])))
}

/// `VPMULUDQ`: products of the low 32 bits of each 64-bit lane.
///
/// Written as assembly because LLVM otherwise drops the implicit 32-bit
/// masking of `_mm256_mul_epu32` operands it cannot bound and expands each
/// product into a three-multiply 64x64-bit sequence.
#[target_feature(enable = "avx2")]
#[inline]
fn mul32(a: __m256i, b: __m256i) -> __m256i {
    let out: __m256i;
    // SAFETY: VPMULUDQ reads and writes only the named YMM registers; AVX2
    // is enabled for this function and was detected by its callers.
    unsafe {
        core::arch::asm!(
            "vpmuludq {o}, {a}, {b}",
            o = lateout(ymm_reg) out,
            a = in(ymm_reg) a,
            b = in(ymm_reg) b,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    out
}

/// Dot product of five limb pairs: `sum a[i] * b[i]` (low 32 bits of each lane).
#[target_feature(enable = "avx2")]
#[inline]
fn dot(a: [__m256i; 5], b: [__m256i; 5]) -> __m256i {
    let p: [__m256i; 5] = core::array::from_fn(|i| mul32(a[i], b[i]));
    _mm256_add_epi64(
        _mm256_add_epi64(p[0], p[1]),
        _mm256_add_epi64(_mm256_add_epi64(p[2], p[3]), p[4]),
    )
}

/// `h * r` with a carry pass; `s = 5 r`.
#[target_feature(enable = "avx2")]
#[inline]
fn mul(h: &Vec5, r: &Vec5, s: &Vec5) -> Vec5 {
    let d0 = dot(*h, [r[0], s[4], s[3], s[2], s[1]]);
    let d1 = dot(*h, [r[1], r[0], s[4], s[3], s[2]]);
    let d2 = dot(*h, [r[2], r[1], r[0], s[4], s[3]]);
    let d3 = dot(*h, [r[3], r[2], r[1], r[0], s[4]]);
    let d4 = dot(*h, [r[4], r[3], r[2], r[1], r[0]]);
    carry([d0, d1, d2, d3, d4])
}

/// One sequential carry pass; outputs are `< 2^26` except limb 1 (`< 2^27`).
#[target_feature(enable = "avx2")]
#[inline]
fn carry(d: Vec5) -> Vec5 {
    let mask = _mm256_set1_epi64x(M26 as i64);
    let [mut d0, mut d1, mut d2, mut d3, mut d4] = d;
    d1 = _mm256_add_epi64(d1, _mm256_srli_epi64::<26>(d0));
    d0 = _mm256_and_si256(d0, mask);
    d2 = _mm256_add_epi64(d2, _mm256_srli_epi64::<26>(d1));
    d1 = _mm256_and_si256(d1, mask);
    d3 = _mm256_add_epi64(d3, _mm256_srli_epi64::<26>(d2));
    d2 = _mm256_and_si256(d2, mask);
    d4 = _mm256_add_epi64(d4, _mm256_srli_epi64::<26>(d3));
    d3 = _mm256_and_si256(d3, mask);
    let c = _mm256_srli_epi64::<26>(d4);
    d4 = _mm256_and_si256(d4, mask);
    d0 = _mm256_add_epi64(d0, _mm256_add_epi64(c, _mm256_slli_epi64::<2>(c)));
    d1 = _mm256_add_epi64(d1, _mm256_srli_epi64::<26>(d0));
    d0 = _mm256_and_si256(d0, mask);
    [d0, d1, d2, d3, d4]
}

/// Loads four blocks (one per lane, in order) as 26-bit limbs with the
/// 2^128 pad bit.
#[target_feature(enable = "avx2")]
#[inline]
fn load(m: &[u8; 4 * BLOCK]) -> Vec5 {
    let (a, b) = m.split_at(32);
    // SAFETY: `a` and `b` are 32 readable bytes each; unaligned loads.
    let a = unsafe { _mm256_loadu_si256(a.as_ptr().cast()) };
    // SAFETY: as above.
    let b = unsafe { _mm256_loadu_si256(b.as_ptr().cast()) };
    // a = [lo0 hi0 lo1 hi1], b = [lo2 hi2 lo3 hi3].
    let lo = _mm256_permute4x64_epi64::<0xd8>(_mm256_unpacklo_epi64(a, b));
    let hi = _mm256_permute4x64_epi64::<0xd8>(_mm256_unpackhi_epi64(a, b));
    let mask = _mm256_set1_epi64x(M26 as i64);
    [
        _mm256_and_si256(lo, mask),
        _mm256_and_si256(_mm256_srli_epi64::<26>(lo), mask),
        _mm256_and_si256(
            _mm256_or_si256(_mm256_srli_epi64::<52>(lo), _mm256_slli_epi64::<12>(hi)),
            mask,
        ),
        _mm256_and_si256(_mm256_srli_epi64::<14>(hi), mask),
        _mm256_or_si256(_mm256_srli_epi64::<40>(hi), _mm256_set1_epi64x(1 << 24)),
    ]
}

#[target_feature(enable = "avx2")]
#[inline]
fn add5(a: &Vec5, b: &Vec5) -> Vec5 {
    core::array::from_fn(|i| _mm256_add_epi64(a[i], b[i]))
}

#[target_feature(enable = "avx2,bmi2")]
fn blocks_inner(state: &mut State, data: &[u8]) {
    let (groups, rest) = data.as_chunks::<{ 4 * BLOCK }>();
    if let Some((first, groups)) = groups.split_first() {
        // Powers r^1..r^4, fully reduced so every limb is < 2^26.
        let mut pow = [[0u64; 5]; 4];
        let mut p = State {
            r: state.r,
            h: [1, 0, 0],
        };
        for limbs in &mut pow {
            p.blocks(&[0; BLOCK], 0);
            *limbs = to_limbs(full_reduce(p.h));
        }
        p.zeroize();
        let r4 = splat(&pow[3]);
        let s4 = times5(&r4);
        // Lane j finishes with r^(4 - j).
        let rf: Vec5 = core::array::from_fn(|i| {
            _mm256_setr_epi64x(
                pow[3][i] as i64,
                pow[2][i] as i64,
                pow[1][i] as i64,
                pow[0][i] as i64,
            )
        });
        let sf = times5(&rf);
        pow.iter_mut().for_each(|l| l.zeroize());

        let h_in = to_limbs(state.h);
        let mut acc = load(first);
        acc = add5(
            &acc,
            &core::array::from_fn(|i| _mm256_setr_epi64x(h_in[i] as i64, 0, 0, 0)),
        );
        for g in groups {
            acc = add5(&mul(&acc, &r4, &s4), &load(g));
        }
        acc = mul(&acc, &rf, &sf);
        let mut lanes = [[0u64; 4]; 5];
        for (dst, v) in lanes.iter_mut().zip(acc) {
            // SAFETY: `dst` is 32 writable bytes; unaligned store.
            unsafe { _mm256_storeu_si256(dst.as_mut_ptr().cast(), v) };
        }
        let mut sum = [0u64; 5];
        for (s, l) in sum.iter_mut().zip(&lanes) {
            *s = l.iter().sum();
        }
        state.h = from_limbs(sum);
        lanes.iter_mut().for_each(|l| l.zeroize());
        sum.zeroize();
    }
    state.blocks(rest, 1);
}

/// AVX2 Poly1305 block function; short inputs (and CPUs without AVX2) use
/// the scalar code.
pub(super) fn blocks(state: &mut State, data: &[u8]) {
    if features().x86_v3() && data.len() >= MIN_LEN {
        // SAFETY: AVX2 and BMI2 (part of x86-64-v3) were detected at run time.
        unsafe { blocks_inner(state, data) }
    } else {
        super::x86::poly1305_blocks_bmi2(state, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_round_trip() {
        for h in [
            [0, 0, 0],
            [u64::MAX, u64::MAX, 3],
            [1 << 63, 12345, 4],
            [5, 0, 4],
        ] {
            let back = from_limbs(to_limbs(h));
            // Equal modulo 2^130 - 5 after full reduction.
            assert_eq!(full_reduce(back), full_reduce(h), "{h:?}");
        }
    }
}
