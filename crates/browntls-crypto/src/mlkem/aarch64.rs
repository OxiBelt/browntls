//! aarch64 Advanced SIMD (NEON) backend: NTT, inverse NTT, base
//! multiplication and reductions on 8 x i16 lanes.
//!
//! Montgomery multiplication is `(sqdmulh(a, b) - sqdmulh(a b q^-1, q)) / 2`
//! (via `shsub`), which equals the portable `(a b - t q) >> 16` exactly;
//! Barrett reduction is `a - q * srshr(sqdmulh(a, 20159), 11)`, which equals
//! the portable two-step rounding exactly. Results are therefore
//! bit-identical to the portable backend, with coefficients kept in the
//! canonical FIPS 203 order.
//!
//! The module is compiled only when NEON is enabled at build time (it is part
//! of every aarch64 Linux/macOS target).
#![allow(unsafe_code)]

use core::arch::aarch64::*;

use super::poly::{
    BARRETT_V, GAMMAS, GAMMAS_QINV, INVNTT_F, MONT_R2, Poly, Q, QINV, ZETAS, ZETAS_QINV, qinv_table,
};

type Vecs = [int16x8_t; 32];

/// Offset (within a 16-coefficient vector pair) of the coefficient held by
/// lane `l` of the shuffled "x" operand of layer `len` (4 or 2).
const fn lane_offset(len: usize, l: usize) -> usize {
    if len == 4 {
        if l < 4 { l } else { 8 + l - 4 }
    } else {
        [0, 4, 8, 12][l / 2] + l % 2
    }
}

const fn intra_zetas(len: usize, inverse: bool) -> [[i16; 8]; 16] {
    let mut t = [[0i16; 8]; 16];
    let mut m = 0;
    while m < 16 {
        let mut l = 0;
        while l < 8 {
            let block = (16 * m + lane_offset(len, l)) / (2 * len);
            let idx = if inverse {
                256 / len - 1 - block
            } else {
                128 / len + block
            };
            t[m][l] = ZETAS[idx];
            l += 1;
        }
        m += 1;
    }
    t
}

const fn qinv2(t: [[i16; 8]; 16]) -> [[i16; 8]; 16] {
    let mut o = [[0i16; 8]; 16];
    let mut m = 0;
    while m < 16 {
        o[m] = qinv_table(t[m]);
        m += 1;
    }
    o
}

struct Tables {
    /// Index 0, 1 = layer length 4, 2.
    fwd: [[[i16; 8]; 16]; 2],
    fwd_q: [[[i16; 8]; 16]; 2],
    inv: [[[i16; 8]; 16]; 2],
    inv_q: [[[i16; 8]; 16]; 2],
}

static TABLES: Tables = Tables {
    fwd: [intra_zetas(4, false), intra_zetas(2, false)],
    fwd_q: [qinv2(intra_zetas(4, false)), qinv2(intra_zetas(2, false))],
    inv: [intra_zetas(4, true), intra_zetas(2, true)],
    inv_q: [qinv2(intra_zetas(4, true)), qinv2(intra_zetas(2, true))],
};

#[inline]
#[target_feature(enable = "neon")]
fn ld(s: &[i16]) -> int16x8_t {
    let s = &s[..8];
    // SAFETY: `s` holds 8 `i16`s; `ld1` has no alignment requirement beyond `i16`.
    unsafe { vld1q_s16(s.as_ptr()) }
}

#[inline]
#[target_feature(enable = "neon")]
fn st(s: &mut [i16], v: int16x8_t) {
    let s = &mut s[..8];
    // SAFETY: `s` holds 8 `i16`s; `st1` has no alignment requirement beyond `i16`.
    unsafe { vst1q_s16(s.as_mut_ptr(), v) }
}

#[inline]
#[target_feature(enable = "neon")]
fn load(p: &Poly) -> Vecs {
    let mut v = [vdupq_n_s16(0); 32];
    for (i, x) in v.iter_mut().enumerate() {
        *x = ld(&p.0[8 * i..]);
    }
    v
}

#[inline]
#[target_feature(enable = "neon")]
fn store(p: &mut Poly, v: &Vecs) {
    for (i, x) in v.iter().enumerate() {
        st(&mut p.0[8 * i..], *x);
    }
}

/// `a b 2^-16 mod q` with `bq = b q^-1 mod 2^16` precomputed (`|b| < 2^15`).
#[inline]
#[target_feature(enable = "neon")]
fn fqmul_pre(a: int16x8_t, b: int16x8_t, bq: int16x8_t) -> int16x8_t {
    let hi = vqdmulhq_s16(a, b);
    let t = vmulq_s16(a, bq);
    let c = vqdmulhq_s16(t, vdupq_n_s16(Q));
    vhsubq_s16(hi, c)
}

/// `a b 2^-16 mod q` (`a`, `b` not both `-2^15`).
#[inline]
#[target_feature(enable = "neon")]
fn fqmul(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    let hi = vqdmulhq_s16(a, b);
    let t = vmulq_s16(vmulq_s16(a, b), vdupq_n_s16(QINV));
    let c = vqdmulhq_s16(t, vdupq_n_s16(Q));
    vhsubq_s16(hi, c)
}

#[inline]
#[target_feature(enable = "neon")]
fn barrett(a: int16x8_t) -> int16x8_t {
    let t = vqdmulhq_s16(a, vdupq_n_s16(BARRETT_V));
    let t = vrshrq_n_s16::<11>(t);
    vmlsq_s16(a, t, vdupq_n_s16(Q))
}

#[inline]
#[target_feature(enable = "neon")]
fn ct_bfly(a: &mut int16x8_t, b: &mut int16x8_t, z: int16x8_t, zq: int16x8_t) {
    let t = fqmul_pre(*b, z, zq);
    *b = vsubq_s16(*a, t);
    *a = vaddq_s16(*a, t);
}

#[inline]
#[target_feature(enable = "neon")]
fn gs_bfly(a: &mut int16x8_t, b: &mut int16x8_t, z: int16x8_t, zq: int16x8_t) {
    let t = *a;
    *a = barrett(vaddq_s16(t, *b));
    *b = fqmul_pre(vsubq_s16(*b, t), z, zq);
}

#[inline]
#[target_feature(enable = "neon")]
fn inter_layer(v: &mut Vecs, len: usize, inverse: bool) {
    let lv = len / 8;
    let nblocks = 128 / len;
    for b in 0..nblocks {
        let k = if inverse {
            256 / len - 1 - b
        } else {
            nblocks + b
        };
        let z = vdupq_n_s16(ZETAS[k]);
        let zq = vdupq_n_s16(ZETAS_QINV[k]);
        for i in 0..lv {
            let (x, y) = (2 * lv * b + i, 2 * lv * b + i + lv);
            let (mut a, mut c) = (v[x], v[y]);
            if inverse {
                gs_bfly(&mut a, &mut c, z, zq);
            } else {
                ct_bfly(&mut a, &mut c, z, zq);
            }
            v[x] = a;
            v[y] = c;
        }
    }
}

#[inline]
#[target_feature(enable = "neon")]
fn split(len: usize, a: int16x8_t, b: int16x8_t) -> (int16x8_t, int16x8_t) {
    if len == 4 {
        let (a, b) = (vreinterpretq_s64_s16(a), vreinterpretq_s64_s16(b));
        (
            vreinterpretq_s16_s64(vtrn1q_s64(a, b)),
            vreinterpretq_s16_s64(vtrn2q_s64(a, b)),
        )
    } else {
        let (a, b) = (vreinterpretq_s32_s16(a), vreinterpretq_s32_s16(b));
        (
            vreinterpretq_s16_s32(vuzp1q_s32(a, b)),
            vreinterpretq_s16_s32(vuzp2q_s32(a, b)),
        )
    }
}

#[inline]
#[target_feature(enable = "neon")]
fn merge(len: usize, x: int16x8_t, y: int16x8_t) -> (int16x8_t, int16x8_t) {
    if len == 4 {
        let (x, y) = (vreinterpretq_s64_s16(x), vreinterpretq_s64_s16(y));
        (
            vreinterpretq_s16_s64(vtrn1q_s64(x, y)),
            vreinterpretq_s16_s64(vtrn2q_s64(x, y)),
        )
    } else {
        let (x, y) = (vreinterpretq_s32_s16(x), vreinterpretq_s32_s16(y));
        (
            vreinterpretq_s16_s32(vzip1q_s32(x, y)),
            vreinterpretq_s16_s32(vzip2q_s32(x, y)),
        )
    }
}

#[inline]
#[target_feature(enable = "neon")]
fn intra_layer(a: &mut int16x8_t, b: &mut int16x8_t, layer: usize, m: usize, inverse: bool) {
    let len = 4 >> layer;
    let (mut x, mut y) = split(len, *a, *b);
    if inverse {
        let (z, zq) = (ld(&TABLES.inv[layer][m]), ld(&TABLES.inv_q[layer][m]));
        gs_bfly(&mut x, &mut y, z, zq);
    } else {
        let (z, zq) = (ld(&TABLES.fwd[layer][m]), ld(&TABLES.fwd_q[layer][m]));
        ct_bfly(&mut x, &mut y, z, zq);
    }
    (*a, *b) = merge(len, x, y);
}

/// Forward NTT followed by Barrett reduction.
#[target_feature(enable = "neon")]
fn ntt_neon(p: &mut Poly) {
    let mut v = load(p);
    for len in [128, 64, 32, 16, 8] {
        inter_layer(&mut v, len, false);
    }
    for m in 0..16 {
        let (mut a, mut b) = (v[2 * m], v[2 * m + 1]);
        intra_layer(&mut a, &mut b, 0, m, false);
        intra_layer(&mut a, &mut b, 1, m, false);
        v[2 * m] = barrett(a);
        v[2 * m + 1] = barrett(b);
    }
    store(p, &v);
}

/// Inverse NTT including the final scaling.
#[target_feature(enable = "neon")]
fn invntt_neon(p: &mut Poly) {
    let mut v = load(p);
    for m in 0..16 {
        let (mut a, mut b) = (v[2 * m], v[2 * m + 1]);
        intra_layer(&mut a, &mut b, 1, m, true);
        intra_layer(&mut a, &mut b, 0, m, true);
        v[2 * m] = a;
        v[2 * m + 1] = b;
    }
    for len in [8, 16, 32, 64, 128] {
        inter_layer(&mut v, len, true);
    }
    let f = vdupq_n_s16(INVNTT_F);
    let fq = vdupq_n_s16(INVNTT_F.wrapping_mul(QINV));
    for x in v.iter_mut() {
        *x = fqmul_pre(*x, f, fq);
    }
    store(p, &v);
}

#[inline]
#[target_feature(enable = "neon")]
fn ld2(s: &[i16]) -> int16x8x2_t {
    let s = &s[..16];
    // SAFETY: `s` holds 16 `i16`s, exactly what `ld2` reads.
    unsafe { vld2q_s16(s.as_ptr()) }
}

/// `r = reduce(sum a[i] o b[i])`.
#[target_feature(enable = "neon")]
fn basemul_acc_neon(r: &mut Poly, a: &[Poly], b: &[Poly]) {
    for c in 0..16 {
        let g = ld(&GAMMAS[8 * c..]);
        let gq = ld(&GAMMAS_QINV[8 * c..]);
        let mut ce = vdupq_n_s16(0);
        let mut co = vdupq_n_s16(0);
        for (x, y) in a.iter().zip(b) {
            let xa = ld2(&x.0[16 * c..]);
            let yb = ld2(&y.0[16 * c..]);
            let (ae, ao, be, bo) = (xa.0, xa.1, yb.0, yb.1);
            let t = fqmul_pre(fqmul(ao, bo), g, gq);
            ce = vaddq_s16(ce, vaddq_s16(t, fqmul(ae, be)));
            co = vaddq_s16(co, vaddq_s16(fqmul(ae, bo), fqmul(ao, be)));
        }
        let pair = int16x8x2_t(barrett(ce), barrett(co));
        let out = &mut r.0[16 * c..16 * c + 16];
        // SAFETY: `out` holds 16 `i16`s, exactly what `st2` writes.
        unsafe { vst2q_s16(out.as_mut_ptr(), pair) };
    }
}

/// Barrett-reduces every coefficient.
#[target_feature(enable = "neon")]
fn reduce_neon(p: &mut Poly) {
    for c in p.0.as_chunks_mut::<8>().0 {
        let v = barrett(ld(c));
        st(c, v);
    }
}

/// Multiplies every coefficient by `2^16`.
#[target_feature(enable = "neon")]
fn tomont_neon(p: &mut Poly) {
    let f = vdupq_n_s16(MONT_R2);
    let fq = vdupq_n_s16(MONT_R2.wrapping_mul(QINV));
    for c in p.0.as_chunks_mut::<8>().0 {
        let v = fqmul_pre(ld(c), f, fq);
        st(c, v);
    }
}

// Safe entry points. Callers hold an `Engine` for `Backend::Neon`, which is
// only constructed when NEON is available (see `backend::Engine`).
macro_rules! entry {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) => $imp:ident;)*) => {$(
        pub(super) fn $name($($arg: $ty),*) {
            // SAFETY: this module is compiled only with NEON enabled at build
            // time, and it is only reached through an `Engine` for
            // `Backend::Neon`, which requires NEON to be detected.
            unsafe { $imp($($arg),*) }
        }
    )*};
}

entry! {
    fn ntt(p: &mut Poly) => ntt_neon;
    fn invntt(p: &mut Poly) => invntt_neon;
    fn basemul_acc(r: &mut Poly, a: &[Poly], b: &[Poly]) => basemul_acc_neon;
    fn reduce(p: &mut Poly) => reduce_neon;
    fn tomont(p: &mut Poly) => tomont_neon;
}
