//! x86-64 AVX2 backend: NTT, inverse NTT, base multiplication and reductions
//! on 16 x i16 lanes, plus vectorised uniform rejection sampling.
//!
//! Montgomery multiplication is `mulhi(a, b) - mulhi(mullo(a, b q^-1), q)`,
//! which equals the portable `(a b - t q) >> 16` exactly, and Barrett
//! reduction is `a - q * mulhrs(mulhi(a, 20159), 32)`, which equals the
//! portable two-step rounding exactly; the results are therefore
//! bit-identical to the portable backend. Coefficients stay in the canonical
//! FIPS 203 order: the last three NTT layers shuffle pairs of vectors into
//! butterfly position and back.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use super::poly::{
    BARRETT_V, GAMMAS, INVNTT_F, MONT_R2, N, Poly, Q, QINV, ZETAS, ZETAS_QINV, qinv_table,
};

type Vecs = [__m256i; 16];

// ---------------------------------------------------------------------------
// Tables.
// ---------------------------------------------------------------------------

/// Offset (within a 32-coefficient pair of vectors) of the coefficient that
/// lane `l` of the shuffled "x" vector holds in the butterfly layer `len`.
const fn lane_offset(len: usize, l: usize) -> usize {
    match len {
        8 => {
            if l < 8 {
                l
            } else {
                16 + l - 8
            }
        }
        4 => [0, 16, 8, 24][l / 4] + l % 4,
        _ => [0, 4, 16, 20, 8, 12, 24, 28][l / 2] + l % 2,
    }
}

/// Per-lane zetas for the intra-vector layer `len` (8, 4 or 2) for each of
/// the eight vector pairs.
const fn intra_zetas(len: usize, inverse: bool) -> [[i16; 16]; 8] {
    let mut t = [[0i16; 16]; 8];
    let mut m = 0;
    while m < 8 {
        let mut l = 0;
        while l < 16 {
            let block = (32 * m + lane_offset(len, l)) / (2 * len);
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

const fn qinv2(t: [[i16; 16]; 8]) -> [[i16; 16]; 8] {
    let mut o = [[0i16; 16]; 8];
    let mut m = 0;
    while m < 8 {
        o[m] = qinv_table(t[m]);
        m += 1;
    }
    o
}

/// Lane `l` of the de-interleaved even/odd vectors holds pair `16 m + PAIR[l]`.
const PAIR: [usize; 16] = [0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15];

const fn gamma_table() -> [[i16; 16]; 8] {
    let mut t = [[0i16; 16]; 8];
    let mut m = 0;
    while m < 8 {
        let mut l = 0;
        while l < 16 {
            t[m][l] = GAMMAS[16 * m + PAIR[l]];
            l += 1;
        }
        m += 1;
    }
    t
}

struct Tables {
    fwd: [[[i16; 16]; 8]; 3],
    fwd_q: [[[i16; 16]; 8]; 3],
    inv: [[[i16; 16]; 8]; 3],
    inv_q: [[[i16; 16]; 8]; 3],
    gamma: [[i16; 16]; 8],
    gamma_q: [[i16; 16]; 8],
}

/// Index 0, 1, 2 = layer length 8, 4, 2.
static TABLES: Tables = Tables {
    fwd: [
        intra_zetas(8, false),
        intra_zetas(4, false),
        intra_zetas(2, false),
    ],
    fwd_q: [
        qinv2(intra_zetas(8, false)),
        qinv2(intra_zetas(4, false)),
        qinv2(intra_zetas(2, false)),
    ],
    inv: [
        intra_zetas(8, true),
        intra_zetas(4, true),
        intra_zetas(2, true),
    ],
    inv_q: [
        qinv2(intra_zetas(8, true)),
        qinv2(intra_zetas(4, true)),
        qinv2(intra_zetas(2, true)),
    ],
    gamma: gamma_table(),
    gamma_q: qinv2(gamma_table()),
};

/// `idx[m]`: byte offsets (`2 j`) of the set bits `j` of `m`, then `0xff`.
static REJ_IDX: [[u8; 8]; 256] = {
    let mut t = [[0xffu8; 8]; 256];
    let mut m = 0;
    while m < 256 {
        let mut n = 0;
        let mut j = 0;
        while j < 8 {
            if m & (1 << j) != 0 {
                t[m][n] = 2 * j as u8;
                n += 1;
            }
            j += 1;
        }
        m += 1;
    }
    t
};

// ---------------------------------------------------------------------------
// Lane arithmetic.
// ---------------------------------------------------------------------------

#[inline]
#[target_feature(enable = "avx2")]
fn ld(s: &[i16]) -> __m256i {
    let s = &s[..16];
    // SAFETY: `s` holds 16 `i16`s (32 bytes); `loadu` has no alignment requirement.
    unsafe { _mm256_loadu_si256(s.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn st(s: &mut [i16], v: __m256i) {
    let s = &mut s[..16];
    // SAFETY: `s` holds 16 `i16`s (32 bytes); `storeu` has no alignment requirement.
    unsafe { _mm256_storeu_si256(s.as_mut_ptr().cast(), v) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn ld_bytes(s: &[u8]) -> __m256i {
    let s = &s[..32];
    // SAFETY: `s` holds 32 bytes; `loadu` has no alignment requirement.
    unsafe { _mm256_loadu_si256(s.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn load(p: &Poly) -> Vecs {
    let mut v = [_mm256_setzero_si256(); 16];
    for (i, x) in v.iter_mut().enumerate() {
        *x = ld(&p.0[16 * i..]);
    }
    v
}

#[inline]
#[target_feature(enable = "avx2")]
fn store(p: &mut Poly, v: &Vecs) {
    for (i, x) in v.iter().enumerate() {
        st(&mut p.0[16 * i..], *x);
    }
}

/// `a b 2^-16 mod q` with `bq = b q^-1 mod 2^16` precomputed.
#[inline]
#[target_feature(enable = "avx2")]
fn fqmul_pre(a: __m256i, b: __m256i, bq: __m256i) -> __m256i {
    let hi = _mm256_mulhi_epi16(a, b);
    let t = _mm256_mullo_epi16(a, bq);
    let c = _mm256_mulhi_epi16(t, _mm256_set1_epi16(Q));
    _mm256_sub_epi16(hi, c)
}

/// `a b 2^-16 mod q`.
#[inline]
#[target_feature(enable = "avx2")]
fn fqmul(a: __m256i, b: __m256i) -> __m256i {
    let hi = _mm256_mulhi_epi16(a, b);
    let t = _mm256_mullo_epi16(_mm256_mullo_epi16(a, b), _mm256_set1_epi16(QINV));
    let c = _mm256_mulhi_epi16(t, _mm256_set1_epi16(Q));
    _mm256_sub_epi16(hi, c)
}

#[inline]
#[target_feature(enable = "avx2")]
fn barrett(a: __m256i) -> __m256i {
    let t = _mm256_mulhi_epi16(a, _mm256_set1_epi16(BARRETT_V));
    let t = _mm256_mulhrs_epi16(t, _mm256_set1_epi16(32));
    let t = _mm256_mullo_epi16(t, _mm256_set1_epi16(Q));
    _mm256_sub_epi16(a, t)
}

#[inline]
#[target_feature(enable = "avx2")]
fn ct_bfly(a: &mut __m256i, b: &mut __m256i, z: __m256i, zq: __m256i) {
    let t = fqmul_pre(*b, z, zq);
    *b = _mm256_sub_epi16(*a, t);
    *a = _mm256_add_epi16(*a, t);
}

#[inline]
#[target_feature(enable = "avx2")]
fn gs_bfly(a: &mut __m256i, b: &mut __m256i, z: __m256i, zq: __m256i) {
    let t = *a;
    *a = barrett(_mm256_add_epi16(t, *b));
    *b = fqmul_pre(_mm256_sub_epi16(*b, t), z, zq);
}

/// Butterflies between whole vectors `v[i]` and `v[i + lv]`.
#[inline]
#[target_feature(enable = "avx2")]
fn inter_layer(v: &mut Vecs, len: usize, inverse: bool) {
    let lv = len / 16;
    let nblocks = 128 / len;
    for b in 0..nblocks {
        let k = if inverse {
            256 / len - 1 - b
        } else {
            nblocks + b
        };
        let z = _mm256_set1_epi16(ZETAS[k]);
        let zq = _mm256_set1_epi16(ZETAS_QINV[k]);
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

/// Moves the operands of layer `len` (8, 4, 2) of the vector pair `(a, b)`
/// into butterfly position.
#[inline]
#[target_feature(enable = "avx2")]
fn split(len: usize, a: __m256i, b: __m256i) -> (__m256i, __m256i) {
    match len {
        8 => (
            _mm256_permute2x128_si256::<0x20>(a, b),
            _mm256_permute2x128_si256::<0x31>(a, b),
        ),
        4 => (_mm256_unpacklo_epi64(a, b), _mm256_unpackhi_epi64(a, b)),
        _ => {
            let (fa, fb) = (_mm256_castsi256_ps(a), _mm256_castsi256_ps(b));
            (
                _mm256_castps_si256(_mm256_shuffle_ps::<0x88>(fa, fb)),
                _mm256_castps_si256(_mm256_shuffle_ps::<0xdd>(fa, fb)),
            )
        }
    }
}

/// Inverse of [`split`].
#[inline]
#[target_feature(enable = "avx2")]
fn merge(len: usize, x: __m256i, y: __m256i) -> (__m256i, __m256i) {
    match len {
        8 => (
            _mm256_permute2x128_si256::<0x20>(x, y),
            _mm256_permute2x128_si256::<0x31>(x, y),
        ),
        4 => (_mm256_unpacklo_epi64(x, y), _mm256_unpackhi_epi64(x, y)),
        _ => (_mm256_unpacklo_epi32(x, y), _mm256_unpackhi_epi32(x, y)),
    }
}

#[inline]
#[target_feature(enable = "avx2")]
fn intra_layer(a: &mut __m256i, b: &mut __m256i, layer: usize, m: usize, inverse: bool) {
    let len = 8 >> layer;
    let (mut x, mut y) = split(len, *a, *b);
    if inverse {
        let z = ld(&TABLES.inv[layer][m]);
        let zq = ld(&TABLES.inv_q[layer][m]);
        gs_bfly(&mut x, &mut y, z, zq);
    } else {
        let z = ld(&TABLES.fwd[layer][m]);
        let zq = ld(&TABLES.fwd_q[layer][m]);
        ct_bfly(&mut x, &mut y, z, zq);
    }
    (*a, *b) = merge(len, x, y);
}

#[target_feature(enable = "avx2")]
fn ntt_avx2(p: &mut Poly) {
    let mut v = load(p);
    for len in [128, 64, 32, 16] {
        inter_layer(&mut v, len, false);
    }
    for m in 0..8 {
        let (mut a, mut b) = (v[2 * m], v[2 * m + 1]);
        for layer in 0..3 {
            intra_layer(&mut a, &mut b, layer, m, false);
        }
        v[2 * m] = barrett(a);
        v[2 * m + 1] = barrett(b);
    }
    store(p, &v);
}

#[target_feature(enable = "avx2")]
fn invntt_avx2(p: &mut Poly) {
    let mut v = load(p);
    for m in 0..8 {
        let (mut a, mut b) = (v[2 * m], v[2 * m + 1]);
        for layer in (0..3).rev() {
            intra_layer(&mut a, &mut b, layer, m, true);
        }
        v[2 * m] = a;
        v[2 * m + 1] = b;
    }
    for len in [16, 32, 64, 128] {
        inter_layer(&mut v, len, true);
    }
    let f = _mm256_set1_epi16(INVNTT_F);
    let fq = _mm256_set1_epi16(INVNTT_F.wrapping_mul(QINV));
    for x in v.iter_mut() {
        *x = fqmul_pre(*x, f, fq);
    }
    store(p, &v);
}

#[target_feature(enable = "avx2")]
fn basemul_acc_avx2(r: &mut Poly, a: &[Poly], b: &[Poly]) {
    #[rustfmt::skip]
    let deint = _mm256_setr_epi8(
        0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15,
        0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15,
    );
    #[rustfmt::skip]
    let inter = _mm256_setr_epi8(
        0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15,
        0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15,
    );
    for m in 0..8 {
        let g = ld(&TABLES.gamma[m]);
        let gq = ld(&TABLES.gamma_q[m]);
        let mut ce = _mm256_setzero_si256();
        let mut co = _mm256_setzero_si256();
        for (x, y) in a.iter().zip(b) {
            let u = _mm256_shuffle_epi8(ld(&x.0[32 * m..]), deint);
            let w = _mm256_shuffle_epi8(ld(&x.0[32 * m + 16..]), deint);
            let (ae, ao) = (_mm256_unpacklo_epi64(u, w), _mm256_unpackhi_epi64(u, w));
            let u = _mm256_shuffle_epi8(ld(&y.0[32 * m..]), deint);
            let w = _mm256_shuffle_epi8(ld(&y.0[32 * m + 16..]), deint);
            let (be, bo) = (_mm256_unpacklo_epi64(u, w), _mm256_unpackhi_epi64(u, w));
            let t = fqmul_pre(fqmul(ao, bo), g, gq);
            ce = _mm256_add_epi16(ce, _mm256_add_epi16(t, fqmul(ae, be)));
            co = _mm256_add_epi16(co, _mm256_add_epi16(fqmul(ae, bo), fqmul(ao, be)));
        }
        let (ce, co) = (barrett(ce), barrett(co));
        let u = _mm256_shuffle_epi8(_mm256_unpacklo_epi64(ce, co), inter);
        let w = _mm256_shuffle_epi8(_mm256_unpackhi_epi64(ce, co), inter);
        st(&mut r.0[32 * m..], u);
        st(&mut r.0[32 * m + 16..], w);
    }
}

#[target_feature(enable = "avx2")]
fn reduce_avx2(p: &mut Poly) {
    for c in p.0.as_chunks_mut::<16>().0 {
        let v = barrett(ld(c));
        st(c, v);
    }
}

#[target_feature(enable = "avx2")]
fn tomont_avx2(p: &mut Poly) {
    let f = _mm256_set1_epi16(MONT_R2);
    let fq = _mm256_set1_epi16(MONT_R2.wrapping_mul(QINV));
    for c in p.0.as_chunks_mut::<16>().0 {
        let v = fqmul_pre(ld(c), f, fq);
        st(c, v);
    }
}

#[inline]
#[target_feature(enable = "avx2")]
fn idx_lo(m: u32) -> __m128i {
    let e = &REJ_IDX[(m & 0xff) as usize];
    // SAFETY: `e` is an 8-byte array; `loadl_epi64` reads exactly 8 bytes.
    unsafe { _mm_loadl_epi64(e.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn store8(out: &mut [i16; N], ctr: usize, v: __m128i) {
    let s = &mut out[ctr..ctr + 8];
    // SAFETY: `s` holds 8 `i16`s (16 bytes); `storeu` has no alignment requirement.
    unsafe { _mm_storeu_si128(s.as_mut_ptr().cast(), v) }
}

/// Uniform rejection sampling (public data, variable time).
#[target_feature(enable = "avx2")]
fn rej_uniform_avx2(out: &mut [i16; N], mut ctr: usize, buf: &[u8]) -> usize {
    let bound = _mm256_set1_epi16(Q);
    let mask = _mm256_set1_epi16(0xfff);
    let ones = _mm256_set1_epi8(1);
    #[rustfmt::skip]
    let idx8 = _mm256_setr_epi8(
        0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11,
        4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11, 12, 13, 14, 14, 15,
    );
    let mut pos = 0;
    while ctr <= N - 32 && pos + 56 <= buf.len() {
        let (f0, f1) = (ld_bytes(&buf[pos..]), ld_bytes(&buf[pos + 24..]));
        let f0 = _mm256_shuffle_epi8(_mm256_permute4x64_epi64::<0x94>(f0), idx8);
        let f1 = _mm256_shuffle_epi8(_mm256_permute4x64_epi64::<0x94>(f1), idx8);
        let f0 = _mm256_and_si256(
            _mm256_blend_epi16::<0xaa>(f0, _mm256_srli_epi16::<4>(f0)),
            mask,
        );
        let f1 = _mm256_and_si256(
            _mm256_blend_epi16::<0xaa>(f1, _mm256_srli_epi16::<4>(f1)),
            mask,
        );
        pos += 48;

        let g0 = _mm256_cmpgt_epi16(bound, f0);
        let g1 = _mm256_cmpgt_epi16(bound, f1);
        let good = _mm256_movemask_epi8(_mm256_packs_epi16(g0, g1)) as u32;

        let i0 =
            _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(idx_lo(good)), idx_lo(good >> 16));
        let i1 = _mm256_inserti128_si256::<1>(
            _mm256_castsi128_si256(idx_lo(good >> 8)),
            idx_lo(good >> 24),
        );
        let i0 = _mm256_unpacklo_epi8(i0, _mm256_add_epi8(i0, ones));
        let i1 = _mm256_unpacklo_epi8(i1, _mm256_add_epi8(i1, ones));
        let f0 = _mm256_shuffle_epi8(f0, i0);
        let f1 = _mm256_shuffle_epi8(f1, i1);

        store8(out, ctr, _mm256_castsi256_si128(f0));
        ctr += (good & 0xff).count_ones() as usize;
        store8(out, ctr, _mm256_extracti128_si256::<1>(f0));
        ctr += ((good >> 16) & 0xff).count_ones() as usize;
        store8(out, ctr, _mm256_castsi256_si128(f1));
        ctr += ((good >> 8) & 0xff).count_ones() as usize;
        store8(out, ctr, _mm256_extracti128_si256::<1>(f1));
        ctr += (good >> 24).count_ones() as usize;
    }
    super::poly::rej_uniform(out, ctr, &buf[pos..])
}

// ---------------------------------------------------------------------------
// Safe entry points. Callers hold an `Engine` for `Backend::Avx2`, which is
// only constructed after AVX2 was detected (see `backend::Engine`).
// ---------------------------------------------------------------------------

macro_rules! entry {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) $(-> $ret:ty)? => $imp:ident;)*) => {$(
        pub(super) fn $name($($arg: $ty),*) $(-> $ret)? {
            debug_assert!(crate::cpu::features().x86_avx2());
            // SAFETY: only reachable through an `Engine` for `Backend::Avx2`,
            // which is constructed only when AVX2 is available.
            unsafe { $imp($($arg),*) }
        }
    )*};
}

entry! {
    fn ntt(p: &mut Poly) => ntt_avx2;
    fn invntt(p: &mut Poly) => invntt_avx2;
    fn basemul_acc(r: &mut Poly, a: &[Poly], b: &[Poly]) => basemul_acc_avx2;
    fn reduce(p: &mut Poly) => reduce_avx2;
    fn tomont(p: &mut Poly) => tomont_avx2;
    fn rej_uniform(out: &mut [i16; N], ctr: usize, buf: &[u8]) -> usize => rej_uniform_avx2;
}
