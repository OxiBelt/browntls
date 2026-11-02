//! Arithmetic in `R_q = Z_q[X]/(X^256 + 1)` with `q = 3329`: constants,
//! the portable backend (NTT, inverse NTT, base multiplication, reductions)
//! and the backend-independent byte encodings, compression and samplers.
//!
//! Coefficients are signed 16-bit values. Montgomery reduction uses
//! `R = 2^16`; Barrett reduction is written as the two-step
//! `((a * 20159) >> 16 + 512) >> 10` so that every SIMD backend (`vpmulhw` +
//! `vpmulhrsw`, `sqdmulh` + `srshr`, `vmulh` + `vadd` + `vsra`) computes
//! bit-identical results. NTT-domain polynomials always use the canonical
//! FIPS 203 coefficient order, in every backend.
//!
//! All functions that may touch secret data are branch-free and use no
//! secret-dependent memory indices; compression uses a multiply-shift instead
//! of division.

use crate::zeroize::Zeroize;

/// Number of coefficients.
pub(crate) const N: usize = 256;
/// The modulus.
pub(crate) const Q: i16 = 3329;
/// `q^-1 mod 2^16` (signed).
pub(crate) const QINV: i16 = -3327;
/// Barrett constant `round(2^26 / q)`.
pub(crate) const BARRETT_V: i16 = 20159;
/// `2^32 mod q`: multiplying by this in Montgomery form converts to Montgomery form.
pub(crate) const MONT_R2: i16 = 1353;
/// `2^32 / 128 mod q`: final scaling of the inverse NTT (undoes the `R^-1` of
/// base multiplication and divides by 128).
pub(crate) const INVNTT_F: i16 = 1441;

const fn pow_mod(base: u32, mut e: u32) -> u32 {
    let q = Q as u32;
    let mut r = 1;
    let mut b = base % q;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % q;
        }
        b = b * b % q;
        e >>= 1;
    }
    r
}

const fn bitrev7(i: usize) -> usize {
    let mut r = 0;
    let mut k = 0;
    while k < 7 {
        r |= ((i >> k) & 1) << (6 - k);
        k += 1;
    }
    r
}

/// Converts `x` (in `[0, q)`) to Montgomery form, centred in `(-q/2, q/2]`.
#[allow(clippy::cast_possible_truncation)]
const fn mont_centered(x: u32) -> i16 {
    let m = (x * 65536 % (Q as u32)) as i32;
    let q = Q as i32;
    (if m > q / 2 { m - q } else { m }) as i16
}

/// `zeta^bitrev7(i)` in Montgomery form (`zeta = 17`).
pub(crate) const ZETAS: [i16; 128] = {
    let mut t = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = mont_centered(pow_mod(17, bitrev7(i) as u32));
        i += 1;
    }
    t
};

/// `zeta^(2 bitrev7(i) + 1)` in Montgomery form: the modulus `X^2 - gamma_i`
/// of coefficient pair `i` in the NTT domain.
pub(crate) const GAMMAS: [i16; 128] = {
    let mut t = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = mont_centered(pow_mod(17, 2 * bitrev7(i) as u32 + 1));
        i += 1;
    }
    t
};

/// Returns `t` with every entry multiplied by `q^-1 mod 2^16` (the low-half
/// Montgomery multiplier used by the SIMD backends).
pub(crate) const fn qinv_table<const L: usize>(t: [i16; L]) -> [i16; L] {
    let mut o = [0i16; L];
    let mut i = 0;
    while i < L {
        o[i] = t[i].wrapping_mul(QINV);
        i += 1;
    }
    o
}

/// `ZETAS[i] * q^-1 mod 2^16`.
pub(crate) const ZETAS_QINV: [i16; 128] = qinv_table(ZETAS);
/// `GAMMAS[i] * q^-1 mod 2^16`.
#[cfg_attr(
    not(any(target_arch = "aarch64", target_arch = "riscv64")),
    allow(dead_code)
)]
pub(crate) const GAMMAS_QINV: [i16; 128] = qinv_table(GAMMAS);

/// A polynomial with 256 signed 16-bit coefficients.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C, align(32))]
pub(crate) struct Poly(pub(crate) [i16; N]);

impl Poly {
    pub(crate) const ZERO: Self = Self([0; N]);
}

impl Default for Poly {
    fn default() -> Self {
        Self::ZERO
    }
}

impl core::fmt::Debug for Poly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Poly(..)")
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Up to four polynomials (only the first `k` are used).
pub(crate) type PolyVec = [Poly; 4];

pub(crate) fn zeroize_vec(v: &mut PolyVec) {
    for p in v.iter_mut() {
        p.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Scalar reductions.
// ---------------------------------------------------------------------------

/// Montgomery reduction: returns `a * 2^-16 mod q` in `(-q, q)` for
/// `|a| < 2^15 q`.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    ((a - i32::from(t) * i32::from(Q)) >> 16) as i16
}

/// `a * b * 2^-16 mod q`.
#[inline(always)]
pub(crate) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(i32::from(a) * i32::from(b))
}

/// Barrett reduction: returns a representative of `a mod q` in `(-q, q)`
/// (centred, `|r| <= q/2 + 1`).
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    let t = (i32::from(a) * i32::from(BARRETT_V)) >> 16;
    let t = (t + 512) >> 10;
    (i32::from(a) - t * i32::from(Q)) as i16
}

/// Maps any `i16` to its canonical representative in `[0, q)`.
#[inline(always)]
pub(crate) fn canonical(a: i16) -> u16 {
    let mut r = barrett_reduce(a);
    r = r.wrapping_add((r >> 15) & Q);
    r = r.wrapping_sub(Q);
    r = r.wrapping_add((r >> 15) & Q);
    r as u16
}

// ---------------------------------------------------------------------------
// Portable backend.
// ---------------------------------------------------------------------------

/// Forward NTT followed by Barrett reduction. Input coefficients must satisfy
/// `|a| < q`; output coefficients are centred (`|a| <= q/2 + 1`).
pub(crate) fn ntt(p: &mut Poly) {
    let r = &mut p.0;
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j].wrapping_sub(t);
                r[j] = r[j].wrapping_add(t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    reduce(p);
}

/// Inverse NTT, multiplying by `2^16` (undoing the `2^-16` factor left by
/// [`basemul_acc`]). Input coefficients must satisfy `|a| < q`; output
/// coefficients satisfy `|a| < q`.
pub(crate) fn invntt(p: &mut Poly) {
    let r = &mut p.0;
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t.wrapping_add(r[j + len]));
                r[j + len] = fqmul(zeta, r[j + len].wrapping_sub(t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in r.iter_mut() {
        *c = fqmul(*c, INVNTT_F);
    }
}

/// `r = sum_i a[i] o b[i]` (NTT-domain products, scaled by `2^-16`), followed
/// by Barrett reduction. Inputs must satisfy `|x| < q`; at most four terms.
pub(crate) fn basemul_acc(r: &mut Poly, a: &[Poly], b: &[Poly]) {
    *r = Poly::ZERO;
    for (x, y) in a.iter().zip(b) {
        for (i, &gamma) in GAMMAS.iter().enumerate() {
            let (a0, a1) = (x.0[2 * i], x.0[2 * i + 1]);
            let (b0, b1) = (y.0[2 * i], y.0[2 * i + 1]);
            let c0 = fqmul(fqmul(a1, b1), gamma).wrapping_add(fqmul(a0, b0));
            let c1 = fqmul(a0, b1).wrapping_add(fqmul(a1, b0));
            r.0[2 * i] = r.0[2 * i].wrapping_add(c0);
            r.0[2 * i + 1] = r.0[2 * i + 1].wrapping_add(c1);
        }
    }
    reduce(r);
}

/// Barrett-reduces every coefficient.
pub(crate) fn reduce(p: &mut Poly) {
    for c in p.0.iter_mut() {
        *c = barrett_reduce(*c);
    }
}

/// Multiplies by `2^16` (conversion to Montgomery form); output `|a| < q`.
pub(crate) fn tomont(p: &mut Poly) {
    for c in p.0.iter_mut() {
        *c = fqmul(*c, MONT_R2);
    }
}

/// Rejection-samples coefficients in `[0, q)` from `buf` (12-bit little-endian
/// pairs) into `out[ctr..]`; returns the new count. Public data only
/// (variable time).
pub(crate) fn rej_uniform(out: &mut [i16; N], mut ctr: usize, buf: &[u8]) -> usize {
    for c in buf.as_chunks::<3>().0 {
        if ctr >= N {
            break;
        }
        let d1 = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
        let d2 = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        if d1 < Q as u16 {
            out[ctr] = d1 as i16;
            ctr += 1;
        }
        if d2 < Q as u16 && ctr < N {
            out[ctr] = d2 as i16;
            ctr += 1;
        }
    }
    ctr
}

// ---------------------------------------------------------------------------
// Element-wise helpers (shared by all backends; auto-vectorised).
// ---------------------------------------------------------------------------

/// `r += b`.
pub(crate) fn add_assign(r: &mut Poly, b: &Poly) {
    for (x, y) in r.0.iter_mut().zip(b.0.iter()) {
        *x = x.wrapping_add(*y);
    }
}

/// `r = a - r`.
pub(crate) fn rsub_assign(r: &mut Poly, a: &Poly) {
    for (x, y) in r.0.iter_mut().zip(a.0.iter()) {
        *x = y.wrapping_sub(*x);
    }
}

// ---------------------------------------------------------------------------
// Centred binomial distribution (FIPS 203 Algorithm 8).
// ---------------------------------------------------------------------------

/// Samples from CBD_2 using 128 bytes of PRF output.
pub(crate) fn cbd2(out: &mut Poly, buf: &[u8; 128]) {
    for (i, c) in buf.as_chunks::<4>().0.iter().enumerate() {
        let t = u32::from_le_bytes(*c);
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 3) as i16;
            let b = ((d >> (4 * j + 2)) & 3) as i16;
            out.0[8 * i + j] = a - b;
        }
    }
}

/// Samples from CBD_3 using 192 bytes of PRF output.
pub(crate) fn cbd3(out: &mut Poly, buf: &[u8; 192]) {
    for (i, c) in buf.as_chunks::<3>().0.iter().enumerate() {
        let t = u32::from(c[0]) | (u32::from(c[1]) << 8) | (u32::from(c[2]) << 16);
        let d = (t & 0x0024_9249) + ((t >> 1) & 0x0024_9249) + ((t >> 2) & 0x0024_9249);
        for j in 0..4 {
            let a = ((d >> (6 * j)) & 7) as i16;
            let b = ((d >> (6 * j + 3)) & 7) as i16;
            out.0[4 * i + j] = a - b;
        }
    }
}

// ---------------------------------------------------------------------------
// Byte encodings and compression (FIPS 203 §4.2.1).
// ---------------------------------------------------------------------------

/// ByteEncode_12 of a polynomial (any representatives; canonicalised here).
pub(crate) fn encode12(p: &Poly, out: &mut [u8; 384]) {
    for (i, o) in out.as_chunks_mut::<3>().0.iter_mut().enumerate() {
        let t0 = canonical(p.0[2 * i]);
        let t1 = canonical(p.0[2 * i + 1]);
        o[0] = t0 as u8;
        o[1] = ((t0 >> 8) | (t1 << 4)) as u8;
        o[2] = (t1 >> 4) as u8;
    }
}

/// ByteDecode_12 without reduction: coefficients in `[0, 4096)`.
pub(crate) fn decode12_raw(bytes: &[u8; 384], p: &mut Poly) {
    for (i, b) in bytes.as_chunks::<3>().0.iter().enumerate() {
        let (b0, b1, b2) = (u16::from(b[0]), u16::from(b[1]), u16::from(b[2]));
        p.0[2 * i] = ((b0 | (b1 << 8)) & 0xfff) as i16;
        p.0[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) as i16;
    }
}

/// ByteDecode_12 (reducing modulo `q`, constant time): coefficients in `[0, q)`.
pub(crate) fn decode12(bytes: &[u8; 384], p: &mut Poly) {
    decode12_raw(bytes, p);
    for c in p.0.iter_mut() {
        let r = c.wrapping_sub(Q);
        *c = r.wrapping_add((r >> 15) & Q);
    }
}

/// Returns whether every 12-bit value in `bytes` is below `q` (FIPS 203 §7.2
/// modulus check); public data.
pub(crate) fn check12(bytes: &[u8; 384]) -> bool {
    let mut p = Poly::ZERO;
    decode12_raw(bytes, &mut p);
    p.0.iter().all(|&c| c < Q)
}

/// `Compress_d(x)` for canonical `x` in `[0, q)`: `round(2^d x / q) mod 2^d`,
/// computed as `((x << d) + 1664) * ceil(2^35 / q) >> 35`, which is exact for
/// all inputs below `2^23` (checked exhaustively in the tests).
#[inline(always)]
pub(crate) fn compress(x: u16, d: u32) -> u16 {
    const M: u64 = 10_321_340; // ceil(2^35 / 3329)
    let n = (u64::from(x) << d) + 1664;
    (((n * M) >> 35) as u16) & ((1u16 << d) - 1)
}

/// `Decompress_d(y) = round(q y / 2^d)`.
#[inline(always)]
pub(crate) fn decompress(y: u16, d: u32) -> i16 {
    ((u32::from(y) * (Q as u32) + (1 << (d - 1))) >> d) as i16
}

/// `ByteEncode_d(Compress_d(p))` into `32 d` bytes.
pub(crate) fn compress_encode(p: &Poly, d: u32, out: &mut [u8]) {
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut o = 0;
    for &c in p.0.iter() {
        acc |= u64::from(compress(canonical(c), d)) << bits;
        bits += d;
        while bits >= 8 {
            out[o] = acc as u8;
            o += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// `Decompress_d(ByteDecode_d(bytes))` from `32 d` bytes.
pub(crate) fn decode_decompress(bytes: &[u8], d: u32, p: &mut Poly) {
    let mask = (1u64 << d) - 1;
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut it = bytes.iter();
    for c in p.0.iter_mut() {
        while bits < d {
            acc |= u64::from(*it.next().unwrap_or(&0)) << bits;
            bits += 8;
        }
        *c = decompress((acc & mask) as u16, d);
        acc >>= d;
        bits -= d;
    }
}

/// `Decompress_1(ByteDecode_1(m))`: each message bit becomes 0 or `(q+1)/2`.
pub(crate) fn from_msg(m: &[u8; 32], p: &mut Poly) {
    for (i, &b) in m.iter().enumerate() {
        for j in 0..8 {
            let mask = (i16::from((b >> j) & 1)).wrapping_neg();
            p.0[8 * i + j] = mask & ((Q + 1) / 2);
        }
    }
}

/// `ByteEncode_1(Compress_1(p))`.
pub(crate) fn to_msg(p: &Poly, m: &mut [u8; 32]) {
    compress_encode(p, 1, m);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeta_tables_match_reference() {
        // First and last entries of the Kyber reference table.
        assert_eq!(&ZETAS[..4], &[-1044, -758, -359, -1517]);
        assert_eq!(&ZETAS[124..], &[958, -1460, 1522, 1628]);
        // basemul uses +/- zetas[64 + i/2] for pairs 2i, 2i+1 in the reference.
        for i in 0..64 {
            assert_eq!(GAMMAS[2 * i], ZETAS[64 + i]);
            assert_eq!(GAMMAS[2 * i + 1], -ZETAS[64 + i]);
        }
    }

    #[test]
    fn compress_exhaustive() {
        for d in [1u32, 4, 5, 10, 11] {
            for x in 0..Q as u32 {
                let exact = (((x << d) + (Q as u32 / 2)) / Q as u32) & ((1 << d) - 1);
                assert_eq!(u32::from(compress(x as u16, d)), exact, "d={d} x={x}");
            }
            for y in 0..(1u32 << d) {
                // round(q y / 2^d), ties up.
                let exact = (Q as u32 * y * 2 + (1 << d)) / (2 << d);
                assert_eq!(decompress(y as u16, d) as u32, exact);
            }
        }
    }

    #[test]
    fn reductions() {
        for a in i16::MIN..=i16::MAX {
            let r = barrett_reduce(a);
            assert!(r.abs() <= Q / 2 + 1, "{a} -> {r}");
            assert_eq!(i32::from(r).rem_euclid(3329), i32::from(a).rem_euclid(3329));
            assert_eq!(i32::from(canonical(a)), i32::from(a).rem_euclid(3329));
        }
        for a in [-i32::from(Q) * 32767, -1, 0, 1, i32::from(Q) * 32767] {
            let r = montgomery_reduce(a);
            assert!(r.abs() < Q);
            assert_eq!((i64::from(r) * 65536 - i64::from(a)).rem_euclid(3329), 0);
        }
    }
}
