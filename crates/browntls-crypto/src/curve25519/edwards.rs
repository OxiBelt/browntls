//! The twisted Edwards curve edwards25519: `-x^2 + y^2 = 1 + d x^2 y^2`.
//!
//! Points use extended coordinates `(X : Y : Z : T)` with `x = X/Z`,
//! `y = Y/Z`, `xy = T/Z` and the unified addition formulas of Hisil, Wong,
//! Carter and Dawson (complete on this curve because `d` is a non-square).
//!
//! * [`EdwardsPoint::mul_base`] is constant time: a radix-16 signed-digit comb
//!   over the precomputed table in `table.rs` with a masked (scan-all) table
//!   lookup.
//! * [`vartime_double_scalar_mul_base`] is **variable time** and must only be
//!   used with public inputs (signature verification): width-5 NAF for the
//!   variable point and width-8 NAF over a precomputed table for `B`.

use super::field::{Fe, cmov_u64, opaque_mask};
use super::table::{BASE, BASE_ODD};
use crate::ct::{self, Choice};
use crate::zeroize::Zeroize;

/// A point in extended twisted Edwards coordinates.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EdwardsPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// `(X : Y : Z)` with `x = X/Z`, `y = Y/Z`.
#[derive(Clone, Copy, Debug)]
struct ProjectivePoint {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// `((X : Z), (Y : T))` with `x = X/Z`, `y = Y/T` (an addition result).
#[derive(Clone, Copy, Debug)]
struct CompletedPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// `(y + x, y - x, 2dxy)` for an affine point.
#[derive(Clone, Copy, Debug)]
struct AffineNiels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
}

/// `(Y + X, Y - X, Z, 2dT)`.
#[derive(Clone, Copy, Debug)]
struct ProjectiveNiels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

impl AffineNiels {
    fn from_table(e: &[[u64; 5]; 3]) -> Self {
        Self {
            y_plus_x: Fe(e[0]),
            y_minus_x: Fe(e[1]),
            xy2d: Fe(e[2]),
        }
    }

    fn neg(&self) -> Self {
        Self {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            xy2d: self.xy2d.neg(),
        }
    }
}

impl CompletedPoint {
    #[inline]
    fn to_projective(self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
        }
    }

    #[inline]
    fn to_extended(self) -> EdwardsPoint {
        EdwardsPoint {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
            t: self.x.mul(&self.y),
        }
    }
}

impl ProjectivePoint {
    const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    #[inline]
    fn double(&self) -> CompletedPoint {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let zz2 = zz.add(&zz);
        let x_plus_y_sq = self.x.add(&self.y).square();
        let yy_plus_xx = yy.add(&xx);
        let yy_minus_xx = yy.sub(&xx);
        CompletedPoint {
            x: x_plus_y_sq.sub(&yy_plus_xx),
            y: yy_plus_xx,
            z: yy_minus_xx,
            t: zz2.sub(&yy_minus_xx),
        }
    }

    fn compress(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x.mul(&recip);
        let y = self.y.mul(&recip);
        let mut s = y.to_bytes();
        s[31] ^= (x.to_bytes()[0] & 1) << 7;
        s
    }
}

impl EdwardsPoint {
    pub(crate) const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Decodes a point per RFC 8032 §5.1.3, additionally rejecting
    /// non-canonical encodings (`y >= p`, or `x = 0` with the sign bit set).
    pub(crate) fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let y = Fe::from_bytes(bytes);
        let mut canonical = *bytes;
        canonical[31] &= 0x7f;
        if y.to_bytes() != canonical {
            return None;
        }
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = yy.mul(&Fe::D).add(&Fe::ONE);
        let (is_square, mut x) = Fe::sqrt_ratio(&u, &v);
        if !is_square.declassify() {
            return None;
        }
        let sign = u64::from(bytes[31] >> 7);
        if sign == 1 && x.is_zero().declassify() {
            return None;
        }
        x.conditional_negate(Choice::from_bit(sign));
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }

    /// Returns the canonical 32-byte encoding.
    pub(crate) fn compress(&self) -> [u8; 32] {
        self.to_projective().compress()
    }

    /// Returns the Montgomery u-coordinate `(1 + y) / (1 - y)` of the
    /// birationally equivalent curve25519 point (zero for the identity).
    pub(crate) fn to_montgomery_u(self) -> [u8; 32] {
        let num = self.z.add(&self.y);
        let den = self.z.sub(&self.y);
        num.mul(&den.invert()).to_bytes()
    }

    #[inline]
    fn to_projective(self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    fn to_niels(self) -> ProjectiveNiels {
        ProjectiveNiels {
            y_plus_x: self.y.add(&self.x),
            y_minus_x: self.y.sub(&self.x),
            z: self.z,
            t2d: self.t.mul(&Fe::D2),
        }
    }

    pub(crate) fn neg(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    #[inline]
    fn double(&self) -> Self {
        self.to_projective().double().to_extended()
    }

    #[inline]
    fn add_niels(&self, q: &ProjectiveNiels) -> CompletedPoint {
        let pp = self.y.add(&self.x).mul(&q.y_plus_x);
        let mm = self.y.sub(&self.x).mul(&q.y_minus_x);
        let tt2d = self.t.mul(&q.t2d);
        let zz = self.z.mul(&q.z);
        let zz2 = zz.add(&zz);
        CompletedPoint {
            x: pp.sub(&mm),
            y: pp.add(&mm),
            z: zz2.add(&tt2d),
            t: zz2.sub(&tt2d),
        }
    }

    #[inline]
    fn sub_niels(&self, q: &ProjectiveNiels) -> CompletedPoint {
        let pm = self.y.add(&self.x).mul(&q.y_minus_x);
        let mp = self.y.sub(&self.x).mul(&q.y_plus_x);
        let tt2d = self.t.mul(&q.t2d);
        let zz = self.z.mul(&q.z);
        let zz2 = zz.add(&zz);
        CompletedPoint {
            x: pm.sub(&mp),
            y: pm.add(&mp),
            z: zz2.sub(&tt2d),
            t: zz2.add(&tt2d),
        }
    }

    #[inline]
    fn add_affine(&self, q: &AffineNiels) -> CompletedPoint {
        let pp = self.y.add(&self.x).mul(&q.y_plus_x);
        let mm = self.y.sub(&self.x).mul(&q.y_minus_x);
        let txy2d = self.t.mul(&q.xy2d);
        let z2 = self.z.add(&self.z);
        CompletedPoint {
            x: pp.sub(&mm),
            y: pp.add(&mm),
            z: z2.add(&txy2d),
            t: z2.sub(&txy2d),
        }
    }

    /// `true` if `[8]P` is the identity (public inputs only).
    pub(crate) fn is_small_order(&self) -> bool {
        let p8 = self.double().double().double();
        p8.x.is_zero().declassify() && p8.y.ct_eq(&p8.z).declassify()
    }

    /// Constant-time `[a]B` for a 256-bit little-endian scalar with
    /// `a[31] <= 127` (true for clamped and for reduced scalars).
    pub(crate) fn mul_base(a: &[u8; 32]) -> Self {
        debug_assert!(a[31] <= 127);
        // Signed radix-16 digits e[i] in [-8, 8] (stored as two's complement
        // bytes so they can be zeroised), a = sum e[i] 16^i.
        let mut e = [0u8; 64];
        for (i, &byte) in a.iter().enumerate() {
            e[2 * i] = byte & 15;
            e[2 * i + 1] = byte >> 4;
        }
        let mut carry = 0i8;
        for d in e.iter_mut().take(63) {
            let v = *d as i8 + carry;
            carry = (v + 8) >> 4;
            *d = (v - (carry << 4)) as u8;
        }
        e[63] = (e[63] as i8 + carry) as u8;

        let mut h = Self::IDENTITY;
        for i in (1..64).step_by(2) {
            h = h.add_affine(&select(i / 2, e[i] as i8)).to_extended();
        }
        let p = h.to_projective().double().to_projective();
        let p = p.double().to_projective();
        let p = p.double().to_projective();
        h = p.double().to_extended();
        for i in (0..64).step_by(2) {
            h = h.add_affine(&select(i / 2, e[i] as i8)).to_extended();
        }
        e.zeroize();
        h
    }
}

/// Constant-time lookup of `b * 256^row * B` for `b` in `[-8, 8]`.
#[inline]
fn select(row: usize, b: i8) -> AffineNiels {
    let bneg = u64::from((b as u8) >> 7);
    let babs = b.wrapping_sub(((bneg as i8).wrapping_neg() & b).wrapping_shl(1)) as u8;
    let mut t: [[u64; 5]; 3] = [[1, 0, 0, 0, 0], [1, 0, 0, 0, 0], [0; 5]];
    for (j, entry) in BASE[row].iter().enumerate() {
        let m = opaque_mask(ct::eq_u64(u64::from(babs), j as u64 + 1));
        for (tk, ek) in t.iter_mut().zip(entry) {
            cmov_u64(m, tk, ek);
        }
    }
    let mut out = AffineNiels::from_table(&t);
    let neg = Choice::from_bit(bneg);
    Fe::conditional_swap(&mut out.y_plus_x, &mut out.y_minus_x, neg);
    out.xy2d.conditional_negate(neg);
    out
}

/// Width-`w` non-adjacent form of a scalar below `2^255`.
fn naf(s: &[u8; 32], w: usize) -> [i8; 256] {
    let mut x = [0u64; 5];
    for (xi, chunk) in x.iter_mut().zip(s.as_chunks::<8>().0) {
        *xi = u64::from_le_bytes(*chunk);
    }
    let width = 1u64 << w;
    let mut out = [0i8; 256];
    let mut pos = 0;
    let mut carry = 0u64;
    while pos < 256 {
        let idx = pos / 64;
        let bit = pos % 64;
        let buf = if bit < 64 - w {
            x[idx] >> bit
        } else {
            (x[idx] >> bit) | (x[idx + 1] << (64 - bit))
        };
        let window = carry + (buf & (width - 1));
        if window & 1 == 0 {
            pos += 1;
            continue;
        }
        if window < width / 2 {
            carry = 0;
            out[pos] = window as i8;
        } else {
            carry = 1;
            out[pos] = (window as i64 - width as i64) as i8;
        }
        pos += w;
    }
    out
}

/// Computes the encoding of `[a]A + [b]B` in **variable time**.
///
/// Only for public inputs (signature verification). Requires `a, b < 2^255`.
pub(crate) fn vartime_double_scalar_mul_base(
    a: &[u8; 32],
    pa: &EdwardsPoint,
    b: &[u8; 32],
) -> [u8; 32] {
    let a_naf = naf(a, 5);
    let b_naf = naf(b, 8);
    // Odd multiples A, 3A, ..., 15A.
    let a2 = pa.double().to_niels();
    let mut table = [pa.to_niels(); 8];
    let mut cur = *pa;
    for entry in table.iter_mut().skip(1) {
        cur = cur.add_niels(&a2).to_extended();
        *entry = cur.to_niels();
    }
    let mut i = 255;
    while i > 0 && a_naf[i] == 0 && b_naf[i] == 0 {
        i -= 1;
    }
    let mut r = ProjectivePoint::IDENTITY;
    loop {
        let mut t = r.double();
        let ai = a_naf[i];
        if ai > 0 {
            t = t.to_extended().add_niels(&table[(ai / 2) as usize]);
        } else if ai < 0 {
            t = t.to_extended().sub_niels(&table[(-ai / 2) as usize]);
        }
        let bi = b_naf[i];
        if bi > 0 {
            t = t
                .to_extended()
                .add_affine(&AffineNiels::from_table(&BASE_ODD[(bi / 2) as usize]));
        } else if bi < 0 {
            t = t
                .to_extended()
                .add_affine(&AffineNiels::from_table(&BASE_ODD[(-bi / 2) as usize]).neg());
        }
        r = t.to_projective();
        if i == 0 {
            break;
        }
        i -= 1;
    }
    r.compress()
}

#[cfg(test)]
mod tests {
    use super::*;

    const B_BYTES: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    fn base() -> EdwardsPoint {
        EdwardsPoint::decompress(&B_BYTES).unwrap()
    }

    fn add(p: &EdwardsPoint, q: &EdwardsPoint) -> EdwardsPoint {
        p.add_niels(&q.to_niels()).to_extended()
    }

    /// Naive double-and-add reference.
    fn mul_ref(s: &[u8; 32], p: &EdwardsPoint) -> EdwardsPoint {
        let mut r = EdwardsPoint::IDENTITY;
        for i in (0..256).rev() {
            r = r.double();
            if (s[i / 8] >> (i % 8)) & 1 == 1 {
                r = add(&r, p);
            }
        }
        r
    }

    fn affine_niels_bytes(p: &EdwardsPoint) -> [[u8; 32]; 3] {
        let zi = p.z.invert();
        let x = p.x.mul(&zi);
        let y = p.y.mul(&zi);
        [
            y.add(&x).to_bytes(),
            y.sub(&x).to_bytes(),
            x.mul(&y).mul(&Fe::D2).to_bytes(),
        ]
    }

    /// Renders `table.rs` from scratch with this module's arithmetic.
    fn table_source() -> std::string::String {
        use std::fmt::Write as _;
        fn fe(out: &mut std::string::String, b: &[u8; 32]) {
            let limbs = Fe::from_bytes(b).0; // canonical bytes -> limbs < 2^51
            out.push('[');
            for (i, l) in limbs.iter().enumerate() {
                let sep = if i == 0 { "" } else { ", " };
                write!(out, "{sep}0x{l:013x}").unwrap();
            }
            out.push(']');
        }
        fn niels(out: &mut std::string::String, p: &EdwardsPoint) {
            let [a, b, c] = affine_niels_bytes(p);
            out.push('[');
            fe(out, &a);
            out.push_str(", ");
            fe(out, &b);
            out.push_str(", ");
            fe(out, &c);
            out.push(']');
        }
        let mut s = std::string::String::from(TABLE_HEADER);
        s.push_str(
            "/// `BASE[i][j] = (j + 1) * 256^i * B` for `i < 32`, `j < 8` (radix-16 comb).\n",
        );
        s.push_str("#[rustfmt::skip]\npub(super) static BASE: [[[[u64; 5]; 3]; 8]; 32] = [\n");
        let b = base();
        let mut row_base = b;
        for _ in 0..32 {
            s.push_str("    [\n");
            let mut p = row_base;
            for _ in 0..8 {
                s.push_str("        ");
                niels(&mut s, &p);
                s.push_str(",\n");
                p = add(&p, &row_base);
            }
            s.push_str("    ],\n");
            for _ in 0..8 {
                row_base = row_base.double();
            }
        }
        s.push_str("];\n\n");
        s.push_str(
            "/// `BASE_ODD[k] = (2k + 1) * B` for `k < 64` (width-8 NAF in verification).\n",
        );
        s.push_str("#[rustfmt::skip]\npub(super) static BASE_ODD: [[[u64; 5]; 3]; 64] = [\n");
        let b2 = b.double();
        let mut p = b;
        for _ in 0..64 {
            s.push_str("    ");
            niels(&mut s, &p);
            s.push_str(",\n");
            p = add(&p, &b2);
        }
        s.push_str("];\n");
        s
    }

    const TABLE_HEADER: &str = "\
//! Precomputed multiples of the Ed25519 base point B (generated; do not edit).
//!
//! Each entry is an affine Niels point `[y + x, y - x, 2dxy]` with field
//! elements as five 51-bit limbs (least significant first), fully reduced.
//! Regenerate with
//! `cargo test -p browntls-crypto --lib regenerate_tables -- --ignored`;
//! the test `edwards::tests::tables_are_reproducible` checks this file.

";

    #[test]
    fn tables_are_reproducible() {
        assert!(
            table_source() == include_str!("table.rs"),
            "table.rs is stale; run the ignored `regenerate_tables` test"
        );
    }

    #[test]
    #[ignore = "rewrites src/curve25519/table.rs"]
    fn regenerate_tables() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/curve25519/table.rs");
        std::fs::write(path, table_source()).unwrap();
    }

    #[test]
    fn mul_base_matches_reference() {
        let b = base();
        let mut s = [0u8; 32];
        let mut st = 0x1234_5678_9abc_def0u64;
        for n in 0..40 {
            for byte in s.iter_mut() {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (st >> 56) as u8;
            }
            s[31] &= 0x7f;
            if n == 0 {
                s = [0; 32];
            } else if n == 1 {
                s = [0xff; 32];
                s[31] = 0x7f;
            }
            let expect = mul_ref(&s, &b).compress();
            assert_eq!(EdwardsPoint::mul_base(&s).compress(), expect);
            // [s]B via the variable-time path: [s]B + [0]B and [0]B + [s]B
            // (the latter through the A-table).
            assert_eq!(vartime_double_scalar_mul_base(&[0; 32], &b, &s), expect);
            assert_eq!(vartime_double_scalar_mul_base(&s, &b, &[0; 32]), expect);
            // [s]P + [t]B for a non-base P.
            let pt = EdwardsPoint::mul_base(&[n as u8 + 3; 32].map(|x| x & 0x7f));
            let t = [n as u8; 32].map(|x| x & 0x3f);
            let want = add(&mul_ref(&s, &pt), &mul_ref(&t, &b)).compress();
            assert_eq!(vartime_double_scalar_mul_base(&s, &pt, &t), want);
        }
    }

    #[test]
    fn decompress_rejects_noncanonical() {
        let b = base();
        assert_eq!(b.compress(), B_BYTES);
        assert_eq!(EdwardsPoint::IDENTITY.compress()[0], 1);
        // y = p (non-canonical encoding of y = 0).
        let mut pb = [0xffu8; 32];
        pb[0] = 0xed;
        pb[31] = 0x7f;
        assert!(EdwardsPoint::decompress(&pb).is_none());
        // y = 1, x = 0 with sign bit set ("negative zero").
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(EdwardsPoint::decompress(&one).unwrap().is_small_order());
        one[31] = 0x80;
        assert!(EdwardsPoint::decompress(&one).is_none());
        assert!(!b.is_small_order());
        // y = 2 is not on the curve.
        let mut two = [0u8; 32];
        two[0] = 2;
        assert!(EdwardsPoint::decompress(&two).is_none());
        // Negation flips the sign bit.
        assert_eq!(b.neg().compress()[31], B_BYTES[31] | 0x80);
        // Montgomery map: B corresponds to u = 9.
        let mut nine = [0u8; 32];
        nine[0] = 9;
        assert_eq!(b.to_montgomery_u(), nine);
    }
}
