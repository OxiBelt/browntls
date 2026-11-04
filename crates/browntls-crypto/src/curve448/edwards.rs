//! The Edwards curve edwards448 (RFC 7748 §4.2, RFC 8032 §5.2):
//! `x^2 + y^2 = 1 + d x^2 y^2` with `d = -39081`.
//!
//! Points use projective coordinates `(X : Y : Z)` with `x = X/Z`, `y = Y/Z`
//! and the addition and doubling formulas of RFC 8032 §5.2.4, which are
//! complete on this curve (`a = 1` and `d` is a non-square): they hold for
//! every pair of curve points, including the identity `(0 : 1 : 1)`, so the
//! scalar multiplications below need no special cases.
//!
//! * [`EdwardsPoint::mul`] is constant time: a fixed 4-bit window over a
//!   16-entry table built per call, with a masked (scan-all) table lookup.
//!   It serves key generation and signing (`[s]B`, `[r]B`).
//! * [`vartime_double_scalar_mul_base`] is **variable time** and must only be
//!   used with public inputs (signature verification): width-5 NAF for both
//!   scalars.

use super::field::{Fe, cmov_u64, opaque_mask};
use super::scalar::Scalar;
use crate::ct::{self, Choice};
use crate::zeroize::Zeroize;

/// `|d| = 39081`; `d = -39081`.
const D_ABS: u32 = 39_081;

/// A point in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EdwardsPoint {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl EdwardsPoint {
    pub(crate) const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    /// The base point B of RFC 8032 Table 2 (`(X(P), Y(P))` of edwards448 in
    /// RFC 7748 §4.2), in affine form. The test `base_point_matches_the_rfc`
    /// checks these limbs against the decimal values in the RFC.
    pub(crate) const BASE: Self = Self {
        x: Fe([
            0x26a82bc70cc05e,
            0x80e18b00938e26,
            0xf72ab66511433b,
            0xa3d3a46412ae1a,
            0x0f1767ea6de324,
            0x36da9e14657047,
            0xed221d15a622bf,
            0x4f1970c66bed0d,
        ]),
        y: Fe([
            0x08795bf230fa14,
            0x132c4ed7c8ad98,
            0x1ce67c39c4fdbd,
            0x05a0c2d73ad3ff,
            0xa3984087789c1e,
            0xc7624bea73736c,
            0x248876203756c9,
            0x693f46716eb6bc,
        ]),
        z: Fe::ONE,
    };

    /// Decodes a point per RFC 8032 §5.2.3, which already rejects every
    /// non-canonical encoding: `y >= p` (including any of the unused bits
    /// 448..454 set), points off the curve, and `x = 0` with the sign bit set.
    ///
    /// Variable time: only for public data.
    pub(crate) fn decompress(bytes: &[u8; 57]) -> Option<Self> {
        // Step 1: bit 455 is x_0; clearing it leaves y, which must be < p.
        if bytes[56] & 0x7f != 0 {
            return None;
        }
        let mut yb = [0u8; 56];
        yb.copy_from_slice(&bytes[..56]);
        let y = Fe::from_bytes(&yb);
        if y.to_bytes() != yb {
            return None;
        }
        let x0 = u64::from(bytes[56] >> 7);
        // Step 2: x^2 = (y^2 - 1) / (d y^2 - 1); with d = -39081 the
        // denominator is -(39081 y^2 + 1), never zero as d is a non-square.
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = yy.mul_small(D_ABS).add(&Fe::ONE).neg();
        // Step 3: the candidate must satisfy v x^2 = u.
        let (ok, mut x) = Fe::sqrt_ratio(&u, &v);
        if !ok.declassify() {
            return None;
        }
        // Step 4: x = 0 with x_0 = 1 fails; otherwise pick the root by x_0.
        if x0 == 1 && x.is_zero().declassify() {
            return None;
        }
        let flip = Choice::from_bit(x0 ^ (x.is_odd().mask() & 1));
        x.conditional_negate(flip);
        Some(Self { x, y, z: Fe::ONE })
    }

    /// Returns the 57-byte encoding of RFC 8032 §5.2.2.
    pub(crate) fn compress(&self) -> [u8; 57] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi);
        let y = self.y.mul(&zi);
        let mut out = [0u8; 57];
        out[..56].copy_from_slice(&y.to_bytes());
        out[56] = ((x.is_odd().mask() & 1) as u8) << 7;
        out
    }

    pub(crate) fn neg(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
        }
    }

    /// Point addition (RFC 8032 §5.2.4), complete.
    pub(crate) fn add(&self, q: &Self) -> Self {
        let a = self.z.mul(&q.z);
        let b = a.square();
        let c = self.x.mul(&q.x);
        let d = self.y.mul(&q.y);
        // E = d C D with d = -39081: F = B - E = B + |d| C D, G = B + E.
        let e_abs = c.mul(&d).mul_small(D_ABS);
        let f = b.add(&e_abs);
        let g = b.sub(&e_abs);
        let h = self.x.add(&self.y).mul(&q.x.add(&q.y));
        Self {
            x: a.mul(&f).mul(&h.sub(&c.add(&d))),
            y: a.mul(&g).mul(&d.sub(&c)),
            z: f.mul(&g),
        }
    }

    /// Point doubling (RFC 8032 §5.2.4), complete: `E = x^2 + y^2` and
    /// `J = E - 2` (in affine terms) never vanish on the curve.
    pub(crate) fn double(&self) -> Self {
        let b = self.x.add(&self.y).square();
        let c = self.x.square();
        let d = self.y.square();
        let e = c.add(&d);
        let h = self.z.square();
        let j = e.sub(&h.add(&h));
        Self {
            x: b.sub(&e).mul(&j),
            y: e.mul(&c.sub(&d)),
            z: e.mul(&j),
        }
    }

    /// `true` if this is the identity `(0 : Z : Z)` (public inputs only).
    pub(crate) fn is_identity(&self) -> bool {
        self.x.is_zero().declassify() && self.y.ct_eq(&self.z).declassify()
    }

    /// `true` if `[4]P` is the identity, i.e. the order divides the cofactor
    /// (public inputs only).
    pub(crate) fn is_small_order(&self) -> bool {
        self.double().double().is_identity()
    }

    fn conditional_assign(&mut self, other: &Self, c: Choice) {
        let mask = opaque_mask(c);
        cmov_u64(mask, &mut self.x.0, &other.x.0);
        cmov_u64(mask, &mut self.y.0, &other.y.0);
        cmov_u64(mask, &mut self.z.0, &other.z.0);
    }

    /// Constant-time `[k]P` for a reduced scalar `k < L < 2^446`.
    ///
    /// Fixed 4-bit windows from the top: four doublings, then the addition
    /// of `table[digit]` selected by scanning all 16 entries, for every one of
    /// the 112 digits. The sequence of field operations and memory accesses
    /// is independent of `k`.
    pub(crate) fn mul(&self, k: &Scalar) -> Self {
        let mut table = [Self::IDENTITY; 16];
        for i in 1..16 {
            table[i] = table[i - 1].add(self);
        }
        let mut kb = k.to_bytes();
        let mut acc = Self::IDENTITY;
        let mut t = Self::IDENTITY;
        for i in (0..112).rev() {
            acc = acc.double().double().double().double();
            let digit = u64::from((kb[i / 2] >> (4 * (i & 1))) & 15);
            t = Self::IDENTITY;
            for (j, entry) in table.iter().enumerate() {
                t.conditional_assign(entry, ct::eq_u64(digit, j as u64));
            }
            acc = acc.add(&t);
        }
        // The digits and the last selected multiple depend on the secret.
        kb.zeroize();
        for c in [&mut t.x, &mut t.y, &mut t.z] {
            c.0.zeroize();
        }
        acc
    }

    /// Constant-time `[k]B` for the base point.
    pub(crate) fn mul_base(k: &Scalar) -> Self {
        Self::BASE.mul(k)
    }

    /// The Montgomery u-coordinate `y^2 / x^2` of the image of this point
    /// under the 4-isogeny of RFC 7748 §4.2 (zero for the identity). Used in
    /// tests to cross-check X448 against the Edwards arithmetic.
    #[cfg(test)]
    pub(crate) fn to_montgomery_u(self) -> [u8; 56] {
        self.y.square().mul(&self.x.square().invert()).to_bytes()
    }
}

/// Width-`w` non-adjacent form of a scalar below `2^446` (at most 447 digits).
fn naf(s: &[u8; 57], w: usize) -> [i8; 448] {
    let mut x = [0u64; 9];
    for (xi, chunk) in x.iter_mut().zip(s[..56].as_chunks::<8>().0) {
        *xi = u64::from_le_bytes(*chunk);
    }
    let width = 1u64 << w;
    let mut out = [0i8; 448];
    let mut pos = 0;
    let mut carry = 0u64;
    while pos < 448 {
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

/// Odd multiples `P, 3P, ..., 15P`.
fn odd_multiples(p: &EdwardsPoint) -> [EdwardsPoint; 8] {
    let p2 = p.double();
    let mut table = [*p; 8];
    for i in 1..8 {
        table[i] = table[i - 1].add(&p2);
    }
    table
}

/// Computes `[a]A + [b]B` in **variable time**.
///
/// Only for public inputs (signature verification). Requires reduced scalars.
pub(crate) fn vartime_double_scalar_mul_base(
    a: &Scalar,
    pa: &EdwardsPoint,
    b: &Scalar,
) -> EdwardsPoint {
    let a_naf = naf(&a.to_bytes(), 5);
    let b_naf = naf(&b.to_bytes(), 5);
    let ta = odd_multiples(pa);
    let tb = odd_multiples(&EdwardsPoint::BASE);
    let mut i = 447;
    while i > 0 && a_naf[i] == 0 && b_naf[i] == 0 {
        i -= 1;
    }
    let mut r = EdwardsPoint::IDENTITY;
    loop {
        r = r.double();
        for (digit, table) in [(a_naf[i], &ta), (b_naf[i], &tb)] {
            if digit > 0 {
                r = r.add(&table[(digit / 2) as usize]);
            } else if digit < 0 {
                r = r.add(&table[(-digit / 2) as usize].neg());
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoding of B: y(B) little endian with the sign of x (even).
    const B_BYTES: &str = "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900";

    fn dec_to_le56(s: &str) -> [u8; 56] {
        let mut out = [0u8; 56];
        for ch in s.bytes() {
            let mut carry = u32::from(ch - b'0');
            for b in &mut out {
                let v = u32::from(*b) * 10 + carry;
                *b = v as u8;
                carry = v >> 8;
            }
            assert_eq!(carry, 0);
        }
        out
    }

    fn scalar(bytes: &[u8; 57]) -> Scalar {
        Scalar::from_bytes_mod_order(bytes)
    }

    /// Naive double-and-add reference.
    fn mul_ref(s: &[u8; 57], p: &EdwardsPoint) -> EdwardsPoint {
        let mut r = EdwardsPoint::IDENTITY;
        for i in (0..456).rev() {
            r = r.double();
            if (s[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.add(p);
            }
        }
        r
    }

    fn eq(p: &EdwardsPoint, q: &EdwardsPoint) -> bool {
        p.compress() == q.compress()
    }

    #[test]
    fn base_point_matches_the_rfc() {
        // RFC 8032 Table 2 / RFC 7748 §4.2, X(P) and Y(P) of edwards448.
        let x = dec_to_le56(
            "224580040295924300187604334099896036246789641632564134246125461\
             686950415467406032909029192869357953282578032075146446173674602635\
             247710",
        );
        let y = dec_to_le56(
            "298819210078481492676017930443930673437544040154080242095928241\
             372331506189835876003536878655418784733982303233503462500531545062\
             832660",
        );
        let b = EdwardsPoint::BASE;
        assert_eq!(b.x.to_bytes(), x);
        assert_eq!(b.y.to_bytes(), y);
        // On the curve: x^2 + y^2 = 1 + d x^2 y^2.
        let xx = b.x.square();
        let yy = b.y.square();
        let lhs = xx.add(&yy);
        let rhs = Fe::ONE.sub(&xx.mul(&yy).mul_small(D_ABS));
        assert!(lhs.ct_eq(&rhs).declassify());
        let enc = b.compress();
        assert_eq!(hex::encode(enc), B_BYTES);
        let dec = EdwardsPoint::decompress(&enc).unwrap();
        assert!(eq(&dec, &b));
        assert_eq!(dec.x.to_bytes(), x);
        // The 4-isogeny maps B to the curve448 base point u = 5.
        let mut five = [0u8; 56];
        five[0] = 5;
        assert_eq!(b.to_montgomery_u(), five);
    }

    #[test]
    fn group_order() {
        // [L]B = O and [L - 1]B = -B.
        let mut l = [0u8; 57];
        l.copy_from_slice(&hex::decode("f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00").unwrap());
        assert!(mul_ref(&l, &EdwardsPoint::BASE).is_identity());
        let mut lm1 = l;
        lm1[0] -= 1;
        let p = EdwardsPoint::mul_base(&scalar(&lm1));
        assert!(eq(&p, &EdwardsPoint::BASE.neg()));
        assert!(!EdwardsPoint::BASE.is_small_order());
        assert!(EdwardsPoint::IDENTITY.is_small_order());
    }

    #[test]
    fn mul_matches_reference() {
        let b = EdwardsPoint::BASE;
        let mut st = 0x1234_5678_9abc_def0u64;
        for n in 0..12 {
            let mut s = [0u8; 57];
            for byte in s.iter_mut().take(55) {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (st >> 56) as u8;
            }
            if n == 0 {
                s = [0; 57];
            } else if n == 1 {
                s[..55].fill(0xff);
                s[55] = 0x3f;
            }
            let k = scalar(&s);
            let expect = mul_ref(&k.to_bytes(), &b);
            assert!(eq(&EdwardsPoint::mul_base(&k), &expect));
            assert!(eq(
                &vartime_double_scalar_mul_base(&Scalar::ZERO, &b, &k),
                &expect
            ));
            assert!(eq(
                &vartime_double_scalar_mul_base(&k, &b, &Scalar::ZERO),
                &expect
            ));
            // [s]P + [t]B for a non-base P.
            let pt = EdwardsPoint::mul_base(&scalar(&[n as u8 + 3; 57]));
            let t = scalar(&[n as u8; 57]);
            let want = mul_ref(&k.to_bytes(), &pt).add(&mul_ref(&t.to_bytes(), &b));
            assert!(eq(&vartime_double_scalar_mul_base(&k, &pt, &t), &want));
            assert!(eq(&pt.mul(&k), &mul_ref(&k.to_bytes(), &pt)));
        }
    }

    #[test]
    fn decompress_rejects_noncanonical() {
        // y = p (non-canonical encoding of y = 0).
        let mut pb = [0xffu8; 57];
        pb[28] = 0xfe;
        pb[56] = 0;
        assert!(EdwardsPoint::decompress(&pb).is_none());
        // Any of the unused bits 448..454 set.
        let enc: [u8; 57] = hex::decode(B_BYTES).unwrap().try_into().unwrap();
        for bit in 0..7 {
            let mut e = enc;
            e[56] |= 1 << bit;
            assert!(EdwardsPoint::decompress(&e).is_none());
        }
        // The identity (y = 1, x = 0) decodes; with the sign bit set it fails.
        let mut one = [0u8; 57];
        one[0] = 1;
        let id = EdwardsPoint::decompress(&one).unwrap();
        assert!(id.is_identity());
        one[56] = 0x80;
        assert!(EdwardsPoint::decompress(&one).is_none());
        // (0, -1) has order 2.
        let mut m1 = [0xffu8; 57];
        m1[0] = 0xfe;
        m1[28] = 0xfe;
        m1[56] = 0;
        let p = EdwardsPoint::decompress(&m1).unwrap();
        assert!(p.is_small_order() && !p.is_identity());
        // y = 0: x^2 = -1 / -1 = 1, so (+-1, 0) are the points of order 4.
        let zero = [0u8; 57];
        let p = EdwardsPoint::decompress(&zero).unwrap();
        assert!(p.is_small_order() && !p.double().is_identity());
        // (y^2 - 1) / (d y^2 - 1) is a non-square for y = 2, 6, 10, 11 and a
        // square for y = 3, 4, 5, 7, 8, 9 (checked with an independent
        // big-integer computation); decoded points round-trip.
        for (y, on_curve) in [
            (2u8, false),
            (3, true),
            (4, true),
            (5, true),
            (6, false),
            (7, true),
            (8, true),
            (9, true),
            (10, false),
            (11, false),
        ] {
            let mut e = [0u8; 57];
            e[0] = y;
            let p = EdwardsPoint::decompress(&e);
            assert_eq!(p.is_some(), on_curve, "y = {y}");
            if let Some(p) = p {
                assert_eq!(p.compress(), e);
                let neg = p.neg().compress();
                assert_eq!(neg[56], 0x80);
            }
        }
        // Negation flips the sign bit and round-trips.
        let nb = EdwardsPoint::BASE.neg().compress();
        assert_eq!(nb[56], enc[56] ^ 0x80);
        assert!(eq(
            &EdwardsPoint::decompress(&nb).unwrap(),
            &EdwardsPoint::BASE.neg()
        ));
    }

    #[test]
    fn naf_reconstructs_scalar() {
        let mut st = 99u64;
        for _ in 0..50 {
            let mut s = [0u8; 57];
            for byte in s.iter_mut().take(55) {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (st >> 56) as u8;
            }
            s[55] &= 0x3f;
            for w in [2, 5, 8] {
                let digits = naf(&s, w);
                // Recompute sum(d_i 2^i) as a signed big integer in bytes.
                let mut acc = [0i64; 64];
                for (i, d) in digits.iter().enumerate() {
                    acc[i / 8] += i64::from(*d) << (i % 8);
                }
                let mut out = [0u8; 57];
                let mut carry = 0i64;
                for i in 0..57 {
                    let v = acc[i] + carry;
                    out[i] = v.rem_euclid(256) as u8;
                    carry = v.div_euclid(256);
                }
                assert_eq!(out, s, "w = {w}");
            }
        }
    }
}
