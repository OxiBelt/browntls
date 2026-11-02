//! Curve parameters, point representations and the complete addition formulas.
//!
//! Field elements are `[u64; N]` in Montgomery form (`x * R mod p`, with
//! `R = 2^(64N)`). Points use homogeneous projective coordinates `(X : Y : Z)`
//! with `x = X/Z`, `y = Y/Z`; the identity is `(0 : 1 : 0)`.
//!
//! The group law uses the complete formulas of Renes, Costello and Batina
//! ("Complete addition formulas for prime order elliptic curves", EUROCRYPT
//! 2016), algorithms 4 (addition), 5 (mixed addition) and 6 (doubling) for
//! `a = -3`. They are exception-free, so the constant-time scalar
//! multiplications never need to special-case the identity, doubling or
//! inverses. Field multiplication goes through [`Curve::mul`], which a
//! backend (such as the x86-64 BMI2/ADX kernel for P-256) can override.

use super::mont;

/// A field element: `N` little-endian limbs in Montgomery form.
pub(crate) type Fe<const N: usize> = [u64; N];

/// An affine point `(x, y)` in Montgomery form. Never the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Affine<const N: usize> {
    pub(crate) x: Fe<N>,
    pub(crate) y: Fe<N>,
}

impl<const N: usize> Affine<N> {
    /// A placeholder (not a curve point) for table initialisation and masked
    /// lookups that select nothing.
    pub(crate) const ZERO: Self = Self {
        x: [0; N],
        y: [0; N],
    };
}

/// A projective point `(X : Y : Z)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Projective<const N: usize> {
    pub(crate) x: Fe<N>,
    pub(crate) y: Fe<N>,
    pub(crate) z: Fe<N>,
}

impl<const N: usize> Projective<N> {
    /// An all-zero value (only for array initialisation).
    pub(crate) const ZERO: Self = Self {
        x: [0; N],
        y: [0; N],
        z: [0; N],
    };

    /// `(0 : 1 : 0)`, the identity, for curve `C`.
    pub(crate) const fn identity<C: Curve<N>>() -> Self {
        Self {
            x: [0; N],
            y: C::ONE,
            z: [0; N],
        }
    }

    /// Lifts an affine point (`Z = 1`).
    pub(crate) const fn from_affine<C: Curve<N>>(a: &Affine<N>) -> Self {
        Self {
            x: a.x,
            y: a.y,
            z: C::ONE,
        }
    }

    /// Returns `a` when `mask` is all ones, otherwise `b` (constant time; the
    /// mask is barriered here).
    #[inline]
    pub(crate) fn select(mask: u64, a: &Self, b: &Self) -> Self {
        let m = mont::barrier(mask);
        Self {
            x: mont::select(m, &a.x, &b.x),
            y: mont::select(m, &a.y, &b.y),
            z: mont::select(m, &a.z, &b.z),
        }
    }
}

/// A short Weierstrass curve `y^2 = x^3 - 3x + b` over `GF(p)` with prime order
/// `n`, with all constants in Montgomery form where applicable.
///
/// `N` is the limb count of both the field and the scalar representation.
pub(crate) trait Curve<const N: usize>: Copy + 'static {
    /// Bit length of `p` (and of `n`).
    const BITS: usize;
    /// Byte length of a field element / scalar encoding.
    const FIELD_LEN: usize;
    /// The field prime.
    const P: [u64; N];
    /// `-p^-1 mod 2^64`.
    const P_INV: u64;
    /// `R mod p`: one in Montgomery form.
    const ONE: Fe<N>;
    /// `R^2 mod p`.
    const R2: Fe<N>;
    /// `p - 2`, the Fermat inversion exponent.
    const P_MINUS_2: [u64; N];
    /// The group order `n`.
    const ORDER: [u64; N];
    /// `-n^-1 mod 2^64`.
    const ORDER_INV: u64;
    /// `R mod n`.
    const ORDER_ONE: [u64; N];
    /// `R^2 mod n`.
    const ORDER_R2: [u64; N];
    /// `n - 2`.
    const ORDER_MINUS_2: [u64; N];
    /// The coefficient `b` in Montgomery form.
    const B: Fe<N>;
    /// The base point in Montgomery form (run-time use is in the table
    /// generator tests; the tables carry its multiples).
    #[allow(dead_code)]
    const G: Affine<N>;
    /// DER contents of the curve's `namedCurve` OBJECT IDENTIFIER.
    const OID: &'static [u8];
    /// Fixed-base comb table: entry `[j][m - 1]` is `m * 2^(16 j) * G` for `m`
    /// in `1..=8` (see `scalar_mul::mul_base`).
    const BASE_TABLE: &'static [[Affine<N>; 8]];
    /// Odd multiples `(2i + 1) * G` for `i` in `0..16` (verification wNAF table).
    const G_ODD: &'static [Affine<N>; 16];

    /// Montgomery multiplication in the field (backend-specific).
    fn mul(a: &Fe<N>, b: &Fe<N>) -> Fe<N>;

    /// Montgomery squaring in the field.
    #[inline]
    fn sqr(a: &Fe<N>) -> Fe<N> {
        Self::mul(a, a)
    }
}

/// Field addition.
#[inline(always)]
pub(crate) fn fe_add<C: Curve<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    mont::add_mod(a, b, &C::P)
}

/// Field subtraction.
#[inline(always)]
pub(crate) fn fe_sub<C: Curve<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    mont::sub_mod(a, b, &C::P)
}

/// Field negation.
#[inline(always)]
pub(crate) fn fe_neg<C: Curve<N>, const N: usize>(a: &Fe<N>) -> Fe<N> {
    mont::neg_mod(a, &C::P)
}

/// Portable Montgomery multiplication.
#[inline(always)]
pub(crate) fn fe_mul_soft<C: Curve<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    mont::mont_mul(a, b, &C::P, C::P_INV)
}

/// Converts into the field's Montgomery form (`a < p`). Evaluable at compile
/// time for the curve constants; at run time only used on public values.
#[inline]
pub(crate) const fn fe_from_canonical<C: Curve<N>, const N: usize>(a: &[u64; N]) -> Fe<N> {
    mont::to_mont_const(a, &C::P, C::P_INV, &C::R2)
}

/// Converts out of Montgomery form.
#[inline]
pub(crate) fn fe_to_canonical<C: Curve<N>, const N: usize>(a: &Fe<N>) -> [u64; N] {
    mont::from_mont(a, &C::P, C::P_INV)
}

/// Constant-time field inversion (`0` maps to `0`).
///
/// Fermat: left-to-right fixed 4-bit windows over the public exponent `p - 2`;
/// the operation sequence is independent of `a`.
pub(crate) fn fe_invert<C: Curve<N>, const N: usize>(a: &Fe<N>) -> Fe<N> {
    let mut table = [[0u64; N]; 16];
    table[0] = C::ONE;
    for i in 1..16 {
        table[i] = C::mul(&table[i - 1], a);
    }
    let exp = &C::P_MINUS_2;
    let mut w = 16 * N;
    while w > 0 && mont::bits(exp, 4 * (w - 1), 4) == 0 {
        w -= 1;
    }
    let mut acc = C::ONE;
    while w > 0 {
        w -= 1;
        for _ in 0..4 {
            acc = C::sqr(&acc);
        }
        let d = mont::bits(exp, 4 * w, 4) as usize;
        if d != 0 {
            acc = C::mul(&acc, &table[d]);
        }
    }
    acc
}

/// Complete projective addition (RCB algorithm 4, `a = -3`).
pub(crate) fn add<C: Curve<N>, const N: usize>(
    p: &Projective<N>,
    q: &Projective<N>,
) -> Projective<N> {
    let t0 = C::mul(&p.x, &q.x);
    let t1 = C::mul(&p.y, &q.y);
    let t2 = C::mul(&p.z, &q.z);
    let t3 = fe_add::<C, N>(&p.x, &p.y);
    let t4 = fe_add::<C, N>(&q.x, &q.y);
    let t3 = C::mul(&t3, &t4);
    let t4 = fe_add::<C, N>(&t0, &t1);
    let t3 = fe_sub::<C, N>(&t3, &t4);
    let t4 = fe_add::<C, N>(&p.y, &p.z);
    let x3 = fe_add::<C, N>(&q.y, &q.z);
    let t4 = C::mul(&t4, &x3);
    let x3 = fe_add::<C, N>(&t1, &t2);
    let t4 = fe_sub::<C, N>(&t4, &x3);
    let x3 = fe_add::<C, N>(&p.x, &p.z);
    let y3 = fe_add::<C, N>(&q.x, &q.z);
    let x3 = C::mul(&x3, &y3);
    let y3 = fe_add::<C, N>(&t0, &t2);
    let y3 = fe_sub::<C, N>(&x3, &y3);
    let z3 = C::mul(&C::B, &t2);
    let x3 = fe_sub::<C, N>(&y3, &z3);
    let z3 = fe_add::<C, N>(&x3, &x3);
    let x3 = fe_add::<C, N>(&x3, &z3);
    let z3 = fe_sub::<C, N>(&t1, &x3);
    let x3 = fe_add::<C, N>(&t1, &x3);
    let y3 = C::mul(&C::B, &y3);
    let t1 = fe_add::<C, N>(&t2, &t2);
    let t2 = fe_add::<C, N>(&t1, &t2);
    let y3 = fe_sub::<C, N>(&y3, &t2);
    let y3 = fe_sub::<C, N>(&y3, &t0);
    let t1 = fe_add::<C, N>(&y3, &y3);
    let y3 = fe_add::<C, N>(&t1, &y3);
    let t1 = fe_add::<C, N>(&t0, &t0);
    let t0 = fe_add::<C, N>(&t1, &t0);
    let t0 = fe_sub::<C, N>(&t0, &t2);
    let t1 = C::mul(&t4, &y3);
    let t2 = C::mul(&t0, &y3);
    let y3 = C::mul(&x3, &z3);
    let y3 = fe_add::<C, N>(&y3, &t2);
    let x3 = C::mul(&t3, &x3);
    let x3 = fe_sub::<C, N>(&x3, &t1);
    let z3 = C::mul(&t4, &z3);
    let t1 = C::mul(&t3, &t0);
    let z3 = fe_add::<C, N>(&z3, &t1);
    Projective {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Complete mixed addition with an affine `q` (RCB algorithm 5, `a = -3`).
pub(crate) fn add_mixed<C: Curve<N>, const N: usize>(
    p: &Projective<N>,
    q: &Affine<N>,
) -> Projective<N> {
    let t0 = C::mul(&p.x, &q.x);
    let t1 = C::mul(&p.y, &q.y);
    let t3 = fe_add::<C, N>(&q.x, &q.y);
    let t4 = fe_add::<C, N>(&p.x, &p.y);
    let t3 = C::mul(&t3, &t4);
    let t4 = fe_add::<C, N>(&t0, &t1);
    let t3 = fe_sub::<C, N>(&t3, &t4);
    let t4 = C::mul(&q.y, &p.z);
    let t4 = fe_add::<C, N>(&t4, &p.y);
    let y3 = C::mul(&q.x, &p.z);
    let y3 = fe_add::<C, N>(&y3, &p.x);
    let z3 = C::mul(&C::B, &p.z);
    let x3 = fe_sub::<C, N>(&y3, &z3);
    let z3 = fe_add::<C, N>(&x3, &x3);
    let x3 = fe_add::<C, N>(&x3, &z3);
    let z3 = fe_sub::<C, N>(&t1, &x3);
    let x3 = fe_add::<C, N>(&t1, &x3);
    let y3 = C::mul(&C::B, &y3);
    let t1 = fe_add::<C, N>(&p.z, &p.z);
    let t2 = fe_add::<C, N>(&t1, &p.z);
    let y3 = fe_sub::<C, N>(&y3, &t2);
    let y3 = fe_sub::<C, N>(&y3, &t0);
    let t1 = fe_add::<C, N>(&y3, &y3);
    let y3 = fe_add::<C, N>(&t1, &y3);
    let t1 = fe_add::<C, N>(&t0, &t0);
    let t0 = fe_add::<C, N>(&t1, &t0);
    let t0 = fe_sub::<C, N>(&t0, &t2);
    let t1 = C::mul(&t4, &y3);
    let t2 = C::mul(&t0, &y3);
    let y3 = C::mul(&x3, &z3);
    let y3 = fe_add::<C, N>(&y3, &t2);
    let x3 = C::mul(&t3, &x3);
    let x3 = fe_sub::<C, N>(&x3, &t1);
    let z3 = C::mul(&t4, &z3);
    let t1 = C::mul(&t3, &t0);
    let z3 = fe_add::<C, N>(&z3, &t1);
    Projective {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Complete doubling (RCB algorithm 6, `a = -3`).
pub(crate) fn double<C: Curve<N>, const N: usize>(p: &Projective<N>) -> Projective<N> {
    let t0 = C::sqr(&p.x);
    let t1 = C::sqr(&p.y);
    let t2 = C::sqr(&p.z);
    let t3 = C::mul(&p.x, &p.y);
    let t3 = fe_add::<C, N>(&t3, &t3);
    let z3 = C::mul(&p.x, &p.z);
    let z3 = fe_add::<C, N>(&z3, &z3);
    let y3 = C::mul(&C::B, &t2);
    let y3 = fe_sub::<C, N>(&y3, &z3);
    let x3 = fe_add::<C, N>(&y3, &y3);
    let y3 = fe_add::<C, N>(&x3, &y3);
    let x3 = fe_sub::<C, N>(&t1, &y3);
    let y3 = fe_add::<C, N>(&t1, &y3);
    let y3 = C::mul(&x3, &y3);
    let x3 = C::mul(&x3, &t3);
    let t3 = fe_add::<C, N>(&t2, &t2);
    let t2 = fe_add::<C, N>(&t2, &t3);
    let z3 = C::mul(&C::B, &z3);
    let z3 = fe_sub::<C, N>(&z3, &t2);
    let z3 = fe_sub::<C, N>(&z3, &t0);
    let t3 = fe_add::<C, N>(&z3, &z3);
    let z3 = fe_add::<C, N>(&z3, &t3);
    let t3 = fe_add::<C, N>(&t0, &t0);
    let t0 = fe_add::<C, N>(&t3, &t0);
    let t0 = fe_sub::<C, N>(&t0, &t2);
    let t0 = C::mul(&t0, &z3);
    let y3 = fe_add::<C, N>(&y3, &t0);
    let t0 = C::mul(&p.y, &p.z);
    let t0 = fe_add::<C, N>(&t0, &t0);
    let z3 = C::mul(&t0, &z3);
    let x3 = fe_sub::<C, N>(&x3, &z3);
    let z3 = C::mul(&t0, &t1);
    let z3 = fe_add::<C, N>(&z3, &z3);
    let z3 = fe_add::<C, N>(&z3, &z3);
    Projective {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Converts to affine coordinates in constant time. Returns `None` for the
/// identity (`Z = 0`), which is a public outcome.
pub(crate) fn to_affine<C: Curve<N>, const N: usize>(p: &Projective<N>) -> Option<Affine<N>> {
    let zi = fe_invert::<C, N>(&p.z);
    let a = Affine {
        x: C::mul(&p.x, &zi),
        y: C::mul(&p.y, &zi),
    };
    if crate::ct::Choice::from_bit(mont::is_zero(&p.z) & 1).declassify() {
        None
    } else {
        Some(a)
    }
}

/// `y^2 == x^3 - 3x + b` for an affine point in Montgomery form.
pub(crate) fn is_on_curve<C: Curve<N>, const N: usize>(a: &Affine<N>) -> bool {
    let y2 = C::sqr(&a.y);
    let x2 = C::sqr(&a.x);
    let x3 = C::mul(&x2, &a.x);
    let three_x = fe_add::<C, N>(&fe_add::<C, N>(&a.x, &a.x), &a.x);
    let rhs = fe_add::<C, N>(&fe_sub::<C, N>(&x3, &three_x), &C::B);
    mont::eq(&y2, &rhs) == u64::MAX
}
