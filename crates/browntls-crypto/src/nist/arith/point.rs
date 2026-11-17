//! Points: the generic code behind `AffinePoint` and `ProjectivePoint`.
//!
//! A projective point is always a valid representative of a curve point:
//! the generator, the identity `(0 : 1 : 0)`, a validated affine point
//! lifted to `Z = 1`, the output of the complete formulas (or of the
//! scalar multiplications built on them) applied to such points, or the
//! output of the variable-time Jacobian double multiplication converted by
//! `jacobian::to_projective` (`(X Z : Y : Z^3)`, which maps the Jacobian
//! identity `(1 : 1 : 0)` to `(0 : 1 : 0)`). The
//! complete formulas of Renes, Costello and Batina need nothing more: no
//! case of their inputs (identity, equal points, opposite points) is
//! exceptional. An affine point carries an identity mask (all ones for the
//! identity, whose coordinates are then zero, a pair no curve point has),
//! so that the conversions are total and constant time.
//!
//! The variable-time double multiplication of signature verification is
//! exposed only under a `vartime` name, for public inputs.

use crate::Error;
use crate::ct::Choice;
use crate::nist::curve::{
    Affine, Curve, Fe, Projective, add as rcb_add, add_mixed as rcb_add_mixed,
    double as rcb_double, is_on_curve, to_affine as to_affine_vartime,
};
use crate::nist::{jacobian, keys, mont, scalar_mul};
use crate::zeroize::zeroize_u64;

use super::{Arith, choice, on_backend, public, scalar};

/// The identity mask of an affine point that is not the identity.
pub(crate) const FINITE: u64 = 0;
/// The identity mask of the affine identity.
pub(crate) const INFINITE: u64 = u64::MAX;

/// Lifts an affine point with identity mask `inf` (constant time).
pub(crate) fn from_affine<A: Arith<N>, const N: usize>(a: &Affine<N>, inf: u64) -> Projective<N> {
    let one = <A::Soft as Curve<N>>::ONE;
    let m = mont::barrier(inf);
    // The identity's affine coordinates are zero, so only Y and Z change.
    Projective {
        x: a.x,
        y: mont::select(m, &one, &a.y),
        z: mont::select(m, &[0; N], &one),
    }
}

fn to_affine_with<C: Curve<N>, const N: usize>(p: &Projective<N>) -> (Affine<N>, u64) {
    let zi = C::invert(&p.z);
    let inf = mont::is_zero(&p.z);
    // The identity's coordinates are (0, 0), selected by its mask rather
    // than left to the inversion's mapping of 0 to 0.
    let m = mont::barrier(inf);
    let a = Affine {
        x: mont::select(m, &[0; N], &C::mul(&p.x, &zi)),
        y: mont::select(m, &[0; N], &C::mul(&p.y, &zi)),
    };
    (a, inf)
}

/// Normalises to affine coordinates and the identity mask (constant time:
/// one inversion whatever the point).
pub(crate) fn to_affine<A: Arith<N>, const N: usize>(p: &Projective<N>) -> (Affine<N>, u64) {
    on_backend!(A, to_affine_with(p))
}

/// `p + q` (complete).
pub(crate) fn add<A: Arith<N>, const N: usize>(
    p: &Projective<N>,
    q: &Projective<N>,
) -> Projective<N> {
    on_backend!(A, rcb_add(p, q))
}

/// `p + q` for an affine `q` with identity mask `q_inf`: the complete mixed
/// formula, whose result is discarded (in constant time) for the identity,
/// the one input it does not cover.
pub(crate) fn add_affine<A: Arith<N>, const N: usize>(
    p: &Projective<N>,
    q: &Affine<N>,
    q_inf: u64,
) -> Projective<N> {
    let sum = on_backend!(A, rcb_add_mixed(p, q));
    Projective::select(q_inf, p, &sum)
}

/// `2 p` (complete).
pub(crate) fn double<A: Arith<N>, const N: usize>(p: &Projective<N>) -> Projective<N> {
    on_backend!(A, rcb_double(p))
}

/// `-p`: `(X : -Y : Z)`.
pub(crate) fn neg<A: Arith<N>, const N: usize>(p: &Projective<N>) -> Projective<N> {
    Projective {
        x: p.x,
        y: super::field::neg::<A, N>(&p.y),
        z: p.z,
    }
}

/// `k p` for a scalar `k` in Montgomery form, in constant time in `k` and
/// `p`; the canonical copy of `k` is wiped.
pub(crate) fn mul<A: Arith<N>, const N: usize>(p: &Projective<N>, k: &[u64; N]) -> Projective<N> {
    use scalar_mul::mul_projective;
    let mut c = scalar::canonical::<A, N>(k);
    let r = on_backend!(A, mul_projective(p, &c));
    zeroize_u64(&mut c);
    r
}

/// `k G` with the comb table, in constant time in `k`; the canonical copy
/// of `k` is wiped.
pub(crate) fn mul_by_generator<A: Arith<N>, const N: usize>(k: &[u64; N]) -> Projective<N> {
    use scalar_mul::mul_base;
    let mut c = scalar::canonical::<A, N>(k);
    let r = on_backend!(A, mul_base(&c));
    zeroize_u64(&mut c);
    r
}

fn lincomb_vartime_with<C: Curve<N>, const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    p: &Projective<N>,
) -> Projective<N> {
    // Variable time: the identity takes another path (b p = 0 for it).
    let (b, q) = match to_affine_vartime::<C, N>(p) {
        Some(q) => (*b, q),
        None => ([0; N], C::G),
    };
    let (j, _) = scalar_mul::mul_double_vartime::<C, N>(a, &b, &q);
    jacobian::to_projective::<C, N>(&j)
}

/// `a G + b p` in variable time (interleaved wNAF in Jacobian coordinates,
/// as in signature verification): for public inputs only.
pub(crate) fn lincomb_vartime<A: Arith<N>, const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    p: &Projective<N>,
) -> Projective<N> {
    let a = scalar::canonical::<A, N>(a);
    let b = scalar::canonical::<A, N>(b);
    on_backend!(A, lincomb_vartime_with(&a, &b, p))
}

fn eq_with<C: Curve<N>, const N: usize>(p: &Projective<N>, q: &Projective<N>) -> u64 {
    // X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1. Representatives of the identity have
    // X = Z = 0 and Y != 0, so it equals only itself.
    let x = mont::eq(&C::mul(&p.x, &q.z), &C::mul(&q.x, &p.z));
    let y = mont::eq(&C::mul(&p.y, &q.z), &C::mul(&q.y, &p.z));
    x & y
}

/// Whether `p` and `q` are the same point (constant time).
pub(crate) fn ct_eq<A: Arith<N>, const N: usize>(p: &Projective<N>, q: &Projective<N>) -> Choice {
    choice(on_backend!(A, eq_with(p, q)))
}

/// Whether `p` is the identity (constant time).
pub(crate) fn is_identity<const N: usize>(p: &Projective<N>) -> Choice {
    choice(mont::is_zero(&p.z))
}

/// Whether two affine points (with their masks) are equal (constant time).
pub(crate) fn affine_eq<const N: usize>(
    a: &Affine<N>,
    a_inf: u64,
    b: &Affine<N>,
    b_inf: u64,
) -> Choice {
    choice(mont::eq(&a.x, &b.x) & mont::eq(&a.y, &b.y) & !(a_inf ^ b_inf))
}

/// `-a` for an affine point (the identity, `(0, 0)`, stays itself).
pub(crate) fn affine_neg<A: Arith<N>, const N: usize>(a: &Affine<N>) -> Affine<N> {
    Affine {
        x: a.x,
        y: super::field::neg::<A, N>(&a.y),
    }
}

fn on_curve_with<C: Curve<N>, const N: usize>(a: &Affine<N>) -> bool {
    is_on_curve::<C, N>(a)
}

/// Validates coordinates: `y^2 = x^3 - 3x + b`. The check is constant time;
/// its outcome is public.
pub(crate) fn from_coordinates<A: Arith<N>, const N: usize>(
    x: &Fe<N>,
    y: &Fe<N>,
) -> Result<Affine<N>, Error> {
    let a = Affine { x: *x, y: *y };
    if on_backend!(A, on_curve_with(&a)) {
        Ok(a)
    } else {
        Err(Error::InvalidKey)
    }
}

/// Decodes a SEC 1 point: `00` (the identity), `04 || X || Y` or
/// `02/03 || X`, with full validation (variable time, for public inputs).
pub(crate) fn decode<A: Arith<N>, const N: usize>(bytes: &[u8]) -> Result<(Affine<N>, u64), Error> {
    if bytes == [0] {
        return Ok((Affine::ZERO, INFINITE));
    }
    keys::decode_point::<A::Soft, N>(bytes).map(|a| (a, FINITE))
}

/// Encodes a point into `out` (`1 + 2 FIELD_LEN` bytes) and returns the
/// length: `00` for the identity, else compressed or uncompressed. The
/// length reveals whether the point is the identity.
pub(crate) fn encode<A: Arith<N>, const N: usize>(
    a: &Affine<N>,
    inf: u64,
    compress: bool,
    out: &mut [u8],
) -> usize {
    let fl = <A::Soft as Curve<N>>::FIELD_LEN;
    if public(inf) {
        out[0] = 0;
        return 1;
    }
    keys::encode_uncompressed::<A::Soft, N>(a, &mut out[..1 + 2 * fl]);
    if compress {
        out[0] = 2 | (out[2 * fl] & 1);
        out[1 + fl..].fill(0);
        1 + fl
    } else {
        1 + 2 * fl
    }
}

/// Zeroises a projective point and leaves the identity.
pub(crate) fn wipe<A: Arith<N>, const N: usize>(p: &mut Projective<N>) {
    zeroize_u64(&mut p.x);
    zeroize_u64(&mut p.y);
    zeroize_u64(&mut p.z);
    p.y = <A::Soft as Curve<N>>::ONE;
}
