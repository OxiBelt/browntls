//! Variable-time Jacobian arithmetic for signature verification (public
//! inputs only).
//!
//! A point `(X : Y : Z)` stands for `(X / Z^2, Y / Z^3)`; `Z = 0` is the
//! identity. The formulas are the classic `a = -3` doubling (4M + 4S) and the
//! addition with `H = U2 - U1`, `R = S2 - S1` (mixed: 8M + 3S, general:
//! 12M + 4S). They are not complete, so the exceptional cases are handled
//! explicitly with branches on public data: either operand the identity,
//! `P = Q` (doubling) and `P = -Q` (the identity). Prime-order curves have no
//! points of order two, so doubling has no exceptional case besides the
//! identity, which it maps to itself.
//!
//! The additions are **not constant time**: never use them with secret
//! scalars or points. [`double`] and the coordinate conversions are
//! branch-free and also serve the constant-time variable-base ladder, where
//! they run between complete additions.

use super::curve::{Affine, Curve, Fe, Projective};
use super::mont;

/// A Jacobian point.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Jacobian<const N: usize> {
    pub(crate) x: Fe<N>,
    pub(crate) y: Fe<N>,
    pub(crate) z: Fe<N>,
}

impl<const N: usize> Jacobian<N> {
    /// The identity `(1 : 1 : 0)`.
    pub(crate) const fn identity<C: Curve<N>>() -> Self {
        Self {
            x: C::ONE,
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

    /// Whether this is the identity (public).
    #[inline]
    pub(crate) fn is_identity(&self) -> bool {
        mont::is_zero(&self.z) != 0
    }
}

/// Converts homogeneous `(X : Y : Z)` to Jacobian `(X Z : Y Z^2 : Z)` in
/// constant time. The identity (`Z = 0`) becomes `(1 : 1 : 0)`, a fixed point
/// of [`double`].
#[inline]
pub(crate) fn from_projective_ct<C: Curve<N>, const N: usize>(p: &Projective<N>) -> Jacobian<N> {
    let z2 = C::sqr(&p.z);
    let x = C::mul(&p.x, &p.z);
    let y = C::mul(&p.y, &z2);
    let id = mont::barrier(mont::is_zero(&p.z));
    Jacobian {
        x: mont::select(id, &C::ONE, &x),
        y: mont::select(id, &C::ONE, &y),
        z: p.z,
    }
}

/// Converts Jacobian `(X : Y : Z)` to homogeneous `(X Z : Y : Z^3)` (branch
/// free; the identity `(1 : 1 : 0)` becomes `(0 : 1 : 0)`).
#[inline]
pub(crate) fn to_projective<C: Curve<N>, const N: usize>(p: &Jacobian<N>) -> Projective<N> {
    Projective {
        x: C::mul(&p.x, &p.z),
        y: p.y,
        z: C::mul(&C::sqr(&p.z), &p.z),
    }
}

#[inline]
fn is_zero<const N: usize>(a: &Fe<N>) -> bool {
    mont::is_zero(a) != 0
}

/// `2P` (`a = -3`), branch free. The identity `(X : Y : 0)` stays at `Z = 0`
/// and `(1 : 1 : 0)` maps to itself.
pub(crate) fn double<C: Curve<N>, const N: usize>(p: &Jacobian<N>) -> Jacobian<N> {
    let delta = C::sqr(&p.z);
    let gamma = C::sqr(&p.y);
    let beta = C::mul(&p.x, &gamma);
    // alpha = 3 (X - delta)(X + delta)
    let t = C::mul(&C::sub(&p.x, &delta), &C::add(&p.x, &delta));
    let alpha = C::add(&C::add(&t, &t), &t);
    let beta2 = C::add(&beta, &beta);
    let beta4 = C::add(&beta2, &beta2);
    let beta8 = C::add(&beta4, &beta4);
    let x3 = C::sub(&C::sqr(&alpha), &beta8);
    let yz = C::mul(&p.y, &p.z);
    let z3 = C::add(&yz, &yz);
    let g1 = C::sqr(&gamma);
    let g2 = C::add(&g1, &g1);
    let g4 = C::add(&g2, &g2);
    let g8 = C::add(&g4, &g4);
    let y3 = C::sub(&C::mul(&alpha, &C::sub(&beta4, &x3)), &g8);
    Jacobian {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Completes an addition from `U1`, `S1`, `H = U2 - U1`, `R = S2 - S1` and
/// `Z3 / H`.
#[inline]
fn finish<C: Curve<N>, const N: usize>(
    u1: &Fe<N>,
    s1: &Fe<N>,
    h: &Fe<N>,
    r: &Fe<N>,
    z_part: &Fe<N>,
) -> Jacobian<N> {
    let hh = C::sqr(h);
    let hhh = C::mul(h, &hh);
    let v = C::mul(u1, &hh);
    let x3 = C::sub(&C::sub(&C::sqr(r), &hhh), &C::add(&v, &v));
    let y3 = C::sub(&C::mul(r, &C::sub(&v, &x3)), &C::mul(s1, &hhh));
    let z3 = C::mul(z_part, h);
    Jacobian {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// `P + Q` for an affine `Q`.
pub(crate) fn add_mixed<C: Curve<N>, const N: usize>(
    p: &Jacobian<N>,
    q: &Affine<N>,
) -> Jacobian<N> {
    if p.is_identity() {
        return Jacobian::from_affine::<C>(q);
    }
    let z1z1 = C::sqr(&p.z);
    let u2 = C::mul(&q.x, &z1z1);
    let s2 = C::mul(&q.y, &C::mul(&p.z, &z1z1));
    let h = C::sub(&u2, &p.x);
    let r = C::sub(&s2, &p.y);
    if is_zero(&h) {
        return if is_zero(&r) {
            double::<C, N>(p)
        } else {
            Jacobian::identity::<C>()
        };
    }
    finish::<C, N>(&p.x, &p.y, &h, &r, &p.z)
}

/// `P + Q`.
pub(crate) fn add<C: Curve<N>, const N: usize>(p: &Jacobian<N>, q: &Jacobian<N>) -> Jacobian<N> {
    if p.is_identity() {
        return *q;
    }
    if q.is_identity() {
        return *p;
    }
    let z1z1 = C::sqr(&p.z);
    let z2z2 = C::sqr(&q.z);
    let u1 = C::mul(&p.x, &z2z2);
    let u2 = C::mul(&q.x, &z1z1);
    let s1 = C::mul(&p.y, &C::mul(&q.z, &z2z2));
    let s2 = C::mul(&q.y, &C::mul(&p.z, &z1z1));
    let h = C::sub(&u2, &u1);
    let r = C::sub(&s2, &s1);
    if is_zero(&h) {
        return if is_zero(&r) {
            double::<C, N>(p)
        } else {
            Jacobian::identity::<C>()
        };
    }
    finish::<C, N>(&u1, &s1, &h, &r, &C::mul(&p.z, &q.z))
}

/// Whether the affine x-coordinate of `p` equals `x` (Montgomery form):
/// `X == x Z^2`, without an inversion. False for the identity.
pub(crate) fn x_equals<C: Curve<N>, const N: usize>(p: &Jacobian<N>, x: &Fe<N>) -> bool {
    !p.is_identity() && mont::eq(&C::mul(x, &C::sqr(&p.z)), &p.x) != 0
}

#[cfg(test)]
mod tests {
    use super::super::curve::{self, Projective, to_affine};
    use super::super::params::{P256, P384, P521};
    use super::*;

    fn to_affine_jacobian<C: Curve<N>, const N: usize>(p: &Jacobian<N>) -> Option<Affine<N>> {
        if p.is_identity() {
            return None;
        }
        let zi = curve::fe_invert::<C, N>(&p.z);
        let zi2 = C::sqr(&zi);
        Some(Affine {
            x: C::mul(&p.x, &zi2),
            y: C::mul(&p.y, &C::mul(&zi2, &zi)),
        })
    }

    /// A Jacobian representative of `a` with a non-trivial `Z`.
    fn rescale<C: Curve<N>, const N: usize>(a: &Affine<N>, z: &Fe<N>) -> Jacobian<N> {
        let z2 = C::sqr(z);
        Jacobian {
            x: C::mul(&a.x, &z2),
            y: C::mul(&a.y, &C::mul(&z2, z)),
            z: *z,
        }
    }

    /// The Jacobian formulas agree with the complete projective ones,
    /// including every exceptional case.
    fn check<C: Curve<N>, const N: usize>() {
        let g = C::G;
        let gp = Projective::from_affine::<C>(&g);
        let neg_g = Affine {
            x: g.x,
            y: curve::fe_neg::<C, N>(&g.y),
        };
        let g2 = to_affine::<C, N>(&curve::double::<C, N>(&gp)).unwrap();
        let g3 =
            to_affine::<C, N>(&curve::add_mixed::<C, N>(&curve::double::<C, N>(&gp), &g)).unwrap();
        let z = C::B; // an arbitrary non-zero, non-one field element
        let id = Jacobian::<N>::identity::<C>();
        let jg = rescale::<C, N>(&g, &z);
        // Doubling.
        assert_eq!(to_affine_jacobian::<C, N>(&double::<C, N>(&jg)), Some(g2));
        assert!(double::<C, N>(&id).is_identity());
        // Mixed addition: generic, identity, P = Q, P = -Q.
        let j2 = rescale::<C, N>(&g2, &C::sqr(&z));
        assert_eq!(
            to_affine_jacobian::<C, N>(&add_mixed::<C, N>(&j2, &g)),
            Some(g3)
        );
        assert_eq!(
            to_affine_jacobian::<C, N>(&add_mixed::<C, N>(&id, &g)),
            Some(g)
        );
        assert_eq!(
            to_affine_jacobian::<C, N>(&add_mixed::<C, N>(&jg, &g)),
            Some(g2)
        );
        assert!(add_mixed::<C, N>(&jg, &neg_g).is_identity());
        // General addition: generic, identities, P = Q, P = -Q.
        let jneg = rescale::<C, N>(&neg_g, &C::ONE);
        assert_eq!(to_affine_jacobian::<C, N>(&add::<C, N>(&j2, &jg)), Some(g3));
        assert_eq!(to_affine_jacobian::<C, N>(&add::<C, N>(&jg, &j2)), Some(g3));
        assert_eq!(to_affine_jacobian::<C, N>(&add::<C, N>(&id, &jg)), Some(g));
        assert_eq!(to_affine_jacobian::<C, N>(&add::<C, N>(&jg, &id)), Some(g));
        assert!(add::<C, N>(&id, &id).is_identity());
        let jg_other = rescale::<C, N>(&g, &C::sqr(&z));
        assert_eq!(
            to_affine_jacobian::<C, N>(&add::<C, N>(&jg, &jg_other)),
            Some(g2)
        );
        assert!(add::<C, N>(&jg_other, &jneg).is_identity());
        // Conversions round-trip, the identity included, and doubling in
        // Jacobian coordinates matches the complete projective doubling.
        let p3 = curve::add_mixed::<C, N>(&curve::double::<C, N>(&gp), &g);
        let j3 = from_projective_ct::<C, N>(&p3);
        assert_eq!(to_affine_jacobian::<C, N>(&j3), Some(g3));
        assert_eq!(to_affine::<C, N>(&to_projective::<C, N>(&j3)), Some(g3));
        assert_eq!(
            to_affine::<C, N>(&to_projective::<C, N>(&double::<C, N>(&j3))),
            to_affine::<C, N>(&curve::double::<C, N>(&p3))
        );
        let jid = from_projective_ct::<C, N>(&Projective::identity::<C>());
        assert_eq!((jid.x, jid.y, jid.z), (C::ONE, C::ONE, [0; N]));
        let jid2 = double::<C, N>(&jid);
        assert_eq!((jid2.x, jid2.y, jid2.z), (C::ONE, C::ONE, [0; N]));
        let pid = to_projective::<C, N>(&jid2);
        assert_eq!((pid.x, pid.y, pid.z), ([0; N], C::ONE, [0; N]));
        // x comparison.
        assert!(x_equals::<C, N>(&jg, &g.x));
        assert!(!x_equals::<C, N>(&jg, &g2.x));
        assert!(!x_equals::<C, N>(&id, &g.x));
    }

    #[test]
    fn p256_jacobian_formulas() {
        check::<P256, 4>();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn p256_adx_jacobian_formulas() {
        if super::super::p256_x86::available() {
            check::<super::super::p256_x86::P256Adx, 4>();
        }
    }

    #[test]
    fn p384_jacobian_formulas() {
        check::<P384, 6>();
    }

    #[test]
    fn p521_jacobian_formulas() {
        check::<P521, 9>();
    }
}
