//! `ProjectivePoint`: the group law and scalar multiplication.

/// Declares `ProjectivePoint` in a curve module.
macro_rules! projective_point {
    ($doc_name:literal, $arith:ty, $soft:ty, $n:literal) => {
        #[doc = concat!("A ", $doc_name, " point in homogeneous projective coordinates `(X : Y : Z)`.")]
        ///
        /// Always a point of the curve, the identity included: the group
        /// law uses the complete formulas of Renes, Costello and Batina
        /// (2016), which have no exceptional case (identity, doubling,
        /// opposite points), so every operation is total. Arithmetic,
        /// scalar multiplication, normalisation and comparison are constant
        /// time; only [`ProjectivePoint::mul_by_generator_and_mul_add_vartime`]
        /// is not. Field operations run on the backend the curve's
        /// acceleration policy selects for each call; they are not part of
        /// load-aware routing. `Copy`, not wiped on drop (it implements
        /// [`Zeroize`](crate::zeroize::Zeroize), which leaves the identity);
        /// `Debug` does not print the coordinates.
        #[derive(Clone, Copy)]
        pub struct ProjectivePoint(crate::nist::curve::Projective<$n>);

        impl ProjectivePoint {
            /// The identity `(0 : 1 : 0)`.
            pub const IDENTITY: Self = Self(crate::nist::curve::Projective::identity::<$soft>());
            /// The standard base point `G`.
            pub const GENERATOR: Self = Self(crate::nist::curve::Projective::from_affine::<$soft>(
                &<$soft as crate::nist::curve::Curve<$n>>::G,
            ));

            /// `self + rhs`.
            #[must_use]
            pub fn add(&self, rhs: &Self) -> Self {
                Self(crate::nist::arith::point::add::<$arith, $n>(
                    &self.0, &rhs.0,
                ))
            }

            /// `self - rhs`.
            #[must_use]
            pub fn sub(&self, rhs: &Self) -> Self {
                self.add(&rhs.neg())
            }

            /// `2 * self`.
            #[must_use]
            pub fn double(&self) -> Self {
                Self(crate::nist::arith::point::double::<$arith, $n>(&self.0))
            }

            /// `-self`.
            #[must_use]
            pub fn neg(&self) -> Self {
                Self(crate::nist::arith::point::neg::<$arith, $n>(&self.0))
            }

            /// `k * self`, constant time in `k` and in the point
            /// (fixed-window signed digits, masked table scans, complete
            /// additions). The canonical copy of `k` it makes is wiped; the
            /// result is not.
            #[must_use]
            pub fn mul(&self, k: &Scalar) -> Self {
                Self(crate::nist::arith::point::mul::<$arith, $n>(&self.0, &k.0))
            }

            /// `k * G` with the precomputed comb table of the base point,
            /// constant time in `k` (as for public key derivation).
            #[must_use]
            pub fn mul_by_generator(k: &Scalar) -> Self {
                Self(crate::nist::arith::point::mul_by_generator::<$arith, $n>(
                    &k.0,
                ))
            }

            /// `a * G + b * p` in **variable time**: the interleaved wNAF
            /// double multiplication of ECDSA verification, whose running
            /// time depends on `a`, `b` and `p`. Only for public inputs
            /// (such as signature verification); use [`ProjectivePoint::mul`]
            /// and [`ProjectivePoint::mul_by_generator`] for secrets.
            #[must_use]
            pub fn mul_by_generator_and_mul_add_vartime(a: &Scalar, b: &Scalar, p: &Self) -> Self {
                Self(crate::nist::arith::point::lincomb_vartime::<$arith, $n>(
                    &a.0, &b.0, &p.0,
                ))
            }

            /// The affine form, with one constant-time inversion (the
            /// identity gives [`AffinePoint::IDENTITY`]).
            #[must_use]
            pub fn to_affine(&self) -> AffinePoint {
                let (point, infinity) = crate::nist::arith::point::to_affine::<$arith, $n>(&self.0);
                AffinePoint { point, infinity }
            }

            /// Whether this is the identity (constant time).
            #[must_use]
            pub fn is_identity(&self) -> crate::ct::Choice {
                crate::nist::arith::point::is_identity(&self.0)
            }

            /// Whether `self` and `other` are the same point, whatever
            /// their representations (constant time).
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> crate::ct::Choice {
                crate::nist::arith::point::ct_eq::<$arith, $n>(&self.0, &other.0)
            }

            /// `self + rhs` for an affine `rhs` (mixed addition).
            fn add_affine(&self, rhs: &AffinePoint) -> Self {
                Self(crate::nist::arith::point::add_affine::<$arith, $n>(
                    &self.0,
                    &rhs.point,
                    rhs.infinity,
                ))
            }

            /// `self - rhs` for an affine `rhs`.
            fn sub_affine(&self, rhs: &AffinePoint) -> Self {
                self.add_affine(&rhs.neg())
            }
        }

        impl core::fmt::Debug for ProjectivePoint {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("ProjectivePoint(..)")
            }
        }

        /// Compares in constant time; only the verdict is revealed.
        impl PartialEq for ProjectivePoint {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).declassify()
            }
        }

        impl Eq for ProjectivePoint {}

        impl Default for ProjectivePoint {
            fn default() -> Self {
                Self::IDENTITY
            }
        }

        impl From<&AffinePoint> for ProjectivePoint {
            fn from(a: &AffinePoint) -> Self {
                Self(crate::nist::arith::point::from_affine::<$arith, $n>(
                    &a.point, a.infinity,
                ))
            }
        }

        impl From<AffinePoint> for ProjectivePoint {
            fn from(a: AffinePoint) -> Self {
                Self::from(&a)
            }
        }

        impl From<&PublicKey> for ProjectivePoint {
            fn from(key: &PublicKey) -> Self {
                key.to_projective()
            }
        }

        impl From<PublicKey> for ProjectivePoint {
            fn from(key: PublicKey) -> Self {
                key.to_projective()
            }
        }

        /// Fails for the identity.
        impl TryFrom<ProjectivePoint> for PublicKey {
            type Error = crate::Error;

            fn try_from(point: ProjectivePoint) -> Result<Self, crate::Error> {
                PublicKey::from_affine(&point.to_affine())
            }
        }

        /// Fails for the identity.
        impl TryFrom<&ProjectivePoint> for PublicKey {
            type Error = crate::Error;

            fn try_from(point: &ProjectivePoint) -> Result<Self, crate::Error> {
                PublicKey::from_affine(&point.to_affine())
            }
        }

        /// Overwrites the coordinates with zero and leaves the identity.
        impl crate::zeroize::Zeroize for ProjectivePoint {
            fn zeroize(&mut self) {
                crate::nist::arith::point::wipe::<$arith, $n>(&mut self.0);
            }
        }

        crate::nist::arith::binop!(
            ProjectivePoint,
            ProjectivePoint,
            ProjectivePoint,
            Add,
            add,
            AddAssign,
            add_assign,
            add
        );
        crate::nist::arith::binop!(
            ProjectivePoint,
            ProjectivePoint,
            ProjectivePoint,
            Sub,
            sub,
            SubAssign,
            sub_assign,
            sub
        );
        crate::nist::arith::binop!(
            ProjectivePoint,
            AffinePoint,
            ProjectivePoint,
            Add,
            add,
            AddAssign,
            add_assign,
            add_affine
        );
        crate::nist::arith::binop!(
            ProjectivePoint,
            AffinePoint,
            ProjectivePoint,
            Sub,
            sub,
            SubAssign,
            sub_assign,
            sub_affine
        );
        crate::nist::arith::binop!(
            ProjectivePoint,
            Scalar,
            ProjectivePoint,
            Mul,
            mul,
            MulAssign,
            mul_assign,
            mul
        );
        crate::nist::arith::negop!(ProjectivePoint);
    };
}

pub(crate) use projective_point;
