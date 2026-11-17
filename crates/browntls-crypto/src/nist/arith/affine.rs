//! `AffinePoint`, its SEC 1 encoding `Sec1Point`, and the conversions
//! between the points and `PublicKey`.

/// Declares `AffinePoint` and `Sec1Point` in a curve module, and the point
/// conversions of its `PublicKey`.
macro_rules! affine_point {
    ($doc_name:literal, $arith:ty, $soft:ty, $n:literal, $field_len:literal) => {
        /// Length of a compressed SEC 1 point (`02/03 || X`).
        pub const COMPRESSED_LEN: usize = 1 + $field_len;

        #[doc = concat!("A ", $doc_name, " point in affine coordinates, or the identity.")]
        ///
        /// Always a point of the curve (a group of prime order): every
        /// constructor validates, and the identity is a flag rather than
        /// coordinates. Conversions and comparisons are constant time;
        /// arithmetic goes through [`ProjectivePoint`]. `Copy`, not wiped on
        /// drop (it implements [`Zeroize`](crate::zeroize::Zeroize), which
        /// leaves the identity); `Debug` does not print the coordinates.
        #[derive(Clone, Copy)]
        pub struct AffinePoint {
            point: crate::nist::curve::Affine<$n>,
            infinity: u64,
        }

        impl AffinePoint {
            /// The identity (the point at infinity).
            pub const IDENTITY: Self = Self {
                point: crate::nist::curve::Affine::ZERO,
                infinity: crate::nist::arith::point::INFINITE,
            };
            /// The standard base point `G`.
            pub const GENERATOR: Self = Self {
                point: <$soft as crate::nist::curve::Curve<$n>>::G,
                infinity: crate::nist::arith::point::FINITE,
            };

            /// The point `(x, y)` if it is on the curve
            /// (`y^2 = x^3 - 3x + b`).
            ///
            /// # Errors
            ///
            /// [`Error::InvalidKey`](crate::Error::InvalidKey) when it is not
            /// (the check is constant time; its outcome is public).
            pub fn from_coordinates(
                x: &FieldElement,
                y: &FieldElement,
            ) -> Result<Self, crate::Error> {
                crate::nist::arith::point::from_coordinates::<$arith, $n>(&x.0, &y.0).map(|point| {
                    Self {
                        point,
                        infinity: crate::nist::arith::point::FINITE,
                    }
                })
            }

            /// Parses a SEC 1 point: `00` (the identity), uncompressed
            /// `04 || X || Y` or compressed `02/03 || X`, with coordinates
            /// below `p` and the point on the curve. Hybrid forms are
            /// rejected. Not constant time (it branches on the format, the
            /// validity and, for compressed points, the parity of `y`): for
            /// public encodings.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidEncoding`](crate::Error::InvalidEncoding) for
            /// a malformed encoding and
            /// [`Error::InvalidKey`](crate::Error::InvalidKey) for
            /// coordinates at or above `p` or a point off the curve, as for
            /// [`PublicKey::from_sec1_bytes`].
            pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
                crate::nist::arith::point::decode::<$arith, $n>(bytes)
                    .map(|(point, infinity)| Self { point, infinity })
            }

            /// The SEC 1 encoding: `00` for the identity, otherwise
            /// compressed (`02/03 || X`) or uncompressed (`04 || X || Y`).
            /// Its length reveals whether the point is the identity.
            #[must_use]
            pub fn to_sec1_point(&self, compress: bool) -> Sec1Point {
                let mut out = Sec1Point {
                    bytes: [0; UNCOMPRESSED_LEN],
                    len: 0,
                };
                out.len = crate::nist::arith::point::encode::<$arith, $n>(
                    &self.point,
                    self.infinity,
                    compress,
                    &mut out.bytes,
                );
                out
            }

            /// The x-coordinate (zero for the identity).
            #[must_use]
            pub fn x(&self) -> FieldElement {
                FieldElement(self.point.x)
            }

            /// The y-coordinate (zero for the identity).
            #[must_use]
            pub fn y(&self) -> FieldElement {
                FieldElement(self.point.y)
            }

            /// Whether this is the identity (constant time).
            #[must_use]
            pub fn is_identity(&self) -> crate::ct::Choice {
                crate::nist::arith::choice(self.infinity)
            }

            /// `-self` (constant time).
            #[must_use]
            pub fn neg(&self) -> Self {
                Self {
                    point: crate::nist::arith::point::affine_neg::<$arith, $n>(&self.point),
                    infinity: self.infinity,
                }
            }

            /// Whether `self == other` (constant time).
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> crate::ct::Choice {
                crate::nist::arith::point::affine_eq(
                    &self.point,
                    self.infinity,
                    &other.point,
                    other.infinity,
                )
            }
        }

        impl core::fmt::Debug for AffinePoint {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("AffinePoint(..)")
            }
        }

        /// Compares in constant time; only the verdict is revealed.
        impl PartialEq for AffinePoint {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).declassify()
            }
        }

        impl Eq for AffinePoint {}

        impl Default for AffinePoint {
            fn default() -> Self {
                Self::IDENTITY
            }
        }

        /// Normalises with one constant-time inversion.
        impl From<&ProjectivePoint> for AffinePoint {
            fn from(p: &ProjectivePoint) -> Self {
                p.to_affine()
            }
        }

        /// Normalises with one constant-time inversion.
        impl From<ProjectivePoint> for AffinePoint {
            fn from(p: ProjectivePoint) -> Self {
                p.to_affine()
            }
        }

        impl From<&PublicKey> for AffinePoint {
            fn from(key: &PublicKey) -> Self {
                key.to_affine()
            }
        }

        impl From<PublicKey> for AffinePoint {
            fn from(key: PublicKey) -> Self {
                key.to_affine()
            }
        }

        /// Fails for the identity.
        impl TryFrom<AffinePoint> for PublicKey {
            type Error = crate::Error;

            fn try_from(point: AffinePoint) -> Result<Self, crate::Error> {
                PublicKey::from_affine(&point)
            }
        }

        /// Fails for the identity.
        impl TryFrom<&AffinePoint> for PublicKey {
            type Error = crate::Error;

            fn try_from(point: &AffinePoint) -> Result<Self, crate::Error> {
                PublicKey::from_affine(point)
            }
        }

        /// Overwrites the coordinates with zero and leaves the identity.
        impl crate::zeroize::Zeroize for AffinePoint {
            fn zeroize(&mut self) {
                crate::zeroize::zeroize_u64(&mut self.point.x);
                crate::zeroize::zeroize_u64(&mut self.point.y);
                self.infinity = crate::nist::arith::point::INFINITE;
            }
        }

        crate::nist::arith::negop!(AffinePoint);

        /// A SEC 1 encoded point, as written by [`AffinePoint::to_sec1_point`].
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct Sec1Point {
            bytes: [u8; UNCOMPRESSED_LEN],
            len: usize,
        }

        impl Sec1Point {
            /// The encoding: 1, [`COMPRESSED_LEN`] or [`UNCOMPRESSED_LEN`]
            /// bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes[..self.len]
            }
        }

        impl AsRef<[u8]> for Sec1Point {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl core::fmt::Debug for Sec1Point {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple("Sec1Point").field(&self.as_bytes()).finish()
            }
        }

        impl PublicKey {
            /// The public key of a point other than the identity (every
            /// other point of a prime-order curve is a valid public key).
            ///
            /// # Errors
            ///
            /// [`Error::InvalidKey`](crate::Error::InvalidKey) for the
            /// identity.
            pub fn from_affine(point: &AffinePoint) -> Result<Self, crate::Error> {
                if point.is_identity().declassify() {
                    Err(crate::Error::InvalidKey)
                } else {
                    Ok(Self { point: point.point })
                }
            }

            /// The key's point.
            #[must_use]
            pub fn to_affine(&self) -> AffinePoint {
                AffinePoint {
                    point: self.point,
                    infinity: crate::nist::arith::point::FINITE,
                }
            }

            /// The key's point in projective coordinates.
            #[must_use]
            pub fn to_projective(&self) -> ProjectivePoint {
                ProjectivePoint::from(self.to_affine())
            }
        }
    };
}

pub(crate) use affine_point;
