//! Field elements: integers modulo `p` in Montgomery form, on the backend
//! the curve's acceleration policy selects (see the parent module).

use crate::Error;
use crate::ct::Choice;
use crate::nist::curve::{Curve, Fe, fe_pow_pubexp};
use crate::nist::mont;

use super::{Arith, choice, load_canonical, on_backend, public};

/// Loads exactly `FIELD_LEN` big-endian bytes below `p`.
pub(crate) fn from_bytes<A: Arith<N>, const N: usize>(bytes: &[u8]) -> Result<Fe<N>, Error> {
    let c = load_canonical::<A::Soft, N>(bytes, &<A::Soft as Curve<N>>::P)?;
    Ok(to_mont::<A::Soft, N>(&c))
}

/// `v` (below `p`) in Montgomery form.
#[inline]
fn to_mont<C: Curve<N>, const N: usize>(v: &[u64; N]) -> Fe<N> {
    mont::to_mont(v, &C::P, C::P_INV, &C::R2)
}

/// A small integer as a field element.
pub(crate) fn from_u64<A: Arith<N>, const N: usize>(v: u64) -> Fe<N> {
    let mut c = [0u64; N];
    c[0] = v;
    // Every field prime here is far above 2^64.
    to_mont::<A::Soft, N>(&c)
}

/// Writes the canonical value big-endian into `out` (`FIELD_LEN` bytes).
pub(crate) fn to_bytes<A: Arith<N>, const N: usize>(a: &Fe<N>, out: &mut [u8]) {
    let c = <A::Soft as Curve<N>>::P;
    mont::to_be_bytes(&mont::from_mont(a, &c, <A::Soft as Curve<N>>::P_INV), out);
}

#[inline]
fn add_with<C: Curve<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    C::add(a, b)
}

#[inline]
fn sub_with<C: Curve<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    C::sub(a, b)
}

#[inline]
fn mul_with<C: Curve<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    C::mul(a, b)
}

#[inline]
fn sqr_with<C: Curve<N>, const N: usize>(a: &Fe<N>) -> Fe<N> {
    C::sqr(a)
}

#[inline]
fn invert_with<C: Curve<N>, const N: usize>(a: &Fe<N>) -> Fe<N> {
    C::invert(a)
}

/// `a + b mod p`.
#[inline]
pub(crate) fn add<A: Arith<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    on_backend!(A, add_with(a, b))
}

/// `a - b mod p`.
#[inline]
pub(crate) fn sub<A: Arith<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    on_backend!(A, sub_with(a, b))
}

/// `-a mod p` (zero stays zero).
#[inline]
pub(crate) fn neg<A: Arith<N>, const N: usize>(a: &Fe<N>) -> Fe<N> {
    on_backend!(A, sub_with(&[0; N], a))
}

/// `a b mod p`.
#[inline]
pub(crate) fn mul<A: Arith<N>, const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
    on_backend!(A, mul_with(a, b))
}

/// `a^2 mod p`.
#[inline]
pub(crate) fn square<A: Arith<N>, const N: usize>(a: &Fe<N>) -> Fe<N> {
    on_backend!(A, sqr_with(a))
}

/// `a^-1 mod p` in constant time; `None` (a public outcome) for zero.
pub(crate) fn invert<A: Arith<N>, const N: usize>(a: &Fe<N>) -> Option<Fe<N>> {
    let inv = on_backend!(A, invert_with(a));
    (!public(mont::is_zero(a))).then_some(inv)
}

/// A square root of `a`: `a^((p + 1) / 4)`, which every curve here allows
/// as `p = 3 mod 4`. The exponentiation and the check are constant time;
/// whether a root exists is public. Of the two roots `r` and `p - r` this
/// returns the one that is itself a square.
fn sqrt_with<C: Curve<N>, const N: usize>(a: &Fe<N>) -> Option<Fe<N>> {
    const { assert!(C::P[0] & 3 == 3) };
    let mut one = [0u64; N];
    one[0] = 1;
    // (p + 1) / 4 = (p >> 2) + 1 for p = 3 mod 4; no carry out of the top limb.
    let exp = mont::add(&mont::shr_small(&C::P, 2), &one).0;
    let r = fe_pow_pubexp::<C, N>(a, &exp);
    public(mont::eq(&C::sqr(&r), a)).then_some(r)
}

/// A square root of `a` (see [`sqrt_with`]); `None` when `a` is not a square.
pub(crate) fn sqrt<A: Arith<N>, const N: usize>(a: &Fe<N>) -> Option<Fe<N>> {
    on_backend!(A, sqrt_with(a))
}

/// Whether `a` is zero.
#[inline]
pub(crate) fn is_zero<const N: usize>(a: &Fe<N>) -> Choice {
    choice(mont::is_zero(a))
}

/// Whether the canonical value of `a` is odd.
pub(crate) fn is_odd<A: Arith<N>, const N: usize>(a: &Fe<N>) -> Choice {
    let c = mont::from_mont(a, &<A::Soft as Curve<N>>::P, <A::Soft as Curve<N>>::P_INV);
    Choice::from_bit(c[0] & 1)
}

/// Whether `a == b` (both reduced, so equal values have equal limbs).
#[inline]
pub(crate) fn ct_eq<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Choice {
    choice(mont::eq(a, b))
}

/// Declares `FieldElement` in a curve module.
macro_rules! field_element {
    ($doc_name:literal, $arith:ty, $soft:ty, $n:literal, $field_len:literal) => {
        #[doc = concat!("An element of the ", $doc_name, " base field: an integer modulo the prime `p`.")]
        ///
        /// Always fully reduced. Arithmetic is constant time and runs on the
        /// backend the curve's acceleration policy selects for each call;
        /// it is not part of load-aware routing. The type is `Copy` and is
        /// not wiped on drop; implementing
        /// [`Zeroize`](crate::zeroize::Zeroize), it can be held in a
        /// [`Zeroizing`](crate::zeroize::Zeroizing) when secret. `Debug`
        /// does not print the value.
        #[derive(Clone, Copy)]
        pub struct FieldElement([u64; $n]);

        impl FieldElement {
            /// Zero.
            pub const ZERO: Self = Self([0; $n]);
            /// One.
            pub const ONE: Self = Self(<$soft as crate::nist::curve::Curve<$n>>::ONE);

            /// Parses the canonical big-endian encoding: exactly
            /// [`FIELD_LEN`] bytes, a value below `p`. Values at or above `p`
            /// are rejected, never reduced.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidLength`](crate::Error::InvalidLength) for
            /// another length and
            /// [`Error::InvalidEncoding`](crate::Error::InvalidEncoding) for a
            /// value at or above `p` (the comparison is constant time; its
            /// outcome is public).
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
                crate::nist::arith::field::from_bytes::<$arith, $n>(bytes).map(Self)
            }

            /// The canonical big-endian encoding.
            #[must_use]
            pub fn to_bytes(&self) -> [u8; $field_len] {
                let mut out = [0u8; $field_len];
                crate::nist::arith::field::to_bytes::<$arith, $n>(&self.0, &mut out);
                out
            }

            /// `self + rhs`.
            #[must_use]
            pub fn add(&self, rhs: &Self) -> Self {
                Self(crate::nist::arith::field::add::<$arith, $n>(&self.0, &rhs.0))
            }

            /// `self - rhs`.
            #[must_use]
            pub fn sub(&self, rhs: &Self) -> Self {
                Self(crate::nist::arith::field::sub::<$arith, $n>(&self.0, &rhs.0))
            }

            /// `-self` (zero stays zero).
            #[must_use]
            pub fn neg(&self) -> Self {
                Self(crate::nist::arith::field::neg::<$arith, $n>(&self.0))
            }

            /// `2 * self`.
            #[must_use]
            pub fn double(&self) -> Self {
                self.add(self)
            }

            /// `self * rhs`.
            #[must_use]
            pub fn mul(&self, rhs: &Self) -> Self {
                Self(crate::nist::arith::field::mul::<$arith, $n>(&self.0, &rhs.0))
            }

            /// `self^2`.
            #[must_use]
            pub fn square(&self) -> Self {
                Self(crate::nist::arith::field::square::<$arith, $n>(&self.0))
            }

            /// The multiplicative inverse, computed in constant time
            /// (safegcd); `None` for zero. Whether the value was zero is
            /// public through the result.
            #[must_use]
            pub fn invert(&self) -> Option<Self> {
                crate::nist::arith::field::invert::<$arith, $n>(&self.0).map(Self)
            }

            /// A square root, `self^((p + 1) / 4)` (`p = 3 mod 4`), computed
            /// in constant time; `None` when `self` is not a square, which is
            /// public through the result. Of the two roots `r` and `-r` the
            /// one returned is itself a square; [`FieldElement::is_odd`] and
            /// [`FieldElement::neg`] pick by parity.
            #[must_use]
            pub fn sqrt(&self) -> Option<Self> {
                crate::nist::arith::field::sqrt::<$arith, $n>(&self.0).map(Self)
            }

            /// Whether the value is zero (constant time).
            #[must_use]
            pub fn is_zero(&self) -> crate::ct::Choice {
                crate::nist::arith::field::is_zero(&self.0)
            }

            /// Whether the canonical value is odd (constant time).
            #[must_use]
            pub fn is_odd(&self) -> crate::ct::Choice {
                crate::nist::arith::field::is_odd::<$arith, $n>(&self.0)
            }

            /// Whether `self == other` (constant time).
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> crate::ct::Choice {
                crate::nist::arith::field::ct_eq(&self.0, &other.0)
            }
        }

        impl core::fmt::Debug for FieldElement {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("FieldElement(..)")
            }
        }

        /// Compares in constant time; only the verdict is revealed.
        impl PartialEq for FieldElement {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).declassify()
            }
        }

        impl Eq for FieldElement {}

        impl Default for FieldElement {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl From<u64> for FieldElement {
            fn from(v: u64) -> Self {
                Self(crate::nist::arith::field::from_u64::<$arith, $n>(v))
            }
        }

        /// Overwrites the value with zero.
        impl crate::zeroize::Zeroize for FieldElement {
            fn zeroize(&mut self) {
                crate::zeroize::zeroize_u64(&mut self.0);
            }
        }

        crate::nist::arith::binop!(FieldElement, FieldElement, FieldElement, Add, add, AddAssign, add_assign, add);
        crate::nist::arith::binop!(FieldElement, FieldElement, FieldElement, Sub, sub, SubAssign, sub_assign, sub);
        crate::nist::arith::binop!(FieldElement, FieldElement, FieldElement, Mul, mul, MulAssign, mul_assign, mul);
        crate::nist::arith::negop!(FieldElement);
    };
}

pub(crate) use field_element;
