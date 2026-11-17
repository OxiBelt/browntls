//! Scalars: integers modulo the group order `n` in Montgomery form, with the
//! generic Montgomery arithmetic of `mont` on every backend.
//!
//! Every function wipes the copies it makes out of Montgomery form; the
//! `Scalar` type wipes its own limbs on drop.

use crate::Error;
use crate::ct::Choice;
use crate::nist::curve::Curve;
use crate::nist::keys;
use crate::nist::mont;
use crate::rand::SecureRandom;
use crate::zeroize::zeroize_u64;

use super::{Arith, choice, load_canonical, public};

/// `v` (below `R`) times `R` modulo `n`: a Montgomery product with an
/// operand below `n` is fully reduced whatever the other operand below `R`.
#[inline]
fn to_mont<C: Curve<N>, const N: usize>(v: &[u64; N]) -> [u64; N] {
    mont::to_mont(v, &C::ORDER, C::ORDER_INV, &C::ORDER_R2)
}

/// The canonical value of `a`, for the caller to wipe.
#[inline]
pub(crate) fn canonical<A: Arith<N>, const N: usize>(a: &[u64; N]) -> [u64; N] {
    mont::from_mont(
        a,
        &<A::Soft as Curve<N>>::ORDER,
        <A::Soft as Curve<N>>::ORDER_INV,
    )
}

/// Loads exactly `FIELD_LEN` big-endian bytes below `n` (zero included).
pub(crate) fn from_bytes<A: Arith<N>, const N: usize>(bytes: &[u8]) -> Result<[u64; N], Error> {
    let mut c = load_canonical::<A::Soft, N>(bytes, &<A::Soft as Curve<N>>::ORDER)?;
    let m = to_mont::<A::Soft, N>(&c);
    zeroize_u64(&mut c);
    Ok(m)
}

/// Reduces a big-endian integer of at most `2 * FIELD_LEN` bytes modulo `n`,
/// in time that depends only on the length.
///
/// With `v = hi R + lo` (`hi, lo < R`), `v R = hi R^2 + lo R (mod n)`: two
/// Montgomery products, by `R^3` and by `R^2`, each fully reduced since
/// one operand is below `n`.
pub(crate) fn from_bytes_reduced<A: Arith<N>, const N: usize>(
    bytes: &[u8],
) -> Result<[u64; N], Error> {
    from_bytes_reduced_with::<A::Soft, N>(bytes)
}

fn from_bytes_reduced_with<C: Curve<N>, const N: usize>(bytes: &[u8]) -> Result<[u64; N], Error> {
    if bytes.len() > 2 * C::FIELD_LEN {
        return Err(Error::InvalidLength);
    }
    let (hi, lo) = bytes.split_at(bytes.len().saturating_sub(8 * N));
    // 2 FIELD_LEN - 8 N <= 8 N for every curve, so both halves fit N limbs.
    let mut lo = mont::from_be_bytes::<N>(lo).ok_or(Error::InvalidLength)?;
    let mut hi = match mont::from_be_bytes::<N>(hi) {
        Some(hi) => hi,
        None => {
            zeroize_u64(&mut lo);
            return Err(Error::InvalidLength);
        }
    };
    let r3 = const { mont::mont_mul_const(&C::ORDER_R2, &C::ORDER_R2, &C::ORDER, C::ORDER_INV) };
    let mut high = mont::mont_mul(&hi, &r3, &C::ORDER, C::ORDER_INV);
    let mut low = to_mont::<C, N>(&lo);
    let out = mont::add_mod(&high, &low, &C::ORDER);
    zeroize_u64(&mut hi);
    zeroize_u64(&mut lo);
    zeroize_u64(&mut high);
    zeroize_u64(&mut low);
    Ok(out)
}

/// A small integer as a scalar.
pub(crate) fn from_u64<A: Arith<N>, const N: usize>(v: u64) -> [u64; N] {
    let mut c = [0u64; N];
    c[0] = v;
    // Every group order here is far above 2^64.
    to_mont::<A::Soft, N>(&c)
}

/// A uniformly random scalar in `[1, n - 1]` (FIPS 186-5 A.2.2 rejection
/// sampling, as for private keys).
pub(crate) fn generate<A: Arith<N>, const N: usize>(
    rng: &dyn SecureRandom,
) -> Result<[u64; N], Error> {
    let d = keys::generate::<A::Soft, N>(rng)?;
    Ok(to_mont::<A::Soft, N>(&d.0))
}

/// Writes the canonical value big-endian into `out` (`FIELD_LEN` bytes).
pub(crate) fn to_bytes<A: Arith<N>, const N: usize>(a: &[u64; N], out: &mut [u8]) {
    let mut c = canonical::<A, N>(a);
    mont::to_be_bytes(&c, out);
    zeroize_u64(&mut c);
}

/// `a + b mod n`.
#[inline]
pub(crate) fn add<A: Arith<N>, const N: usize>(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    mont::add_mod(a, b, &<A::Soft as Curve<N>>::ORDER)
}

/// `a - b mod n`.
#[inline]
pub(crate) fn sub<A: Arith<N>, const N: usize>(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    mont::sub_mod(a, b, &<A::Soft as Curve<N>>::ORDER)
}

/// `-a mod n` (zero stays zero).
#[inline]
pub(crate) fn neg<A: Arith<N>, const N: usize>(a: &[u64; N]) -> [u64; N] {
    sub::<A, N>(&[0; N], a)
}

/// `a b mod n`.
#[inline]
pub(crate) fn mul<A: Arith<N>, const N: usize>(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    mont::mont_mul(
        a,
        b,
        &<A::Soft as Curve<N>>::ORDER,
        <A::Soft as Curve<N>>::ORDER_INV,
    )
}

/// `a^-1 mod n` in constant time; `None` (a public outcome) for zero.
pub(crate) fn invert<A: Arith<N>, const N: usize>(a: &[u64; N]) -> Option<[u64; N]> {
    let mut inv = <A::Soft as Curve<N>>::scalar_invert(a);
    if public(mont::is_zero(a)) {
        zeroize_u64(&mut inv);
        None
    } else {
        Some(inv)
    }
}

/// Whether `a` is zero.
#[inline]
pub(crate) fn is_zero<const N: usize>(a: &[u64; N]) -> Choice {
    choice(mont::is_zero(a))
}

/// Whether `a == b` (both reduced).
#[inline]
pub(crate) fn ct_eq<const N: usize>(a: &[u64; N], b: &[u64; N]) -> Choice {
    choice(mont::eq(a, b))
}

/// Declares `Scalar` in a curve module.
macro_rules! scalar_type {
    ($doc_name:literal, $arith:ty, $soft:ty, $n:literal, $field_len:literal) => {
        #[doc = concat!("An integer modulo the order `n` of the ", $doc_name, " group.")]
        ///
        /// Always fully reduced. Arithmetic is constant time (inversion
        /// included) and uses the portable Montgomery arithmetic on every
        /// backend, as ECDSA does. A scalar may be secret: the type is not
        /// `Copy`, its value is zeroised on drop, [`Scalar::to_bytes`]
        /// returns a [`Zeroizing`](crate::zeroize::Zeroizing) buffer, and
        /// `Debug` does not print it. Copies the compiler makes in registers
        /// or on the stack during arithmetic are not wiped.
        #[derive(Clone)]
        pub struct Scalar([u64; $n]);

        impl Drop for Scalar {
            fn drop(&mut self) {
                crate::zeroize::zeroize_u64(&mut self.0);
            }
        }

        impl Scalar {
            /// Zero.
            pub const ZERO: Self = Self([0; $n]);
            /// One.
            pub const ONE: Self = Self(<$soft as crate::nist::curve::Curve<$n>>::ORDER_ONE);

            /// Parses the canonical big-endian encoding: exactly
            /// [`FIELD_LEN`] bytes, a value below `n` (zero included). Values
            /// at or above `n` are rejected, never reduced;
            /// [`Scalar::from_bytes_reduced`] reduces.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidLength`](crate::Error::InvalidLength) for
            /// another length and
            /// [`Error::InvalidEncoding`](crate::Error::InvalidEncoding) for a
            /// value at or above `n` (the comparison is constant time; its
            /// outcome is public).
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
                crate::nist::arith::scalar::from_bytes::<$arith, $n>(bytes).map(Self)
            }

            /// Reduces a big-endian integer of up to `2 * FIELD_LEN` bytes
            /// modulo `n` (a hash output, for example), in constant time in
            /// the value.
            /// Reducing twice the scalar length of uniform bytes gives a
            /// negligibly biased scalar; shorter inputs may be biased.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidLength`](crate::Error::InvalidLength) for a
            /// longer input.
            pub fn from_bytes_reduced(bytes: &[u8]) -> Result<Self, crate::Error> {
                crate::nist::arith::scalar::from_bytes_reduced::<$arith, $n>(bytes).map(Self)
            }

            /// A uniformly random scalar in `[1, n - 1]`, by the rejection
            /// sampling used for private keys (FIPS 186-5, A.2.2).
            ///
            /// # Errors
            ///
            /// [`Error::RandomFailure`](crate::Error::RandomFailure) if `rng`
            /// fails.
            pub fn generate(rng: &dyn crate::rand::SecureRandom) -> Result<Self, crate::Error> {
                crate::nist::arith::scalar::generate::<$arith, $n>(rng).map(Self)
            }

            /// The canonical big-endian encoding, in a buffer zeroised on
            /// drop.
            #[must_use]
            pub fn to_bytes(&self) -> crate::zeroize::Zeroizing<[u8; $field_len]> {
                let mut out = crate::zeroize::Zeroizing([0u8; $field_len]);
                crate::nist::arith::scalar::to_bytes::<$arith, $n>(&self.0, &mut out[..]);
                out
            }

            /// `self + rhs`.
            #[must_use]
            pub fn add(&self, rhs: &Self) -> Self {
                Self(crate::nist::arith::scalar::add::<$arith, $n>(
                    &self.0, &rhs.0,
                ))
            }

            /// `self - rhs`.
            #[must_use]
            pub fn sub(&self, rhs: &Self) -> Self {
                Self(crate::nist::arith::scalar::sub::<$arith, $n>(
                    &self.0, &rhs.0,
                ))
            }

            /// `-self` (zero stays zero).
            #[must_use]
            pub fn neg(&self) -> Self {
                Self(crate::nist::arith::scalar::neg::<$arith, $n>(&self.0))
            }

            /// `2 * self`.
            #[must_use]
            pub fn double(&self) -> Self {
                self.add(self)
            }

            /// `self * rhs`.
            #[must_use]
            pub fn mul(&self, rhs: &Self) -> Self {
                Self(crate::nist::arith::scalar::mul::<$arith, $n>(
                    &self.0, &rhs.0,
                ))
            }

            /// `self^2`.
            #[must_use]
            pub fn square(&self) -> Self {
                self.mul(self)
            }

            /// The multiplicative inverse, computed in constant time; `None`
            /// for zero. Whether the value was zero is public through the
            /// result.
            #[must_use]
            pub fn invert(&self) -> Option<Self> {
                crate::nist::arith::scalar::invert::<$arith, $n>(&self.0).map(Self)
            }

            /// Whether the value is zero (constant time).
            #[must_use]
            pub fn is_zero(&self) -> crate::ct::Choice {
                crate::nist::arith::scalar::is_zero(&self.0)
            }

            /// Whether `self == other` (constant time).
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> crate::ct::Choice {
                crate::nist::arith::scalar::ct_eq(&self.0, &other.0)
            }
        }

        impl core::fmt::Debug for Scalar {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("Scalar(..)")
            }
        }

        /// Compares in constant time; only the verdict is revealed.
        impl PartialEq for Scalar {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).declassify()
            }
        }

        impl Eq for Scalar {}

        impl Default for Scalar {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl From<u64> for Scalar {
            fn from(v: u64) -> Self {
                Self(crate::nist::arith::scalar::from_u64::<$arith, $n>(v))
            }
        }

        /// Overwrites the value with zero (as dropping does).
        impl crate::zeroize::Zeroize for Scalar {
            fn zeroize(&mut self) {
                crate::zeroize::zeroize_u64(&mut self.0);
            }
        }

        crate::nist::arith::binop!(Scalar, Scalar, Scalar, Add, add, AddAssign, add_assign, add);
        crate::nist::arith::binop!(Scalar, Scalar, Scalar, Sub, sub, SubAssign, sub_assign, sub);
        crate::nist::arith::binop!(Scalar, Scalar, Scalar, Mul, mul, MulAssign, mul_assign, mul);
        crate::nist::arith::negop!(Scalar);
    };
}

pub(crate) use scalar_type;
