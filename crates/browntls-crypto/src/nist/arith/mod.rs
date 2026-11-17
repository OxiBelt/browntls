//! Public field, scalar and point arithmetic of P-256, P-384 and P-521.
//!
//! [`arith_module!`] declares, in each curve module, `FieldElement` (the
//! integers modulo the field prime `p`), `Scalar` (the integers modulo the
//! group order `n`), `AffinePoint` with its SEC 1 encoding `Sec1Point`, and
//! `ProjectivePoint`, with the same API on every curve. The names follow the
//! RustCrypto `primeorder` / `elliptic-curve` 0.14 vocabulary where it fits;
//! none of their traits is implemented and nothing depends on them. The
//! generic functions of [`field`], [`scalar`] and [`point`] do the work; the
//! macros only wrap them in per-curve types.
//!
//! # Representation
//!
//! Field elements, scalars and point coordinates hold their values in
//! Montgomery form (`x R mod m`, with `R = 2^(64 N)`), the form of the curve
//! code underneath, so no conversion happens between operations. The
//! portable and the BMI2/ADX field backends share that form, so a value
//! computed on one is valid on the other. Every value is fully reduced
//! (below its modulus): the constructors reject or reduce anything else, and
//! every operation keeps the invariant.
//!
//! # Backends
//!
//! Each field and point operation runs on the backend the curve's
//! acceleration policy selects at the time of the call ([`crate::accel`]):
//! the BMI2/ADX kernels where the CPU has them, the portable code otherwise
//! or under `browntls_force_soft`. Scalar arithmetic is the generic
//! word-by-word Montgomery code (`mont`) on every backend, as it is for
//! ECDSA. These operations do **not** take part in load-aware routing
//! ([`crate::accel::load`]): only the key, ECDH and ECDSA entry points of
//! the curve modules are routed and timed.
//!
//! # Constant time
//!
//! Arithmetic (addition, subtraction, negation, multiplication, squaring,
//! inversion, square roots, comparisons, the group law, scalar
//! multiplication, normalisation) is constant time in the values: no branch
//! or memory access depends on them. Comparisons return a
//! [`crate::ct::Choice`]. Where a result is an `Option` or a `Result`, its
//! variant is public: decoding reveals whether the encoding was canonical
//! and the point on the curve, [`field::invert`] and [`scalar::invert`]
//! whether the value was zero, and [`field::sqrt`] whether a square root
//! exists. The work done before that outcome is still constant time. Two
//! exceptions say so in their documentation: SEC 1 decoding and encoding
//! handle public data (an encoding's length shows whether the point is the
//! identity), and `ProjectivePoint::mul_by_generator_and_mul_add_vartime`
//! is the variable-time double multiplication of signature verification.
//!
//! # Secrets
//!
//! A `Scalar` may hold a secret (a private key, a nonce): it is not `Copy`,
//! its limbs are zeroised on drop, `to_bytes` returns them in a
//! [`crate::zeroize::Zeroizing`] buffer, and the copies that the conversions
//! of this module make out of Montgomery form are wiped as well. Field
//! elements are `Copy` and not wiped implicitly; they implement
//! [`crate::zeroize::Zeroize`], so a caller that keeps a secret one can hold
//! it in a [`crate::zeroize::Zeroizing`]. As for the existing key types,
//! copies that the compiler makes in registers or on the stack during
//! arithmetic are not wiped. Points are `Copy` like field elements and
//! implement `Zeroize` (leaving the identity); `ProjectivePoint::mul` wipes
//! the canonical copy of its scalar but not its result or the multiples of
//! the point it tabulates, as for ECDH. `Sec1Point`, which may encode a
//! secret point, is `Copy` and implements `Zeroize` (leaving the identity's
//! encoding) as well. `Debug` prints the value of none of these types.

pub(crate) mod affine;
pub(crate) mod field;
pub(crate) mod point;
pub(crate) mod projective;
pub(crate) mod scalar;

use crate::Error;
use crate::ct::Choice;
use crate::nist::curve::Curve;
use crate::nist::mont;
use crate::zeroize::zeroize_u64;

/// The two field backends of a curve for the public arithmetic types.
pub(crate) trait Arith<const N: usize> {
    /// The portable backend; also supplies the constants.
    type Soft: Curve<N>;
    /// The accelerated backend (the portable one on targets without it).
    type Fast: Curve<N>;
    /// Whether the curve's acceleration policy currently selects [`Self::Fast`].
    fn fast() -> bool;
}

/// Declassifies a mask (all ones or zero) whose value is a public outcome.
#[inline]
pub(crate) fn public(mask: u64) -> bool {
    Choice::from_bit(mask & 1).declassify()
}

/// A mask (all ones or zero) as a [`Choice`].
#[inline]
pub(crate) fn choice(mask: u64) -> Choice {
    Choice::from_bit(mask & 1)
}

/// Loads exactly `FIELD_LEN` big-endian bytes as an integer below `modulus`.
///
/// # Errors
///
/// [`Error::InvalidLength`] for any other length and
/// [`Error::InvalidEncoding`] for a value at least `modulus`; the comparison
/// is constant time, its outcome public.
pub(crate) fn load_canonical<C: Curve<N>, const N: usize>(
    bytes: &[u8],
    modulus: &[u64; N],
) -> Result<[u64; N], Error> {
    if bytes.len() != C::FIELD_LEN {
        return Err(Error::InvalidLength);
    }
    let mut v = mont::from_be_bytes::<N>(bytes).ok_or(Error::InvalidLength)?;
    if public(mont::lt(&v, modulus)) {
        Ok(v)
    } else {
        zeroize_u64(&mut v);
        Err(Error::InvalidEncoding)
    }
}

/// Runs the generic function `$f::<C, N>(args)` with the backend `C` of
/// `$a: Arith<N>` that the curve's policy selects for this call. The caller
/// names its limb count `N`.
macro_rules! on_backend {
    ($a:ident, $f:ident($($arg:expr),*)) => {
        if <$a as $crate::nist::arith::Arith<N>>::fast() {
            $f::<<$a as $crate::nist::arith::Arith<N>>::Fast, N>($($arg),*)
        } else {
            $f::<<$a as $crate::nist::arith::Arith<N>>::Soft, N>($($arg),*)
        }
    };
}

pub(crate) use on_backend;

/// Implements a binary operator and its assigning form, for owned and
/// borrowed operands, through the inherent method `$inherent(&self, &Rhs)`.
macro_rules! binop {
    ($t:ty, $rhs:ty, $out:ty, $tr:ident, $f:ident, $tr_assign:ident, $f_assign:ident, $inherent:ident) => {
        impl core::ops::$tr<&$rhs> for &$t {
            type Output = $out;

            #[inline]
            fn $f(self, rhs: &$rhs) -> $out {
                <$t>::$inherent(self, rhs)
            }
        }

        impl core::ops::$tr<&$rhs> for $t {
            type Output = $out;

            #[inline]
            fn $f(self, rhs: &$rhs) -> $out {
                <$t>::$inherent(&self, rhs)
            }
        }

        impl core::ops::$tr<$rhs> for &$t {
            type Output = $out;

            #[inline]
            fn $f(self, rhs: $rhs) -> $out {
                <$t>::$inherent(self, &rhs)
            }
        }

        impl core::ops::$tr<$rhs> for $t {
            type Output = $out;

            #[inline]
            fn $f(self, rhs: $rhs) -> $out {
                <$t>::$inherent(&self, &rhs)
            }
        }

        impl core::ops::$tr_assign<&$rhs> for $t {
            #[inline]
            fn $f_assign(&mut self, rhs: &$rhs) {
                *self = <$t>::$inherent(self, rhs);
            }
        }

        impl core::ops::$tr_assign<$rhs> for $t {
            #[inline]
            fn $f_assign(&mut self, rhs: $rhs) {
                *self = <$t>::$inherent(self, &rhs);
            }
        }
    };
}

pub(crate) use binop;

/// Implements `Neg` for owned and borrowed values through the inherent
/// method `neg(&self)`.
macro_rules! negop {
    ($t:ty) => {
        impl core::ops::Neg for &$t {
            type Output = $t;

            #[inline]
            fn neg(self) -> $t {
                <$t>::neg(self)
            }
        }

        impl core::ops::Neg for $t {
            type Output = $t;

            #[inline]
            fn neg(self) -> $t {
                <$t>::neg(&self)
            }
        }
    };
}

pub(crate) use negop;

/// Declares the arithmetic types of one curve module (see the module
/// documentation of [`crate::nist::arith`]).
macro_rules! arith_module {
    (
        name = $doc_name:literal,
        soft = $soft:ty,
        fast = $fast:ty,
        backend = $backend:ident,
        limbs = $n:literal,
        field_len = $field_len:literal
    ) => {
        #[cfg(test)]
        mod arith_backend_tests {
            use crate::accel::Backends as _;
            use crate::nist::arith::Arith as _;

            /// The arithmetic types use the accelerated backend exactly when
            /// the policy selects it: under the default policy (which no
            /// library test changes), whenever the CPU has it.
            #[test]
            fn fast_follows_the_policy() {
                let available = crate::nist::$backend::BmiAdx.available();
                assert_eq!(super::ArithBackends::fast(), available);
                assert_eq!(
                    crate::accel::select::<crate::nist::$backend>()
                        == crate::nist::$backend::BmiAdx,
                    available
                );
            }
        }

        /// The curve's field backends for the arithmetic types.
        #[derive(Clone, Copy, Debug)]
        struct ArithBackends;

        impl crate::nist::arith::Arith<$n> for ArithBackends {
            type Soft = $soft;
            type Fast = $fast;

            #[inline]
            fn fast() -> bool {
                crate::accel::select::<crate::nist::$backend>() == crate::nist::$backend::BmiAdx
            }
        }

        crate::nist::arith::field::field_element!($doc_name, ArithBackends, $soft, $n, $field_len);
        crate::nist::arith::scalar::scalar_type!($doc_name, ArithBackends, $soft, $n, $field_len);
        crate::nist::arith::affine::affine_point!($doc_name, ArithBackends, $soft, $n, $field_len);
        crate::nist::arith::projective::projective_point!($doc_name, ArithBackends, $soft, $n);
    };
}

pub(crate) use arith_module;
