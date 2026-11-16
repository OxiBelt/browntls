//! NIST prime-order curves P-256, P-384 and P-521: ECDH and ECDSA (FIPS 186-5, SEC 1).
//!
//! Each curve has its own module ([`p256`], [`p384`], [`p521`]) with the same
//! API: [`p256::SecretKey`] (generation, raw / RFC 5915 / PKCS#8 loading,
//! ECDH), [`p256::PublicKey`] (SEC 1 and `SubjectPublicKeyInfo`),
//! [`p256::SigningKey`] / [`p256::Signature`] and the [`p256::verify`] family.
//!
//! # Implementation
//!
//! * Field arithmetic: 64-bit limbs in Montgomery form. Each curve forms the
//!   full double-width product and then reduces it with a method that
//!   exploits the shape of its prime: four (P-256, `p256_field`) or six
//!   (P-384, `p384_field`) Montgomery rounds whose quotient digit needs no
//!   multiplication by `-p^-1`, and for the Mersenne prime of P-521 a fold
//!   and a 55-bit rotation (`p521_field`). Scalar arithmetic modulo the group
//!   order is generic word-by-word CIOS Montgomery multiplication with a
//!   masked final subtraction (`mont`).
//! * Group law: complete projective formulas (Renes–Costello–Batina 2016,
//!   `a = -3`), so no secret-dependent special cases (`curve`).
//! * Secret scalars: fixed-window Booth recoding with masked table scans;
//!   fixed-base multiplication uses committed, test-validated comb tables
//!   (`scalar_mul`, `table`; width 6 without doublings for P-256). Between
//!   complete additions, runs of doublings use branch-free Jacobian doubling,
//!   which has no exceptional case on prime-order curves (`jacobian`).
//! * Inversions: constant-time Bernstein–Yang safegcd for the field and the
//!   group order, with a fixed number of division steps per curve (`safegcd`
//!   for P-256; `wide::invert`, on the generic `rsa::bigint::inv`, for P-384
//!   and P-521).
//! * Verification is variable time (public inputs only): interleaved wNAF in
//!   Jacobian coordinates with explicit exceptional cases, and `x(R) mod n = r`
//!   checked as `X = r Z^2` without an inversion.
//! * x86-64 with BMI2 + ADX: `mulx`/`adcx`/`adox` multiplication and squaring,
//!   and the reduction, addition and subtraction in branch-free assembly
//!   (`p256_x86`; `wide_x86` with `p384_x86` and `p521_x86`). aarch64 and
//!   riscv64 use the portable backend, which has the same specialised
//!   reductions.
//!
//! Nonces follow RFC 6979, hedged with fresh randomness by default.
//!
//! Each curve's operations take part in load-aware routing
//! ([`crate::accel::load`]) with one stream per kind of operation, as their
//! costs differ: public key derivation, ECDH, ECDSA signing and ECDSA
//! verification. While routing is enabled and the selected backend runs
//! slower than usual, a share of an operation's calls uses the other
//! backend; one call runs on one backend throughout. Only completed
//! operations are timed: of the verifications those that accepted the
//! signature, and of the signatures those with the curve's TLS hash (the
//! others are routed without being timed).

mod api;
mod curve;
mod ecdsa;
mod jacobian;
mod keys;
mod mont;
mod p256_field;
mod p384_field;
mod p521_field;
mod params;
mod safegcd;
mod scalar_mul;
mod table;
mod tables;
mod wide;

#[cfg(target_arch = "x86_64")]
mod p256_x86;
#[cfg(target_arch = "x86_64")]
mod p384_x86;
#[cfg(target_arch = "x86_64")]
mod p521_x86;
#[cfg(target_arch = "x86_64")]
mod wide_x86;

pub mod p256;
pub mod p384;

use crate::accel::load::Stream;

/// Whether the CPU offers the accelerated P-256 field arithmetic.
pub(crate) fn p256_hardware_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        p256_x86::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// The streams of one curve for load-aware routing ([`crate::accel::load`]):
/// one per kind of operation, indexed by the constants below. The kinds
/// differ in cost, and a stream holds calls of one cost.
const fn curve_streams() -> [Stream; 4] {
    [
        Stream::op("public key"),
        Stream::op("ECDH"),
        Stream::op("ECDSA sign"),
        Stream::op("ECDSA verify"),
    ]
}

/// The stream of fixed-base multiplications that derive a public key.
pub(crate) const LOAD_PUBLIC_KEY: usize = 0;
/// The stream of ECDH variable-base multiplications.
pub(crate) const LOAD_ECDH: usize = 1;
/// The stream of ECDSA signatures (timed with the curve's TLS hash).
pub(crate) const LOAD_SIGN: usize = 2;
/// The stream of ECDSA verifications that accepted the signature.
pub(crate) const LOAD_VERIFY: usize = 3;

/// Load-aware routing state of P-256.
pub(crate) static P256_LOAD: [Stream; 4] = curve_streams();
/// Load-aware routing state of P-384.
pub(crate) static P384_LOAD: [Stream; 4] = curve_streams();
/// Load-aware routing state of P-521.
pub(crate) static P521_LOAD: [Stream; 4] = curve_streams();

/// P-256 field arithmetic backends (for the acceleration policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum P256Backend {
    /// BMI2 `mulx` + ADX `adcx`/`adox` (x86-64).
    BmiAdx,
    /// Portable 64-bit Montgomery arithmetic.
    Portable,
}

impl crate::accel::Backends for P256Backend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::P256;
    const PREFERENCE: &'static [Self] = &[Self::BmiAdx, Self::Portable];

    fn available(self) -> bool {
        match self {
            Self::BmiAdx => p256_hardware_available(),
            Self::Portable => true,
        }
    }

    fn uses(self) -> crate::accel::Uses {
        match self {
            Self::BmiAdx => crate::accel::Uses::DEDICATED,
            Self::Portable => crate::accel::Uses::PORTABLE,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::BmiAdx => "BMI2/ADX",
            Self::Portable => "portable",
        }
    }

    fn streams() -> &'static [Stream] {
        &P256_LOAD
    }
}
pub mod p521;

/// Whether the CPU offers the BMI2/ADX product kernels of P-384 and P-521.
pub(crate) fn wide_hardware_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        wide_x86::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Declares the backend set of a curve whose only accelerated backend is the
/// BMI2/ADX product kernel.
macro_rules! wide_backend {
    ($(#[$m:meta])* $name:ident, $alg:ident, $load:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum $name {
            /// BMI2 `mulx` + ADX `adcx`/`adox` products (x86-64).
            BmiAdx,
            /// Portable 64-bit arithmetic.
            Portable,
        }

        impl crate::accel::Backends for $name {
            const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::$alg;
            const PREFERENCE: &'static [Self] = &[Self::BmiAdx, Self::Portable];

            fn available(self) -> bool {
                match self {
                    Self::BmiAdx => wide_hardware_available(),
                    Self::Portable => true,
                }
            }

            fn uses(self) -> crate::accel::Uses {
                match self {
                    Self::BmiAdx => crate::accel::Uses::DEDICATED,
                    Self::Portable => crate::accel::Uses::PORTABLE,
                }
            }

            fn name(self) -> &'static str {
                match self {
                    Self::BmiAdx => "BMI2/ADX",
                    Self::Portable => "portable",
                }
            }

            fn streams() -> &'static [Stream] {
                &$load
            }
        }
    };
}

wide_backend! {
    /// P-384 field arithmetic backends (for the acceleration policy).
    P384Backend, P384, P384_LOAD
}

wide_backend! {
    /// P-521 field arithmetic backends (for the acceleration policy).
    P521Backend, P521, P521_LOAD
}
