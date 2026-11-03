//! NIST prime-order curves P-256, P-384 and P-521: ECDH and ECDSA (FIPS 186-5, SEC 1).
//!
//! Each curve has its own module ([`p256`], [`p384`], [`p521`]) with the same
//! API: [`p256::SecretKey`] (generation, raw / RFC 5915 / PKCS#8 loading,
//! ECDH), [`p256::PublicKey`] (SEC 1 and `SubjectPublicKeyInfo`),
//! [`p256::SigningKey`] / [`p256::Signature`] and the [`p256::verify`] family.
//!
//! # Implementation
//!
//! * Field and scalar arithmetic: 64-bit limbs in Montgomery form, word-by-word
//!   CIOS multiplication with masked final subtraction (`mont`). P-256 has a
//!   specialised field multiplication that exploits the shape of `p`
//!   (`p256_field`).
//! * Group law: complete projective formulas (Renes–Costello–Batina 2016,
//!   `a = -3`), so no secret-dependent special cases (`curve`).
//! * Secret scalars: fixed-window Booth recoding with masked table scans;
//!   fixed-base multiplication uses committed, test-validated comb tables
//!   (`scalar_mul`, `table`; width 6 without doublings for P-256). Between
//!   complete additions, runs of doublings use branch-free Jacobian doubling,
//!   which has no exceptional case on prime-order curves (`jacobian`).
//! * Inversions: P-256 uses constant-time Bernstein–Yang safegcd for the field
//!   and the group order (`safegcd`); P-384 and P-521 use Fermat
//!   exponentiations with a fixed schedule.
//! * Verification is variable time (public inputs only): interleaved wNAF in
//!   Jacobian coordinates with explicit exceptional cases, and `x(R) mod n = r`
//!   checked as `X = r Z^2` without an inversion.
//! * x86-64 with BMI2 + ADX: `mulx`/`adcx`/`adox` multiplication and squaring
//!   with the P-256 reduction, and branch-free addition and subtraction in
//!   assembly (`p256_x86`). aarch64 and riscv64 use the portable backend.
//!
//! Nonces follow RFC 6979, hedged with fresh randomness by default.

mod api;
mod curve;
mod ecdsa;
mod jacobian;
mod keys;
mod mont;
mod p256_field;
mod params;
mod safegcd;
mod scalar_mul;
mod table;
mod tables;

#[cfg(target_arch = "x86_64")]
mod p256_x86;

pub mod p256;
pub mod p384;

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

/// Whether P-256 operations use the accelerated field arithmetic now.
pub(crate) fn p256_accelerated() -> bool {
    crate::accel::select::<P256Backend>() == P256Backend::BmiAdx
}

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
}
pub mod p521;
