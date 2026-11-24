//! ML-DSA parameter sets (FIPS 204 §4, Table 1 and Table 2).

use super::dsa;
use crate::Error;
pub use crate::mlkem::ByteArray;

pub(super) mod sealed {
    use crate::Error;

    /// Dispatch from a parameter set to the algorithms instantiated with its
    /// exact vector dimensions `k` and `l` (const generics), so that every
    /// temporary is sized for the parameter set in use.
    pub trait Sealed {
        /// ML-DSA.KeyGen_internal: writes `pk` and the expanded `sk`.
        fn keygen(xi: &[u8; 32], pk: &mut [u8], sk: &mut [u8]);
        /// Validates an expanded `sk` (coefficient ranges, `t0` and `tr`
        /// consistency) and writes the public key it implies to `pk`.
        /// Returns whether the key is valid; only that bit depends on secret
        /// data.
        fn check_expanded(sk: &[u8], pk: &mut [u8]) -> bool;
        /// ML-DSA.Sign_internal from `mu` onwards.
        fn sign_mu(sk: &[u8], mu: &[u8; 64], rnd: &[u8; 32], sig: &mut [u8]) -> Result<(), Error>;
        /// ML-DSA.Verify_internal from `mu` onwards.
        fn verify_mu(pk: &[u8], mu: &[u8; 64], sig: &[u8]) -> bool;
    }
}

/// An ML-DSA parameter set.
///
/// The constants are the FIPS 204 parameters; the byte lengths follow from
/// them. Implemented by [`MlDsa44`], [`MlDsa65`] and [`MlDsa87`] only.
pub trait ParameterSet:
    sealed::Sealed + Copy + core::fmt::Debug + Default + Send + Sync + 'static
{
    /// Human-readable name (`"ML-DSA-65"`).
    const NAME: &'static str;
    /// Rows of the matrix `A` (length of `s2`, `t`, `w`, `h`).
    const K: usize;
    /// Columns of the matrix `A` (length of `s1`, `y`, `z`).
    const L: usize;
    /// Private key range `eta`.
    const ETA: usize;
    /// Number of `+-1` coefficients in the challenge `c`.
    const TAU: usize;
    /// Collision strength `lambda` of the commitment hash `c~` in bits.
    const LAMBDA: usize;
    /// Coefficient range `gamma1` of `y`.
    const GAMMA1: usize;
    /// Low-order rounding range `gamma2`.
    const GAMMA2: usize;
    /// `beta = tau * eta`.
    const BETA: usize = Self::TAU * Self::ETA;
    /// Maximum number of ones in the hint `h`.
    const OMEGA: usize;
    /// Encoded public key length (`32 + 320 k`).
    const VERIFYING_KEY_LEN: usize;
    /// Expanded private key length.
    const SIGNING_KEY_LEN: usize;
    /// Signature length.
    const SIGNATURE_LEN: usize;
    /// DER contents of the RFC 9881 `id-ml-dsa-*` OBJECT IDENTIFIER, which
    /// identifies this parameter set's keys and signatures alike.
    const OID: &'static [u8];

    /// `[u8; VERIFYING_KEY_LEN]`.
    type VerifyingKeyBytes: ByteArray;
    /// `[u8; SIGNING_KEY_LEN]`.
    type SigningKeyBytes: ByteArray;
    /// `[u8; SIGNATURE_LEN]`.
    type Signature: ByteArray;
}

/// The modulus `q = 2^23 - 2^13 + 1`.
pub(super) const Q: usize = 8_380_417;

/// Bits per coefficient of `s1` and `s2` (`bitlen(2 eta)`).
pub(super) const fn eta_bits<P: ParameterSet>() -> usize {
    if P::ETA == 2 { 3 } else { 4 }
}

/// Bits per coefficient of `z` (`1 + bitlen(gamma1 - 1)`).
pub(super) const fn z_bits<P: ParameterSet>() -> usize {
    if P::GAMMA1 == 1 << 17 { 18 } else { 20 }
}

/// Bits per coefficient of `w1` (`bitlen((q - 1) / (2 gamma2) - 1)`).
pub(super) const fn w1_bits<P: ParameterSet>() -> usize {
    if P::GAMMA2 == (Q - 1) / 88 { 6 } else { 4 }
}

/// Length of `c~` in bytes (`lambda / 4`).
pub(super) const fn ctilde_len<P: ParameterSet>() -> usize {
    P::LAMBDA / 4
}

/// The FIPS 204 lengths computed from the parameters: public key, expanded
/// private key, signature.
const fn lengths<P: ParameterSet>() -> (usize, usize, usize) {
    let k = P::K;
    let l = P::L;
    let pk = 32 + 320 * k;
    let sk = 128 + 32 * ((k + l) * eta_bits::<P>() + 13 * k);
    let sig = ctilde_len::<P>() + 32 * l * z_bits::<P>() + P::OMEGA + k;
    (pk, sk, sig)
}

macro_rules! parameter_set {
    ($(#[$m:meta])* $name:ident, $label:literal, k = $k:literal, l = $l:literal,
     eta = $eta:literal, tau = $tau:literal, lambda = $lambda:literal,
     gamma1 = $g1:expr, gamma2 = $g2:expr, omega = $omega:literal,
     pk = $pk:literal, sk = $sk:literal, sig = $sig:literal,
     oid = $oid:expr) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl sealed::Sealed for $name {
            fn keygen(xi: &[u8; 32], pk: &mut [u8], sk: &mut [u8]) {
                dsa::keygen::<Self, $k, $l>(xi, pk, sk);
            }
            fn check_expanded(sk: &[u8], pk: &mut [u8]) -> bool {
                dsa::check_expanded::<Self, $k, $l>(sk, pk)
            }
            fn sign_mu(
                sk: &[u8],
                mu: &[u8; 64],
                rnd: &[u8; 32],
                sig: &mut [u8],
            ) -> Result<(), Error> {
                dsa::sign_mu::<Self, $k, $l>(sk, mu, rnd, sig)
            }
            fn verify_mu(pk: &[u8], mu: &[u8; 64], sig: &[u8]) -> bool {
                dsa::verify_mu::<Self, $k, $l>(pk, mu, sig)
            }
        }

        impl ParameterSet for $name {
            const NAME: &'static str = $label;
            const K: usize = $k;
            const L: usize = $l;
            const ETA: usize = $eta;
            const TAU: usize = $tau;
            const LAMBDA: usize = $lambda;
            const GAMMA1: usize = $g1;
            const GAMMA2: usize = $g2;
            const OMEGA: usize = $omega;
            const VERIFYING_KEY_LEN: usize = $pk;
            const SIGNING_KEY_LEN: usize = $sk;
            const SIGNATURE_LEN: usize = $sig;
            const OID: &'static [u8] = &$oid;
            type VerifyingKeyBytes = [u8; $pk];
            type SigningKeyBytes = [u8; $sk];
            type Signature = [u8; $sig];
        }

        impl $name {
            /// Encoded public key length in bytes.
            pub const VERIFYING_KEY_LEN: usize = $pk;
            /// Expanded private key length in bytes.
            pub const SIGNING_KEY_LEN: usize = $sk;
            /// Signature length in bytes.
            pub const SIGNATURE_LEN: usize = $sig;
        }

        const _: () = {
            let (pk, sk, sig) = lengths::<$name>();
            assert!(pk == $pk && sk == $sk && sig == $sig);
            assert!(<$name as ParameterSet>::ETA == 2 || <$name as ParameterSet>::ETA == 4);
            assert!(
                <$name as ParameterSet>::GAMMA2 == (Q - 1) / 88
                    || <$name as ParameterSet>::GAMMA2 == (Q - 1) / 32
            );
            assert!(
                <$name as ParameterSet>::GAMMA1 == 1 << 17
                    || <$name as ParameterSet>::GAMMA1 == 1 << 19
            );
        };
    };
}

parameter_set!(
    /// ML-DSA-44 (security category 2).
    MlDsa44,
    "ML-DSA-44",
    k = 4,
    l = 4,
    eta = 2,
    tau = 39,
    lambda = 128,
    gamma1 = 1 << 17,
    gamma2 = (Q - 1) / 88,
    omega = 80,
    pk = 1312,
    sk = 2560,
    sig = 2420,
    oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]
);
parameter_set!(
    /// ML-DSA-65 (security category 3).
    MlDsa65,
    "ML-DSA-65",
    k = 6,
    l = 5,
    eta = 4,
    tau = 49,
    lambda = 192,
    gamma1 = 1 << 19,
    gamma2 = (Q - 1) / 32,
    omega = 55,
    pk = 1952,
    sk = 4032,
    sig = 3309,
    oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]
);
parameter_set!(
    /// ML-DSA-87 (security category 5).
    MlDsa87,
    "ML-DSA-87",
    k = 8,
    l = 7,
    eta = 2,
    tau = 60,
    lambda = 256,
    gamma1 = 1 << 19,
    gamma2 = (Q - 1) / 32,
    omega = 75,
    pk = 2592,
    sk = 4896,
    sig = 4627,
    oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13]
);
