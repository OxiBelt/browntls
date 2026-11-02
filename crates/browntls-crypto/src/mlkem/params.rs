//! ML-KEM parameter sets (FIPS 203 §8).

use super::kpke::Params;
use crate::zeroize::Zeroize;

mod sealed {
    pub trait Sealed {}
    impl<const N: usize> Sealed for [u8; N] {}
}

/// A fixed-size byte array (`[u8; N]`) used for keys and ciphertexts.
pub trait ByteArray:
    sealed::Sealed
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Copy
    + core::fmt::Debug
    + PartialEq
    + Eq
    + Send
    + Sync
    + Zeroize
    + 'static
{
    /// Length in bytes.
    const LEN: usize;
    /// An all-zero value.
    fn zeroed() -> Self;
}

impl<const N: usize> ByteArray for [u8; N] {
    const LEN: usize = N;
    fn zeroed() -> Self {
        [0; N]
    }
}

mod sealed_params {
    pub trait Sealed {}
}

/// An ML-KEM parameter set.
pub trait ParameterSet:
    sealed_params::Sealed + Copy + core::fmt::Debug + Default + Send + Sync + 'static
{
    /// Human-readable name (`"ML-KEM-768"`).
    const NAME: &'static str;
    /// Module rank `k`.
    const K: usize;
    /// `eta_1`.
    const ETA1: usize;
    /// `eta_2`.
    const ETA2: usize;
    /// `d_u`.
    const DU: usize;
    /// `d_v`.
    const DV: usize;
    /// Encapsulation key length (`384 k + 32`).
    const ENCAPSULATION_KEY_LEN: usize = 384 * Self::K + 32;
    /// Expanded decapsulation key length (`768 k + 96`).
    const DECAPSULATION_KEY_LEN: usize = 768 * Self::K + 96;
    /// Ciphertext length (`32 (d_u k + d_v)`).
    const CIPHERTEXT_LEN: usize = 32 * (Self::DU * Self::K + Self::DV);
    /// Shared secret length.
    const SHARED_SECRET_LEN: usize = 32;
    /// Seed (`d || z`) length.
    const SEED_LEN: usize = 64;

    /// `[u8; ENCAPSULATION_KEY_LEN]`.
    type EncapsulationKeyBytes: ByteArray;
    /// `[u8; DECAPSULATION_KEY_LEN]`.
    type DecapsulationKeyBytes: ByteArray;
    /// `[u8; CIPHERTEXT_LEN]`.
    type Ciphertext: ByteArray;
}

/// The run-time parameters of `P`.
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn params<P: ParameterSet>() -> Params {
    Params {
        k: P::K,
        eta1: P::ETA1,
        eta2: P::ETA2,
        du: P::DU as u32,
        dv: P::DV as u32,
    }
}

macro_rules! parameter_set {
    ($(#[$m:meta])* $name:ident, $label:literal, k = $k:literal, eta1 = $e1:literal,
     eta2 = $e2:literal, du = $du:literal, dv = $dv:literal, ek = $ek:literal, dk = $dk:literal,
     ct = $ct:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl sealed_params::Sealed for $name {}

        impl ParameterSet for $name {
            const NAME: &'static str = $label;
            const K: usize = $k;
            const ETA1: usize = $e1;
            const ETA2: usize = $e2;
            const DU: usize = $du;
            const DV: usize = $dv;
            type EncapsulationKeyBytes = [u8; $ek];
            type DecapsulationKeyBytes = [u8; $dk];
            type Ciphertext = [u8; $ct];
        }

        impl $name {
            /// Encapsulation key length in bytes.
            pub const ENCAPSULATION_KEY_LEN: usize = $ek;
            /// Expanded decapsulation key length in bytes.
            pub const DECAPSULATION_KEY_LEN: usize = $dk;
            /// Ciphertext length in bytes.
            pub const CIPHERTEXT_LEN: usize = $ct;
            /// Shared secret length in bytes.
            pub const SHARED_SECRET_LEN: usize = 32;
            /// Seed (`d || z`) length in bytes.
            pub const SEED_LEN: usize = 64;
        }

        const _: () = {
            assert!(<$name as ParameterSet>::ENCAPSULATION_KEY_LEN == $ek);
            assert!(<$name as ParameterSet>::DECAPSULATION_KEY_LEN == $dk);
            assert!(<$name as ParameterSet>::CIPHERTEXT_LEN == $ct);
            assert!(params::<$name>().ct_len() == $ct);
        };
    };
}

parameter_set!(
    /// ML-KEM-512 (security category 1).
    MlKem512, "ML-KEM-512", k = 2, eta1 = 3, eta2 = 2, du = 10, dv = 4,
    ek = 800, dk = 1632, ct = 768
);
parameter_set!(
    /// ML-KEM-768 (security category 3); used by `X25519MLKEM768`,
    /// `SecP256r1MLKEM768` and `MLKEM768`.
    MlKem768, "ML-KEM-768", k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4,
    ek = 1184, dk = 2400, ct = 1088
);
parameter_set!(
    /// ML-KEM-1024 (security category 5); used by `SecP384r1MLKEM1024` and
    /// `MLKEM1024`.
    MlKem1024, "ML-KEM-1024", k = 4, eta1 = 2, eta2 = 2, du = 11, dv = 5,
    ek = 1568, dk = 3168, ct = 1568
);
