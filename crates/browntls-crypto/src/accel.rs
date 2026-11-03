//! Acceleration policy and run-time status.
//!
//! Every algorithm family with SIMD or hardware-accelerated backends obeys a
//! process-wide [`Acceleration`] policy:
//!
//! * [`Acceleration::Preferred`] (default): use the best backend the CPU
//!   supports and fall back to the portable implementation otherwise.
//! * [`Acceleration::Required`]: like `Preferred`, but [`set_policy`] fails
//!   with [`Error::Unsupported`] unless an accelerated backend is available,
//!   so a deployment can refuse to start without hardware acceleration.
//! * [`Acceleration::None`]: always use the portable, constant-time
//!   implementation (for example to compare behaviour, to avoid vector-unit
//!   state, or to work around a suspected backend issue).
//!
//! Policies are consulted when a backend is selected: hash compressions and
//! stream-cipher calls select per call, while keyed objects (AES and AES-GCM
//! keys, ML-KEM keys) select once when constructed and keep that backend.
//! Change the policy before creating keys or connections.
//!
//! [`status`], [`status_all`] and [`accelerated`] report, per algorithm, the
//! policy, whether the CPU offers an accelerated backend, and the backend that
//! is selected now.
//!
//! The compile-time `--cfg browntls_force_soft` flag removes every
//! accelerated backend regardless of policy.
//!
//! ```
//! use browntls_crypto::accel::{self, Acceleration, Algorithm};
//!
//! // Report what runs accelerated on this machine.
//! for s in accel::accelerated() {
//!     println!("{}: {}", s.algorithm.name(), s.backend);
//! }
//!
//! // Insist on hardware AES, or fail at start-up.
//! match accel::set_policy(Algorithm::Aes, Acceleration::Required) {
//!     Ok(()) => assert!(accel::status(Algorithm::Aes).accelerated),
//!     Err(_) => assert!(!accel::status(Algorithm::Aes).hardware_available),
//! }
//!
//! // Portable code only, for every algorithm.
//! accel::set_policy_all(Acceleration::None).unwrap();
//! assert_eq!(accel::accelerated().count(), 0);
//! # accel::set_policy_all(Acceleration::Preferred).unwrap();
//! ```

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::Error;
use crate::cpu::{self, Features};

/// How an algorithm family may use accelerated backends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Acceleration {
    /// An accelerated backend must be available; setting this policy fails
    /// otherwise. Selection behaves like [`Acceleration::Preferred`].
    Required,
    /// Use the best available backend, falling back to portable code.
    #[default]
    Preferred,
    /// Use only the portable implementation.
    None,
}

impl Acceleration {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Required => 0,
            Self::Preferred => 1,
            Self::None => 2,
        }
    }

    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Required,
            2 => Self::None,
            _ => Self::Preferred,
        }
    }

    /// The policy's name: `"required"`, `"preferred"` or `"none"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::None => "none",
        }
    }
}

impl fmt::Display for Acceleration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl core::str::FromStr for Acceleration {
    type Err = Error;

    /// Parses `required`, `preferred` (or `prefered`) and `none`, ignoring
    /// ASCII case; convenient for configuration files and environment
    /// variables.
    fn from_str(s: &str) -> Result<Self, Error> {
        if s.eq_ignore_ascii_case("required") {
            Ok(Self::Required)
        } else if s.eq_ignore_ascii_case("preferred") || s.eq_ignore_ascii_case("prefered") {
            Ok(Self::Preferred)
        } else if s.eq_ignore_ascii_case("none") {
            Ok(Self::None)
        } else {
            Err(Error::Unsupported)
        }
    }
}

/// An algorithm family with selectable backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// SHA-224/SHA-256 compression.
    Sha256,
    /// SHA-384/SHA-512 compression.
    Sha512,
    /// Single-state Keccak-f\[1600\] (SHA-3, SHAKE).
    Keccak,
    /// Four-way Keccak-f\[1600\] (batched SHAKE, ML-KEM sampling).
    KeccakX4,
    /// AES block encryption and CTR mode.
    Aes,
    /// GHASH (AES-GCM authentication).
    Ghash,
    /// ChaCha20.
    ChaCha20,
    /// Poly1305.
    Poly1305,
    /// X25519 field arithmetic.
    X25519,
    /// P-256 field arithmetic.
    P256,
    /// RSA Montgomery multiplication.
    Rsa,
    /// ML-KEM polynomial arithmetic.
    MlKem,
}

impl Algorithm {
    /// Every algorithm family, in reporting order.
    pub const ALL: [Self; 12] = [
        Self::Sha256,
        Self::Sha512,
        Self::Keccak,
        Self::KeccakX4,
        Self::Aes,
        Self::Ghash,
        Self::ChaCha20,
        Self::Poly1305,
        Self::X25519,
        Self::P256,
        Self::Rsa,
        Self::MlKem,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Sha256 => 0,
            Self::Sha512 => 1,
            Self::Keccak => 2,
            Self::KeccakX4 => 3,
            Self::Aes => 4,
            Self::Ghash => 5,
            Self::ChaCha20 => 6,
            Self::Poly1305 => 7,
            Self::X25519 => 8,
            Self::P256 => 9,
            Self::Rsa => 10,
            Self::MlKem => 11,
        }
    }

    /// A short display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Keccak => "Keccak",
            Self::KeccakX4 => "Keccak x4",
            Self::Aes => "AES",
            Self::Ghash => "GHASH",
            Self::ChaCha20 => "ChaCha20",
            Self::Poly1305 => "Poly1305",
            Self::X25519 => "X25519",
            Self::P256 => "P-256",
            Self::Rsa => "RSA",
            Self::MlKem => "ML-KEM",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

const PREFERRED: u8 = Acceleration::Preferred.to_u8();

static POLICY: [AtomicU8; Algorithm::ALL.len()] = [
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
    AtomicU8::new(PREFERRED),
];

/// The current policy for `alg`.
#[must_use]
pub fn policy(alg: Algorithm) -> Acceleration {
    Acceleration::from_u8(POLICY[alg.index()].load(Ordering::Relaxed))
}

/// Sets the policy for `alg`.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] (leaving the policy unchanged) when
/// `policy` is [`Acceleration::Required`] and the CPU, the target or the
/// build offers no accelerated backend for `alg`.
pub fn set_policy(alg: Algorithm, policy: Acceleration) -> Result<(), Error> {
    if policy == Acceleration::Required && !hardware_available(alg) {
        return Err(Error::Unsupported);
    }
    POLICY[alg.index()].store(policy.to_u8(), Ordering::Relaxed);
    Ok(())
}

/// Sets the same policy for every algorithm.
///
/// # Errors
///
/// For [`Acceleration::Required`], returns [`Error::Unsupported`] and changes
/// nothing unless every algorithm has an accelerated backend on this CPU (use
/// [`status_all`] to see which do, and [`set_policy`] per algorithm).
pub fn set_policy_all(policy: Acceleration) -> Result<(), Error> {
    if policy == Acceleration::Required && !Algorithm::ALL.iter().all(|&a| hardware_available(a)) {
        return Err(Error::Unsupported);
    }
    for alg in Algorithm::ALL {
        POLICY[alg.index()].store(policy.to_u8(), Ordering::Relaxed);
    }
    Ok(())
}

/// Whether the policy lets `alg` use accelerated backends.
#[inline]
pub(crate) fn allowed(alg: Algorithm) -> bool {
    !cfg!(browntls_force_soft) && policy(alg) != Acceleration::None
}

/// The CPU features `alg` may use under the current policy.
#[inline]
pub(crate) fn features_for(alg: Algorithm) -> Features {
    if allowed(alg) {
        cpu::features()
    } else {
        Features::NONE
    }
}

/// Per-algorithm acceleration state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgorithmStatus {
    /// The algorithm family.
    pub algorithm: Algorithm,
    /// The policy in force.
    pub policy: Acceleration,
    /// Whether the CPU offers an accelerated backend (ignoring the policy).
    pub hardware_available: bool,
    /// Whether the backend selected now is accelerated.
    pub accelerated: bool,
    /// The backend selected now under the policy, e.g. `"AES-NI"` or
    /// `"portable"`.
    pub backend: &'static str,
}

impl fmt::Display for AlgorithmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (policy {}, hardware {})",
            self.algorithm,
            self.backend,
            self.policy,
            if self.hardware_available {
                "available"
            } else {
                "unavailable"
            }
        )
    }
}

/// The acceleration state of `alg`.
#[must_use]
pub fn status(alg: Algorithm) -> AlgorithmStatus {
    let backend = selected_backend(alg);
    AlgorithmStatus {
        algorithm: alg,
        policy: policy(alg),
        hardware_available: hardware_available(alg),
        accelerated: backend != PORTABLE,
        backend,
    }
}

/// The acceleration state of every algorithm, in [`Algorithm::ALL`] order.
#[must_use]
pub fn status_all() -> [AlgorithmStatus; Algorithm::ALL.len()] {
    Algorithm::ALL.map(status)
}

/// The algorithms that currently run an accelerated backend.
pub fn accelerated() -> impl Iterator<Item = AlgorithmStatus> {
    status_all().into_iter().filter(|s| s.accelerated)
}

const PORTABLE: &str = "portable";

/// Whether an accelerated backend exists for `alg` on this CPU and build.
fn hardware_available(alg: Algorithm) -> bool {
    if cfg!(browntls_force_soft) {
        return false;
    }
    let f = cpu::features();
    match alg {
        Algorithm::Sha256 => crate::hash::sha256_backend_name(f) != PORTABLE,
        Algorithm::Sha512 => crate::hash::sha512_backend_name(f) != PORTABLE,
        Algorithm::Keccak => crate::hash::keccak_backend_name(f) != PORTABLE,
        Algorithm::KeccakX4 => crate::hash::keccak_x4_backend_name(f) != PORTABLE,
        Algorithm::Aes => crate::aes::Backend::ALL
            .iter()
            .any(|b| *b != crate::aes::Backend::Soft && b.is_available()),
        Algorithm::Ghash => crate::gcm::GhashBackend::ALL
            .iter()
            .any(|b| *b != crate::gcm::GhashBackend::Soft && b.is_available()),
        Algorithm::ChaCha20 => crate::chacha::Backend::ALL
            .iter()
            .any(|b| *b != crate::chacha::Backend::Soft && b.is_available()),
        Algorithm::Poly1305 => crate::chacha::PolyBackend::ALL
            .iter()
            .any(|b| *b != crate::chacha::PolyBackend::Soft && b.is_available()),
        Algorithm::X25519 => crate::curve25519::x25519::Backend::X86Adx.is_available(),
        Algorithm::P256 => crate::nist::p256_hardware_available(),
        Algorithm::Rsa => crate::rsa::hardware_kernel_available(),
        Algorithm::MlKem => {
            crate::mlkem::Backend::available().any(|b| b != crate::mlkem::Backend::Portable)
        }
    }
}

/// The backend selected now for `alg`, honouring the policy.
fn selected_backend(alg: Algorithm) -> &'static str {
    use crate::aes::Backend as Aes;
    use crate::chacha::{Backend as ChaCha, PolyBackend as Poly};
    use crate::curve25519::x25519::Backend as X25519;
    use crate::gcm::GhashBackend as Ghash;
    use crate::mlkem::Backend as MlKem;

    match alg {
        Algorithm::Sha256 => crate::hash::sha256_backend_name(features_for(alg)),
        Algorithm::Sha512 => crate::hash::sha512_backend_name(features_for(alg)),
        Algorithm::Keccak => crate::hash::keccak_backend_name(features_for(alg)),
        Algorithm::KeccakX4 => crate::hash::keccak_x4_backend_name(features_for(alg)),
        Algorithm::Aes => match Aes::select() {
            Aes::Soft => PORTABLE,
            Aes::AesNi => "AES-NI",
            Aes::Vaes => "VAES (AVX2)",
            Aes::ArmAes => "FEAT_AES",
            Aes::RvZvkned => "Zvkned",
            Aes::RvZkne => "Zkne",
        },
        Algorithm::Ghash => match Ghash::select() {
            Ghash::Soft => PORTABLE,
            Ghash::Clmul => "PCLMULQDQ",
            Ghash::Pmull => "FEAT_PMULL",
            Ghash::RvZvkg => "Zvkg",
            Ghash::RvZvbc => "Zvbc",
            Ghash::RvClmul => "Zbc/Zbkc",
        },
        Algorithm::ChaCha20 => match ChaCha::best() {
            ChaCha::Soft => PORTABLE,
            ChaCha::Avx2 => "AVX2",
            ChaCha::Avx512 => "AVX-512",
            ChaCha::Neon => "NEON",
            ChaCha::Rvv => "RVV",
        },
        Algorithm::Poly1305 => match Poly::best() {
            Poly::Soft => PORTABLE,
            Poly::Bmi2 => "BMI2/ADX",
            Poly::Avx2 => "AVX2",
        },
        Algorithm::X25519 => match X25519::best() {
            X25519::Portable => PORTABLE,
            X25519::X86Adx => "BMI2/ADX",
        },
        Algorithm::P256 => {
            if crate::nist::p256_accelerated() {
                "BMI2/ADX"
            } else {
                PORTABLE
            }
        }
        Algorithm::Rsa => {
            if crate::rsa::kernel_accelerated() {
                "BMI2/ADX"
            } else {
                PORTABLE
            }
        }
        Algorithm::MlKem => match MlKem::detect() {
            MlKem::Portable => PORTABLE,
            MlKem::Avx2 => "AVX2",
            MlKem::Neon => "NEON",
            MlKem::Rvv => "RVV",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_round_trip_and_parse() {
        for p in [
            Acceleration::Required,
            Acceleration::Preferred,
            Acceleration::None,
        ] {
            assert_eq!(Acceleration::from_u8(p.to_u8()), p);
            assert_eq!(p.name().parse::<Acceleration>(), Ok(p));
        }
        assert_eq!("PREFERED".parse(), Ok(Acceleration::Preferred));
        assert!("fast".parse::<Acceleration>().is_err());
        for (i, a) in Algorithm::ALL.iter().enumerate() {
            assert_eq!(a.index(), i);
        }
    }

    #[test]
    fn status_is_consistent() {
        // Read-only: tests in this binary run concurrently, so they must not
        // change the process-wide policy (see `tests/accel.rs`).
        for s in status_all() {
            assert_eq!(s.accelerated, s.backend != PORTABLE);
            if s.accelerated {
                assert!(s.hardware_available, "{s}");
            }
        }
    }
}
