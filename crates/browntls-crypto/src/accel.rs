//! Acceleration policy and run-time status, per kind of acceleration.
//!
//! Accelerated backends rely on one or both [`Kind`]s of hardware support:
//!
//! * [`Kind::Simd`]: general-purpose vector units used for data-parallel code
//!   — AVX2 and AVX-512 on x86-64, Advanced SIMD (NEON) on aarch64, RVV on
//!   riscv64.
//! * [`Kind::Dedicated`]: special-purpose instructions outside those SIMD
//!   units — cryptographic and hashing instructions (AES-NI, PCLMULQDQ, SHA,
//!   Armv8 AES/PMULL/SHA2/SHA512/SHA3, RISC-V Zk\*/Zvk\*, Zbc/Zbkc) and the
//!   scalar multi-precision and bit-manipulation extensions used by
//!   cryptographic code (BMI1/BMI2/ADX, Zbb). Dedicated instructions may use
//!   the architecture's baseline 128-bit registers (AES-NI on XMM, Armv8
//!   crypto on NEON registers) without counting as SIMD.
//!
//! Some backends use both, for example VAES (AES instructions on 256-bit
//! vectors) and RISC-V vector cryptography (Zvkned, Zvkg, Zvknh\*).
//!
//! Each algorithm family has a [`Policy`] that sets an [`Acceleration`] level
//! for each kind:
//!
//! * [`Acceleration::Preferred`] (default): backends using this kind may be
//!   selected; the best available backend wins.
//! * [`Acceleration::Required`]: the selected backend must use this kind;
//!   setting the policy fails with [`Error::Unsupported`] (leaving it
//!   unchanged) if no available backend qualifies.
//! * [`Acceleration::None`]: backends using this kind are never selected.
//!
//! Selection picks the most preferred available backend that the policy
//! permits; the portable implementation uses neither kind and is the
//! fallback. Hash compressions and stream-cipher calls select per call, while
//! keyed objects (AES and AES-GCM keys, ML-KEM keys) select once when
//! constructed, so set policies before creating keys or connections. The
//! hardware checks that guard `unsafe` backend code are independent of the
//! policy, and `--cfg browntls_force_soft` removes every accelerated backend.
//!
//! ```
//! use browntls_crypto::accel::{self, Acceleration, Algorithm, Kind, Policy};
//!
//! // What runs accelerated now, and with which kind of hardware support.
//! for s in accel::accelerated() {
//!     println!("{s}");
//! }
//! let dedicated: Vec<_> = accel::accelerated_by(Kind::Dedicated).collect();
//! # let _ = dedicated;
//!
//! // Keep AES-NI / Armv8 AES but never use the SIMD units.
//! accel::set_kind_all(Kind::Simd, Acceleration::None).unwrap();
//! assert_eq!(accel::accelerated_by(Kind::Simd).count(), 0);
//!
//! // Insist on dedicated AES instructions, or fail at start-up.
//! let aes = Policy::new(Acceleration::Preferred, Acceleration::Required);
//! match accel::set_policy(Algorithm::Aes, aes) {
//!     Ok(()) => assert!(accel::status(Algorithm::Aes).uses.dedicated),
//!     Err(_) => assert!(!accel::status(Algorithm::Aes).available.dedicated),
//! }
//!
//! // Portable code only.
//! accel::set_policy_all(Policy::NONE).unwrap();
//! assert_eq!(accel::accelerated().count(), 0);
//! # accel::set_policy_all(Policy::PREFERRED).unwrap();
//! ```

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::Error;

/// A kind of hardware support an accelerated backend relies on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// General-purpose vector units (AVX2, AVX-512, NEON, RVV).
    Simd,
    /// Dedicated cryptographic/hashing instructions and scalar
    /// multi-precision or bit-manipulation extensions.
    Dedicated,
}

impl Kind {
    /// Both kinds.
    pub const ALL: [Self; 2] = [Self::Simd, Self::Dedicated];

    /// `"SIMD"` or `"dedicated"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Simd => "SIMD",
            Self::Dedicated => "dedicated",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How one [`Kind`] of acceleration may be used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Acceleration {
    /// The selected backend must use this kind.
    Required,
    /// Backends using this kind may be selected.
    #[default]
    Preferred,
    /// Backends using this kind are never selected.
    None,
}

impl Acceleration {
    const fn to_bits(self) -> u8 {
        match self {
            Self::Required => 0,
            Self::Preferred => 1,
            Self::None => 2,
        }
    }

    const fn from_bits(v: u8) -> Self {
        match v & 3 {
            0 => Self::Required,
            2 => Self::None,
            _ => Self::Preferred,
        }
    }

    /// `"required"`, `"preferred"` or `"none"`.
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
    /// ASCII case.
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

/// The acceleration levels for SIMD and for dedicated instructions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Policy {
    /// Level for [`Kind::Simd`].
    pub simd: Acceleration,
    /// Level for [`Kind::Dedicated`].
    pub dedicated: Acceleration,
}

impl Policy {
    /// Both kinds preferred (the default).
    pub const PREFERRED: Self = Self::new(Acceleration::Preferred, Acceleration::Preferred);
    /// Portable code only.
    pub const NONE: Self = Self::new(Acceleration::None, Acceleration::None);

    /// A policy with the given levels for SIMD and dedicated instructions.
    #[must_use]
    pub const fn new(simd: Acceleration, dedicated: Acceleration) -> Self {
        Self { simd, dedicated }
    }

    /// The level for `kind`.
    #[must_use]
    pub const fn get(self, kind: Kind) -> Acceleration {
        match kind {
            Kind::Simd => self.simd,
            Kind::Dedicated => self.dedicated,
        }
    }

    /// A copy with the level for `kind` replaced.
    #[must_use]
    pub const fn with(self, kind: Kind, level: Acceleration) -> Self {
        match kind {
            Kind::Simd => Self::new(level, self.dedicated),
            Kind::Dedicated => Self::new(self.simd, level),
        }
    }

    /// Whether a backend using `uses` may be selected under this policy.
    #[must_use]
    pub fn permits(self, uses: Uses) -> bool {
        Kind::ALL.iter().all(|&k| match self.get(k) {
            Acceleration::Required => uses.get(k),
            Acceleration::Preferred => true,
            Acceleration::None => !uses.get(k),
        })
    }

    const fn to_bits(self) -> u8 {
        self.simd.to_bits() | (self.dedicated.to_bits() << 2)
    }

    const fn from_bits(v: u8) -> Self {
        Self::new(Acceleration::from_bits(v), Acceleration::from_bits(v >> 2))
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIMD {}, dedicated {}", self.simd, self.dedicated)
    }
}

/// The kinds of hardware support a backend uses (or that are available).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Uses {
    /// Uses SIMD units.
    pub simd: bool,
    /// Uses dedicated instructions.
    pub dedicated: bool,
}

impl Uses {
    /// The portable implementation: neither kind.
    pub const PORTABLE: Self = Self {
        simd: false,
        dedicated: false,
    };
    /// SIMD only.
    pub const SIMD: Self = Self {
        simd: true,
        dedicated: false,
    };
    /// Dedicated instructions only.
    pub const DEDICATED: Self = Self {
        simd: false,
        dedicated: true,
    };
    /// SIMD and dedicated instructions.
    pub const BOTH: Self = Self {
        simd: true,
        dedicated: true,
    };

    /// Whether `kind` is used.
    #[must_use]
    pub const fn get(self, kind: Kind) -> bool {
        match kind {
            Kind::Simd => self.simd,
            Kind::Dedicated => self.dedicated,
        }
    }

    /// Whether any acceleration is used.
    #[must_use]
    pub const fn any(self) -> bool {
        self.simd || self.dedicated
    }

    const fn union(self, other: Self) -> Self {
        Self {
            simd: self.simd || other.simd,
            dedicated: self.dedicated || other.dedicated,
        }
    }
}

impl fmt::Display for Uses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match (self.simd, self.dedicated) {
            (true, true) => "SIMD+dedicated",
            (true, false) => "SIMD",
            (false, true) => "dedicated",
            (false, false) => "none",
        })
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

/// A family's backends, as seen by the policy machinery.
pub(crate) trait Backends: Copy + PartialEq + 'static {
    /// The family.
    const ALGORITHM: Algorithm;
    /// Every backend, most preferred first, ending with the portable one.
    const PREFERENCE: &'static [Self];
    /// Whether the CPU, target and build can run this backend.
    fn available(self) -> bool;
    /// The kinds of hardware support this backend uses.
    fn uses(self) -> Uses;
    /// A display name such as `"AES-NI"` or `"portable"`.
    fn name(self) -> &'static str;
}

fn portable<B: Backends>() -> B {
    B::PREFERENCE[B::PREFERENCE.len() - 1]
}

/// The most preferred available backend that `policy` permits.
fn select_under<B: Backends>(policy: Policy) -> Option<B> {
    B::PREFERENCE
        .iter()
        .copied()
        .find(|b| b.available() && policy.permits(b.uses()))
}

/// The backend `B`'s family uses under its current policy.
#[inline]
pub(crate) fn select<B: Backends>() -> B {
    // `set_policy` only stores satisfiable policies, so the fallback is only
    // reached if hardware detection changed underneath us.
    select_under::<B>(policy(B::ALGORITHM)).unwrap_or_else(portable::<B>)
}

fn satisfiable<B: Backends>(policy: Policy) -> bool {
    select_under::<B>(policy).is_some()
}

fn status_of<B: Backends>() -> AlgorithmStatus {
    let policy = policy(B::ALGORITHM);
    let selected = select_under::<B>(policy).unwrap_or_else(portable::<B>);
    let available = B::PREFERENCE
        .iter()
        .filter(|b| b.available())
        .fold(Uses::PORTABLE, |acc, b| acc.union(b.uses()));
    AlgorithmStatus {
        algorithm: B::ALGORITHM,
        policy,
        backend: selected.name(),
        uses: selected.uses(),
        available,
    }
}

/// Runs a generic function for the backend set of `$alg`.
macro_rules! for_family {
    ($alg:expr, $f:ident $(, $arg:expr)*) => {
        match $alg {
            Algorithm::Sha256 => $f::<crate::hash::Sha256Backend>($($arg),*),
            Algorithm::Sha512 => $f::<crate::hash::Sha512Backend>($($arg),*),
            Algorithm::Keccak => $f::<crate::hash::KeccakBackend>($($arg),*),
            Algorithm::KeccakX4 => $f::<crate::hash::KeccakX4Backend>($($arg),*),
            Algorithm::Aes => $f::<crate::aes::Backend>($($arg),*),
            Algorithm::Ghash => $f::<crate::gcm::GhashBackend>($($arg),*),
            Algorithm::ChaCha20 => $f::<crate::chacha::Backend>($($arg),*),
            Algorithm::Poly1305 => $f::<crate::chacha::PolyBackend>($($arg),*),
            Algorithm::X25519 => $f::<crate::curve25519::x25519::Backend>($($arg),*),
            Algorithm::P256 => $f::<crate::nist::P256Backend>($($arg),*),
            Algorithm::Rsa => $f::<crate::rsa::RsaBackend>($($arg),*),
            Algorithm::MlKem => $f::<crate::mlkem::Backend>($($arg),*),
        }
    };
}

static POLICY: [AtomicU8; Algorithm::ALL.len()] =
    [const { AtomicU8::new(Policy::PREFERRED.to_bits()) }; Algorithm::ALL.len()];

/// The current policy for `alg`.
#[must_use]
pub fn policy(alg: Algorithm) -> Policy {
    Policy::from_bits(POLICY[alg.index()].load(Ordering::Relaxed))
}

/// Sets the policy for `alg`.
///
/// # Errors
///
/// Returns [`Error::Unsupported`], leaving the policy unchanged, when a kind
/// is [`Acceleration::Required`] but no available backend satisfies the
/// policy.
pub fn set_policy(alg: Algorithm, policy: Policy) -> Result<(), Error> {
    if !for_family!(alg, satisfiable, policy) {
        return Err(Error::Unsupported);
    }
    POLICY[alg.index()].store(policy.to_bits(), Ordering::Relaxed);
    Ok(())
}

/// Sets the same policy for every algorithm.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] and changes nothing unless every algorithm
/// can satisfy `policy` (see [`status_all`]).
pub fn set_policy_all(policy: Policy) -> Result<(), Error> {
    if !Algorithm::ALL
        .iter()
        .all(|&alg| for_family!(alg, satisfiable, policy))
    {
        return Err(Error::Unsupported);
    }
    for alg in Algorithm::ALL {
        POLICY[alg.index()].store(policy.to_bits(), Ordering::Relaxed);
    }
    Ok(())
}

/// Sets the level of one [`Kind`] for `alg`, keeping the other kind's level.
///
/// # Errors
///
/// As for [`set_policy`].
pub fn set_kind(alg: Algorithm, kind: Kind, level: Acceleration) -> Result<(), Error> {
    set_policy(alg, policy(alg).with(kind, level))
}

/// Sets the level of one [`Kind`] for every algorithm, keeping each
/// algorithm's level for the other kind.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] and changes nothing unless every algorithm
/// can satisfy its resulting policy.
pub fn set_kind_all(kind: Kind, level: Acceleration) -> Result<(), Error> {
    let mut next = [Policy::PREFERRED; Algorithm::ALL.len()];
    for alg in Algorithm::ALL {
        let p = policy(alg).with(kind, level);
        if !for_family!(alg, satisfiable, p) {
            return Err(Error::Unsupported);
        }
        next[alg.index()] = p;
    }
    for alg in Algorithm::ALL {
        POLICY[alg.index()].store(next[alg.index()].to_bits(), Ordering::Relaxed);
    }
    Ok(())
}

/// Per-algorithm acceleration state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgorithmStatus {
    /// The algorithm family.
    pub algorithm: Algorithm,
    /// The policy in force.
    pub policy: Policy,
    /// The backend selected now, e.g. `"AES-NI"` or `"portable"`.
    pub backend: &'static str,
    /// The kinds of acceleration the selected backend uses.
    pub uses: Uses,
    /// The kinds offered by the backends this CPU can run, ignoring the
    /// policy.
    pub available: Uses,
}

impl AlgorithmStatus {
    /// Whether the selected backend uses any acceleration.
    #[must_use]
    pub const fn accelerated(&self) -> bool {
        self.uses.any()
    }
}

impl fmt::Display for AlgorithmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} [uses {}] (policy: {}; available: {})",
            self.algorithm, self.backend, self.uses, self.policy, self.available
        )
    }
}

/// The acceleration state of `alg`.
#[must_use]
pub fn status(alg: Algorithm) -> AlgorithmStatus {
    for_family!(alg, status_of)
}

/// The acceleration state of every algorithm, in [`Algorithm::ALL`] order.
#[must_use]
pub fn status_all() -> [AlgorithmStatus; Algorithm::ALL.len()] {
    Algorithm::ALL.map(status)
}

/// The algorithms whose selected backend uses any acceleration.
pub fn accelerated() -> impl Iterator<Item = AlgorithmStatus> {
    status_all()
        .into_iter()
        .filter(AlgorithmStatus::accelerated)
}

/// The algorithms whose selected backend uses `kind`.
pub fn accelerated_by(kind: Kind) -> impl Iterator<Item = AlgorithmStatus> {
    status_all().into_iter().filter(move |s| s.uses.get(kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEVELS: [Acceleration; 3] = [
        Acceleration::Required,
        Acceleration::Preferred,
        Acceleration::None,
    ];

    #[test]
    fn encodings_round_trip() {
        for simd in LEVELS {
            for dedicated in LEVELS {
                let p = Policy::new(simd, dedicated);
                assert_eq!(Policy::from_bits(p.to_bits()), p);
            }
            assert_eq!(simd.name().parse::<Acceleration>(), Ok(simd));
        }
        assert_eq!("PREFERED".parse(), Ok(Acceleration::Preferred));
        assert!("fast".parse::<Acceleration>().is_err());
        for (i, a) in Algorithm::ALL.iter().enumerate() {
            assert_eq!(a.index(), i);
        }
    }

    #[test]
    fn permits_truth_table() {
        let uses = [Uses::PORTABLE, Uses::SIMD, Uses::DEDICATED, Uses::BOTH];
        for simd in LEVELS {
            for dedicated in LEVELS {
                let p = Policy::new(simd, dedicated);
                for u in uses {
                    let ok = |level, used| match level {
                        Acceleration::Required => used,
                        Acceleration::Preferred => true,
                        Acceleration::None => !used,
                    };
                    assert_eq!(
                        p.permits(u),
                        ok(simd, u.simd) && ok(dedicated, u.dedicated),
                        "{p} {u}"
                    );
                }
            }
        }
    }

    fn families_well_formed<B: Backends>() -> bool {
        let last = portable::<B>();
        last.uses() == Uses::PORTABLE
            && last.available()
            && B::PREFERENCE[..B::PREFERENCE.len() - 1]
                .iter()
                .all(|b| b.uses().any())
    }

    #[test]
    fn status_is_consistent() {
        // Read-only: tests in this binary run concurrently, so they must not
        // change the process-wide policy (see `tests/accel.rs`).
        for alg in Algorithm::ALL {
            assert!(for_family!(alg, families_well_formed), "{alg}");
            let s = status(alg);
            assert_eq!(s.accelerated(), s.backend != "portable", "{s}");
            assert!(s.uses.simd <= s.available.simd, "{s}");
            assert!(s.uses.dedicated <= s.available.dedicated, "{s}");
        }
    }
}
