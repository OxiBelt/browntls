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
//! keyed objects (AES and AES-GCM keys, ML-KEM keys, RSA private keys)
//! select once when constructed or loaded, so set policies before creating keys or connections. The
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
use core::sync::atomic::{AtomicU64, Ordering};

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

    /// This kind's bit in a kind mask (`Uses::bits`, policy nibbles).
    const fn bit(self) -> u8 {
        match self {
            Self::Simd => 0b01,
            Self::Dedicated => 0b10,
        }
    }

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
    pub const fn permits(self, uses: Uses) -> bool {
        permits_bits(self.to_bits(), uses.bits())
    }

    /// The mask of kinds set to `level`.
    const fn mask(self, level: Acceleration) -> u8 {
        const fn same(a: Acceleration, b: Acceleration) -> bool {
            matches!(
                (a, b),
                (Acceleration::Required, Acceleration::Required)
                    | (Acceleration::Preferred, Acceleration::Preferred)
                    | (Acceleration::None, Acceleration::None)
            )
        }
        (if same(self.simd, level) {
            Kind::Simd.bit()
        } else {
            0
        }) | (if same(self.dedicated, level) {
            Kind::Dedicated.bit()
        } else {
            0
        })
    }

    /// The policy's 4-bit encoding: bits 0-1 hold the mask of `Required`
    /// kinds, bits 2-3 the mask of `None` kinds; `Preferred` is 0.
    const fn to_bits(self) -> u8 {
        self.mask(Acceleration::Required) | (self.mask(Acceleration::None) << 2)
    }

    /// Decodes [`Policy::to_bits`]. A kind marked both required and none
    /// (never produced by `to_bits`) decodes as required.
    const fn from_bits(v: u8) -> Self {
        const fn level(v: u8, kind: Kind) -> Acceleration {
            if v & kind.bit() != 0 {
                Acceleration::Required
            } else if (v >> 2) & kind.bit() != 0 {
                Acceleration::None
            } else {
                Acceleration::Preferred
            }
        }
        Self::new(level(v, Kind::Simd), level(v, Kind::Dedicated))
    }
}

/// `permits` on encodings: every required kind is used and no forbidden kind
/// is used.
#[inline]
const fn permits_bits(policy: u8, uses: u8) -> bool {
    let required = policy & 0b11;
    let forbidden = (policy >> 2) & 0b11;
    required & !uses == 0 && forbidden & uses == 0
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

    /// The kind mask: bit 0 for SIMD, bit 1 for dedicated instructions.
    #[must_use]
    pub const fn bits(self) -> u8 {
        (if self.simd { Kind::Simd.bit() } else { 0 })
            | (if self.dedicated {
                Kind::Dedicated.bit()
            } else {
                0
            })
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

/// The most preferred available backend that the encoded policy permits.
#[inline]
fn select_under<B: Backends>(policy: u8) -> Option<B> {
    B::PREFERENCE
        .iter()
        .copied()
        .find(|b| permits_bits(policy, b.uses().bits()) && b.available())
}

/// The backend `B`'s family uses under its current policy.
#[inline]
pub(crate) fn select<B: Backends>() -> B {
    // Only satisfiable policies are stored, so the fallback is only reached
    // if hardware detection changed underneath us.
    select_under::<B>(nibble(POLICIES.load(Ordering::Relaxed), B::ALGORITHM))
        .unwrap_or_else(portable::<B>)
}

fn satisfiable<B: Backends>(policy: Policy) -> bool {
    select_under::<B>(policy.to_bits()).is_some()
}

fn status_of<B: Backends>(policy: Policy) -> AlgorithmStatus {
    let selected = select_under::<B>(policy.to_bits()).unwrap_or_else(portable::<B>);
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

/// Every algorithm's policy in one word: algorithm `i` occupies bits
/// `4 * i .. 4 * i + 4` with the [`Policy::to_bits`] encoding. All-preferred
/// is zero, so the initial value is the default policy. Updates are single
/// atomic stores or compare-and-swap loops, so readers always observe a
/// consistent set of policies.
static POLICIES: AtomicU64 = AtomicU64::new(0);

const NIBBLE: u64 = 0xf;

#[inline]
const fn shift(alg: Algorithm) -> u32 {
    // `index` < 12, so the shift is below 48.
    #[allow(clippy::cast_possible_truncation)]
    {
        4 * alg.index() as u32
    }
}

#[inline]
const fn nibble(word: u64, alg: Algorithm) -> u8 {
    // Masked to four bits.
    #[allow(clippy::cast_possible_truncation)]
    {
        ((word >> shift(alg)) & NIBBLE) as u8
    }
}

#[inline]
const fn with_nibble(word: u64, alg: Algorithm, policy: Policy) -> u64 {
    (word & !(NIBBLE << shift(alg))) | ((policy.to_bits() as u64) << shift(alg))
}

/// The current policies of every algorithm, from one atomic load.
fn snapshot() -> [Policy; Algorithm::ALL.len()] {
    let word = POLICIES.load(Ordering::Relaxed);
    Algorithm::ALL.map(|alg| Policy::from_bits(nibble(word, alg)))
}

/// Applies `next` to every algorithm's policy atomically, failing (and
/// changing nothing) if any resulting policy is unsatisfiable.
fn update_all(next: impl Fn(Algorithm, Policy) -> Policy) -> Result<(), Error> {
    POLICIES
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |word| {
            let mut out = word;
            for alg in Algorithm::ALL {
                let p = next(alg, Policy::from_bits(nibble(word, alg)));
                if !for_family!(alg, satisfiable, p) {
                    return None;
                }
                out = with_nibble(out, alg, p);
            }
            Some(out)
        })
        .map(|_| ())
        .map_err(|_| Error::Unsupported)
}

/// The current policy for `alg`.
#[must_use]
pub fn policy(alg: Algorithm) -> Policy {
    Policy::from_bits(nibble(POLICIES.load(Ordering::Relaxed), alg))
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
    POLICIES
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |word| {
            Some(with_nibble(word, alg, policy))
        })
        .map(|_| ())
        .map_err(|_| Error::Unsupported)
}

/// Sets the same policy for every algorithm, atomically.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] and changes nothing unless every algorithm
/// can satisfy `policy` (see [`status_all`]).
pub fn set_policy_all(policy: Policy) -> Result<(), Error> {
    update_all(|_, _| policy)
}

/// Sets the level of one [`Kind`] for `alg`, keeping the other kind's level.
///
/// # Errors
///
/// As for [`set_policy`].
pub fn set_kind(alg: Algorithm, kind: Kind, level: Acceleration) -> Result<(), Error> {
    POLICIES
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |word| {
            let p = Policy::from_bits(nibble(word, alg)).with(kind, level);
            for_family!(alg, satisfiable, p).then(|| with_nibble(word, alg, p))
        })
        .map(|_| ())
        .map_err(|_| Error::Unsupported)
}

/// Sets the level of one [`Kind`] for every algorithm, keeping each
/// algorithm's level for the other kind; applied atomically.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] and changes nothing unless every algorithm
/// can satisfy its resulting policy.
pub fn set_kind_all(kind: Kind, level: Acceleration) -> Result<(), Error> {
    update_all(|_, p| p.with(kind, level))
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
    for_family!(alg, status_of, policy(alg))
}

/// The acceleration state of every algorithm, in [`Algorithm::ALL`] order,
/// from one consistent snapshot of the policies.
#[must_use]
pub fn status_all() -> [AlgorithmStatus; Algorithm::ALL.len()] {
    let policies = snapshot();
    Algorithm::ALL.map(|alg| for_family!(alg, status_of, policies[alg.index()]))
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
        assert_eq!(Policy::PREFERRED.to_bits(), 0);
        assert_eq!(Policy::NONE.to_bits(), 0b1100);
        assert_eq!(Uses::BOTH.bits(), 0b11);
        let mut word = 0u64;
        for (i, simd) in LEVELS.into_iter().enumerate() {
            for (j, dedicated) in LEVELS.into_iter().enumerate() {
                let p = Policy::new(simd, dedicated);
                assert_eq!(Policy::from_bits(p.to_bits()), p);
                // Neighbouring nibbles are untouched.
                let alg = Algorithm::ALL[(3 * i + j) % Algorithm::ALL.len()];
                let before = word;
                word = with_nibble(word, alg, p);
                assert_eq!(Policy::from_bits(nibble(word, alg)), p);
                assert_eq!(
                    word & !(NIBBLE << shift(alg)),
                    before & !(NIBBLE << shift(alg))
                );
            }
            assert_eq!(simd.name().parse::<Acceleration>(), Ok(simd));
        }
        assert!(word >> 48 == 0, "only 48 bits are used");
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
