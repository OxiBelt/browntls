//! Runtime CPU feature detection and backend selection support.
//!
//! Every accelerated backend in this crate is selected at run time from the
//! [`Features`] snapshot returned by [`features`]. Detection runs once and is
//! cached in an atomic; concurrent first calls may each run detection, which is
//! harmless because the result is deterministic.
//!
//! Detection sources:
//!
//! * x86-64: `CPUID` and `XGETBV` (works without `std`). The supported baseline
//!   is x86-64-v3 (AVX2, BMI1/2, FMA, MOVBE, LZCNT); AES-NI, PCLMULQDQ, SHA,
//!   VAES, VPCLMULQDQ, SHA512 and AVX-512 are optional extensions on top.
//! * aarch64: `std::arch::is_aarch64_feature_detected!` with the `std` feature,
//!   otherwise compile-time `target_feature`s only. Advanced SIMD (NEON) is
//!   architecturally mandatory on aarch64.
//! * riscv64: the Linux `riscv_hwprobe` system call (kernel 6.4+). On other
//!   systems, or for emulators whose `riscv_hwprobe` does not report the vector
//!   crypto extensions, a build may assert extensions with
//!   `--cfg browntls_assume_riscv="<ext>"`; asserting an extension the CPU lacks
//!   results in an illegal-instruction trap, never in silent miscomputation.
//!
//! Building with `--cfg browntls_force_soft` disables every SIMD and hardware
//! backend so that only the portable implementations run.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use core::sync::atomic::{AtomicU64, Ordering};

/// Bit set in the cache once detection has completed.
const INITIALIZED: u64 = 1 << 63;

static CACHE: AtomicU64 = AtomicU64::new(0);

/// A snapshot of the CPU features relevant to this crate.
///
/// Accessors for other architectures always return `false`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Features {
    bits: u64,
}

/// Returns the detected CPU features (cached after the first call).
#[inline]
pub fn features() -> Features {
    let cached = CACHE.load(Ordering::Relaxed);
    if cached & INITIALIZED != 0 {
        return Features {
            bits: cached & !INITIALIZED,
        };
    }
    let bits = if cfg!(browntls_force_soft) {
        0
    } else {
        detect()
    };
    CACHE.store(bits | INITIALIZED, Ordering::Relaxed);
    Features { bits }
}

#[cfg(target_arch = "x86_64")]
fn detect() -> u64 {
    x86_64::detect()
}

#[cfg(target_arch = "aarch64")]
fn detect() -> u64 {
    aarch64::detect()
}

#[cfg(target_arch = "riscv64")]
fn detect() -> u64 {
    riscv64::detect()
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
fn detect() -> u64 {
    0
}

/// Feature bit positions. The same bit may mean different things on different
/// architectures; accessors are compiled only for their architecture.
#[allow(dead_code)]
mod bit {
    // x86-64
    pub(crate) const X86_V3: u64 = 1 << 0; // AVX, AVX2, BMI1, BMI2, FMA, MOVBE, LZCNT, F16C + OS YMM state
    pub(crate) const X86_AES: u64 = 1 << 1;
    pub(crate) const X86_PCLMULQDQ: u64 = 1 << 2;
    pub(crate) const X86_SHA: u64 = 1 << 3;
    pub(crate) const X86_SHA512: u64 = 1 << 4; // requires AVX2 state
    pub(crate) const X86_VAES: u64 = 1 << 5; // requires AVX2 state
    pub(crate) const X86_VPCLMULQDQ: u64 = 1 << 6; // requires AVX2 state
    pub(crate) const X86_AVX512: u64 = 1 << 7; // F + VL + BW + DQ with OS ZMM state
    pub(crate) const X86_AVX512_IFMA: u64 = 1 << 8;
    pub(crate) const X86_AVX512_VBMI: u64 = 1 << 9;
    pub(crate) const X86_ADX: u64 = 1 << 10;
    pub(crate) const X86_GFNI: u64 = 1 << 11;
    pub(crate) const X86_SSSE3: u64 = 1 << 12;
    pub(crate) const X86_SSE41: u64 = 1 << 13;
    pub(crate) const X86_AVX: u64 = 1 << 14;
    pub(crate) const X86_AVX2: u64 = 1 << 15;
    pub(crate) const X86_BMI2: u64 = 1 << 16;

    // aarch64
    pub(crate) const ARM_NEON: u64 = 1 << 0;
    pub(crate) const ARM_AES: u64 = 1 << 1; // FEAT_AES + FEAT_PMULL
    pub(crate) const ARM_SHA2: u64 = 1 << 2; // FEAT_SHA1 + FEAT_SHA256
    pub(crate) const ARM_SHA3: u64 = 1 << 3; // FEAT_SHA3 + FEAT_SHA512

    // riscv64
    pub(crate) const RV_V: u64 = 1 << 0;
    pub(crate) const RV_ZVKNED: u64 = 1 << 1;
    pub(crate) const RV_ZVKNHA: u64 = 1 << 2;
    pub(crate) const RV_ZVKNHB: u64 = 1 << 3;
    pub(crate) const RV_ZVKG: u64 = 1 << 4;
    pub(crate) const RV_ZVBC: u64 = 1 << 5;
    pub(crate) const RV_ZVBB: u64 = 1 << 6;
    pub(crate) const RV_ZVKB: u64 = 1 << 7;
    pub(crate) const RV_ZBB: u64 = 1 << 8;
    pub(crate) const RV_ZBC: u64 = 1 << 9;
    pub(crate) const RV_ZBKB: u64 = 1 << 10;
    pub(crate) const RV_ZBKC: u64 = 1 << 11;
    pub(crate) const RV_ZKNH: u64 = 1 << 12;
    pub(crate) const RV_ZKNE: u64 = 1 << 13;
    pub(crate) const RV_ZKND: u64 = 1 << 14;
}

macro_rules! accessors {
    ($arch:literal: $($(#[$m:meta])* $name:ident => $bit:ident),* $(,)?) => {
        $(
            $(#[$m])*
            #[inline]
            #[must_use]
            pub fn $name(self) -> bool {
                cfg!(target_arch = $arch) && self.bits & bit::$bit == bit::$bit
            }
        )*
    };
}

impl Features {
    /// A snapshot with no optional features (portable code only).
    pub const NONE: Self = Self { bits: 0 };

    accessors! { "x86_64":
        /// x86-64-v3 baseline: AVX, AVX2, BMI1, BMI2, FMA, MOVBE, LZCNT, F16C with
        /// operating-system support for YMM state.
        x86_v3 => X86_V3,
        /// SSSE3.
        x86_ssse3 => X86_SSSE3,
        /// SSE4.1.
        x86_sse41 => X86_SSE41,
        /// AVX with OS YMM support.
        x86_avx => X86_AVX,
        /// AVX2 with OS YMM support.
        x86_avx2 => X86_AVX2,
        /// BMI2 (`MULX`, `SHRX`, ...).
        x86_bmi2 => X86_BMI2,
        /// AES-NI.
        x86_aes => X86_AES,
        /// PCLMULQDQ.
        x86_pclmulqdq => X86_PCLMULQDQ,
        /// SHA extensions (SHA-1 / SHA-256).
        x86_sha => X86_SHA,
        /// SHA512 extensions (VEX-encoded, YMM).
        x86_sha512 => X86_SHA512,
        /// VAES on YMM registers.
        x86_vaes => X86_VAES,
        /// VPCLMULQDQ on YMM registers.
        x86_vpclmulqdq => X86_VPCLMULQDQ,
        /// AVX-512 F, VL, BW and DQ with OS ZMM support.
        x86_avx512 => X86_AVX512,
        /// AVX-512 IFMA52.
        x86_avx512_ifma => X86_AVX512_IFMA,
        /// AVX-512 VBMI.
        x86_avx512_vbmi => X86_AVX512_VBMI,
        /// ADX (`ADCX`/`ADOX`).
        x86_adx => X86_ADX,
        /// GFNI.
        x86_gfni => X86_GFNI,
    }

    accessors! { "aarch64":
        /// Advanced SIMD (NEON); mandatory on aarch64 unless `browntls_force_soft`.
        arm_neon => ARM_NEON,
        /// FEAT_AES and FEAT_PMULL.
        arm_aes => ARM_AES,
        /// FEAT_SHA256 (and FEAT_SHA1).
        arm_sha2 => ARM_SHA2,
        /// FEAT_SHA3 and FEAT_SHA512.
        arm_sha3 => ARM_SHA3,
    }

    accessors! { "riscv64":
        /// RVV 1.0 (`V`). RVV 0.7.1 / XTheadVector is never reported.
        rv_v => RV_V,
        /// Zvkned: vector AES.
        rv_zvkned => RV_ZVKNED,
        /// Zvknha: vector SHA-256.
        rv_zvknha => RV_ZVKNHA,
        /// Zvknhb: vector SHA-256 and SHA-512.
        rv_zvknhb => RV_ZVKNHB,
        /// Zvkg: vector GHASH.
        rv_zvkg => RV_ZVKG,
        /// Zvbc: vector carry-less multiplication.
        rv_zvbc => RV_ZVBC,
        /// Zvbb: vector basic bit manipulation.
        rv_zvbb => RV_ZVBB,
        /// Zvkb: vector crypto bit manipulation.
        rv_zvkb => RV_ZVKB,
        /// Zbb: scalar basic bit manipulation.
        rv_zbb => RV_ZBB,
        /// Zbc: scalar carry-less multiplication.
        rv_zbc => RV_ZBC,
        /// Zbkb: scalar crypto bit manipulation.
        rv_zbkb => RV_ZBKB,
        /// Zbkc: scalar crypto carry-less multiplication.
        rv_zbkc => RV_ZBKC,
        /// Zknh: scalar SHA-2.
        rv_zknh => RV_ZKNH,
        /// Zkne: scalar AES encryption.
        rv_zkne => RV_ZKNE,
        /// Zknd: scalar AES decryption.
        rv_zknd => RV_ZKND,
    }

    /// Returns the raw feature bits (architecture specific; for diagnostics).
    #[must_use]
    pub fn bits(self) -> u64 {
        self.bits
    }

    /// Returns a copy with every feature in `mask` removed.
    ///
    /// Intended for tests that exercise a lower backend tier on capable hardware.
    #[must_use]
    pub fn without(self, mask: Self) -> Self {
        Self {
            bits: self.bits & !mask.bits,
        }
    }
}

impl core::fmt::Debug for Features {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut list = f.debug_set();
        macro_rules! show {
            ($($name:ident),*) => { $( if self.$name() { list.entry(&stringify!($name)); } )* };
        }
        show!(
            x86_v3,
            x86_ssse3,
            x86_sse41,
            x86_avx,
            x86_avx2,
            x86_bmi2,
            x86_aes,
            x86_pclmulqdq,
            x86_sha,
            x86_sha512,
            x86_vaes,
            x86_vpclmulqdq,
            x86_avx512,
            x86_avx512_ifma,
            x86_avx512_vbmi,
            x86_adx,
            x86_gfni,
            arm_neon,
            arm_aes,
            arm_sha2,
            arm_sha3,
            rv_v,
            rv_zvkned,
            rv_zvknha,
            rv_zvknhb,
            rv_zvkg,
            rv_zvbc,
            rv_zvbb,
            rv_zvkb,
            rv_zbb,
            rv_zbc,
            rv_zbkb,
            rv_zbkc,
            rv_zknh,
            rv_zkne,
            rv_zknd
        );
        list.finish()
    }
}

/// Returns the RVV vector register length in bytes (`vlenb`), or 0 when RVV 1.0
/// is unavailable or the target is not riscv64.
#[must_use]
pub fn riscv_vlenb() -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        if features().rv_v() {
            return riscv64::vlenb();
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_is_stable() {
        let a = features();
        let b = features();
        assert_eq!(a, b);
        assert_eq!(a.bits() & INITIALIZED, 0);
        #[cfg(feature = "std")]
        std::println!("detected: {a:?}, rvv vlenb = {}", riscv_vlenb());
    }

    #[test]
    fn without_masks_bits() {
        let f = features();
        assert_eq!(f.without(f), Features::NONE);
    }

    #[cfg(all(target_arch = "x86_64", feature = "std", not(browntls_force_soft)))]
    #[test]
    fn x86_matches_std_detection() {
        let f = features();
        assert_eq!(f.x86_avx2(), std::is_x86_feature_detected!("avx2"));
        assert_eq!(f.x86_aes(), std::is_x86_feature_detected!("aes"));
        assert_eq!(
            f.x86_pclmulqdq(),
            std::is_x86_feature_detected!("pclmulqdq")
        );
        assert_eq!(f.x86_sha(), std::is_x86_feature_detected!("sha"));
        assert_eq!(f.x86_adx(), std::is_x86_feature_detected!("adx"));
        assert_eq!(f.x86_bmi2(), std::is_x86_feature_detected!("bmi2"));
        assert_eq!(
            f.x86_vaes(),
            std::is_x86_feature_detected!("vaes") && std::is_x86_feature_detected!("avx2")
        );
        assert_eq!(
            f.x86_avx512(),
            std::is_x86_feature_detected!("avx512f")
                && std::is_x86_feature_detected!("avx512vl")
                && std::is_x86_feature_detected!("avx512bw")
                && std::is_x86_feature_detected!("avx512dq")
        );
    }
}
