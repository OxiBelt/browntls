//! CPU feature detection used to select accelerated backends.
//!
//! With the `std` feature, detection happens at runtime (and is cached by the
//! standard library). Without `std`, only features enabled at compile time via
//! `-C target-feature` are reported.
//!
//! [`set_portable_only`] forces every algorithm onto its portable backend. It
//! exists so tests can exercise both code paths on the same machine and so
//! deployments can rule out a misbehaving accelerated backend.

use core::sync::atomic::{AtomicBool, Ordering};

static PORTABLE_ONLY: AtomicBool = AtomicBool::new(false);

/// Forces (or stops forcing) portable implementations for subsequently created
/// cipher, hash, and key objects. Objects created earlier keep their backend.
pub fn set_portable_only(portable: bool) {
    PORTABLE_ONLY.store(portable, Ordering::SeqCst);
}

/// Returns whether portable implementations are being forced.
#[must_use]
pub fn portable_only() -> bool {
    PORTABLE_ONLY.load(Ordering::SeqCst)
}

/// CPU capabilities relevant to browntls backends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Features {
    /// x86 AES-NI.
    pub aes: bool,
    /// x86 carry-less multiplication.
    pub pclmulqdq: bool,
    /// x86 SHA extensions (SHA-1/SHA-256).
    pub sha: bool,
    /// x86 SSSE3.
    pub ssse3: bool,
    /// x86 SSE4.1.
    pub sse41: bool,
    /// x86 AVX.
    pub avx: bool,
    /// x86 AVX2.
    pub avx2: bool,
    /// x86 BMI2 (`mulx`).
    pub bmi2: bool,
    /// x86 ADX (`adcx`/`adox`).
    pub adx: bool,
    /// AArch64 Advanced SIMD.
    pub neon: bool,
    /// AArch64 AES instructions.
    pub arm_aes: bool,
    /// AArch64 polynomial multiply long (64x64 -> 128).
    pub pmull: bool,
    /// AArch64 SHA-256 instructions.
    pub arm_sha2: bool,
    /// AArch64 SHA-512 instructions.
    pub arm_sha512: bool,
}

impl Features {
    /// Returns the features usable for newly created objects, honouring
    /// [`set_portable_only`].
    #[must_use]
    pub fn get() -> Self {
        if portable_only() {
            return Self::default();
        }
        Self::detect()
    }

    /// Detects the CPU features, ignoring [`set_portable_only`].
    #[must_use]
    pub fn detect() -> Self {
        detect_impl()
    }
}

#[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "x86")))]
fn detect_impl() -> Features {
    use std::is_x86_feature_detected as has;
    Features {
        aes: has!("aes"),
        pclmulqdq: has!("pclmulqdq"),
        sha: has!("sha"),
        ssse3: has!("ssse3"),
        sse41: has!("sse4.1"),
        avx: has!("avx"),
        avx2: has!("avx2"),
        bmi2: has!("bmi2"),
        adx: has!("adx"),
        ..Features::default()
    }
}

#[cfg(all(feature = "std", target_arch = "aarch64"))]
fn detect_impl() -> Features {
    use std::arch::is_aarch64_feature_detected as has;
    Features {
        neon: has!("neon"),
        arm_aes: has!("aes"),
        pmull: has!("pmull"),
        arm_sha2: has!("sha2"),
        arm_sha512: has!("sha3"),
        ..Features::default()
    }
}

#[cfg(not(all(
    feature = "std",
    any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")
)))]
fn detect_impl() -> Features {
    Features {
        aes: cfg!(target_feature = "aes") && cfg!(any(target_arch = "x86_64", target_arch = "x86")),
        pclmulqdq: cfg!(target_feature = "pclmulqdq"),
        sha: cfg!(target_feature = "sha"),
        ssse3: cfg!(target_feature = "ssse3"),
        sse41: cfg!(target_feature = "sse4.1"),
        avx: cfg!(target_feature = "avx"),
        avx2: cfg!(target_feature = "avx2"),
        bmi2: cfg!(target_feature = "bmi2"),
        adx: cfg!(target_feature = "adx"),
        neon: cfg!(all(target_arch = "aarch64", target_feature = "neon")),
        arm_aes: cfg!(all(target_arch = "aarch64", target_feature = "aes")),
        pmull: cfg!(all(target_arch = "aarch64", target_feature = "aes")),
        arm_sha2: cfg!(all(target_arch = "aarch64", target_feature = "sha2")),
        arm_sha512: cfg!(all(target_arch = "aarch64", target_feature = "sha3")),
    }
}
