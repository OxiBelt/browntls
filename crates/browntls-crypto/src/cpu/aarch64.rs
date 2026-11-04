//! aarch64 feature detection.

use super::bit;

#[cfg(feature = "std")]
pub(super) fn detect() -> u64 {
    let mut out = bit::ARM_NEON; // Advanced SIMD is mandatory for AArch64 Linux/macOS ABIs.
    if std::arch::is_aarch64_feature_detected!("aes") {
        out |= bit::ARM_AES;
    }
    if std::arch::is_aarch64_feature_detected!("sha2") {
        out |= bit::ARM_SHA2;
    }
    if std::arch::is_aarch64_feature_detected!("sha3") {
        out |= bit::ARM_SHA3;
    }
    out
}

#[cfg(not(feature = "std"))]
pub(super) fn detect() -> u64 {
    let mut out = 0;
    if cfg!(target_feature = "neon") {
        out |= bit::ARM_NEON;
    }
    if cfg!(all(target_feature = "aes", target_feature = "neon")) {
        out |= bit::ARM_AES;
    }
    if cfg!(all(target_feature = "sha2", target_feature = "neon")) {
        out |= bit::ARM_SHA2;
    }
    if cfg!(all(target_feature = "sha3", target_feature = "neon")) {
        out |= bit::ARM_SHA3;
    }
    out
}
