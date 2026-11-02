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
///
/// Supported floors: x86-64-v3 (AVX2, BMI2) on x86_64, ARMv8-A with Advanced
/// SIMD on AArch64, and RV64GC on RISC-V. Accelerated backends still check
/// every instruction-set extension they use, including those outside the
/// floor (AES-NI, PCLMULQDQ, SHA, VAES, AVX-512, ARMv8 Cryptography
/// Extensions, RISC-V V and vector crypto).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Features {
    /// x86 AES-NI.
    pub aes: bool,
    /// x86 carry-less multiplication.
    pub pclmulqdq: bool,
    /// x86 SHA extensions (SHA-1/SHA-256).
    pub sha: bool,
    /// x86 SHA-512 extensions.
    pub sha512: bool,
    /// x86 AVX.
    pub avx: bool,
    /// x86 AVX2.
    pub avx2: bool,
    /// x86 BMI2 (`mulx`).
    pub bmi2: bool,
    /// x86 ADX (`adcx`/`adox`).
    pub adx: bool,
    /// x86 vector AES (256/512-bit AES-NI).
    pub vaes: bool,
    /// x86 vector carry-less multiplication.
    pub vpclmulqdq: bool,
    /// x86 AVX-512 Foundation.
    pub avx512f: bool,
    /// x86 AVX-512 Vector Length extensions.
    pub avx512vl: bool,
    /// x86 AVX-512 Byte/Word instructions.
    pub avx512bw: bool,
    /// AArch64 Advanced SIMD (NEON).
    pub neon: bool,
    /// AArch64 AES instructions.
    pub arm_aes: bool,
    /// AArch64 polynomial multiply long (64x64 -> 128).
    pub pmull: bool,
    /// AArch64 SHA-256 instructions.
    pub arm_sha2: bool,
    /// AArch64 SHA-512 instructions.
    pub arm_sha512: bool,
    /// RISC-V vector extension 1.0 (`V`).
    pub rv_v: bool,
    /// RISC-V vector AES (`Zvkned`).
    pub rv_zvkned: bool,
    /// RISC-V vector SHA-256 (`Zvknha` or `Zvknhb`).
    pub rv_zvknha: bool,
    /// RISC-V vector SHA-256 and SHA-512 (`Zvknhb`).
    pub rv_zvknhb: bool,
    /// RISC-V vector GCM/GMAC (`Zvkg`).
    pub rv_zvkg: bool,
    /// RISC-V vector carry-less multiplication (`Zvbc`).
    pub rv_zvbc: bool,
    /// RISC-V vector cryptography bit-manipulation (`Zvkb` or `Zvbb`).
    pub rv_zvkb: bool,
    /// RISC-V scalar carry-less multiplication (`Zbc`).
    pub rv_zbc: bool,
    /// RISC-V scalar crypto bit-manipulation (`Zbkb`).
    pub rv_zbkb: bool,
    /// RISC-V basic bit-manipulation (`Zbb`).
    pub rv_zbb: bool,
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
        sha512: has!("sha512"),
        avx: has!("avx"),
        avx2: has!("avx2"),
        bmi2: has!("bmi2"),
        adx: has!("adx"),
        vaes: has!("vaes"),
        vpclmulqdq: has!("vpclmulqdq"),
        avx512f: has!("avx512f"),
        avx512vl: has!("avx512vl"),
        avx512bw: has!("avx512bw"),
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

/// RISC-V runtime detection reads the ISA string the Linux kernel publishes
/// in `/proc/cpuinfo`; `is_riscv_feature_detected!` is not yet stable. Only
/// extensions reported for every hart are trusted.
#[cfg(all(feature = "std", target_arch = "riscv64", target_os = "linux"))]
fn detect_impl() -> Features {
    static CACHE: std::sync::OnceLock<Features> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|info| parse_riscv_cpuinfo(&info))
            .unwrap_or_else(compile_time_features)
    })
}

#[cfg(not(any(
    all(
        feature = "std",
        any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")
    ),
    all(feature = "std", target_arch = "riscv64", target_os = "linux")
)))]
fn detect_impl() -> Features {
    compile_time_features()
}

/// Features guaranteed by the compilation target (`-C target-feature`).
#[allow(dead_code)]
fn compile_time_features() -> Features {
    let x86 = cfg!(any(target_arch = "x86_64", target_arch = "x86"));
    let arm = cfg!(target_arch = "aarch64");
    let rv = cfg!(target_arch = "riscv64");
    Features {
        aes: x86 && cfg!(target_feature = "aes"),
        pclmulqdq: x86 && cfg!(target_feature = "pclmulqdq"),
        sha: x86 && cfg!(target_feature = "sha"),
        avx: x86 && cfg!(target_feature = "avx"),
        avx2: x86 && cfg!(target_feature = "avx2"),
        bmi2: x86 && cfg!(target_feature = "bmi2"),
        adx: x86 && cfg!(target_feature = "adx"),
        neon: arm && cfg!(target_feature = "neon"),
        arm_aes: arm && cfg!(target_feature = "aes"),
        pmull: arm && cfg!(target_feature = "aes"),
        arm_sha2: arm && cfg!(target_feature = "sha2"),
        arm_sha512: arm && cfg!(target_feature = "sha3"),
        rv_v: rv && cfg!(target_feature = "v"),
        rv_zbc: rv && cfg!(target_feature = "zbc"),
        rv_zbkb: rv && cfg!(target_feature = "zbkb"),
        rv_zbb: rv && cfg!(target_feature = "zbb"),
        ..Features::default()
    }
}

/// Parses the `isa` lines of a RISC-V `/proc/cpuinfo`, intersecting all harts.
#[allow(dead_code)]
fn parse_riscv_cpuinfo(info: &str) -> Option<Features> {
    let mut result: Option<Features> = None;
    for line in info.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != "isa" {
            continue;
        }
        let hart = parse_riscv_isa(value.trim());
        result = Some(match result {
            None => hart,
            Some(prev) => intersect(prev, hart),
        });
    }
    result
}

/// Parses one RISC-V ISA string such as `rv64imafdcv_zbc_zvkned`.
#[allow(dead_code)]
fn parse_riscv_isa(isa: &str) -> Features {
    let isa = isa.to_ascii_lowercase();
    let mut parts = isa.split('_');
    let base = parts.next().unwrap_or("");
    let single = base
        .strip_prefix("rv64")
        .or_else(|| base.strip_prefix("rv32"));
    let mut f = Features::default();
    if let Some(letters) = single {
        f.rv_v = letters.contains('v');
    }
    for ext in parts {
        match ext {
            "zvkned" => f.rv_zvkned = true,
            "zvknha" => f.rv_zvknha = true,
            "zvknhb" => {
                f.rv_zvknha = true;
                f.rv_zvknhb = true;
            }
            "zvkg" => f.rv_zvkg = true,
            "zvbc" => f.rv_zvbc = true,
            "zvkb" | "zvbb" => f.rv_zvkb = true,
            "zbc" => f.rv_zbc = true,
            "zbkb" => f.rv_zbkb = true,
            "zbb" => f.rv_zbb = true,
            _ => {}
        }
    }
    // Vector crypto is unusable without the vector unit itself.
    if !f.rv_v {
        f.rv_zvkned = false;
        f.rv_zvknha = false;
        f.rv_zvknhb = false;
        f.rv_zvkg = false;
        f.rv_zvbc = false;
        f.rv_zvkb = false;
    }
    f
}

#[allow(dead_code)]
fn intersect(a: Features, b: Features) -> Features {
    Features {
        rv_v: a.rv_v && b.rv_v,
        rv_zvkned: a.rv_zvkned && b.rv_zvkned,
        rv_zvknha: a.rv_zvknha && b.rv_zvknha,
        rv_zvknhb: a.rv_zvknhb && b.rv_zvknhb,
        rv_zvkg: a.rv_zvkg && b.rv_zvkg,
        rv_zvbc: a.rv_zvbc && b.rv_zvbc,
        rv_zvkb: a.rv_zvkb && b.rv_zvkb,
        rv_zbc: a.rv_zbc && b.rv_zbc,
        rv_zbkb: a.rv_zbkb && b.rv_zbkb,
        rv_zbb: a.rv_zbb && b.rv_zbb,
        ..Features::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn riscv_isa_parsing() {
        let info = "processor\t: 0\nisa\t\t: rv64imafdcvh_zba_zbb_zbc_zbkb_zvbc_zvkg_zvkned_zvknhb\n\
                    processor\t: 1\nisa\t\t: rv64imafdcvh_zbb_zbc_zvkned\n";
        let f = parse_riscv_cpuinfo(info).unwrap();
        assert!(f.rv_v && f.rv_zvkned && f.rv_zbc && f.rv_zbb);
        assert!(!f.rv_zvkg && !f.rv_zvknhb && !f.rv_zbkb);

        let no_v = parse_riscv_isa("rv64imafdc_zvkned");
        assert!(!no_v.rv_v && !no_v.rv_zvkned);
        assert!(parse_riscv_cpuinfo("processor: 0\n").is_none());
    }

    #[test]
    fn portable_override() {
        set_portable_only(true);
        assert_eq!(Features::get(), Features::default());
        set_portable_only(false);
        assert_eq!(Features::get(), Features::detect());
    }
}
