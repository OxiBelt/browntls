//! riscv64 feature detection via `riscv_hwprobe(2)` plus build-time assertions.
#![allow(unsafe_code)]

use super::bit;

#[cfg(target_os = "linux")]
fn hwprobe_bits() -> u64 {
    use crate::sys::{HwProbe, riscv_hwprobe};
    const KEY_BASE_BEHAVIOR: i64 = 3;
    const BASE_BEHAVIOR_IMA: u64 = 1 << 0;
    const KEY_IMA_EXT_0: i64 = 4;

    let mut pairs = [
        HwProbe {
            key: KEY_BASE_BEHAVIOR,
            value: 0,
        },
        HwProbe {
            key: KEY_IMA_EXT_0,
            value: 0,
        },
    ];
    if !riscv_hwprobe(&mut pairs) {
        return 0;
    }
    if pairs[0].key != KEY_BASE_BEHAVIOR
        || pairs[0].value & BASE_BEHAVIOR_IMA == 0
        || pairs[1].key != KEY_IMA_EXT_0
    {
        return 0;
    }
    let ext = pairs[1].value;
    // Bit positions from linux/arch/riscv/include/uapi/asm/hwprobe.h.
    let map: [(u32, u64); 15] = [
        (2, bit::RV_V),
        (4, bit::RV_ZBB),
        (7, bit::RV_ZBC),
        (8, bit::RV_ZBKB),
        (9, bit::RV_ZBKC),
        (12, bit::RV_ZKNE),
        (11, bit::RV_ZKND),
        (13, bit::RV_ZKNH),
        (17, bit::RV_ZVBB),
        (18, bit::RV_ZVBC),
        (19, bit::RV_ZVKB),
        (20, bit::RV_ZVKG),
        (21, bit::RV_ZVKNED),
        (22, bit::RV_ZVKNHA),
        (23, bit::RV_ZVKNHB),
    ];
    let mut out = 0;
    for (b, f) in map {
        if ext & (1 << b) != 0 {
            out |= f;
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn hwprobe_bits() -> u64 {
    0
}

fn assumed_bits() -> u64 {
    let mut out = 0;
    macro_rules! assume {
        ($($name:literal => $bit:ident),*) => {
            $( if cfg!(browntls_assume_riscv = $name) { out |= bit::$bit; } )*
        };
    }
    assume!(
        "v" => RV_V, "zvkned" => RV_ZVKNED, "zvknha" => RV_ZVKNHA, "zvknhb" => RV_ZVKNHB,
        "zvkg" => RV_ZVKG, "zvbc" => RV_ZVBC, "zvbb" => RV_ZVBB, "zvkb" => RV_ZVKB,
        "zbb" => RV_ZBB, "zbc" => RV_ZBC, "zbkb" => RV_ZBKB, "zbkc" => RV_ZBKC,
        "zknh" => RV_ZKNH, "zkne" => RV_ZKNE, "zknd" => RV_ZKND
    );
    out
}

pub(super) fn detect() -> u64 {
    let mut out = hwprobe_bits() | assumed_bits();
    // Vector crypto extensions are only usable with the vector unit.
    let vector_only = bit::RV_ZVKNED
        | bit::RV_ZVKNHA
        | bit::RV_ZVKNHB
        | bit::RV_ZVKG
        | bit::RV_ZVBC
        | bit::RV_ZVBB
        | bit::RV_ZVKB;
    if out & bit::RV_V == 0 {
        out &= !vector_only;
    }
    // Zvbb implies Zvkb.
    if out & bit::RV_ZVBB != 0 {
        out |= bit::RV_ZVKB;
    }
    // Zvknhb implies Zvknha.
    if out & bit::RV_ZVKNHB != 0 {
        out |= bit::RV_ZVKNHA;
    }
    out
}

/// Reads `vlenb`. Only called after RVV 1.0 has been detected.
pub(super) fn vlenb() -> usize {
    let v: usize;
    // SAFETY: the caller verified RVV 1.0 support; reading the read-only
    // `vlenb` CSR has no side effects and accesses no memory.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v",
            "csrr {0}, vlenb",
            ".option pop",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}
