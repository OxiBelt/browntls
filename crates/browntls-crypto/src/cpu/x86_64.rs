//! x86-64 feature detection via `CPUID` / `XGETBV`.
#![allow(unsafe_code)]

use core::arch::x86_64::{__cpuid_count, CpuidResult};

use super::bit;

#[inline]
fn cpuid(leaf: u32, sub_leaf: u32) -> CpuidResult {
    __cpuid_count(leaf, sub_leaf)
}

/// Reads XCR0. Must only be called when CPUID reports OSXSAVE.
#[inline]
fn xgetbv0() -> u64 {
    let eax: u32;
    let edx: u32;
    // SAFETY: the caller checked CPUID.1:ECX.OSXSAVE[bit 27], which guarantees
    // that XGETBV is supported and enabled by the operating system. The
    // instruction only reads XCR0 into EDX:EAX and touches no memory.
    unsafe {
        core::arch::asm!(
            "xgetbv",
            in("ecx") 0u32,
            out("eax") eax,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    (u64::from(edx) << 32) | u64::from(eax)
}

const fn has(reg: u32, b: u32) -> bool {
    reg & (1 << b) != 0
}

pub(super) fn detect() -> u64 {
    let max_leaf = cpuid(0, 0).eax;
    if max_leaf < 1 {
        return 0;
    }
    let l1 = cpuid(1, 0);
    let (l7, l7_1) = if max_leaf >= 7 {
        let l7 = cpuid(7, 0);
        let l7_1 = if l7.eax >= 1 {
            cpuid(7, 1)
        } else {
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        };
        (l7, l7_1)
    } else {
        let zero = CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
        (zero, zero)
    };
    let max_ext = cpuid(0x8000_0000, 0).eax;
    let ext1 = if max_ext >= 0x8000_0001 {
        cpuid(0x8000_0001, 0).ecx
    } else {
        0
    };

    let osxsave = has(l1.ecx, 27);
    let xcr0 = if osxsave { xgetbv0() } else { 0 };
    // XMM (bit 1) and YMM (bit 2) state enabled by the OS.
    let os_ymm = xcr0 & 0b110 == 0b110;
    // Opmask (5), ZMM_Hi256 (6) and Hi16_ZMM (7) in addition to YMM.
    let os_zmm = os_ymm && xcr0 & 0b1110_0000 == 0b1110_0000;

    let mut out = 0u64;
    let mut set = |cond: bool, b: u64| {
        if cond {
            out |= b;
        }
    };

    let sse2 = has(l1.edx, 26);
    let ssse3 = sse2 && has(l1.ecx, 9);
    let sse41 = ssse3 && has(l1.ecx, 19);
    let avx = os_ymm && has(l1.ecx, 28) && sse41;
    let avx2 = avx && has(l7.ebx, 5);
    let bmi1 = has(l7.ebx, 3);
    let bmi2 = has(l7.ebx, 8);
    let fma = has(l1.ecx, 12);
    let movbe = has(l1.ecx, 22);
    let f16c = has(l1.ecx, 29);
    let lzcnt = has(ext1, 5);

    set(ssse3, bit::X86_SSSE3);
    set(sse41, bit::X86_SSE41);
    set(avx, bit::X86_AVX);
    set(avx2, bit::X86_AVX2);
    set(bmi2, bit::X86_BMI2);
    set(
        avx2 && bmi1 && bmi2 && fma && movbe && f16c && lzcnt,
        bit::X86_V3,
    );
    set(sse2 && has(l1.ecx, 25), bit::X86_AES);
    set(sse2 && has(l1.ecx, 1), bit::X86_PCLMULQDQ);
    set(sse41 && has(l7.ebx, 29), bit::X86_SHA);
    set(avx2 && has(l7_1.eax, 0), bit::X86_SHA512);
    set(avx2 && has(l7.ecx, 9), bit::X86_VAES);
    set(avx2 && has(l7.ecx, 10), bit::X86_VPCLMULQDQ);
    set(sse41 && has(l7.ecx, 8), bit::X86_GFNI);
    set(has(l7.ebx, 19), bit::X86_ADX);

    let avx512 = os_zmm
        && avx2
        && has(l7.ebx, 16) // F
        && has(l7.ebx, 17) // DQ
        && has(l7.ebx, 30) // BW
        && has(l7.ebx, 31); // VL
    set(avx512, bit::X86_AVX512);
    set(avx512 && has(l7.ebx, 21), bit::X86_AVX512_IFMA);
    set(avx512 && has(l7.ecx, 1), bit::X86_AVX512_VBMI);
    out
}
