//! BMI2/ADX kernels for the full-width products of P-384 and P-521 (x86-64);
//! the curve backends built on them are `p384_x86` and `p521_x86`.
//!
//! [`mul6`]/[`mul9`] are row-wise schoolbook multiplications: every row adds
//! `a * b[i]` to a window of registers with `mulx` and two independent carry
//! chains (`adcx` on the carry flag for the low halves, `adox` on the
//! overflow flag for the high halves), stores the limb that became final and
//! rotates the window by one register. [`sqr6`]/[`sqr9`] compute the cross
//! products `a[i] * a[j]`, `i < j`, once, then double them on one flag chain
//! while adding the squares `a[i]^2` on the other.
//!
//! The reductions are the portable ones (`p384_field::reduce`,
//! `p521_field::reduce`), so the two backends of a curve differ only in how
//! the product is formed.
//!
//! Every kernel is one straight-line instruction sequence: no branch, no
//! data-dependent address and no instruction with operand-dependent timing
//! (`mulx`, `adcx`, `adox`, `add`, `adc`, `mov`, `xor`, `push`). Only entered
//! when [`available`] is true.
#![allow(unsafe_code)]

use core::arch::asm;

/// Whether the CPU has BMI2 and ADX.
#[inline]
pub(crate) fn available() -> bool {
    let f = crate::cpu::features();
    f.x86_bmi2() && f.x86_adx()
}

/// `($lo, $hi) += a[$off / 8] * rdx`: the low half joins the carry-flag
/// chain into `$lo`, the high half the overflow-flag chain into `$hi`.
/// `rsi` points to `a`; clobbers `rax` and `rcx`.
macro_rules! mac {
    ($off:literal, $lo:literal, $hi:literal) => {
        concat!(
            "mulx rcx, rax, qword ptr [rsi + ",
            $off,
            "]\n",
            "adcx ",
            $lo,
            ", rax\n",
            "adox ",
            $hi,
            ", rcx\n",
        )
    };
}

/// The last product of a row: as [`mac`], but the high half starts the new
/// top limb `$top`, which also absorbs the final carry of both chains (it
/// cannot overflow: the row sum fits the window plus one limb). `mov` leaves
/// the flags alone, so `rax` serves as the zero for both chains.
macro_rules! mac_top {
    ($off:literal, $lo:literal, $top:literal) => {
        concat!(
            "mulx ",
            $top,
            ", rax, qword ptr [rsi + ",
            $off,
            "]\n",
            "adcx ",
            $lo,
            ", rax\n",
            "mov eax, 0\n",
            "adox ",
            $top,
            ", rax\n",
            "adcx ",
            $top,
            ", rax\n",
        )
    };
}

/// `[$mem] = 2 * [$mem] + $add` across the two flag chains (doubling on the
/// carry flag, the addition on the overflow flag); clobbers `r9`.
macro_rules! dbl {
    ($mem:literal, $add:literal) => {
        concat!(
            "mov r9, qword ptr [",
            $mem,
            "]\n",
            "adcx r9, r9\n",
            "adox r9, ",
            $add,
            "\n",
            "mov qword ptr [",
            $mem,
            "], r9\n",
        )
    };
}

/// `a * b` for six-limb operands.
#[inline]
pub(crate) fn mul6(a: &[u64; 6], b: &[u64; 6]) -> [u64; 12] {
    let mut out = [0u64; 12];
    // SAFETY: only reachable through `P384Adx`, which is selected after
    // `available()` reported BMI2 and ADX. The asm reads the 48 bytes behind
    // each of `a` and `b` and writes the 96 bytes of `out` (all valid, and
    // `out` is a distinct local); it does not touch the stack and declares
    // every register it clobbers.
    unsafe {
        asm!(
            // Row 0: t[0..7] = a * b[0].
            "mov rdx, qword ptr [rdi]",
            "mulx r9, r8, qword ptr [rsi]",
            "mov qword ptr [r14], r8",
            "mulx r10, rax, qword ptr [rsi + 8]",
            "add r9, rax",
            "mulx r11, rax, qword ptr [rsi + 16]",
            "adc r10, rax",
            "mulx r12, rax, qword ptr [rsi + 24]",
            "adc r11, rax",
            "mulx r13, rax, qword ptr [rsi + 32]",
            "adc r12, rax",
            "mulx r8, rax, qword ptr [rsi + 40]",
            "adc r13, rax",
            "adc r8, 0",
            // Row 1: t[1..8] += a * b[1].
            "mov rdx, qword ptr [rdi + 8]",
            "xor eax, eax",
            mac!("0", "r9", "r10"),
            "mov qword ptr [r14 + 8], r9",
            mac!("8", "r10", "r11"),
            mac!("16", "r11", "r12"),
            mac!("24", "r12", "r13"),
            mac!("32", "r13", "r8"),
            mac_top!("40", "r8", "r9"),
            // Row 2: t[2..9] += a * b[2].
            "mov rdx, qword ptr [rdi + 16]",
            "xor eax, eax",
            mac!("0", "r10", "r11"),
            "mov qword ptr [r14 + 16], r10",
            mac!("8", "r11", "r12"),
            mac!("16", "r12", "r13"),
            mac!("24", "r13", "r8"),
            mac!("32", "r8", "r9"),
            mac_top!("40", "r9", "r10"),
            // Row 3: t[3..10] += a * b[3].
            "mov rdx, qword ptr [rdi + 24]",
            "xor eax, eax",
            mac!("0", "r11", "r12"),
            "mov qword ptr [r14 + 24], r11",
            mac!("8", "r12", "r13"),
            mac!("16", "r13", "r8"),
            mac!("24", "r8", "r9"),
            mac!("32", "r9", "r10"),
            mac_top!("40", "r10", "r11"),
            // Row 4: t[4..11] += a * b[4].
            "mov rdx, qword ptr [rdi + 32]",
            "xor eax, eax",
            mac!("0", "r12", "r13"),
            "mov qword ptr [r14 + 32], r12",
            mac!("8", "r13", "r8"),
            mac!("16", "r8", "r9"),
            mac!("24", "r9", "r10"),
            mac!("32", "r10", "r11"),
            mac_top!("40", "r11", "r12"),
            // Row 5: t[5..12] += a * b[5].
            "mov rdx, qword ptr [rdi + 40]",
            "xor eax, eax",
            mac!("0", "r13", "r8"),
            "mov qword ptr [r14 + 40], r13",
            mac!("8", "r8", "r9"),
            mac!("16", "r9", "r10"),
            mac!("24", "r10", "r11"),
            mac!("32", "r11", "r12"),
            mac_top!("40", "r12", "r13"),
            // The window holds t[6..12].
            "mov qword ptr [r14 + 48], r8",
            "mov qword ptr [r14 + 56], r9",
            "mov qword ptr [r14 + 64], r10",
            "mov qword ptr [r14 + 72], r11",
            "mov qword ptr [r14 + 80], r12",
            "mov qword ptr [r14 + 88], r13",
            in("rsi") a.as_ptr(),
            in("rdi") b.as_ptr(),
            in("r14") out.as_mut_ptr(),
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            options(nostack),
        );
    }
    out
}

/// `a^2` for a six-limb operand.
#[inline]
pub(crate) fn sqr6(a: &[u64; 6]) -> [u64; 12] {
    let mut out = [0u64; 12];
    // SAFETY: as for `mul6`: BMI2/ADX are present, the asm reads the 48
    // bytes behind `a`, writes (and re-reads) the 96 bytes of `out`, does not
    // touch the stack and declares every clobbered register.
    unsafe {
        asm!(
            // Cross products a[i] * a[j], i < j, into c[1..11]; limb k lives in
            // register k mod 6 until it is final and stored.
            // Row 0: a[0] * a[1..6].
            "mov rdx, qword ptr [rsi]",
            "mulx r10, r9, qword ptr [rsi + 8]",
            "mulx r11, rax, qword ptr [rsi + 16]",
            "add r10, rax",
            "mulx r12, rax, qword ptr [rsi + 24]",
            "adc r11, rax",
            "mulx r13, rax, qword ptr [rsi + 32]",
            "adc r12, rax",
            "mulx r8, rax, qword ptr [rsi + 40]",
            "adc r13, rax",
            "adc r8, 0",
            "mov qword ptr [rdi + 8], r9",
            "mov qword ptr [rdi + 16], r10",
            // Row 1: a[1] * a[2..6].
            "mov rdx, qword ptr [rsi + 8]",
            "xor eax, eax",
            mac!("16", "r11", "r12"),
            mac!("24", "r12", "r13"),
            mac!("32", "r13", "r8"),
            mac_top!("40", "r8", "r9"),
            "mov qword ptr [rdi + 24], r11",
            "mov qword ptr [rdi + 32], r12",
            // Row 2: a[2] * a[3..6].
            "mov rdx, qword ptr [rsi + 16]",
            "xor eax, eax",
            mac!("24", "r13", "r8"),
            mac!("32", "r8", "r9"),
            mac_top!("40", "r9", "r10"),
            "mov qword ptr [rdi + 40], r13",
            "mov qword ptr [rdi + 48], r8",
            // Row 3: a[3] * a[4..6].
            "mov rdx, qword ptr [rsi + 24]",
            "xor eax, eax",
            mac!("32", "r9", "r10"),
            mac_top!("40", "r10", "r11"),
            "mov qword ptr [rdi + 56], r9",
            "mov qword ptr [rdi + 64], r10",
            // Row 4: a[4] * a[5..6].
            "mov rdx, qword ptr [rsi + 32]",
            "xor eax, eax",
            mac_top!("40", "r11", "r12"),
            "mov qword ptr [rdi + 72], r11",
            "mov qword ptr [rdi + 80], r12",
            // out = 2 c + sum a[i]^2 2^(128 i): the carry flag chain doubles c
            // while the overflow flag chain adds the squares.
            "xor eax, eax",
            "mov rdx, qword ptr [rsi]",
            "mulx rcx, rax, rdx",
            "mov qword ptr [rdi], rax",
            dbl!("rdi + 8", "rcx"),
            "mov rdx, qword ptr [rsi + 8]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 16", "rax"),
            dbl!("rdi + 24", "rcx"),
            "mov rdx, qword ptr [rsi + 16]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 32", "rax"),
            dbl!("rdi + 40", "rcx"),
            "mov rdx, qword ptr [rsi + 24]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 48", "rax"),
            dbl!("rdi + 56", "rcx"),
            "mov rdx, qword ptr [rsi + 32]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 64", "rax"),
            dbl!("rdi + 72", "rcx"),
            "mov rdx, qword ptr [rsi + 40]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 80", "rax"),
            // c[11] = 0.
            "mov r9d, 0",
            "adcx r9, r9",
            "adox r9, rcx",
            "mov qword ptr [rdi + 88], r9",
            in("rsi") a.as_ptr(),
            in("rdi") out.as_mut_ptr(),
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            options(nostack),
        );
    }
    out
}

/// `a * b` for nine-limb operands.
#[inline]
pub(crate) fn mul9(a: &[u64; 9], b: &[u64; 9]) -> [u64; 18] {
    let mut out = [0u64; 18];
    // SAFETY: only reachable through `P521Adx`, which is selected after
    // `available()` reported BMI2 and ADX. The asm reads the 72 bytes behind
    // each of `a` and `b` and writes the 144 bytes of `out` (all valid, and
    // `out` is a distinct local). The nine-limb window needs the registers
    // of `b` and `out`, so both pointers are pushed first and reloaded from
    // `[rsp]` / `[rsp + 8]`; the two words are released before the block
    // ends, and the block is not `nostack`, so the compiler keeps the red
    // zone clear. Every clobbered register is declared.
    unsafe {
        asm!(
            // Save `out` and `b`; their registers join the window.
            "push rdx",
            "push rdi",
            // Row 0: t[0..10] = a * b[0].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax]",
            "mulx r9, r8, qword ptr [rsi]",
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax], r8",
            "mulx r10, rax, qword ptr [rsi + 8]",
            "add r9, rax",
            "mulx r11, rax, qword ptr [rsi + 16]",
            "adc r10, rax",
            "mulx r12, rax, qword ptr [rsi + 24]",
            "adc r11, rax",
            "mulx r13, rax, qword ptr [rsi + 32]",
            "adc r12, rax",
            "mulx r14, rax, qword ptr [rsi + 40]",
            "adc r13, rax",
            "mulx r15, rax, qword ptr [rsi + 48]",
            "adc r14, rax",
            "mulx rdi, rax, qword ptr [rsi + 56]",
            "adc r15, rax",
            "mulx r8, rax, qword ptr [rsi + 64]",
            "adc rdi, rax",
            "adc r8, 0",
            // Row 1: t[1..11] += a * b[1].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax + 8]",
            "xor eax, eax",
            mac!("0", "r9", "r10"),
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 8], r9",
            mac!("8", "r10", "r11"),
            mac!("16", "r11", "r12"),
            mac!("24", "r12", "r13"),
            mac!("32", "r13", "r14"),
            mac!("40", "r14", "r15"),
            mac!("48", "r15", "rdi"),
            mac!("56", "rdi", "r8"),
            mac_top!("64", "r8", "r9"),
            // Row 2: t[2..12] += a * b[2].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax + 16]",
            "xor eax, eax",
            mac!("0", "r10", "r11"),
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 16], r10",
            mac!("8", "r11", "r12"),
            mac!("16", "r12", "r13"),
            mac!("24", "r13", "r14"),
            mac!("32", "r14", "r15"),
            mac!("40", "r15", "rdi"),
            mac!("48", "rdi", "r8"),
            mac!("56", "r8", "r9"),
            mac_top!("64", "r9", "r10"),
            // Row 3: t[3..13] += a * b[3].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax + 24]",
            "xor eax, eax",
            mac!("0", "r11", "r12"),
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 24], r11",
            mac!("8", "r12", "r13"),
            mac!("16", "r13", "r14"),
            mac!("24", "r14", "r15"),
            mac!("32", "r15", "rdi"),
            mac!("40", "rdi", "r8"),
            mac!("48", "r8", "r9"),
            mac!("56", "r9", "r10"),
            mac_top!("64", "r10", "r11"),
            // Row 4: t[4..14] += a * b[4].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax + 32]",
            "xor eax, eax",
            mac!("0", "r12", "r13"),
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 32], r12",
            mac!("8", "r13", "r14"),
            mac!("16", "r14", "r15"),
            mac!("24", "r15", "rdi"),
            mac!("32", "rdi", "r8"),
            mac!("40", "r8", "r9"),
            mac!("48", "r9", "r10"),
            mac!("56", "r10", "r11"),
            mac_top!("64", "r11", "r12"),
            // Row 5: t[5..15] += a * b[5].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax + 40]",
            "xor eax, eax",
            mac!("0", "r13", "r14"),
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 40], r13",
            mac!("8", "r14", "r15"),
            mac!("16", "r15", "rdi"),
            mac!("24", "rdi", "r8"),
            mac!("32", "r8", "r9"),
            mac!("40", "r9", "r10"),
            mac!("48", "r10", "r11"),
            mac!("56", "r11", "r12"),
            mac_top!("64", "r12", "r13"),
            // Row 6: t[6..16] += a * b[6].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax + 48]",
            "xor eax, eax",
            mac!("0", "r14", "r15"),
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 48], r14",
            mac!("8", "r15", "rdi"),
            mac!("16", "rdi", "r8"),
            mac!("24", "r8", "r9"),
            mac!("32", "r9", "r10"),
            mac!("40", "r10", "r11"),
            mac!("48", "r11", "r12"),
            mac!("56", "r12", "r13"),
            mac_top!("64", "r13", "r14"),
            // Row 7: t[7..17] += a * b[7].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax + 56]",
            "xor eax, eax",
            mac!("0", "r15", "rdi"),
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 56], r15",
            mac!("8", "rdi", "r8"),
            mac!("16", "r8", "r9"),
            mac!("24", "r9", "r10"),
            mac!("32", "r10", "r11"),
            mac!("40", "r11", "r12"),
            mac!("48", "r12", "r13"),
            mac!("56", "r13", "r14"),
            mac_top!("64", "r14", "r15"),
            // Row 8: t[8..18] += a * b[8].
            "mov rax, qword ptr [rsp]",
            "mov rdx, qword ptr [rax + 64]",
            "xor eax, eax",
            mac!("0", "rdi", "r8"),
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 64], rdi",
            mac!("8", "r8", "r9"),
            mac!("16", "r9", "r10"),
            mac!("24", "r10", "r11"),
            mac!("32", "r11", "r12"),
            mac!("40", "r12", "r13"),
            mac!("48", "r13", "r14"),
            mac!("56", "r14", "r15"),
            mac_top!("64", "r15", "rdi"),
            // The window holds t[9..18].
            "mov rax, qword ptr [rsp + 8]",
            "mov qword ptr [rax + 72], r8",
            "mov qword ptr [rax + 80], r9",
            "mov qword ptr [rax + 88], r10",
            "mov qword ptr [rax + 96], r11",
            "mov qword ptr [rax + 104], r12",
            "mov qword ptr [rax + 112], r13",
            "mov qword ptr [rax + 120], r14",
            "mov qword ptr [rax + 128], r15",
            "mov qword ptr [rax + 136], rdi",
            "add rsp, 16",
            in("rsi") a.as_ptr(),
            inout("rdi") b.as_ptr() => _,
            inout("rdx") out.as_mut_ptr() => _,
            out("rax") _,
            out("rcx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
        );
    }
    out
}

/// `a^2` for a nine-limb operand.
#[inline]
pub(crate) fn sqr9(a: &[u64; 9]) -> [u64; 18] {
    let mut out = [0u64; 18];
    // SAFETY: as for `mul9`: BMI2/ADX are present, the asm reads the 72
    // bytes behind `a` and writes (and re-reads) the 144 bytes of `out`. The
    // `out` pointer is pushed while its register is part of the window and
    // the word is released before the block ends (the block is not
    // `nostack`). Every clobbered register is declared.
    unsafe {
        asm!(
            // Save `out`; its register joins the window.
            "push rdi",
            // Cross products a[i] * a[j], i < j, into c[1..17]; limb k lives in
            // register k mod 9 until it is final and stored.
            // Row 0: a[0] * a[1..9].
            "mov rdx, qword ptr [rsi]",
            "mulx r10, r9, qword ptr [rsi + 8]",
            "mulx r11, rax, qword ptr [rsi + 16]",
            "add r10, rax",
            "mulx r12, rax, qword ptr [rsi + 24]",
            "adc r11, rax",
            "mulx r13, rax, qword ptr [rsi + 32]",
            "adc r12, rax",
            "mulx r14, rax, qword ptr [rsi + 40]",
            "adc r13, rax",
            "mulx r15, rax, qword ptr [rsi + 48]",
            "adc r14, rax",
            "mulx rdi, rax, qword ptr [rsi + 56]",
            "adc r15, rax",
            "mulx r8, rax, qword ptr [rsi + 64]",
            "adc rdi, rax",
            "adc r8, 0",
            "mov rax, qword ptr [rsp]",
            "mov qword ptr [rax + 8], r9",
            "mov qword ptr [rax + 16], r10",
            // Row 1: a[1] * a[2..9].
            "mov rdx, qword ptr [rsi + 8]",
            "xor eax, eax",
            mac!("16", "r11", "r12"),
            mac!("24", "r12", "r13"),
            mac!("32", "r13", "r14"),
            mac!("40", "r14", "r15"),
            mac!("48", "r15", "rdi"),
            mac!("56", "rdi", "r8"),
            mac_top!("64", "r8", "r9"),
            "mov rax, qword ptr [rsp]",
            "mov qword ptr [rax + 24], r11",
            "mov qword ptr [rax + 32], r12",
            // Row 2: a[2] * a[3..9].
            "mov rdx, qword ptr [rsi + 16]",
            "xor eax, eax",
            mac!("24", "r13", "r14"),
            mac!("32", "r14", "r15"),
            mac!("40", "r15", "rdi"),
            mac!("48", "rdi", "r8"),
            mac!("56", "r8", "r9"),
            mac_top!("64", "r9", "r10"),
            "mov rax, qword ptr [rsp]",
            "mov qword ptr [rax + 40], r13",
            "mov qword ptr [rax + 48], r14",
            // Row 3: a[3] * a[4..9].
            "mov rdx, qword ptr [rsi + 24]",
            "xor eax, eax",
            mac!("32", "r15", "rdi"),
            mac!("40", "rdi", "r8"),
            mac!("48", "r8", "r9"),
            mac!("56", "r9", "r10"),
            mac_top!("64", "r10", "r11"),
            "mov rax, qword ptr [rsp]",
            "mov qword ptr [rax + 56], r15",
            "mov qword ptr [rax + 64], rdi",
            // Row 4: a[4] * a[5..9].
            "mov rdx, qword ptr [rsi + 32]",
            "xor eax, eax",
            mac!("40", "r8", "r9"),
            mac!("48", "r9", "r10"),
            mac!("56", "r10", "r11"),
            mac_top!("64", "r11", "r12"),
            "mov rax, qword ptr [rsp]",
            "mov qword ptr [rax + 72], r8",
            "mov qword ptr [rax + 80], r9",
            // Row 5: a[5] * a[6..9].
            "mov rdx, qword ptr [rsi + 40]",
            "xor eax, eax",
            mac!("48", "r10", "r11"),
            mac!("56", "r11", "r12"),
            mac_top!("64", "r12", "r13"),
            "mov rax, qword ptr [rsp]",
            "mov qword ptr [rax + 88], r10",
            "mov qword ptr [rax + 96], r11",
            // Row 6: a[6] * a[7..9].
            "mov rdx, qword ptr [rsi + 48]",
            "xor eax, eax",
            mac!("56", "r12", "r13"),
            mac_top!("64", "r13", "r14"),
            "mov rax, qword ptr [rsp]",
            "mov qword ptr [rax + 104], r12",
            "mov qword ptr [rax + 112], r13",
            // Row 7: a[7] * a[8..9].
            "mov rdx, qword ptr [rsi + 56]",
            "xor eax, eax",
            mac_top!("64", "r14", "r15"),
            "mov rax, qword ptr [rsp]",
            "mov qword ptr [rax + 120], r14",
            "mov qword ptr [rax + 128], r15",
            // out = 2 c + sum a[i]^2 2^(128 i): the carry flag chain doubles c
            // while the overflow flag chain adds the squares.
            "mov rdi, qword ptr [rsp]",
            "xor eax, eax",
            "mov rdx, qword ptr [rsi]",
            "mulx rcx, rax, rdx",
            "mov qword ptr [rdi], rax",
            dbl!("rdi + 8", "rcx"),
            "mov rdx, qword ptr [rsi + 8]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 16", "rax"),
            dbl!("rdi + 24", "rcx"),
            "mov rdx, qword ptr [rsi + 16]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 32", "rax"),
            dbl!("rdi + 40", "rcx"),
            "mov rdx, qword ptr [rsi + 24]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 48", "rax"),
            dbl!("rdi + 56", "rcx"),
            "mov rdx, qword ptr [rsi + 32]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 64", "rax"),
            dbl!("rdi + 72", "rcx"),
            "mov rdx, qword ptr [rsi + 40]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 80", "rax"),
            dbl!("rdi + 88", "rcx"),
            "mov rdx, qword ptr [rsi + 48]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 96", "rax"),
            dbl!("rdi + 104", "rcx"),
            "mov rdx, qword ptr [rsi + 56]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 112", "rax"),
            dbl!("rdi + 120", "rcx"),
            "mov rdx, qword ptr [rsi + 64]",
            "mulx rcx, rax, rdx",
            dbl!("rdi + 128", "rax"),
            // c[17] = 0.
            "mov r9d, 0",
            "adcx r9, r9",
            "adox r9, rcx",
            "mov qword ptr [rdi + 136], r9",
            "add rsp, 8",
            in("rsi") a.as_ptr(),
            inout("rdi") out.as_mut_ptr() => _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::wide;
    use super::*;

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    /// Operands that stress the carry chains (all-ones and single-limb
    /// patterns, every limb position) followed by random values.
    fn operands<const N: usize>() -> std::vec::Vec<[u64; N]> {
        let mut v = std::vec![[0u64; N], [u64::MAX; N], [1u64; N], [1 << 63; N]];
        for i in 0..N {
            for x in [1, u64::MAX, 1 << 63] {
                let mut a = [0u64; N];
                a[i] = x;
                v.push(a);
                let mut a = [u64::MAX; N];
                a[i] = !x;
                v.push(a);
            }
        }
        let mut seed = 0xa409_3822_299f_31d0u64;
        for _ in 0..120 {
            v.push(core::array::from_fn(|_| xorshift(&mut seed)));
        }
        // Sparse values: random limbs forced to 0 or all ones.
        for _ in 0..120 {
            v.push(core::array::from_fn(|_| match xorshift(&mut seed) % 4 {
                0 => 0,
                1 => u64::MAX,
                _ => xorshift(&mut seed),
            }));
        }
        v
    }

    #[test]
    fn kernels_match_portable_products() {
        if !available() {
            return;
        }
        let v6 = operands::<6>();
        for a in &v6 {
            assert_eq!(sqr6(a), wide::mul::<6, 12>(a, a), "a = {a:x?}");
            for b in &v6 {
                assert_eq!(
                    mul6(a, b),
                    wide::mul::<6, 12>(a, b),
                    "a = {a:x?} b = {b:x?}"
                );
            }
        }
        let v9 = operands::<9>();
        for a in &v9 {
            assert_eq!(sqr9(a), wide::mul::<9, 18>(a, a), "a = {a:x?}");
            for b in &v9 {
                assert_eq!(
                    mul9(a, b),
                    wide::mul::<9, 18>(a, b),
                    "a = {a:x?} b = {b:x?}"
                );
            }
        }
    }
}
