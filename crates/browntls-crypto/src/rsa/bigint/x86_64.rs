//! x86-64 Montgomery multiplication step using BMI2 `mulx` and ADX
//! `adcx`/`adox`.
//!
//! The kernel performs the same CIOS step as [`super::soft::step`]: it adds
//! `a * b_i` to the accumulator window and then adds `m * (w[0] * m0inv)`.
//! Each row uses two independent carry chains (CF for the running sum, OF for
//! the high halves of the products), four limbs per iteration with a one-limb
//! tail, so any `len >= 1` is supported.
//!
//! Constant time: the instruction sequence depends only on `len`.
#![allow(unsafe_code)]

use core::arch::asm;

/// Proof that the running CPU supports BMI2 and ADX; the only way to reach
/// the assembly kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MulxAdx(());

impl MulxAdx {
    /// Returns a token when `features()` reports BMI2 and ADX.
    pub(crate) fn detect() -> Option<Self> {
        let f = crate::cpu::features();
        (f.x86_bmi2() && f.x86_adx()).then_some(Self(()))
    }

    /// Runs the accelerated CIOS step (see [`step`]).
    #[inline]
    pub(crate) fn step(self, w: &mut [u64], a: &[u64], bi: u64, m: &[u64], m0inv: u64) {
        // SAFETY: a `MulxAdx` token exists only when `detect` observed BMI2
        // and ADX support, which is exactly the target-feature requirement of
        // `step`; all other preconditions are checked by `step` itself.
        unsafe { step(w, a, bi, m, m0inv) }
    }
}

/// `w[0..len] += a[0..len] * b_i; w[0..len] += m * (w[0] * m0inv)` with carry
/// propagation into `w[len]` and `w[len + 1]`.
///
/// Callers must have confirmed that the CPU supports BMI2 and ADX (see
/// [`crate::cpu::Features::x86_bmi2`] and [`crate::cpu::Features::x86_adx`]);
/// calling this function otherwise is undefined behaviour, which is why it is
/// only reachable through a [`MulxAdx`] token.
///
/// # Panics
///
/// Panics if `len == 0`, `m.len() != len` or `w.len() != len + 2`
/// (programming errors; lengths come from the public modulus size).
#[target_feature(enable = "bmi2,adx")]
fn step(w: &mut [u64], a: &[u64], bi: u64, m: &[u64], m0inv: u64) {
    let len = a.len();
    assert!(len >= 1 && m.len() == len && w.len() == len + 2);

    // SAFETY: the caller guarantees BMI2 and ADX are available (enforced by
    // the dispatcher), and the assertion above guarantees every memory access
    // stays inside the slices: each row reads `a[0..len]` (or `m[0..len]`) and
    // reads/writes `w[0..len]`, after which the epilogue touches `w[len]` and
    // `w[len + 1]`. `rbx` is saved and restored manually because it cannot be
    // named as an operand; the block uses `call`/`ret` and `push`/`pop`, so it
    // does not use the `nostack` option and leaves the stack pointer as found.
    unsafe {
        asm!(
            "push rbx",
            // Row 1: w[0..len] += a[0..len] * bi (rdx holds bi).
            "mov r10, r8",
            "call 20f",
            "add qword ptr [r11], rbx",
            "mov r15d, 0",
            "adc r15, 0",
            "mov qword ptr [r11 + 8], r15",
            // Row 2: mm = w[0] * m0inv; w[0..len] += m[0..len] * mm.
            "mov rdx, qword ptr [rdi]",
            "imul rdx, rsi",
            "mov r10, r9",
            "call 20f",
            "add qword ptr [r11], rbx",
            "adc qword ptr [r11 + 8], 0",
            "pop rbx",
            "jmp 30f",
            // Row routine. In: rdx = multiplier, r10 = operand pointer,
            // rdi = window base, rcx = len. Out: rbx = carry word, r11 = window
            // base + 8 * len. Clobbers rax, r12, r13, r14.
            "20:",
            "mov r11, rdi",
            "mov r12, rcx",
            "xor r14d, r14d",
            "xor ebx, ebx",
            "cmp r12, 4",
            "jb 22f",
            // Four limbs per iteration; CF and OF are both clear on entry.
            "21:",
            "mulx r13, rax, qword ptr [r10]",
            "adcx rax, qword ptr [r11]",
            "adox rax, rbx",
            "mov qword ptr [r11], rax",
            "mulx rbx, rax, qword ptr [r10 + 8]",
            "adcx rax, qword ptr [r11 + 8]",
            "adox rax, r13",
            "mov qword ptr [r11 + 8], rax",
            "mulx r13, rax, qword ptr [r10 + 16]",
            "adcx rax, qword ptr [r11 + 16]",
            "adox rax, rbx",
            "mov qword ptr [r11 + 16], rax",
            "mulx rbx, rax, qword ptr [r10 + 24]",
            "adcx rax, qword ptr [r11 + 24]",
            "adox rax, r13",
            "mov qword ptr [r11 + 24], rax",
            // Fold both carry flags into the carry word (cannot overflow:
            // the partial sum fits in len + 1 limbs), clearing CF and OF.
            "adcx rbx, r14",
            "adox rbx, r14",
            "lea r10, [r10 + 32]",
            "lea r11, [r11 + 32]",
            "sub r12, 4",
            "cmp r12, 4",
            "jae 21b",
            "22:",
            "test r12, r12",
            "jz 24f",
            // One limb per iteration for the tail.
            "23:",
            "mulx r13, rax, qword ptr [r10]",
            "adcx rax, qword ptr [r11]",
            "adox rax, rbx",
            "mov qword ptr [r11], rax",
            "mov rbx, r13",
            "adcx rbx, r14",
            "adox rbx, r14",
            "lea r10, [r10 + 8]",
            "lea r11, [r11 + 8]",
            "dec r12",
            "jnz 23b",
            "24:",
            "ret",
            "30:",
            in("rdi") w.as_mut_ptr(),
            in("rsi") m0inv,
            in("rcx") len,
            in("r8") a.as_ptr(),
            in("r9") m.as_ptr(),
            inout("rdx") bi => _,
            out("rax") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
        );
    }
}
