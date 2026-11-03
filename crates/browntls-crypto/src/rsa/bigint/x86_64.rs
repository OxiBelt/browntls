//! x86-64 Montgomery multiplication step using BMI2 `mulx` and ADX
//! `adcx`/`adox`.
//!
//! The kernel performs the same CIOS step as [`super::soft::step`]: it adds
//! `a * b_i` to the accumulator window and then adds `m * (w[0] * m0inv)`.
//! Each row uses two independent carry chains (CF for the running sum, OF for
//! the high halves of the products), four limbs per iteration with a one-limb
//! tail, so any `len >= 1` is supported.
//!
//! [`MulxAdx::mont_mul4`] runs a whole multiplication in one block for
//! lengths that are a multiple of four, fusing the two rows of each step
//! into one sweep.
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

    /// Runs the whole fused CIOS multiplication (see [`mont_mul4`]); `len`
    /// must be a non-zero multiple of four.
    #[inline]
    pub(crate) fn mont_mul4(self, t: &mut [u64], a: &[u64], b: &[u64], m: &[u64], m0inv: u64) {
        // SAFETY: as for `step`: the token proves BMI2 and ADX support, and
        // `mont_mul4` checks every slice length itself.
        unsafe { mont_mul4(t, a, b, m, m0inv) }
    }
}

/// Full Montgomery multiplication `t[1 .. len + 2] = (a b + M m) / 2^(64 len)`
/// (CIOS with the two row passes of each limb of `b` fused into one sweep),
/// for `len = a.len()` a non-zero multiple of four.
///
/// `t` is `len + 2` limbs and must be zero on entry; on return `t[1..=len]`
/// holds the low limbs of the (below `2 m`) result and `t[len + 1]` its top
/// limb (0 or 1); `t[0]` is scratch. Each outer iteration adds `a b_i` and
/// `m mm` (with `mm = (t_0 + a_0 b_i) m0inv mod 2^64`) four limbs at a time:
/// the `a b_i` products are accumulated with CF (`adcx`, adding the old
/// accumulator) and OF (`adox`, adding the previous high half), then the
/// `m mm` products likewise, and the sum is stored one limb lower, which
/// divides by `2^64`. Each pending high half and both flags are folded into
/// one carry word per chunk; a chunk sum is below `2^320`, so the fold cannot
/// overflow.
///
/// Callers must have confirmed that the CPU supports BMI2 and ADX; calling
/// this function otherwise is undefined behaviour, which is why it is only
/// reachable through a [`MulxAdx`] token.
///
/// # Panics
///
/// Panics if `len` is zero or not a multiple of four, or if a slice length
/// differs from the above (programming errors; lengths are public).
#[target_feature(enable = "bmi2,adx")]
fn mont_mul4(t: &mut [u64], a: &[u64], b: &[u64], m: &[u64], m0inv: u64) {
    let len = a.len();
    assert!(len >= 4 && len.is_multiple_of(4));
    assert!(b.len() == len && m.len() == len && t.len() == len + 2);

    // SAFETY: the caller guarantees BMI2 and ADX are available (enforced by
    // the token). With `tp = t + 1`, the block reads `a[0..len]`,
    // `m[0..len]` and `b[0..len]` and reads/writes `tp[-1..=len]`, i.e.
    // `t[0..len + 2]`, all inside the slices by the assertions above.
    // `rbx` and `rbp` cannot be named as operands, so they are saved and
    // restored manually; three further stack slots hold `len`, the outer
    // counter and `m0inv`. The pushes are balanced, so the stack pointer is
    // restored, and the block does not use the `nostack` option.
    unsafe {
        asm!(
            "push rbx",
            "push rbp",
            "push rcx", // [rsp + 16]: len
            "push rcx", // [rsp + 8]: outer counter
            "push rdx", // [rsp]: m0inv
            // Outer loop over the limbs of b (r9 points at b_i).
            "2:",
            "mov rdx, qword ptr [r9]",
            "mulx rax, rbx, qword ptr [rsi]",
            "add rbx, qword ptr [rdi]",
            "imul rbx, qword ptr [rsp]",
            "mov rbp, rbx", // mm
            "xor r14d, r14d", // pending high half of a b_i
            "xor r15d, r15d", // pending high half of m mm
            "xor ecx, ecx",
            // Chunk loop: four limbs per iteration.
            "3:",
            "mov rdx, qword ptr [r9]",
            "xor eax, eax", // CF = OF = 0
            "mulx rax, r10, qword ptr [rsi + 8*rcx]",
            "adcx r10, qword ptr [rdi + 8*rcx]",
            "adox r10, r14",
            "mulx r14, r11, qword ptr [rsi + 8*rcx + 8]",
            "adcx r11, qword ptr [rdi + 8*rcx + 8]",
            "adox r11, rax",
            "mulx rax, r12, qword ptr [rsi + 8*rcx + 16]",
            "adcx r12, qword ptr [rdi + 8*rcx + 16]",
            "adox r12, r14",
            "mulx r14, r13, qword ptr [rsi + 8*rcx + 24]",
            "adcx r13, qword ptr [rdi + 8*rcx + 24]",
            "adox r13, rax",
            "mov eax, 0",
            "adcx r14, rax",
            "adox r14, rax", // CF = OF = 0 again
            "mov rdx, rbp",
            "mulx rbx, rax, qword ptr [r8 + 8*rcx]",
            "adcx r10, rax",
            "adox r10, r15",
            "mulx r15, rax, qword ptr [r8 + 8*rcx + 8]",
            "adcx r11, rax",
            "adox r11, rbx",
            "mulx rbx, rax, qword ptr [r8 + 8*rcx + 16]",
            "adcx r12, rax",
            "adox r12, r15",
            "mulx r15, rax, qword ptr [r8 + 8*rcx + 24]",
            "adcx r13, rax",
            "adox r13, rbx",
            "mov eax, 0",
            "adcx r15, rax",
            "adox r15, rax",
            // Store one limb lower (the lowest limb of the first chunk is
            // zero by the choice of mm and lands in the scratch limb t[0]).
            "mov qword ptr [rdi + 8*rcx - 8], r10",
            "mov qword ptr [rdi + 8*rcx], r11",
            "mov qword ptr [rdi + 8*rcx + 8], r12",
            "mov qword ptr [rdi + 8*rcx + 16], r13",
            "add rcx, 4",
            "cmp rcx, qword ptr [rsp + 16]",
            "jb 3b",
            // Top: tp[len - 1] = tp[len] + both pending halves, tp[len] = carry.
            "xor eax, eax",
            "add r14, r15",
            "adc rax, 0",
            "add r14, qword ptr [rdi + 8*rcx]",
            "adc rax, 0",
            "mov qword ptr [rdi + 8*rcx - 8], r14",
            "mov qword ptr [rdi + 8*rcx], rax",
            "add r9, 8",
            "dec qword ptr [rsp + 8]",
            "jnz 2b",
            "add rsp, 24",
            "pop rbp",
            "pop rbx",
            in("rdi") t.as_mut_ptr().wrapping_add(1),
            in("rsi") a.as_ptr(),
            in("r8") m.as_ptr(),
            inout("r9") b.as_ptr() => _,
            inout("rcx") len => _,
            inout("rdx") m0inv => _,
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
