//! Minimal libc-free Linux system-call access.
//!
//! A single naked, C-variadic trampoline (`syscall(nr, ...)`, stable since
//! Rust 1.99 via `c_variadic_naked_functions`) moves the system-call number
//! and up to six arguments from the platform C calling convention into the
//! kernel's system-call registers and executes the trap instruction. There is
//! no compiler-generated prologue, so the trampoline costs a call, register
//! moves and the trap itself.
//!
//! Only the system calls this crate needs are wrapped, each with a safe,
//! narrowly-typed interface:
//!
//! * `getrandom(2)` for operating-system entropy;
//! * `riscv_hwprobe(2)` for RISC-V extension discovery.
#![allow(unsafe_code)]

/// Raw Linux system call: returns the kernel result (`-errno` on failure).
///
/// # Safety
///
/// The caller must pass a valid system-call number and arguments that satisfy
/// that call's contract, including the validity and lifetime of every pointer.
/// Integer arguments must be passed as pointer-sized values.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn syscall(nr: usize, _: ...) -> isize {
    // SysV: nr=rdi, a1..a5=rsi,rdx,rcx,r8,r9, a6=[rsp+8].
    // Kernel: nr=rax, a1..a6=rdi,rsi,rdx,r10,r8,r9. `syscall` clobbers rcx/r11,
    // which are caller-saved in the C ABI.
    core::arch::naked_asm!(
        "mov rax, rdi",
        "mov rdi, rsi",
        "mov rsi, rdx",
        "mov rdx, rcx",
        "mov r10, r8",
        "mov r8, r9",
        "mov r9, [rsp + 8]",
        "syscall",
        "ret",
    )
}

/// Raw Linux system call: returns the kernel result (`-errno` on failure).
///
/// # Safety
///
/// See the x86-64 definition.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn syscall(nr: usize, _: ...) -> isize {
    // AAPCS64 (Linux passes variadic integers in x0-x7): nr=x0, a1..a6=x1..x6.
    // Kernel: nr=x8, a1..a6=x0..x5.
    core::arch::naked_asm!(
        "mov x8, x0",
        "mov x0, x1",
        "mov x1, x2",
        "mov x2, x3",
        "mov x3, x4",
        "mov x4, x5",
        "mov x5, x6",
        "svc #0",
        "ret",
    )
}

/// Raw Linux system call: returns the kernel result (`-errno` on failure).
///
/// # Safety
///
/// See the x86-64 definition.
#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
unsafe extern "C" fn syscall(nr: usize, _: ...) -> isize {
    // LP64D: nr=a0, a1..a6=a1..a6 (variadic integers use integer registers).
    // Kernel: nr=a7, a1..a6=a0..a5.
    core::arch::naked_asm!(
        "mv a7, a0",
        "mv a0, a1",
        "mv a1, a2",
        "mv a2, a3",
        "mv a3, a4",
        "mv a4, a5",
        "mv a5, a6",
        "ecall",
        "ret",
    )
}

#[cfg(target_arch = "x86_64")]
const SYS_GETRANDOM: usize = 318;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const SYS_GETRANDOM: usize = 278;

const EINTR: isize = 4;
const EAGAIN: isize = 11;

/// Fills `dest` with bytes from the kernel CSPRNG via `getrandom(2)`.
///
/// Blocks until the kernel entropy pool is initialised. Retries on `EINTR`
/// and short reads.
pub(crate) fn getrandom(mut dest: &mut [u8]) -> Result<(), i32> {
    while !dest.is_empty() {
        // Linux caps a single request; keep requests modest.
        let len = dest.len().min(1 << 20);
        // SAFETY: `dest` is a valid, writable buffer of at least `len` bytes
        // for the duration of the call; flags = 0 requests blocking behaviour
        // from the urandom source. The kernel writes at most `len` bytes.
        let ret = unsafe { syscall(SYS_GETRANDOM, dest.as_mut_ptr(), len, 0usize) };
        if ret < 0 {
            if ret == -EINTR || ret == -EAGAIN {
                continue;
            }
            return Err(i32::try_from(-ret).unwrap_or(i32::MAX));
        }
        let n = ret.unsigned_abs().min(len);
        if n == 0 {
            return Err(0);
        }
        dest = &mut dest[n..];
    }
    Ok(())
}

/// One `riscv_hwprobe` key/value pair (`struct riscv_hwprobe`).
#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct HwProbe {
    pub(crate) key: i64,
    pub(crate) value: u64,
}

/// Queries `riscv_hwprobe(2)` for all online CPUs. Unknown keys are returned
/// by the kernel with `key = -1`. Returns `false` if the call is unsupported.
#[cfg(target_arch = "riscv64")]
pub(crate) fn riscv_hwprobe(pairs: &mut [HwProbe]) -> bool {
    const SYS_RISCV_HWPROBE: usize = 258;
    // SAFETY: `pairs` is a valid, writable array of `pairs.len()`
    // `struct riscv_hwprobe` (repr(C) {i64, u64}); cpusetsize = 0 with a null
    // cpu set means "all online CPUs"; flags = 0. The kernel only writes within
    // the array.
    let ret = unsafe {
        syscall(
            SYS_RISCV_HWPROBE,
            pairs.as_mut_ptr(),
            pairs.len(),
            0usize,
            core::ptr::null_mut::<u8>(),
            0usize,
        )
    };
    ret == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn getrandom_fills() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        super::getrandom(&mut a).unwrap();
        super::getrandom(&mut b).unwrap();
        assert_ne!(a, b);
        let mut empty = [0u8; 0];
        super::getrandom(&mut empty).unwrap();
    }
}
