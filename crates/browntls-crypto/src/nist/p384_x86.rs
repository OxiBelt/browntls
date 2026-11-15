//! P-384 with the BMI2/ADX full-width product kernels (x86-64).
//!
//! Multiplication and squaring form the product with `wide_x86::mul6` /
//! `wide_x86::sqr6`; the reduction, addition and subtraction are assembly
//! versions of the portable algorithms in `p384_field` and `mont`, with fixed
//! carry chains and mask or flag selection instead of branches. Every
//! constant and table is shared with the portable [`P384`]. Only used when
//! `wide_x86::available()` is true.
#![allow(unsafe_code)]

use core::arch::asm;

use super::curve::{Affine, Curve, Fe};
use super::params::{P384, wide_invert, wide_scalar_invert};
use super::wide_x86;

/// Montgomery reduction of `t < p 2^384` to `t 2^-384 mod p`, fully reduced:
/// the same rounds as `p384_field::reduce`.
#[inline]
fn reduce(t: &[u64; 12]) -> Fe<6> {
    let mut o = [0u64; 6];
    // SAFETY: only reachable through `P384Adx`, which is selected after
    // `wide_x86::available()` reported BMI2 (`mulx`), and from a test that
    // checks the same. The asm reads the 96
    // bytes behind `t` (a valid reference), writes no memory, does not touch
    // the stack and declares every register it clobbers.
    unsafe {
        asm!(
            "mov r8, qword ptr [rsi]",
            "mov r9, qword ptr [rsi + 8]",
            "mov r10, qword ptr [rsi + 16]",
            "mov r11, qword ptr [rsi + 24]",
            "mov r12, qword ptr [rsi + 32]",
            "mov r13, qword ptr [rsi + 40]",
            // k = 2^384 - p = (r14, r15, 1).
            "mov r14, 0xffffffff00000001",
            "mov r15d, 0xffffffff",
            // Round 0: q = w0 (2^32 + 1); window = (window - q k) / 2^64 + q 2^320.
            "mov rdx, r8",
            "shl rdx, 32",
            "add rdx, r8",
            "mulx rcx, rax, r14",
            "mulx rdi, rax, r15",
            "add rcx, rax",
            "adc rdi, rdx",
            "mov eax, 0",
            "adc eax, 0",
            "sub r9, rcx",
            "sbb r10, rdi",
            "sbb r11, rax",
            "sbb r12, 0",
            "sbb r13, 0",
            "sbb rdx, 0",
            "mov r8, rdx",
            // Round 1: q = w0 (2^32 + 1); window = (window - q k) / 2^64 + q 2^320.
            "mov rdx, r9",
            "shl rdx, 32",
            "add rdx, r9",
            "mulx rcx, rax, r14",
            "mulx rdi, rax, r15",
            "add rcx, rax",
            "adc rdi, rdx",
            "mov eax, 0",
            "adc eax, 0",
            "sub r10, rcx",
            "sbb r11, rdi",
            "sbb r12, rax",
            "sbb r13, 0",
            "sbb r8, 0",
            "sbb rdx, 0",
            "mov r9, rdx",
            // Round 2: q = w0 (2^32 + 1); window = (window - q k) / 2^64 + q 2^320.
            "mov rdx, r10",
            "shl rdx, 32",
            "add rdx, r10",
            "mulx rcx, rax, r14",
            "mulx rdi, rax, r15",
            "add rcx, rax",
            "adc rdi, rdx",
            "mov eax, 0",
            "adc eax, 0",
            "sub r11, rcx",
            "sbb r12, rdi",
            "sbb r13, rax",
            "sbb r8, 0",
            "sbb r9, 0",
            "sbb rdx, 0",
            "mov r10, rdx",
            // Round 3: q = w0 (2^32 + 1); window = (window - q k) / 2^64 + q 2^320.
            "mov rdx, r11",
            "shl rdx, 32",
            "add rdx, r11",
            "mulx rcx, rax, r14",
            "mulx rdi, rax, r15",
            "add rcx, rax",
            "adc rdi, rdx",
            "mov eax, 0",
            "adc eax, 0",
            "sub r12, rcx",
            "sbb r13, rdi",
            "sbb r8, rax",
            "sbb r9, 0",
            "sbb r10, 0",
            "sbb rdx, 0",
            "mov r11, rdx",
            // Round 4: q = w0 (2^32 + 1); window = (window - q k) / 2^64 + q 2^320.
            "mov rdx, r12",
            "shl rdx, 32",
            "add rdx, r12",
            "mulx rcx, rax, r14",
            "mulx rdi, rax, r15",
            "add rcx, rax",
            "adc rdi, rdx",
            "mov eax, 0",
            "adc eax, 0",
            "sub r13, rcx",
            "sbb r8, rdi",
            "sbb r9, rax",
            "sbb r10, 0",
            "sbb r11, 0",
            "sbb rdx, 0",
            "mov r12, rdx",
            // Round 5: q = w0 (2^32 + 1); window = (window - q k) / 2^64 + q 2^320.
            "mov rdx, r13",
            "shl rdx, 32",
            "add rdx, r13",
            "mulx rcx, rax, r14",
            "mulx rdi, rax, r15",
            "add rcx, rax",
            "adc rdi, rdx",
            "mov eax, 0",
            "adc eax, 0",
            "sub r8, rcx",
            "sbb r9, rdi",
            "sbb r10, rax",
            "sbb r11, 0",
            "sbb r12, 0",
            "sbb rdx, 0",
            "mov r13, rdx",
            // Add the high half; rax takes the carry.
            "add r8, qword ptr [rsi + 48]",
            "adc r9, qword ptr [rsi + 56]",
            "adc r10, qword ptr [rsi + 64]",
            "adc r11, qword ptr [rsi + 72]",
            "adc r12, qword ptr [rsi + 80]",
            "adc r13, qword ptr [rsi + 88]",
            "mov eax, 0",
            "adc eax, 0",
            // Subtract p = (r15, !r15, -2, -1, -1, -1); rax becomes the borrow mask.
            "mov rdx, r15",
            "not rdx",
            "sub r8, r15",
            "sbb r9, rdx",
            "sbb r10, -2",
            "sbb r11, -1",
            "sbb r12, -1",
            "sbb r13, -1",
            "sbb rax, 0",
            // Add p back where the subtraction borrowed.
            "mov rcx, r15",
            "and rcx, rax",
            "and rdx, rax",
            "mov rdi, rax",
            "and rdi, -2",
            "add r8, rcx",
            "adc r9, rdx",
            "adc r10, rdi",
            "adc r11, rax",
            "adc r12, rax",
            "adc r13, rax",
            in("rsi") t.as_ptr(),
            out("rdi") _,
            out("r8") o[0],
            out("r9") o[1],
            out("r10") o[2],
            out("r11") o[3],
            out("r12") o[4],
            out("r13") o[5],
            out("r14") _,
            out("r15") _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            options(pure, readonly, nostack),
        );
    }
    o
}

/// `a + b mod p` for `a, b < p`.
#[inline]
fn add(a: &Fe<6>, b: &Fe<6>) -> Fe<6> {
    let mut o = [0u64; 6];
    // SAFETY: baseline x86-64 integer instructions only. The asm reads the
    // 48 bytes behind each of `a` and `b` (valid references), writes no
    // memory, does not touch the stack and declares every clobbered register.
    unsafe {
        asm!(
            "mov r8, qword ptr [rsi]",
            "mov r9, qword ptr [rsi + 8]",
            "mov r10, qword ptr [rsi + 16]",
            "mov r11, qword ptr [rsi + 24]",
            "mov r12, qword ptr [rsi + 32]",
            "mov r13, qword ptr [rsi + 40]",
            "add r8, qword ptr [rdi]",
            "adc r9, qword ptr [rdi + 8]",
            "adc r10, qword ptr [rdi + 16]",
            "adc r11, qword ptr [rdi + 24]",
            "adc r12, qword ptr [rdi + 32]",
            "adc r13, qword ptr [rdi + 40]",
            "mov eax, 0",
            "adc eax, 0",
            // Subtract p = (rcx, rsi, -2, -1, -1, -1); rax becomes the borrow mask.
            "mov ecx, 0xffffffff",
            "mov rsi, rcx",
            "not rsi",
            "sub r8, rcx",
            "sbb r9, rsi",
            "sbb r10, -2",
            "sbb r11, -1",
            "sbb r12, -1",
            "sbb r13, -1",
            "sbb rax, 0",
            // Add p back where the subtraction borrowed.
            "and rcx, rax",
            "and rsi, rax",
            "mov rdi, rax",
            "and rdi, -2",
            "add r8, rcx",
            "adc r9, rsi",
            "adc r10, rdi",
            "adc r11, rax",
            "adc r12, rax",
            "adc r13, rax",
            inout("rsi") a.as_ptr() => _,
            inout("rdi") b.as_ptr() => _,
            out("r8") o[0],
            out("r9") o[1],
            out("r10") o[2],
            out("r11") o[3],
            out("r12") o[4],
            out("r13") o[5],
            out("rax") _,
            out("rcx") _,
            options(pure, readonly, nostack),
        );
    }
    o
}

/// `a - b mod p` for `a, b < p`.
#[inline]
fn sub(a: &Fe<6>, b: &Fe<6>) -> Fe<6> {
    let mut o = [0u64; 6];
    // SAFETY: as for `add`.
    unsafe {
        asm!(
            "mov r8, qword ptr [rsi]",
            "mov r9, qword ptr [rsi + 8]",
            "mov r10, qword ptr [rsi + 16]",
            "mov r11, qword ptr [rsi + 24]",
            "mov r12, qword ptr [rsi + 32]",
            "mov r13, qword ptr [rsi + 40]",
            "sub r8, qword ptr [rdi]",
            "sbb r9, qword ptr [rdi + 8]",
            "sbb r10, qword ptr [rdi + 16]",
            "sbb r11, qword ptr [rdi + 24]",
            "sbb r12, qword ptr [rdi + 32]",
            "sbb r13, qword ptr [rdi + 40]",
            // rax = -borrow; add p & rax.
            "sbb rax, rax",
            "mov ecx, 0xffffffff",
            "mov rsi, rcx",
            "not rsi",
            "and rcx, rax",
            "and rsi, rax",
            "mov rdi, rax",
            "and rdi, -2",
            "add r8, rcx",
            "adc r9, rsi",
            "adc r10, rdi",
            "adc r11, rax",
            "adc r12, rax",
            "adc r13, rax",
            inout("rsi") a.as_ptr() => _,
            inout("rdi") b.as_ptr() => _,
            out("r8") o[0],
            out("r9") o[1],
            out("r10") o[2],
            out("r11") o[3],
            out("r12") o[4],
            out("r13") o[5],
            out("rax") _,
            out("rcx") _,
            options(pure, readonly, nostack),
        );
    }
    o
}

/// P-384 on the BMI2/ADX backend.
#[derive(Clone, Copy, Debug)]
pub(crate) struct P384Adx;

impl Curve<6> for P384Adx {
    const BITS: usize = P384::BITS;
    const FIELD_LEN: usize = P384::FIELD_LEN;
    const P: [u64; 6] = P384::P;
    const P_INV: u64 = P384::P_INV;
    const ONE: Fe<6> = P384::ONE;
    const R2: Fe<6> = P384::R2;
    const P_MINUS_2: [u64; 6] = P384::P_MINUS_2;
    const ORDER: [u64; 6] = P384::ORDER;
    const ORDER_INV: u64 = P384::ORDER_INV;
    const ORDER_ONE: [u64; 6] = P384::ORDER_ONE;
    const ORDER_R2: [u64; 6] = P384::ORDER_R2;
    const ORDER_MINUS_2: [u64; 6] = P384::ORDER_MINUS_2;
    const B: Fe<6> = P384::B;
    const G: Affine<6> = P384::G;
    const OID: &'static [u8] = P384::OID;
    const COMB_WIDTH: usize = P384::COMB_WIDTH;
    const COMB_INTERLEAVE: usize = P384::COMB_INTERLEAVE;
    const BASE_TABLE: &'static [Affine<6>] = P384::BASE_TABLE;
    const G_ODD: &'static [Affine<6>; 16] = P384::G_ODD;

    #[inline]
    fn mul(a: &Fe<6>, b: &Fe<6>) -> Fe<6> {
        reduce(&wide_x86::mul6(a, b))
    }

    #[inline]
    fn sqr(a: &Fe<6>) -> Fe<6> {
        reduce(&wide_x86::sqr6(a))
    }

    #[inline]
    fn add(a: &Fe<6>, b: &Fe<6>) -> Fe<6> {
        add(a, b)
    }

    #[inline]
    fn sub(a: &Fe<6>, b: &Fe<6>) -> Fe<6> {
        sub(a, b)
    }

    #[inline]
    fn invert(a: &Fe<6>) -> Fe<6> {
        wide_invert::<Self, 6>(a)
    }

    #[inline]
    fn scalar_invert(a: &[u64; 6]) -> [u64; 6] {
        wide_scalar_invert::<Self, 6>(a)
    }
}

#[cfg(test)]
mod tests {
    use super::super::curve::{fe_mul_soft, to_affine};
    use super::super::scalar_mul;
    use super::super::{mont, p384_field};
    use super::*;

    /// Multiplication and squaring agree with the generic Montgomery
    /// multiplication on edge and random field elements.
    #[test]
    fn matches_generic_montgomery() {
        if !wide_x86::available() {
            return;
        }
        let v = p384_field::tests::inputs();
        for a in &v {
            assert_eq!(P384Adx::sqr(a), fe_mul_soft::<P384, 6>(a, a), "a = {a:x?}");
            for b in &v {
                assert_eq!(
                    P384Adx::mul(a, b),
                    fe_mul_soft::<P384, 6>(a, b),
                    "a = {a:x?} b = {b:x?}"
                );
            }
        }
    }

    #[test]
    fn addition_and_subtraction_match_generic() {
        let p = P384::P;
        let v = p384_field::tests::inputs();
        for a in &v {
            for b in &v {
                assert_eq!(add(a, b), mont::add_mod(a, b, &p), "a = {a:x?} b = {b:x?}");
                assert_eq!(sub(a, b), mont::sub_mod(a, b, &p), "a = {a:x?} b = {b:x?}");
            }
        }
    }

    /// The assembly reduction agrees with the portable one on products of
    /// reduced operands and on high halves at their extremes.
    #[test]
    fn reduction_matches_portable() {
        if !wide_x86::available() {
            return;
        }
        let mut seed = 0x3f84_d5b5_b547_0917u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let p = P384::P;
        let pm1 = mont::sub(&p, &[1, 0, 0, 0, 0, 0]).0;
        let mut v = std::vec![[0u64; 12]];
        // Any low half with a high half below p is in the domain t < p 2^384.
        for hi in [[0u64; 6], pm1, [u64::MAX, 0, 0, 0, 0, 0]] {
            for lo in [[0u64; 6], [u64::MAX; 6], [1, 0, 0, 0, 0, 0], p, pm1] {
                let mut t = [0u64; 12];
                t[..6].copy_from_slice(&lo);
                t[6..].copy_from_slice(&hi);
                v.push(t);
            }
        }
        for _ in 0..2000 {
            let mut t: [u64; 12] = core::array::from_fn(|_| next());
            t[11] &= u64::MAX >> 1;
            v.push(t);
        }
        for t in &v {
            assert_eq!(reduce(t), p384_field::reduce(t), "t = {t:x?}");
        }
    }

    /// Fixed-base and variable-base multiplications agree with the portable
    /// backend.
    #[test]
    fn scalar_multiplication_matches_portable() {
        if !wide_x86::available() {
            return;
        }
        let mut seed = 0x082e_fa98_ec4e_6c89u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..12 {
            let mut k: [u64; 6] = core::array::from_fn(|_| next());
            let mut l: [u64; 6] = core::array::from_fn(|_| next());
            k[6 - 1] &= P384::ORDER[6 - 1] >> 1;
            l[6 - 1] &= P384::ORDER[6 - 1] >> 1;
            let base = to_affine::<P384, 6>(&scalar_mul::mul_base::<P384, 6>(&k)).unwrap();
            let fast = to_affine::<P384Adx, 6>(&scalar_mul::mul_base::<P384Adx, 6>(&k));
            assert_eq!(fast.unwrap(), base);
            let var = to_affine::<P384, 6>(&scalar_mul::mul::<P384, 6>(&base, &l)).unwrap();
            let fast = to_affine::<P384Adx, 6>(&scalar_mul::mul::<P384Adx, 6>(&base, &l));
            assert_eq!(fast.unwrap(), var);
        }
    }
}
