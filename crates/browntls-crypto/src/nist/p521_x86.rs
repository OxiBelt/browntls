//! P-521 with the BMI2/ADX full-width product kernels (x86-64).
//!
//! Multiplication and squaring form the product with `wide_x86::mul9` /
//! `wide_x86::sqr9`; the reduction, addition and subtraction are assembly
//! versions of the portable algorithms in `p521_field`, with fixed
//! carry chains and mask or flag selection instead of branches. Every
//! constant and table is shared with the portable [`P521`]. Only used when
//! `wide_x86::available()` is true.
#![allow(unsafe_code)]

use core::arch::asm;

use super::curve::{Affine, Curve, Fe};
use super::params::{P521, wide_invert, wide_scalar_invert};
use super::wide_x86;

/// Reduces a product `t < 2^1042` to `t * 2^-576 mod p`, fully reduced: the
/// same steps as `p521_field::reduce`.
#[inline]
fn reduce(t: &[u64; 18]) -> Fe<9> {
    let mut o = [0u64; 9];
    // SAFETY: baseline x86-64 integer instructions only. The asm reads the
    // 144 bytes behind `t` (a valid reference), writes no memory, does not
    // touch the stack and declares every clobbered register.
    unsafe {
        asm!(
            // hi = t >> 521: limbs t[8..18] shifted right by nine bits.
            "mov r8, qword ptr [rsi + 64]",
            "mov r9, qword ptr [rsi + 72]",
            "mov r10, qword ptr [rsi + 80]",
            "mov r11, qword ptr [rsi + 88]",
            "mov r12, qword ptr [rsi + 96]",
            "mov r13, qword ptr [rsi + 104]",
            "mov r14, qword ptr [rsi + 112]",
            "mov r15, qword ptr [rsi + 120]",
            "mov rax, qword ptr [rsi + 128]",
            "mov rdx, qword ptr [rsi + 136]",
            // lo[8] = t[8] mod 2^9.
            "mov rcx, r8",
            "and ecx, 0x1ff",
            "shrd r8, r9, 9",
            "shrd r9, r10, 9",
            "shrd r10, r11, 9",
            "shrd r11, r12, 9",
            "shrd r12, r13, 9",
            "shrd r13, r14, 9",
            "shrd r14, r15, 9",
            "shrd r15, rax, 9",
            "shrd rax, rdx, 9",
            // s = lo + hi + 1.
            "stc",
            "adc r8, qword ptr [rsi]",
            "adc r9, qword ptr [rsi + 8]",
            "adc r10, qword ptr [rsi + 16]",
            "adc r11, qword ptr [rsi + 24]",
            "adc r12, qword ptr [rsi + 32]",
            "adc r13, qword ptr [rsi + 40]",
            "adc r14, qword ptr [rsi + 48]",
            "adc r15, qword ptr [rsi + 56]",
            "adc rax, rcx",
            // rcx = 1 - bit 521; clear the bit; subtract rcx.
            "mov rcx, rax",
            "shr rcx, 9",
            "xor ecx, 1",
            "and eax, 0x1ff",
            "sub r8, rcx",
            "sbb r9, 0",
            "sbb r10, 0",
            "sbb r11, 0",
            "sbb r12, 0",
            "sbb r13, 0",
            "sbb r14, 0",
            "sbb r15, 0",
            "sbb rax, 0",
            // Rotate right by 55 within 521 bits; rcx = (low 55 bits) << 9.
            "mov rcx, r8",
            "shl rcx, 9",
            "shrd r8, r9, 55",
            "shrd r9, r10, 55",
            "shrd r10, r11, 55",
            "shrd r11, r12, 55",
            "shrd r12, r13, 55",
            "shrd r13, r14, 55",
            "shrd r14, r15, 55",
            "shrd r15, rax, 55",
            "mov rax, rcx",
            "shr rax, 55",
            "shl rcx, 9",
            "or r15, rcx",
            in("rsi") t.as_ptr(),
            out("r8") o[0],
            out("r9") o[1],
            out("r10") o[2],
            out("r11") o[3],
            out("r12") o[4],
            out("r13") o[5],
            out("r14") o[6],
            out("r15") o[7],
            out("rax") o[8],
            out("rcx") _,
            out("rdx") _,
            options(pure, readonly, nostack),
        );
    }
    o
}

/// `a + b mod p` for `a, b < p` (as `p521_field::add`).
#[inline]
fn add(a: &Fe<9>, b: &Fe<9>) -> Fe<9> {
    let mut o = [0u64; 9];
    // SAFETY: baseline x86-64 integer instructions only. The asm reads the
    // 72 bytes behind each of `a` and `b` (valid references), writes no
    // memory, does not touch the stack and declares every clobbered register.
    unsafe {
        asm!(
            "mov r8, qword ptr [rsi]",
            "mov r9, qword ptr [rsi + 8]",
            "mov r10, qword ptr [rsi + 16]",
            "mov r11, qword ptr [rsi + 24]",
            "mov r12, qword ptr [rsi + 32]",
            "mov r13, qword ptr [rsi + 40]",
            "mov r14, qword ptr [rsi + 48]",
            "mov r15, qword ptr [rsi + 56]",
            "mov rax, qword ptr [rsi + 64]",
            // s = a + b + 1.
            "stc",
            "adc r8, qword ptr [rdi]",
            "adc r9, qword ptr [rdi + 8]",
            "adc r10, qword ptr [rdi + 16]",
            "adc r11, qword ptr [rdi + 24]",
            "adc r12, qword ptr [rdi + 32]",
            "adc r13, qword ptr [rdi + 40]",
            "adc r14, qword ptr [rdi + 48]",
            "adc r15, qword ptr [rdi + 56]",
            "adc rax, qword ptr [rdi + 64]",
            // rcx = 1 - bit 521; clear the bit; subtract rcx.
            "mov rcx, rax",
            "shr rcx, 9",
            "xor ecx, 1",
            "and eax, 0x1ff",
            "sub r8, rcx",
            "sbb r9, 0",
            "sbb r10, 0",
            "sbb r11, 0",
            "sbb r12, 0",
            "sbb r13, 0",
            "sbb r14, 0",
            "sbb r15, 0",
            "sbb rax, 0",
            in("rsi") a.as_ptr(),
            in("rdi") b.as_ptr(),
            out("r8") o[0],
            out("r9") o[1],
            out("r10") o[2],
            out("r11") o[3],
            out("r12") o[4],
            out("r13") o[5],
            out("r14") o[6],
            out("r15") o[7],
            out("rax") o[8],
            out("rcx") _,
            options(pure, readonly, nostack),
        );
    }
    o
}

/// `a - b mod p` for `a, b < p` (as `p521_field::sub`).
#[inline]
fn sub(a: &Fe<9>, b: &Fe<9>) -> Fe<9> {
    let mut o = [0u64; 9];
    // SAFETY: as for `add`.
    unsafe {
        asm!(
            "mov r8, qword ptr [rsi]",
            "mov r9, qword ptr [rsi + 8]",
            "mov r10, qword ptr [rsi + 16]",
            "mov r11, qword ptr [rsi + 24]",
            "mov r12, qword ptr [rsi + 32]",
            "mov r13, qword ptr [rsi + 40]",
            "mov r14, qword ptr [rsi + 48]",
            "mov r15, qword ptr [rsi + 56]",
            "mov rax, qword ptr [rsi + 64]",
            "sub r8, qword ptr [rdi]",
            "sbb r9, qword ptr [rdi + 8]",
            "sbb r10, qword ptr [rdi + 16]",
            "sbb r11, qword ptr [rdi + 24]",
            "sbb r12, qword ptr [rdi + 32]",
            "sbb r13, qword ptr [rdi + 40]",
            "sbb r14, qword ptr [rdi + 48]",
            "sbb r15, qword ptr [rdi + 56]",
            "sbb rax, qword ptr [rdi + 64]",
            // rcx = -borrow; adding it to all nine limbs subtracts the borrow.
            "sbb rcx, rcx",
            "add r8, rcx",
            "adc r9, rcx",
            "adc r10, rcx",
            "adc r11, rcx",
            "adc r12, rcx",
            "adc r13, rcx",
            "adc r14, rcx",
            "adc r15, rcx",
            "adc rax, rcx",
            "and eax, 0x1ff",
            in("rsi") a.as_ptr(),
            in("rdi") b.as_ptr(),
            out("r8") o[0],
            out("r9") o[1],
            out("r10") o[2],
            out("r11") o[3],
            out("r12") o[4],
            out("r13") o[5],
            out("r14") o[6],
            out("r15") o[7],
            out("rax") o[8],
            out("rcx") _,
            options(pure, readonly, nostack),
        );
    }
    o
}

/// P-521 on the BMI2/ADX backend.
#[derive(Clone, Copy, Debug)]
pub(crate) struct P521Adx;

impl Curve<9> for P521Adx {
    const BITS: usize = P521::BITS;
    const FIELD_LEN: usize = P521::FIELD_LEN;
    const P: [u64; 9] = P521::P;
    const P_INV: u64 = P521::P_INV;
    const ONE: Fe<9> = P521::ONE;
    const R2: Fe<9> = P521::R2;
    const P_MINUS_2: [u64; 9] = P521::P_MINUS_2;
    const ORDER: [u64; 9] = P521::ORDER;
    const ORDER_INV: u64 = P521::ORDER_INV;
    const ORDER_ONE: [u64; 9] = P521::ORDER_ONE;
    const ORDER_R2: [u64; 9] = P521::ORDER_R2;
    const ORDER_MINUS_2: [u64; 9] = P521::ORDER_MINUS_2;
    const B: Fe<9> = P521::B;
    const G: Affine<9> = P521::G;
    const OID: &'static [u8] = P521::OID;
    const COMB_WIDTH: usize = P521::COMB_WIDTH;
    const COMB_INTERLEAVE: usize = P521::COMB_INTERLEAVE;
    const BASE_TABLE: &'static [Affine<9>] = P521::BASE_TABLE;
    const G_ODD: &'static [Affine<9>; 16] = P521::G_ODD;

    #[inline]
    fn mul(a: &Fe<9>, b: &Fe<9>) -> Fe<9> {
        reduce(&wide_x86::mul9(a, b))
    }

    #[inline]
    fn sqr(a: &Fe<9>) -> Fe<9> {
        reduce(&wide_x86::sqr9(a))
    }

    #[inline]
    fn add(a: &Fe<9>, b: &Fe<9>) -> Fe<9> {
        add(a, b)
    }

    #[inline]
    fn sub(a: &Fe<9>, b: &Fe<9>) -> Fe<9> {
        sub(a, b)
    }

    #[inline]
    fn invert(a: &Fe<9>) -> Fe<9> {
        wide_invert::<Self, 9>(a)
    }

    #[inline]
    fn scalar_invert(a: &[u64; 9]) -> [u64; 9] {
        wide_scalar_invert::<Self, 9>(a)
    }
}

#[cfg(test)]
mod tests {
    use super::super::curve::{fe_mul_soft, to_affine};
    use super::super::scalar_mul;
    use super::super::{mont, p521_field};
    use super::*;

    /// Multiplication and squaring agree with the generic Montgomery
    /// multiplication on edge and random field elements.
    #[test]
    fn matches_generic_montgomery() {
        if !wide_x86::available() {
            return;
        }
        let v = p521_field::tests::inputs();
        for a in &v {
            assert_eq!(P521Adx::sqr(a), fe_mul_soft::<P521, 9>(a, a), "a = {a:x?}");
            for b in &v {
                assert_eq!(
                    P521Adx::mul(a, b),
                    fe_mul_soft::<P521, 9>(a, b),
                    "a = {a:x?} b = {b:x?}"
                );
            }
        }
    }

    #[test]
    fn addition_and_subtraction_match_generic() {
        let p = P521::P;
        let v = p521_field::tests::inputs();
        for a in &v {
            for b in &v {
                assert_eq!(add(a, b), mont::add_mod(a, b, &p), "a = {a:x?} b = {b:x?}");
                assert_eq!(sub(a, b), mont::sub_mod(a, b, &p), "a = {a:x?} b = {b:x?}");
            }
        }
    }

    /// The assembly reduction agrees with the portable one on the whole
    /// documented domain (`t < 2^1042`), including its extremes.
    #[test]
    fn reduction_matches_portable() {
        let mut seed = 0x3f84_d5b5_b547_0917u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let clamp = |mut t: [u64; 18]| {
            t[16] &= (1 << 18) - 1;
            t[17] = 0;
            t
        };
        let mut v = std::vec![[0u64; 18], clamp([u64::MAX; 18])];
        for i in 0..17 {
            let mut t = [0u64; 18];
            t[i] = u64::MAX;
            v.push(clamp(t));
            let mut t = [u64::MAX; 18];
            t[i] = 0;
            v.push(clamp(t));
        }
        // lo + hi = p - 1, p and p + 1 (the conditional subtraction's edges).
        for low in [u64::MAX - 1, u64::MAX, 0] {
            let mut t = [0u64; 18];
            t[..8].fill(u64::MAX);
            t[0] = low;
            t[8] = 0x1ff;
            if low == 0 {
                // hi = 1: bit 521.
                t[..8].fill(u64::MAX);
                t[8] = 0x3ff;
            }
            v.push(t);
        }
        for _ in 0..2000 {
            v.push(clamp(core::array::from_fn(|_| next())));
        }
        for t in &v {
            assert_eq!(reduce(t), p521_field::reduce(t), "t = {t:x?}");
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
            let mut k: [u64; 9] = core::array::from_fn(|_| next());
            let mut l: [u64; 9] = core::array::from_fn(|_| next());
            k[9 - 1] &= P521::ORDER[9 - 1] >> 1;
            l[9 - 1] &= P521::ORDER[9 - 1] >> 1;
            let base = to_affine::<P521, 9>(&scalar_mul::mul_base::<P521, 9>(&k)).unwrap();
            let fast = to_affine::<P521Adx, 9>(&scalar_mul::mul_base::<P521Adx, 9>(&k));
            assert_eq!(fast.unwrap(), base);
            let var = to_affine::<P521, 9>(&scalar_mul::mul::<P521, 9>(&base, &l)).unwrap();
            let fast = to_affine::<P521Adx, 9>(&scalar_mul::mul::<P521Adx, 9>(&base, &l));
            assert_eq!(fast.unwrap(), var);
        }
    }
}
