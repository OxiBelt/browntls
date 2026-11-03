//! P-256 field arithmetic for x86-64 with BMI2 (`mulx`) and ADX
//! (`adcx`/`adox`).
//!
//! Multiplication and squaring first form the full 512-bit product (two
//! independent carry chains in the carry and overflow flags), then run four
//! Montgomery reduction rounds that exploit the shape of
//! `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`: since `-p^-1 = 1 mod 2^64`, the
//! quotient of a round is the low limb `q` itself, and adding `q * p` to the
//! window `(t0, t1, t2, t3)` reduces to adding `q * 2^32` at limb 1 and
//! `q * p[3]` at limb 3 (one `mulx` instead of four). The window never grows
//! beyond four limbs, the high half of the product is added afterwards, and
//! the result (below `2p`) is reduced by a subtraction followed by `cmov`s.
//! Squaring computes the six cross products once and doubles them while the
//! four squares are added. Addition and subtraction are fixed carry chains
//! with `cmov` or mask selection inside the assembly.
//!
//! No instruction sequence or memory access depends on the operands. Only
//! entered when [`available`] is true; the x86-64 host and the `x86_64-max`
//! QEMU profile both have BMI2 and ADX.
#![allow(unsafe_code)]

use super::curve::{Affine, Curve, Fe};
use super::params::{P256, p256_invert, p256_scalar_invert};

/// `p[1] = 2^32 - 1`.
const P1: u64 = 0x0000_0000_ffff_ffff;
/// `p[3] = 2^64 - 2^32 + 1`.
const P3: u64 = 0xffff_ffff_0000_0001;

/// `p[3]` as a memory operand for the multiplication kernels.
static P3_MEM: u64 = P3;

/// Whether the CPU has BMI2 and ADX.
#[inline]
pub(crate) fn available() -> bool {
    let f = crate::cpu::features();
    f.x86_bmi2() && f.x86_adx()
}

/// One reduction round on the four-limb window `(q, w1, w2, w3)`: adds
/// `q * p` and drops the (now zero) low limb. The new window is
/// `(w1, w2, w3, q)`, with the register of `q` holding the new top limb.
/// Clobbers `rax`, `rcx`, `rdx` and the flags.
macro_rules! reduce_round {
    ($q:literal, $w1:literal, $w2:literal, $w3:literal) => {
        concat!(
            "mov rdx, ",
            $q,
            "\n",
            "shr ",
            $q,
            ", 32\n",
            "mulx rcx, rax, qword ptr [rip + {p3m}]\n",
            "shl rdx, 32\n",
            "add ",
            $w1,
            ", rdx\n",
            "adc ",
            $w2,
            ", ",
            $q,
            "\n",
            "adc ",
            $w3,
            ", rax\n",
            "adc rcx, 0\n",
            "mov ",
            $q,
            ", rcx\n",
        )
    };
}

/// The common tail of multiplication and squaring: reduces the 512-bit value
/// in `r8..r15` (little-endian) to `r8..r11`, fully reduced below `p` when the
/// value is below `p * 2^256`.
macro_rules! reduce_tail {
    () => {
        concat!(
            reduce_round!("r8", "r9", "r10", "r11"),
            reduce_round!("r9", "r10", "r11", "r8"),
            reduce_round!("r10", "r11", "r8", "r9"),
            reduce_round!("r11", "r8", "r9", "r10"),
            // (r8..r11) + (r12..r15) with the carry in rax: below 2p.
            "xor eax, eax\n",
            "add r8, r12\n",
            "adc r9, r13\n",
            "adc r10, r14\n",
            "adc r11, r15\n",
            "adc rax, 0\n",
            // Subtract p; keep the difference unless the whole value borrowed.
            "mov r12, r8\n",
            "mov r13, r9\n",
            "mov r14, r10\n",
            "mov r15, r11\n",
            "mov ecx, 0xffffffff\n",
            "sub r12, -1\n",
            "sbb r13, rcx\n",
            "sbb r14, 0\n",
            "sbb r15, qword ptr [rip + {p3m}]\n",
            "sbb rax, 0\n",
            "cmovnc r8, r12\n",
            "cmovnc r9, r13\n",
            "cmovnc r10, r14\n",
            "cmovnc r11, r15\n",
        )
    };
}

/// One product row `t[i..i + 5] += a * b[i]` for `i >= 1`; `$t4` is the new
/// top limb (zeroed here).
macro_rules! mul_row {
    ($off:literal, $t0:literal, $t1:literal, $t2:literal, $t3:literal, $t4:literal) => {
        concat!(
            "mov rdx, qword ptr [{b} + ",
            $off,
            "]\n",
            "xor ",
            $t4,
            ", ",
            $t4,
            "\n",
            "mulx rcx, rax, qword ptr [{a}]\n",
            "adcx ",
            $t0,
            ", rax\n",
            "adox ",
            $t1,
            ", rcx\n",
            "mulx rcx, rax, qword ptr [{a} + 8]\n",
            "adcx ",
            $t1,
            ", rax\n",
            "adox ",
            $t2,
            ", rcx\n",
            "mulx rcx, rax, qword ptr [{a} + 16]\n",
            "adcx ",
            $t2,
            ", rax\n",
            "adox ",
            $t3,
            ", rcx\n",
            "mulx rcx, rax, qword ptr [{a} + 24]\n",
            "adcx ",
            $t3,
            ", rax\n",
            "adox ",
            $t4,
            ", rcx\n",
            "adc ",
            $t4,
            ", 0\n",
        )
    };
}

/// Montgomery multiplication `a * b * 2^-256 mod p`.
///
/// For `a, b < p` the result is fully reduced. For any `a, b < 2^256` it is
/// congruent to the product and below `2^256`.
#[inline]
pub(crate) fn mul(a: &Fe<4>, b: &Fe<4>) -> Fe<4> {
    let (o0, o1, o2, o3): (u64, u64, u64, u64);
    // SAFETY: the caller selected this backend only after `available()`
    // reported BMI2 and ADX, so `mulx`/`adcx`/`adox` are supported. The asm
    // only reads the 32 bytes behind each of `a` and `b` (valid references),
    // writes no memory, does not touch the stack and declares every register
    // it clobbers.
    unsafe {
        core::arch::asm!(
            // Row 0: t[0..5] = a * b[0].
            "mov rdx, qword ptr [{b}]",
            "mulx r9, r8, qword ptr [{a}]",
            "mulx r10, rax, qword ptr [{a} + 8]",
            "add r9, rax",
            "mulx r11, rax, qword ptr [{a} + 16]",
            "adc r10, rax",
            "mulx r12, rax, qword ptr [{a} + 24]",
            "adc r11, rax",
            "adc r12, 0",
            mul_row!("8", "r9", "r10", "r11", "r12", "r13"),
            mul_row!("16", "r10", "r11", "r12", "r13", "r14"),
            mul_row!("24", "r11", "r12", "r13", "r14", "r15"),
            reduce_tail!(),
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            p3m = sym P3_MEM,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") o0,
            out("r9") o1,
            out("r10") o2,
            out("r11") o3,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [o0, o1, o2, o3]
}

/// Montgomery squaring `a^2 * 2^-256 mod p` (same reduction guarantees as
/// [`mul`]).
#[inline]
pub(crate) fn sqr(a: &Fe<4>) -> Fe<4> {
    let (o0, o1, o2, o3): (u64, u64, u64, u64);
    // SAFETY: as for `mul`: BMI2/ADX are present, the asm reads only the 32
    // bytes behind `a`, writes no memory, does not touch the stack and
    // declares every clobbered register.
    unsafe {
        core::arch::asm!(
            // Cross products a_i * a_j (i < j) into t1..t6.
            "mov rdx, qword ptr [{a}]",
            "mulx r10, r9, qword ptr [{a} + 8]",
            "mulx r11, rax, qword ptr [{a} + 16]",
            "add r10, rax",
            "mulx r12, rax, qword ptr [{a} + 24]",
            "adc r11, rax",
            "adc r12, 0",
            "mov rdx, qword ptr [{a} + 8]",
            "xor r13d, r13d",
            "mulx rcx, rax, qword ptr [{a} + 16]",
            "adcx r11, rax",
            "adox r12, rcx",
            "mulx rcx, rax, qword ptr [{a} + 24]",
            "adcx r12, rax",
            "adox r13, rcx",
            "adc r13, 0",
            "mov rdx, qword ptr [{a} + 16]",
            "mulx r14, rax, qword ptr [{a} + 24]",
            "add r13, rax",
            "adc r14, 0",
            // Double the cross products (carry flag chain) while adding the
            // squares a_i^2 (overflow flag chain).
            "xor r15d, r15d",
            "mov rdx, qword ptr [{a}]",
            "mulx rcx, r8, rdx",
            "adcx r9, r9",
            "adox r9, rcx",
            "mov rdx, qword ptr [{a} + 8]",
            "mulx rcx, rax, rdx",
            "adcx r10, r10",
            "adox r10, rax",
            "adcx r11, r11",
            "adox r11, rcx",
            "mov rdx, qword ptr [{a} + 16]",
            "mulx rcx, rax, rdx",
            "adcx r12, r12",
            "adox r12, rax",
            "adcx r13, r13",
            "adox r13, rcx",
            "mov rdx, qword ptr [{a} + 24]",
            "mulx rcx, rax, rdx",
            "adcx r14, r14",
            "adox r14, rax",
            "adcx r15, r15",
            "adox r15, rcx",
            reduce_tail!(),
            a = in(reg) a.as_ptr(),
            p3m = sym P3_MEM,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") o0,
            out("r9") o1,
            out("r10") o2,
            out("r11") o3,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [o0, o1, o2, o3]
}

/// `a + b mod p` for `a, b < p`.
#[inline]
pub(crate) fn add(a: &Fe<4>, b: &Fe<4>) -> Fe<4> {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: plain integer instructions (baseline x86-64) on registers and
    // the 32 bytes behind `b`; no stores, no stack use, all outputs declared.
    unsafe {
        core::arch::asm!(
            "add {r0}, qword ptr [{b}]",
            "adc {r1}, qword ptr [{b} + 8]",
            "adc {r2}, qword ptr [{b} + 16]",
            "adc {r3}, qword ptr [{b} + 24]",
            "mov {c:e}, 0",
            "adc {c}, 0",
            "mov {s0}, {r0}",
            "mov {s1}, {r1}",
            "mov {s2}, {r2}",
            "mov {s3}, {r3}",
            "sub {s0}, -1",
            "sbb {s1}, {p1}",
            "sbb {s2}, 0",
            "sbb {s3}, {p3}",
            "sbb {c}, 0",
            "cmovnc {r0}, {s0}",
            "cmovnc {r1}, {s1}",
            "cmovnc {r2}, {s2}",
            "cmovnc {r3}, {s3}",
            b = in(reg) b.as_ptr(),
            p1 = in(reg) P1,
            p3 = in(reg) P3,
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            c = out(reg) _,
            s0 = out(reg) _,
            s1 = out(reg) _,
            s2 = out(reg) _,
            s3 = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a - b mod p` for `a, b < p`.
#[inline]
pub(crate) fn sub(a: &Fe<4>, b: &Fe<4>) -> Fe<4> {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: plain integer instructions (baseline x86-64) on registers and
    // the 32 bytes behind `b`; no stores, no stack use, all outputs declared.
    unsafe {
        core::arch::asm!(
            "sub {r0}, qword ptr [{b}]",
            "sbb {r1}, qword ptr [{b} + 8]",
            "sbb {r2}, qword ptr [{b} + 16]",
            "sbb {r3}, qword ptr [{b} + 24]",
            // m = -borrow; add p & m.
            "sbb {m}, {m}",
            "mov {s1}, {m}",
            "shr {s1}, 32",
            "mov {s3}, {m}",
            "and {s3}, {p3}",
            "add {r0}, {m}",
            "adc {r1}, {s1}",
            "adc {r2}, 0",
            "adc {r3}, {s3}",
            b = in(reg) b.as_ptr(),
            p3 = in(reg) P3,
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            m = out(reg) _,
            s1 = out(reg) _,
            s3 = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// P-256 with the BMI2/ADX field arithmetic; shares every constant with the
/// portable [`P256`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256Adx;

impl Curve<4> for P256Adx {
    const BITS: usize = P256::BITS;
    const FIELD_LEN: usize = P256::FIELD_LEN;
    const P: [u64; 4] = P256::P;
    const P_INV: u64 = P256::P_INV;
    const ONE: Fe<4> = P256::ONE;
    const R2: Fe<4> = P256::R2;
    const P_MINUS_2: [u64; 4] = P256::P_MINUS_2;
    const ORDER: [u64; 4] = P256::ORDER;
    const ORDER_INV: u64 = P256::ORDER_INV;
    const ORDER_ONE: [u64; 4] = P256::ORDER_ONE;
    const ORDER_R2: [u64; 4] = P256::ORDER_R2;
    const ORDER_MINUS_2: [u64; 4] = P256::ORDER_MINUS_2;
    const B: Fe<4> = P256::B;
    const G: Affine<4> = P256::G;
    const OID: &'static [u8] = P256::OID;
    const BASE_TABLE: &'static [[Affine<4>; 8]] = P256::BASE_TABLE;
    const G_ODD: &'static [Affine<4>; 16] = P256::G_ODD;

    #[inline]
    fn mul(a: &Fe<4>, b: &Fe<4>) -> Fe<4> {
        mul(a, b)
    }

    #[inline]
    fn sqr(a: &Fe<4>) -> Fe<4> {
        sqr(a)
    }

    #[inline]
    fn add(a: &Fe<4>, b: &Fe<4>) -> Fe<4> {
        add(a, b)
    }

    #[inline]
    fn sub(a: &Fe<4>, b: &Fe<4>) -> Fe<4> {
        sub(a, b)
    }

    #[inline]
    fn invert(a: &Fe<4>) -> Fe<4> {
        p256_invert::<Self>(a)
    }

    #[inline]
    fn scalar_invert(a: &[u64; 4]) -> [u64; 4] {
        p256_scalar_invert(a)
    }
}

#[cfg(test)]
mod tests {
    use super::super::curve::{fe_mul_soft, to_affine};
    use super::super::mont;
    use super::super::scalar_mul;
    use super::*;

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    fn random_fe(seed: &mut u64) -> Fe<4> {
        loop {
            let v = [
                xorshift(seed),
                xorshift(seed),
                xorshift(seed),
                xorshift(seed),
            ];
            if mont::lt(&v, &P256::P) != 0 {
                return v;
            }
        }
    }

    /// Reduced edge values and random elements below `p`.
    fn inputs() -> std::vec::Vec<Fe<4>> {
        let mut seed = 0x0123_4567_89ab_cdef;
        let (pm1, _) = mont::sub(&P256::P, &[1, 0, 0, 0]);
        let (pm2, _) = mont::sub(&P256::P, &[2, 0, 0, 0]);
        let mut v = std::vec![
            [0u64; 4],
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            pm1,
            pm2,
            P256::ONE,
            P256::R2,
            [u64::MAX, u64::MAX, u64::MAX, 0],
            [u64::MAX, 0, 0, 0xffff_ffff_0000_0000],
            [0, 0, 0, 0xffff_ffff_0000_0000],
            [0, P1, 0, 0],
            [u64::MAX, P1, 0, 0],
            [0, 0, 0, P3 - 1],
            [u64::MAX, u64::MAX - 1, u64::MAX, P3 - 1],
            [0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_fffe, 0, P3],
        ];
        for _ in 0..200 {
            v.push(random_fe(&mut seed));
        }
        for x in &v {
            assert!(mont::lt(x, &P256::P) != 0);
        }
        v
    }

    #[test]
    fn matches_portable_field_arithmetic() {
        if !available() {
            std::eprintln!("skipping: BMI2/ADX unavailable");
            return;
        }
        let v = inputs();
        for a in &v {
            assert_eq!(sqr(a), fe_mul_soft::<P256, 4>(a, a), "sqr a={a:x?}");
            for b in &v {
                assert_eq!(mul(a, b), fe_mul_soft::<P256, 4>(a, b), "a={a:x?} b={b:x?}");
                assert_eq!(add(a, b), mont::add_mod(a, b, &P256::P), "add a={a:x?} b={b:x?}");
                assert_eq!(sub(a, b), mont::sub_mod(a, b, &P256::P), "sub a={a:x?} b={b:x?}");
            }
        }
    }

    /// Unreduced operands (up to `2^256 - 1`) give a congruent product below
    /// `2^256`.
    #[test]
    fn unreduced_products_are_congruent() {
        if !available() {
            return;
        }
        let mut seed = 0x5555_aaaa_1234_9876;
        let mut v = std::vec![
            P256::P,
            [u64::MAX; 4],
            mont::add(&P256::P, &[1, 0, 0, 0]).0,
            [0, 0, 0, u64::MAX],
        ];
        for _ in 0..50 {
            v.push([
                xorshift(&mut seed),
                xorshift(&mut seed),
                xorshift(&mut seed),
                xorshift(&mut seed) | 0xffff_ffff_0000_0000,
            ]);
        }
        let reduce = |x: &Fe<4>| {
            let (d, borrow) = mont::sub(x, &P256::P);
            if borrow == 0 { d } else { *x }
        };
        for a in &v {
            let ar = reduce(a);
            assert_eq!(reduce(&sqr(a)), fe_mul_soft::<P256, 4>(&ar, &ar));
            for b in &v {
                let br = reduce(b);
                assert_eq!(reduce(&mul(a, b)), fe_mul_soft::<P256, 4>(&ar, &br));
            }
        }
    }

    #[test]
    fn scalar_multiplication_matches_portable() {
        if !available() {
            return;
        }
        let mut seed = 0xdead_beef_cafe_f00d;
        for _ in 0..8 {
            let mut k = random_fe(&mut seed);
            k[3] &= 0x7fff_ffff_ffff_ffff;
            let fast = to_affine::<P256Adx, 4>(&scalar_mul::mul_base::<P256Adx, 4>(&k)).unwrap();
            let soft = to_affine::<P256, 4>(&scalar_mul::mul_base::<P256, 4>(&k)).unwrap();
            assert_eq!(fast, soft);
            let fast = to_affine::<P256Adx, 4>(&scalar_mul::mul::<P256Adx, 4>(&soft, &k)).unwrap();
            let soft2 = to_affine::<P256, 4>(&scalar_mul::mul::<P256, 4>(&soft, &k)).unwrap();
            assert_eq!(fast, soft2);
        }
    }
}
