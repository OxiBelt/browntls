//! P-256 field multiplication for x86-64 with BMI2 (`mulx`) and ADX
//! (`adcx`/`adox`).
//!
//! The kernel is the same word-by-word CIOS Montgomery multiplication as the
//! portable backend, with the two carry chains of each row (`a * b[i]`, then
//! `q * p`) kept in the carry and overflow flags so they run independently.
//! Because `p = -1 mod 2^64`, the Montgomery quotient of a row is simply its
//! low limb. The accumulator rotates through six registers so the shift at the
//! end of every row is free, and the final reduction is a subtraction followed
//! by `cmov`s: there is no data-dependent branch and the instruction sequence
//! is fixed.
//!
//! Only entered when [`available`] is true; the x86-64 host and the `x86_64-max`
//! QEMU profile both have BMI2 and ADX.
#![allow(unsafe_code)]

use super::curve::{Affine, Curve, Fe};
use super::params::P256;

/// The field prime followed by a zero limb (a memory operand for carry folding).
static P: [u64; 5] = [P256::P[0], P256::P[1], P256::P[2], P256::P[3], 0];

/// Whether the CPU has BMI2 and ADX.
#[inline]
pub(crate) fn available() -> bool {
    let f = crate::cpu::features();
    f.x86_bmi2() && f.x86_adx()
}

/// One CIOS row with accumulator `(t0..t4)`, scratch top limb `t5` (must be
/// zero on entry; `t0` is zero on exit and becomes the next row's `t5`), and
/// multiplier `b[i]`.
macro_rules! row {
    ($t0:literal, $t1:literal, $t2:literal, $t3:literal, $t4:literal, $t5:literal, $i:literal) => {
        concat!(
            // acc += a * b[i]
            "mov rdx, qword ptr [{b} + ",
            $i,
            "]\n",
            "xor ",
            $t5,
            ", ",
            $t5,
            "\n",
            "mulx r9, r8, qword ptr [{a}]\n",
            "adcx ",
            $t0,
            ", r8\n",
            "adox ",
            $t1,
            ", r9\n",
            "mulx r9, r8, qword ptr [{a} + 8]\n",
            "adcx ",
            $t1,
            ", r8\n",
            "adox ",
            $t2,
            ", r9\n",
            "mulx r9, r8, qword ptr [{a} + 16]\n",
            "adcx ",
            $t2,
            ", r8\n",
            "adox ",
            $t3,
            ", r9\n",
            "mulx r9, r8, qword ptr [{a} + 24]\n",
            "adcx ",
            $t3,
            ", r8\n",
            "adox ",
            $t4,
            ", r9\n",
            "adcx ",
            $t4,
            ", qword ptr [{p} + 32]\n",
            "adox ",
            $t5,
            ", qword ptr [{p} + 32]\n",
            "adcx ",
            $t5,
            ", qword ptr [{p} + 32]\n",
            // acc = (acc + q * p) / 2^64 with q = acc[0] (since -p^-1 = 1 mod 2^64)
            "mov rdx, ",
            $t0,
            "\n",
            "xor r8d, r8d\n",
            "mulx r9, r8, qword ptr [{p}]\n",
            "adcx ",
            $t0,
            ", r8\n",
            "adox ",
            $t1,
            ", r9\n",
            "mulx r9, r8, qword ptr [{p} + 8]\n",
            "adcx ",
            $t1,
            ", r8\n",
            "adox ",
            $t2,
            ", r9\n",
            "mulx r9, r8, qword ptr [{p} + 16]\n",
            "adcx ",
            $t2,
            ", r8\n",
            "adox ",
            $t3,
            ", r9\n",
            "mulx r9, r8, qword ptr [{p} + 24]\n",
            "adcx ",
            $t3,
            ", r8\n",
            "adox ",
            $t4,
            ", r9\n",
            "adcx ",
            $t4,
            ", qword ptr [{p} + 32]\n",
            "adox ",
            $t5,
            ", qword ptr [{p} + 32]\n",
            "adcx ",
            $t5,
            ", qword ptr [{p} + 32]\n",
        )
    };
}

/// Montgomery multiplication `a * b * 2^-256 mod p` for `a, b < p`.
#[inline]
pub(crate) fn mul(a: &Fe<4>, b: &Fe<4>) -> Fe<4> {
    let (o0, o1, o2, o3): (u64, u64, u64, u64);
    // SAFETY: the caller selected this backend only after `available()`
    // reported BMI2 and ADX, so `mulx`/`adcx`/`adox` are supported. The asm
    // only reads the 32 bytes behind `a` and `b` and the 40 bytes behind `P`,
    // all valid for the given references / static, writes no memory, and
    // declares every register it clobbers.
    unsafe {
        core::arch::asm!(
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            row!("r10", "r11", "r12", "r13", "r14", "r15", "0"),
            row!("r11", "r12", "r13", "r14", "r15", "r10", "8"),
            row!("r12", "r13", "r14", "r15", "r10", "r11", "16"),
            row!("r13", "r14", "r15", "r10", "r11", "r12", "24"),
            // acc = (r14, r15, r10, r11, r12) < 2p; subtract p and keep the
            // difference unless it borrowed.
            "mov r8, r14",
            "mov r9, r15",
            "mov rdx, r10",
            "mov r13, r11",
            "sub r8, qword ptr [{p}]",
            "sbb r9, qword ptr [{p} + 8]",
            "sbb rdx, qword ptr [{p} + 16]",
            "sbb r13, qword ptr [{p} + 24]",
            "sbb r12, 0",
            "cmovnc r14, r8",
            "cmovnc r15, r9",
            "cmovnc r10, rdx",
            "cmovnc r11, r13",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            p = in(reg) P.as_ptr(),
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") o2,
            out("r11") o3,
            out("r12") _,
            out("r13") _,
            out("r14") o0,
            out("r15") o1,
            options(pure, readonly, nostack),
        );
    }
    [o0, o1, o2, o3]
}

/// P-256 with the BMI2/ADX field multiplication; shares every constant with
/// the portable [`P256`].
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

    #[test]
    fn matches_portable_multiplication() {
        if !available() {
            std::eprintln!("skipping: BMI2/ADX unavailable");
            return;
        }
        let mut seed = 0x0123_4567_89ab_cdef;
        let (pm1, _) = mont::sub(&P256::P, &[1, 0, 0, 0]);
        let mut inputs = std::vec![
            [0u64; 4],
            [1, 0, 0, 0],
            pm1,
            P256::ONE,
            P256::R2,
            [u64::MAX, u64::MAX, u64::MAX, 0],
            [u64::MAX, 0, 0, 0xffff_ffff_0000_0000],
            [0, 0, 0, 0xffff_ffff_0000_0000],
            [
                0xffff_ffff_ffff_ffff,
                0x0000_0000_ffff_fffe,
                0,
                0xffff_ffff_0000_0000
            ],
        ];
        for _ in 0..200 {
            inputs.push(random_fe(&mut seed));
        }
        for a in &inputs {
            for b in &inputs {
                assert_eq!(mul(a, b), fe_mul_soft::<P256, 4>(a, b), "a={a:x?} b={b:x?}");
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
