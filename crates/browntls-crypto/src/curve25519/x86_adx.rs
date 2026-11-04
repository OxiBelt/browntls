//! X25519 Montgomery ladder over GF(2^255 - 19) in radix 2^64 (four limbs)
//! using BMI2 `MULX` and ADX `ADCX`/`ADOX` (x86-64).
//!
//! Elements are kept *partially reduced*: any 256-bit value congruent to the
//! field element. Multiplication and squaring compute the 512-bit product
//! with two independent carry chains and fold the high half with
//! `2^256 = 38 (mod p)`; only `to_bytes` reduces fully. All code is
//! branch-free with fixed memory access patterns (constant time).
//!
//! Entry point [`x25519`] must only be called after checking
//! `features().x86_bmi2() && features().x86_adx()`.
#![allow(unsafe_code)]

use core::arch::asm;

use super::field::{cmov_u64, cswap_u64, opaque_mask};
use crate::ct::Choice;
use crate::zeroize::zeroize_u64;

type Fe4 = [u64; 4];

/// `out = a * b` (partially reduced).
#[inline]
#[target_feature(enable = "bmi2,adx")]
fn mul(out: &mut Fe4, a: &Fe4, b: &Fe4) {
    // SAFETY: `a` and `b` point to four readable u64s and `out` to four
    // writable u64s (array references); the asm accesses exactly
    // `[ptr + 0..32)` of each. MULX/ADCX/ADOX are available because this
    // function is only reachable from `ladder`, whose caller verified BMI2
    // and ADX at run time. All clobbered registers are declared; no stack use.
    unsafe {
        asm!(
            // Row 0: b0 * a -> z0..z4 (z0 stored).
            "mov rdx, qword ptr [{b}]",
            "mulx r9, r8, qword ptr [{a}]",
            "mulx r10, rax, qword ptr [{a} + 8]",
            "add r9, rax",
            "mulx r11, rax, qword ptr [{a} + 16]",
            "adc r10, rax",
            "mulx r12, rax, qword ptr [{a} + 24]",
            "adc r11, rax",
            "adc r12, 0",
            "mov qword ptr [{out}], r8",
            // Row 1: z1..z5 += b1 * a; r8 becomes the zero register.
            "mov rdx, qword ptr [{b} + 8]",
            "xor r8d, r8d",
            "mulx r14, rax, qword ptr [{a}]",
            "adcx r9, rax",
            "adox r10, r14",
            "mulx r14, rax, qword ptr [{a} + 8]",
            "adcx r10, rax",
            "adox r11, r14",
            "mulx r14, rax, qword ptr [{a} + 16]",
            "adcx r11, rax",
            "adox r12, r14",
            "mulx r13, rax, qword ptr [{a} + 24]",
            "adcx r12, rax",
            "adox r13, r8",
            "adcx r13, r8",
            "mov qword ptr [{out} + 8], r9",
            // Row 2: z2..z6 += b2 * a (z6 in r9).
            "mov rdx, qword ptr [{b} + 16]",
            "xor eax, eax",
            "mulx r14, rax, qword ptr [{a}]",
            "adcx r10, rax",
            "adox r11, r14",
            "mulx r14, rax, qword ptr [{a} + 8]",
            "adcx r11, rax",
            "adox r12, r14",
            "mulx r14, rax, qword ptr [{a} + 16]",
            "adcx r12, rax",
            "adox r13, r14",
            "mulx r9, rax, qword ptr [{a} + 24]",
            "adcx r13, rax",
            "adox r9, r8",
            "adcx r9, r8",
            "mov qword ptr [{out} + 16], r10",
            // Row 3: z3..z7 += b3 * a (z7 in r10).
            "mov rdx, qword ptr [{b} + 24]",
            "xor eax, eax",
            "mulx r14, rax, qword ptr [{a}]",
            "adcx r11, rax",
            "adox r12, r14",
            "mulx r14, rax, qword ptr [{a} + 8]",
            "adcx r12, rax",
            "adox r13, r14",
            "mulx r14, rax, qword ptr [{a} + 16]",
            "adcx r13, rax",
            "adox r9, r14",
            "mulx r10, rax, qword ptr [{a} + 24]",
            "adcx r9, rax",
            "adox r10, r8",
            "adcx r10, r8",
            // z0..z2 in memory, z3 = r11, z4 = r12, z5 = r13, z6 = r9, z7 = r10.
            // Fold: z_lo + 38 * z_hi.
            "mov edx, 38",
            "mulx rax, r12, r12",
            "mulx r15, r13, r13",
            "mulx r14, r9, r9",
            "mulx r8, r10, r10",
            "add r12, qword ptr [{out}]",
            "adc r13, qword ptr [{out} + 8]",
            "adc r9, qword ptr [{out} + 16]",
            "adc r10, r11",
            "adc r8, 0",
            "add r13, rax",
            "adc r9, r15",
            "adc r10, r14",
            "adc r8, 0",
            // Fold the top word (< 2^7) and a possible final carry.
            "imul r8, r8, 38",
            "add r12, r8",
            "adc r13, 0",
            "adc r9, 0",
            "adc r10, 0",
            "sbb rax, rax",
            "and eax, 38",
            "add r12, rax",
            "mov qword ptr [{out}], r12",
            "mov qword ptr [{out} + 8], r13",
            "mov qword ptr [{out} + 16], r9",
            "mov qword ptr [{out} + 24], r10",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            out("rax") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
            options(nostack),
        );
    }
}

/// `out = a^2` (partially reduced).
#[inline]
#[target_feature(enable = "bmi2,adx")]
fn sqr(out: &mut Fe4, a: &Fe4) {
    // SAFETY: as for `mul`: `a` is readable and `out` writable for 32 bytes,
    // BMI2/ADX were detected by the caller of `ladder`, clobbers declared.
    unsafe {
        asm!(
            // Off-diagonal products a_i a_j (i < j) into z1..z6.
            "mov rdx, qword ptr [{a}]",
            "mulx r10, r9, qword ptr [{a} + 8]",
            "mulx r11, rax, qword ptr [{a} + 16]",
            "add r10, rax",
            "mulx r12, rax, qword ptr [{a} + 24]",
            "adc r11, rax",
            "adc r12, 0",
            "mov rdx, qword ptr [{a} + 8]",
            "mulx r14, rax, qword ptr [{a} + 16]",
            "mulx r13, r15, qword ptr [{a} + 24]",
            "xor r8d, r8d",
            "adcx r11, rax",
            "adox r12, r14",
            "adcx r12, r15",
            "adox r13, r8",
            "adcx r13, r8",
            "mov rdx, qword ptr [{a} + 16]",
            "mulx r14, rax, qword ptr [{a} + 24]",
            "add r13, rax",
            "adc r14, r8",
            // Double: z1..z7.
            "xor r15d, r15d",
            "add r9, r9",
            "adc r10, r10",
            "adc r11, r11",
            "adc r12, r12",
            "adc r13, r13",
            "adc r14, r14",
            "adc r15, r15",
            // Add the squares a_i^2.
            "mov rdx, qword ptr [{a}]",
            "mulx rax, r8, rdx",
            "add r9, rax",
            "mov rdx, qword ptr [{a} + 8]",
            "mulx {t}, rax, rdx",
            "adc r10, rax",
            "adc r11, {t}",
            "mov rdx, qword ptr [{a} + 16]",
            "mulx {t}, rax, rdx",
            "adc r12, rax",
            "adc r13, {t}",
            "mov rdx, qword ptr [{a} + 24]",
            "mulx {t}, rax, rdx",
            "adc r14, rax",
            "adc r15, {t}",
            // z0..z3 = r8..r11, z4..z7 = r12..r15. Fold: z_lo + 38 * z_hi.
            "mov edx, 38",
            "mulx rax, r12, r12",
            "mulx {t}, r13, r13",
            "add r8, r12",
            "adc r9, r13",
            "mulx r13, r14, r14",
            "adc r10, r14",
            "mulx r12, r15, r15",
            "adc r11, r15",
            "adc r12, 0",
            "add r9, rax",
            "adc r10, {t}",
            "adc r11, r13",
            "adc r12, 0",
            "imul r12, r12, 38",
            "add r8, r12",
            "adc r9, 0",
            "adc r10, 0",
            "adc r11, 0",
            "sbb rax, rax",
            "and eax, 38",
            "add r8, rax",
            "mov qword ptr [{out}], r8",
            "mov qword ptr [{out} + 8], r9",
            "mov qword ptr [{out} + 16], r10",
            "mov qword ptr [{out} + 24], r11",
            a = in(reg) a.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            t = out(reg) _,
            out("rax") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
            options(nostack),
        );
    }
}

/// `out = a + b` (partially reduced).
#[inline]
#[target_feature(enable = "bmi2,adx")]
fn add(out: &mut Fe4, a: &Fe4, b: &Fe4) {
    // SAFETY: `a`, `b` readable and `out` writable for 32 bytes; only
    // baseline instructions; clobbers declared; no stack use.
    unsafe {
        asm!(
            "mov r8, qword ptr [{a}]",
            "mov r9, qword ptr [{a} + 8]",
            "mov r10, qword ptr [{a} + 16]",
            "mov r11, qword ptr [{a} + 24]",
            "add r8, qword ptr [{b}]",
            "adc r9, qword ptr [{b} + 8]",
            "adc r10, qword ptr [{b} + 16]",
            "adc r11, qword ptr [{b} + 24]",
            // 2^256 = 38: add 38 per carry; a second carry leaves r8 < 38.
            "sbb rax, rax",
            "and eax, 38",
            "add r8, rax",
            "adc r9, 0",
            "adc r10, 0",
            "adc r11, 0",
            "sbb rax, rax",
            "and eax, 38",
            "add r8, rax",
            "mov qword ptr [{out}], r8",
            "mov qword ptr [{out} + 8], r9",
            "mov qword ptr [{out} + 16], r10",
            "mov qword ptr [{out} + 24], r11",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            out("rax") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            options(nostack),
        );
    }
}

/// `out = a - b` (partially reduced).
#[inline]
#[target_feature(enable = "bmi2,adx")]
fn sub(out: &mut Fe4, a: &Fe4, b: &Fe4) {
    // SAFETY: as for `add`.
    unsafe {
        asm!(
            "mov r8, qword ptr [{a}]",
            "mov r9, qword ptr [{a} + 8]",
            "mov r10, qword ptr [{a} + 16]",
            "mov r11, qword ptr [{a} + 24]",
            "sub r8, qword ptr [{b}]",
            "sbb r9, qword ptr [{b} + 8]",
            "sbb r10, qword ptr [{b} + 16]",
            "sbb r11, qword ptr [{b} + 24]",
            // A borrow added 2^256 = 38: subtract 38 per borrow (at most
            // twice; after a second borrow r8 >= 2^64 - 76).
            "sbb rax, rax",
            "and eax, 38",
            "sub r8, rax",
            "sbb r9, 0",
            "sbb r10, 0",
            "sbb r11, 0",
            "sbb rax, rax",
            "and eax, 38",
            "sub r8, rax",
            "mov qword ptr [{out}], r8",
            "mov qword ptr [{out} + 8], r9",
            "mov qword ptr [{out} + 16], r10",
            "mov qword ptr [{out} + 24], r11",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            out("rax") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            options(nostack),
        );
    }
}

/// `out = a * 121665` (the RFC 7748 `a24` constant).
#[inline]
#[target_feature(enable = "bmi2,adx")]
fn mul_a24(out: &mut Fe4, a: &Fe4) {
    // SAFETY: as for `mul` (MULX requires BMI2, detected by the caller).
    unsafe {
        asm!(
            "mov edx, 121665",
            "mulx r9, r8, qword ptr [{a}]",
            "mulx r10, rax, qword ptr [{a} + 8]",
            "add r9, rax",
            "mulx r11, rax, qword ptr [{a} + 16]",
            "adc r10, rax",
            "mulx rdx, rax, qword ptr [{a} + 24]",
            "adc r11, rax",
            "adc rdx, 0",
            // Fold the top word (< 2^17) times 38, then a possible carry.
            "imul rdx, rdx, 38",
            "add r8, rdx",
            "adc r9, 0",
            "adc r10, 0",
            "adc r11, 0",
            "sbb rax, rax",
            "and eax, 38",
            "add r8, rax",
            "mov qword ptr [{out}], r8",
            "mov qword ptr [{out} + 8], r9",
            "mov qword ptr [{out} + 16], r10",
            "mov qword ptr [{out} + 24], r11",
            a = in(reg) a.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            out("rax") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            options(nostack),
        );
    }
}

/// `out = a^(2^n)` for `n >= 1`.
#[inline]
#[target_feature(enable = "bmi2,adx")]
fn sqr_n(out: &mut Fe4, a: &Fe4, n: u32) {
    sqr(out, a);
    let mut t = [0u64; 4];
    for _ in 1..n {
        sqr(&mut t, out);
        *out = t;
    }
}

/// `a^(p-2)`.
#[target_feature(enable = "bmi2,adx")]
fn invert(a: &Fe4) -> Fe4 {
    let mut s = [0u64; 4];
    let (mut t0, mut t1, mut t2, mut t3, mut t5) = ([0u64; 4], [0; 4], [0; 4], [0; 4], [0; 4]);
    let (mut t7, mut t9, mut t11, mut t13, mut t15) = ([0u64; 4], [0; 4], [0; 4], [0; 4], [0; 4]);
    sqr(&mut t0, a); // 2
    sqr_n(&mut s, &t0, 2); // 8
    mul(&mut t2, a, &s); // 9
    mul(&mut t3, &t0, &t2); // 11
    sqr(&mut t1, &t3); // 22
    mul(&mut t5, &t2, &t1); // 2^5 - 1
    sqr_n(&mut s, &t5, 5);
    mul(&mut t7, &s, &t5); // 2^10 - 1
    sqr_n(&mut s, &t7, 10);
    mul(&mut t9, &s, &t7); // 2^20 - 1
    sqr_n(&mut s, &t9, 20);
    mul(&mut t11, &s, &t9); // 2^40 - 1
    sqr_n(&mut s, &t11, 10);
    mul(&mut t13, &s, &t7); // 2^50 - 1
    sqr_n(&mut s, &t13, 50);
    mul(&mut t15, &s, &t13); // 2^100 - 1
    sqr_n(&mut s, &t15, 100);
    mul(&mut t1, &s, &t15); // 2^200 - 1
    sqr_n(&mut s, &t1, 50);
    mul(&mut t0, &s, &t13); // 2^250 - 1
    sqr_n(&mut s, &t0, 5);
    mul(&mut t1, &s, &t3); // 2^255 - 21 = p - 2
    t1
}

/// Fully reduces and encodes.
fn to_bytes(a: &Fe4) -> [u8; 32] {
    const MASK63: u64 = (1 << 63) - 1;
    let mut r = *a;
    // Fold bit 255: value < 2^255 + 19 afterwards.
    let mut c = (r[3] >> 63) * 19;
    r[3] &= MASK63;
    for x in r.iter_mut() {
        let t = u128::from(*x) + u128::from(c);
        *x = t as u64;
        c = (t >> 64) as u64;
    }
    // If r >= p then r + 19 >= 2^255: take (r + 19) mod 2^255.
    let mut w = [0u64; 4];
    let mut c = 19u64;
    for (wi, x) in w.iter_mut().zip(r) {
        let t = u128::from(x) + u128::from(c);
        *wi = t as u64;
        c = (t >> 64) as u64;
    }
    let ge = opaque_mask(Choice::from_bit(w[3] >> 63));
    w[3] &= MASK63;
    cmov_u64(ge, &mut r, &w);
    let mut out = [0u8; 32];
    for (chunk, ri) in out.as_chunks_mut::<8>().0.iter_mut().zip(r) {
        *chunk = ri.to_le_bytes();
    }
    out
}

fn from_bytes(b: &[u8; 32]) -> Fe4 {
    let mut r = [0u64; 4];
    for (ri, chunk) in r.iter_mut().zip(b.as_chunks::<8>().0) {
        *ri = u64::from_le_bytes(*chunk);
    }
    r[3] &= (1 << 63) - 1; // RFC 7748: mask the most significant bit.
    r
}

#[target_feature(enable = "bmi2,adx")]
fn ladder(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = from_bytes(u);
    let mut x2: Fe4 = [1, 0, 0, 0];
    let mut z2: Fe4 = [0; 4];
    let mut x3 = x1;
    let mut z3: Fe4 = [1, 0, 0, 0];
    // Temporaries: A, AA, B, BB, E, C, D, DA, CB, t1, t2.
    let mut tmp = [[0u64; 4]; 11];
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= kt;
        let m = opaque_mask(Choice::from_bit(swap));
        cswap_u64(m, &mut x2, &mut x3);
        cswap_u64(m, &mut z2, &mut z3);
        swap = kt;
        // Independent operations are grouped so that the out-of-order core
        // can overlap them (asm blocks are not reordered by the compiler).
        let [a, aa, b, bb, e, c, d, da, cb, t1, t2] = &mut tmp;
        add(a, &x2, &z2);
        sub(b, &x2, &z2);
        add(c, &x3, &z3);
        sub(d, &x3, &z3);
        mul(da, d, a);
        mul(cb, c, b);
        sqr(aa, a);
        sqr(bb, b);
        add(t1, da, cb);
        sub(t2, da, cb);
        sub(e, aa, bb);
        mul(&mut x2, aa, bb);
        sqr(&mut x3, t1);
        sqr(d, t2);
        mul_a24(t1, e);
        add(t2, aa, t1);
        mul(&mut z3, &x1, d);
        mul(&mut z2, e, t2);
    }
    let m = opaque_mask(Choice::from_bit(swap));
    cswap_u64(m, &mut x2, &mut x3);
    cswap_u64(m, &mut z2, &mut z3);
    let mut zi = invert(&z2);
    let mut r = [0u64; 4];
    mul(&mut r, &x2, &zi);
    let out = to_bytes(&r);
    for v in [&mut x2, &mut z2, &mut x3, &mut z3, &mut r, &mut zi] {
        zeroize_u64(v);
    }
    zeroize_u64(tmp.as_flattened_mut());
    out
}

/// X25519 with an already clamped scalar.
///
/// # Panics
///
/// Panics if BMI2 or ADX is unavailable (a dispatch bug, never input-driven).
pub(super) fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let f = crate::cpu::features();
    assert!(
        f.x86_bmi2() && f.x86_adx(),
        "BMI2/ADX backend without CPU support"
    );
    // SAFETY: BMI2 and ADX support was verified at run time just above.
    unsafe { ladder(k, u) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available() -> bool {
        let f = crate::cpu::features();
        f.x86_bmi2() && f.x86_adx()
    }

    fn rand(st: &mut u64) -> Fe4 {
        let mut r = [0u64; 4];
        for x in r.iter_mut() {
            *st ^= *st << 13;
            *st ^= *st >> 7;
            *st ^= *st << 17;
            *x = *st;
        }
        r
    }

    #[target_feature(enable = "bmi2,adx")]
    fn all_ops(a: &Fe4, b: &Fe4) -> [Fe4; 5] {
        let mut r = [[0u64; 4]; 5];
        mul(&mut r[0], a, b);
        sqr(&mut r[1], a);
        add(&mut r[2], a, b);
        sub(&mut r[3], a, b);
        mul_a24(&mut r[4], a);
        r
    }

    #[target_feature(enable = "bmi2,adx")]
    fn invert_check(a: &Fe4) -> Fe4 {
        let mut one = [0u64; 4];
        mul(&mut one, &invert(a), a);
        one
    }

    /// Compares against the portable radix-2^51 field on random 256-bit
    /// inputs, including all-ones limbs and values near p and 2^256.
    #[test]
    fn field_ops_match_portable() {
        use super::super::field::Fe;
        if !available() {
            return;
        }
        let to_fe = |a: &Fe4| {
            // a = lo255 + bit255 * 2^255 = lo255 + bit255 * 19 (mod p).
            let mut b = [0u8; 32];
            for (c, w) in b.as_chunks_mut::<8>().0.iter_mut().zip(a) {
                *c = w.to_le_bytes();
            }
            let lo = Fe::from_bytes(&b);
            let hi = Fe([19 * (a[3] >> 63), 0, 0, 0, 0]);
            lo.add(&hi)
        };
        let mut st = 0x9e37_79b9_7f4a_7c15u64;
        let mut vals = std::vec![
            [0; 4],
            [u64::MAX; 4],
            [u64::MAX - 18, u64::MAX, u64::MAX, u64::MAX >> 1],
            [u64::MAX - 19, u64::MAX, u64::MAX, u64::MAX >> 1],
            [u64::MAX - 17, u64::MAX, u64::MAX, u64::MAX >> 1],
            [37, 0, 0, 0],
            [u64::MAX - 37, u64::MAX, u64::MAX, u64::MAX],
        ];
        for _ in 0..2000 {
            vals.push(rand(&mut st));
        }
        for w in vals.windows(2) {
            let (a, b) = (&w[0], &w[1]);
            let (fa, fb) = (to_fe(a), to_fe(b));
            // SAFETY: BMI2/ADX availability checked above.
            let r = unsafe { all_ops(a, b) };
            assert_eq!(to_bytes(&r[0]), fa.mul(&fb).to_bytes());
            assert_eq!(to_bytes(&r[1]), fa.square().to_bytes());
            assert_eq!(to_bytes(&r[2]), fa.add(&fb).to_bytes());
            assert_eq!(to_bytes(&r[3]), fa.sub(&fb).to_bytes());
            assert_eq!(to_bytes(&r[4]), fa.mul_small(121_665).to_bytes());
            assert_eq!(to_bytes(a), fa.to_bytes());
        }
        // SAFETY: BMI2/ADX availability checked above.
        let one = unsafe { invert_check(&vals[10]) };
        assert_eq!(to_bytes(&one), Fe::ONE.to_bytes());
    }
}
