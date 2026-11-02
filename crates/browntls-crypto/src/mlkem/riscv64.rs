//! riscv64 RVV 1.0 backend: NTT, inverse NTT, base multiplication and
//! reductions with SEW = 16 (`vmulh.vv` / `vmul.vv` Montgomery arithmetic).
//!
//! The kernels are vector-length agnostic: every loop strip-mines with
//! `vsetvli`, so they are correct for any VLEN (tested with 128, 256 and
//! 1024). NTT layers with long runs of butterflies sharing one zeta
//! (`len >= 16`) use unit-stride accesses with a scalar zeta; the short
//! layers (`len <= 8`) gather one butterfly per block with strided accesses
//! and a vector of per-block zetas. Base multiplication uses two-field
//! segment loads to de-interleave coefficient pairs.
//!
//! Montgomery multiplication is `vmulh(a, b) - vmulh(vmul(a, b q^-1), q)`
//! and Barrett reduction `a - q * ((vmulh(a, 20159) + 512) >> 10)`, both
//! bit-identical to the portable backend. The code is written with inline
//! assembly (RVV intrinsics are not available on stable Rust) and is only
//! entered after RVV 1.0 was detected.
#![allow(unsafe_code)]

use core::arch::asm;

use super::poly::{
    BARRETT_V, GAMMAS, GAMMAS_QINV, INVNTT_F, MONT_R2, N, Poly, Q, QINV, ZETAS, ZETAS_QINV,
};

const fn i(x: i16) -> isize {
    x as isize
}

/// Cooley-Tukey butterflies `a[j] += t, b[j] = a[j] - t` with
/// `t = zeta * b[j]`, for `n` elements at unit stride.
///
/// # Safety
///
/// RVV 1.0 must be available, `a` and `b` must be valid for `n` `i16` reads
/// and writes, and the ranges must not overlap.
unsafe fn ct_vx(a: *mut i16, b: *mut i16, n: usize, z: i16, zq: i16) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v",
            "2:",
            "vsetvli {vl}, {n}, e16, m4, ta, ma",
            "vle16.v v0, ({a})",
            "vle16.v v4, ({b})",
            "vmulh.vx v8, v4, {z}",
            "vmul.vx v12, v4, {zq}",
            "vmulh.vx v12, v12, {q}",
            "vsub.vv v8, v8, v12",
            "vsub.vv v4, v0, v8",
            "vadd.vv v0, v0, v8",
            "vse16.v v0, ({a})",
            "vse16.v v4, ({b})",
            "sub {n}, {n}, {vl}",
            "slli {vl}, {vl}, 1",
            "add {a}, {a}, {vl}",
            "add {b}, {b}, {vl}",
            "bnez {n}, 2b",
            ".option pop",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            n = inout(reg) n => _,
            vl = out(reg) _,
            z = in(reg) i(z),
            zq = in(reg) i(zq),
            q = in(reg) i(Q),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            options(nostack),
        );
    }
}

/// Cooley-Tukey butterflies on `n` strided pairs `(a[j s], b[j s])` with
/// zetas `zp[j]` (`zqp[j] = zp[j] q^-1`); `stride` is in bytes.
///
/// # Safety
///
/// RVV 1.0 must be available; `a + j stride` and `b + j stride` must be valid,
/// distinct `i16` locations for `j < n`, and `zp`, `zqp` valid for `n` reads.
unsafe fn ct_strided(
    a: *mut i16,
    b: *mut i16,
    stride: usize,
    zp: *const i16,
    zqp: *const i16,
    n: usize,
) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v",
            "2:",
            "vsetvli {vl}, {n}, e16, m4, ta, ma",
            "vlse16.v v0, ({a}), {s}",
            "vlse16.v v4, ({b}), {s}",
            "vle16.v v8, ({zp})",
            "vle16.v v12, ({zqp})",
            "vmulh.vv v16, v4, v8",
            "vmul.vv v20, v4, v12",
            "vmulh.vx v20, v20, {q}",
            "vsub.vv v16, v16, v20",
            "vsub.vv v4, v0, v16",
            "vadd.vv v0, v0, v16",
            "vsse16.v v0, ({a}), {s}",
            "vsse16.v v4, ({b}), {s}",
            "sub {n}, {n}, {vl}",
            "mul {t}, {vl}, {s}",
            "add {a}, {a}, {t}",
            "add {b}, {b}, {t}",
            "slli {vl}, {vl}, 1",
            "add {zp}, {zp}, {vl}",
            "add {zqp}, {zqp}, {vl}",
            "bnez {n}, 2b",
            ".option pop",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            zp = inout(reg) zp => _,
            zqp = inout(reg) zqp => _,
            n = inout(reg) n => _,
            s = in(reg) stride,
            vl = out(reg) _,
            t = out(reg) _,
            q = in(reg) i(Q),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack),
        );
    }
}

/// Gentleman-Sande butterflies `a[j] = barrett(a[j] + b[j])`,
/// `b[j] = zeta (b[j] - a[j])` for `n` elements at unit stride.
///
/// # Safety
///
/// As for [`ct_vx`].
unsafe fn gs_vx(a: *mut i16, b: *mut i16, n: usize, z: i16, zq: i16) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v",
            "2:",
            "vsetvli {vl}, {n}, e16, m4, ta, ma",
            "vle16.v v0, ({a})",
            "vle16.v v4, ({b})",
            "vadd.vv v8, v0, v4",
            "vsub.vv v12, v4, v0",
            "vmulh.vx v16, v8, {bv}",
            "vadd.vx v16, v16, {r}",
            "vsra.vi v16, v16, 10",
            "vnmsac.vx v8, {q}, v16",
            "vmulh.vx v16, v12, {z}",
            "vmul.vx v20, v12, {zq}",
            "vmulh.vx v20, v20, {q}",
            "vsub.vv v12, v16, v20",
            "vse16.v v8, ({a})",
            "vse16.v v12, ({b})",
            "sub {n}, {n}, {vl}",
            "slli {vl}, {vl}, 1",
            "add {a}, {a}, {vl}",
            "add {b}, {b}, {vl}",
            "bnez {n}, 2b",
            ".option pop",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            n = inout(reg) n => _,
            vl = out(reg) _,
            z = in(reg) i(z),
            zq = in(reg) i(zq),
            q = in(reg) i(Q),
            bv = in(reg) i(BARRETT_V),
            r = in(reg) 512isize,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack),
        );
    }
}

/// Gentleman-Sande butterflies on strided pairs (see [`ct_strided`]).
///
/// # Safety
///
/// As for [`ct_strided`].
unsafe fn gs_strided(
    a: *mut i16,
    b: *mut i16,
    stride: usize,
    zp: *const i16,
    zqp: *const i16,
    n: usize,
) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v",
            "2:",
            "vsetvli {vl}, {n}, e16, m4, ta, ma",
            "vlse16.v v0, ({a}), {s}",
            "vlse16.v v4, ({b}), {s}",
            "vle16.v v24, ({zp})",
            "vle16.v v28, ({zqp})",
            "vadd.vv v8, v0, v4",
            "vsub.vv v12, v4, v0",
            "vmulh.vx v16, v8, {bv}",
            "vadd.vx v16, v16, {r}",
            "vsra.vi v16, v16, 10",
            "vnmsac.vx v8, {q}, v16",
            "vmulh.vv v16, v12, v24",
            "vmul.vv v20, v12, v28",
            "vmulh.vx v20, v20, {q}",
            "vsub.vv v12, v16, v20",
            "vsse16.v v8, ({a}), {s}",
            "vsse16.v v12, ({b}), {s}",
            "sub {n}, {n}, {vl}",
            "mul {t}, {vl}, {s}",
            "add {a}, {a}, {t}",
            "add {b}, {b}, {t}",
            "slli {vl}, {vl}, 1",
            "add {zp}, {zp}, {vl}",
            "add {zqp}, {zqp}, {vl}",
            "bnez {n}, 2b",
            ".option pop",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            zp = inout(reg) zp => _,
            zqp = inout(reg) zqp => _,
            n = inout(reg) n => _,
            s = in(reg) stride,
            vl = out(reg) _,
            t = out(reg) _,
            q = in(reg) i(Q),
            bv = in(reg) i(BARRETT_V),
            r = in(reg) 512isize,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            options(nostack),
        );
    }
}

/// Barrett-reduces all 256 coefficients of `p`.
///
/// # Safety
///
/// RVV 1.0 must be available.
unsafe fn barrett_all(p: &mut Poly) {
    // SAFETY: the caller guarantees RVV 1.0; the loop touches exactly the 256
    // coefficients of `p`.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v",
            "2:",
            "vsetvli {vl}, {n}, e16, m4, ta, ma",
            "vle16.v v0, ({a})",
            "vmulh.vx v4, v0, {bv}",
            "vadd.vx v4, v4, {r}",
            "vsra.vi v4, v4, 10",
            "vnmsac.vx v0, {q}, v4",
            "vse16.v v0, ({a})",
            "sub {n}, {n}, {vl}",
            "slli {vl}, {vl}, 1",
            "add {a}, {a}, {vl}",
            "bnez {n}, 2b",
            ".option pop",
            a = inout(reg) p.0.as_mut_ptr() => _,
            n = inout(reg) N => _,
            vl = out(reg) _,
            q = in(reg) i(Q),
            bv = in(reg) i(BARRETT_V),
            r = in(reg) 512isize,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            options(nostack),
        );
    }
}

/// Multiplies all coefficients of `p` by `c 2^-16` (`cq = c q^-1`).
///
/// # Safety
///
/// RVV 1.0 must be available.
unsafe fn mul_const(p: &mut Poly, c: i16, cq: i16) {
    // SAFETY: the caller guarantees RVV 1.0; the loop touches exactly the 256
    // coefficients of `p`.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v",
            "2:",
            "vsetvli {vl}, {n}, e16, m4, ta, ma",
            "vle16.v v0, ({a})",
            "vmulh.vx v4, v0, {c}",
            "vmul.vx v8, v0, {cq}",
            "vmulh.vx v8, v8, {q}",
            "vsub.vv v0, v4, v8",
            "vse16.v v0, ({a})",
            "sub {n}, {n}, {vl}",
            "slli {vl}, {vl}, 1",
            "add {a}, {a}, {vl}",
            "bnez {n}, 2b",
            ".option pop",
            a = inout(reg) p.0.as_mut_ptr() => _,
            n = inout(reg) N => _,
            vl = out(reg) _,
            c = in(reg) i(c),
            cq = in(reg) i(cq),
            q = in(reg) i(Q),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            options(nostack),
        );
    }
}

/// `r += a o b` (NTT-domain base multiplication, scaled by `2^-16`).
///
/// # Safety
///
/// RVV 1.0 must be available.
unsafe fn basemul_add(r: &mut Poly, a: &Poly, b: &Poly) {
    // SAFETY: the caller guarantees RVV 1.0. The loop processes exactly the
    // 128 coefficient pairs of `r`, `a`, `b` (two-field segment accesses of
    // 4 bytes each) and the 128 entries of the gamma tables.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v",
            "2:",
            "vsetvli {vl}, {n}, e16, m2, ta, ma",
            "vlseg2e16.v v0, ({a})",
            "vlseg2e16.v v4, ({b})",
            "vlseg2e16.v v8, ({r})",
            "vle16.v v12, ({g})",
            "vle16.v v14, ({gq})",
            // a1 b1 gamma
            "vmulh.vv v16, v2, v6",
            "vmul.vv v18, v2, v6",
            "vmul.vx v18, v18, {qinv}",
            "vmulh.vx v18, v18, {q}",
            "vsub.vv v16, v16, v18",
            "vmulh.vv v18, v16, v12",
            "vmul.vv v20, v16, v14",
            "vmulh.vx v20, v20, {q}",
            "vsub.vv v16, v18, v20",
            "vadd.vv v8, v8, v16",
            // a0 b0
            "vmulh.vv v16, v0, v4",
            "vmul.vv v18, v0, v4",
            "vmul.vx v18, v18, {qinv}",
            "vmulh.vx v18, v18, {q}",
            "vsub.vv v16, v16, v18",
            "vadd.vv v8, v8, v16",
            // a0 b1
            "vmulh.vv v16, v0, v6",
            "vmul.vv v18, v0, v6",
            "vmul.vx v18, v18, {qinv}",
            "vmulh.vx v18, v18, {q}",
            "vsub.vv v16, v16, v18",
            "vadd.vv v10, v10, v16",
            // a1 b0
            "vmulh.vv v16, v2, v4",
            "vmul.vv v18, v2, v4",
            "vmul.vx v18, v18, {qinv}",
            "vmulh.vx v18, v18, {q}",
            "vsub.vv v16, v16, v18",
            "vadd.vv v10, v10, v16",
            "vsseg2e16.v v8, ({r})",
            "sub {n}, {n}, {vl}",
            "slli {vl}, {vl}, 1",
            "add {g}, {g}, {vl}",
            "add {gq}, {gq}, {vl}",
            "slli {vl}, {vl}, 1",
            "add {a}, {a}, {vl}",
            "add {b}, {b}, {vl}",
            "add {r}, {r}, {vl}",
            "bnez {n}, 2b",
            ".option pop",
            r = inout(reg) r.0.as_mut_ptr() => _,
            a = inout(reg) a.0.as_ptr() => _,
            b = inout(reg) b.0.as_ptr() => _,
            g = inout(reg) GAMMAS.as_ptr() => _,
            gq = inout(reg) GAMMAS_QINV.as_ptr() => _,
            n = inout(reg) N / 2 => _,
            vl = out(reg) _,
            q = in(reg) i(Q),
            qinv = in(reg) i(QINV),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _,
            options(nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// Entry points. Callers hold an `Engine` for `Backend::Rvv`, which is only
// constructed after RVV 1.0 was detected (see `backend::Engine`).
// ---------------------------------------------------------------------------

/// One NTT layer: butterflies between `r[start + j]` and `r[start + j + len]`.
fn layer(p: &mut Poly, len: usize, inverse: bool) {
    let nblocks = N / (2 * len);
    let base = p.0.as_mut_ptr();
    if len >= 16 {
        let bfly: unsafe fn(*mut i16, *mut i16, usize, i16, i16) =
            if inverse { gs_vx } else { ct_vx };
        for blk in 0..nblocks {
            let k = if inverse {
                256 / len - 1 - blk
            } else {
                nblocks + blk
            };
            let start = 2 * len * blk;
            let a = base.wrapping_add(start);
            let b = base.wrapping_add(start + len);
            // SAFETY: RVV 1.0 is available (Engine invariant); `a` and `b`
            // address the disjoint ranges `[start, start + len)` and
            // `[start + len, start + 2 len)` of the 256-element array.
            unsafe { bfly(a, b, len, ZETAS[k], ZETAS_QINV[k]) };
        }
    } else {
        // Block `blk` uses ZETAS[nblocks + blk] (forward) or
        // ZETAS[2 nblocks - 1 - blk] (inverse); the inverse order is stored
        // reversed in `INV_ZETAS` so both are unit-stride vectors.
        let (z, zq) = if inverse {
            (
                &INV_ZETAS.0[nblocks..2 * nblocks],
                &INV_ZETAS.1[nblocks..2 * nblocks],
            )
        } else {
            (
                &ZETAS[nblocks..2 * nblocks],
                &ZETAS_QINV[nblocks..2 * nblocks],
            )
        };
        let stride = 2 * len * size_of::<i16>();
        let bfly: unsafe fn(*mut i16, *mut i16, usize, *const i16, *const i16, usize) =
            if inverse { gs_strided } else { ct_strided };
        for o in 0..len {
            let a = base.wrapping_add(o);
            let b = base.wrapping_add(o + len);
            // SAFETY: RVV 1.0 is available (Engine invariant). The accessed
            // elements are `o + 2 len j` and `o + len + 2 len j` for
            // `j < nblocks`; the largest is `o + len + 256 - 2 len < 256`
            // because `o < len`, and the two sets are disjoint. `z` and `zq`
            // hold `nblocks` entries.
            unsafe { bfly(a, b, stride, z.as_ptr(), zq.as_ptr(), nblocks) };
        }
    }
}

/// `INV_ZETAS.0[n + j] = ZETAS[2 n - 1 - j]` for each power of two `n`, and
/// `.1` the same for `ZETAS_QINV`.
static INV_ZETAS: ([i16; 128], [i16; 128]) = {
    let mut t = ([0i16; 128], [0i16; 128]);
    let mut n = 1;
    while n < 128 {
        let mut j = 0;
        while j < n {
            t.0[n + j] = ZETAS[2 * n - 1 - j];
            t.1[n + j] = ZETAS_QINV[2 * n - 1 - j];
            j += 1;
        }
        n *= 2;
    }
    t
};

pub(super) fn ntt(p: &mut Poly) {
    for len in [128, 64, 32, 16, 8, 4, 2] {
        layer(p, len, false);
    }
    reduce(p);
}

pub(super) fn invntt(p: &mut Poly) {
    for len in [2, 4, 8, 16, 32, 64, 128] {
        layer(p, len, true);
    }
    // SAFETY: RVV 1.0 is available (Engine invariant).
    unsafe { mul_const(p, INVNTT_F, INVNTT_F.wrapping_mul(QINV)) };
}

pub(super) fn basemul_acc(r: &mut Poly, a: &[Poly], b: &[Poly]) {
    *r = Poly::ZERO;
    for (x, y) in a.iter().zip(b) {
        // SAFETY: RVV 1.0 is available (Engine invariant).
        unsafe { basemul_add(r, x, y) };
    }
    reduce(r);
}

pub(super) fn reduce(p: &mut Poly) {
    // SAFETY: RVV 1.0 is available (Engine invariant).
    unsafe { barrett_all(p) };
}

pub(super) fn tomont(p: &mut Poly) {
    // SAFETY: RVV 1.0 is available (Engine invariant).
    unsafe { mul_const(p, MONT_R2, MONT_R2.wrapping_mul(QINV)) };
}
