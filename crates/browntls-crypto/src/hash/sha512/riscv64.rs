//! SHA-512 on riscv64: vector crypto (Zvknhb + Zvkb) and scalar crypto
//! (Zknh, RV64 forms).
//!
//! Neither RVV nor the scalar-crypto intrinsics are available on stable
//! Rust, so the instructions are emitted with inline assembly assembled under
//! `.option arch, +...`.
#![allow(unsafe_code)]

use core::arch::asm;

use super::{K, soft};
use crate::cpu::{self, Features};

pub(super) fn zvknhb_available(f: Features) -> bool {
    f.rv_v() && f.rv_zvknhb() && f.rv_zvkb()
}

pub(super) fn zknh_available(f: Features) -> bool {
    f.rv_zknh()
}

/// Assembly text for one quad-round with schedule update (SEW=64, LMUL=2,
/// so every operand is an even register group). `$w` holds W[i..i+4], `$w1`,
/// `$w2`, `$w3` the following three groups. Uses v18 (merged operand), v20
/// (W + K) and v22 (K, loaded from `{kp}`).
macro_rules! quad {
    ($w:literal, $w1:literal, $w2:literal, $w3:literal) => {
        concat!(
            "vle64.v v22, ({kp})\n",
            "addi {kp}, {kp}, 32\n",
            "vadd.vv v20, ",
            $w,
            ", v22\n",
            "vsha2cl.vv v4, v2, v20\n",
            "vsha2ch.vv v2, v4, v20\n",
            "vmerge.vvm v18, ",
            $w2,
            ", ",
            $w1,
            ", v0\n",
            "vsha2ms.vv ",
            $w,
            ", v18, ",
            $w3,
        )
    };
}

/// Quad-round without schedule update (the last four quads).
macro_rules! quad_last {
    ($w:literal) => {
        concat!(
            "vle64.v v22, ({kp})\n",
            "addi {kp}, {kp}, 32\n",
            "vadd.vv v20, ",
            $w,
            ", v22\n",
            "vsha2cl.vv v4, v2, v20\n",
            "vsha2ch.vv v2, v4, v20",
        )
    };
}

/// Compresses `blocks` with Zvknhb, or with [`soft`] if unavailable.
pub(super) fn compress_zvknhb(state: &mut [u64; 8], blocks: &[u8]) {
    if !zvknhb_available(cpu::features()) {
        soft::compress(state, blocks);
        return;
    }
    let n = blocks.len() / 128;
    if n == 0 {
        return;
    }
    // Element-group layout {a,b,e,f}, {c,d,g,h} with `a` in the highest
    // element.
    let [a, b, c, d, e, f, g, h] = *state;
    let mut st = [f, e, b, a, h, g, d, c];
    // SAFETY: RVV 1.0, Zvknhb and Zvkb were detected at run time. With
    // LMUL=2 a register group holds the 256-bit element group for any
    // VLEN >= 128. `st` is 64 readable/writable bytes; `blocks` holds
    // `n * 128` readable bytes and the loop reads exactly that; each block
    // reads all 640 bytes of `K` once. Every vector register is declared
    // clobbered.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v, +zvknhb, +zvkb",
            "vsetivli zero, 4, e64, m2, ta, ma",
            "vmv.v.i v0, 1",
            "vle64.v v2, ({st})",
            "addi {t}, {st}, 32",
            "vle64.v v4, ({t})",
            "2:",
            "vmv.v.v v6, v2",
            "vmv.v.v v8, v4",
            "vle64.v v10, ({p})", "addi {p}, {p}, 32",
            "vle64.v v12, ({p})", "addi {p}, {p}, 32",
            "vle64.v v14, ({p})", "addi {p}, {p}, 32",
            "vle64.v v16, ({p})", "addi {p}, {p}, 32",
            "vrev8.v v10, v10",
            "vrev8.v v12, v12",
            "vrev8.v v14, v14",
            "vrev8.v v16, v16",
            "mv {kp}, {k}",
            quad!("v10", "v12", "v14", "v16"),
            quad!("v12", "v14", "v16", "v10"),
            quad!("v14", "v16", "v10", "v12"),
            quad!("v16", "v10", "v12", "v14"),
            quad!("v10", "v12", "v14", "v16"),
            quad!("v12", "v14", "v16", "v10"),
            quad!("v14", "v16", "v10", "v12"),
            quad!("v16", "v10", "v12", "v14"),
            quad!("v10", "v12", "v14", "v16"),
            quad!("v12", "v14", "v16", "v10"),
            quad!("v14", "v16", "v10", "v12"),
            quad!("v16", "v10", "v12", "v14"),
            quad!("v10", "v12", "v14", "v16"),
            quad!("v12", "v14", "v16", "v10"),
            quad!("v14", "v16", "v10", "v12"),
            quad!("v16", "v10", "v12", "v14"),
            quad_last!("v10"),
            quad_last!("v12"),
            quad_last!("v14"),
            quad_last!("v16"),
            "vadd.vv v2, v2, v6",
            "vadd.vv v4, v4, v8",
            "addi {n}, {n}, -1",
            "bnez {n}, 2b",
            "vse64.v v2, ({st})",
            "addi {t}, {st}, 32",
            "vse64.v v4, ({t})",
            ".option pop",
            st = in(reg) st.as_mut_ptr(),
            k = in(reg) K.as_ptr(),
            kp = out(reg) _,
            p = inout(reg) blocks.as_ptr() => _,
            n = inout(reg) n => _,
            t = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack),
        );
    }
    let [f, e, b, a, h, g, d, c] = st;
    *state = [a, b, c, d, e, f, g, h];
}

// --- Scalar Zknh ---------------------------------------------------------

macro_rules! zknh_op {
    ($name:ident, $insn:literal) => {
        /// The RV64 Zknh instruction of the same name.
        #[target_feature(enable = "zknh")]
        #[inline]
        fn $name(x: u64) -> u64 {
            let r: u64;
            // SAFETY: Zknh is enabled for this function, so it is only
            // (safely) callable from code compiled for Zknh, which is only
            // entered after detection. Register-only instruction.
            unsafe {
                asm!(
                    ".option push",
                    ".option arch, +zknh",
                    concat!($insn, " {r}, {x}"),
                    ".option pop",
                    r = lateout(reg) r,
                    x = in(reg) x,
                    options(pure, nomem, nostack, preserves_flags),
                );
            }
            r
        }
    };
}

zknh_op!(sig0, "sha512sig0");
zknh_op!(sig1, "sha512sig1");
zknh_op!(sum0, "sha512sum0");
zknh_op!(sum1, "sha512sum1");

#[target_feature(enable = "zknh")]
fn compress_zknh_inner(state: &mut [u64; 8], blocks: &[u8]) {
    for block in blocks.as_chunks::<128>().0 {
        let mut w = [0u64; 80];
        for (i, word) in block.as_chunks::<8>().0.iter().enumerate() {
            w[i] = u64::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = w[i - 16]
                .wrapping_add(sig0(w[i - 15]))
                .wrapping_add(w[i - 7])
                .wrapping_add(sig1(w[i - 2]));
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..80 {
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(sum1(e))
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = sum0(a).wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// Compresses `blocks` with Zknh, or with [`soft`] if unavailable.
pub(super) fn compress_zknh(state: &mut [u64; 8], blocks: &[u8]) {
    if zknh_available(cpu::features()) {
        // SAFETY: Zknh was detected at run time (or asserted at build time).
        unsafe { compress_zknh_inner(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}
