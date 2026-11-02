//! SHA-256 on riscv64: vector crypto (Zvknha + Zvkb) and scalar crypto
//! (Zknh).
//!
//! Neither RVV nor the scalar-crypto intrinsics are available on stable
//! Rust, so the instructions are emitted with inline assembly assembled under
//! `.option arch, +...`.
#![allow(unsafe_code)]

use core::arch::asm;

use super::{K, soft};
use crate::cpu::{self, Features};

pub(super) fn zvknha_available(f: Features) -> bool {
    f.rv_v() && f.rv_zvknha() && f.rv_zvkb()
}

pub(super) fn zknh_available(f: Features) -> bool {
    f.rv_zknh()
}

/// Assembly text for one quad-round with schedule update. `$w` holds
/// W[i..i+4], `$w1`, `$w2`, `$w3` the following three groups, `$k` the
/// constants. Uses v9 (merged operand) and v10 (W + K).
macro_rules! quad {
    ($w:literal, $k:literal, $w1:literal, $w2:literal, $w3:literal) => {
        concat!(
            "vadd.vv v10, ",
            $w,
            ", ",
            $k,
            "\n",
            "vsha2cl.vv v2, v1, v10\n",
            "vsha2ch.vv v1, v2, v10\n",
            "vmerge.vvm v9, ",
            $w2,
            ", ",
            $w1,
            ", v0\n",
            "vsha2ms.vv ",
            $w,
            ", v9, ",
            $w3,
        )
    };
}

/// Quad-round without schedule update (the last four quads).
macro_rules! quad_last {
    ($w:literal, $k:literal) => {
        concat!(
            "vadd.vv v10, ",
            $w,
            ", ",
            $k,
            "\n",
            "vsha2cl.vv v2, v1, v10\n",
            "vsha2ch.vv v1, v2, v10",
        )
    };
}

/// Compresses `blocks` with Zvknha, or with [`soft`] if unavailable.
pub(super) fn compress_zvknha(state: &mut [u32; 8], blocks: &[u8]) {
    if !zvknha_available(cpu::features()) {
        soft::compress(state, blocks);
        return;
    }
    let n = blocks.len() / 64;
    if n == 0 {
        return;
    }
    // vsha2c[hl] operate on element groups {a,b,e,f} and {c,d,g,h} with `a`
    // in the highest element: lay the state out as [f, e, b, a, h, g, d, c].
    let [a, b, c, d, e, f, g, h] = *state;
    let mut st = [f, e, b, a, h, g, d, c];
    // SAFETY: RVV 1.0, Zvknha and Zvkb were detected at run time (VLEN >= 128
    // is implied by V, so one e32/m1 register holds the 4-element group).
    // `st` is 32 readable/writable bytes; `blocks` holds `n * 64` readable
    // bytes and the loop reads exactly that; `K` is 256 readable bytes. Every
    // vector register is declared clobbered.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +v, +zvknha, +zvkb",
            "vsetivli zero, 4, e32, m1, ta, ma",
            // v0 = mask selecting element 0 (for vmerge).
            "vmv.v.i v0, 1",
            "vle32.v v1, ({st})",
            "addi {t}, {st}, 16",
            "vle32.v v2, ({t})",
            // K[0..64] in v16..v31.
            "mv {t}, {k}",
            "vle32.v v16, ({t})", "addi {t}, {t}, 16",
            "vle32.v v17, ({t})", "addi {t}, {t}, 16",
            "vle32.v v18, ({t})", "addi {t}, {t}, 16",
            "vle32.v v19, ({t})", "addi {t}, {t}, 16",
            "vle32.v v20, ({t})", "addi {t}, {t}, 16",
            "vle32.v v21, ({t})", "addi {t}, {t}, 16",
            "vle32.v v22, ({t})", "addi {t}, {t}, 16",
            "vle32.v v23, ({t})", "addi {t}, {t}, 16",
            "vle32.v v24, ({t})", "addi {t}, {t}, 16",
            "vle32.v v25, ({t})", "addi {t}, {t}, 16",
            "vle32.v v26, ({t})", "addi {t}, {t}, 16",
            "vle32.v v27, ({t})", "addi {t}, {t}, 16",
            "vle32.v v28, ({t})", "addi {t}, {t}, 16",
            "vle32.v v29, ({t})", "addi {t}, {t}, 16",
            "vle32.v v30, ({t})", "addi {t}, {t}, 16",
            "vle32.v v31, ({t})",
            "2:",
            "vmv.v.v v3, v1",
            "vmv.v.v v4, v2",
            // Message words W[0..16] in v5..v8, byte-swapped to big endian.
            "vle32.v v5, ({p})", "addi {p}, {p}, 16",
            "vle32.v v6, ({p})", "addi {p}, {p}, 16",
            "vle32.v v7, ({p})", "addi {p}, {p}, 16",
            "vle32.v v8, ({p})", "addi {p}, {p}, 16",
            "vrev8.v v5, v5",
            "vrev8.v v6, v6",
            "vrev8.v v7, v7",
            "vrev8.v v8, v8",
            // Quad-round: v10 = W + K; two rounds each with vsha2cl (low
            // words) and vsha2ch (high words); then, for the first 12 quads,
            // W[i+16..i+20] = vsha2ms(W[i..], {W[i+9..i+12], W[i+4]},
            // W[i+12..]).
            quad!("v5", "v16", "v6", "v7", "v8"),
            quad!("v6", "v17", "v7", "v8", "v5"),
            quad!("v7", "v18", "v8", "v5", "v6"),
            quad!("v8", "v19", "v5", "v6", "v7"),
            quad!("v5", "v20", "v6", "v7", "v8"),
            quad!("v6", "v21", "v7", "v8", "v5"),
            quad!("v7", "v22", "v8", "v5", "v6"),
            quad!("v8", "v23", "v5", "v6", "v7"),
            quad!("v5", "v24", "v6", "v7", "v8"),
            quad!("v6", "v25", "v7", "v8", "v5"),
            quad!("v7", "v26", "v8", "v5", "v6"),
            quad!("v8", "v27", "v5", "v6", "v7"),
            quad_last!("v5", "v28"),
            quad_last!("v6", "v29"),
            quad_last!("v7", "v30"),
            quad_last!("v8", "v31"),
            "vadd.vv v1, v1, v3",
            "vadd.vv v2, v2, v4",
            "addi {n}, {n}, -1",
            "bnez {n}, 2b",
            "vse32.v v1, ({st})",
            "addi {t}, {st}, 16",
            "vse32.v v2, ({t})",
            ".option pop",
            st = in(reg) st.as_mut_ptr(),
            k = in(reg) K.as_ptr(),
            p = inout(reg) blocks.as_ptr() => _,
            n = inout(reg) n => _,
            t = out(reg) _,
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
    let [f, e, b, a, h, g, d, c] = st;
    *state = [a, b, c, d, e, f, g, h];
}

// --- Scalar Zknh ---------------------------------------------------------

macro_rules! zknh_op {
    ($name:ident, $insn:literal) => {
        /// The Zknh instruction of the same name (low 32 bits of the
        /// result).
        #[target_feature(enable = "zknh")]
        #[inline]
        fn $name(x: u32) -> u32 {
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
                    x = in(reg) u64::from(x),
                    options(pure, nomem, nostack, preserves_flags),
                );
            }
            // The RV64 forms sign-extend a 32-bit result.
            #[allow(clippy::cast_possible_truncation)]
            {
                r as u32
            }
        }
    };
}

zknh_op!(sig0, "sha256sig0");
zknh_op!(sig1, "sha256sig1");
zknh_op!(sum0, "sha256sum0");
zknh_op!(sum1, "sha256sum1");

#[target_feature(enable = "zknh")]
fn compress_zknh_inner(state: &mut [u32; 8], blocks: &[u8]) {
    for block in blocks.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            w[i] = w[i - 16]
                .wrapping_add(sig0(w[i - 15]))
                .wrapping_add(w[i - 7])
                .wrapping_add(sig1(w[i - 2]));
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
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
pub(super) fn compress_zknh(state: &mut [u32; 8], blocks: &[u8]) {
    if zknh_available(cpu::features()) {
        // SAFETY: Zknh was detected at run time (or asserted at build time).
        unsafe { compress_zknh_inner(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}
