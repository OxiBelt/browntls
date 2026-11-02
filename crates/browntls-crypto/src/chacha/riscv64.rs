//! riscv64 RVV 1.0 ChaCha20, VLEN-agnostic.
//!
//! The state is word-sliced across vector registers `v0..v15` (SEW=32,
//! LMUL=1): element `j` of `v<i>` is word `i` of block `j`, so one pass of the
//! kernel produces `vl = min(VLEN / 32, 32, remaining blocks)` blocks. The
//! keystream is written block-major into an aligned stack buffer with two
//! strided segment stores and XORed into the data with scalar code, so the
//! vector unit never touches the (possibly misaligned) caller buffer.
//!
//! With Zvkb (implied by Zvbb) rotations use `vror.vi`; otherwise they are
//! built from `vsll.vi`/`vsrl.vi`/`vor.vv`.
#![allow(unsafe_code)]

use super::soft::{self, BLOCK};
use crate::cpu::features;
use crate::zeroize::Zeroize;

/// Upper bound on blocks per kernel call (the full vector at VLEN = 1024).
const MAX_BLOCKS: usize = 32;

#[repr(C, align(16))]
struct KeystreamBuf([u8; MAX_BLOCKS * BLOCK]);

/// Rotate `v$r` left by `$n` (`$m = 32 - $n`) using Zvkb.
macro_rules! rot_zvkb {
    ($r:literal, $t:literal, $n:literal, $m:literal) => {
        concat!("vror.vi v", $r, ", v", $r, ", ", $m, "\n")
    };
}

/// Rotate `v$r` left by `$n` (`$m = 32 - $n`) using temporary `v$t`.
macro_rules! rot_base {
    ($r:literal, $t:literal, $n:literal, $m:literal) => {
        concat!(
            "vsll.vi v",
            $t,
            ", v",
            $r,
            ", ",
            $n,
            "\n",
            "vsrl.vi v",
            $r,
            ", v",
            $r,
            ", ",
            $m,
            "\n",
            "vor.vv v",
            $r,
            ", v",
            $r,
            ", v",
            $t,
            "\n",
        )
    };
}

/// Four interleaved quarter rounds on `(a, b, c, d)` with temporary `t`.
macro_rules! round4 {
    ($rot:ident; $($a:literal $b:literal $c:literal $d:literal $t:literal),*) => {
        concat!(
            $("vadd.vv v", $a, ", v", $a, ", v", $b, "\n",)*
            $("vxor.vv v", $d, ", v", $d, ", v", $a, "\n",)*
            $($rot!($d, $t, 16, 16),)*
            $("vadd.vv v", $c, ", v", $c, ", v", $d, "\n",)*
            $("vxor.vv v", $b, ", v", $b, ", v", $c, "\n",)*
            $($rot!($b, $t, 12, 20),)*
            $("vadd.vv v", $a, ", v", $a, ", v", $b, "\n",)*
            $("vxor.vv v", $d, ", v", $d, ", v", $a, "\n",)*
            $($rot!($d, $t, 8, 24),)*
            $("vadd.vv v", $c, ", v", $c, ", v", $d, "\n",)*
            $("vxor.vv v", $b, ", v", $b, ", v", $c, "\n",)*
            $($rot!($b, $t, 7, 25),)*
        )
    };
}

macro_rules! kernel {
    ($name:ident, $arch:literal, $rot:ident) => {
        /// Writes `vl` keystream blocks for `state` (whose word 12 is the
        /// first block counter) to `out` and returns `vl`.
        ///
        /// # Safety
        ///
        /// RVV 1.0 (plus the extensions in the `.option arch` line) must be
        /// available, and `1 <= blocks <= MAX_BLOCKS`.
        unsafe fn $name(state: &[u32; 16], blocks: usize, out: &mut KeystreamBuf) -> usize {
            let vl: usize;
            // SAFETY: the caller guarantees the vector extensions; `state`
            // is 64 readable bytes and `out` holds MAX_BLOCKS * 64 writable
            // bytes, of which the segment stores write vl * 64 with
            // vl <= blocks <= MAX_BLOCKS. All 32-bit accesses are aligned.
            unsafe {
                core::arch::asm!(
                    ".option push",
                    concat!(".option arch, ", $arch),
                    "vsetvli {vl}, {n}, e32, m1, ta, ma",
                    // Initial state: broadcast words, counter lanes += lane index.
                    "lw {t}, 0({st})", "vmv.v.x v0, {t}",
                    "lw {t}, 4({st})", "vmv.v.x v1, {t}",
                    "lw {t}, 8({st})", "vmv.v.x v2, {t}",
                    "lw {t}, 12({st})", "vmv.v.x v3, {t}",
                    "lw {t}, 16({st})", "vmv.v.x v4, {t}",
                    "lw {t}, 20({st})", "vmv.v.x v5, {t}",
                    "lw {t}, 24({st})", "vmv.v.x v6, {t}",
                    "lw {t}, 28({st})", "vmv.v.x v7, {t}",
                    "lw {t}, 32({st})", "vmv.v.x v8, {t}",
                    "lw {t}, 36({st})", "vmv.v.x v9, {t}",
                    "lw {t}, 40({st})", "vmv.v.x v10, {t}",
                    "lw {t}, 44({st})", "vmv.v.x v11, {t}",
                    "lw {t}, 48({st})", "vid.v v16", "vadd.vx v16, v16, {t}", "vmv.v.v v12, v16",
                    "lw {t}, 52({st})", "vmv.v.x v13, {t}",
                    "lw {t}, 56({st})", "vmv.v.x v14, {t}",
                    "lw {t}, 60({st})", "vmv.v.x v15, {t}",
                    "li {cnt}, 10",
                    "2:",
                    round4!($rot; 0 4 8 12 20, 1 5 9 13 21, 2 6 10 14 22, 3 7 11 15 23),
                    round4!($rot; 0 5 10 15 20, 1 6 11 12 21, 2 7 8 13 22, 3 4 9 14 23),
                    "addi {cnt}, {cnt}, -1",
                    "bnez {cnt}, 2b",
                    // Feed-forward.
                    "lw {t}, 0({st})", "vadd.vx v0, v0, {t}",
                    "lw {t}, 4({st})", "vadd.vx v1, v1, {t}",
                    "lw {t}, 8({st})", "vadd.vx v2, v2, {t}",
                    "lw {t}, 12({st})", "vadd.vx v3, v3, {t}",
                    "lw {t}, 16({st})", "vadd.vx v4, v4, {t}",
                    "lw {t}, 20({st})", "vadd.vx v5, v5, {t}",
                    "lw {t}, 24({st})", "vadd.vx v6, v6, {t}",
                    "lw {t}, 28({st})", "vadd.vx v7, v7, {t}",
                    "lw {t}, 32({st})", "vadd.vx v8, v8, {t}",
                    "lw {t}, 36({st})", "vadd.vx v9, v9, {t}",
                    "lw {t}, 40({st})", "vadd.vx v10, v10, {t}",
                    "lw {t}, 44({st})", "vadd.vx v11, v11, {t}",
                    "vadd.vv v12, v12, v16",
                    "lw {t}, 52({st})", "vadd.vx v13, v13, {t}",
                    "lw {t}, 56({st})", "vadd.vx v14, v14, {t}",
                    "lw {t}, 60({st})", "vadd.vx v15, v15, {t}",
                    // Block-major store: block j at out + 64 j.
                    "li {t}, 64",
                    "vssseg8e32.v v0, ({out}), {t}",
                    "addi {out}, {out}, 32",
                    "vssseg8e32.v v8, ({out}), {t}",
                    ".option pop",
                    st = in(reg) state.as_ptr(),
                    n = in(reg) blocks,
                    out = inout(reg) out.0.as_mut_ptr() => _,
                    vl = out(reg) vl,
                    t = out(reg) _,
                    cnt = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v20") _, out("v21") _, out("v22") _,
                    out("v23") _,
                    options(nostack),
                );
            }
            vl
        }
    };
}

kernel!(keystream_zvkb, "+v, +zvkb", rot_zvkb);
kernel!(keystream_base, "+v", rot_base);

/// RVV ChaCha20; falls back to the portable code without RVV 1.0.
pub(super) fn xor_rvv(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    let f = features();
    if !f.rv_v() {
        soft::xor(key, counter, nonce, data);
        return;
    }
    let zvkb = f.rv_zvkb();
    let mut state = soft::initial_state(key, counter, nonce);
    let mut buf = KeystreamBuf([0; MAX_BLOCKS * BLOCK]);
    let mut rest = data;
    while !rest.is_empty() {
        let blocks = rest.len().div_ceil(BLOCK).min(MAX_BLOCKS);
        let vl = if zvkb {
            // SAFETY: RVV 1.0 and Zvkb were detected; 1 <= blocks <= MAX_BLOCKS.
            unsafe { keystream_zvkb(&state, blocks, &mut buf) }
        } else {
            // SAFETY: RVV 1.0 was detected; 1 <= blocks <= MAX_BLOCKS.
            unsafe { keystream_base(&state, blocks, &mut buf) }
        };
        if vl == 0 {
            // Unreachable for a conforming implementation (AVL >= 1 gives
            // vl >= 1); never loop forever.
            soft::xor(key, state[12], nonce, rest);
            break;
        }
        let n = (vl * BLOCK).min(rest.len());
        let (head, tail) = rest.split_at_mut(n);
        soft::xor_in_place(head, &buf.0[..n]);
        rest = tail;
        state[12] = state[12].wrapping_add(vl as u32);
    }
    buf.0.zeroize();
    state.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both rotation variants against the portable code, independent of which
    /// one the dispatcher would pick.
    #[test]
    fn kernels_match_soft() {
        let f = features();
        std::eprintln!(
            "rvv: v={} zvkb={} vlenb={}",
            f.rv_v(),
            f.rv_zvkb(),
            crate::cpu::riscv_vlenb()
        );
        if !f.rv_v() {
            return;
        }
        let key: [u32; 8] = core::array::from_fn(|i| 0x0101_0101 * (i as u32 + 1));
        let nonce = [7, 8, 9];
        for blocks in 1..=MAX_BLOCKS {
            for ctr in [0, u32::MAX - 2] {
                let state = soft::initial_state(&key, ctr, &nonce);
                let mut want = [0u8; MAX_BLOCKS * BLOCK];
                soft::xor(&key, ctr, &nonce, &mut want);
                let mut out = KeystreamBuf([0; MAX_BLOCKS * BLOCK]);
                // SAFETY: RVV 1.0 detected; 1 <= blocks <= MAX_BLOCKS.
                let vl = unsafe { keystream_base(&state, blocks, &mut out) };
                assert!(vl >= 1 && vl <= blocks);
                assert_eq!(out.0[..vl * BLOCK], want[..vl * BLOCK], "base {blocks}");
                if f.rv_zvkb() {
                    let mut out2 = KeystreamBuf([0; MAX_BLOCKS * BLOCK]);
                    // SAFETY: RVV 1.0 and Zvkb detected; 1 <= blocks <= MAX_BLOCKS.
                    let vl2 = unsafe { keystream_zvkb(&state, blocks, &mut out2) };
                    assert_eq!(vl, vl2);
                    assert_eq!(out2.0[..vl * BLOCK], want[..vl * BLOCK], "zvkb {blocks}");
                }
            }
        }
    }
}
