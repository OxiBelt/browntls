//! riscv64 AES backends.
//!
//! * [`VectorKey`]: Zvkned over RVV 1.0. Round keys live in `v1..v15` (one
//!   element group each, applied with the `.vs` forms); data uses `LMUL=4`
//!   element groups so each iteration handles `VLEN/32` blocks. Counter
//!   blocks are generated in-register (`vid.v`, `vadd.vx`, Zvkb `vrev8.v`)
//!   and the code is VLEN-agnostic (`vsetvli`, with the AVL capped at
//!   `VLMAX` so `vl` is always a multiple of the element-group size).
//! * [`ScalarKey`]: Zkne `aes64esm`/`aes64es` on 64-bit halves, four blocks
//!   interleaved.
//!
//! Vector loads of data use `e8` so unaligned buffers are fine; round keys
//! and counter words are kept 4-byte aligned for `vle32.v`.
#![allow(unsafe_code)]

use core::arch::asm;

use super::RoundKeys;
use crate::cpu::features;
use crate::zeroize::{zeroize_u32, zeroize_u64};

/// Zvkned round keys as little-endian 32-bit words (4-byte aligned).
///
/// A value can only be constructed by [`VectorKey::new`], which checks that
/// RVV 1.0, Zvkned and Zvkb are present; this makes the `asm!` blocks sound.
pub(crate) struct VectorKey {
    rk: [u32; 60],
    rounds: usize,
}

impl Drop for VectorKey {
    fn drop(&mut self) {
        zeroize_u32(&mut self.rk);
    }
}

/// Zkne round keys as pairs of little-endian 64-bit halves.
///
/// A value can only be constructed by [`ScalarKey::new`], which checks that
/// Zkne is present; this makes the `asm!` blocks sound.
pub(crate) struct ScalarKey {
    rk: [u64; 30],
    rounds: usize,
}

impl Drop for ScalarKey {
    fn drop(&mut self) {
        zeroize_u64(&mut self.rk);
    }
}

impl VectorKey {
    pub(crate) fn new(rk: RoundKeys) -> Self {
        let f = features();
        assert!(
            f.rv_v() && f.rv_zvkned() && f.rv_zvkb(),
            "Zvkned backend selected without CPU support"
        );
        let mut words = [0u32; 60];
        for (w, bytes) in words
            .iter_mut()
            .zip(rk.rk.as_flattened().as_chunks::<4>().0)
        {
            *w = u32::from_le_bytes(*bytes);
        }
        Self {
            rk: words,
            rounds: rk.rounds,
        }
    }

    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        if blocks.is_empty() {
            return;
        }
        // SAFETY: `VectorKey::new` verified RVV 1.0 + Zvkned + Zvkb. `blocks`
        // is an exclusive slice of `16 * n` bytes and the loop reads and
        // writes exactly `4 * n` 32-bit elements (`16 * n` bytes, accessed
        // with `e8` loads and stores) starting at its base; `rk` points to 60 aligned words of
        // which the first 16 * (rounds + 1) are meaningful and all 60 are
        // readable; `vl` is capped at `VLMAX` so every `vsetvli` yields a
        // multiple of four elements as Zvkned requires. All 32 vector
        // registers are declared clobbered.
        unsafe {
            asm!(
                ".option push",
                ".option arch, +v, +zvkned",
                "vsetivli zero, 4, e32, m1, ta, ma",
                "vle32.v v1, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v2, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v3, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v4, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v5, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v6, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v7, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v8, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v9, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v10, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v11, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v12, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v13, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v14, ({rk})",
                "addi {rk}, {rk}, 16",
                "vle32.v v15, ({rk})",
                "li {vlmax}, -1",
                "vsetvli {vlmax}, {vlmax}, e32, m4, ta, ma",
                "addi {tmp}, {rounds}, -10",
                "2:",
                "mv {vl}, {elems}",
                "bleu {elems}, {vlmax}, 3f",
                "mv {vl}, {vlmax}",
                "3:",
                "slli {bytes}, {vl}, 2",
                "vsetvli zero, {bytes}, e8, m4, ta, ma",
                "vle8.v v28, ({ptr})",
                "vsetvli zero, {vl}, e32, m4, ta, ma",
                "vaesz.vs v28, v1",
                "vaesem.vs v28, v2",
                "vaesem.vs v28, v3",
                "vaesem.vs v28, v4",
                "vaesem.vs v28, v5",
                "vaesem.vs v28, v6",
                "vaesem.vs v28, v7",
                "vaesem.vs v28, v8",
                "vaesem.vs v28, v9",
                "vaesem.vs v28, v10",
                "beqz {tmp}, 4f",
                "vaesem.vs v28, v11",
                "vaesem.vs v28, v12",
                "vaesem.vs v28, v13",
                "vaesem.vs v28, v14",
                "vaesef.vs v28, v15",
                "j 5f",
                "4:",
                "vaesef.vs v28, v11",
                "5:",
                "vsetvli zero, {bytes}, e8, m4, ta, ma",
                "vse8.v v28, ({ptr})",
                "add {ptr}, {ptr}, {bytes}",
                "sub {elems}, {elems}, {vl}",
                "bnez {elems}, 2b",
                ".option pop",
                ptr = inout(reg) blocks.as_mut_ptr().cast::<u8>() => _,
                elems = inout(reg) blocks.len() * 4 => _,
                rk = inout(reg) self.rk.as_ptr() => _,
                rounds = in(reg) self.rounds,
                vlmax = out(reg) _,
                vl = out(reg) _,
                bytes = out(reg) _,
                tmp = out(reg) _,
                out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _,
                out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _, out("v17") _,
                out("v18") _, out("v19") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _,
                out("v30") _, out("v31") _,
                options(nostack),
            );
        }
    }

    pub(crate) fn ctr32_xor(&self, ctr: &[u8; 16], in_out: &mut [u8]) {
        let mut counter = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
        let words: [u32; 4] = core::array::from_fn(|i| {
            u32::from_le_bytes([ctr[4 * i], ctr[4 * i + 1], ctr[4 * i + 2], ctr[4 * i + 3]])
        });
        let (blocks, rest) = in_out.as_chunks_mut::<16>();
        if !blocks.is_empty() {
            // SAFETY: `VectorKey::new` verified RVV 1.0 + Zvkned + Zvkb. The
            // loop touches exactly `16 * blocks.len()` bytes of the exclusive
            // slice `blocks` (loaded and stored with `e8`), reads the 60
            // aligned key words and the 4 aligned counter words; `vl` is
            // capped at `VLMAX` so it is always a multiple of four as Zvkned
            // requires. All 32 vector registers are declared clobbered.
            unsafe {
                asm!(
                    ".option push",
                    ".option arch, +v, +zvkned, +zvkb",
                    "vsetivli zero, 4, e32, m1, ta, ma",
                    "vle32.v v1, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v2, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v3, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v4, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v5, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v6, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v7, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v8, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v9, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v10, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v11, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v12, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v13, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v14, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v15, ({rk})",
                    // Counter block words into the first element group of v16.
                    "vsetivli zero, 4, e32, m4, ta, ma",
                    "vle32.v v16, ({ctr})",
                    "li {vlmax}, -1",
                    "vsetvli {vlmax}, {vlmax}, e32, m4, ta, ma",
                    "mv {vl}, {elems}",
                    "bleu {elems}, {vlmax}, 2f",
                    "mv {vl}, {vlmax}",
                    "2:",
                    "vsetvli zero, {vl}, e32, m4, ta, ma",
                    // v20 = block index of each element, v0 = mask of counter
                    // lanes (lane 3 of every block), v16 = replicated base.
                    "vid.v v20",
                    "vand.vi v24, v20, 3",
                    "vmseq.vi v0, v24, 3",
                    "vrgather.vv v28, v16, v24",
                    "vsrl.vi v20, v20, 2",
                    "vmv.v.v v16, v28",
                    "addi {tmp}, {rounds}, -10",
                    "3:",
                    "mv {vl}, {elems}",
                    "bleu {elems}, {vlmax}, 4f",
                    "mv {vl}, {vlmax}",
                    "4:",
                    "vsetvli zero, {vl}, e32, m4, ta, ma",
                    "vadd.vx v24, v20, {counter}",
                    "vrev8.v v24, v24",
                    "vmerge.vvm v28, v16, v24, v0",
                    "vaesz.vs v28, v1",
                    "vaesem.vs v28, v2",
                    "vaesem.vs v28, v3",
                    "vaesem.vs v28, v4",
                    "vaesem.vs v28, v5",
                    "vaesem.vs v28, v6",
                    "vaesem.vs v28, v7",
                    "vaesem.vs v28, v8",
                    "vaesem.vs v28, v9",
                    "vaesem.vs v28, v10",
                    "beqz {tmp}, 5f",
                    "vaesem.vs v28, v11",
                    "vaesem.vs v28, v12",
                    "vaesem.vs v28, v13",
                    "vaesem.vs v28, v14",
                    "vaesef.vs v28, v15",
                    "j 6f",
                    "5:",
                    "vaesef.vs v28, v11",
                    "6:",
                    "slli {bytes}, {vl}, 2",
                    "vsetvli zero, {bytes}, e8, m4, ta, ma",
                    "vle8.v v24, ({ptr})",
                    "vxor.vv v24, v24, v28",
                    "vse8.v v24, ({ptr})",
                    "add {ptr}, {ptr}, {bytes}",
                    "sub {elems}, {elems}, {vl}",
                    "srli {tmp2}, {vl}, 2",
                    "add {counter}, {counter}, {tmp2}",
                    "bnez {elems}, 3b",
                    ".option pop",
                    ptr = inout(reg) blocks.as_mut_ptr().cast::<u8>() => _,
                    elems = inout(reg) blocks.len() * 4 => _,
                    rk = inout(reg) self.rk.as_ptr() => _,
                    ctr = in(reg) words.as_ptr(),
                    counter = inout(reg) u64::from(counter) => _,
                    rounds = in(reg) self.rounds,
                    vlmax = out(reg) _,
                    vl = out(reg) _,
                    bytes = out(reg) _,
                    tmp = out(reg) _,
                    tmp2 = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _,
                    out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _, out("v17") _,
                    out("v18") _, out("v19") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _,
                    out("v30") _, out("v31") _,
                    options(nostack),
                );
            }
            // Truncation to 32 bits is the GCM inc32 wrap.
            #[allow(clippy::cast_possible_truncation)]
            let advanced = counter.wrapping_add(blocks.len() as u32);
            counter = advanced;
        }
        if !rest.is_empty() {
            let mut ks = *ctr;
            ks[12..].copy_from_slice(&counter.to_be_bytes());
            self.encrypt_blocks(core::slice::from_mut(&mut ks));
            for (b, k) in rest.iter_mut().zip(ks) {
                *b ^= k;
            }
        }
    }
}

/// `aes64esm`: ShiftRows + SubBytes + MixColumns of the two columns in `a`
/// given the other two columns in `b`.
#[inline(always)]
fn aes64esm(a: u64, b: u64) -> u64 {
    let r: u64;
    // SAFETY: only reachable through `ScalarKey`, whose constructor verified
    // Zkne. The instruction touches registers only.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +zkne",
            "aes64esm {r}, {a}, {b}",
            ".option pop",
            a = in(reg) a,
            b = in(reg) b,
            r = lateout(reg) r,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    r
}

/// `aes64es`: final round (no MixColumns) counterpart of [`aes64esm`].
#[inline(always)]
fn aes64es(a: u64, b: u64) -> u64 {
    let r: u64;
    // SAFETY: as for `aes64esm`.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +zkne",
            "aes64es {r}, {a}, {b}",
            ".option pop",
            a = in(reg) a,
            b = in(reg) b,
            r = lateout(reg) r,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    r
}

impl ScalarKey {
    pub(crate) fn new(rk: RoundKeys) -> Self {
        assert!(
            features().rv_zkne(),
            "Zkne backend selected without CPU support"
        );
        let mut halves = [0u64; 30];
        for (h, bytes) in halves
            .iter_mut()
            .zip(rk.rk.as_flattened().as_chunks::<8>().0)
        {
            *h = u64::from_le_bytes(*bytes);
        }
        Self {
            rk: halves,
            rounds: rk.rounds,
        }
    }

    /// Encrypts up to four blocks with their rounds interleaved.
    fn encrypt4(&self, blocks: &mut [[u8; 16]]) {
        let n = blocks.len();
        let mut s = [[0u64; 2]; 4];
        for (st, b) in s.iter_mut().zip(blocks.iter()) {
            st[0] = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
            st[1] = u64::from_le_bytes(b[8..].try_into().unwrap_or([0; 8]));
        }
        for st in &mut s {
            st[0] ^= self.rk[0];
            st[1] ^= self.rk[1];
        }
        for r in 1..self.rounds {
            let (k0, k1) = (self.rk[2 * r], self.rk[2 * r + 1]);
            for st in &mut s {
                let t0 = aes64esm(st[0], st[1]);
                let t1 = aes64esm(st[1], st[0]);
                st[0] = t0 ^ k0;
                st[1] = t1 ^ k1;
            }
        }
        let (k0, k1) = (self.rk[2 * self.rounds], self.rk[2 * self.rounds + 1]);
        for st in &mut s {
            let t0 = aes64es(st[0], st[1]);
            let t1 = aes64es(st[1], st[0]);
            st[0] = t0 ^ k0;
            st[1] = t1 ^ k1;
        }
        for (b, st) in blocks.iter_mut().zip(&s).take(n) {
            b[..8].copy_from_slice(&st[0].to_le_bytes());
            b[8..].copy_from_slice(&st[1].to_le_bytes());
        }
    }

    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        for chunk in blocks.chunks_mut(4) {
            self.encrypt4(chunk);
        }
    }
}
