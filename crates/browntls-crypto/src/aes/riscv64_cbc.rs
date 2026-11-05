//! riscv64 AES decryption and CBC mode.
//!
//! * Zvkned ([`VectorKey`]): decryption needs no separate key schedule,
//!   since `vaesdm`/`vaesdf` follow the standard inverse cipher (AddRoundKey
//!   before InvMixColumns) and simply take the encryption round keys in
//!   reverse order. CBC decryption is parallel and handles `VLEN/32` blocks
//!   per iteration in `LMUL=4` groups: the chaining blocks are the ciphertext
//!   slid up by one element group (`vslideup.vi`), with the IV or the last
//!   ciphertext block of the previous iteration in the first group
//!   (`vslidedown.vx`). CBC encryption is serial and runs one element group
//!   (one block) at a time. The code is VLEN-agnostic as in [`super::riscv64`].
//! * Zknd ([`ScalarDecKey`]): `aes64dsm`/`aes64ds` implement the equivalent
//!   inverse cipher, whose middle round keys go through `aes64im`, four
//!   blocks interleaved.
#![allow(unsafe_code)]

use core::arch::asm;

use super::RoundKeys;
use super::riscv64::VectorKey;
use crate::cpu::features;
use crate::zeroize::zeroize_u64;

/// Loads the fifteen round-key slots into `v1..v15` (`e32`, `vl = 4`),
/// advancing `{rk}`.
macro_rules! load_round_keys {
    () => {
        concat!(
            "vsetivli zero, 4, e32, m1, ta, ma\n",
            "vle32.v v1, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v2, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v3, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v4, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v5, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v6, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v7, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v8, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v9, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v10, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v11, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v12, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v13, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v14, ({rk})\n",
            "addi {rk}, {rk}, 16\n",
            "vle32.v v15, ({rk})\n",
        )
    };
}

impl VectorKey {
    /// CBC encryption (SP 800-38A §6.2), one block at a time.
    pub(crate) fn cbc_encrypt(&self, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
        if blocks.is_empty() {
            return;
        }
        // SAFETY: `VectorKey::new` verified RVV 1.0 + Zvkned + Zvkb. The loop
        // reads the 16-byte `iv` once and reads and writes exactly
        // `16 * blocks.len()` bytes of the exclusive slice `blocks`, one
        // block per iteration with `e8` accesses (`vl = 16` is at most
        // `VLMAX` for `e8, m1` since VLEN >= 128); `rk` points to 60 aligned,
        // readable words. Zvkned runs with `vl = 4`, one element group. All
        // 32 vector registers are declared clobbered.
        unsafe {
            asm!(
                ".option push",
                ".option arch, +v, +zvkned",
                load_round_keys!(),
                "vsetivli zero, 16, e8, m1, ta, ma",
                "vle8.v v16, ({iv})",
                "addi {tmp}, {rounds}, -10",
                "2:",
                "vsetivli zero, 16, e8, m1, ta, ma",
                "vle8.v v17, ({ptr})",
                "vsetivli zero, 4, e32, m1, ta, ma",
                "vxor.vv v16, v16, v17",
                "vaesz.vs v16, v1",
                "vaesem.vs v16, v2",
                "vaesem.vs v16, v3",
                "vaesem.vs v16, v4",
                "vaesem.vs v16, v5",
                "vaesem.vs v16, v6",
                "vaesem.vs v16, v7",
                "vaesem.vs v16, v8",
                "vaesem.vs v16, v9",
                "vaesem.vs v16, v10",
                "beqz {tmp}, 3f",
                "vaesem.vs v16, v11",
                "vaesem.vs v16, v12",
                "vaesem.vs v16, v13",
                "vaesem.vs v16, v14",
                "vaesef.vs v16, v15",
                "j 4f",
                "3:",
                "vaesef.vs v16, v11",
                "4:",
                "vsetivli zero, 16, e8, m1, ta, ma",
                "vse8.v v16, ({ptr})",
                "addi {ptr}, {ptr}, 16",
                "addi {n}, {n}, -1",
                "bnez {n}, 2b",
                ".option pop",
                ptr = inout(reg) blocks.as_mut_ptr().cast::<u8>() => _,
                n = inout(reg) blocks.len() => _,
                rk = inout(reg) self.rk.as_ptr() => _,
                iv = in(reg) iv.as_ptr(),
                rounds = in(reg) self.rounds,
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

    /// CBC decryption (SP 800-38A §6.2), `VLEN/32` blocks per iteration.
    pub(crate) fn cbc_decrypt(&self, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
        if blocks.is_empty() {
            return;
        }
        // SAFETY: `VectorKey::new` verified RVV 1.0 + Zvkned + Zvkb. The
        // loop reads the 16-byte `iv` once and reads and writes exactly
        // `16 * blocks.len()` bytes of the exclusive slice `blocks` (`e8`
        // accesses; each iteration loads its whole chunk before storing
        // it); `rk` points to 60 aligned, readable words. `vl` is capped at
        // `VLMAX` so it is always a multiple of four elements as Zvkned
        // requires, and `vl - 4` never underflows. The `vslideup`
        // destination (v20) does not overlap its source (v24). All 32
        // vector registers are declared clobbered.
        unsafe {
            asm!(
                ".option push",
                ".option arch, +v, +zvkned",
                load_round_keys!(),
                // v20, first element group: the chaining block.
                "vsetivli zero, 16, e8, m4, ta, ma",
                "vle8.v v20, ({iv})",
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
                "vle8.v v24, ({ptr})",
                "vsetvli zero, {vl}, e32, m4, ta, ma",
                // v20 = chaining block, C_0, ..., C_{n-2}.
                "vslideup.vi v20, v24, 4",
                "vmv.v.v v28, v24",
                "bnez {tmp}, 4f",
                "vaesz.vs v28, v11",
                "j 5f",
                "4:",
                "vaesz.vs v28, v15",
                "vaesdm.vs v28, v14",
                "vaesdm.vs v28, v13",
                "vaesdm.vs v28, v12",
                "vaesdm.vs v28, v11",
                "5:",
                "vaesdm.vs v28, v10",
                "vaesdm.vs v28, v9",
                "vaesdm.vs v28, v8",
                "vaesdm.vs v28, v7",
                "vaesdm.vs v28, v6",
                "vaesdm.vs v28, v5",
                "vaesdm.vs v28, v4",
                "vaesdm.vs v28, v3",
                "vaesdm.vs v28, v2",
                "vaesdf.vs v28, v1",
                "vxor.vv v28, v28, v20",
                // The last ciphertext block chains into the next iteration.
                "addi {off}, {vl}, -4",
                "vslidedown.vx v20, v24, {off}",
                "vsetvli zero, {bytes}, e8, m4, ta, ma",
                "vse8.v v28, ({ptr})",
                "add {ptr}, {ptr}, {bytes}",
                "sub {elems}, {elems}, {vl}",
                "bnez {elems}, 2b",
                ".option pop",
                ptr = inout(reg) blocks.as_mut_ptr().cast::<u8>() => _,
                elems = inout(reg) blocks.len() * 4 => _,
                rk = inout(reg) self.rk.as_ptr() => _,
                iv = in(reg) iv.as_ptr(),
                rounds = in(reg) self.rounds,
                vlmax = out(reg) _,
                vl = out(reg) _,
                bytes = out(reg) _,
                off = out(reg) _,
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
}

/// Zknd decryption round keys for the equivalent inverse cipher, as pairs
/// of little-endian 64-bit halves: `dk[0] = rk[Nr]`,
/// `dk[i] = InvMixColumns(rk[Nr - i])` for `0 < i < Nr` and `dk[Nr] = rk[0]`.
///
/// A value can only be constructed by [`ScalarDecKey::new`], which checks
/// that Zknd is present; this makes the `asm!` blocks sound.
pub(crate) struct ScalarDecKey {
    dk: [u64; 30],
    rounds: usize,
}

impl Drop for ScalarDecKey {
    fn drop(&mut self) {
        zeroize_u64(&mut self.dk);
    }
}

/// Defines a wrapper around a two-operand Zknd instruction.
macro_rules! zknd_op {
    ($(#[$m:meta])* $name:ident, $insn:literal) => {
        $(#[$m])*
        #[inline(always)]
        fn $name(a: u64, b: u64) -> u64 {
            let r: u64;
            // SAFETY: only reachable through `ScalarDecKey`, whose
            // constructor verified Zknd. The instruction touches registers
            // only.
            unsafe {
                asm!(
                    ".option push",
                    ".option arch, +zknd",
                    concat!($insn, " {r}, {a}, {b}"),
                    ".option pop",
                    a = in(reg) a,
                    b = in(reg) b,
                    r = lateout(reg) r,
                    options(pure, nomem, nostack, preserves_flags),
                );
            }
            r
        }
    };
}

zknd_op!(
    /// `aes64dsm`: InvShiftRows + InvSubBytes + InvMixColumns of the two
    /// columns in `a` given the other two columns in `b`.
    aes64dsm,
    "aes64dsm"
);
zknd_op!(
    /// `aes64ds`: final round (no InvMixColumns) counterpart of
    /// [`aes64dsm`].
    aes64ds,
    "aes64ds"
);

/// `aes64im`: InvMixColumns of both columns in `a`.
#[inline(always)]
fn aes64im(a: u64) -> u64 {
    let r: u64;
    // SAFETY: only reachable through `ScalarDecKey::new`, which verified
    // Zknd first. The instruction touches registers only.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +zknd",
            "aes64im {r}, {a}",
            ".option pop",
            a = in(reg) a,
            r = lateout(reg) r,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    r
}

impl ScalarDecKey {
    /// Returns whether the CPU has Zknd.
    pub(crate) fn supported() -> bool {
        features().rv_zknd()
    }

    pub(crate) fn new(rk: &RoundKeys) -> Self {
        assert!(Self::supported(), "Zknd used without CPU support");
        let mut halves = [0u64; 30];
        for (h, bytes) in halves
            .iter_mut()
            .zip(rk.rk.as_flattened().as_chunks::<8>().0)
        {
            *h = u64::from_le_bytes(*bytes);
        }
        let n = rk.rounds;
        let mut dk = [0u64; 30];
        dk[0] = halves[2 * n];
        dk[1] = halves[2 * n + 1];
        for i in 1..n {
            dk[2 * i] = aes64im(halves[2 * (n - i)]);
            dk[2 * i + 1] = aes64im(halves[2 * (n - i) + 1]);
        }
        dk[2 * n] = halves[0];
        dk[2 * n + 1] = halves[1];
        zeroize_u64(&mut halves);
        Self { dk, rounds: n }
    }

    /// Decrypts up to four blocks with their rounds interleaved.
    fn decrypt4(&self, blocks: &mut [[u8; 16]]) {
        let n = blocks.len();
        let mut st = [[0u64; 2]; 4];
        for (x, b) in st.iter_mut().zip(blocks.iter()) {
            let (lo, hi) = b.split_at(8);
            x[0] = u64::from_le_bytes(lo.try_into().unwrap_or([0; 8]));
            x[1] = u64::from_le_bytes(hi.try_into().unwrap_or([0; 8]));
        }
        let s = &mut st[..n];
        for x in s.iter_mut() {
            x[0] ^= self.dk[0];
            x[1] ^= self.dk[1];
        }
        for r in 1..self.rounds {
            let (k0, k1) = (self.dk[2 * r], self.dk[2 * r + 1]);
            for x in s.iter_mut() {
                let t0 = aes64dsm(x[0], x[1]);
                let t1 = aes64dsm(x[1], x[0]);
                x[0] = t0 ^ k0;
                x[1] = t1 ^ k1;
            }
        }
        let (k0, k1) = (self.dk[2 * self.rounds], self.dk[2 * self.rounds + 1]);
        for x in s.iter_mut() {
            let t0 = aes64ds(x[0], x[1]);
            let t1 = aes64ds(x[1], x[0]);
            x[0] = t0 ^ k0;
            x[1] = t1 ^ k1;
        }
        for (b, x) in blocks.iter_mut().zip(s.iter()) {
            b[..8].copy_from_slice(&x[0].to_le_bytes());
            b[8..].copy_from_slice(&x[1].to_le_bytes());
        }
        // The state holds plaintext.
        zeroize_u64(st.as_flattened_mut());
    }

    /// Decrypts every block in place.
    pub(crate) fn decrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        for chunk in blocks.chunks_mut(4) {
            self.decrypt4(chunk);
        }
    }
}
