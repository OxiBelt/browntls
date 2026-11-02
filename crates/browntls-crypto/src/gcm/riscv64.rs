//! riscv64 GHASH backends.
//!
//! * [`ZvkgKey`]: `vghsh.vv` (Zvkg) absorbs one block per instruction in
//!   GCM's native byte order; the instruction performs the bit reflection
//!   internally.
//! * [`ZvbcKey`]: Zvbc `vclmul`/`vclmulh` compute the four 64×64 partial
//!   products of a 128×128 carry-less multiplication in one `e64` vector of
//!   two elements; the reduction runs in scalar code.
//! * [`ClmulKey`]: scalar `clmul`/`clmulh` (Zbc or Zbkc).
//!
//! The two carry-less-multiplication backends use the POLYVAL representation
//! (byte-reversed blocks, key pre-multiplied by `x`; see `gcm/x86.rs`) and a
//! shift-based Montgomery reduction by `x^128` modulo
//! `x^128 + x^127 + x^126 + x^121 + 1`.
#![allow(unsafe_code)]

use core::arch::asm;

use crate::cpu::features;
use crate::zeroize::{zeroize_u32, zeroize_u64};

/// Hash subkey in GCM byte order as four little-endian words (aligned for
/// `vle32.v`).
///
/// A value can only be constructed by [`ZvkgKey::new`], which checks that RVV
/// 1.0 and Zvkg are present; this makes the `asm!` block sound.
pub(crate) struct ZvkgKey {
    h: [u32; 4],
}

impl Drop for ZvkgKey {
    fn drop(&mut self) {
        zeroize_u32(&mut self.h);
    }
}

fn words(block: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| {
        u32::from_le_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ])
    })
}

fn unwords(w: &[u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(w) {
        *chunk = word.to_le_bytes();
    }
    out
}

impl ZvkgKey {
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        let f = features();
        assert!(
            f.rv_v() && f.rv_zvkg(),
            "Zvkg backend selected without CPU support"
        );
        Self { h: words(h) }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into the accumulator `y`.
    pub(crate) fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        let n = blocks.len() / 16;
        if n == 0 {
            return;
        }
        let mut acc = words(y);
        // SAFETY: `ZvkgKey::new` verified RVV 1.0 + Zvkg. The loop reads
        // exactly `16 * n` bytes of `blocks` with `e8` loads (no alignment
        // requirement), reads the four aligned key words and reads/writes the
        // four aligned accumulator words. Vector registers v1..v3 are
        // declared clobbered.
        unsafe {
            asm!(
                ".option push",
                ".option arch, +v, +zvkg",
                "vsetivli zero, 4, e32, m1, ta, ma",
                "vle32.v v1, ({h})",
                "vle32.v v2, ({y})",
                "2:",
                "vsetivli zero, 16, e8, m1, ta, ma",
                "vle8.v v3, ({ptr})",
                "vsetivli zero, 4, e32, m1, ta, ma",
                "vghsh.vv v2, v1, v3",
                "addi {ptr}, {ptr}, 16",
                "addi {n}, {n}, -1",
                "bnez {n}, 2b",
                "vse32.v v2, ({y})",
                ".option pop",
                ptr = inout(reg) blocks.as_ptr() => _,
                n = inout(reg) n => _,
                h = in(reg) self.h.as_ptr(),
                y = in(reg) acc.as_mut_ptr(),
                out("v1") _, out("v2") _, out("v3") _,
                options(nostack),
            );
        }
        *y = unwords(&acc);
    }
}

/// Shift-based Montgomery reduction of the 256-bit product `t` (least
/// significant limb first) by `x^128` modulo `x^128 + x^127 + x^126 + x^121 + 1`.
#[inline(always)]
fn reduce(t: [u64; 4]) -> (u64, u64) {
    let [v0, mut v1, mut v2, mut v3] = t;
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    (v2, v3)
}

/// Loads a block in POLYVAL form (byte-reversed little-endian): returns
/// `(low, high)` 64-bit limbs.
#[inline(always)]
fn reflected(block: &[u8; 16]) -> (u64, u64) {
    let hi = u64::from_be_bytes([
        block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
    ]);
    let lo = u64::from_be_bytes([
        block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
    ]);
    (lo, hi)
}

/// Runs the Horner loop for `blocks` given a carry-less 128×128 multiplier
/// `mul(x_lo, x_hi, h_lo, h_hi) -> [t0, t1, t2, t3]`.
#[inline(always)]
fn horner(
    h: &[u64; 2],
    y: &mut [u8; 16],
    blocks: &[u8],
    mul: impl Fn(u64, u64, u64, u64) -> [u64; 4],
) {
    let (mut y_lo, mut y_hi) = reflected(y);
    for block in blocks.as_chunks::<16>().0 {
        let (x_lo, x_hi) = reflected(block);
        let t = mul(x_lo ^ y_lo, x_hi ^ y_hi, h[0], h[1]);
        (y_lo, y_hi) = reduce(t);
    }
    y[..8].copy_from_slice(&y_hi.to_be_bytes());
    y[8..].copy_from_slice(&y_lo.to_be_bytes());
}

/// POLYVAL-form hash key for the Zvbc backend.
///
/// A value can only be constructed by [`ZvbcKey::new`], which checks that RVV
/// 1.0 and Zvbc are present; this makes the `asm!` block sound.
pub(crate) struct ZvbcKey {
    h: [u64; 2],
}

impl Drop for ZvbcKey {
    fn drop(&mut self) {
        zeroize_u64(&mut self.h);
    }
}

impl ZvbcKey {
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        let f = features();
        assert!(
            f.rv_v() && f.rv_zvbc(),
            "Zvbc backend selected without CPU support"
        );
        let k = super::polyval_key(h);
        let (lo, hi) = (
            u64::from_le_bytes(k[..8].try_into().unwrap_or([0; 8])),
            u64::from_le_bytes(k[8..].try_into().unwrap_or([0; 8])),
        );
        Self { h: [lo, hi] }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into the accumulator `y`.
    pub(crate) fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        horner(&self.h, y, blocks, |x_lo, x_hi, h_lo, h_hi| {
            let (a, b, c, d, e, f, g, h): (u64, u64, u64, u64, u64, u64, u64, u64);
            // SAFETY: `ZvbcKey::new` verified RVV 1.0 + Zvbc. The block only
            // touches registers (v1..v5 declared clobbered) and no memory.
            unsafe {
                asm!(
                    ".option push",
                    ".option arch, +v, +zvbc",
                    "vsetivli zero, 2, e64, m1, tu, ma",
                    "vmv.v.x v1, {xhi}",
                    "vmv.s.x v1, {xlo}",
                    "vclmul.vx v2, v1, {hlo}",
                    "vclmulh.vx v3, v1, {hlo}",
                    "vclmul.vx v4, v1, {hhi}",
                    "vclmulh.vx v5, v1, {hhi}",
                    "vmv.x.s {a}, v2",
                    "vmv.x.s {b}, v3",
                    "vmv.x.s {c}, v4",
                    "vmv.x.s {d}, v5",
                    "vslidedown.vi v2, v2, 1",
                    "vslidedown.vi v3, v3, 1",
                    "vslidedown.vi v4, v4, 1",
                    "vslidedown.vi v5, v5, 1",
                    "vmv.x.s {e}, v2",
                    "vmv.x.s {f}, v3",
                    "vmv.x.s {g}, v4",
                    "vmv.x.s {h}, v5",
                    ".option pop",
                    xlo = in(reg) x_lo,
                    xhi = in(reg) x_hi,
                    hlo = in(reg) h_lo,
                    hhi = in(reg) h_hi,
                    a = lateout(reg) a,
                    b = lateout(reg) b,
                    c = lateout(reg) c,
                    d = lateout(reg) d,
                    e = lateout(reg) e,
                    f = lateout(reg) f,
                    g = lateout(reg) g,
                    h = lateout(reg) h,
                    out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _,
                    options(nomem, nostack),
                );
            }
            // a = lo(xlo*hlo)  b = hi(xlo*hlo)  c = lo(xlo*hhi)  d = hi(xlo*hhi)
            // e = lo(xhi*hlo)  f = hi(xhi*hlo)  g = lo(xhi*hhi)  h = hi(xhi*hhi)
            [a, b ^ c ^ e, d ^ f ^ g, h]
        });
    }
}

/// POLYVAL-form hash key for the scalar carry-less multiplication backend.
///
/// A value can only be constructed by [`ClmulKey::new`], which checks that
/// Zbc or Zbkc is present; this makes the `asm!` block sound.
pub(crate) struct ClmulKey {
    h: [u64; 2],
}

impl Drop for ClmulKey {
    fn drop(&mut self) {
        zeroize_u64(&mut self.h);
    }
}

/// Full 128-bit carry-less product of two 64-bit values, `(low, high)`.
#[inline(always)]
fn clmul64(a: u64, b: u64) -> (u64, u64) {
    let (lo, hi): (u64, u64);
    // SAFETY: only reachable through `ClmulKey`, whose constructor verified
    // Zbc or Zbkc (both provide `clmul`/`clmulh`). Registers only.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +zbc, +zbkc",
            "clmul {lo}, {a}, {b}",
            "clmulh {hi}, {a}, {b}",
            ".option pop",
            a = in(reg) a,
            b = in(reg) b,
            // `lo` is written before `clmulh` reads `a`/`b`, so it must not
            // share their registers (`out`, not `lateout`).
            lo = out(reg) lo,
            hi = lateout(reg) hi,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    (lo, hi)
}

impl ClmulKey {
    pub(crate) fn new(h: &[u8; 16]) -> Self {
        let f = features();
        assert!(
            f.rv_zbc() || f.rv_zbkc(),
            "scalar clmul backend selected without CPU support"
        );
        let k = super::polyval_key(h);
        let (lo, hi) = (
            u64::from_le_bytes(k[..8].try_into().unwrap_or([0; 8])),
            u64::from_le_bytes(k[8..].try_into().unwrap_or([0; 8])),
        );
        Self { h: [lo, hi] }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into the accumulator `y`.
    pub(crate) fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 16, 0);
        horner(&self.h, y, blocks, |x_lo, x_hi, h_lo, h_hi| {
            // Karatsuba: three 64x64 products.
            let (ll_lo, ll_hi) = clmul64(x_lo, h_lo);
            let (hh_lo, hh_hi) = clmul64(x_hi, h_hi);
            let (mm_lo, mm_hi) = clmul64(x_lo ^ x_hi, h_lo ^ h_hi);
            let mid_lo = mm_lo ^ ll_lo ^ hh_lo;
            let mid_hi = mm_hi ^ ll_hi ^ hh_hi;
            [ll_lo, ll_hi ^ mid_lo, hh_lo ^ mid_hi, hh_hi]
        });
    }
}
