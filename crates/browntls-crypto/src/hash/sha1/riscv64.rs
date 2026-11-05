//! SHA-1 on riscv64: the portable code compiled with Zbb (`RORIW`, `ANDN`).
//! RISC-V defines no SHA-1 instructions.
#![allow(unsafe_code)]

use super::soft;
use crate::cpu::{self, Features};

pub(super) fn zbb_available(f: Features) -> bool {
    f.rv_zbb()
}

#[target_feature(enable = "zbb")]
fn compress_zbb_inner(state: &mut [u32; 5], blocks: &[u8]) {
    soft::compress(state, blocks);
}

/// Compresses `blocks` with Zbb, or with [`soft`] if unavailable.
pub(super) fn compress_zbb(state: &mut [u32; 5], blocks: &[u8]) {
    if zbb_available(cpu::features()) {
        // SAFETY: Zbb was detected at run time (or asserted at build time).
        unsafe { compress_zbb_inner(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}
