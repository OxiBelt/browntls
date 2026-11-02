//! SHA-256 with the Armv8 SHA-256 instructions (FEAT_SHA256).
#![allow(unsafe_code)]

use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8, vrev32q_u8, vsha256h2q_u32,
    vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
};

use super::{K, soft};
use crate::cpu::{self, Features};

pub(super) fn available(f: Features) -> bool {
    f.arm_neon() && f.arm_sha2()
}

/// Compresses `blocks` with FEAT_SHA256, or with [`soft`] if unavailable.
pub(super) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    if available(cpu::features()) {
        // SAFETY: Advanced SIMD and FEAT_SHA256 were detected at run time.
        unsafe { compress_sha2(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}

#[target_feature(enable = "neon,sha2")]
fn compress_sha2(state: &mut [u32; 8], blocks: &[u8]) {
    let [s_lo, s_hi] = state.as_chunks_mut::<4>().0 else {
        return;
    };
    let k = K.as_chunks::<4>().0;
    // SAFETY: `s_lo` is 16 readable bytes.
    let mut abcd = unsafe { vld1q_u32(s_lo.as_ptr()) };
    // SAFETY: `s_hi` is 16 readable bytes.
    let mut efgh = unsafe { vld1q_u32(s_hi.as_ptr()) };

    for block in blocks.as_chunks::<64>().0 {
        let abcd_save = abcd;
        let efgh_save = efgh;
        let words = block.as_chunks::<16>().0;
        let mut w: [uint32x4_t; 4] = core::array::from_fn(|i| {
            // SAFETY: `words[i]` is 16 readable bytes.
            let m = unsafe { vld1q_u8(words[i].as_ptr()) };
            vreinterpretq_u32_u8(vrev32q_u8(m))
        });
        for (i, ki) in k.iter().enumerate() {
            // SAFETY: `ki` is 16 readable bytes.
            let kv = unsafe { vld1q_u32(ki.as_ptr()) };
            let wk = vaddq_u32(w[i % 4], kv);
            if i < 12 {
                // W[4i+16..4i+20] from W[4i..4i+16].
                let t = vsha256su0q_u32(w[i % 4], w[(i + 1) % 4]);
                w[i % 4] = vsha256su1q_u32(t, w[(i + 2) % 4], w[(i + 3) % 4]);
            }
            let abcd_prev = abcd;
            abcd = vsha256hq_u32(abcd, efgh, wk);
            efgh = vsha256h2q_u32(efgh, abcd_prev, wk);
        }
        abcd = vaddq_u32(abcd, abcd_save);
        efgh = vaddq_u32(efgh, efgh_save);
    }

    // SAFETY: `s_lo` is 16 writable bytes.
    unsafe { vst1q_u32(s_lo.as_mut_ptr(), abcd) };
    // SAFETY: `s_hi` is 16 writable bytes.
    unsafe { vst1q_u32(s_hi.as_mut_ptr(), efgh) };
}
