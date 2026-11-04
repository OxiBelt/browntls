//! SHA-1 with the Armv8 SHA-1 instructions (FEAT_SHA1). Rust exposes them
//! under the `sha2` target feature, which `std` detects together with
//! FEAT_SHA256 (Armv8 defines no SHA-256 implementation without SHA-1).
#![allow(unsafe_code)]

use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vdupq_n_u32, vgetq_lane_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8,
    vrev32q_u8, vsha1cq_u32, vsha1h_u32, vsha1mq_u32, vsha1pq_u32, vsha1su0q_u32, vsha1su1q_u32,
    vst1q_u32,
};

use super::{K, soft};
use crate::cpu::{self, Features};

pub(super) fn available(f: Features) -> bool {
    f.arm_neon() && f.arm_sha2()
}

/// Compresses `blocks` with FEAT_SHA1, or with [`soft`] if unavailable.
pub(super) fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    if available(cpu::features()) {
        // SAFETY: Advanced SIMD and FEAT_SHA1 (target feature `sha2`) were
        // detected at run time.
        unsafe { compress_sha1(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}

#[target_feature(enable = "neon,sha2")]
fn compress_sha1(state: &mut [u32; 5], blocks: &[u8]) {
    let Some((s_abcd, [s_e])) = state.split_first_chunk_mut::<4>() else {
        return;
    };
    // SAFETY: `s_abcd` is 16 readable bytes.
    let mut abcd = unsafe { vld1q_u32(s_abcd.as_ptr()) };
    let mut e = *s_e;
    let k: [uint32x4_t; 4] = core::array::from_fn(|i| vdupq_n_u32(K[i]));

    for block in blocks.as_chunks::<64>().0 {
        let abcd_save = abcd;
        let e_save = e;
        let words = block.as_chunks::<16>().0;
        let mut w: [uint32x4_t; 4] = core::array::from_fn(|i| {
            // SAFETY: `words[i]` is 16 readable bytes.
            let m = unsafe { vld1q_u8(words[i].as_ptr()) };
            vreinterpretq_u32_u8(vrev32q_u8(m))
        });
        for i in 0..20 {
            let wk = vaddq_u32(w[i % 4], k[i / 5]);
            // E for the next quad-round is A of this one, rotated.
            let e_next = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = match i / 5 {
                0 => vsha1cq_u32(abcd, e, wk),
                2 => vsha1mq_u32(abcd, e, wk),
                _ => vsha1pq_u32(abcd, e, wk),
            };
            e = e_next;
            if i < 16 {
                // W[4i+16..4i+20] from W[4i..4i+16].
                let t = vsha1su0q_u32(w[i % 4], w[(i + 1) % 4], w[(i + 2) % 4]);
                w[i % 4] = vsha1su1q_u32(t, w[(i + 3) % 4]);
            }
        }
        abcd = vaddq_u32(abcd, abcd_save);
        e = e.wrapping_add(e_save);
    }

    // SAFETY: `s_abcd` is 16 writable bytes.
    unsafe { vst1q_u32(s_abcd.as_mut_ptr(), abcd) };
    *s_e = e;
}
