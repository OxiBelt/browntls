//! SHA-512 with the Armv8.2 SHA-512 instructions (FEAT_SHA512, reported by
//! the `sha3` feature).
//!
//! The round structure follows the Arm reference sequence (also used by
//! Linux and Mbed TLS): each step performs two rounds with `SHA512H` and
//! `SHA512H2`, the state registers `ab`, `cd`, `ef`, `gh` rotate roles every
//! step, and `SHA512SU0`/`SHA512SU1` extend the message schedule two words
//! at a time.
#![allow(unsafe_code)]

use core::arch::aarch64::{
    uint64x2_t, vaddq_u64, vextq_u64, vld1q_u8, vld1q_u64, vreinterpretq_u64_u8, vrev64q_u8,
    vsha512h2q_u64, vsha512hq_u64, vsha512su0q_u64, vsha512su1q_u64, vst1q_u64,
};

use super::{K, soft};
use crate::cpu::{self, Features};

pub(super) fn available(f: Features) -> bool {
    f.arm_neon() && f.arm_sha3()
}

/// Compresses `blocks` with FEAT_SHA512, or with [`soft`] if unavailable.
pub(super) fn compress(state: &mut [u64; 8], blocks: &[u8]) {
    if available(cpu::features()) {
        // SAFETY: Advanced SIMD and FEAT_SHA512 were detected at run time.
        unsafe { compress_sha512(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}

#[target_feature(enable = "neon,sha3")]
fn compress_sha512(state: &mut [u64; 8], blocks: &[u8]) {
    let st = state.as_chunks_mut::<2>().0;
    let k = K.as_chunks::<2>().0;
    let mut s: [uint64x2_t; 4] = core::array::from_fn(|i| {
        // SAFETY: `st[i]` is 16 readable bytes.
        unsafe { vld1q_u64(st[i].as_ptr()) }
    });

    for block in blocks.as_chunks::<128>().0 {
        let save = s;
        let words = block.as_chunks::<16>().0;
        let mut w: [uint64x2_t; 8] = core::array::from_fn(|i| {
            // SAFETY: `words[i]` is 16 readable bytes.
            let m = unsafe { vld1q_u8(words[i].as_ptr()) };
            vreinterpretq_u64_u8(vrev64q_u8(m))
        });
        let [mut ab, mut cd, mut ef, mut gh] = s;

        // Two rounds using W[t..t+2] (in `w[t/2 % 8]`); the roles of the
        // state registers rotate (ab, cd, ef, gh) -> (gh, ab, cd, ef).
        macro_rules! step {
            ($t:expr, $ab:ident, $cd:ident, $ef:ident, $gh:ident) => {{
                let t: usize = $t;
                let j = (t / 2) % 8;
                if t >= 16 {
                    let s0 = vsha512su0q_u64(w[j], w[(j + 1) % 8]);
                    w[j] = vsha512su1q_u64(
                        s0,
                        w[(j + 7) % 8],
                        vextq_u64::<1>(w[(j + 4) % 8], w[(j + 5) % 8]),
                    );
                }
                // SAFETY: `k[t / 2]` is 16 readable bytes.
                let kv = unsafe { vld1q_u64(k[t / 2].as_ptr()) };
                let wk = vaddq_u64(w[j], kv);
                let sum = vaddq_u64(vextq_u64::<1>(wk, wk), $gh);
                let im = vsha512hq_u64(sum, vextq_u64::<1>($ef, $gh), vextq_u64::<1>($cd, $ef));
                $gh = vsha512h2q_u64(im, $cd, $ab);
                $cd = vaddq_u64($cd, im);
            }};
        }

        for t in (0..80).step_by(8) {
            step!(t, ab, cd, ef, gh);
            step!(t + 2, gh, ab, cd, ef);
            step!(t + 4, ef, gh, ab, cd);
            step!(t + 6, cd, ef, gh, ab);
        }

        s = [
            vaddq_u64(ab, save[0]),
            vaddq_u64(cd, save[1]),
            vaddq_u64(ef, save[2]),
            vaddq_u64(gh, save[3]),
        ];
    }

    for (dst, v) in st.iter_mut().zip(s) {
        // SAFETY: `dst` is 16 writable bytes.
        unsafe { vst1q_u64(dst.as_mut_ptr(), v) };
    }
}
