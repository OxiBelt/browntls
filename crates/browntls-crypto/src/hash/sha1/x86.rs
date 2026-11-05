//! SHA-1 with the x86-64 SHA extensions (`SHA1RNDS4`, `SHA1NEXTE`,
//! `SHA1MSG1`, `SHA1MSG2`).
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_cvtsi128_si32, _mm_loadu_si128, _mm_set_epi32, _mm_set_epi64x,
    _mm_sha1msg1_epu32, _mm_sha1msg2_epu32, _mm_sha1nexte_epu32, _mm_sha1rnds4_epu32,
    _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_storeu_si128, _mm_xor_si128,
};

use super::soft;
use crate::cpu::{self, Features};

pub(super) fn available(f: Features) -> bool {
    f.x86_sha() && f.x86_ssse3() && f.x86_sse41()
}

/// Compresses `blocks` with SHA-NI, or with [`soft`] if unavailable.
pub(super) fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    if available(cpu::features()) {
        // SAFETY: SHA, SSSE3 and SSE4.1 were detected at run time.
        unsafe { compress_sha(state, blocks) }
    } else {
        soft::compress(state, blocks);
    }
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn compress_sha(state: &mut [u32; 5], blocks: &[u8]) {
    // Reverses all 16 bytes: big-endian words with W[0] in element 3.
    let bswap = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f);

    let [a, b, c, d, e] = *state;
    // The SHA1 instructions hold A in element 3 and E in element 3 of a
    // second register.
    let mut abcd = _mm_set_epi32(
        a.cast_signed(),
        b.cast_signed(),
        c.cast_signed(),
        d.cast_signed(),
    );
    let mut e0 = _mm_set_epi32(e.cast_signed(), 0, 0, 0);

    for block in blocks.as_chunks::<64>().0 {
        let words = block.as_chunks::<16>().0;
        let mut w: [__m128i; 4] = core::array::from_fn(|i| {
            // SAFETY: `words[i]` is 16 readable bytes; unaligned loads are
            // allowed.
            let m = unsafe { _mm_loadu_si128(words[i].as_ptr().cast()) };
            _mm_shuffle_epi8(m, bswap)
        });

        let abcd_save = abcd;
        // `cur` is the state entering quad-round `i`, `prev` the state
        // entering quad-round `i - 1` (from which SHA1NEXTE derives E).
        let mut prev = abcd;
        let mut cur = _mm_sha1rnds4_epu32::<0>(abcd, _mm_add_epi32(e0, w[0]));

        // Quad-round `$i` (1..20) with round function `$f` (an immediate,
        // hence the unrolled invocations below).
        macro_rules! quad {
            ($i:literal, $f:literal) => {
                // W[4i..4i+4] is complete once quad-round i - 1 has run;
                // for i >= 4 it is derived from the previous four groups
                // and replaces the oldest of them, W[4(i-4)..].
                if $i >= 4 {
                    let t = _mm_sha1msg1_epu32(w[$i % 4], w[($i + 1) % 4]);
                    let t = _mm_xor_si128(t, w[($i + 2) % 4]);
                    w[$i % 4] = _mm_sha1msg2_epu32(t, w[($i + 3) % 4]);
                }
                let next = _mm_sha1rnds4_epu32::<$f>(cur, _mm_sha1nexte_epu32(prev, w[$i % 4]));
                prev = cur;
                cur = next;
            };
        }
        quad!(1, 0);
        quad!(2, 0);
        quad!(3, 0);
        quad!(4, 0);
        quad!(5, 1);
        quad!(6, 1);
        quad!(7, 1);
        quad!(8, 1);
        quad!(9, 1);
        quad!(10, 2);
        quad!(11, 2);
        quad!(12, 2);
        quad!(13, 2);
        quad!(14, 2);
        quad!(15, 3);
        quad!(16, 3);
        quad!(17, 3);
        quad!(18, 3);
        quad!(19, 3);
        abcd = _mm_add_epi32(cur, abcd_save);
        e0 = _mm_sha1nexte_epu32(prev, e0);
    }

    let mut out = [0u32; 4];
    // SAFETY: `out` is 16 writable bytes; unaligned stores are allowed.
    unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), abcd) };
    let [d, c, b, a] = out;
    // Element 3 of `e0` holds E.
    let e = _mm_cvtsi128_si32(_mm_shuffle_epi32::<0xff>(e0)).cast_unsigned();
    *state = [a, b, c, d, e];
}
