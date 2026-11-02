//! Four-way batched SHAKE128 / SHAKE256.

use super::Sponge;
use crate::hash::keccak::{StateX4, keccak_f1600_x4_lanes};

/// SHAKE domain-separation and first padding bit.
const SHAKE_DS: u8 = 0x1f;

/// Four SHAKE sponges in lane-major layout, all in the squeezing phase at the
/// same offset `pos` within the current output block.
#[derive(Clone)]
struct SpongeX4<const RATE: usize> {
    s: StateX4,
    pos: usize,
}

#[inline]
fn xor_byte(s: &mut StateX4, j: usize, idx: usize, b: u8) {
    s[idx / 8][j] ^= u64::from(b) << (8 * (idx % 8));
}

/// Copies bytes `pos..pos + out.len()` of instance `j`'s state into `out`.
fn extract(s: &StateX4, j: usize, mut pos: usize, mut out: &mut [u8]) {
    // Leading bytes up to a lane boundary.
    while !pos.is_multiple_of(8) {
        let Some((first, rest)) = out.split_first_mut() else {
            return;
        };
        // Truncation extracts the addressed byte of the lane.
        #[allow(clippy::cast_possible_truncation)]
        {
            *first = (s[pos / 8][j] >> (8 * (pos % 8))) as u8;
        }
        pos += 1;
        out = rest;
    }
    let (lanes, tail) = out.as_chunks_mut::<8>();
    for (k, chunk) in lanes.iter_mut().enumerate() {
        *chunk = s[pos / 8 + k][j].to_le_bytes();
    }
    pos += 8 * lanes.len();
    if !tail.is_empty() {
        let bytes = s[pos / 8][j].to_le_bytes();
        tail.copy_from_slice(&bytes[..tail.len()]);
    }
}

impl<const RATE: usize> SpongeX4<RATE> {
    fn new(inputs: [&[u8]; 4]) -> Self {
        let mut s: StateX4 = [[0; 4]; 25];
        let blocks = inputs[0].len() / RATE;
        if inputs.iter().all(|i| i.len() / RATE == blocks) {
            // Same number of full blocks: absorb them in lock step.
            for b in 0..blocks {
                for (j, input) in inputs.iter().enumerate() {
                    let block = &input[b * RATE..(b + 1) * RATE];
                    for (lane, w) in s.iter_mut().zip(block.as_chunks::<8>().0) {
                        lane[j] ^= u64::from_le_bytes(*w);
                    }
                }
                keccak_f1600_x4_lanes(&mut s);
            }
            for (j, input) in inputs.iter().enumerate() {
                let tail = &input[blocks * RATE..];
                for (idx, &b) in tail.iter().enumerate() {
                    xor_byte(&mut s, j, idx, b);
                }
                xor_byte(&mut s, j, tail.len(), SHAKE_DS);
                xor_byte(&mut s, j, RATE - 1, 0x80);
            }
            keccak_f1600_x4_lanes(&mut s);
        } else {
            // Different block counts: absorb each instance on its own.
            for (j, input) in inputs.iter().enumerate() {
                let mut one = Sponge::<RATE, SHAKE_DS>::default();
                one.absorb(input);
                one.pad();
                for (lane, v) in s.iter_mut().zip(one.state) {
                    lane[j] = v;
                }
                crate::zeroize::zeroize_u64(&mut one.state);
            }
        }
        Self { s, pos: 0 }
    }

    fn squeeze<const N: usize>(&mut self, out: &mut [[u8; N]; 4]) {
        let mut off = 0;
        while off < N {
            if self.pos == RATE {
                keccak_f1600_x4_lanes(&mut self.s);
                self.pos = 0;
            }
            let take = (RATE - self.pos).min(N - off);
            for (j, o) in out.iter_mut().enumerate() {
                extract(&self.s, j, self.pos, &mut o[off..off + take]);
            }
            self.pos += take;
            off += take;
        }
    }
}

impl<const RATE: usize> Drop for SpongeX4<RATE> {
    fn drop(&mut self) {
        crate::zeroize::zeroize_u64(self.s.as_flattened_mut());
    }
}

macro_rules! shake_x4 {
    ($(#[$m:meta])* $name:ident, $single:literal, $rate:literal) => {
        $(#[$m])*
        ///
        /// The four instances are absorbed and squeezed in lock step with the
        /// batched permutation [`keccak_f1600_x4`](super::keccak_f1600_x4).
        /// Inputs may have different lengths; when they span different
        /// numbers of rate-sized blocks, absorption falls back to one
        /// instance at a time (squeezing remains batched).
        ///
        /// The state is zeroised on drop.
        #[derive(Clone)]
        pub struct $name(SpongeX4<$rate>);

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl $name {
            /// Rate (output block size) in bytes.
            pub const RATE: usize = $rate;

            /// Absorbs `inputs[j]` into instance `j` and finishes absorbing.
            #[must_use]
            pub fn new(inputs: [&[u8]; 4]) -> Self {
                Self(SpongeX4::new(inputs))
            }

            /// Writes the next `N` output bytes of instance `j` to `out[j]`.
            ///
            /// Successive calls continue each output stream, exactly like
            #[doc = concat!("[`", $single, "`](super::", $single, ") followed by repeated")]
            /// [`ShakeReader::read`](super::ShakeReader::read) calls.
            pub fn squeeze<const N: usize>(&mut self, out: &mut [[u8; N]; 4]) {
                self.0.squeeze(out);
            }

            /// Writes the next [`Self::RATE`] output bytes of each instance;
            /// when called from a block boundary (e.g. always, if only this
            /// method is used) each call costs one batched permutation.
            pub fn squeeze_blocks(&mut self, out: &mut [[u8; $rate]; 4]) {
                self.0.squeeze(out);
            }
        }
    };
}

shake_x4!(
    /// Four independent SHAKE128 computations.
    Shake128x4,
    "Shake128",
    168
);
shake_x4!(
    /// Four independent SHAKE256 computations.
    Shake256x4,
    "Shake256",
    136
);
