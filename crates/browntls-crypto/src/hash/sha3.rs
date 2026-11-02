//! SHA-3 and SHAKE (FIPS 202) built on Keccak-f\[1600\].
//!
//! [`Shake128x4`] and [`Shake256x4`] compute four independent SHAKE
//! instances with the batched permutation [`keccak_f1600_x4`], as used for
//! ML-KEM matrix expansion and noise sampling.

use super::HashFunction;

mod x4;

pub use super::keccak::{keccak_f1600, keccak_f1600_x4};
pub use x4::{Shake128x4, Shake256x4};

/// A Keccak sponge with rate `RATE` bytes and domain-separation byte `DS`.
#[derive(Clone)]
struct Sponge<const RATE: usize, const DS: u8> {
    state: [u64; 25],
    pos: usize,
}

impl<const RATE: usize, const DS: u8> Default for Sponge<RATE, DS> {
    fn default() -> Self {
        Self {
            state: [0; 25],
            pos: 0,
        }
    }
}

impl<const RATE: usize, const DS: u8> Sponge<RATE, DS> {
    #[inline]
    fn xor_byte(&mut self, i: usize, b: u8) {
        self.state[i / 8] ^= u64::from(b) << (8 * (i % 8));
    }

    fn absorb(&mut self, mut data: &[u8]) {
        // Finish a partial block byte-wise.
        while self.pos != 0 && !data.is_empty() {
            self.xor_byte(self.pos, data[0]);
            self.pos += 1;
            data = &data[1..];
            if self.pos == RATE {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
        // Whole blocks lane-wise.
        while data.len() >= RATE {
            for (lane, chunk) in self.state.iter_mut().zip(data[..RATE].as_chunks::<8>().0) {
                *lane ^= u64::from_le_bytes(*chunk);
            }
            keccak_f1600(&mut self.state);
            data = &data[RATE..];
        }
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
        }
    }

    fn pad(&mut self) {
        self.xor_byte(self.pos, DS);
        self.xor_byte(RATE - 1, 0x80);
        keccak_f1600(&mut self.state);
        self.pos = 0;
    }

    /// Squeezes `out`; `pos` tracks the read offset within the current block.
    fn squeeze(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.pos == RATE {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            let take = (RATE - self.pos).min(out.len());
            for (i, o) in out[..take].iter_mut().enumerate() {
                let idx = self.pos + i;
                // Truncation extracts the addressed byte of the lane.
                #[allow(clippy::cast_possible_truncation)]
                {
                    *o = (self.state[idx / 8] >> (8 * (idx % 8))) as u8;
                }
            }
            self.pos += take;
            out = &mut out[take..];
        }
    }
}

macro_rules! sha3_variant {
    ($(#[$m:meta])* $name:ident, $rate:literal, $out:literal) => {
        $(#[$m])*
        #[derive(Clone, Default)]
        pub struct $name(Sponge<$rate, 0x06>);

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl HashFunction for $name {
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = $rate;
            type Output = [u8; $out];

            fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            fn finalize(mut self) -> [u8; $out] {
                self.0.pad();
                let mut out = [0u8; $out];
                self.0.squeeze(&mut out);
                out
            }
        }
    };
}

sha3_variant!(
    /// SHA3-256.
    Sha3_256, 136, 32
);
sha3_variant!(
    /// SHA3-384.
    Sha3_384, 104, 48
);
sha3_variant!(
    /// SHA3-512.
    Sha3_512, 72, 64
);

/// Output stream of an extendable-output function.
#[derive(Clone)]
pub struct ShakeReader<const RATE: usize>(Sponge<RATE, 0x1f>);

impl<const RATE: usize> ShakeReader<RATE> {
    /// Writes the next `out.len()` bytes of output.
    pub fn read(&mut self, out: &mut [u8]) {
        self.0.squeeze(out);
    }

    /// Squeezes whole rate-sized blocks directly from the permutation state;
    /// `out.len()` must be a multiple of `RATE` and the reader must be
    /// block-aligned (no previous partial `read`).
    ///
    /// # Panics
    ///
    /// Panics if `out.len()` is not a multiple of `RATE`.
    pub fn read_blocks(&mut self, out: &mut [u8]) {
        assert_eq!(out.len() % RATE, 0);
        self.0.squeeze(out);
    }
}

impl<const RATE: usize> core::fmt::Debug for ShakeReader<RATE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShakeReader { .. }")
    }
}

macro_rules! shake_variant {
    ($(#[$m:meta])* $name:ident, $rate:literal) => {
        $(#[$m])*
        #[derive(Clone, Default)]
        pub struct $name(Sponge<$rate, 0x1f>);

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl $name {
            /// Rate in bytes.
            pub const RATE: usize = $rate;

            /// Starts a new computation.
            #[must_use]
            pub fn new() -> Self {
                Self::default()
            }

            /// Absorbs `data`.
            pub fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            /// Finishes absorbing and returns the output stream.
            #[must_use]
            pub fn finalize_xof(mut self) -> ShakeReader<$rate> {
                self.0.pad();
                ShakeReader(self.0)
            }

            /// One-shot: absorbs `data` and fills `out`.
            pub fn digest_into(data: &[u8], out: &mut [u8]) {
                let mut h = Self::new();
                h.update(data);
                h.finalize_xof().read(out);
            }
        }
    };
}

shake_variant!(
    /// SHAKE128.
    Shake128, 168
);
shake_variant!(
    /// SHAKE256.
    Shake256, 136
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(
            hex::encode(Sha3_256::digest(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex::encode(Sha3_256::digest(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex::encode(Sha3_512::digest(b"abc")),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        let mut out = [0u8; 32];
        Shake128::digest_into(b"", &mut out);
        assert_eq!(
            hex::encode(out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        Shake256::digest_into(b"", &mut out);
        assert_eq!(
            hex::encode(out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn incremental_squeeze() {
        let mut a = [0u8; 500];
        Shake128::digest_into(b"browntls", &mut a);
        let mut r = {
            let mut h = Shake128::new();
            h.update(b"brown");
            h.update(b"tls");
            h.finalize_xof()
        };
        let mut b = [0u8; 500];
        let (x, y) = b.split_at_mut(7);
        r.read(x);
        r.read(y);
        assert_eq!(a, b);
    }
}
