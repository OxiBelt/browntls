//! SHA-384 and SHA-512 (FIPS 180-4).

use super::{BlockBuffer, HashFunction};
use crate::cpu::Features;

const BLOCK: usize = 128;

pub(crate) const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const H512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const H384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86;

/// A SHA-512 compression backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    /// Portable code.
    Soft,
    /// x86-64-v3: AVX2 message schedule (two blocks at a time) and BMI2
    /// scalar rounds.
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    X86V3,
    /// Armv8.2 FEAT_SHA512 (`SHA512H`, `SHA512H2`, `SHA512SU0/1`).
    #[cfg(target_arch = "aarch64")]
    ArmSha512,
    /// RISC-V vector crypto Zvknhb (`vsha2ms`, `vsha2ch`, `vsha2cl` at
    /// SEW=64) with Zvkb (`vrev8`).
    #[cfg(target_arch = "riscv64")]
    Zvknhb,
    /// RISC-V scalar crypto Zknh, RV64 forms (`sha512sig0/1`,
    /// `sha512sum0/1`).
    #[cfg(target_arch = "riscv64")]
    Zknh,
}

impl Backend {
    /// Every backend in order of preference.
    pub(crate) const ALL: &'static [Self] = &[
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        Self::X86V3,
        #[cfg(target_arch = "aarch64")]
        Self::ArmSha512,
        #[cfg(target_arch = "riscv64")]
        Self::Zvknhb,
        #[cfg(target_arch = "riscv64")]
        Self::Zknh,
        Self::Soft,
    ];

    /// Whether this backend can run with features `f`.
    pub(crate) fn is_available(self, f: Features) -> bool {
        // `f` is unused when every accelerated backend is compiled out.
        let _ = f;
        match self {
            Self::Soft => true,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86V3 => x86::available(f),
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha512 => aarch64::available(f),
            #[cfg(target_arch = "riscv64")]
            Self::Zvknhb => riscv64::zvknhb_available(f),
            #[cfg(target_arch = "riscv64")]
            Self::Zknh => riscv64::zknh_available(f),
        }
    }

    /// The preferred available backend.
    /// A display name for acceleration status reports.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Soft => "portable",
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86V3 => "x86-64-v3 (AVX2+BMI2)",
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha512 => "FEAT_SHA512",
            #[cfg(target_arch = "riscv64")]
            Self::Zvknhb => "Zvknhb",
            #[cfg(target_arch = "riscv64")]
            Self::Zknh => "Zknh",
        }
    }

    /// Compresses `blocks` (a multiple of 128 bytes) into `state`. Falls
    /// back to [`soft`] if the backend is not available on this CPU.
    pub(crate) fn compress(self, state: &mut [u64; 8], blocks: &[u8]) {
        match self {
            Self::Soft => soft::compress(state, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86V3 => x86::compress(state, blocks),
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha512 => aarch64::compress(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Self::Zvknhb => riscv64::compress_zvknhb(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Self::Zknh => riscv64::compress_zknh(state, blocks),
        }
    }
}

impl crate::accel::Backends for Backend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::Sha512;
    const PREFERENCE: &'static [Self] = Self::ALL;

    fn available(self) -> bool {
        self.is_available(crate::cpu::features())
    }

    fn uses(self) -> crate::accel::Uses {
        use crate::accel::Uses;
        match self {
            Self::Soft => Uses::PORTABLE,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86V3 => Uses::BOTH,
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha512 => Uses::DEDICATED,
            #[cfg(target_arch = "riscv64")]
            Self::Zvknhb => Uses::BOTH,
            #[cfg(target_arch = "riscv64")]
            Self::Zknh => Uses::DEDICATED,
        }
    }

    fn name(self) -> &'static str {
        Backend::name(self)
    }
}

/// Compresses `blocks` (a multiple of 128 bytes) into `state`, selecting the
/// best available backend.
#[inline]
pub(crate) fn compress(state: &mut [u64; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % BLOCK, 0);
    crate::accel::select::<Backend>().compress(state, blocks);
}

pub(crate) mod soft {
    use super::K;

    /// Portable SHA-512 compression.
    pub(crate) fn compress(state: &mut [u64; 8], blocks: &[u8]) {
        for block in blocks.as_chunks::<128>().0 {
            let mut w = [0u64; 80];
            for (i, word) in block.as_chunks::<8>().0.iter().enumerate() {
                w[i] = u64::from_be_bytes(*word);
            }
            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            for (wi, ki) in w.iter_mut().zip(K) {
                *wi = wi.wrapping_add(ki);
            }
            rounds(state, &w);
        }
    }

    /// The 80 rounds and feed-forward, given `W[i] + K[i]`. Inlined into
    /// accelerated callers so it is compiled with their target features.
    #[inline(always)]
    pub(crate) fn rounds(state: &mut [u64; 8], wk: &[u64; 80]) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for &wki in wk {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(wki);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

#[derive(Clone)]
struct Core {
    state: [u64; 8],
    buffer: BlockBuffer<BLOCK>,
    total: u128,
}

impl Core {
    fn new(iv: [u64; 8]) -> Self {
        Self::with_state(iv, 0)
    }

    fn with_state(state: [u64; 8], total: u128) -> Self {
        Self {
            state,
            buffer: BlockBuffer::default(),
            total,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u128);
        let state = &mut self.state;
        self.buffer.update(data, |blocks| compress(state, blocks));
    }

    fn finalize(mut self) -> [u64; 8] {
        let bit_len = self.total.wrapping_mul(8);
        let mut pad = [0u8; 2 * BLOCK];
        pad[0] = 0x80;
        let used = self.buffer.len;
        let pad_len = if used < 112 { 112 - used } else { 240 - used };
        pad[pad_len..pad_len + 16].copy_from_slice(&bit_len.to_be_bytes());
        let state = &mut self.state;
        self.buffer
            .update(&pad[..pad_len + 16], |blocks| compress(state, blocks));
        debug_assert_eq!(self.buffer.len, 0);
        self.state
    }
}

/// Big-endian serialisation of `state`, truncated to `out.len()` bytes.
fn write_digest(state: &[u64; 8], out: &mut [u8]) {
    for (chunk, word) in out.chunks_mut(8).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes()[..chunk.len()]);
    }
}

macro_rules! sha512_variant {
    ($(#[$m:meta])* $name:ident, $iv:expr, $out:literal) => {
        $(#[$m])*
        #[derive(Clone)]
        pub struct $name(Core);

        impl Default for $name {
            fn default() -> Self {
                Self(Core::new($iv))
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl HashFunction for $name {
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = BLOCK;
            type Output = [u8; $out];

            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            fn finalize(self) -> [u8; $out] {
                let mut out = [0u8; $out];
                write_digest(&self.0.finalize(), &mut out);
                out
            }
        }

        impl super::MdHash for $name {
            type State = [u64; 8];
            const LEN_BYTES: usize = 16;
            const IV: [u64; 8] = $iv;

            fn compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
                compress(state, blocks);
            }

            fn write_digest(state: &[u64; 8], out: &mut [u8]) {
                debug_assert_eq!(out.len(), $out);
                write_digest(state, out);
            }

            fn from_state(state: [u64; 8], bytes: u64) -> Self {
                Self(Core::with_state(state, bytes.into()))
            }
        }
    };
}

sha512_variant!(
    /// SHA-512.
    Sha512, H512, 64
);
sha512_variant!(
    /// SHA-384.
    Sha384, H384, 48
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(
            hex::encode(Sha512::digest(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hex::encode(Sha384::digest(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex::encode(Sha512::digest(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data: std::vec::Vec<u8> = (0..1000u32).map(|i| (i * 13 + 1) as u8).collect();
        for split in [0, 1, 111, 112, 127, 128, 129, 255, 256, 999] {
            let mut h = Sha512::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), Sha512::digest(&data));
        }
    }
}
