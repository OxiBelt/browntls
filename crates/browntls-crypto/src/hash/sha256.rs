//! SHA-224 and SHA-256 (FIPS 180-4).

use super::{BlockBuffer, HashFunction};
use crate::cpu::Features;

const BLOCK: usize = 64;

pub(crate) const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const H224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86;

/// A SHA-256 compression backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    /// Portable code.
    Soft,
    /// x86-64 SHA extensions (`SHA256RNDS2`, `SHA256MSG1/2`).
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    ShaNi,
    /// x86-64-v3: AVX2 message schedule (two blocks at a time) and BMI2
    /// scalar rounds.
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    X86V3,
    /// Armv8 FEAT_SHA256 (`SHA256H`, `SHA256H2`, `SHA256SU0/1`).
    #[cfg(target_arch = "aarch64")]
    ArmSha2,
    /// RISC-V vector crypto Zvknha (`vsha2ms`, `vsha2ch`, `vsha2cl`) with
    /// Zvkb (`vrev8`).
    #[cfg(target_arch = "riscv64")]
    Zvknha,
    /// RISC-V scalar crypto Zknh (`sha256sig0/1`, `sha256sum0/1`).
    #[cfg(target_arch = "riscv64")]
    Zknh,
}

impl Backend {
    /// Every backend in order of preference.
    pub(crate) const ALL: &'static [Self] = &[
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        Self::ShaNi,
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        Self::X86V3,
        #[cfg(target_arch = "aarch64")]
        Self::ArmSha2,
        #[cfg(target_arch = "riscv64")]
        Self::Zvknha,
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
            Self::ShaNi => x86::available(f),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86V3 => x86::v3_available(f),
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha2 => aarch64::available(f),
            #[cfg(target_arch = "riscv64")]
            Self::Zvknha => riscv64::zvknha_available(f),
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
            Self::ShaNi => "SHA-NI",
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86V3 => "x86-64-v3 (AVX2+BMI2)",
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha2 => "FEAT_SHA256",
            #[cfg(target_arch = "riscv64")]
            Self::Zvknha => "Zvknha",
            #[cfg(target_arch = "riscv64")]
            Self::Zknh => "Zknh",
        }
    }

    /// Compresses `blocks` (a multiple of 64 bytes) into `state`. Falls back
    /// to [`soft`] if the backend is not available on this CPU.
    pub(crate) fn compress(self, state: &mut [u32; 8], blocks: &[u8]) {
        match self {
            Self::Soft => soft::compress(state, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::ShaNi => x86::compress(state, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86V3 => x86::compress_v3(state, blocks),
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha2 => aarch64::compress(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Self::Zvknha => riscv64::compress_zvknha(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Self::Zknh => riscv64::compress_zknh(state, blocks),
        }
    }
}

impl crate::accel::Backends for Backend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::Sha256;
    const PREFERENCE: &'static [Self] = Self::ALL;

    fn available(self) -> bool {
        self.is_available(crate::cpu::features())
    }

    fn uses(self) -> crate::accel::Uses {
        use crate::accel::Uses;
        match self {
            Self::Soft => Uses::PORTABLE,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::ShaNi => Uses::DEDICATED,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::X86V3 => Uses::BOTH,
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha2 => Uses::DEDICATED,
            #[cfg(target_arch = "riscv64")]
            Self::Zvknha => Uses::BOTH,
            #[cfg(target_arch = "riscv64")]
            Self::Zknh => Uses::DEDICATED,
        }
    }

    fn name(self) -> &'static str {
        Backend::name(self)
    }
}

/// Compresses `blocks` (a multiple of 64 bytes) into `state`, selecting the
/// best available backend.
#[inline]
pub(crate) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % BLOCK, 0);
    crate::accel::select::<Backend>().compress(state, blocks);
}

pub(crate) mod soft {
    use super::K;

    /// Portable SHA-256 compression.
    pub(crate) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
        for block in blocks.as_chunks::<64>().0 {
            let mut w = [0u32; 64];
            for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
                w[i] = u32::from_be_bytes(*word);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
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

    /// The 64 rounds and feed-forward, given `W[i] + K[i]`. Inlined into
    /// accelerated callers so it is compiled with their target features.
    #[inline(always)]
    pub(crate) fn rounds(state: &mut [u32; 8], wk: &[u32; 64]) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for &wki in wk {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(wki);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
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
    state: [u32; 8],
    buffer: BlockBuffer<BLOCK>,
    total: u64,
}

impl Core {
    fn new(iv: [u32; 8]) -> Self {
        Self::with_state(iv, 0)
    }

    fn with_state(state: [u32; 8], total: u64) -> Self {
        Self {
            state,
            buffer: BlockBuffer::default(),
            total,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        let state = &mut self.state;
        self.buffer.update(data, |blocks| compress(state, blocks));
    }

    fn finalize(mut self) -> [u32; 8] {
        let bit_len = self.total.wrapping_mul(8);
        let mut pad = [0u8; 2 * BLOCK];
        pad[0] = 0x80;
        let used = self.buffer.len;
        let pad_len = if used < 56 { 56 - used } else { 120 - used };
        pad[pad_len..pad_len + 8].copy_from_slice(&bit_len.to_be_bytes());
        let state = &mut self.state;
        self.buffer
            .update(&pad[..pad_len + 8], |blocks| compress(state, blocks));
        debug_assert_eq!(self.buffer.len, 0);
        self.state
    }
}

/// Big-endian serialisation of `state`, truncated to `out.len()` bytes.
fn write_digest(state: &[u32; 8], out: &mut [u8]) {
    for (chunk, word) in out.chunks_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes()[..chunk.len()]);
    }
}

macro_rules! sha256_variant {
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
            type State = [u32; 8];
            const LEN_BYTES: usize = 8;
            const IV: [u32; 8] = $iv;

            fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
                compress(state, blocks);
            }

            fn write_digest(state: &[u32; 8], out: &mut [u8]) {
                debug_assert_eq!(out.len(), $out);
                write_digest(state, out);
            }

            fn from_state(state: [u32; 8], bytes: u64) -> Self {
                Self(Core::with_state(state, bytes))
            }
        }
    };
}

sha256_variant!(
    /// SHA-256.
    Sha256, H256, 32
);
sha256_variant!(
    /// SHA-224.
    Sha224, H224, 28
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(
            hex::encode(Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(Sha256::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex::encode(Sha224::digest(b"abc")),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data: std::vec::Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for split in [0, 1, 55, 56, 63, 64, 65, 127, 128, 500, 1000] {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), Sha256::digest(&data));
        }
    }
}
