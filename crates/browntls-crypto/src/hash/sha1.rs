//! SHA-1 (FIPS 180-4, RFC 3174), for HMAC-SHA1 in TLS 1.2 CBC suites only.
//!
//! SHA-1 is not collision resistant (practical chosen-prefix collisions are
//! known) and must never be used for signatures, certificate fingerprints or
//! any other purpose that relies on collision resistance. browntls uses it
//! only as the hash of HMAC-SHA1, the record MAC of the TLS 1.2
//! `*_CBC_SHA` cipher suites (see [`crate::tls_cbc`]); HMAC security rests on
//! the pseudorandomness of the compression function, which collision attacks
//! do not break.

use super::{BlockBuffer, HashFunction};
use crate::cpu::Features;

const BLOCK: usize = 64;

/// The round constants, one per group of 20 rounds.
pub(crate) const K: [u32; 4] = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6];

pub(crate) const IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86;

/// A SHA-1 compression backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    /// Portable code.
    Soft,
    /// x86-64 SHA extensions (`SHA1RNDS4`, `SHA1NEXTE`, `SHA1MSG1/2`).
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    ShaNi,
    /// Armv8 FEAT_SHA1 (`SHA1C/P/M`, `SHA1H`, `SHA1SU0/1`; Rust target
    /// feature `sha2`).
    #[cfg(target_arch = "aarch64")]
    ArmSha1,
    /// riscv64 scalar code compiled with Zbb (`RORIW`, `ANDN`). RISC-V has no
    /// SHA-1 extension.
    #[cfg(target_arch = "riscv64")]
    RvZbb,
}

impl Backend {
    /// Every backend in order of preference.
    pub(crate) const ALL: &'static [Self] = &[
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        Self::ShaNi,
        #[cfg(target_arch = "aarch64")]
        Self::ArmSha1,
        #[cfg(target_arch = "riscv64")]
        Self::RvZbb,
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
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha1 => aarch64::available(f),
            #[cfg(target_arch = "riscv64")]
            Self::RvZbb => riscv64::zbb_available(f),
        }
    }

    /// A display name for acceleration status reports.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Soft => "portable",
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::ShaNi => "SHA-NI",
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha1 => "FEAT_SHA1",
            #[cfg(target_arch = "riscv64")]
            Self::RvZbb => "Zbb",
        }
    }

    /// Compresses `blocks` (a multiple of 64 bytes) into `state`. Falls back
    /// to [`soft`] if the backend is not available on this CPU.
    pub(crate) fn compress(self, state: &mut [u32; 5], blocks: &[u8]) {
        match self {
            Self::Soft => soft::compress(state, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::ShaNi => x86::compress(state, blocks),
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha1 => aarch64::compress(state, blocks),
            #[cfg(target_arch = "riscv64")]
            Self::RvZbb => riscv64::compress_zbb(state, blocks),
        }
    }
}

impl crate::accel::Backends for Backend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::Sha1;
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
            #[cfg(target_arch = "aarch64")]
            Self::ArmSha1 => Uses::DEDICATED,
            #[cfg(target_arch = "riscv64")]
            Self::RvZbb => Uses::DEDICATED,
        }
    }

    fn name(self) -> &'static str {
        Backend::name(self)
    }
}

/// Compresses `blocks` (a multiple of 64 bytes) into `state`, selecting the
/// best available backend.
#[inline]
pub(crate) fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % BLOCK, 0);
    crate::accel::select::<Backend>().compress(state, blocks);
}

pub(crate) mod soft {
    use super::K;

    /// Portable SHA-1 compression. Inlined into accelerated callers so it is
    /// compiled with their target features.
    #[inline(always)]
    pub(crate) fn compress(state: &mut [u32; 5], blocks: &[u8]) {
        for block in blocks.as_chunks::<64>().0 {
            // 16-word circular message schedule (FIPS 180-4, section 6.1.3).
            let mut w = [0u32; 16];
            for (wi, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
                *wi = u32::from_be_bytes(*word);
            }
            let mut v = *state;
            // Rounds `$t` with round function `$f` and constant `$k`.
            macro_rules! rounds {
                ($t:expr, $f:expr, $k:expr) => {
                    for t in $t {
                        if t >= 16 {
                            w[t % 16] =
                                (w[(t + 13) % 16] ^ w[(t + 8) % 16] ^ w[(t + 2) % 16] ^ w[t % 16])
                                    .rotate_left(1);
                        }
                        let [a, b, c, d, e] = v;
                        let f: u32 = $f(b, c, d);
                        let tmp = a
                            .rotate_left(5)
                            .wrapping_add(f)
                            .wrapping_add(e)
                            .wrapping_add($k)
                            .wrapping_add(w[t % 16]);
                        v = [tmp, a, b.rotate_left(30), c, d];
                    }
                };
            }
            rounds!(0..20, |b: u32, c: u32, d: u32| (b & c) | (!b & d), K[0]);
            rounds!(20..40, |b: u32, c: u32, d: u32| b ^ c ^ d, K[1]);
            rounds!(
                40..60,
                |b: u32, c: u32, d: u32| (b & c) | (b & d) | (c & d),
                K[2]
            );
            rounds!(60..80, |b: u32, c: u32, d: u32| b ^ c ^ d, K[3]);
            for (s, x) in state.iter_mut().zip(v) {
                *s = s.wrapping_add(x);
            }
        }
    }
}

#[derive(Clone)]
struct Core {
    state: [u32; 5],
    buffer: BlockBuffer<BLOCK>,
    total: u64,
}

impl Core {
    fn new(state: [u32; 5], total: u64) -> Self {
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

    fn finalize(mut self) -> [u32; 5] {
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

/// SHA-1, for HMAC-SHA1 in TLS 1.2 `*_CBC_SHA` cipher suites only.
///
/// SHA-1 is not collision resistant: never use it for signatures,
/// certificate fingerprints or other collision-sensitive purposes.
#[derive(Clone)]
pub struct Sha1(Core);

impl Default for Sha1 {
    fn default() -> Self {
        Self(Core::new(IV, 0))
    }
}

impl core::fmt::Debug for Sha1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sha1 { .. }")
    }
}

impl HashFunction for Sha1 {
    const OUTPUT_LEN: usize = 20;
    const BLOCK_LEN: usize = BLOCK;
    type Output = [u8; 20];

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> [u8; 20] {
        let mut out = [0u8; 20];
        write_digest(&self.0.finalize(), &mut out);
        out
    }
}

fn write_digest(state: &[u32; 5], out: &mut [u8]) {
    for (chunk, word) in out.chunks_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes()[..chunk.len()]);
    }
}

impl super::MdHash for Sha1 {
    type State = [u32; 5];
    const LEN_BYTES: usize = 8;
    const IV: [u32; 5] = IV;

    fn compress_blocks(state: &mut [u32; 5], blocks: &[u8]) {
        compress(state, blocks);
    }

    fn write_digest(state: &[u32; 5], out: &mut [u8]) {
        write_digest(state, out);
    }

    fn from_state(state: [u32; 5], bytes: u64) -> Self {
        Self(Core::new(state, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        // FIPS 180-4 examples / RFC 3174 section 7.3.
        assert_eq!(
            hex::encode(Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex::encode(Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        // RFC 3174 TEST4: "01234567" repeated 80 times.
        let t4 = b"0123456701234567012345670123456701234567012345670123456701234567".repeat(10);
        assert_eq!(
            hex::encode(Sha1::digest(&t4)),
            "dea356a2cddd90c7a7ecedc5ebb563934f460452"
        );
        // FIPS 180-4 long message: one million 'a'.
        let mut h = Sha1::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex::encode(h.finalize()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data: std::vec::Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for split in [0, 1, 55, 56, 63, 64, 65, 127, 128, 500, 1000] {
            let mut h = Sha1::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), Sha1::digest(&data));
        }
    }
}
