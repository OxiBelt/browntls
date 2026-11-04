//! AES-128 and AES-256 block encryption (FIPS 197).
//!
//! Only the forward cipher is provided: TLS and QUIC use AES exclusively in
//! counter-based modes (GCM) and for QUIC header protection, none of which
//! need the inverse cipher.
//!
//! Backends, selected once at key setup from [`crate::cpu::features`]:
//!
//! | Backend | Where | Notes |
//! |---|---|---|
//! | [`Backend::Soft`] | everywhere | 64-bit bitsliced, four blocks in parallel, constant time |
//! | [`Backend::AesNi`] | x86-64 with AES-NI | eight independent blocks per iteration |
//! | [`Backend::Vaes`] | x86-64 with VAES + AVX2 | sixteen blocks per iteration on YMM registers |
//! | [`Backend::VaesAvx512`] | x86-64 with VAES + AVX-512 | thirty-two blocks per iteration on ZMM registers |
//! | [`Backend::ArmAes`] | aarch64 with FEAT_AES | eight independent blocks per iteration |
//! | [`Backend::RvZvkned`] | riscv64 with RVV 1.0 + Zvkned + Zvkb | `LMUL=4`, VLEN-agnostic |
//! | [`Backend::RvZkne`] | riscv64 with Zkne | scalar `aes64es`/`aes64esm`, four blocks interleaved |
//!
//! The key schedule is always computed by the portable code (its `SubWord`
//! uses the bitsliced S-box, so no table is indexed by key material); the
//! hardware backends consume the resulting round keys. Expanded keys are
//! zeroised on drop.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
mod soft;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86_vaes;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
pub(crate) mod x86_vaes512;

use crate::Error;
use crate::cpu::features;
use crate::zeroize::{zeroize_bytes, zeroize_u32};

/// AES block length in bytes.
pub const BLOCK_LEN: usize = 16;

/// Round keys in FIPS 197 byte order (`rk[r]` is XORed into the state before
/// round `r + 1`). Zeroised on drop.
#[cfg_attr(
    not(any(
        all(target_arch = "x86_64", target_feature = "sse2"),
        target_arch = "aarch64",
        target_arch = "riscv64"
    )),
    allow(dead_code)
)]
pub(crate) struct RoundKeys {
    pub(crate) rk: [[u8; 16]; 15],
    pub(crate) rounds: usize,
}

#[cfg_attr(
    not(any(
        all(target_arch = "x86_64", target_feature = "sse2"),
        target_arch = "aarch64",
        target_arch = "riscv64"
    )),
    allow(dead_code)
)]
impl RoundKeys {
    fn new(words: &[u32; 60], rounds: usize) -> Self {
        let mut rk = [[0u8; 16]; 15];
        for (r, key) in rk.iter_mut().enumerate().take(rounds + 1) {
            for (c, chunk) in key.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *chunk = words[4 * r + c].to_le_bytes();
            }
        }
        Self { rk, rounds }
    }
}

impl Drop for RoundKeys {
    fn drop(&mut self) {
        for key in &mut self.rk {
            zeroize_bytes(key);
        }
    }
}

/// AES implementation backends. Exposed for differential testing; the
/// dispatcher picks the best available one automatically.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// Portable bitsliced implementation (always available).
    Soft,
    /// x86-64 AES-NI on XMM registers.
    AesNi,
    /// x86-64 VAES on YMM registers (requires AVX2).
    Vaes,
    /// x86-64 VAES on ZMM registers (requires AVX-512 F/BW/VL).
    VaesAvx512,
    /// Armv8 Cryptographic Extension (FEAT_AES).
    ArmAes,
    /// RISC-V vector AES (Zvkned over RVV 1.0).
    RvZvkned,
    /// RISC-V scalar AES (Zkne).
    RvZkne,
}

impl Backend {
    /// Every backend, in no particular order.
    pub const ALL: [Self; 7] = [
        Self::Soft,
        Self::AesNi,
        Self::Vaes,
        Self::VaesAvx512,
        Self::ArmAes,
        Self::RvZvkned,
        Self::RvZkne,
    ];

    /// Returns whether this backend can run on the current CPU.
    #[must_use]
    pub fn is_available(self) -> bool {
        let f = features();
        match self {
            Self::Soft => true,
            Self::AesNi => f.x86_aes() && f.x86_sse41(),
            Self::Vaes => f.x86_vaes() && f.x86_avx2() && f.x86_aes() && f.x86_sse41(),
            Self::VaesAvx512 => {
                f.x86_avx512() && f.x86_vaes() && f.x86_avx2() && f.x86_aes() && f.x86_sse41()
            }
            Self::ArmAes => f.arm_aes(),
            // The CTR path byte-swaps counters with Zvkb `vrev8.v`.
            Self::RvZvkned => f.rv_v() && f.rv_zvkned() && f.rv_zvkb(),
            Self::RvZkne => f.rv_zkne(),
        }
    }

    /// The backend the dispatcher selects on the current CPU.
    #[must_use]
    pub fn select() -> Self {
        crate::accel::select::<Self>()
    }
}

impl crate::accel::Backends for Backend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::Aes;
    const PREFERENCE: &'static [Self] = &[
        Self::VaesAvx512,
        Self::Vaes,
        Self::AesNi,
        Self::ArmAes,
        Self::RvZvkned,
        Self::RvZkne,
        Self::Soft,
    ];

    fn available(self) -> bool {
        self.is_available()
    }

    fn uses(self) -> crate::accel::Uses {
        use crate::accel::Uses;
        match self {
            Self::Soft => Uses::PORTABLE,
            Self::AesNi => Uses::DEDICATED,
            Self::Vaes => Uses::BOTH,
            Self::VaesAvx512 => Uses::BOTH,
            Self::ArmAes => Uses::DEDICATED,
            Self::RvZvkned => Uses::BOTH,
            Self::RvZkne => Uses::DEDICATED,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Soft => "portable",
            Self::AesNi => "AES-NI",
            Self::Vaes => "VAES (AVX2)",
            Self::VaesAvx512 => "VAES (AVX-512)",
            Self::ArmAes => "FEAT_AES",
            Self::RvZvkned => "Zvkned",
            Self::RvZkne => "Zkne",
        }
    }
}

// Keys are long-lived (one per connection); the 960-byte bitsliced schedule is
// not worth an allocation.
#[allow(clippy::large_enum_variant)]
enum Imp {
    Soft(soft::Key),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    AesNi(x86::Key),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    Vaes(x86_vaes::Key),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    VaesAvx512(x86_vaes512::Key),
    #[cfg(target_arch = "aarch64")]
    ArmAes(aarch64::Key),
    #[cfg(target_arch = "riscv64")]
    RvZvkned(riscv64::VectorKey),
    #[cfg(target_arch = "riscv64")]
    RvZkne(riscv64::ScalarKey),
}

/// An expanded AES key of either size, shared by the block cipher types and
/// AES-GCM.
pub(crate) struct Key {
    imp: Imp,
}

impl Key {
    /// Expands `key` (16 or 32 bytes) for `backend`.
    ///
    /// Returns [`Error::Unsupported`] when the backend cannot run on this CPU
    /// and [`Error::InvalidKey`] for other key lengths.
    pub(crate) fn new(key: &[u8], backend: Backend) -> Result<Self, Error> {
        if key.len() != 16 && key.len() != 32 {
            return Err(Error::InvalidKey);
        }
        if !backend.is_available() {
            return Err(Error::Unsupported);
        }
        let (mut words, rounds) = soft::key_schedule(key);
        let imp = match backend {
            Backend::Soft => Imp::Soft(soft::Key::new(&words, rounds)),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::AesNi => Imp::AesNi(x86::Key::new(RoundKeys::new(&words, rounds))),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::Vaes => Imp::Vaes(x86_vaes::Key::new(RoundKeys::new(&words, rounds))),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::VaesAvx512 => {
                Imp::VaesAvx512(x86_vaes512::Key::new(RoundKeys::new(&words, rounds)))
            }
            #[cfg(target_arch = "aarch64")]
            Backend::ArmAes => Imp::ArmAes(aarch64::Key::new(RoundKeys::new(&words, rounds))),
            #[cfg(target_arch = "riscv64")]
            Backend::RvZvkned => {
                Imp::RvZvkned(riscv64::VectorKey::new(RoundKeys::new(&words, rounds)))
            }
            #[cfg(target_arch = "riscv64")]
            Backend::RvZkne => Imp::RvZkne(riscv64::ScalarKey::new(RoundKeys::new(&words, rounds))),
            #[allow(unreachable_patterns)]
            _ => return Err(Error::Unsupported),
        };
        zeroize_u32(&mut words);
        Ok(Self { imp })
    }

    /// The backend in use.
    pub(crate) fn backend(&self) -> Backend {
        match &self.imp {
            Imp::Soft(_) => Backend::Soft,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::AesNi(_) => Backend::AesNi,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::Vaes(_) => Backend::Vaes,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::VaesAvx512(_) => Backend::VaesAvx512,
            #[cfg(target_arch = "aarch64")]
            Imp::ArmAes(_) => Backend::ArmAes,
            #[cfg(target_arch = "riscv64")]
            Imp::RvZvkned(_) => Backend::RvZvkned,
            #[cfg(target_arch = "riscv64")]
            Imp::RvZkne(_) => Backend::RvZkne,
        }
    }

    /// The ZMM VAES key, when that backend is in use (for the fused AES-GCM
    /// path).
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    pub(crate) fn vaes_avx512(&self) -> Option<&x86_vaes512::Key> {
        match &self.imp {
            Imp::VaesAvx512(k) => Some(k),
            _ => None,
        }
    }

    /// Encrypts every block in place.
    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        match &self.imp {
            Imp::Soft(k) => k.encrypt_blocks(blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::AesNi(k) => k.encrypt_blocks(blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::Vaes(k) => k.encrypt_blocks(blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::VaesAvx512(k) => k.encrypt_blocks(blocks),
            #[cfg(target_arch = "aarch64")]
            Imp::ArmAes(k) => k.encrypt_blocks(blocks),
            #[cfg(target_arch = "riscv64")]
            Imp::RvZvkned(k) => k.encrypt_blocks(blocks),
            #[cfg(target_arch = "riscv64")]
            Imp::RvZkne(k) => k.encrypt_blocks(blocks),
        }
    }

    /// XORs `in_out` with the CTR keystream whose first block is `ctr` and
    /// whose last four bytes count up modulo 2^32 in big-endian order
    /// (the GCM `inc32` function).
    pub(crate) fn ctr32_xor(&self, ctr: &[u8; 16], in_out: &mut [u8]) {
        match &self.imp {
            Imp::Soft(k) => ctr32_xor_generic(|b| k.encrypt_blocks(b), ctr, in_out),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::AesNi(k) => k.ctr32_xor(ctr, in_out),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::Vaes(k) => k.ctr32_xor(ctr, in_out),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::VaesAvx512(k) => k.ctr32_xor(ctr, in_out),
            #[cfg(target_arch = "aarch64")]
            Imp::ArmAes(k) => k.ctr32_xor(ctr, in_out),
            #[cfg(target_arch = "riscv64")]
            Imp::RvZvkned(k) => k.ctr32_xor(ctr, in_out),
            #[cfg(target_arch = "riscv64")]
            Imp::RvZkne(k) => ctr32_xor_generic(|b| k.encrypt_blocks(b), ctr, in_out),
        }
    }
}

/// CTR keystream application built on a block-encryption primitive, eight
/// blocks per call.
pub(crate) fn ctr32_xor_generic(
    encrypt: impl Fn(&mut [[u8; 16]]),
    ctr: &[u8; 16],
    in_out: &mut [u8],
) {
    let mut counter = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
    let mut ks = [[0u8; 16]; 8];
    let (blocks, rest) = in_out.as_chunks_mut::<16>();
    for batch in blocks.chunks_mut(8) {
        for k in ks.iter_mut().take(batch.len()) {
            *k = *ctr;
            k[12..].copy_from_slice(&counter.to_be_bytes());
            counter = counter.wrapping_add(1);
        }
        encrypt(&mut ks[..batch.len()]);
        for (block, k) in batch.iter_mut().zip(&ks) {
            for (b, kb) in block.iter_mut().zip(k) {
                *b ^= kb;
            }
        }
    }
    if !rest.is_empty() {
        ks[0] = *ctr;
        ks[0][12..].copy_from_slice(&counter.to_be_bytes());
        encrypt(&mut ks[..1]);
        for (b, kb) in rest.iter_mut().zip(&ks[0]) {
            *b ^= kb;
        }
    }
    for k in &mut ks {
        zeroize_bytes(k);
    }
}

macro_rules! aes_variant {
    ($(#[$m:meta])* $name:ident, $len:literal) => {
        $(#[$m])*
        pub struct $name {
            key: Key,
        }

        impl $name {
            /// Expands `key` using the best backend available on this CPU.
            #[must_use]
            pub fn new(key: &[u8; $len]) -> Self {
                match Key::new(key, Backend::select()) {
                    Ok(key) => Self { key },
                    // `select` only returns available backends and the key
                    // length is fixed by the type, so this cannot fail; fall
                    // back to the portable code rather than panic.
                    Err(_) => Self::soft(key),
                }
            }

            fn soft(key: &[u8; $len]) -> Self {
                let (mut words, rounds) = soft::key_schedule(key);
                let imp = Imp::Soft(soft::Key::new(&words, rounds));
                zeroize_u32(&mut words);
                Self { key: Key { imp } }
            }

            /// Expands `key` for a specific backend (differential testing).
            ///
            /// # Errors
            ///
            /// Returns [`Error::Unsupported`] if `backend` cannot run here.
            #[doc(hidden)]
            pub fn with_backend(key: &[u8; $len], backend: Backend) -> Result<Self, Error> {
                Key::new(key, backend).map(|key| Self { key })
            }

            /// The backend in use.
            #[doc(hidden)]
            #[must_use]
            pub fn backend(&self) -> Backend {
                self.key.backend()
            }

            /// Encrypts one block in place.
            pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
                self.key.encrypt_blocks(core::slice::from_mut(block));
            }

            /// Encrypts every block in place (independently, ECB-style; used
            /// for QUIC header protection and as a building block for
            /// counter modes).
            pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
                self.key.encrypt_blocks(blocks);
            }

            /// XORs `in_out` with the counter-mode keystream starting at
            /// `counter_block`, incrementing its last 32 bits as a big-endian
            /// integer modulo 2^32 for every subsequent block (GCM `inc32`).
            pub fn ctr32_xor(&self, counter_block: &[u8; BLOCK_LEN], in_out: &mut [u8]) {
                self.key.ctr32_xor(counter_block, in_out);
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("backend", &self.backend())
                    .finish_non_exhaustive()
            }
        }
    };
}

aes_variant!(
    /// AES-128 (encryption only).
    Aes128, 16
);
aes_variant!(
    /// AES-256 (encryption only).
    Aes256, 32
);

#[cfg(test)]
mod tests {
    use super::*;

    const FIPS197_PT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    #[test]
    fn fips197_c1_aes128() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        for backend in Backend::ALL {
            let Ok(aes) = Aes128::with_backend(&key, backend) else {
                continue;
            };
            let mut block = FIPS197_PT;
            aes.encrypt_block(&mut block);
            assert_eq!(
                hex::encode(block),
                "69c4e0d86a7b0430d8cdb78070b4c55a",
                "{backend:?}"
            );
        }
    }

    #[test]
    fn fips197_c3_aes256() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        for backend in Backend::ALL {
            let Ok(aes) = Aes256::with_backend(&key, backend) else {
                continue;
            };
            let mut block = FIPS197_PT;
            aes.encrypt_block(&mut block);
            assert_eq!(
                hex::encode(block),
                "8ea2b7ca516745bfeafc49904b496089",
                "{backend:?}"
            );
        }
    }

    #[test]
    fn selected_backend_is_available() {
        assert!(Backend::select().is_available());
        assert_eq!(Aes128::new(&[0; 16]).backend(), Backend::select());
    }

    #[test]
    fn ctr_matches_block_encryption_on_all_backends() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let mut ctr = [0xa5u8; 16];
        // Start near the 32-bit wrap to exercise it.
        ctr[12..].copy_from_slice(&0xffff_fffdu32.to_be_bytes());
        let data: std::vec::Vec<u8> = (0..1000u32).map(|i| (i * 13 + 5) as u8).collect();
        for backend in Backend::ALL {
            let Ok(aes) = Aes256::with_backend(&key, backend) else {
                continue;
            };
            for len in [
                0usize, 1, 15, 16, 17, 64, 65, 127, 128, 129, 255, 256, 257, 1000,
            ] {
                let mut out = data[..len].to_vec();
                aes.ctr32_xor(&ctr, &mut out);
                let mut expected = data[..len].to_vec();
                let mut c = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
                for chunk in expected.chunks_mut(16) {
                    let mut ks = ctr;
                    ks[12..].copy_from_slice(&c.to_be_bytes());
                    c = c.wrapping_add(1);
                    Aes256::with_backend(&key, Backend::Soft)
                        .unwrap()
                        .encrypt_block(&mut ks);
                    for (b, k) in chunk.iter_mut().zip(ks) {
                        *b ^= k;
                    }
                }
                assert_eq!(out, expected, "{backend:?} len={len}");
            }
        }
    }
}
