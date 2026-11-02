//! ChaCha20 (RFC 8439), Poly1305 and the ChaCha20-Poly1305 AEAD.
//!
//! ChaCha20 dispatches at run time (see [`crate::cpu::features`]) between:
//!
//! | Backend | Blocks per step | Requirement |
//! |---|---|---|
//! | [`Backend::Soft`] | 1 | none |
//! | [`Backend::Avx2`] | 8 (4 and 1 for tails) | x86-64-v3 |
//! | [`Backend::Avx512`] | 16 (8, 4, 1 for tails) | AVX-512 F/VL/BW/DQ |
//! | [`Backend::Neon`] | 4 (1 for tails) | aarch64 Advanced SIMD |
//! | [`Backend::Rvv`] | `VLEN / 32`, capped at 32 | RVV 1.0 (uses `vror` with Zvkb) |
//!
//! Poly1305 uses radix-2^64 scalar arithmetic on every architecture (see
//! [`PolyBackend`]).
//!
//! The ChaCha20 block counter is 32 bits and wraps modulo 2^32 in
//! [`chacha20_xor`]; [`ChaCha20Poly1305`] rejects messages that would wrap it.

/// Twenty ChaCha rounds over a word-sliced state `$x: [V; 16]` where each
/// vector lane holds the same word of a different block. The operations are
/// passed as function names so the macro expands inside each backend's
/// `#[target_feature]` function.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! chacha_rounds {
    ($x:ident, $add:ident, $xor:ident, $r16:ident, $r12:ident, $r8:ident, $r7:ident) => {
        for _ in 0..10 {
            chacha_rounds!(@qr $x, $add, $xor, $r16, $r12, $r8, $r7, 0, 4, 8, 12);
            chacha_rounds!(@qr $x, $add, $xor, $r16, $r12, $r8, $r7, 1, 5, 9, 13);
            chacha_rounds!(@qr $x, $add, $xor, $r16, $r12, $r8, $r7, 2, 6, 10, 14);
            chacha_rounds!(@qr $x, $add, $xor, $r16, $r12, $r8, $r7, 3, 7, 11, 15);
            chacha_rounds!(@qr $x, $add, $xor, $r16, $r12, $r8, $r7, 0, 5, 10, 15);
            chacha_rounds!(@qr $x, $add, $xor, $r16, $r12, $r8, $r7, 1, 6, 11, 12);
            chacha_rounds!(@qr $x, $add, $xor, $r16, $r12, $r8, $r7, 2, 7, 8, 13);
            chacha_rounds!(@qr $x, $add, $xor, $r16, $r12, $r8, $r7, 3, 4, 9, 14);
        }
    };
    (@qr $x:ident, $add:ident, $xor:ident, $r16:ident, $r12:ident, $r8:ident, $r7:ident,
     $a:literal, $b:literal, $c:literal, $d:literal) => {
        $x[$a] = $add($x[$a], $x[$b]);
        $x[$d] = $r16($xor($x[$d], $x[$a]));
        $x[$c] = $add($x[$c], $x[$d]);
        $x[$b] = $r12($xor($x[$b], $x[$c]));
        $x[$a] = $add($x[$a], $x[$b]);
        $x[$d] = $r8($xor($x[$d], $x[$a]));
        $x[$c] = $add($x[$c], $x[$d]);
        $x[$b] = $r7($xor($x[$b], $x[$c]));
    };
}

mod aead;
mod poly1305;
mod soft;

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "x86_64")]
mod x86;

pub use aead::ChaCha20Poly1305;
pub use poly1305::{
    KEY_LEN as POLY1305_KEY_LEN, Poly1305, PolyBackend, TAG_LEN as POLY1305_TAG_LEN,
};

use crate::Error;
use crate::zeroize::Zeroize;

/// ChaCha20 key length in bytes.
pub const KEY_LEN: usize = 32;
/// ChaCha20 (IETF) nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// ChaCha20 block length in bytes.
pub const BLOCK_LEN: usize = soft::BLOCK;

/// ChaCha20 implementation tiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Backend {
    /// Portable one-block-at-a-time code.
    Soft,
    /// x86-64 AVX2, eight blocks in parallel.
    Avx2,
    /// x86-64 AVX-512, sixteen blocks in parallel.
    Avx512,
    /// aarch64 Advanced SIMD, four blocks in parallel.
    Neon,
    /// riscv64 RVV 1.0, `vl` blocks in parallel.
    Rvv,
}

impl Backend {
    /// Every tier, in increasing order of preference within an architecture.
    pub const ALL: [Self; 5] = [Self::Soft, Self::Avx2, Self::Avx512, Self::Neon, Self::Rvv];

    /// Returns whether this tier can run on the current CPU.
    #[must_use]
    pub fn is_available(self) -> bool {
        let f = crate::cpu::features();
        match self {
            Self::Soft => true,
            Self::Avx2 => f.x86_v3(),
            Self::Avx512 => f.x86_v3() && f.x86_avx512(),
            Self::Neon => f.arm_neon() && cfg!(target_endian = "little"),
            Self::Rvv => f.rv_v(),
        }
    }

    /// The preferred available tier.
    #[must_use]
    pub fn best() -> Self {
        Self::ALL
            .into_iter()
            .rev()
            .find(|b| b.is_available())
            .unwrap_or(Self::Soft)
    }
}

/// Expanded ChaCha20 key (little-endian words), zeroised on drop.
#[derive(Clone)]
pub(crate) struct Key(pub(crate) [u32; 8]);

impl Key {
    pub(crate) fn new(key: &[u8; KEY_LEN]) -> Self {
        let mut k = [0u32; 8];
        for (w, b) in k.iter_mut().zip(key.as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*b);
        }
        Self(k)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn nonce_words(nonce: &[u8; NONCE_LEN]) -> [u32; 3] {
    let mut n = [0u32; 3];
    for (w, b) in n.iter_mut().zip(nonce.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*b);
    }
    n
}

/// Runs `backend` (which the caller verified is available).
fn xor_words(backend: Backend, key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8]) {
    match backend {
        #[cfg(target_arch = "x86_64")]
        Backend::Avx512 => x86::xor_avx512(key, counter, nonce, data),
        #[cfg(target_arch = "x86_64")]
        Backend::Avx2 => x86::xor_avx2(key, counter, nonce, data),
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        Backend::Neon => aarch64::xor_neon(key, counter, nonce, data),
        #[cfg(target_arch = "riscv64")]
        Backend::Rvv => riscv64::xor_rvv(key, counter, nonce, data),
        _ => soft::xor(key, counter, nonce, data),
    }
}

/// XORs `data` in place with the ChaCha20 keystream for `key` and `nonce`,
/// starting at block `counter` (RFC 8439, section 2.4).
///
/// The block counter wraps modulo 2^32 after block `u32::MAX`; callers that
/// must not reuse keystream (anything but a single call per nonce of at most
/// `(2^32 - counter) * 64` bytes) must enforce that limit themselves.
///
/// Encryption and decryption are the same operation. For QUIC header
/// protection (RFC 9001, section 5.4.4) pass the 5-byte zero mask as `data`.
pub fn chacha20_xor(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    let key = Key::new(key);
    xor_words(Backend::best(), &key.0, counter, &nonce_words(nonce), data);
}

/// Like [`chacha20_xor`] with an explicit backend (for tests and diagnostics).
///
/// # Errors
///
/// Returns [`Error::Unsupported`] if `backend` is not available on this CPU.
pub fn chacha20_xor_with(
    backend: Backend,
    key: &[u8; KEY_LEN],
    counter: u32,
    nonce: &[u8; NONCE_LEN],
    data: &mut [u8],
) -> Result<(), Error> {
    if !backend.is_available() {
        return Err(Error::Unsupported);
    }
    let key = Key::new(key);
    xor_words(backend, &key.0, counter, &nonce_words(nonce), data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439, section 2.3.2.
    #[test]
    fn block_function() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut out = [0u8; 64];
        soft::block(&Key::new(&key).0, 1, &nonce_words(&nonce), &mut out);
        assert_eq!(
            hex::encode(out),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn every_backend_matches_soft() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let nonce: [u8; 12] = core::array::from_fn(|i| (i * 3 + 5) as u8);
        let data: std::vec::Vec<u8> = (0..4200u32).map(|i| (i * 31 + 7) as u8).collect();
        for b in Backend::ALL.into_iter().filter(|b| b.is_available()) {
            for len in [
                0, 1, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4200,
            ] {
                for ctr in [0, 1, u32::MAX - 3] {
                    let mut a = data[..len].to_vec();
                    let mut c = a.clone();
                    soft::xor(&Key::new(&key).0, ctr, &nonce_words(&nonce), &mut a);
                    chacha20_xor_with(b, &key, ctr, &nonce, &mut c).unwrap();
                    assert_eq!(a, c, "{b:?} len={len} ctr={ctr}");
                }
            }
        }
    }
}
