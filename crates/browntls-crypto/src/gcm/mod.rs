//! GHASH and AES-GCM (NIST SP 800-38D).
//!
//! [`Aes128Gcm`] and [`Aes256Gcm`] implement [`Aead`] with 96-bit nonces and
//! 128-bit tags, as used by TLS 1.2 (RFC 5288) and TLS 1.3 (RFC 8446).
//! [`Ghash`] is GHASH on its own, keyed by the hash subkey `H`, for
//! constructions other than AES-GCM; it runs on the same backends and is not
//! a MAC by itself (see its security notes).
//!
//! Encryption is CTR mode over the [`crate::aes`] backends; GHASH dispatches
//! independently to one of:
//!
//! | Backend | Where | Notes |
//! |---|---|---|
//! | [`GhashBackend::Soft`] | everywhere | masked integer multiplications, constant time |
//! | [`GhashBackend::Clmul`] | x86-64 with PCLMULQDQ | 8 blocks per reduction, Karatsuba |
//! | [`GhashBackend::Vpclmul`] | x86-64 with VPCLMULQDQ + AVX2 | 8 blocks per reduction on YMM registers |
//! | [`GhashBackend::VpclmulAvx512`] | x86-64 with VPCLMULQDQ + AVX-512 | 32 blocks per reduction on ZMM registers |
//! | [`GhashBackend::Pmull`] | aarch64 with FEAT_PMULL | 8 blocks per reduction, Karatsuba |
//! | [`GhashBackend::RvZvkg`] | riscv64 with RVV 1.0 + Zvkg | `vghsh.vv` |
//! | [`GhashBackend::RvZvbc`] | riscv64 with RVV 1.0 + Zvbc | `vclmul`/`vclmulh` |
//! | [`GhashBackend::RvClmul`] | riscv64 with Zbc or Zbkc | scalar `clmul`/`clmulh` |
//!
//! When both ZMM backends ([`aes::Backend::VaesAvx512`] and
//! [`GhashBackend::VpclmulAvx512`]) are selected, sealing and opening run
//! through a fused loop that encrypts and hashes 32 blocks per iteration
//! (see `x86_avx512`); other backend combinations run CTR and GHASH as
//! separate passes. On the fused path decryption writes plaintext into the
//! caller's buffer while the tag is being computed and zeroes the buffer
//! before returning an error; the buffer is exclusively borrowed, but memory
//! that other processes can observe (for example a shared mapping) may
//! briefly hold unauthenticated plaintext, as with other fused
//! implementations.
//!
//! Keys made by [`Aead::new`] while load-aware routing
//! ([`crate::accel::load`]) is enabled take part in it: while the selected
//! AES backend runs slower than usual, a share of the records is sealed and
//! opened with another AES backend. Records under 128-bit and under 256-bit
//! keys are separate streams, since they cost differently per byte. A
//! [`Ghash`] does not take part: it keeps the GHASH backend it was created
//! with.
//!
//! An expanded key serves one backend only. A routable key therefore keeps
//! a copy of the AES key (in a small allocation, wiped on drop) and expands
//! it for the alternate AES backends when one of its records is first
//! routed to an alternate; that record is not timed. Most keys never reach
//! that point and cost nothing more than the copy. An alternate runs with
//! the GHASH backend of its own instruction class (VAES with VPCLMULQDQ of
//! the same width, AES-NI with PCLMULQDQ, FEAT_AES with FEAT_PMULL, Zvkned
//! with Zvkg, Zkne with Zbc/Zbkc, portable with portable), so that a moved
//! record leaves the selected backends' instructions for both halves of
//! the work; if the GHASH policy forbids that backend or the CPU lacks it,
//! with the next one in GHASH preference order that is permitted and
//! available, and an AES backend left without one is not an alternate. The
//! alternates and their GHASH backends are those of the moment of the
//! expansion and stay with the key. On x86-64 an expanded key takes 1664
//! bytes: that is the size of [`Aes128Gcm`] and [`Aes256Gcm`] with or
//! without routing, and each alternate of an expanded key adds as much on
//! the heap (three of them, 4992 bytes per key, on a CPU with AVX-512 VAES
//! under the default policy and configuration). The whole of that memory
//! is zeroised when the key is dropped.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod ghash;
mod keys;
#[cfg(target_arch = "riscv64")]
mod riscv64;
mod soft;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86_avx512;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86_vpclmul;

use crate::Error;
use crate::aead::{Aead, NONCE_LEN, TAG_LEN};
use crate::aes;
use crate::cpu::features;
use crate::zeroize::zeroize_bytes;
use keys::Keys;

pub use ghash::{GHASH_BLOCK_LEN, Ghash};

/// Maximum plaintext length in bytes (2^39 - 256 bits).
const P_MAX: u64 = (1 << 36) - 32;
/// Maximum additional-data length in bytes (2^64 - 1 bits).
const A_MAX: u64 = (1 << 61) - 1;

/// GHASH implementation backends. Exposed for differential testing and for
/// [`Ghash::with_backend`]; the dispatcher picks the best available one
/// automatically.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GhashBackend {
    /// Portable constant-time implementation (always available).
    Soft,
    /// x86-64 PCLMULQDQ on XMM registers.
    Clmul,
    /// x86-64 VPCLMULQDQ on YMM registers (requires AVX2).
    Vpclmul,
    /// x86-64 VPCLMULQDQ on ZMM registers (requires AVX-512 F/BW/VL).
    VpclmulAvx512,
    /// aarch64 FEAT_PMULL.
    Pmull,
    /// RISC-V vector GHASH (Zvkg).
    RvZvkg,
    /// RISC-V vector carry-less multiplication (Zvbc).
    RvZvbc,
    /// RISC-V scalar carry-less multiplication (Zbc or Zbkc).
    RvClmul,
}

impl GhashBackend {
    /// Every backend, in no particular order.
    pub const ALL: [Self; 8] = [
        Self::Soft,
        Self::Clmul,
        Self::Vpclmul,
        Self::VpclmulAvx512,
        Self::Pmull,
        Self::RvZvkg,
        Self::RvZvbc,
        Self::RvClmul,
    ];

    /// Returns whether this backend can run on the current CPU.
    #[must_use]
    pub fn is_available(self) -> bool {
        let f = features();
        match self {
            Self::Soft => true,
            Self::Clmul => f.x86_pclmulqdq() && f.x86_sse41(),
            Self::Vpclmul => {
                f.x86_vpclmulqdq() && f.x86_avx2() && f.x86_pclmulqdq() && f.x86_sse41()
            }
            Self::VpclmulAvx512 => {
                f.x86_avx512()
                    && f.x86_vpclmulqdq()
                    && f.x86_avx2()
                    && f.x86_pclmulqdq()
                    && f.x86_sse41()
            }
            Self::Pmull => f.arm_aes(),
            Self::RvZvkg => f.rv_v() && f.rv_zvkg(),
            Self::RvZvbc => f.rv_v() && f.rv_zvbc(),
            Self::RvClmul => f.rv_zbc() || f.rv_zbkc(),
        }
    }

    /// The backend the dispatcher selects on the current CPU.
    #[must_use]
    pub fn select() -> Self {
        crate::accel::select::<Self>()
    }

    /// The GHASH backend of the same instruction class as an AES backend.
    #[cfg(feature = "std")]
    fn class_of(aes: aes::Backend) -> Self {
        match aes {
            aes::Backend::VaesAvx512 => Self::VpclmulAvx512,
            aes::Backend::Vaes => Self::Vpclmul,
            aes::Backend::AesNi => Self::Clmul,
            aes::Backend::ArmAes => Self::Pmull,
            aes::Backend::RvZvkned => Self::RvZvkg,
            aes::Backend::RvZkne => Self::RvClmul,
            aes::Backend::Soft => Self::Soft,
        }
    }

    /// [`Self::companion`] with `usable` in place of the policy and the CPU.
    #[cfg(feature = "std")]
    fn companion_where(aes: aes::Backend, usable: impl Fn(Self) -> bool) -> Option<Self> {
        use crate::accel::Backends as _;
        let class = Self::class_of(aes);
        Self::PREFERENCE
            .iter()
            .copied()
            .skip_while(|b| *b != class)
            .find(|b| usable(*b))
    }

    /// The GHASH backend that runs beside the alternate AES backend `aes`
    /// when load-aware routing moves a record to it.
    ///
    /// That is the backend of the same instruction class as `aes`, so that a
    /// moved record leaves the primary's class for GHASH as well; or, when
    /// the GHASH policy forbids that one or the CPU lacks it, the next
    /// backend after it in GHASH preference order that is permitted and
    /// available (never a more preferred one, which would be back in a class
    /// the record was meant to leave). `None` when there is none: `aes` is
    /// then not used as an alternate.
    #[cfg(feature = "std")]
    fn companion(aes: aes::Backend) -> Option<Self> {
        use crate::accel::Backends as _;
        let policy = crate::accel::policy(crate::accel::Algorithm::Ghash);
        Self::companion_where(aes, |b| policy.permits(b.uses()) && b.is_available())
    }
}

impl crate::accel::Backends for GhashBackend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::Ghash;
    const PREFERENCE: &'static [Self] = &[
        Self::VpclmulAvx512,
        Self::Vpclmul,
        Self::Clmul,
        Self::Pmull,
        Self::RvZvkg,
        Self::RvZvbc,
        Self::RvClmul,
        Self::Soft,
    ];

    fn available(self) -> bool {
        self.is_available()
    }

    fn uses(self) -> crate::accel::Uses {
        use crate::accel::Uses;
        match self {
            Self::Soft => Uses::PORTABLE,
            Self::Clmul => Uses::DEDICATED,
            Self::Vpclmul => Uses::BOTH,
            Self::VpclmulAvx512 => Uses::BOTH,
            Self::Pmull => Uses::DEDICATED,
            Self::RvZvkg => Uses::BOTH,
            Self::RvZvbc => Uses::BOTH,
            Self::RvClmul => Uses::DEDICATED,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Soft => "portable",
            Self::Clmul => "PCLMULQDQ",
            Self::Vpclmul => "VPCLMULQDQ (AVX2)",
            Self::VpclmulAvx512 => "VPCLMULQDQ (AVX-512)",
            Self::Pmull => "FEAT_PMULL",
            Self::RvZvkg => "Zvkg",
            Self::RvZvbc => "Zvbc",
            Self::RvClmul => "Zbc/Zbkc",
        }
    }
}

// Keys are long-lived (one per connection); the precomputed key powers are
// not worth an allocation.
#[allow(clippy::large_enum_variant)]
enum GhashKey {
    Soft(soft::Key),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    Clmul(x86::Key),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    Vpclmul(x86_vpclmul::Key),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    VpclmulAvx512(x86_avx512::Key),
    #[cfg(target_arch = "aarch64")]
    Pmull(aarch64::Key),
    #[cfg(target_arch = "riscv64")]
    RvZvkg(riscv64::ZvkgKey),
    #[cfg(target_arch = "riscv64")]
    RvZvbc(riscv64::ZvbcKey),
    #[cfg(target_arch = "riscv64")]
    RvClmul(riscv64::ClmulKey),
}

impl GhashKey {
    fn new(h: &[u8; 16], backend: GhashBackend) -> Result<Self, Error> {
        if !backend.is_available() {
            return Err(Error::Unsupported);
        }
        Ok(match backend {
            GhashBackend::Soft => Self::Soft(soft::Key::new(h)),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            GhashBackend::Clmul => Self::Clmul(x86::Key::new(h)),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            GhashBackend::Vpclmul => Self::Vpclmul(x86_vpclmul::Key::new(h)),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            GhashBackend::VpclmulAvx512 => Self::VpclmulAvx512(x86_avx512::Key::new(h)),
            #[cfg(target_arch = "aarch64")]
            GhashBackend::Pmull => Self::Pmull(aarch64::Key::new(h)),
            #[cfg(target_arch = "riscv64")]
            GhashBackend::RvZvkg => Self::RvZvkg(riscv64::ZvkgKey::new(h)),
            #[cfg(target_arch = "riscv64")]
            GhashBackend::RvZvbc => Self::RvZvbc(riscv64::ZvbcKey::new(h)),
            #[cfg(target_arch = "riscv64")]
            GhashBackend::RvClmul => Self::RvClmul(riscv64::ClmulKey::new(h)),
            #[allow(unreachable_patterns)]
            _ => return Err(Error::Unsupported),
        })
    }

    fn backend(&self) -> GhashBackend {
        match self {
            Self::Soft(_) => GhashBackend::Soft,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Clmul(_) => GhashBackend::Clmul,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Vpclmul(_) => GhashBackend::Vpclmul,
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::VpclmulAvx512(_) => GhashBackend::VpclmulAvx512,
            #[cfg(target_arch = "aarch64")]
            Self::Pmull(_) => GhashBackend::Pmull,
            #[cfg(target_arch = "riscv64")]
            Self::RvZvkg(_) => GhashBackend::RvZvkg,
            #[cfg(target_arch = "riscv64")]
            Self::RvZvbc(_) => GhashBackend::RvZvbc,
            #[cfg(target_arch = "riscv64")]
            Self::RvClmul(_) => GhashBackend::RvClmul,
        }
    }

    /// Absorbs `blocks` (a multiple of 16 bytes) into `y`.
    fn update(&self, y: &mut [u8; 16], blocks: &[u8]) {
        match self {
            Self::Soft(k) => k.update(y, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Clmul(k) => k.update(y, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Vpclmul(k) => k.update(y, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::VpclmulAvx512(k) => k.update(y, blocks),
            #[cfg(target_arch = "aarch64")]
            Self::Pmull(k) => k.update(y, blocks),
            #[cfg(target_arch = "riscv64")]
            Self::RvZvkg(k) => k.update(y, blocks),
            #[cfg(target_arch = "riscv64")]
            Self::RvZvbc(k) => k.update(y, blocks),
            #[cfg(target_arch = "riscv64")]
            Self::RvClmul(k) => k.update(y, blocks),
        }
    }
}

/// Converts the GCM hash subkey into the POLYVAL-representation key used by
/// the carry-less-multiplication backends: byte-reverse (so that the
/// bit-reflected GCM element becomes a little-endian polynomial) and multiply
/// by `x` modulo `x^128 + x^127 + x^126 + x^121 + 1` (RFC 8452 Appendix A).
#[allow(dead_code)]
pub(crate) fn polyval_key(h: &[u8; 16]) -> [u8; 16] {
    let mut hr = *h;
    hr.reverse();
    let v = u128::from_le_bytes(hr);
    let carry = v >> 127;
    let v = (v << 1) ^ carry ^ (carry << 127) ^ (carry << 126) ^ (carry << 121);
    v.to_le_bytes()
}

/// A key of either size expanded for one AES and one GHASH backend. Both
/// parts zeroise their key material when dropped.
struct Gcm {
    aes: aes::Key,
    ghash: GhashKey,
}

/// A keyed AES-GCM instance: an expanded key, wherever it is stored.
#[derive(Clone, Copy)]
struct Instance<'a> {
    aes: &'a aes::Key,
    ghash: &'a GhashKey,
}

fn j0(nonce: &[u8; NONCE_LEN]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..NONCE_LEN].copy_from_slice(nonce);
    block[15] = 1;
    block
}

fn inc32(block: &mut [u8; 16]) {
    let c = u32::from_be_bytes([block[12], block[13], block[14], block[15]]).wrapping_add(1);
    block[12..].copy_from_slice(&c.to_be_bytes());
}

fn check_lengths(aad: &[u8], in_out: &[u8]) -> Result<(), Error> {
    if in_out.len() as u64 > P_MAX || aad.len() as u64 > A_MAX {
        return Err(Error::InvalidLength);
    }
    Ok(())
}

impl Gcm {
    fn new(
        key: &[u8],
        aes_backend: aes::Backend,
        ghash_backend: GhashBackend,
    ) -> Result<Self, Error> {
        let aes = aes::Key::new(key, aes_backend)?;
        let mut h = [0u8; 16];
        aes.encrypt_blocks(core::slice::from_mut(&mut h));
        let ghash = GhashKey::new(&h, ghash_backend);
        zeroize_bytes(&mut h);
        Ok(Self { aes, ghash: ghash? })
    }

    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    fn instance(&self) -> Instance<'_> {
        Instance {
            aes: &self.aes,
            ghash: &self.ghash,
        }
    }
}

impl<'a> Instance<'a> {
    /// GHASHes `data` followed by zero padding to a block boundary.
    fn ghash_padded(self, y: &mut [u8; 16], data: &[u8]) {
        let full = data.len() - data.len() % 16;
        self.ghash.update(y, &data[..full]);
        let rest = &data[full..];
        if !rest.is_empty() {
            let mut last = [0u8; 16];
            last[..rest.len()].copy_from_slice(rest);
            self.ghash.update(y, &last);
        }
    }

    /// Computes the tag for `aad` and ciphertext `ct` under `nonce`.
    fn tag(self, nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
        let mut y = [0u8; 16];
        self.ghash_padded(&mut y, aad);
        self.ghash_padded(&mut y, ct);
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
        lengths[8..].copy_from_slice(&((ct.len() as u64) << 3).to_be_bytes());
        self.ghash.update(&mut y, &lengths);
        let mut tag = j0(nonce);
        self.aes.encrypt_blocks(core::slice::from_mut(&mut tag));
        for (t, s) in tag.iter_mut().zip(y) {
            *t ^= s;
        }
        tag
    }

    fn ctr(self, nonce: &[u8; NONCE_LEN], in_out: &mut [u8]) {
        let mut counter = j0(nonce);
        inc32(&mut counter);
        self.aes.ctr32_xor(&counter, in_out);
    }

    /// The ZMM keys when both ZMM backends are in use.
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    fn fused(self) -> Option<(&'a aes::x86_vaes512::Key, &'a x86_avx512::Key)> {
        match (self.ghash, self.aes.vaes_avx512()) {
            (GhashKey::VpclmulAvx512(g), Some(a)) => Some((a, g)),
            _ => None,
        }
    }

    fn seal(
        self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        check_lengths(aad, in_out)?;
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        if let Some((a, g)) = self.fused() {
            return Ok(x86_avx512::seal(a, g, nonce, aad, in_out));
        }
        self.ctr(nonce, in_out);
        Ok(self.tag(nonce, aad, in_out))
    }

    fn open(
        self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        check_lengths(aad, in_out)?;
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        if let Some((a, g)) = self.fused() {
            return x86_avx512::open(a, g, nonce, aad, in_out, tag);
        }
        let expected = self.tag(nonce, aad, in_out);
        if !crate::ct::eq(&expected, tag) {
            zeroize_bytes(in_out);
            return Err(Error::DecryptFailed);
        }
        self.ctr(nonce, in_out);
        Ok(())
    }
}

macro_rules! gcm_variant {
    ($(#[$m:meta])* $name:ident, $len:literal) => {
        $(#[$m])*
        pub struct $name {
            inner: Keys<{ $len / 32 }>,
        }

        impl $name {
            /// Expands `key` for specific AES and GHASH backends (differential
            /// testing).
            ///
            /// # Errors
            ///
            /// Returns [`Error::Unsupported`] if a backend cannot run here.
            #[doc(hidden)]
            pub fn with_backends(
                key: &[u8; $len],
                aes_backend: aes::Backend,
                ghash_backend: GhashBackend,
            ) -> Result<Self, Error> {
                Keys::pinned(key, aes_backend, ghash_backend).map(|inner| Self { inner })
            }

            /// The AES and GHASH backends the instance was created for. With
            /// load-aware routing ([`crate::accel::load`]) a record may be
            /// processed by another AES backend and its GHASH companion.
            #[doc(hidden)]
            #[must_use]
            pub fn backends(&self) -> (aes::Backend, GhashBackend) {
                self.inner.backends()
            }
        }

        impl Aead for $name {
            const KEY_LEN: usize = $len;

            fn new(key: &[u8]) -> Result<Self, Error> {
                if key.len() != $len {
                    return Err(Error::InvalidKey);
                }
                Keys::selected(key).map(|inner| Self { inner })
            }

            fn seal_in_place(
                &self,
                nonce: &[u8; NONCE_LEN],
                aad: &[u8],
                in_out: &mut [u8],
            ) -> Result<[u8; TAG_LEN], Error> {
                self.inner.seal(nonce, aad, in_out)
            }

            fn open_in_place(
                &self,
                nonce: &[u8; NONCE_LEN],
                aad: &[u8],
                in_out: &mut [u8],
                tag: &[u8; TAG_LEN],
            ) -> Result<(), Error> {
                self.inner.open(nonce, aad, in_out, tag)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let (aes, ghash) = self.backends();
                f.debug_struct(stringify!($name))
                    .field("aes", &aes)
                    .field("ghash", &ghash)
                    .finish_non_exhaustive()
            }
        }
    };
}

gcm_variant!(
    /// AES-128-GCM.
    Aes128Gcm,
    16
);
gcm_variant!(
    /// AES-256-GCM.
    Aes256Gcm,
    32
);

#[cfg(test)]
mod tests {
    use super::*;

    /// The ZMM backend pair, and only that pair, takes the fused path, so
    /// differential tests of that pair exercise the fused loop.
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    #[test]
    fn fused_path_exactly_for_the_zmm_pair() {
        for ab in aes::Backend::ALL {
            for gb in GhashBackend::ALL {
                let Ok(gcm) = Gcm::new(&[7; 16], ab, gb) else {
                    continue;
                };
                let zmm = ab == aes::Backend::VaesAvx512 && gb == GhashBackend::VpclmulAvx512;
                assert_eq!(gcm.instance().fused().is_some(), zmm, "{ab:?}/{gb:?}");
            }
        }
    }

    /// A routed record leaves the primary's instruction class for GHASH
    /// too, and a companion that cannot be used is replaced only by a less
    /// preferred backend.
    #[cfg(feature = "std")]
    #[test]
    fn companions_follow_the_instruction_class() {
        use crate::aes::Backend as A;
        use GhashBackend as G;
        let classes = [
            (A::VaesAvx512, G::VpclmulAvx512),
            (A::Vaes, G::Vpclmul),
            (A::AesNi, G::Clmul),
            (A::ArmAes, G::Pmull),
            (A::RvZvkned, G::RvZvkg),
            (A::RvZkne, G::RvClmul),
            (A::Soft, G::Soft),
        ];
        assert_eq!(classes.len(), A::ALL.len());
        for (ab, gb) in classes {
            assert_eq!(G::companion_where(ab, |_| true), Some(gb), "{ab:?}");
            assert_eq!(G::companion_where(ab, |_| false), None, "{ab:?}");
            // Without its own class and the portable code, only less
            // preferred backends are left.
            let rest = G::companion_where(ab, |b| b != gb && b != G::Soft);
            let after = |b| {
                use crate::accel::Backends as _;
                let at = |x| G::PREFERENCE.iter().position(|p| *p == x).unwrap();
                at(b) > at(gb)
            };
            assert!(rest.is_none_or(after), "{ab:?}: {rest:?}");
        }
        // Fallbacks: the next backend in GHASH preference order.
        let without = |ab, gone: &[G]| G::companion_where(ab, |b| !gone.contains(&b));
        assert_eq!(
            without(A::VaesAvx512, &[G::VpclmulAvx512]),
            Some(G::Vpclmul)
        );
        assert_eq!(
            without(A::VaesAvx512, &[G::VpclmulAvx512, G::Vpclmul]),
            Some(G::Clmul)
        );
        assert_eq!(without(A::Vaes, &[G::Vpclmul]), Some(G::Clmul));
        assert_eq!(without(A::RvZvkned, &[G::RvZvkg]), Some(G::RvZvbc));
        assert_eq!(
            without(A::RvZvkned, &[G::RvZvkg, G::RvZvbc]),
            Some(G::RvClmul)
        );
        assert_eq!(without(A::RvZkne, &[G::RvClmul]), Some(G::Soft));
        assert_eq!(without(A::Soft, &[G::Soft]), None);
        // What GHASH policies leave usable on x86-64: the portable code
        // when both kinds of acceleration are forbidden, PCLMULQDQ when SIMD
        // is, and nothing for AES-NI when SIMD is required.
        let x86 = |ab, usable: &[G]| G::companion_where(ab, |b| usable.contains(&b));
        assert_eq!(x86(A::AesNi, &[G::Soft]), Some(G::Soft));
        assert_eq!(x86(A::Vaes, &[G::Clmul, G::Soft]), Some(G::Clmul));
        assert_eq!(x86(A::AesNi, &[G::VpclmulAvx512, G::Vpclmul]), None);

        // On this CPU, under the default policy (which no test of this
        // binary changes): the class itself where the CPU has it, else
        // something it can run.
        for ab in A::ALL {
            let companion = G::companion(ab).unwrap();
            assert!(companion.is_available(), "{ab:?}: {companion:?}");
            if G::class_of(ab).is_available() {
                assert_eq!(companion, G::class_of(ab));
            }
        }
    }

    #[test]
    fn polyval_key_matches_rfc8452_relation() {
        // GHASH(H, X) == ByteReverse(POLYVAL(mulX(ByteReverse(H)), ByteReverse(X)))
        // is exercised indirectly by every hardware backend; here check mulX
        // on a value with the top bit set.
        let mut h = [0u8; 16];
        h[0] = 0x80; // after reversal: bit 127 of the little-endian integer
        let k = polyval_key(&h);
        let v = u128::from_le_bytes(k);
        assert_eq!(v, 1 | (1 << 127) | (1 << 126) | (1 << 121));
    }

    #[test]
    fn soft_ghash_matches_test_case_2() {
        // SP 800-38D / McGrew–Viega test case 2: K = 0, IV = 0, P = 0^128.
        let gcm =
            Aes128Gcm::with_backends(&[0; 16], aes::Backend::Soft, GhashBackend::Soft).unwrap();
        let mut buf = [0u8; 16];
        let tag = gcm.seal_in_place(&[0; 12], &[], &mut buf).unwrap();
        assert_eq!(hex::encode(buf), "0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(hex::encode(tag), "ab6e47d42cec13bdf53a67b21257bddf");
        assert!(gcm.open_in_place(&[0; 12], &[], &mut buf, &tag).is_ok());
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn all_backend_pairs_agree() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 3 + 1) as u8);
        let nonce: [u8; 12] = core::array::from_fn(|i| (i * 5 + 7) as u8);
        let data: std::vec::Vec<u8> = (0..700u32).map(|i| (i * 11 + 3) as u8).collect();
        let reference =
            Aes256Gcm::with_backends(&key, aes::Backend::Soft, GhashBackend::Soft).unwrap();
        for len in [
            0usize, 1, 15, 16, 17, 31, 32, 33, 127, 128, 129, 255, 256, 257, 700,
        ] {
            let aad = &data[..len % 40];
            let mut expected = data[..len].to_vec();
            let tag = reference.seal_in_place(&nonce, aad, &mut expected).unwrap();
            for ab in aes::Backend::ALL {
                for gb in GhashBackend::ALL {
                    let Ok(gcm) = Aes256Gcm::with_backends(&key, ab, gb) else {
                        continue;
                    };
                    let mut buf = data[..len].to_vec();
                    let t = gcm.seal_in_place(&nonce, aad, &mut buf).unwrap();
                    assert_eq!(buf, expected, "{ab:?}/{gb:?} len={len}");
                    assert_eq!(t, tag, "{ab:?}/{gb:?} len={len}");
                    gcm.open_in_place(&nonce, aad, &mut buf, &t).unwrap();
                    assert_eq!(buf, &data[..len]);
                }
            }
        }
    }
}
