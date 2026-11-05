//! AES decryption key schedules and the CBC mode loops (SP 800-38A §6.2).
//!
//! [`DecKey`] holds the inverse-cipher key for the backend of an
//! encryption [`Key`]:
//!
//! | Backend | Decryption |
//! |---|---|
//! | [`Backend::Soft`] | bitsliced inverse cipher on the encryption schedule |
//! | [`Backend::AesNi`] | `aesdec`, equivalent inverse cipher (`aesimc` keys), eight blocks per iteration |
//! | [`Backend::Vaes`], [`Backend::VaesAvx512`] | `vaesdec` on YMM, sixteen blocks per iteration |
//! | [`Backend::ArmAes`] | `aesd` + `aesimc`, eight blocks per iteration |
//! | [`Backend::RvZvkned`] | `vaesdm`/`vaesdf` on the encryption schedule, `VLEN/32` blocks per iteration |
//! | [`Backend::RvZkne`] | Zknd `aes64dsm`/`aes64ds` when present, otherwise the portable code |
//!
//! CBC encryption is serial: every backend chains one block at a time, the
//! hardware ones with the round keys held in registers.

#[cfg(target_arch = "aarch64")]
use super::aarch64;
#[cfg(target_arch = "riscv64")]
use super::riscv64_cbc;
use super::{Backend, Imp, Key, RoundKeys, soft};
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
use super::{x86, x86_vaes};
use crate::Error;
use crate::zeroize::zeroize_u32;

// One key per connection direction; the 960-byte bitsliced schedule is not
// worth an allocation.
#[allow(clippy::large_enum_variant)]
enum DecImp {
    Soft(soft::Key),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    AesNi(x86::DecKey),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    Vaes(x86_vaes::DecKey),
    #[cfg(target_arch = "aarch64")]
    ArmAes(aarch64::DecKey),
    #[cfg(target_arch = "riscv64")]
    RvZvkned(super::riscv64::VectorKey),
    #[cfg(target_arch = "riscv64")]
    RvZknd(riscv64_cbc::ScalarDecKey),
}

/// An expanded AES decryption key of either size. Every variant wipes its
/// round keys on drop.
pub(crate) struct DecKey {
    imp: DecImp,
}

impl DecKey {
    /// Expands `key` (16 or 32 bytes) for decryption on `backend`.
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
        #[cfg_attr(
            not(any(
                all(target_arch = "x86_64", target_feature = "sse2"),
                target_arch = "aarch64",
                target_arch = "riscv64"
            )),
            allow(unused_variables)
        )]
        let rk = RoundKeys::new(&words, rounds);
        let soft = || DecImp::Soft(soft::Key::new(&words, rounds));
        let imp = match backend {
            Backend::Soft => soft(),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::AesNi => DecImp::AesNi(x86::DecKey::new(&rk)),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Backend::Vaes | Backend::VaesAvx512 => DecImp::Vaes(x86_vaes::DecKey::new(&rk)),
            #[cfg(target_arch = "aarch64")]
            Backend::ArmAes => DecImp::ArmAes(aarch64::DecKey::new(&rk)),
            #[cfg(target_arch = "riscv64")]
            Backend::RvZvkned => DecImp::RvZvkned(super::riscv64::VectorKey::new(rk)),
            // Zkne without Zknd: no scalar decryption instructions.
            #[cfg(target_arch = "riscv64")]
            Backend::RvZkne if riscv64_cbc::ScalarDecKey::supported() => {
                DecImp::RvZknd(riscv64_cbc::ScalarDecKey::new(&rk))
            }
            #[cfg(target_arch = "riscv64")]
            Backend::RvZkne => soft(),
            #[allow(unreachable_patterns)]
            _ => {
                zeroize_u32(&mut words);
                return Err(Error::Unsupported);
            }
        };
        zeroize_u32(&mut words);
        Ok(Self { imp })
    }

    /// CBC-decrypts `blocks` in place, chaining from `iv`.
    pub(crate) fn cbc_decrypt(&self, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
        match &self.imp {
            DecImp::Soft(k) => cbc_decrypt_generic(|b| k.decrypt_blocks(b), iv, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            DecImp::AesNi(k) => k.cbc_decrypt(iv, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            DecImp::Vaes(k) => k.cbc_decrypt(iv, blocks),
            #[cfg(target_arch = "aarch64")]
            DecImp::ArmAes(k) => k.cbc_decrypt(iv, blocks),
            #[cfg(target_arch = "riscv64")]
            DecImp::RvZvkned(k) => k.cbc_decrypt(iv, blocks),
            #[cfg(target_arch = "riscv64")]
            DecImp::RvZknd(k) => cbc_decrypt_generic(|b| k.decrypt_blocks(b), iv, blocks),
        }
    }
}

impl Key {
    /// CBC-encrypts `blocks` in place, chaining from `iv`.
    pub(crate) fn cbc_encrypt(&self, iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
        match &self.imp {
            Imp::Soft(k) => cbc_encrypt_generic(|b| k.encrypt_blocks(b), iv, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::AesNi(k) => k.cbc_encrypt(iv, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::Vaes(k) => k.cbc_encrypt(iv, blocks),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Imp::VaesAvx512(k) => k.cbc_encrypt(iv, blocks),
            #[cfg(target_arch = "aarch64")]
            Imp::ArmAes(k) => k.cbc_encrypt(iv, blocks),
            #[cfg(target_arch = "riscv64")]
            Imp::RvZvkned(k) => k.cbc_encrypt(iv, blocks),
            #[cfg(target_arch = "riscv64")]
            Imp::RvZkne(k) => cbc_encrypt_generic(|b| k.encrypt_blocks(b), iv, blocks),
        }
    }
}

/// CBC encryption on a block-encryption primitive, one block per call.
fn cbc_encrypt_generic(encrypt: impl Fn(&mut [[u8; 16]]), iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
    let mut prev = iv;
    for block in blocks {
        for (b, p) in block.iter_mut().zip(prev) {
            *b ^= p;
        }
        encrypt(core::slice::from_mut(block));
        prev = block;
    }
}

/// CBC decryption on a block-decryption primitive, eight blocks per call.
/// Each batch's ciphertext (public data) is saved before it is decrypted in
/// place.
fn cbc_decrypt_generic(decrypt: impl Fn(&mut [[u8; 16]]), iv: &[u8; 16], blocks: &mut [[u8; 16]]) {
    let mut prev = *iv;
    let mut saved = [[0u8; 16]; 8];
    for batch in blocks.chunks_mut(8) {
        let saved = &mut saved[..batch.len()];
        saved.copy_from_slice(batch);
        decrypt(batch);
        for (i, block) in batch.iter_mut().enumerate() {
            let p = if i == 0 { &prev } else { &saved[i - 1] };
            for (b, p) in block.iter_mut().zip(p) {
                *b ^= p;
            }
        }
        prev = saved[saved.len() - 1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decryption runs on the encryption backend's hardware, except on a
    /// riscv64 CPU with Zkne but without Zknd.
    #[test]
    fn decryption_follows_encryption_backend() {
        for backend in Backend::ALL.into_iter().filter(|b| b.is_available()) {
            let dec = DecKey::new(&[0x11; 32], backend).unwrap();
            let is_soft = matches!(dec.imp, DecImp::Soft(_));
            let zkne_only = cfg!(target_arch = "riscv64")
                && backend == Backend::RvZkne
                && !crate::cpu::features().rv_zknd();
            assert_eq!(
                is_soft,
                backend == Backend::Soft || zkne_only,
                "{backend:?}"
            );
        }
    }
}
