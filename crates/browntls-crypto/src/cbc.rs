//! AES in CBC mode (NIST SP 800-38A §6.2), without padding.
//!
//! This is the bulk cipher of the TLS 1.2 CBC suites (RFC 5246 §6.2.3.2)
//! with AES-128 and AES-256. Buffers must be a whole number of 16-byte
//! blocks: padding (and its constant-time removal) belongs to the record
//! layer, which also owns the MAC that authenticates the ciphertext. CBC on
//! its own provides confidentiality only.
//!
//! The mode runs on the expanded keys of [`crate::aes`], so the AES backend
//! selection and acceleration policy apply unchanged. [`AesCbcKey`] holds
//! both an encryption and a decryption key schedule for the selected
//! backend. Encryption is inherently sequential and processes one block at
//! a time; decryption is parallel and every hardware backend pipelines
//! several blocks per iteration. Every backend runs in constant time with
//! respect to the key and the data.

use crate::Error;
use crate::aes::{self, BLOCK_LEN};

/// An AES-128 or AES-256 key expanded for CBC encryption and decryption.
///
/// Both key schedules are wiped when the value is dropped.
pub struct AesCbcKey {
    enc: aes::Key,
    dec: aes::DecKey,
}

impl AesCbcKey {
    /// Expands `key` using the AES backend selected for this CPU (subject to
    /// the acceleration policy, see [`crate::accel`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] unless `key` is 16 bytes (AES-128) or
    /// 32 bytes (AES-256).
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Self::with_backend(key, aes::Backend::select())
    }

    /// Expands `key` for a specific AES backend (differential testing).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for a key that is not 16 or 32 bytes
    /// and [`Error::Unsupported`] if `backend` cannot run here.
    pub fn with_backend(key: &[u8], backend: aes::Backend) -> Result<Self, Error> {
        let enc = aes::Key::new(key, backend)?;
        let dec = aes::DecKey::new(key, backend)?;
        Ok(Self { enc, dec })
    }

    /// The AES backend in use.
    #[must_use]
    pub fn backend(&self) -> aes::Backend {
        self.enc.backend()
    }

    /// CBC-encrypts `buf` in place with the initialisation vector `iv`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`], leaving `buf` unchanged, unless its
    /// length is a multiple of 16 bytes (an empty buffer is accepted).
    pub fn encrypt(&self, iv: &[u8; BLOCK_LEN], buf: &mut [u8]) -> Result<(), Error> {
        let blocks = as_blocks(buf)?;
        self.enc.cbc_encrypt(iv, blocks);
        Ok(())
    }

    /// CBC-decrypts `buf` in place with the initialisation vector `iv`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`], leaving `buf` unchanged, unless its
    /// length is a multiple of 16 bytes (an empty buffer is accepted).
    pub fn decrypt(&self, iv: &[u8; BLOCK_LEN], buf: &mut [u8]) -> Result<(), Error> {
        let blocks = as_blocks(buf)?;
        self.dec.cbc_decrypt(iv, blocks);
        Ok(())
    }
}

/// Views `buf` as whole blocks.
fn as_blocks(buf: &mut [u8]) -> Result<&mut [[u8; BLOCK_LEN]], Error> {
    let (blocks, rest) = buf.as_chunks_mut::<BLOCK_LEN>();
    if rest.is_empty() {
        Ok(blocks)
    } else {
        Err(Error::InvalidLength)
    }
}

/// Lets [`crate::tls_cbc::RecordKey`] protect TLS 1.2 records with AES-CBC.
///
/// The record layer only ever passes whole blocks, so the length checks of
/// [`AesCbcKey::encrypt`] and [`AesCbcKey::decrypt`] cannot fail; a
/// non-aligned buffer is left untouched rather than panicking.
impl crate::tls_cbc::CbcBlockCipher for AesCbcKey {
    fn cbc_encrypt(&self, iv: &[u8; BLOCK_LEN], buf: &mut [u8]) {
        let _ = self.encrypt(iv, buf);
    }

    fn cbc_decrypt(&self, iv: &[u8; BLOCK_LEN], buf: &mut [u8]) {
        let _ = self.decrypt(iv, buf);
    }
}

impl core::fmt::Debug for AesCbcKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesCbcKey")
            .field("backend", &self.backend())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 197 Appendix C.1 and C.3: one block, decrypted as CBC with a
    /// zero IV.
    #[test]
    fn fips197_single_block_decrypt() {
        let pt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        for (key_len, ct) in [
            (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (32, "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            let key: std::vec::Vec<u8> = (0..key_len as u8).collect();
            for backend in aes::Backend::ALL {
                let Ok(cbc) = AesCbcKey::with_backend(&key, backend) else {
                    continue;
                };
                let mut buf = hex::decode(ct).unwrap();
                cbc.decrypt(&[0; 16], &mut buf).unwrap();
                assert_eq!(buf, pt, "{backend:?} AES-{}", key_len * 8);
                cbc.encrypt(&[0; 16], &mut buf).unwrap();
                assert_eq!(hex::encode(&buf), ct, "{backend:?} AES-{}", key_len * 8);
            }
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        assert_eq!(AesCbcKey::new(&[0; 24]).err(), Some(Error::InvalidKey));
        assert_eq!(AesCbcKey::new(&[]).err(), Some(Error::InvalidKey));
        let cbc = AesCbcKey::new(&[7; 16]).unwrap();
        for len in [1usize, 15, 17, 31, 33] {
            let mut buf = std::vec![0xa5u8; len];
            assert_eq!(cbc.encrypt(&[0; 16], &mut buf), Err(Error::InvalidLength));
            assert_eq!(cbc.decrypt(&[0; 16], &mut buf), Err(Error::InvalidLength));
            assert!(buf.iter().all(|&b| b == 0xa5));
        }
        let mut empty = [0u8; 0];
        assert_eq!(cbc.encrypt(&[0; 16], &mut empty), Ok(()));
        assert_eq!(cbc.decrypt(&[0; 16], &mut empty), Ok(()));
    }

    #[test]
    fn debug_hides_key_and_backend_is_selected() {
        let cbc = AesCbcKey::new(&[0x42; 32]).unwrap();
        assert_eq!(cbc.backend(), aes::Backend::select());
        let s = std::format!("{cbc:?}");
        assert!(s.starts_with("AesCbcKey"), "{s}");
        assert!(!s.contains("42") && !s.contains("66"), "{s}");
    }
}
