//! ChaCha20-Poly1305 AEAD (RFC 8439, section 2.8).

use super::poly1305::{Poly1305, PolyBackend};
use super::{Backend, KEY_LEN, Key, nonce_words, xor_words};
use crate::Error;
use crate::aead::{Aead, NONCE_LEN, TAG_LEN};
use crate::zeroize::Zeroize;

/// Largest plaintext accepted: 2^32 - 1 blocks of 64 bytes, so the 32-bit
/// block counter (starting at 1) never wraps.
const MAX_LEN: u64 = (1 << 38) - 64;

/// ChaCha20-Poly1305 keyed instance. The key is zeroised on drop.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: Key,
    backend: Backend,
    poly: PolyBackend,
}

impl core::fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20Poly1305")
            .field("backend", &self.backend)
            .field("poly", &self.poly)
            .finish_non_exhaustive()
    }
}

impl ChaCha20Poly1305 {
    /// Creates an instance using explicit ChaCha20 and Poly1305 backends (for
    /// tests and diagnostics).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for a key that is not 32 bytes long and
    /// [`Error::Unsupported`] if either backend is unavailable on this CPU.
    pub fn with_backends(key: &[u8], backend: Backend, poly: PolyBackend) -> Result<Self, Error> {
        let key: &[u8; KEY_LEN] = key.try_into().map_err(|_| Error::InvalidKey)?;
        if !backend.is_available() || !poly.is_available() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            key: Key::new(key),
            backend,
            poly,
        })
    }

    /// Returns the ChaCha20 and Poly1305 backends in use.
    #[must_use]
    pub fn backends(&self) -> (Backend, PolyBackend) {
        (self.backend, self.poly)
    }

    fn check_len(len: usize) -> Result<(), Error> {
        if u64::try_from(len).map_or(true, |l| l > MAX_LEN) {
            return Err(Error::InvalidLength);
        }
        Ok(())
    }

    /// Derives the one-time Poly1305 key from block 0 (RFC 8439, 2.6).
    fn poly(&self, nonce: &[u32; 3]) -> Poly1305 {
        let mut otk = [0u8; 64];
        xor_words(self.backend, &self.key.0, 0, nonce, &mut otk[..32]);
        let mac = Poly1305::with_backend(otk.first_chunk::<32>().unwrap_or(&[0; 32]), self.poly);
        otk.zeroize();
        mac
    }

    fn tag(mut mac: Poly1305, aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
        mac.update_padded(aad);
        mac.update_padded(ciphertext);
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        mac.update(&lens);
        mac.finalize()
    }
}

impl Aead for ChaCha20Poly1305 {
    const KEY_LEN: usize = KEY_LEN;

    fn new(key: &[u8]) -> Result<Self, Error> {
        Self::with_backends(key, Backend::best(), PolyBackend::best())
    }

    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        Self::check_len(in_out.len())?;
        let n = nonce_words(nonce);
        let mac = self.poly(&n);
        xor_words(self.backend, &self.key.0, 1, &n, in_out);
        Ok(Self::tag(mac, aad, in_out))
    }

    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        Self::check_len(in_out.len())?;
        let n = nonce_words(nonce);
        let mac = self.poly(&n);
        // Authenticate before decrypting so unauthenticated plaintext never
        // exists in `in_out`.
        let mut expected = Self::tag(mac, aad, in_out);
        let ok = crate::ct::eq(&expected, tag);
        expected.zeroize();
        if !ok {
            in_out.zeroize();
            return Err(Error::DecryptFailed);
        }
        xor_words(self.backend, &self.key.0, 1, &n, in_out);
        Ok(())
    }
}
