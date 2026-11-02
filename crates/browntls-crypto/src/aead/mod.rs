//! Authenticated encryption with associated data.
//!
//! All AEADs in this crate use 96-bit nonces and 128-bit tags, as required by
//! TLS 1.2 (RFC 5288, RFC 7905) and TLS 1.3 (RFC 8446).

use crate::Error;

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// Tag length in bytes.
pub const TAG_LEN: usize = 16;

/// An AEAD keyed instance.
///
/// Implementations expand the key once in [`Aead::new`] and may be shared
/// across threads; the expanded key is zeroised on drop.
pub trait Aead: Sized + Send + Sync {
    /// Key length in bytes.
    const KEY_LEN: usize;

    /// Expands `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `key.len() != Self::KEY_LEN`.
    fn new(key: &[u8]) -> Result<Self, Error>;

    /// Encrypts `in_out` in place and returns the authentication tag.
    ///
    /// The caller must never reuse a nonce under the same key. Callers must
    /// also keep `in_out.len()` within the algorithm's per-message limit
    /// (AES-GCM: 2^36 - 32 bytes; ChaCha20-Poly1305: 2^38 - 64 bytes);
    /// implementations return [`Error::InvalidLength`] beyond it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when the message is too long.
    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error>;

    /// Verifies `tag` and decrypts `in_out` in place.
    ///
    /// The tag comparison is constant time. On failure `in_out` is overwritten
    /// with zeros so that no unauthenticated plaintext is released.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptFailed`] if authentication fails, or
    /// [`Error::InvalidLength`] when the message is too long.
    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error>;
}
