//! Types shared by the AEAD constructions ([`crate::aes_gcm`] and
//! [`crate::chacha20poly1305`]).

/// AEAD nonce length used by every supported construction.
pub const NONCE_LEN: usize = 12;
/// AEAD tag length used by every supported construction.
pub const TAG_LEN: usize = 16;

/// Authentication failed, or the input was out of range for the algorithm.
///
/// Deliberately carries no detail so that callers cannot leak which check
/// failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeadError;

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("aead operation failed")
    }
}

/// A key had a length the algorithm does not support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidKeyLength;

impl core::fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid key length")
    }
}
