//! HMAC.

use alloc::boxed::Box;

/// An HMAC algorithm.
pub trait Hmac: Send + Sync {
    /// Keys the algorithm.
    fn with_key(&self, key: &[u8]) -> Box<dyn Key>;

    /// The output length of the underlying hash.
    fn hash_output_len(&self) -> usize;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// An HMAC tag of at most 64 bytes; zeroised on drop.
#[derive(Clone)]
pub struct Tag {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl Tag {
    /// Wraps `bytes`, which must be at most [`Self::MAX_LEN`] long.
    pub fn new(bytes: &[u8]) -> Self {
        let mut tag = Self {
            buf: [0u8; Self::MAX_LEN],
            used: bytes.len().min(Self::MAX_LEN),
        };
        tag.buf[..tag.used].copy_from_slice(&bytes[..tag.used]);
        tag
    }

    /// The largest tag supported.
    pub const MAX_LEN: usize = 64;
}

impl Drop for Tag {
    fn drop(&mut self) {
        super::zeroize_slice(&mut self.buf);
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl core::fmt::Debug for Tag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Tag(..)")
    }
}

/// A keyed HMAC.
pub trait Key: Send + Sync {
    /// Computes the tag over the concatenation of `data`.
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    /// Computes the tag over `first || middle... || last`.
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag;

    /// The tag length.
    fn tag_len(&self) -> usize;
}
