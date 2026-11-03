//! The TLS 1.3 key derivation primitives: HKDF (RFC 5869).

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{ActiveKeyExchange, hmac};
use crate::error::Error;
use crate::versions::TLS13;

/// HKDF for a particular hash.
pub trait Hkdf: Send + Sync {
    /// `HKDF-Extract(salt, 0^HashLen)`.
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander>;

    /// `HKDF-Extract(salt, secret)`.
    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander>;

    /// `HKDF-Extract(salt, shared_secret)` where the shared secret comes from
    /// completing `kx` with `peer_pub_key`.
    fn extract_from_kx_shared_secret(
        &self,
        salt: Option<&[u8]>,
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
    ) -> Result<Box<dyn HkdfExpander>, Error> {
        Ok(self.extract_from_secret(
            salt,
            kx.complete_for_tls_version(peer_pub_key, &TLS13)?
                .secret_bytes(),
        ))
    }

    /// An expander whose PRK is `okm` (used when a derived secret is itself a PRK).
    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander>;

    /// `HMAC(key, message)` with this HKDF's hash.
    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> hmac::Tag;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// `HKDF-Expand` for one PRK.
pub trait HkdfExpander: Send + Sync {
    /// Expands into `output`, which may be at most `255 * hash_len` long.
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError>;

    /// Expands exactly one hash-length block.
    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock;

    /// The hash length.
    fn hash_len(&self) -> usize;
}

/// Expands `N` bytes from `expander` into `T`.
///
/// `N` must be at most `255 * hash_len`; the caller guarantees this by only
/// using array sizes that are valid for every supported hash.
pub fn expand<T, const N: usize>(expander: &dyn HkdfExpander, info: &[&[u8]]) -> T
where
    T: From<[u8; N]>,
{
    let mut output = [0u8; N];
    // Every array size used in this crate is below 255 * 32, so this cannot fail.
    let _ = expander.expand_slice(info, &mut output);
    T::from(output)
}

/// One hash-length block of output keying material; zeroised on drop.
#[derive(Clone)]
pub struct OkmBlock {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl OkmBlock {
    /// Wraps `bytes`, which must be at most [`Self::MAX_LEN`] long.
    pub fn new(bytes: &[u8]) -> Self {
        let mut block = Self {
            buf: [0u8; Self::MAX_LEN],
            used: bytes.len().min(Self::MAX_LEN),
        };
        block.buf[..block.used].copy_from_slice(&bytes[..block.used]);
        block
    }

    /// The largest block supported.
    pub const MAX_LEN: usize = 64;
}

impl Drop for OkmBlock {
    fn drop(&mut self) {
        super::zeroize_slice(&mut self.buf);
    }
}

impl AsRef<[u8]> for OkmBlock {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl core::fmt::Debug for OkmBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OkmBlock(..)")
    }
}

/// The requested output was longer than `255 * hash_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputLengthError;

/// An [`Hkdf`] built from any [`hmac::Hmac`].
pub struct HkdfUsingHmac<'a>(pub &'a dyn hmac::Hmac);

impl core::fmt::Debug for HkdfUsingHmac<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HkdfUsingHmac")
    }
}

impl HkdfUsingHmac<'_> {
    fn extract(&self, salt: Option<&[u8]>, ikm: &[u8]) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; hmac::Tag::MAX_LEN];
        let salt = salt.unwrap_or(&zeroes[..self.0.hash_output_len()]);
        let prk = self.0.with_key(salt).sign(&[ikm]);
        Box::new(HkdfExpanderUsingHmac(self.0.with_key(prk.as_ref())))
    }
}

impl Hkdf for HkdfUsingHmac<'_> {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; hmac::Tag::MAX_LEN];
        self.extract(salt, &zeroes[..self.0.hash_output_len()])
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        self.extract(salt, secret)
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(HkdfExpanderUsingHmac(self.0.with_key(okm.as_ref())))
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> hmac::Tag {
        self.0.with_key(key.as_ref()).sign(&[message])
    }
}

/// An [`HkdfExpander`] built from a keyed HMAC.
pub struct HkdfExpanderUsingHmac(Box<dyn hmac::Key>);

impl core::fmt::Debug for HkdfExpanderUsingHmac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HkdfExpanderUsingHmac")
    }
}

impl HkdfExpanderUsingHmac {
    fn expand_unchecked(&self, info: &[&[u8]], output: &mut [u8]) {
        let mut previous: Option<hmac::Tag> = None;
        for (n, chunk) in output.chunks_mut(self.0.tag_len()).enumerate() {
            // `n < 255` because the caller bounded `output.len()`.
            let counter = [(n + 1) as u8];
            let term = match &previous {
                Some(prev) => self.0.sign_concat(prev.as_ref(), info, &counter),
                None => self.0.sign_concat(&[], info, &counter),
            };
            chunk.copy_from_slice(&term.as_ref()[..chunk.len()]);
            previous = Some(term);
        }
    }
}

impl HkdfExpander for HkdfExpanderUsingHmac {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        if output.len() > 255 * self.0.tag_len() {
            return Err(OutputLengthError);
        }
        self.expand_unchecked(info, output);
        Ok(())
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut out = [0u8; OkmBlock::MAX_LEN];
        let len = self.0.tag_len();
        self.expand_unchecked(info, &mut out[..len]);
        let block = OkmBlock::new(&out[..len]);
        super::zeroize_slice(&mut out);
        block
    }

    fn hash_len(&self) -> usize {
        self.0.tag_len()
    }
}

/// Collects `info` parts into one vector (test helper and provider convenience).
#[allow(dead_code)]
pub(crate) fn concat_info(info: &[&[u8]]) -> Vec<u8> {
    info.concat()
}
