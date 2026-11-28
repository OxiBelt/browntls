//! `LabeledExtract` and `LabeledExpand` (RFC 9180 §4), dispatched over [`Kdf`].

use super::{Kdf, MAX_SECRET_LEN};
use crate::Error;
use crate::hash::{HashFunction, Sha256, Sha384, Sha512};
use crate::hkdf::Hkdf;
use crate::hmac::Hmac;
use crate::zeroize::zeroize_bytes;

const VERSION_LABEL: &[u8] = b"HPKE-v1";

/// A secret of at most [`MAX_SECRET_LEN`] bytes, zeroised on drop.
pub(crate) struct Secret {
    bytes: [u8; MAX_SECRET_LEN],
    len: usize,
}

impl Secret {
    pub(crate) fn zeroed(len: usize) -> Self {
        debug_assert!(len <= MAX_SECRET_LEN);
        Self {
            bytes: [0; MAX_SECRET_LEN],
            len: len.min(MAX_SECRET_LEN),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    /// Empties the buffer, zeroising what it held.
    #[cfg(any(feature = "key-log", all(test, feature = "alloc")))]
    pub(crate) fn clear(&mut self) {
        zeroize_bytes(&mut self.bytes);
        self.len = 0;
    }

    /// Replaces the content with a copy of `other`'s.
    pub(crate) fn copy_from(&mut self, other: &Self) {
        zeroize_bytes(&mut self.bytes);
        self.len = other.len;
        self.bytes[..other.len].copy_from_slice(other.as_bytes());
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.bytes);
    }
}

/// `LabeledExtract(salt, label, ikm)` =
/// `Extract(salt, "HPKE-v1" || suite_id || label || ikm)`.
pub(crate) fn labeled_extract(
    kdf: Kdf,
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Secret {
    fn go<H: HashFunction>(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Secret {
        // HMAC with an empty key equals HMAC with `HashLen` zero bytes, which
        // is what RFC 5869 prescribes for an absent salt.
        let mut m = Hmac::<H>::new(salt);
        m.update(VERSION_LABEL);
        m.update(suite_id);
        m.update(label);
        m.update(ikm);
        let mut prk = m.finalize();
        let mut out = Secret::zeroed(H::OUTPUT_LEN);
        out.as_mut_bytes().copy_from_slice(prk.as_ref());
        zeroize_bytes(prk.as_mut());
        out
    }
    match kdf {
        Kdf::HkdfSha256 => go::<Sha256>(suite_id, salt, label, ikm),
        Kdf::HkdfSha384 => go::<Sha384>(suite_id, salt, label, ikm),
        Kdf::HkdfSha512 => go::<Sha512>(suite_id, salt, label, ikm),
    }
}

/// Most pieces the `info` of [`labeled_expand`] is given in: the KEM context
/// of `AuthEncap` is `enc || pkRm || pkSm`.
const MAX_INFO_PARTS: usize = 3;

/// `LabeledExpand(prk, label, info, L)` =
/// `Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)`
/// with `L = out.len()` and `info` the concatenation of `info`'s at most
/// three pieces.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `L` exceeds `255 * Nh` (or `2^16 - 1`), or
/// `info` has more than three pieces.
pub(crate) fn labeled_expand(
    kdf: Kdf,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    let len = u16::try_from(out.len()).map_err(|_| Error::InvalidLength)?;
    let len = len.to_be_bytes();
    let mut parts: [&[u8]; 4 + MAX_INFO_PARTS] =
        [&len, VERSION_LABEL, suite_id, label, &[], &[], &[]];
    let slots = parts
        .get_mut(4..4 + info.len())
        .ok_or(Error::InvalidLength)?;
    slots.copy_from_slice(info);
    match kdf {
        Kdf::HkdfSha256 => Hkdf::<Sha256>::from_prk(prk).expand(&parts, out),
        Kdf::HkdfSha384 => Hkdf::<Sha384>::from_prk(prk).expand(&parts, out),
        Kdf::HkdfSha512 => Hkdf::<Sha512>::from_prk(prk).expand(&parts, out),
    }
}
