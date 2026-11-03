//! HMAC (RFC 2104) via `browntls_crypto::hmac`.

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::hash::{self as bc_hash, HashFunction, Output as _};
use browntls_crypto::hmac::Hmac as BcHmac;
use browntls_crypto::zeroize::zeroize_bytes;

use super::hash::Named;
use crate::crypto::hmac::{Hmac, Key, Tag};

/// HMAC-SHA256.
pub static HMAC_SHA256: &dyn Hmac = &HMAC_SHA256_IMPL;
/// HMAC-SHA384.
pub static HMAC_SHA384: &dyn Hmac = &HMAC_SHA384_IMPL;
/// HMAC-SHA512.
pub static HMAC_SHA512: &dyn Hmac = &HMAC_SHA512_IMPL;

pub(crate) static HMAC_SHA256_IMPL: HmacAlg<bc_hash::Sha256> = HmacAlg(PhantomData);
pub(crate) static HMAC_SHA384_IMPL: HmacAlg<bc_hash::Sha384> = HmacAlg(PhantomData);
pub(crate) static HMAC_SHA512_IMPL: HmacAlg<bc_hash::Sha512> = HmacAlg(PhantomData);

/// An HMAC algorithm over a `browntls-crypto` hash.
pub(crate) struct HmacAlg<H>(PhantomData<H>);

impl<H: Named> Hmac for HmacAlg<H> {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacKey(BcHmac::<H>::new(key)))
    }

    fn hash_output_len(&self) -> usize {
        H::OUTPUT_LEN
    }
}

impl<H: Named> fmt::Debug for HmacAlg<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hmac({:?})", H::BC_ALGORITHM)
    }
}

/// A keyed HMAC: the precomputed inner and outer hash states.
struct HmacKey<H: HashFunction>(BcHmac<H>);

impl<H: Named> Key for HmacKey<H> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut mac = self.0.clone();
        mac.update(first);
        for part in middle {
            mac.update(part);
        }
        mac.update(last);
        tag_and_wipe(mac.finalize())
    }

    fn tag_len(&self) -> usize {
        H::OUTPUT_LEN
    }
}

/// Copies a MAC into a [`Tag`] (zeroised on drop) and wipes the source:
/// HKDF and the TLS 1.2 PRF use tags as keys.
pub(crate) fn tag_and_wipe<O: bc_hash::Output>(mut out: O) -> Tag {
    let tag = Tag::new(out.as_ref());
    zeroize_bytes(out.as_mut());
    tag
}

/// An all-zero digest-sized buffer (used as HKDF's default salt / IKM).
pub(crate) fn zeroed<H: HashFunction>() -> H::Output {
    H::Output::zeroed()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test case 2.
    #[test]
    fn rfc4231_case2() {
        let key = HMAC_SHA256.with_key(b"Jefe");
        let tag = key.sign(&[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            hex::encode(tag.as_ref()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(key.tag_len(), 32);
        assert_eq!(HMAC_SHA384.hash_output_len(), 48);
        let tag384 =
            HMAC_SHA384
                .with_key(b"Jefe")
                .sign_concat(b"what do ya want", &[b" for"], b" nothing?");
        assert_eq!(
            hex::encode(tag384.as_ref()),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        );
        assert_eq!(HMAC_SHA512.with_key(b"Jefe").tag_len(), 64);
    }
}
