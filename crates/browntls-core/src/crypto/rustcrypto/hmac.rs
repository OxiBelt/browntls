//! HMAC via the `hmac` crate.

use alloc::boxed::Box;
use core::marker::PhantomData;

use hmac::{Hmac as HmacImpl, KeyInit, Mac};
use sha2::Digest;
use sha2::digest::block_api::{BlockSizeUser, EagerHash};

use crate::crypto::hmac::{Hmac, Key, Tag};

/// An HMAC algorithm for a `sha2` digest type.
pub(crate) struct HmacAlg<D>(PhantomData<D>);

pub(crate) static HMAC_SHA256: HmacAlg<sha2::Sha256> = HmacAlg(PhantomData);
pub(crate) static HMAC_SHA384: HmacAlg<sha2::Sha384> = HmacAlg(PhantomData);

impl<D> Hmac for HmacAlg<D>
where
    D: Digest + EagerHash + BlockSizeUser + Clone + Send + Sync + 'static,
    HmacImpl<D>: Mac + KeyInit + Clone + Send + Sync + 'static,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        // HMAC accepts keys of any length (RFC 2104 §2): keys longer than the
        // block size are hashed first by the implementation. `new_from_slice`
        // therefore cannot fail for `Hmac<D>`.
        #[allow(clippy::expect_used)]
        let mac = HmacImpl::<D>::new_from_slice(key).expect("HMAC accepts keys of any length");
        Box::new(HmacKey(mac))
    }

    fn hash_output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

struct HmacKey<D>(HmacImpl<D>)
where
    D: EagerHash + BlockSizeUser;

impl<D> Key for HmacKey<D>
where
    D: Digest + EagerHash + BlockSizeUser + Clone + Send + Sync + 'static,
    HmacImpl<D>: Mac + Clone + Send + Sync + 'static,
{
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut mac = self.0.clone();
        Mac::update(&mut mac, first);
        for part in middle {
            Mac::update(&mut mac, part);
        }
        Mac::update(&mut mac, last);
        Tag::new(&mac.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        <D as Digest>::output_size()
    }
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
    }
}
