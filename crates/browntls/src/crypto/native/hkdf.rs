//! HKDF (RFC 5869) for the TLS 1.3 key schedule, via `browntls_crypto::hkdf`.

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use browntls_crypto::hash::{self as bc_hash, HashFunction};
use browntls_crypto::hkdf::Hkdf as BcHkdf;
use browntls_crypto::hmac::Hmac as BcHmac;
use browntls_crypto::zeroize::zeroize_bytes;

use super::hash::Named;
use super::hmac::{tag_and_wipe, zeroed};
use crate::crypto::hmac::Tag;
use crate::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};

/// HKDF-SHA256.
pub static HKDF_SHA256: &dyn Hkdf = &HKDF_SHA256_IMPL;
/// HKDF-SHA384.
pub static HKDF_SHA384: &dyn Hkdf = &HKDF_SHA384_IMPL;

pub(crate) static HKDF_SHA256_IMPL: HkdfImpl<bc_hash::Sha256> = HkdfImpl(PhantomData);
pub(crate) static HKDF_SHA384_IMPL: HkdfImpl<bc_hash::Sha384> = HkdfImpl(PhantomData);

/// HKDF over a `browntls-crypto` hash.
pub(crate) struct HkdfImpl<H>(PhantomData<H>);

impl<H: Named> HkdfImpl<H> {
    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Box<dyn HkdfExpander> {
        // `None` means HashLen zero bytes (RFC 5869 §2.2), which
        // `extract_prk` implements.
        let mut prk = BcHkdf::<H>::extract_prk(salt, ikm);
        let expander = BcHkdf::<H>::from_prk(prk.as_ref());
        zeroize_bytes(prk.as_mut());
        Box::new(Expander(expander))
    }
}

impl<H: Named> Hkdf for HkdfImpl<H> {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        Self::extract(salt, zeroed::<H>().as_ref())
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        Self::extract(salt, secret)
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(Expander(BcHkdf::<H>::from_prk(okm.as_ref())))
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        tag_and_wipe(BcHmac::<H>::mac(key.as_ref(), message))
    }
}

impl<H: Named> fmt::Debug for HkdfImpl<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hkdf({:?})", H::BC_ALGORITHM)
    }
}

/// `HKDF-Expand` for one PRK (held as a keyed HMAC).
struct Expander<H: HashFunction>(BcHkdf<H>);

impl<H: Named> HkdfExpander for Expander<H> {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.0.expand(info, output).map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut out = zeroed::<H>();
        // One hash-length block is always within `255 * HashLen`.
        let _ = self.0.expand(info, out.as_mut());
        let block = OkmBlock::new(out.as_ref());
        zeroize_bytes(out.as_mut());
        block
    }

    fn hash_len(&self) -> usize {
        H::OUTPUT_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 test case 1.
    #[test]
    fn rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt: alloc::vec::Vec<u8> = (0..=0x0c).collect();
        let info: alloc::vec::Vec<u8> = (0xf0..=0xf9).collect();
        let expander = HKDF_SHA256.extract_from_secret(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        expander
            .expand_slice(&[&info[..3], &info[3..]], &mut okm)
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
        assert_eq!(expander.hash_len(), 32);
        let mut too_long = [0u8; 255 * 32 + 1];
        assert_eq!(
            expander.expand_slice(&[], &mut too_long),
            Err(OutputLengthError)
        );
        let block = expander.expand_block(&[&info]);
        assert_eq!(&block.as_ref()[..32], &okm[..32]);
    }

    #[test]
    fn zero_ikm_and_okm_expander() {
        let a = HKDF_SHA384.extract_from_zero_ikm(None);
        let b = HKDF_SHA384.extract_from_secret(Some(&[0u8; 48]), &[0u8; 48]);
        assert_eq!(
            a.expand_block(&[b"x"]).as_ref(),
            b.expand_block(&[b"x"]).as_ref()
        );
        let okm = a.expand_block(&[b"secret"]);
        let c = HKDF_SHA384.expander_for_okm(&okm);
        assert_eq!(c.hash_len(), 48);
        assert_eq!(
            HKDF_SHA384.hmac_sign(&okm, b"m").as_ref(),
            BcHmac::<bc_hash::Sha384>::mac(okm.as_ref(), b"m").as_ref()
        );
    }
}
