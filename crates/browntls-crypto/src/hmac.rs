//! HMAC (RFC 2104, FIPS 198-1) over any [`Digest`].

use crate::hash::{Digest, MAX_BLOCK_LEN, MAX_OUTPUT_LEN};
use zeroize::Zeroize;

/// A keyed HMAC computation.
#[derive(Clone)]
pub struct Hmac<D: Digest> {
    inner: D,
    outer: D,
}

impl<D: Digest> Hmac<D> {
    /// Starts an HMAC computation keyed with `key`.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        debug_assert!(D::BLOCK_LEN <= MAX_BLOCK_LEN);
        let mut block = [0u8; MAX_BLOCK_LEN];
        if key.len() > D::BLOCK_LEN {
            let hashed = D::digest(key);
            block[..D::OUTPUT_LEN].copy_from_slice(hashed.as_ref());
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let block = &mut block[..D::BLOCK_LEN];

        for b in block.iter_mut() {
            *b ^= 0x36;
        }
        let mut inner = D::new();
        inner.update(block);

        for b in block.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        let mut outer = D::new();
        outer.update(block);

        block.zeroize();
        Self { inner, outer }
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finishes and returns the tag.
    #[must_use]
    pub fn finalize(self) -> D::Output {
        let Self { inner, mut outer } = self;
        let inner_hash = inner.finalize();
        outer.update(inner_hash.as_ref());
        outer.finalize()
    }

    /// Finishes and compares the tag with `expected` in constant time.
    /// Truncated tags are accepted only if at least half the output length.
    #[must_use]
    pub fn verify(self, expected: &[u8]) -> bool {
        let tag = self.finalize();
        let tag = tag.as_ref();
        if expected.len() > tag.len() || expected.len() < tag.len() / 2 {
            return false;
        }
        crate::ct::bytes_eq(&tag[..expected.len()], expected)
    }

    /// Computes `HMAC(key, data)` in one call.
    #[must_use]
    pub fn mac(key: &[u8], data: &[u8]) -> D::Output {
        let mut h = Self::new(key);
        h.update(data);
        h.finalize()
    }
}

impl<D: Digest> core::fmt::Debug for Hmac<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hmac")
    }
}

const _: () = assert!(MAX_OUTPUT_LEN <= MAX_BLOCK_LEN);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha256, Sha384, Sha512};

    fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        hex::decode(s).unwrap()
    }

    // RFC 4231 test cases 1, 2, 6 and 7.
    #[test]
    #[allow(clippy::type_complexity)]
    fn rfc4231() {
        let cases: [(&[u8], &[u8], &str, &str, &str); 4] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            ),
            (
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
                "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
            ),
        ];
        for (key, data, t256, t384, t512) in cases {
            assert_eq!(
                Hmac::<Sha256>::mac(key, data).as_ref(),
                unhex(t256).as_slice()
            );
            assert_eq!(
                Hmac::<Sha384>::mac(key, data).as_ref(),
                unhex(t384).as_slice()
            );
            assert_eq!(
                Hmac::<Sha512>::mac(key, data).as_ref(),
                unhex(t512).as_slice()
            );
            let mut h = Hmac::<Sha256>::new(key);
            h.update(data);
            assert!(h.clone().verify(&unhex(t256)));
            assert!(h.clone().verify(&unhex(t256)[..16]));
            assert!(!h.clone().verify(&unhex(t256)[..15]));
            let mut wrong = unhex(t256);
            wrong[31] ^= 1;
            assert!(!h.verify(&wrong));
        }
    }
}
