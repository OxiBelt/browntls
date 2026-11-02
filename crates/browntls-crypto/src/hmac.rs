//! HMAC (RFC 2104, FIPS 198-1).

use crate::ct;
use crate::hash::{HashFunction, MAX_BLOCK_LEN};
use crate::zeroize::zeroize_bytes;

/// A keyed HMAC computation.
///
/// Cloning a freshly keyed instance is the cheap way to compute many MACs
/// under one key: the key-dependent inner and outer hash states are reused.
#[derive(Clone)]
pub struct Hmac<H: HashFunction> {
    inner: H,
    outer: H,
}

impl<H: HashFunction> core::fmt::Debug for Hmac<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hmac { .. }")
    }
}

impl<H: HashFunction> Hmac<H> {
    /// Keys a new HMAC computation. Keys longer than the block size are hashed.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut block = [0u8; MAX_BLOCK_LEN];
        let block = &mut block[..H::BLOCK_LEN];
        if key.len() > H::BLOCK_LEN {
            let d = H::digest(key);
            block[..H::OUTPUT_LEN].copy_from_slice(d.as_ref());
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        for b in block.iter_mut() {
            *b ^= 0x36;
        }
        let mut inner = H::new();
        inner.update(block);
        for b in block.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        let mut outer = H::new();
        outer.update(block);
        zeroize_bytes(block);
        Self { inner, outer }
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Completes the computation and returns the tag.
    #[must_use]
    pub fn finalize(self) -> H::Output {
        let inner = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(inner.as_ref());
        outer.finalize()
    }

    /// Completes the computation and compares the tag with `expected` in
    /// constant time. Truncated tags of at least half the digest length are
    /// accepted (RFC 2104, section 5).
    #[must_use]
    pub fn verify(self, expected: &[u8]) -> bool {
        if expected.len() < H::OUTPUT_LEN / 2 || expected.len() > H::OUTPUT_LEN {
            return false;
        }
        let tag = self.finalize();
        ct::eq(&tag.as_ref()[..expected.len()], expected)
    }

    /// One-shot MAC.
    #[must_use]
    pub fn mac(key: &[u8], data: &[u8]) -> H::Output {
        let mut m = Self::new(key);
        m.update(data);
        m.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha256, Sha384, Sha512};

    // RFC 4231 test case 2.
    #[test]
    fn rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        assert_eq!(
            hex::encode(Hmac::<Sha256>::mac(key, data)),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex::encode(Hmac::<Sha384>::mac(key, data)),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
        );
        assert_eq!(
            hex::encode(Hmac::<Sha512>::mac(key, data)),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    // RFC 4231 test case 6: key longer than the block size.
    #[test]
    fn rfc4231_case6() {
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hex::encode(Hmac::<Sha256>::mac(&key, data)),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        let mut m = Hmac::<Sha256>::new(&key);
        m.update(data);
        assert!(m.clone().verify(&Hmac::<Sha256>::mac(&key, data)));
        assert!(!m.verify(&[0u8; 32]));
    }
}
