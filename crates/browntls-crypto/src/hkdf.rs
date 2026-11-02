//! HKDF (RFC 5869).

use crate::Error;
use crate::hash::{HashFunction, Output};
use crate::hmac::Hmac;

/// An HKDF pseudorandom key, ready for `expand`.
#[derive(Clone)]
pub struct Hkdf<H: HashFunction> {
    prk: Hmac<H>,
}

impl<H: HashFunction> core::fmt::Debug for Hkdf<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hkdf { .. }")
    }
}

impl<H: HashFunction> Hkdf<H> {
    /// HKDF-Extract. A missing salt is treated as `HashLen` zero bytes.
    #[must_use]
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        Self::from_prk(Self::extract_prk(salt, ikm).as_ref())
    }

    /// HKDF-Extract, returning the raw PRK bytes.
    #[must_use]
    pub fn extract_prk(salt: Option<&[u8]>, ikm: &[u8]) -> H::Output {
        let zeros = H::Output::zeroed();
        let salt = salt.unwrap_or(zeros.as_ref());
        Hmac::<H>::mac(salt, ikm)
    }

    /// Uses `prk` directly as the pseudorandom key (skipping Extract).
    #[must_use]
    pub fn from_prk(prk: &[u8]) -> Self {
        Self {
            prk: Hmac::new(prk),
        }
    }

    /// HKDF-Expand with `info` given as concatenated fragments.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `okm` exceeds `255 * HashLen`.
    pub fn expand(&self, info: &[&[u8]], okm: &mut [u8]) -> Result<(), Error> {
        if okm.len() > 255 * H::OUTPUT_LEN {
            return Err(Error::InvalidLength);
        }
        let mut prev = H::Output::zeroed();
        let mut have_prev = false;
        for (i, chunk) in okm.chunks_mut(H::OUTPUT_LEN).enumerate() {
            let mut m = self.prk.clone();
            if have_prev {
                m.update(prev.as_ref());
            }
            for part in info {
                m.update(part);
            }
            // `i < 255` is guaranteed by the length check above.
            #[allow(clippy::cast_possible_truncation)]
            m.update(&[(i + 1) as u8]);
            prev = m.finalize();
            have_prev = true;
            chunk.copy_from_slice(&prev.as_ref()[..chunk.len()]);
        }
        crate::zeroize::zeroize_bytes(prev.as_mut());
        Ok(())
    }

    /// Computes HMAC(PRK, `data`) — used by TLS 1.3 for Finished MACs where the
    /// "PRK" is a finished key.
    #[must_use]
    pub fn hmac(&self, data: &[&[u8]]) -> H::Output {
        let mut m = self.prk.clone();
        for d in data {
            m.update(d);
        }
        m.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;

    // RFC 5869 test case 1.
    #[test]
    fn rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt: std::vec::Vec<u8> = (0..=0x0c).collect();
        let info: std::vec::Vec<u8> = (0xf0..=0xf9).collect();
        let prk = Hkdf::<Sha256>::extract_prk(Some(&salt), &ikm);
        assert_eq!(
            hex::encode(prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::extract(Some(&salt), &ikm)
            .expand(&[&info[..4], &info[4..]], &mut okm)
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
        let mut too_long = [0u8; 255 * 32 + 1];
        assert_eq!(
            Hkdf::<Sha256>::from_prk(&prk).expand(&[], &mut too_long),
            Err(Error::InvalidLength)
        );
    }
}
