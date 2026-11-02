//! HKDF (RFC 5869) over any [`Digest`].

use crate::hash::Digest;
use crate::hmac::Hmac;

/// The requested HKDF output was longer than `255 * HashLen`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputTooLong;

/// HKDF-Extract. A missing salt is treated as `HashLen` zero bytes.
#[must_use]
pub fn extract<D: Digest>(salt: Option<&[u8]>, ikm: &[u8]) -> D::Output {
    let zeros = [0u8; crate::hash::MAX_OUTPUT_LEN];
    let salt = salt.unwrap_or(&zeros[..D::OUTPUT_LEN]);
    Hmac::<D>::mac(salt, ikm)
}

/// HKDF-Expand. `info` is given in parts that are concatenated.
///
/// # Errors
///
/// Returns [`OutputTooLong`] when `out.len() > 255 * D::OUTPUT_LEN`; `out` is
/// left unchanged in that case.
pub fn expand<D: Digest>(prk: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<(), OutputTooLong> {
    if out.len() > 255 * D::OUTPUT_LEN {
        return Err(OutputTooLong);
    }
    let base = Hmac::<D>::new(prk);
    let mut prev: Option<D::Output> = None;
    for (counter, chunk) in (1u8..=255).zip(out.chunks_mut(D::OUTPUT_LEN)) {
        let mut h = base.clone();
        if let Some(t) = &prev {
            h.update(t.as_ref());
        }
        for part in info {
            h.update(part);
        }
        h.update(&[counter]);
        let t = h.finalize();
        chunk.copy_from_slice(&t.as_ref()[..chunk.len()]);
        prev = Some(t);
    }
    if let Some(mut t) = prev {
        zeroize::Zeroize::zeroize(t.as_mut());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;

    fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        hex::decode(s).unwrap()
    }

    // RFC 5869 test cases 1-3 (SHA-256).
    #[test]
    fn rfc5869() {
        let cases = [
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                Some("000102030405060708090a0b0c"),
                "f0f1f2f3f4f5f6f7f8f9",
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                Some(
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                ),
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                None,
                "",
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, prk, okm) in cases {
            let salt = salt.map(unhex);
            let p = extract::<Sha256>(salt.as_deref(), &unhex(ikm));
            assert_eq!(p.as_slice(), unhex(prk).as_slice());
            let expected = unhex(okm);
            let mut out = alloc::vec![0u8; expected.len()];
            let info = unhex(info);
            let (a, b) = info.split_at(info.len() / 2);
            expand::<Sha256>(&p, &[a, b], &mut out).unwrap();
            assert_eq!(out, expected);
        }
        let mut too_long = [0u8; 255 * 32 + 1];
        assert_eq!(
            expand::<Sha256>(&[0; 32], &[], &mut too_long),
            Err(OutputTooLong)
        );
    }
}
