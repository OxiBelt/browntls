//! EMSA-PKCS1-v1_5 encoding (RFC 8017, section 9.2).
//!
//! Verification never parses an encoded message: the expected encoding is
//! rebuilt from the message and compared in full, which rules out the
//! classic Bleichenbacher '06 forgeries against lenient parsers.

use crate::Error;
use crate::der::{Writer, tag};
use crate::hash::{DynHash, HashAlgorithm};

/// Contents of the `id-sha*` object identifiers under
/// `joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3)
/// nistAlgorithms(4) hashAlgs(2)`.
fn hash_oid(hash: HashAlgorithm) -> [u8; 9] {
    let last = match hash {
        HashAlgorithm::Sha224 => 4,
        HashAlgorithm::Sha256 => 1,
        HashAlgorithm::Sha384 => 2,
        HashAlgorithm::Sha512 => 3,
        HashAlgorithm::Sha3_256 => 8,
        HashAlgorithm::Sha3_384 => 9,
        HashAlgorithm::Sha3_512 => 10,
    };
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last]
}

/// Length of the `DigestInfo` encoding for `hash`.
pub(crate) const fn digest_info_len(hash: HashAlgorithm) -> usize {
    // SEQUENCE { SEQUENCE { OID(9) NULL } OCTET STRING(hLen) }
    2 + (2 + 11 + 2) + 2 + hash.output_len()
}

/// Writes `EM = 0x00 || 0x01 || PS || 0x00 || T` for `msg` into `em`, whose
/// length is the modulus length `k`.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `k < tLen + 11`.
pub(crate) fn encode(hash: HashAlgorithm, msg: &[u8], em: &mut [u8]) -> Result<(), Error> {
    let digest = DynHash::digest(hash, msg);
    encode_digest(hash, digest.as_ref(), em)
}

/// [`encode`] for an already computed digest.
pub(crate) fn encode_digest(
    hash: HashAlgorithm,
    digest: &[u8],
    em: &mut [u8],
) -> Result<(), Error> {
    let k = em.len();
    let t_len = digest_info_len(hash);
    if digest.len() != hash.output_len() || k < t_len + 11 {
        return Err(Error::InvalidLength);
    }
    let ps_len = k - t_len - 3;
    em[0] = 0x00;
    em[1] = 0x01;
    em[2..2 + ps_len].fill(0xff);
    em[2 + ps_len] = 0x00;
    let mut w = Writer::new(&mut em[3 + ps_len..]);
    w.header(tag::SEQUENCE, t_len - 2)?;
    w.header(tag::SEQUENCE, 13)?;
    w.tlv(tag::OID, &hash_oid(hash))?;
    w.tlv(tag::NULL, &[])?;
    w.tlv(tag::OCTET_STRING, digest)?;
    debug_assert_eq!(w.len(), t_len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn sha256_prefix_matches_rfc8017() {
        // RFC 8017 section 9.2 note 1 lists the DigestInfo prefix for SHA-256.
        let mut em = [0u8; 64];
        let digest = [0xabu8; 32];
        encode_digest(HashAlgorithm::Sha256, &digest, &mut em).unwrap();
        assert_eq!(&em[..2], &[0, 1]);
        assert_eq!(&em[2..12], &[0xff; 10]);
        assert_eq!(em[12], 0);
        assert_eq!(
            &em[13..32],
            &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20
            ]
        );
        assert_eq!(&em[32..], &digest);
        // Too short.
        let mut short = [0u8; 61];
        assert_eq!(
            encode_digest(HashAlgorithm::Sha256, &digest, &mut short),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn prefixes_for_other_hashes() {
        for (hash, prefix) in [
            (
                HashAlgorithm::Sha224,
                &[
                    0x30u8, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x04, 0x05, 0x00, 0x04, 0x1c,
                ][..],
            ),
            (
                HashAlgorithm::Sha384,
                &[
                    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
                ][..],
            ),
            (
                HashAlgorithm::Sha512,
                &[
                    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
                ][..],
            ),
            (
                HashAlgorithm::Sha3_256,
                &[
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x08, 0x05, 0x00, 0x04, 0x20,
                ][..],
            ),
        ] {
            let mut em = [0u8; 128];
            let digest = vec![0x11u8; hash.output_len()];
            encode_digest(hash, &digest, &mut em).unwrap();
            let t_len = digest_info_len(hash);
            assert_eq!(&em[128 - t_len..128 - hash.output_len()], prefix);
        }
    }
}
