//! EMSA-PSS encoding and verification (RFC 8017, section 9.1) with MGF1.
//!
//! The mask generation function uses the same hash as the message, and the
//! salt length equals the digest length, as required for TLS 1.3
//! (RFC 8446, section 4.2.3) and by the Web PKI profile.

use crate::Error;
use crate::hash::{DynHash, HashAlgorithm, MAX_OUTPUT_LEN};

/// XORs `MGF1(seed)` into `out` (RFC 8017, appendix B.2.1).
fn mgf1_xor(hash: HashAlgorithm, seed: &[u8], out: &mut [u8]) {
    let h_len = hash.output_len();
    for (counter, chunk) in out.chunks_mut(h_len).enumerate() {
        let mut h = DynHash::new(hash);
        h.update(seed);
        // The output is at most 1024 bytes, so the counter fits in a byte,
        // but RFC 8017 specifies a 4-byte big-endian counter.
        h.update(&(counter as u32).to_be_bytes());
        let mask = h.finalize();
        for (o, m) in chunk.iter_mut().zip(mask.as_ref()) {
            *o ^= m;
        }
    }
}

/// `H = Hash(0x00 * 8 || mHash || salt)`.
fn hash_m_prime(hash: HashAlgorithm, m_hash: &[u8], salt: &[u8], out: &mut [u8]) {
    let mut h = DynHash::new(hash);
    h.update(&[0u8; 8]);
    h.update(m_hash);
    h.update(salt);
    out.copy_from_slice(h.finalize().as_ref());
}

/// Encodes `mHash` with `salt` (of length `hLen`) into `em`, the encoded
/// message of `emBits` bits (`em.len() == ceil(emBits / 8)`).
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `emLen < 2 hLen + 2` or when the
/// salt or digest lengths are wrong.
pub(crate) fn encode(
    hash: HashAlgorithm,
    m_hash: &[u8],
    salt: &[u8],
    em_bits: usize,
    em: &mut [u8],
) -> Result<(), Error> {
    let h_len = hash.output_len();
    let em_len = em.len();
    if em_bits.div_ceil(8) != em_len
        || m_hash.len() != h_len
        || salt.len() != h_len
        || em_len < 2 * h_len + 2
    {
        return Err(Error::InvalidLength);
    }
    let mut h = [0u8; MAX_OUTPUT_LEN];
    let h = &mut h[..h_len];
    hash_m_prime(hash, m_hash, salt, h);

    let db_len = em_len - h_len - 1;
    let ps_len = db_len - h_len - 1;
    let (db, rest) = em.split_at_mut(db_len);
    db[..ps_len].fill(0);
    db[ps_len] = 0x01;
    db[ps_len + 1..].copy_from_slice(salt);
    mgf1_xor(hash, h, db);
    // Clear the leftmost 8 emLen - emBits bits of the first octet.
    let unused = 8 * em_len - em_bits;
    db[0] &= 0xffu8 >> unused;
    rest[..h_len].copy_from_slice(h);
    rest[h_len] = 0xbc;
    Ok(())
}

/// Verifies that `em` (of `emBits` bits) is a valid PSS encoding of `mHash`
/// with a salt of length `hLen`.
///
/// This operates on public data; it checks every condition of RFC 8017
/// section 9.1.2 and reports a single combined result.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] on any inconsistency.
pub(crate) fn verify(
    hash: HashAlgorithm,
    m_hash: &[u8],
    em: &[u8],
    em_bits: usize,
) -> Result<(), Error> {
    let h_len = hash.output_len();
    let em_len = em.len();
    if em_bits.div_ceil(8) != em_len || m_hash.len() != h_len || em_len < 2 * h_len + 2 {
        return Err(Error::InvalidSignature);
    }
    let mut bad = 0u8;
    bad |= em[em_len - 1] ^ 0xbc;
    let db_len = em_len - h_len - 1;
    let unused = 8 * em_len - em_bits;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..h_len];
    bad |= masked_db[0] & !(0xffu8 >> unused);

    // DB = maskedDB XOR MGF1(H), computed in place in a stack buffer.
    let mut db = [0u8; super::MAX_MODULUS_BYTES];
    let db = &mut db[..db_len];
    db.copy_from_slice(masked_db);
    mgf1_xor(hash, h, db);
    db[0] &= 0xffu8 >> unused;

    let ps_len = db_len - h_len - 1;
    for &b in &db[..ps_len] {
        bad |= b;
    }
    bad |= db[ps_len] ^ 0x01;
    let salt = &db[ps_len + 1..];
    let mut h2 = [0u8; MAX_OUTPUT_LEN];
    let h2 = &mut h2[..h_len];
    hash_m_prime(hash, m_hash, salt, h2);
    let h_ok = crate::ct::eq(h, h2);
    if bad == 0 && h_ok {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn encode_then_verify_roundtrip() {
        for hash in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
        ] {
            let h_len = hash.output_len();
            let m_hash: Vec<u8> = (0..h_len as u8).collect();
            let salt: Vec<u8> = (0..h_len as u8).map(|b| b ^ 0x5a).collect();
            for em_bits in [2047usize, 2048, 1023, 1030, 8191] {
                let em_len = em_bits.div_ceil(8);
                if em_len < 2 * h_len + 2 {
                    continue; // SHA-512 needs at least 130 bytes
                }
                let mut em = vec![0u8; em_len];
                encode(hash, &m_hash, &salt, em_bits, &mut em).unwrap();
                verify(hash, &m_hash, &em, em_bits).unwrap();
                // Any bit flip must be detected.
                for pos in [0usize, 1, em_len / 2, em_len - h_len - 2, em_len - 1] {
                    let mut bad = em.clone();
                    bad[pos] ^= 0x40;
                    assert!(
                        verify(hash, &m_hash, &bad, em_bits).is_err(),
                        "{hash:?} {em_bits} {pos}"
                    );
                }
                let mut other = m_hash.clone();
                other[0] ^= 1;
                assert!(verify(hash, &other, &em, em_bits).is_err());
            }
        }
    }

    #[test]
    fn rejects_short_encodings() {
        let m_hash = [0u8; 32];
        let salt = [0u8; 32];
        let mut em = [0u8; 65];
        assert_eq!(
            encode(HashAlgorithm::Sha256, &m_hash, &salt, 520, &mut em),
            Err(Error::InvalidLength)
        );
        let mut em = [0u8; 66];
        encode(HashAlgorithm::Sha256, &m_hash, &salt, 528, &mut em).unwrap();
        verify(HashAlgorithm::Sha256, &m_hash, &em, 528).unwrap();
        assert!(verify(HashAlgorithm::Sha256, &m_hash, &em[1..], 520).is_err());
    }

    #[test]
    fn mgf1_known_answer() {
        // MGF1-SHA256 values cross-checked against an independent implementation.
        let mut out = [0u8; 3];
        mgf1_xor(HashAlgorithm::Sha256, b"foo", &mut out);
        assert_eq!(hex::encode(out), "3bdaba");
        let mut out = [0u8; 5];
        mgf1_xor(HashAlgorithm::Sha256, b"foo", &mut out);
        assert_eq!(hex::encode(out), "3bdaba83cf");
        let mut out = [0u8; 50];
        mgf1_xor(HashAlgorithm::Sha256, b"bar", &mut out);
        assert_eq!(
            hex::encode(out),
            "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
        );
    }
}
