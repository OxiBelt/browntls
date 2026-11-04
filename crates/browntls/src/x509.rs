//! Minimal DER helpers: wrapping values in SEQUENCE/BIT STRING and locating the
//! `SubjectPublicKeyInfo` inside an X.509 certificate.
//!
//! This is deliberately not a general X.509 parser: path validation lives in
//! `browntls-pki`. The functions here only need to be strict enough to never
//! misattribute bytes, and they reject anything that is not canonical DER.

use alloc::vec::Vec;

use crate::error::{CertificateError, Error};

const TAG_SEQUENCE: u8 = 0x30;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_INTEGER: u8 = 0x02;
const TAG_CONTEXT_0: u8 = 0xa0;

/// Encodes a DER length.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        // Lengths below 0x80 are a single byte by construction.
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    // At most 8 significant bytes on any platform, so this fits.
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

pub(crate) fn asn1_wrap(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(bytes.len() + 6);
    ret.push(tag);
    encode_length(bytes.len(), &mut ret);
    ret.extend_from_slice(bytes);
    ret
}

/// Wraps `bytes` in a DER SEQUENCE.
pub(crate) fn wrap_in_sequence(bytes: &[u8]) -> Vec<u8> {
    asn1_wrap(TAG_SEQUENCE, bytes)
}

/// Wraps `bytes` in a DER BIT STRING with no unused bits.
pub(crate) fn wrap_in_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(bytes.len() + 1);
    inner.push(0);
    inner.extend_from_slice(bytes);
    asn1_wrap(TAG_BIT_STRING, &inner)
}

/// A strict DER cursor.
struct Der<'a> {
    input: &'a [u8],
}

impl<'a> Der<'a> {
    fn read_tlv(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), ()> {
        let (&tag, rest) = self.input.split_first().ok_or(())?;
        if tag & 0x1f == 0x1f {
            return Err(()); // multi-byte tags are not used in certificates
        }
        let (&first, rest) = rest.split_first().ok_or(())?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return Err(());
            }
            let (len_bytes, rest) = rest.split_at(n);
            if len_bytes[0] == 0 {
                return Err(()); // non-minimal length
            }
            let mut len = 0usize;
            for b in len_bytes {
                len = (len << 8) | usize::from(*b);
            }
            if len < 0x80 {
                return Err(()); // non-minimal length
            }
            (len, rest)
        };
        if rest.len() < len {
            return Err(());
        }
        let (value, after) = rest.split_at(len);
        let whole = &self.input[..self.input.len() - after.len()];
        self.input = after;
        Ok((tag, value, whole))
    }

    fn expect(&mut self, tag: u8) -> Result<(&'a [u8], &'a [u8]), ()> {
        let (got, value, whole) = self.read_tlv()?;
        if got != tag {
            return Err(());
        }
        Ok((value, whole))
    }

    fn done(&self) -> Result<(), ()> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Returns the DER-encoded `SubjectPublicKeyInfo` (with its outer SEQUENCE)
/// from `cert`, a DER-encoded X.509 v3 certificate.
pub(crate) fn subject_public_key_info(cert: &[u8]) -> Result<&[u8], Error> {
    parse_spki(cert).map_err(|()| CertificateError::BadEncoding.into())
}

fn parse_spki(cert: &[u8]) -> Result<&[u8], ()> {
    let mut outer = Der { input: cert };
    let (cert_body, _) = outer.expect(TAG_SEQUENCE)?;
    outer.done()?;

    let mut cert_body = Der { input: cert_body };
    let (tbs, _) = cert_body.expect(TAG_SEQUENCE)?;
    // signatureAlgorithm and signatureValue follow; they are not needed here.

    let mut tbs = Der { input: tbs };
    // version [0] EXPLICIT INTEGER (optional, but mandatory for v3).
    let (tag, _, _) = Der { input: tbs.input }.read_tlv()?;
    if tag == TAG_CONTEXT_0 {
        tbs.expect(TAG_CONTEXT_0)?;
    }
    tbs.expect(TAG_INTEGER)?; // serialNumber
    tbs.expect(TAG_SEQUENCE)?; // signature AlgorithmIdentifier
    tbs.expect(TAG_SEQUENCE)?; // issuer Name
    tbs.expect(TAG_SEQUENCE)?; // validity
    tbs.expect(TAG_SEQUENCE)?; // subject Name
    let (spki_value, spki) = tbs.expect(TAG_SEQUENCE)?; // subjectPublicKeyInfo

    // Sanity-check the SPKI shape: AlgorithmIdentifier SEQUENCE then BIT STRING.
    let mut inner = Der { input: spki_value };
    inner.expect(TAG_SEQUENCE)?;
    let (bits, _) = inner.expect(TAG_BIT_STRING)?;
    if bits.first() != Some(&0) {
        return Err(());
    }
    inner.done()?;
    Ok(spki)
}

/// Splits a DER `SubjectPublicKeyInfo` into the contents of its
/// `AlgorithmIdentifier` (without the outer SEQUENCE) and the
/// `subjectPublicKey` bytes (without the unused-bits octet).
pub(crate) fn split_spki(spki: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let bad = || Error::from(CertificateError::BadEncoding);
    let mut outer = Der { input: spki };
    let (value, _) = outer.expect(TAG_SEQUENCE).map_err(|()| bad())?;
    outer.done().map_err(|()| bad())?;
    let mut inner = Der { input: value };
    let (alg, _) = inner.expect(TAG_SEQUENCE).map_err(|()| bad())?;
    let (bits, _) = inner.expect(TAG_BIT_STRING).map_err(|()| bad())?;
    inner.done().map_err(|()| bad())?;
    match bits.split_first() {
        Some((0, key)) => Ok((alg, key)),
        _ => Err(bad()),
    }
}

/// Returns the contents of the `privateKeyAlgorithm` `AlgorithmIdentifier`
/// of a DER PKCS #8 `PrivateKeyInfo` (RFC 5958 §2) without examining the
/// rest, or `None` if the structure does not start as one.
#[cfg(feature = "native")]
pub(crate) fn pkcs8_algorithm_identifier(der: &[u8]) -> Option<&[u8]> {
    let mut outer = Der { input: der };
    let (info, _) = outer.expect(TAG_SEQUENCE).ok()?;
    outer.done().ok()?;
    let mut info = Der { input: info };
    info.expect(TAG_INTEGER).ok()?; // version
    info.expect(TAG_SEQUENCE).ok().map(|(alg, _)| alg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping() {
        assert_eq!(wrap_in_sequence(&[1, 2, 3]), [0x30, 3, 1, 2, 3]);
        assert_eq!(wrap_in_bit_string(&[0xff]), [0x03, 2, 0, 0xff]);
        let long = alloc::vec![0u8; 300];
        let wrapped = wrap_in_sequence(&long);
        assert_eq!(&wrapped[..4], &[0x30, 0x82, 0x01, 0x2c]);
        assert_eq!(wrapped.len(), 304);
        let medium = alloc::vec![0u8; 200];
        let wrapped = wrap_in_sequence(&medium);
        assert_eq!(&wrapped[..3], &[0x30, 0x81, 200]);
    }

    #[test]
    fn spki_split() {
        let alg = [0x06, 0x03, 0x2b, 0x65, 0x70];
        let key = [0xaa; 32];
        let mut inner = wrap_in_sequence(&alg);
        inner.extend(wrap_in_bit_string(&key));
        let spki = wrap_in_sequence(&inner);
        let (a, k) = split_spki(&spki).unwrap();
        assert_eq!(a, alg);
        assert_eq!(k, key);
        assert!(split_spki(&spki[..spki.len() - 1]).is_err());
        assert!(split_spki(&[0x30, 0x00]).is_err());
        // non-minimal length encoding is rejected
        assert!(split_spki(&[0x30, 0x81, 0x02, 0x30, 0x00]).is_err());
    }

    #[test]
    fn spki_from_synthetic_certificate() {
        let alg = [0x06, 0x03, 0x2b, 0x65, 0x70];
        let mut spki_inner = wrap_in_sequence(&alg);
        spki_inner.extend(wrap_in_bit_string(&[1, 2, 3]));
        let spki = wrap_in_sequence(&spki_inner);

        let mut tbs = Vec::new();
        tbs.extend(asn1_wrap(TAG_CONTEXT_0, &[0x02, 0x01, 0x02])); // version v3
        tbs.extend(asn1_wrap(TAG_INTEGER, &[0x01])); // serial
        tbs.extend(wrap_in_sequence(&alg)); // signature alg
        tbs.extend(wrap_in_sequence(&[])); // issuer
        tbs.extend(wrap_in_sequence(&[])); // validity
        tbs.extend(wrap_in_sequence(&[])); // subject
        tbs.extend(&spki);
        let mut cert_body = wrap_in_sequence(&tbs);
        cert_body.extend(wrap_in_sequence(&alg));
        cert_body.extend(wrap_in_bit_string(&[9]));
        let cert = wrap_in_sequence(&cert_body);

        assert_eq!(subject_public_key_info(&cert).unwrap(), &spki[..]);
        assert!(subject_public_key_info(&cert[1..]).is_err());
        assert!(subject_public_key_info(&[]).is_err());
    }
}
