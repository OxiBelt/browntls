//! The `PkiPath` object of RFC 6066 §10.1: `PkiPath ::= SEQUENCE OF
//! Certificate`, DER-encoded, with the issuer of each certificate before
//! the certificate (the reverse of the TLS order).

use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::{CertificateUrlError, MAX_PKI_PATH_CERTIFICATES};
use crate::error::Error;
use crate::x509;

const TAG_SEQUENCE: u8 = 0x30;

/// Splits one DER SEQUENCE off the front of `input`: the whole element and
/// what follows it. Only definite, minimally encoded lengths of up to four
/// bytes are accepted.
fn split_sequence(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        // 0x80 is the indefinite form, which DER forbids.
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (bytes, rest) = rest.split_at(count);
        if bytes[0] == 0 {
            return None;
        }
        let len = bytes
            .iter()
            .fold(0usize, |len, b| (len << 8) | usize::from(*b));
        if len < 0x80 {
            return None;
        }
        (len, rest)
    };
    if rest.len() < len {
        return None;
    }
    let header = input.len() - rest.len();
    Some(input.split_at(header + len))
}

/// DER-encodes `chain`, given in TLS order (end entity first), as a
/// `PkiPath`: the same certificates, issuer first and end entity last
/// (RFC 6066 §10.1). Its SHA-1 hash is what a `pkipath` CertificateURL
/// sends.
///
/// Fails for an empty chain, more than
/// [`MAX_PKI_PATH_CERTIFICATES`](super::MAX_PKI_PATH_CERTIFICATES)
/// certificates, or a certificate that is not one DER SEQUENCE.
pub fn encode_pki_path(chain: &[CertificateDer<'_>]) -> Result<Vec<u8>, Error> {
    if chain.is_empty() || chain.len() > MAX_PKI_PATH_CERTIFICATES {
        return Err(Error::General(
            "a PkiPath holds 1 to 16 certificates".into(),
        ));
    }
    let mut contents = Vec::new();
    for cert in chain.iter().rev() {
        match split_sequence(cert.as_ref()) {
            Some((_, [])) => contents.extend_from_slice(cert.as_ref()),
            _ => return Err(Error::General("certificate is not one DER SEQUENCE".into())),
        }
    }
    Ok(x509::wrap_in_sequence(&contents))
}

/// Decodes a DER `PkiPath` strictly and returns its certificates in TLS
/// order (end entity first): the inverse of [`encode_pki_path`].
///
/// The object must be one SEQUENCE with nothing after it, holding 1 to
/// [`MAX_PKI_PATH_CERTIFICATES`](super::MAX_PKI_PATH_CERTIFICATES)
/// elements that are each a SEQUENCE, all with definite, minimal lengths.
/// The certificates themselves are left to the verifier.
pub fn decode_pki_path(der: &[u8]) -> Result<Vec<CertificateDer<'static>>, Error> {
    let malformed = || Error::from(CertificateUrlError::MalformedPkiPath);
    let Some((outer, [])) = split_sequence(der) else {
        return Err(malformed());
    };
    // The outer header is at most six bytes; skip it.
    let header = match outer.get(1) {
        Some(first) if *first < 0x80 => 2,
        Some(first) => 2 + usize::from(first & 0x7f),
        None => return Err(malformed()),
    };
    let mut contents = &outer[header..];
    let mut certs = Vec::new();
    while !contents.is_empty() {
        if certs.len() == MAX_PKI_PATH_CERTIFICATES {
            return Err(malformed());
        }
        let (cert, rest) = split_sequence(contents).ok_or_else(malformed)?;
        certs.push(CertificateDer::from(cert.to_vec()));
        contents = rest;
    }
    if certs.is_empty() {
        return Err(malformed());
    }
    certs.reverse();
    Ok(certs)
}
