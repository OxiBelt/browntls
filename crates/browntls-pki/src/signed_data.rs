//! Signed structures (`tbs || signatureAlgorithm || signature`) and
//! signature verification through [`SignatureVerificationAlgorithm`].

use crate::der::{self, Reader, tag};
use crate::error::Error;
use crate::path::Budget;
use crate::types::SignatureVerificationAlgorithm;

/// The signed part of a certificate or CRL.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SignedData<'a> {
    /// The complete DER encoding of the signed structure (`tbsCertificate`
    /// or `tbsCertList`), including its tag and length.
    pub(crate) data: &'a [u8],
    /// Contents of the `signatureAlgorithm` `AlgorithmIdentifier`.
    pub(crate) algorithm: &'a [u8],
    /// The signature octets.
    pub(crate) signature: &'a [u8],
}

impl<'a> SignedData<'a> {
    /// Reads `tbs, signatureAlgorithm, signature` from the contents of the
    /// outer `SEQUENCE`, with `limit` bounding the `tbs` length. Returns the
    /// `tbs` contents and the signed data.
    pub(crate) fn read(
        reader: &mut Reader<'a>,
        limit: usize,
    ) -> Result<(&'a [u8], SignedData<'a>), Error> {
        let tbs = reader.tlv_limited(limit)?;
        if tbs.tag != tag::SEQUENCE {
            return Err(Error::BadDer);
        }
        let algorithm = reader.expect(tag::SEQUENCE)?;
        let signature = reader.bit_string_no_unused_bits()?;
        Ok((
            tbs.value,
            SignedData {
                data: tbs.raw,
                algorithm,
                signature,
            },
        ))
    }
}

/// A decoded `SubjectPublicKeyInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Spki<'a> {
    /// Contents of the `algorithm` `AlgorithmIdentifier`.
    pub(crate) algorithm: &'a [u8],
    /// The `subjectPublicKey` octets.
    pub(crate) key: &'a [u8],
}

impl<'a> Spki<'a> {
    /// Parses the contents of a `SubjectPublicKeyInfo` `SEQUENCE`.
    pub(crate) fn from_contents(contents: &'a [u8]) -> Result<Self, Error> {
        der::read_all(contents, |r| {
            let algorithm = r.expect(tag::SEQUENCE)?;
            let key = r.bit_string_no_unused_bits()?;
            Ok(Spki { algorithm, key })
        })
    }

    /// Parses either a complete `SubjectPublicKeyInfo` `SEQUENCE` or its
    /// contents. The two are unambiguous: the complete form is a single
    /// element, the contents are two.
    pub(crate) fn from_der_or_contents(bytes: &'a [u8]) -> Result<Self, Error> {
        match der::read_all(bytes, |r| r.expect(tag::SEQUENCE)) {
            Ok(contents) => Self::from_contents(contents),
            Err(_) => Self::from_contents(bytes),
        }
    }
}

/// Verifies `signed` with the key in `spki` using an algorithm from `algs`
/// whose identifiers match both the signature algorithm and the key
/// ([`AlgorithmIdentifier::matches_signature`],
/// [`AlgorithmIdentifier::matches_public_key`]: byte for byte, or by the
/// canonical form of `id-RSASSA-PSS` parameters).
///
/// [`AlgorithmIdentifier::matches_signature`]: crate::AlgorithmIdentifier::matches_signature
/// [`AlgorithmIdentifier::matches_public_key`]: crate::AlgorithmIdentifier::matches_public_key
pub(crate) fn verify_signed_data(
    algs: &[&dyn SignatureVerificationAlgorithm],
    spki: &Spki<'_>,
    signed: &SignedData<'_>,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.consume_signature()?;
    let mut key_mismatch = false;
    for alg in algs
        .iter()
        .filter(|alg| alg.signature_alg_id().matches_signature(signed.algorithm))
    {
        if !alg.public_key_alg_id().matches_public_key(spki.algorithm) {
            key_mismatch = true;
            continue;
        }
        return alg
            .verify_signature(spki.key, signed.data, signed.signature)
            .map_err(|_| Error::InvalidSignatureForPublicKey);
    }
    Err(if key_mismatch {
        Error::UnsupportedSignatureAlgorithmForPublicKey
    } else {
        Error::UnsupportedSignatureAlgorithm
    })
}

/// Verifies a detached signature (e.g. a TLS `CertificateVerify`) with a
/// caller-chosen algorithm, which must match the key type in `spki`
/// ([`AlgorithmIdentifier::matches_public_key`]).
///
/// [`AlgorithmIdentifier::matches_public_key`]: crate::AlgorithmIdentifier::matches_public_key
pub(crate) fn verify_signature(
    alg: &dyn SignatureVerificationAlgorithm,
    spki: &Spki<'_>,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if !alg.public_key_alg_id().matches_public_key(spki.algorithm) {
        return Err(Error::UnsupportedSignatureAlgorithmForPublicKey);
    }
    alg.verify_signature(spki.key, msg, signature)
        .map_err(|_| Error::InvalidSignatureForPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_SPKI: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xfe, 0x5a, 0x1e,
        0x36, 0x6c, 0x17, 0x27, 0x5b, 0xf1, 0x58, 0x1e, 0x3a, 0x0e, 0xe6, 0x56, 0x29, 0x8d, 0x9e,
        0x1b, 0x3f, 0xd3, 0x3f, 0x96, 0x46, 0xef, 0xbf, 0x04, 0x6b, 0xc7, 0x3d, 0x47, 0x5c,
    ];

    #[test]
    fn spki_forms() {
        let full = Spki::from_der_or_contents(ED25519_SPKI).unwrap();
        let contents = Spki::from_der_or_contents(&ED25519_SPKI[2..]).unwrap();
        assert_eq!(full.algorithm, contents.algorithm);
        assert_eq!(full.key, contents.key);
        assert_eq!(full.key.len(), 32);
        assert_eq!(full.algorithm, crate::alg_id::ED25519.as_bytes());
        assert!(Spki::from_der_or_contents(&ED25519_SPKI[..20]).is_err());
        // Unused bits in the key BIT STRING are rejected.
        let mut bad = ED25519_SPKI.to_vec();
        bad[11] = 1;
        assert_eq!(Spki::from_der_or_contents(&bad), Err(Error::BadDer));
    }
}
