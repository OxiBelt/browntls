//! Signed structures (`tbs || signatureAlgorithm || signature`) and
//! signature verification through [`SignatureVerificationAlgorithm`].

use core::fmt;

use crate::der::{self, CRL_LEN_LIMIT, HexDebug, Reader, tag};
use crate::error::Error;
use crate::path::Budget;
use crate::types::SignatureVerificationAlgorithm;

/// Signed data: a message, the `AlgorithmIdentifier` of its signature, and
/// the signature. Verify it with [`Self::verify_signature`].
///
/// [`Self::from_der`] reads the X.509 signed structure shared by
/// certificates, CRLs and PKCS #10 certification requests:
///
/// ```text
/// SEQUENCE { tbs SEQUENCE, signatureAlgorithm AlgorithmIdentifier,
///            signature BIT STRING }
/// ```
///
/// [`Self::from_parts`] takes the three parts of any other signature. Only
/// the outer structure is read: the `tbs` contents are not interpreted (in
/// particular, a certificate's `tbsCertificate.signature` is not compared
/// with `signatureAlgorithm`; [`Cert`](crate::Cert) parsing does that), and
/// verification checks the signature only, not validity periods, names or
/// trust.
#[derive(Clone, Copy)]
pub struct SignedData<'a> {
    /// The complete DER encoding of the signed structure (`tbsCertificate`
    /// or `tbsCertList`), including its tag and length.
    pub(crate) data: &'a [u8],
    /// Contents of the `signatureAlgorithm` `AlgorithmIdentifier`.
    pub(crate) algorithm: &'a [u8],
    /// The signature octets.
    pub(crate) signature: &'a [u8],
}

impl<'a> SignedData<'a> {
    /// Reads the signed structure of a DER certificate, CRL or certification
    /// request (see above). The `tbs` element may be up to 4 GiB (as a CRL),
    /// the algorithm and signature up to 65535 octets; the signature `BIT
    /// STRING` must have no unused bits.
    ///
    /// # Errors
    ///
    /// [`Error::BadDer`] for malformed or non-DER input, a `tbs` that is not
    /// a `SEQUENCE` or a signature with unused bits; [`Error::TrailingData`]
    /// for bytes after the structure or after its three elements.
    pub fn from_der(der: &'a [u8]) -> Result<Self, Error> {
        der::read_all(der, |r| {
            let outer = r.expect_limited(tag::SEQUENCE, CRL_LEN_LIMIT)?;
            der::read_all(outer, |signed| Self::read(signed, CRL_LEN_LIMIT))
        })
        .map(|(_, signed)| signed)
    }

    /// Wraps a message, the contents of its signature algorithm's
    /// `AlgorithmIdentifier` (without the outer `SEQUENCE` tag and length,
    /// as the [`alg_id`](crate::alg_id) constants hold them) and the
    /// signature, for example from a protocol that signs with X.509
    /// algorithm identifiers. Nothing is checked until verification.
    #[must_use]
    pub fn from_parts(message: &'a [u8], algorithm: &'a [u8], signature: &'a [u8]) -> Self {
        Self {
            data: message,
            algorithm,
            signature,
        }
    }

    /// The signed message: the complete DER encoding of the `tbs` element
    /// (with its tag and length) for [`Self::from_der`].
    #[must_use]
    pub fn message(&self) -> &'a [u8] {
        self.data
    }

    /// The contents of the signature `AlgorithmIdentifier` (without the
    /// outer `SEQUENCE` tag and length).
    #[must_use]
    pub fn algorithm(&self) -> &'a [u8] {
        self.algorithm
    }

    /// The signature octets (the `BIT STRING` contents without the
    /// unused-bit count for [`Self::from_der`]).
    #[must_use]
    pub fn signature(&self) -> &'a [u8] {
        self.signature
    }

    /// Verifies the signature with the key in `spki`, given either as a
    /// complete `SubjectPublicKeyInfo` `SEQUENCE` (such as a
    /// [`SubjectPublicKeyInfoDer`](crate::SubjectPublicKeyInfoDer), which
    /// dereferences to `[u8]`) or as its contents (such as
    /// [`TrustAnchor::subject_public_key_info`](crate::TrustAnchor::subject_public_key_info)),
    /// like path validation and [`CertRevocationList::verify_signature`].
    /// The two forms cannot be confused: the complete form is one element,
    /// the contents are two (an `AlgorithmIdentifier` and a `BIT STRING`).
    /// The signature is checked by the first algorithm of
    /// `supported_sig_algs` whose signature and public key
    /// `AlgorithmIdentifier`s both match
    /// ([`AlgorithmIdentifier::matches_signature`],
    /// [`AlgorithmIdentifier::matches_public_key`]: byte for byte, or by the
    /// canonical form of `id-RSASSA-PSS` parameters), exactly as path
    /// validation verifies certificate signatures.
    ///
    /// The cryptographic check, including its timing, is the chosen
    /// algorithm's; the work here is linear in the input lengths.
    ///
    /// # Errors
    ///
    /// * [`Error::BadDer`] or [`Error::TrailingData`] if `spki` is neither
    ///   form;
    /// * [`Error::UnsupportedSignatureAlgorithm`] if no algorithm matches
    ///   the signature algorithm;
    /// * [`Error::UnsupportedSignatureAlgorithmForPublicKey`] if some do,
    ///   but none for the key's type;
    /// * [`Error::InvalidSignatureForPublicKey`] if the matching algorithm
    ///   rejects the signature.
    ///
    /// [`AlgorithmIdentifier::matches_signature`]: crate::AlgorithmIdentifier::matches_signature
    /// [`AlgorithmIdentifier::matches_public_key`]: crate::AlgorithmIdentifier::matches_public_key
    /// [`CertRevocationList::verify_signature`]: crate::CertRevocationList::verify_signature
    pub fn verify_signature(
        &self,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        spki: &[u8],
    ) -> Result<(), Error> {
        let spki = Spki::from_der_or_contents(spki)?;
        verify_signed_data(supported_sig_algs, &spki, self, &mut Budget::default())
    }

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

impl fmt::Debug for SignedData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedData")
            .field("message_len", &self.data.len())
            .field("algorithm", &HexDebug(self.algorithm))
            .field("signature", &HexDebug(self.signature))
            .finish()
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
        der::read_all(contents, Self::from_reader)
    }

    fn from_reader(r: &mut Reader<'a>) -> Result<Self, Error> {
        let algorithm = r.expect(tag::SEQUENCE)?;
        let key = r.bit_string_no_unused_bits()?;
        Ok(Spki { algorithm, key })
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

    pub(crate) fn equivalent(self, other: Self) -> bool {
        self == other
            || (self.key == other.key
                && crate::rsassa_pss::equivalent_key_restrictions(self.algorithm, other.algorithm)
                && der::read_all(self.key, |r| {
                    r.nested(tag::SEQUENCE, |r| {
                        let modulus = r.nonnegative_integer()?;
                        let exponent = r.nonnegative_integer()?;
                        if modulus == [0] || exponent == [0] {
                            return Err(Error::BadDer);
                        }
                        Ok(())
                    })
                })
                .is_ok())
    }
}

/// Compares two complete DER-encoded `SubjectPublicKeyInfo` values.
///
/// Distinct encodings agree only for supported RSASSA-PSS parameters
/// that impose the same restrictions on the same DER-encoded RSA key.
/// The comparison does not establish that a key or certificate is trusted.
///
/// # Errors
///
/// Returns a DER error if either input lacks the enclosing SPKI structure.
pub fn subject_public_keys_match(left: &[u8], right: &[u8]) -> Result<bool, Error> {
    let parse = |spki| der::read_all(spki, |r| r.nested(tag::SEQUENCE, Spki::from_reader));
    Ok(parse(left)?.equivalent(parse(right)?))
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
    // Canonicalise each input once, not once per algorithm: a crafted
    // identifier can be long.
    let signature_alg = crate::alg_id::canonical_signature_alg_id(signed.algorithm);
    let key_alg = crate::alg_id::canonical_public_key_alg_id(spki.algorithm);
    let mut key_mismatch = false;
    for alg in algs.iter().filter(|alg| {
        alg.signature_alg_id()
            .matches_given(signed.algorithm, signature_alg)
    }) {
        if !alg
            .public_key_alg_id()
            .matches_given(spki.algorithm, key_alg)
        {
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
