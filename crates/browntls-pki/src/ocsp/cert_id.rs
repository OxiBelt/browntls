//! `CertID` (RFC 6960 section 4.1.1) and the `OCSPRequest` built from it.

use alloc::vec::Vec;
use core::fmt;

use super::{CertIdHash, CertIdHashers, HashValue, MAX_NONCE_LEN, OcspError, oid, push_tlv, tlv};
use crate::cert::Cert;
use crate::der::{self, HexDebug, OidDebug, Reader, tag};
use crate::error::Error;
use crate::signed_data::Spki;

/// The identifier of a certificate in OCSP requests and responses: hashes
/// of the issuer's name and key, and the serial number.
///
/// Owned and hashable, so it can key a response cache.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CertId {
    hash: CertIdHash,
    issuer_name_hash: HashValue,
    issuer_key_hash: HashValue,
    serial: Vec<u8>,
}

impl CertId {
    /// Computes the identifier of `cert`, issued by the holder of
    /// `issuer_spki` (a complete `SubjectPublicKeyInfo` or its contents,
    /// as [`SignedData::verify_signature`](crate::SignedData::verify_signature)
    /// takes it).
    ///
    /// The name hash covers the certificate's own `issuer` field; nothing
    /// checks that `issuer_spki` belongs to that issuer.
    ///
    /// # Errors
    ///
    /// [`OcspError::DigestUnavailable`] without the digest function for
    /// `hash`; [`OcspError::BadIssuerKey`] for a malformed `issuer_spki`.
    pub fn new(
        hash: CertIdHash,
        hashers: &CertIdHashers,
        cert: &Cert<'_>,
        issuer_spki: &[u8],
    ) -> Result<Self, OcspError> {
        let spki = Spki::from_der_or_contents(issuer_spki).map_err(OcspError::BadIssuerKey)?;
        Self::compute(hash, hashers, cert, spki.key)
    }

    /// As [`Self::new`] with the issuer's `subjectPublicKey` octets.
    pub(crate) fn compute(
        hash: CertIdHash,
        hashers: &CertIdHashers,
        cert: &Cert<'_>,
        issuer_key: &[u8],
    ) -> Result<Self, OcspError> {
        // The hash covers the DER encoding of the issuer `Name`, including
        // its tag and length.
        let issuer_name_hash = hashers.digest(hash, &tlv(tag::SEQUENCE, cert.issuer))?;
        let issuer_key_hash = hashers.digest(hash, issuer_key)?;
        Ok(Self {
            hash,
            issuer_name_hash,
            issuer_key_hash,
            serial: cert.serial.to_vec(),
        })
    }

    /// Builds an identifier from stored parts. `serial` is the
    /// `serialNumber` contents as [`Cert::serial`] returns them.
    ///
    /// # Errors
    ///
    /// [`OcspError::InvalidCertId`] if a hash has the wrong length for
    /// `hash`, or `serial` is not a minimal `INTEGER` of at most 255 octets.
    pub fn from_parts(
        hash: CertIdHash,
        issuer_name_hash: &[u8],
        issuer_key_hash: &[u8],
        serial: &[u8],
    ) -> Result<Self, OcspError> {
        if issuer_name_hash.len() != hash.output_len()
            || issuer_key_hash.len() != hash.output_len()
            || serial.len() > 255
            || der::check_integer(serial).is_err()
        {
            return Err(OcspError::InvalidCertId);
        }
        Ok(Self {
            hash,
            issuer_name_hash: HashValue::new(issuer_name_hash),
            issuer_key_hash: HashValue::new(issuer_key_hash),
            serial: serial.to_vec(),
        })
    }

    /// The hash algorithm.
    #[must_use]
    pub fn hash_algorithm(&self) -> CertIdHash {
        self.hash
    }

    /// The hash of the issuer's distinguished name.
    #[must_use]
    pub fn issuer_name_hash(&self) -> &[u8] {
        self.issuer_name_hash.as_slice()
    }

    /// The hash of the issuer's public key (the `subjectPublicKey` bits).
    #[must_use]
    pub fn issuer_key_hash(&self) -> &[u8] {
        self.issuer_key_hash.as_slice()
    }

    /// The `serialNumber` contents.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// Whether a response's `CertID` names the same certificate: the same
    /// hash algorithm, hashes and serial number.
    #[must_use]
    pub fn matches(&self, other: &ResponseCertId<'_>) -> bool {
        other.hash == Some(self.hash)
            && other.issuer_name_hash == self.issuer_name_hash()
            && other.issuer_key_hash == self.issuer_key_hash()
            && other.serial == self.serial
    }

    /// The DER encoding of the `CertID`.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        // AlgorithmIdentifier with NULL parameters, as deployed requesters
        // and responders encode both algorithms.
        let mut algorithm = tlv(tag::OID, self.hash.oid());
        push_tlv(&mut algorithm, tag::NULL, &[]);
        let mut contents = tlv(tag::SEQUENCE, &algorithm);
        push_tlv(&mut contents, tag::OCTET_STRING, self.issuer_name_hash());
        push_tlv(&mut contents, tag::OCTET_STRING, self.issuer_key_hash());
        push_tlv(&mut contents, tag::INTEGER, &self.serial);
        tlv(tag::SEQUENCE, &contents)
    }
}

impl fmt::Debug for CertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertId")
            .field("hash", &self.hash)
            .field("issuer_name_hash", &self.issuer_name_hash)
            .field("issuer_key_hash", &self.issuer_key_hash)
            .field("serial", &HexDebug(&self.serial))
            .finish()
    }
}

/// Encodes an unsigned `OCSPRequest` for one certificate (RFC 5019
/// section 2.1.1), to send by HTTP `POST` as `application/ocsp-request` or
/// base64 encoded in a `GET` path (RFC 6960 appendix A).
///
/// `nonce` adds the nonce extension (RFC 8954) with 1 to
/// [`MAX_NONCE_LEN`] octets, which must come from a cryptographically
/// secure generator. Responders following RFC 5019 ignore it and serve
/// cacheable responses; leave it out to allow that.
///
/// # Errors
///
/// [`OcspError::InvalidNonce`] for an empty or over-long nonce.
pub fn encode_request(cert_id: &CertId, nonce: Option<&[u8]>) -> Result<Vec<u8>, OcspError> {
    // Request ::= SEQUENCE { reqCert CertID }, in a one-element list.
    let request = tlv(tag::SEQUENCE, &cert_id.to_der());
    let mut tbs = tlv(tag::SEQUENCE, &request);
    if let Some(nonce) = nonce {
        if nonce.is_empty() || nonce.len() > MAX_NONCE_LEN {
            return Err(OcspError::InvalidNonce);
        }
        // Extension { extnID, extnValue OCTET STRING { Nonce OCTET STRING } }.
        let mut extension = tlv(tag::OID, oid::NONCE);
        push_tlv(
            &mut extension,
            tag::OCTET_STRING,
            &tlv(tag::OCTET_STRING, nonce),
        );
        let extensions = tlv(tag::SEQUENCE, &tlv(tag::SEQUENCE, &extension));
        // requestExtensions [2] EXPLICIT Extensions.
        push_tlv(&mut tbs, tag::context_constructed(2), &extensions);
    }
    Ok(tlv(tag::SEQUENCE, &tlv(tag::SEQUENCE, &tbs)))
}

/// The `CertID` of a single response, borrowed from the response.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResponseCertId<'a> {
    pub(crate) hash_oid: &'a [u8],
    pub(crate) hash: Option<CertIdHash>,
    pub(crate) issuer_name_hash: &'a [u8],
    pub(crate) issuer_key_hash: &'a [u8],
    pub(crate) serial: &'a [u8],
}

impl<'a> ResponseCertId<'a> {
    /// The hash algorithm, or `None` for one this crate does not know
    /// (see [`Self::hash_algorithm_oid`]).
    #[must_use]
    pub fn hash_algorithm(&self) -> Option<CertIdHash> {
        self.hash
    }

    /// The hash algorithm's `OBJECT IDENTIFIER` contents.
    #[must_use]
    pub fn hash_algorithm_oid(&self) -> &'a [u8] {
        self.hash_oid
    }

    /// The hash of the issuer's distinguished name. Its length matches a
    /// known algorithm.
    #[must_use]
    pub fn issuer_name_hash(&self) -> &'a [u8] {
        self.issuer_name_hash
    }

    /// The hash of the issuer's public key. Its length matches a known
    /// algorithm.
    #[must_use]
    pub fn issuer_key_hash(&self) -> &'a [u8] {
        self.issuer_key_hash
    }

    /// The `serialNumber` contents (a minimal two's-complement `INTEGER`).
    #[must_use]
    pub fn serial(&self) -> &'a [u8] {
        self.serial
    }

    /// Reads a `CertID`. The parameters of a known hash algorithm must be
    /// absent or `NULL` and its hashes must have the algorithm's length.
    pub(crate) fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
        reader.nested(tag::SEQUENCE, |id| {
            let (hash_oid, parameters) = id.nested(tag::SEQUENCE, |alg| {
                let oid = alg.oid()?;
                let parameters = if alg.at_end() { None } else { Some(alg.tlv()?) };
                Ok((oid, parameters))
            })?;
            let issuer_name_hash = id.expect(tag::OCTET_STRING)?;
            let issuer_key_hash = id.expect(tag::OCTET_STRING)?;
            let serial = id.integer()?;
            let hash = CertIdHash::from_oid(hash_oid);
            if let Some(hash) = hash {
                let null_or_absent =
                    parameters.is_none_or(|p| p.tag == tag::NULL && p.value.is_empty());
                if !null_or_absent
                    || issuer_name_hash.len() != hash.output_len()
                    || issuer_key_hash.len() != hash.output_len()
                {
                    return Err(Error::BadDer);
                }
            }
            Ok(Self {
                hash_oid,
                hash,
                issuer_name_hash,
                issuer_key_hash,
                serial,
            })
        })
    }
}

impl fmt::Debug for ResponseCertId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseCertId")
            .field("hash_algorithm", &OidDebug(self.hash_oid))
            .field("issuer_name_hash", &HexDebug(self.issuer_name_hash))
            .field("issuer_key_hash", &HexDebug(self.issuer_key_hash))
            .field("serial", &HexDebug(self.serial))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> CertId {
        CertId::from_parts(CertIdHash::Sha1, &[0x11; 20], &[0x22; 20], &[0x01, 0x02]).unwrap()
    }

    #[test]
    fn encodes_cert_id_and_request() {
        let mut expected = alloc::vec![
            0x30, 0x3b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ];
        expected.extend_from_slice(&[0x11; 20]);
        expected.extend_from_slice(&[0x04, 0x14]);
        expected.extend_from_slice(&[0x22; 20]);
        expected.extend_from_slice(&[0x02, 0x02, 0x01, 0x02]);
        let id = id();
        assert_eq!(id.to_der(), expected);

        // OCSPRequest { TBSRequest { requestList { Request { CertID } } } }.
        let mut request = alloc::vec![0x30, 0x43, 0x30, 0x41, 0x30, 0x3f, 0x30, 0x3d];
        request.extend_from_slice(&expected);
        assert_eq!(encode_request(&id, None).unwrap(), request);

        let with_nonce = encode_request(&id, Some(&[0xaa, 0xbb])).unwrap();
        let nonce_extension = [
            0xa2, 0x15, 0x30, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
            0x30, 0x01, 0x02, 0x04, 0x04, 0x04, 0x02, 0xaa, 0xbb,
        ];
        assert!(with_nonce.ends_with(&nonce_extension));
        assert_eq!(with_nonce.len(), request.len() + nonce_extension.len());

        assert_eq!(encode_request(&id, Some(&[])), Err(OcspError::InvalidNonce));
        assert_eq!(
            encode_request(&id, Some(&[0; MAX_NONCE_LEN + 1])),
            Err(OcspError::InvalidNonce)
        );
        assert!(encode_request(&id, Some(&[0; MAX_NONCE_LEN])).is_ok());
    }

    #[test]
    fn reads_back_and_matches() {
        let id = id();
        let der = id.to_der();
        let parsed = der::read_all(&der, ResponseCertId::read).unwrap();
        assert_eq!(parsed.hash_algorithm(), Some(CertIdHash::Sha1));
        assert_eq!(parsed.serial(), &[0x01, 0x02]);
        assert!(id.matches(&parsed));
        let other = CertId::from_parts(CertIdHash::Sha1, &[0x11; 20], &[0x22; 20], &[0x03]);
        assert!(!other.unwrap().matches(&parsed));
        let sha256 = CertId::from_parts(CertIdHash::Sha256, &[0x11; 32], &[0x22; 32], &[1, 2]);
        assert!(!sha256.unwrap().matches(&parsed));
    }

    #[test]
    fn rejects_bad_parts() {
        for (name, key, serial) in [
            (&[0u8; 19][..], &[0u8; 20][..], &[1u8][..]),
            (&[0; 20], &[0; 32], &[1]),
            (&[0; 20], &[0; 20], &[]),
            (&[0; 20], &[0; 20], &[0x00, 0x01]),
        ] {
            assert_eq!(
                CertId::from_parts(CertIdHash::Sha1, name, key, serial),
                Err(OcspError::InvalidCertId)
            );
        }
    }

    #[test]
    fn response_cert_id_forms() {
        // Absent parameters are accepted for a known algorithm.
        let mut absent = alloc::vec![
            0x30, 0x39, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
        ];
        absent.extend_from_slice(&[0x04, 0x14]);
        absent.extend_from_slice(&[0x11; 20]);
        absent.extend_from_slice(&[0x04, 0x14]);
        absent.extend_from_slice(&[0x22; 20]);
        absent.extend_from_slice(&[0x02, 0x02, 0x01, 0x02]);
        let parsed = der::read_all(&absent, ResponseCertId::read).unwrap();
        assert!(id().matches(&parsed));

        // A hash of the wrong length for a known algorithm.
        let mut short = id().to_der();
        short[1] -= 1;
        short[14] -= 1;
        short.remove(15);
        assert_eq!(
            der::read_all(&short, ResponseCertId::read),
            Err(Error::BadDer)
        );

        // An unknown algorithm is kept, and never matches.
        let mut unknown = id().to_der();
        unknown[10] = 0x1b;
        let parsed = der::read_all(&unknown, ResponseCertId::read).unwrap();
        assert_eq!(parsed.hash_algorithm(), None);
        assert_eq!(parsed.hash_algorithm_oid(), &[0x2b, 0x0e, 0x03, 0x02, 0x1b]);
        assert!(!id().matches(&parsed));

        // A non-minimal serial number.
        let mut serial = id().to_der();
        let len = serial.len();
        serial[len - 2] = 0x00;
        serial[len - 1] = 0x01;
        assert_eq!(
            der::read_all(&serial, ResponseCertId::read),
            Err(Error::BadDer)
        );
    }
}
