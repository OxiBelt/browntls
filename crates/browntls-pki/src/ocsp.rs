//! Online Certificate Status Protocol (RFC 6960) in its lightweight profile
//! (RFC 5019): request encoding, strict bounded response parsing and
//! response validation.
//!
//! * [`CertId`] identifies a certificate to a responder and
//!   [`encode_request`] encodes the single-certificate, unsigned
//!   `OCSPRequest` of RFC 5019 section 2.1.1.
//! * [`OcspResponse`] parses an `OCSPResponse`; nothing is trusted until
//!   [`OcspResponse::verify`] (or [`verify_response`]) authenticates it for
//!   one certificate under an [`OcspPolicy`].
//! * [`must_staple`], [`ocsp_responder_uris`], [`ca_issuer_uris`] and
//!   [`has_ocsp_nocheck`] read the related certificate extensions.
//!
//! # Trust boundary
//!
//! Responses, the certificates they carry and stapled data are untrusted.
//! Verification authenticates a response with the key of the certificate's
//! issuer, either directly or through a responder certificate that the
//! issuer itself signed and that asserts `id-kp-OCSPSigning` explicitly
//! (RFC 6960 section 4.2.2.2). The caller vouches for the [`OcspIssuer`]:
//! take it from a validated path. This module performs no network access,
//! keeps no state and contains no cryptography: digests come from
//! [`CertIdHashers`] and signatures are checked through
//! [`SignatureVerificationAlgorithm`](crate::SignatureVerificationAlgorithm).
//!
//! # Outcomes
//!
//! An authenticated response yields [`VerifiedOcspStatus`] whatever its
//! [`CertStatus`]: `Unknown` and `Revoked` are answers, not errors. A
//! responder that declined to answer is reported as
//! [`OcspError::ResponderUnsuccessful`] (never authenticated), and every
//! other [`OcspError`] describes a response that is malformed, not
//! authentic, not about the certificate or not fresh.
//!
//! # Bounds
//!
//! A response is at most [`MAX_RESPONSE_LEN`] octets with at most
//! [`MAX_RESPONSE_CERTS`] certificates; parsing is linear in its length.
//! Verification performs at most two signature checks per carried
//! certificate plus one per applicable CRL, under the signature budget of
//! path validation.

use core::fmt;

use crate::UnixTime;
use crate::error::Error;

mod cert_ext;
mod cert_id;
mod response;
mod verify;

pub use cert_ext::{
    AccessUris, ca_issuer_uris, has_ocsp_nocheck, must_staple, ocsp_responder_uris,
};
pub use cert_id::{CertId, ResponseCertId, encode_request};
pub use response::{
    BasicResponse, CertStatus, OcspResponse, ResponderId, ResponseCertificates, ResponseStatus,
    SingleResponse, SingleResponses,
};
pub use verify::{OcspIssuer, OcspPolicy, OcspSigner, VerifiedOcspStatus, verify_response};

/// Largest accepted `OCSPResponse` encoding, in octets: an outer `SEQUENCE`
/// with 65535 octets of contents.
pub const MAX_RESPONSE_LEN: usize = 65_539;

/// Largest number of certificates accepted in a response's `certs` field.
pub const MAX_RESPONSE_CERTS: usize = 8;

/// Longest nonce [`encode_request`] sends (RFC 8954 section 2.1).
pub const MAX_NONCE_LEN: usize = 32;

/// Encoded `OBJECT IDENTIFIER` contents used by OCSP.
pub mod oid {
    /// `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1).
    pub const BASIC_RESPONSE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
    /// `id-pkix-ocsp-nonce` (1.3.6.1.5.5.7.48.1.2).
    pub const NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
    /// `id-pkix-ocsp-nocheck` (1.3.6.1.5.5.7.48.1.5).
    pub const NOCHECK: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05];
    /// `id-ad-ocsp` (1.3.6.1.5.5.7.48.1).
    pub const AD_OCSP: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    /// `id-ad-caIssuers` (1.3.6.1.5.5.7.48.2).
    pub const AD_CA_ISSUERS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
    /// `id-pe-authorityInfoAccess` (1.3.6.1.5.5.7.1.1).
    pub const AUTHORITY_INFO_ACCESS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
    /// `id-pe-tlsfeature` (1.3.6.1.5.5.7.1.24, RFC 7633).
    pub const TLS_FEATURE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];
    /// `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9).
    pub const KP_OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
    /// The signed certificate timestamp list of an OCSP single response
    /// (1.3.6.1.4.1.11129.2.4.5, RFC 6962 section 3.3).
    pub const SCT_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x05];
    /// `id-sha1` (1.3.14.3.2.26).
    pub const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
    /// `id-sha256` (2.16.840.1.101.3.4.2.1).
    pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
}

/// A `CertID` hash algorithm.
///
/// RFC 5019 requires SHA-1 here, where it only names an issuer and is not
/// relied on for collision resistance; RFC 6960 also allows SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertIdHash {
    /// SHA-1 (20 octets).
    Sha1,
    /// SHA-256 (32 octets).
    Sha256,
}

impl CertIdHash {
    /// The digest length in octets.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// The algorithm's `OBJECT IDENTIFIER` contents.
    #[must_use]
    pub const fn oid(self) -> &'static [u8] {
        match self {
            Self::Sha1 => oid::SHA1,
            Self::Sha256 => oid::SHA256,
        }
    }

    pub(crate) fn from_oid(oid: &[u8]) -> Option<Self> {
        if oid == oid::SHA1 {
            Some(Self::Sha1)
        } else if oid == oid::SHA256 {
            Some(Self::Sha256)
        } else {
            None
        }
    }
}

/// A one-shot SHA-1 function.
pub type Sha1Fn = fn(&[u8]) -> [u8; 20];

/// A one-shot SHA-256 function.
pub type Sha256Fn = fn(&[u8]) -> [u8; 32];

/// One-shot digest functions supplied by a cryptography provider.
///
/// SHA-1 is needed for `CertID`s that use it (all RFC 5019 responders) and
/// to recognise a responder identified by key hash (`byKey`, always SHA-1).
/// A missing function makes the responses that need it fail with
/// [`OcspError::DigestUnavailable`].
#[derive(Clone, Copy, Debug, Default)]
pub struct CertIdHashers {
    /// SHA-1 of the input.
    pub sha1: Option<Sha1Fn>,
    /// SHA-256 of the input.
    pub sha256: Option<Sha256Fn>,
}

impl CertIdHashers {
    pub(crate) fn digest(&self, hash: CertIdHash, data: &[u8]) -> Result<HashValue, OcspError> {
        let unavailable = OcspError::DigestUnavailable(hash);
        match hash {
            CertIdHash::Sha1 => self
                .sha1
                .map(|f| HashValue::new(&f(data)))
                .ok_or(unavailable),
            CertIdHash::Sha256 => self
                .sha256
                .map(|f| HashValue::new(&f(data)))
                .ok_or(unavailable),
        }
    }
}

/// A digest of at most 32 octets; unused octets are zero.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct HashValue {
    bytes: [u8; 32],
    len: usize,
}

impl HashValue {
    /// Copies `digest`, truncating anything beyond 32 octets (callers pass
    /// 20 or 32).
    pub(crate) fn new(digest: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let len = digest.len().min(bytes.len());
        for (to, from) in bytes.iter_mut().zip(digest) {
            *to = *from;
        }
        Self { bytes, len }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

impl fmt::Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::der::HexDebug(self.as_slice()).fmt(f)
    }
}

/// Why an OCSP request could not be built or a response not be used.
///
/// No variant is produced for an authenticated response: `Unknown` and
/// `Revoked` statuses are returned in [`VerifiedOcspStatus`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OcspError {
    /// The response is not strict DER of the expected structure, carries
    /// an unknown critical extension or an invalid extension value.
    Malformed(Error),
    /// The response is longer than [`MAX_RESPONSE_LEN`].
    ResponseTooLarge,
    /// The response carries more than [`MAX_RESPONSE_CERTS`] certificates.
    TooManyCertificates,
    /// The response type is not `id-pkix-ocsp-basic`.
    UnsupportedResponseType,
    /// The `ResponseData` version is not v1.
    UnsupportedVersion,
    /// The responder answered with an error status and no certificate
    /// status. Such responses are unsigned: this says nothing about the
    /// certificate and is not authenticated.
    ResponderUnsuccessful(ResponseStatus),
    /// A digest function needed for this request or response is missing
    /// from [`CertIdHashers`].
    DigestUnavailable(CertIdHash),
    /// The issuer's `SubjectPublicKeyInfo` given by the caller is malformed.
    BadIssuerKey(Error),
    /// A `CertID` field given by the caller is malformed.
    InvalidCertId,
    /// The nonce is empty or longer than [`MAX_NONCE_LEN`].
    InvalidNonce,
    /// The certificate was not issued by the given issuer (names differ).
    IssuerMismatch,
    /// No single response is about the certificate.
    NoMatchingResponse,
    /// More than one single response is, or may be, about the certificate:
    /// two entries name it (under the same or different hash algorithms),
    /// or one does beside an entry with its serial number under a hash
    /// algorithm this crate does not know. Rejected whatever the statuses,
    /// so that the outcome cannot depend on the order of the entries.
    AmbiguousResponse,
    /// The responder identifier names neither the issuer nor a carried
    /// certificate.
    UnknownResponder,
    /// The response signature does not verify with the responder's key, or
    /// its algorithm is unsupported (the inner error tells which).
    BadSignature(Error),
    /// The responder certificate is malformed, not signed by the issuer or
    /// outside its validity period (the inner error tells which).
    DelegateInvalid(Error),
    /// The responder certificate was not issued by the certificate's
    /// issuer.
    DelegateNotIssuedByCa,
    /// The responder certificate lacks an explicit `id-kp-OCSPSigning`
    /// extended key usage.
    DelegateNotOcspSigner,
    /// The responder certificate's key usage forbids signatures.
    DelegateKeyUsage,
    /// The responder certificate is listed in a CRL of the issuer.
    DelegateRevoked,
    /// The responder certificate has no `id-pkix-ocsp-nocheck` extension
    /// and no current CRL of the issuer covers it.
    DelegateRevocationUnknown,
    /// A CRL applicable to the responder certificate could not be used
    /// (the inner error tells why).
    DelegateCrl(Error),
    /// `thisUpdate` or `producedAt` is in the future.
    NotYetValid {
        /// Validation time.
        time: UnixTime,
        /// The later of the response's `thisUpdate` and `producedAt`.
        not_before: UnixTime,
    },
    /// The response is stale: `nextUpdate`, the policy's age limit or the
    /// responder certificate's `notAfter` has passed.
    Expired {
        /// Validation time.
        time: UnixTime,
        /// When the status stopped being usable.
        expires: UnixTime,
    },
    /// `nextUpdate` is absent and the policy requires it.
    MissingNextUpdate,
    /// `nextUpdate` precedes `thisUpdate`.
    InvalidUpdateTimes,
    /// The response nonce differs from the one sent.
    NonceMismatch,
    /// The response has no nonce and the policy requires one.
    NonceMissing,
}

impl OcspError {
    /// Whether the response was authentic and about the certificate but
    /// outside its freshness window ([`Self::NotYetValid`],
    /// [`Self::Expired`]).
    #[must_use]
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::NotYetValid { .. } | Self::Expired { .. })
    }
}

impl fmt::Display for OcspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for OcspError {}

/// Appends the DER element `tag`, length, `contents` to `out`.
pub(crate) fn push_tlv(out: &mut alloc::vec::Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    let len = contents.len();
    match u8::try_from(len) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let bytes = len.to_be_bytes();
            let skip = bytes.iter().take_while(|b| **b == 0).count();
            let significant = bytes.get(skip..).unwrap_or(&[]);
            // At most `size_of::<usize>()` octets, so the count fits.
            out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0x7f));
            out.extend_from_slice(significant);
        }
    }
    out.extend_from_slice(contents);
}

/// The DER element `tag`, length, `contents`.
pub(crate) fn tlv(tag: u8, contents: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(contents.len() + 6);
    push_tlv(&mut out, tag, contents);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_lengths() {
        assert_eq!(tlv(0x04, &[1, 2]), [0x04, 0x02, 1, 2]);
        assert_eq!(tlv(0x04, &[0; 0x7f]).get(..2), Some(&[0x04, 0x7f][..]));
        assert_eq!(
            tlv(0x04, &[0; 0x80]).get(..3),
            Some(&[0x04, 0x81, 0x80][..])
        );
        assert_eq!(
            tlv(0x04, &[0; 0x1234]).get(..4),
            Some(&[0x04, 0x82, 0x12, 0x34][..])
        );
        // The reader accepts what the writer produces.
        for len in [0usize, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff] {
            let encoded = tlv(0x04, &alloc::vec![7u8; len]);
            let value = crate::der::read_all(&encoded, |r| r.expect(0x04));
            assert_eq!(value.map(<[u8]>::len), Ok(len));
        }
    }

    #[test]
    fn hash_values() {
        let value = HashValue::new(&[1; 20]);
        assert_eq!(value.as_slice(), &[1; 20]);
        assert_ne!(value, HashValue::new(&[1; 32]));
        let hashers = CertIdHashers::default();
        assert_eq!(
            hashers.digest(CertIdHash::Sha1, b"").err(),
            Some(OcspError::DigestUnavailable(CertIdHash::Sha1))
        );
        assert_eq!(CertIdHash::from_oid(oid::SHA256), Some(CertIdHash::Sha256));
        assert_eq!(CertIdHash::from_oid(oid::NONCE), None);
        assert_eq!(CertIdHash::Sha1.output_len(), 20);
    }
}
