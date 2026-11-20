//! `OCSPResponse` parsing (RFC 6960 section 4.2.1).
//!
//! Parsing is eager: every single response and every extension list is
//! validated by [`OcspResponse::from_der`], so the accessors and iterators
//! cannot fail. Carried certificates are only checked to be `SEQUENCE`s;
//! verification parses the ones it uses.

use core::fmt;

use super::cert_id::ResponseCertId;
use super::{MAX_RESPONSE_CERTS, MAX_RESPONSE_LEN, OcspError, oid};
use crate::asn1_time::read_time;
use crate::crl::RevocationReason;
use crate::der::{self, CERT_LEN_LIMIT, HexDebug, Reader, tag};
use crate::error::Error;
use crate::extensions::{self, UnknownExtensionPolicy, set_once};
use crate::signed_data::SignedData;
use crate::{CertificateDer, UnixTime};

/// `OCSPResponseStatus`: whether the responder produced a certificate
/// status (RFC 6960 section 4.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseStatus {
    /// The response carries certificate statuses.
    Successful,
    /// The request was malformed.
    MalformedRequest,
    /// The responder failed internally.
    InternalError,
    /// The responder is temporarily unable to answer.
    TryLater,
    /// The responder requires signed requests.
    SigRequired,
    /// The responder is not authorized to answer for this certificate, or
    /// the client is not authorized to ask (RFC 5019 section 2.2.3).
    Unauthorized,
}

impl ResponseStatus {
    fn from_enumerated(value: &[u8]) -> Result<Self, Error> {
        match value {
            [0] => Ok(Self::Successful),
            [1] => Ok(Self::MalformedRequest),
            [2] => Ok(Self::InternalError),
            [3] => Ok(Self::TryLater),
            [5] => Ok(Self::SigRequired),
            [6] => Ok(Self::Unauthorized),
            _ => Err(Error::BadDer),
        }
    }
}

/// A parsed, unauthenticated `OCSPResponse` borrowing from its encoding.
///
/// Use [`Self::verify`](OcspResponse::verify) before relying on anything
/// it says.
#[derive(Clone, Copy, Debug)]
pub struct OcspResponse<'a> {
    pub(crate) status: ResponseStatus,
    pub(crate) basic: Option<BasicResponse<'a>>,
}

impl<'a> OcspResponse<'a> {
    /// Parses a DER `OCSPResponse` of at most [`MAX_RESPONSE_LEN`] octets.
    ///
    /// A response whose status is not [`ResponseStatus::Successful`] parses
    /// to a value without a [`BasicResponse`]; any response bytes it
    /// carries are ignored.
    ///
    /// # Errors
    ///
    /// * [`OcspError::ResponseTooLarge`], [`OcspError::TooManyCertificates`]
    ///   for input over the bounds;
    /// * [`OcspError::UnsupportedResponseType`] for a response type other
    ///   than `id-pkix-ocsp-basic`, [`OcspError::UnsupportedVersion`] for a
    ///   version other than v1;
    /// * [`OcspError::Malformed`] otherwise: [`Error::BadDer`],
    ///   [`Error::TrailingData`] or [`Error::BadDerTime`] (times must be
    ///   `GeneralizedTime`) for the encoding, a successful status without
    ///   response bytes, [`Error::UnsupportedCriticalExtension`],
    ///   [`Error::MalformedExtensions`] for a repeated nonce, SCT list,
    ///   Transparency Information or timestamp list extension,
    ///   [`Error::ExtensionValueInvalid`] for an SCT list, Transparency
    ///   Information or timestamp list that is not an `OCTET STRING`.
    pub fn from_der(der: &'a [u8]) -> Result<Self, OcspError> {
        if der.len() > MAX_RESPONSE_LEN {
            return Err(OcspError::ResponseTooLarge);
        }
        let (status, response_bytes) = der::read_all(der, |r| {
            r.nested(tag::SEQUENCE, |response| {
                let status = ResponseStatus::from_enumerated(response.expect(tag::ENUMERATED)?)?;
                let bytes = response.optional(tag::context_constructed(0))?;
                Ok((status, bytes))
            })
        })
        .map_err(OcspError::Malformed)?;
        if status != ResponseStatus::Successful {
            return Ok(Self {
                status,
                basic: None,
            });
        }
        let response_bytes = response_bytes.ok_or(OcspError::Malformed(Error::BadDer))?;
        let (response_type, response) = der::read_all(response_bytes, |r| {
            r.nested(tag::SEQUENCE, |bytes| {
                Ok((bytes.oid()?, bytes.expect(tag::OCTET_STRING)?))
            })
        })
        .map_err(OcspError::Malformed)?;
        if response_type != oid::BASIC_RESPONSE {
            return Err(OcspError::UnsupportedResponseType);
        }
        Ok(Self {
            status,
            basic: Some(BasicResponse::parse(response)?),
        })
    }

    /// The responder's status for the request as a whole.
    #[must_use]
    pub fn status(&self) -> ResponseStatus {
        self.status
    }

    /// The `BasicOCSPResponse`, present exactly when the status is
    /// [`ResponseStatus::Successful`].
    #[must_use]
    pub fn basic(&self) -> Option<&BasicResponse<'a>> {
        self.basic.as_ref()
    }
}

/// A `BasicOCSPResponse`: signed statuses of one or more certificates.
#[derive(Clone, Copy)]
pub struct BasicResponse<'a> {
    pub(crate) signed: SignedData<'a>,
    pub(crate) responder_id: ResponderId<'a>,
    pub(crate) produced_at: UnixTime,
    /// Contents of the validated `SEQUENCE OF SingleResponse`.
    pub(crate) responses: &'a [u8],
    pub(crate) nonce: Option<&'a [u8]>,
    /// Contents of the `SEQUENCE OF Certificate` (empty when absent).
    pub(crate) certs: &'a [u8],
}

impl<'a> BasicResponse<'a> {
    fn parse(der: &'a [u8]) -> Result<Self, OcspError> {
        let ((tbs, signed), certs) = der::read_all(der, |r| {
            r.nested(tag::SEQUENCE, |basic| {
                let signed = SignedData::read(basic, CERT_LEN_LIMIT)?;
                let certs = match basic.optional(tag::context_constructed(0))? {
                    Some(wrapped) => der::read_all(wrapped, |c| c.expect(tag::SEQUENCE))?,
                    None => &[][..],
                };
                Ok((signed, certs))
            })
        })
        .map_err(OcspError::Malformed)?;

        let cert_count = der::read_all(certs, |r| {
            let mut count = 0usize;
            while !r.at_end() {
                r.expect(tag::SEQUENCE)?;
                count += 1;
            }
            Ok(count)
        })
        .map_err(OcspError::Malformed)?;
        if cert_count > MAX_RESPONSE_CERTS {
            return Err(OcspError::TooManyCertificates);
        }

        let (version, responder_id, produced_at, responses, nonce) = der::read_all(tbs, |r| {
            // version [0] EXPLICIT INTEGER DEFAULT v1(0); an encoded default
            // violates DER but is harmless.
            let version = match r.optional(tag::context_constructed(0))? {
                Some(wrapped) => der::read_all(wrapped, |v| v.small_nonnegative_integer())?,
                None => 0,
            };
            let responder_id = ResponderId::read(r)?;
            let produced_at = generalized_time(r)?;
            let responses = r.expect(tag::SEQUENCE)?;
            der::read_all(responses, |singles| {
                while !singles.at_end() {
                    SingleResponse::read(singles)?;
                }
                Ok(())
            })?;
            let mut nonce = None;
            if let Some(wrapped) = r.optional(tag::context_constructed(1))? {
                let list = der::read_all(wrapped, |e| e.expect(tag::SEQUENCE))?;
                extensions::for_each(list, true, |ext| {
                    if ext.id == oid::NONCE {
                        set_once(&mut nonce, || Ok(nonce_value(ext.value)))
                    } else {
                        ext.unsupported(UnknownExtensionPolicy::Strict)
                    }
                })?;
            }
            Ok((version, responder_id, produced_at, responses, nonce))
        })
        .map_err(OcspError::Malformed)?;
        if version != 0 {
            return Err(OcspError::UnsupportedVersion);
        }

        Ok(Self {
            signed,
            responder_id,
            produced_at,
            responses,
            nonce,
            certs,
        })
    }

    /// Who the response says signed it.
    #[must_use]
    pub fn responder_id(&self) -> ResponderId<'a> {
        self.responder_id
    }

    /// `producedAt`: when the responder signed the response.
    #[must_use]
    pub fn produced_at(&self) -> UnixTime {
        self.produced_at
    }

    /// The single responses, in encoding order.
    #[must_use]
    pub fn responses(&self) -> SingleResponses<'a> {
        SingleResponses {
            reader: Reader::new(self.responses),
        }
    }

    /// The certificates the responder attached (at most
    /// [`MAX_RESPONSE_CERTS`]), unparsed and untrusted.
    #[must_use]
    pub fn certificates(&self) -> ResponseCertificates<'a> {
        ResponseCertificates {
            reader: Reader::new(self.certs),
        }
    }

    /// The nonce of the response extension (RFC 8954), if any: the
    /// contents of the `Nonce` `OCTET STRING`, or the raw extension value
    /// from responders that do not wrap it.
    #[must_use]
    pub fn nonce(&self) -> Option<&'a [u8]> {
        self.nonce
    }

    /// The signed parts (`tbsResponseData`, `signatureAlgorithm`,
    /// `signature`). A valid signature alone does not authorize the signer:
    /// use [`OcspResponse::verify`].
    #[must_use]
    pub fn signed_data(&self) -> SignedData<'a> {
        self.signed
    }
}

impl fmt::Debug for BasicResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicResponse")
            .field("responder_id", &self.responder_id)
            .field("produced_at", &self.produced_at)
            .field("responses", &self.responses())
            .field("nonce", &self.nonce.map(HexDebug))
            .field("certificates", &self.certificates().count())
            .finish_non_exhaustive()
    }
}

/// The nonce inside a nonce extension value: the `OCTET STRING` contents
/// when the value is one, otherwise the value itself.
fn nonce_value(value: &[u8]) -> &[u8] {
    der::read_all(value, |r| r.expect(tag::OCTET_STRING)).unwrap_or(value)
}

/// Reads a `GeneralizedTime`; OCSP does not use `UTCTime`.
fn generalized_time(reader: &mut Reader<'_>) -> Result<UnixTime, Error> {
    if !reader.peek(tag::GENERALIZED_TIME) {
        return Err(Error::BadDerTime);
    }
    read_time(reader)
}

/// `ResponderID`: the signer's name or the SHA-1 hash of its public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResponderId<'a> {
    /// The signer's subject `Name` contents (without the outer `SEQUENCE`),
    /// as [`Cert::subject`](crate::Cert::subject) returns them.
    ByName(&'a [u8]),
    /// The SHA-1 hash (20 octets) of the signer's `subjectPublicKey` bits.
    ByKey(&'a [u8]),
}

impl<'a> ResponderId<'a> {
    fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
        let choice = reader.tlv()?;
        if choice.tag == tag::context_constructed(1) {
            der::read_all(choice.value, |r| r.expect(tag::SEQUENCE)).map(Self::ByName)
        } else if choice.tag == tag::context_constructed(2) {
            let hash = der::read_all(choice.value, |r| r.expect(tag::OCTET_STRING))?;
            if hash.len() != 20 {
                return Err(Error::BadDer);
            }
            Ok(Self::ByKey(hash))
        } else {
            Err(Error::BadDer)
        }
    }
}

impl fmt::Debug for ResponderId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByName(name) => f.debug_tuple("ByName").field(&HexDebug(name)).finish(),
            Self::ByKey(hash) => f.debug_tuple("ByKey").field(&HexDebug(hash)).finish(),
        }
    }
}

/// `CertStatus`: what the responder says about one certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertStatus {
    /// Not revoked, as far as the responder knows.
    Good,
    /// Revoked, permanently or on hold.
    Revoked {
        /// `revocationTime`.
        time: UnixTime,
        /// `revocationReason`, or `None` when absent or not a reason this
        /// crate knows (the certificate is revoked either way).
        reason: Option<RevocationReason>,
    },
    /// The responder does not know the certificate.
    Unknown,
}

impl CertStatus {
    fn read(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let choice = reader.tlv()?;
        if choice.tag == tag::context(0) && choice.value.is_empty() {
            Ok(Self::Good)
        } else if choice.tag == tag::context(2) && choice.value.is_empty() {
            Ok(Self::Unknown)
        } else if choice.tag == tag::context_constructed(1) {
            der::read_all(choice.value, |info| {
                let time = generalized_time(info)?;
                let reason = match info.optional(tag::context_constructed(0))? {
                    Some(wrapped) => {
                        let code = der::read_all(wrapped, |e| e.expect(tag::ENUMERATED))?;
                        der::check_integer(code)?;
                        match *code {
                            [code] => RevocationReason::try_from(code).ok(),
                            _ => None,
                        }
                    }
                    None => None,
                };
                Ok(Self::Revoked { time, reason })
            })
        } else {
            Err(Error::BadDer)
        }
    }
}

/// A `SingleResponse`: the status of one certificate and how long it holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SingleResponse<'a> {
    pub(crate) cert_id: ResponseCertId<'a>,
    pub(crate) status: CertStatus,
    pub(crate) this_update: UnixTime,
    pub(crate) next_update: Option<UnixTime>,
    pub(crate) sct_list: Option<&'a [u8]>,
    pub(crate) transparency_info: Option<&'a [u8]>,
}

impl<'a> SingleResponse<'a> {
    /// The certificate this response is about.
    #[must_use]
    pub fn cert_id(&self) -> ResponseCertId<'a> {
        self.cert_id
    }

    /// The certificate's status.
    #[must_use]
    pub fn status(&self) -> CertStatus {
        self.status
    }

    /// `thisUpdate`: when the status was known to be correct.
    #[must_use]
    pub fn this_update(&self) -> UnixTime {
        self.this_update
    }

    /// `nextUpdate`: when newer information will be available, if stated.
    #[must_use]
    pub fn next_update(&self) -> Option<UnixTime> {
        self.next_update
    }

    /// The `SignedCertificateTimestampList` of the RFC 6962 single
    /// extension, in its TLS encoding (the contents of the inner `OCTET
    /// STRING`), if present. The list itself is not parsed, and is only
    /// authenticated in [`VerifiedOcspStatus`](super::VerifiedOcspStatus).
    #[must_use]
    pub fn sct_list(&self) -> Option<&'a [u8]> {
        self.sct_list
    }

    /// The `TransItemList` of the RFC 9162 Transparency Information single
    /// extension (the contents of the `OCTET STRING` in the extension
    /// value), if present. The list itself is not parsed: give it to
    /// [`CtV2Verifier::verify_ocsp_response`](crate::transparency::CtV2Verifier::verify_ocsp_response)
    /// once the response is authenticated
    /// ([`VerifiedOcspStatus`](super::VerifiedOcspStatus)).
    #[must_use]
    pub fn transparency_info(&self) -> Option<&'a [u8]> {
        self.transparency_info
    }

    pub(crate) fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
        reader.nested(tag::SEQUENCE, |single| {
            let cert_id = ResponseCertId::read(single)?;
            let status = CertStatus::read(single)?;
            let this_update = generalized_time(single)?;
            let next_update = match single.optional(tag::context_constructed(0))? {
                Some(wrapped) => Some(der::read_all(wrapped, generalized_time)?),
                None => None,
            };
            let mut sct_list = None;
            let mut transparency_info = None;
            if let Some(wrapped) = single.optional(tag::context_constructed(1))? {
                let list = der::read_all(wrapped, |e| e.expect(tag::SEQUENCE))?;
                extensions::for_each(list, true, |ext| {
                    let slot = if ext.id == oid::SCT_LIST {
                        Some(&mut sct_list)
                    } else if ext.id == oid::TRANSPARENCY_INFO {
                        Some(&mut transparency_info)
                    } else {
                        None
                    };
                    if let Some(slot) = slot {
                        set_once(slot, || {
                            der::read_all(ext.value, |v| v.expect(tag::OCTET_STRING))
                                .map_err(|_| Error::ExtensionValueInvalid)
                        })
                    } else {
                        ext.unsupported(UnknownExtensionPolicy::Strict)
                    }
                })?;
            }
            Ok(Self {
                cert_id,
                status,
                this_update,
                next_update,
                sct_list,
                transparency_info,
            })
        })
    }
}

impl fmt::Debug for SingleResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleResponse")
            .field("cert_id", &self.cert_id)
            .field("status", &self.status)
            .field("this_update", &self.this_update)
            .field("next_update", &self.next_update)
            .field("sct_list", &self.sct_list.map(HexDebug))
            .field("transparency_info", &self.transparency_info.map(HexDebug))
            .finish()
    }
}

/// An iterator over the single responses of a [`BasicResponse`]. They were
/// validated when the response was parsed, so iteration cannot fail.
#[derive(Clone)]
pub struct SingleResponses<'a> {
    reader: Reader<'a>,
}

impl<'a> Iterator for SingleResponses<'a> {
    type Item = SingleResponse<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }
        // Validated when the response was parsed; a failure (impossible)
        // ends the iteration rather than panicking.
        match SingleResponse::read(&mut self.reader) {
            Ok(single) => Some(single),
            Err(_) => {
                self.reader = Reader::new(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for SingleResponses<'_> {}

impl fmt::Debug for SingleResponses<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// An iterator over the certificates attached to a [`BasicResponse`], each
/// a complete DER element that has not been parsed as a certificate.
#[derive(Clone)]
pub struct ResponseCertificates<'a> {
    reader: Reader<'a>,
}

impl<'a> Iterator for ResponseCertificates<'a> {
    type Item = CertificateDer<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }
        match self.reader.expect_tlv(tag::SEQUENCE) {
            Ok(cert) => Some(CertificateDer::from_slice(cert.raw)),
            Err(_) => {
                self.reader = Reader::new(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for ResponseCertificates<'_> {}

impl fmt::Debug for ResponseCertificates<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseCertificates")
            .field("count", &self.clone().count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsuccessful_statuses() {
        for (code, status) in [
            (1, ResponseStatus::MalformedRequest),
            (2, ResponseStatus::InternalError),
            (3, ResponseStatus::TryLater),
            (5, ResponseStatus::SigRequired),
            (6, ResponseStatus::Unauthorized),
        ] {
            let der = [0x30, 0x03, 0x0a, 0x01, code];
            let response = OcspResponse::from_der(&der).unwrap();
            assert_eq!(response.status(), status);
            assert!(response.basic().is_none());
        }
        for bad in [
            &[0x30, 0x03, 0x0a, 0x01, 0x04][..],         // unassigned status
            &[0x30, 0x03, 0x0a, 0x01, 0x07],             // unassigned status
            &[0x30, 0x04, 0x0a, 0x02, 0x00, 0x01],       // non-minimal status
            &[0x30, 0x03, 0x02, 0x01, 0x03],             // INTEGER status
            &[0x30, 0x03, 0x0a, 0x01, 0x00],             // successful, no bytes
            &[0x30, 0x05, 0x0a, 0x01, 0x03, 0x05, 0x00], // unexpected element
            &[0x30, 0x03, 0x0a, 0x01, 0x03, 0x00],       // trailing data
            &[],
        ] {
            assert!(
                matches!(OcspResponse::from_der(bad), Err(OcspError::Malformed(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn size_and_type_limits() {
        let large = alloc::vec![0u8; MAX_RESPONSE_LEN + 1];
        assert_eq!(
            OcspResponse::from_der(&large).err(),
            Some(OcspError::ResponseTooLarge)
        );
        // responseType 1.3.6.1.5.5.7.48.1.2 (the nonce identifier).
        let other_type = [
            0x30, 0x14, 0x0a, 0x01, 0x00, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06, 0x01,
            0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x00,
        ];
        assert_eq!(
            OcspResponse::from_der(&other_type).err(),
            Some(OcspError::UnsupportedResponseType)
        );
    }

    #[test]
    fn cert_status_forms() {
        let read = |bytes: &[u8]| der::read_all(bytes, CertStatus::read);
        assert_eq!(read(&[0x80, 0x00]), Ok(CertStatus::Good));
        assert_eq!(read(&[0x82, 0x00]), Ok(CertStatus::Unknown));
        assert_eq!(read(&[0x80, 0x01, 0x00]), Err(Error::BadDer));
        assert_eq!(read(&[0x81, 0x00]), Err(Error::BadDer));
        assert_eq!(read(&[0x83, 0x00]), Err(Error::BadDer));
        let mut revoked = alloc::vec![0xa1, 0x11];
        revoked.extend_from_slice(b"\x18\x0f20240601000000Z");
        assert_eq!(
            read(&revoked),
            Ok(CertStatus::Revoked {
                time: UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_717_200_000)),
                reason: None,
            })
        );
        for (code, reason) in [
            (1, Some(RevocationReason::KeyCompromise)),
            (6, Some(RevocationReason::CertificateHold)),
            // Unassigned: still revoked.
            (7, None),
        ] {
            let mut with_reason = revoked.clone();
            with_reason[1] += 5;
            with_reason.extend_from_slice(&[0xa0, 0x03, 0x0a, 0x01, code]);
            assert!(
                matches!(read(&with_reason), Ok(CertStatus::Revoked { reason: r, .. }) if r == reason)
            );
        }
        // UTCTime is not allowed.
        let mut utc = alloc::vec![0xa1, 0x0f];
        utc.extend_from_slice(b"\x17\x0d240601000000Z");
        assert_eq!(read(&utc), Err(Error::BadDerTime));
    }

    #[test]
    fn nonce_forms() {
        assert_eq!(nonce_value(&[0x04, 0x02, 0xaa, 0xbb]), &[0xaa, 0xbb]);
        assert_eq!(nonce_value(&[0xaa, 0xbb]), &[0xaa, 0xbb]);
    }
}
