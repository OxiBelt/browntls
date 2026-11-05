//! Certificate, CertificateRequest and CertificateStatus messages.

use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::extensions::{encode_extension, read_extensions};
use super::{DistinguishedName, MAX_CERTIFICATE_SIZE_LIMIT};
use crate::enums::{CertificateCompressionAlgorithm, SignatureScheme};
use crate::error::InvalidMessage;
use crate::msgs::base::{Payload, PayloadU8, PayloadU16, PayloadU24};
use crate::msgs::codec::{
    Codec, LengthPrefixedBuffer, ListLength, Reader, encode_vec_u8, encode_vec_u16, encode_vec_u24,
    read_nonempty_vec_u16, read_vec_u8, read_vec_u16, read_vec_u24, u24,
};
use crate::msgs::enums::{CertificateStatusType, ClientCertificateType, ExtensionType};

/// A TLS 1.2 certificate chain: the end entity first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CertificateChain<'a>(pub(crate) Vec<CertificateDer<'a>>);

impl CertificateChain<'_> {
    pub(crate) fn into_owned(self) -> CertificateChain<'static> {
        CertificateChain(self.0.into_iter().map(CertificateDer::into_owned).collect())
    }
}

impl<'a> Codec<'a> for CertificateChain<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u24(bytes, &self.0);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        read_vec_u24(
            r,
            MAX_CERTIFICATE_SIZE_LIMIT,
            InvalidMessage::CertificatePayloadTooLarge,
        )
        .map(Self)
    }
}

/// The client's `status_request` extension (RFC 6066 §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CertificateStatusRequest {
    Ocsp {
        responder_ids: Vec<PayloadU16>,
        extensions: PayloadU16,
    },
    Unknown((CertificateStatusType, Payload<'static>)),
}

impl CertificateStatusRequest {
    pub(crate) fn build_ocsp() -> Self {
        Self::Ocsp {
            responder_ids: Vec::new(),
            extensions: PayloadU16::empty(),
        }
    }
}

impl Codec<'_> for CertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Ocsp {
                responder_ids,
                extensions,
            } => {
                CertificateStatusType::OCSP.encode(bytes);
                encode_vec_u16(bytes, responder_ids);
                extensions.encode(bytes);
            }
            Self::Unknown((typ, payload)) => {
                typ.encode(bytes);
                payload.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = CertificateStatusType::read(r)?;
        match typ {
            CertificateStatusType::OCSP => Ok(Self::Ocsp {
                responder_ids: read_vec_u16(r)?,
                extensions: PayloadU16::read(r)?,
            }),
            _ => Ok(Self::Unknown((typ, Payload::read(r).into_owned()))),
        }
    }
}

/// A CertificateStatus message (RFC 6066 §8), carrying an OCSP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateStatus<'a> {
    pub(crate) ocsp_response: PayloadU24<'a>,
}

impl<'a> CertificateStatus<'a> {
    pub(crate) fn new(ocsp: &'a [u8]) -> Self {
        Self {
            ocsp_response: PayloadU24(Payload::Borrowed(ocsp)),
        }
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.ocsp_response.0.into_vec()
    }

    pub(crate) fn into_owned(self) -> CertificateStatus<'static> {
        CertificateStatus {
            ocsp_response: self.ocsp_response.into_owned(),
        }
    }
}

impl<'a> Codec<'a> for CertificateStatus<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.ocsp_response.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        match CertificateStatusType::read(r)? {
            CertificateStatusType::OCSP => Ok(Self {
                ocsp_response: PayloadU24::read(r)?,
            }),
            _ => Err(InvalidMessage::InvalidCertificateStatusType),
        }
    }
}

/// One entry of a TLS 1.3 Certificate message (RFC 8446 §4.4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateEntry<'a> {
    pub(crate) cert: CertificateDer<'a>,
    pub(crate) status: Option<CertificateStatus<'a>>,
    pub(crate) sct_list: Option<Payload<'a>>,
}

impl<'a> CertificateEntry<'a> {
    pub(crate) fn new(cert: CertificateDer<'a>) -> Self {
        Self {
            cert,
            status: None,
            sct_list: None,
        }
    }

    pub(crate) fn into_owned(self) -> CertificateEntry<'static> {
        CertificateEntry {
            cert: self.cert.into_owned(),
            status: self.status.map(CertificateStatus::into_owned),
            sct_list: self.sct_list.map(Payload::into_owned),
        }
    }
}

impl<'a> Codec<'a> for CertificateEntry<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cert.encode(bytes);
        let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        if let Some(status) = &self.status {
            encode_extension(ExtensionType::StatusRequest, list.buf, |b| status.encode(b));
        }
        if let Some(scts) = &self.sct_list {
            encode_extension(ExtensionType::SCT, list.buf, |b| scts.encode(b));
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let cert = CertificateDer::read(r)?;
        let mut status = None;
        let mut sct_list = None;
        read_extensions(r, |typ, body| {
            match typ {
                ExtensionType::StatusRequest => status = Some(CertificateStatus::read(body)?),
                ExtensionType::SCT => sct_list = Some(Payload::read(body)),
                // RFC 9846 §4.3: a recognised extension that may not
                // appear in a CertificateEntry is illegal_parameter; any
                // other one cannot answer anything we sent.
                other
                    if crate::tls13::extensions::allowed_in(
                        other,
                        crate::tls13::extensions::Tls13Message::Certificate,
                    ) == Some(false) =>
                {
                    return Err(InvalidMessage::DisallowedCertificateExtension);
                }
                _ => return Err(InvalidMessage::UnknownCertificateExtension),
            }
            Ok(())
        })?;
        Ok(Self {
            cert,
            status,
            sct_list,
        })
    }
}

/// A TLS 1.3 Certificate message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CertificatePayloadTls13<'a> {
    pub(crate) context: PayloadU8,
    pub(crate) entries: Vec<CertificateEntry<'a>>,
}

impl<'a> CertificatePayloadTls13<'a> {
    pub(crate) fn new(
        certs: impl Iterator<Item = &'a CertificateDer<'a>>,
        ocsp: Option<&'a [u8]>,
    ) -> Self {
        let mut entries: Vec<CertificateEntry<'a>> = certs
            .map(|c| CertificateEntry::new(CertificateDer::from_slice(c.as_ref())))
            .collect();
        if let (Some(first), Some(ocsp)) = (entries.first_mut(), ocsp)
            && !ocsp.is_empty()
        {
            first.status = Some(CertificateStatus::new(ocsp));
        }
        Self {
            context: PayloadU8::empty(),
            entries,
        }
    }

    pub(crate) fn into_owned(self) -> CertificatePayloadTls13<'static> {
        CertificatePayloadTls13 {
            context: self.context,
            entries: self
                .entries
                .into_iter()
                .map(CertificateEntry::into_owned)
                .collect(),
        }
    }

    /// Whether any entry other than the first carries extensions (RFC 8446
    /// §4.4.2: only the end entity may have `status_request` or `sct`).
    pub(crate) fn end_entity_ocsp(&self) -> Vec<u8> {
        self.entries
            .first()
            .and_then(|e| e.status.as_ref())
            .map(|s| s.ocsp_response.0.bytes().to_vec())
            .unwrap_or_default()
    }

    pub(crate) fn into_certificate_chain(self) -> CertificateChain<'a> {
        CertificateChain(self.entries.into_iter().map(|e| e.cert).collect())
    }
}

impl<'a> Codec<'a> for CertificatePayloadTls13<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        encode_vec_u24(bytes, &self.entries);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            context: PayloadU8::read(r)?,
            entries: read_vec_u24(
                r,
                MAX_CERTIFICATE_SIZE_LIMIT,
                InvalidMessage::CertificatePayloadTooLarge,
            )?,
        })
    }
}

/// A CompressedCertificate message (RFC 8879 §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompressedCertificatePayload<'a> {
    pub(crate) alg: CertificateCompressionAlgorithm,
    pub(crate) uncompressed_len: u32,
    pub(crate) compressed: PayloadU24<'a>,
}

impl CompressedCertificatePayload<'_> {
    pub(crate) fn into_owned(self) -> CompressedCertificatePayload<'static> {
        CompressedCertificatePayload {
            alg: self.alg,
            uncompressed_len: self.uncompressed_len,
            compressed: self.compressed.into_owned(),
        }
    }
}

impl<'a> Codec<'a> for CompressedCertificatePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.alg.encode(bytes);
        u24(self.uncompressed_len).encode(bytes);
        self.compressed.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let alg = CertificateCompressionAlgorithm::read(r)?;
        let uncompressed_len = u24::read(r)?.0;
        if uncompressed_len as usize > MAX_CERTIFICATE_SIZE_LIMIT {
            return Err(InvalidMessage::CertificatePayloadTooLarge);
        }
        let compressed = PayloadU24::read(r)?;
        if compressed.0.bytes().is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self {
            alg,
            uncompressed_len,
            compressed,
        })
    }
}

/// A TLS 1.2 CertificateRequest (RFC 5246 §7.4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateRequestPayload {
    pub(crate) certtypes: Vec<ClientCertificateType>,
    pub(crate) sigschemes: Vec<SignatureScheme>,
    pub(crate) canames: Vec<DistinguishedName>,
}

impl Codec<'_> for CertificateRequestPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8(bytes, &self.certtypes);
        encode_vec_u16(bytes, &self.sigschemes);
        encode_vec_u16(bytes, &self.canames);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        // RFC 5246 §7.4.4: certificate_types<1..2^8-1>.
        let certtypes = read_vec_u8(r)?;
        if certtypes.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        let sigschemes = read_vec_u16::<SignatureScheme>(r)?;
        if sigschemes.is_empty() {
            return Err(InvalidMessage::NoSignatureSchemes);
        }
        let canames = read_vec_u16(r)?;
        Ok(Self {
            certtypes,
            sigschemes,
            canames,
        })
    }
}

/// The extensions of a TLS 1.3 CertificateRequest (RFC 8446 §4.3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CertificateRequestExtensions {
    pub(crate) signature_algorithms: Option<Vec<SignatureScheme>>,
    pub(crate) signature_algorithms_cert: Option<Vec<SignatureScheme>>,
    pub(crate) authorities: Option<Vec<DistinguishedName>>,
    pub(crate) certificate_compression: Option<Vec<CertificateCompressionAlgorithm>>,
    pub(crate) unknown: Vec<ExtensionType>,
}

impl Codec<'_> for CertificateRequestExtensions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        let out = &mut *list.buf;
        if let Some(s) = &self.signature_algorithms {
            encode_extension(ExtensionType::SignatureAlgorithms, out, |b| {
                encode_vec_u16(b, s)
            });
        }
        if let Some(s) = &self.signature_algorithms_cert {
            encode_extension(ExtensionType::SignatureAlgorithmsCert, out, |b| {
                encode_vec_u16(b, s);
            });
        }
        if let Some(cas) = &self.authorities {
            encode_extension(ExtensionType::CertificateAuthorities, out, |b| {
                encode_vec_u16(b, cas);
            });
        }
        if let Some(algs) = &self.certificate_compression {
            encode_extension(ExtensionType::CompressCertificate, out, |b| {
                encode_vec_u8(b, algs)
            });
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();
        read_extensions(r, |typ, body| {
            match typ {
                ExtensionType::SignatureAlgorithms => {
                    out.signature_algorithms =
                        Some(read_nonempty_vec_u16(body, "SignatureSchemes")?);
                }
                ExtensionType::SignatureAlgorithmsCert => {
                    out.signature_algorithms_cert =
                        Some(read_nonempty_vec_u16(body, "SignatureSchemesCert")?);
                }
                ExtensionType::CertificateAuthorities => {
                    out.authorities = Some(read_nonempty_vec_u16(body, "CertificateAuthorities")?);
                }
                ExtensionType::CompressCertificate => {
                    out.certificate_compression = Some(crate::msgs::codec::read_nonempty_vec_u8(
                        body,
                        "CertificateCompressionAlgorithms",
                    )?);
                }
                other => {
                    out.unknown.push(other);
                    body.rest();
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
}

/// A TLS 1.3 CertificateRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateRequestPayloadTls13 {
    pub(crate) context: PayloadU8,
    pub(crate) extensions: CertificateRequestExtensions,
}

impl Codec<'_> for CertificateRequestPayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            context: PayloadU8::read(r)?,
            extensions: CertificateRequestExtensions::read(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_certificate_roundtrip() {
        let certs = [
            CertificateDer::from_slice(&[1, 2, 3]),
            CertificateDer::from_slice(&[4, 5]),
        ];
        let ocsp = [7u8, 8];
        let msg = CertificatePayloadTls13::new(certs.iter(), Some(&ocsp));
        let enc = msg.get_encoding();
        let back = CertificatePayloadTls13::read_bytes(&enc).unwrap();
        assert_eq!(back, msg);
        assert_eq!(back.end_entity_ocsp(), ocsp);
        assert_eq!(back.into_certificate_chain().0, certs);
    }

    #[test]
    fn certificate_entry_rejects_unknown_extension() {
        // cert [1] with an extension of type 0x0000 (server_name) and empty
        // body: recognised, but not allowed in a CertificateEntry.
        let bytes = [0, 0, 1, 1, 0, 4, 0, 0, 0, 0];
        assert_eq!(
            CertificateEntry::read_bytes(&bytes),
            Err(InvalidMessage::DisallowedCertificateExtension)
        );
        // An extension type this crate does not know.
        let bytes = [0, 0, 1, 1, 0, 4, 0x12, 0x34, 0, 0];
        assert_eq!(
            CertificateEntry::read_bytes(&bytes),
            Err(InvalidMessage::UnknownCertificateExtension)
        );
    }

    #[test]
    fn certificate_chain_limit() {
        let bytes = [0x01, 0, 1];
        assert_eq!(
            CertificateChain::read_bytes(&bytes),
            Err(InvalidMessage::CertificatePayloadTooLarge)
        );
        let chain = CertificateChain(alloc::vec![CertificateDer::from_slice(&[1])]);
        assert_eq!(
            CertificateChain::read_bytes(&chain.get_encoding()).unwrap(),
            chain
        );
    }

    #[test]
    fn certificate_status() {
        let cs = CertificateStatus::new(&[1, 2, 3]);
        assert_eq!(cs.get_encoding(), [1, 0, 0, 3, 1, 2, 3]);
        assert_eq!(
            CertificateStatus::read_bytes(&[1, 0, 0, 3, 1, 2, 3]).unwrap(),
            cs
        );
        assert_eq!(
            CertificateStatus::read_bytes(&[2, 0, 0, 0]),
            Err(InvalidMessage::InvalidCertificateStatusType)
        );
        let req = CertificateStatusRequest::build_ocsp();
        assert_eq!(
            CertificateStatusRequest::read_bytes(&req.get_encoding()).unwrap(),
            req
        );
    }

    #[test]
    fn certificate_requests() {
        let cr = CertificateRequestPayload {
            certtypes: alloc::vec![ClientCertificateType::ECDSASign],
            sigschemes: alloc::vec![SignatureScheme::ECDSA_NISTP256_SHA256],
            canames: alloc::vec![DistinguishedName::in_sequence(&[1])],
        };
        assert_eq!(
            CertificateRequestPayload::read_bytes(&cr.get_encoding()).unwrap(),
            cr
        );
        let empty_schemes = [1, 0x40, 0, 0, 0, 0];
        assert_eq!(
            CertificateRequestPayload::read_bytes(&empty_schemes),
            Err(InvalidMessage::NoSignatureSchemes)
        );

        let cr13 = CertificateRequestPayloadTls13 {
            context: PayloadU8::empty(),
            extensions: CertificateRequestExtensions {
                signature_algorithms: Some(alloc::vec![SignatureScheme::ED25519]),
                authorities: Some(alloc::vec![DistinguishedName::in_sequence(&[1])]),
                ..Default::default()
            },
        };
        assert_eq!(
            CertificateRequestPayloadTls13::read_bytes(&cr13.get_encoding()).unwrap(),
            cr13
        );
    }

    #[test]
    fn compressed_certificate() {
        let cc = CompressedCertificatePayload {
            alg: CertificateCompressionAlgorithm::Zlib,
            uncompressed_len: 10,
            compressed: PayloadU24(Payload::Borrowed(&[1, 2])),
        };
        assert_eq!(
            CompressedCertificatePayload::read_bytes(&cc.get_encoding()).unwrap(),
            cc
        );
        let too_big = [0, 1, 0x01, 0, 1, 0, 0, 1, 0];
        assert_eq!(
            CompressedCertificatePayload::read_bytes(&too_big),
            Err(InvalidMessage::CertificatePayloadTooLarge)
        );
    }
}
