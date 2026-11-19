//! Per-entry OCSP responses and SCT lists of a TLS 1.3 Certificate message
//! (RFC 8446 §4.4.2.1, RFC 6962 §3.3).

use alloc::vec::Vec;

use super::{CertificatePayloadTls13, CertificateStatus};
use crate::error::InvalidMessage;
use crate::msgs::base::Payload;
use crate::msgs::codec::{Codec, Reader};
use crate::sign::CertifiedKey;

/// Checks that `bytes` is a `SignedCertificateTimestampList` (RFC 6962
/// §3.3): a non-empty list of non-empty `SerializedSCT`s filling `bytes`
/// exactly. The SCTs themselves are not interpreted.
pub(super) fn validate_sct_list(bytes: &[u8]) -> Result<(), InvalidMessage> {
    const NAME: &str = "SignedCertificateTimestampList";
    let mut r = Reader::init(bytes);
    let len = usize::from(u16::read(&mut r)?);
    let mut list = r.sub(len)?;
    r.expect_empty(NAME)?;
    if !list.any_left() {
        return Err(InvalidMessage::IllegalEmptyList(NAME));
    }
    while list.any_left() {
        let sct_len = usize::from(u16::read(&mut list)?);
        if sct_len == 0 {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        list.sub(sct_len)?;
    }
    Ok(())
}

impl<'a> CertificatePayloadTls13<'a> {
    /// See [`validate_sct_list`]; for SCT lists from configuration or from
    /// other messages.
    pub(crate) fn validate_sct_list(bytes: &[u8]) -> Result<(), InvalidMessage> {
        validate_sct_list(bytes)
    }

    /// The Certificate message for `key`'s chain. With `with_ocsp`, every
    /// entry carries the OCSP response configured for it; with `with_sct`,
    /// the end entity's entry carries the configured SCT list. The caller
    /// passes whether the peer asked for each.
    pub(crate) fn from_certified_key(
        key: &'a CertifiedKey,
        with_ocsp: bool,
        with_sct: bool,
    ) -> Self {
        let mut payload = Self::new(key.cert.iter(), None);
        if with_ocsp {
            for index in 0..key.cert.len() {
                if let Some(response) = key.ocsp_for(index) {
                    payload.set_ocsp(index, response);
                }
            }
        }
        if with_sct && let Some(sct_list) = key.sct_list() {
            payload.set_sct_list(0, sct_list);
        }
        payload
    }

    /// Staples `response` to entry `index`. Does nothing for an empty
    /// response (`OCSPResponse<1..2^24-1>`) or an entry that does not exist.
    pub(crate) fn set_ocsp(&mut self, index: usize, response: &'a [u8]) {
        if let Some(entry) = self.entries.get_mut(index)
            && !response.is_empty()
        {
            entry.status = Some(CertificateStatus::new(response));
        }
    }

    /// Attaches `sct_list`, an encoded `SignedCertificateTimestampList`, to
    /// entry `index`. Does nothing for an empty list or an entry that does
    /// not exist.
    pub(crate) fn set_sct_list(&mut self, index: usize, sct_list: &'a [u8]) {
        if let Some(entry) = self.entries.get_mut(index)
            && !sct_list.is_empty()
        {
            entry.sct_list = Some(Payload::Borrowed(sct_list));
        }
    }

    /// The OCSP response of every entry, in chain order: `None` for an
    /// entry without `status_request`. A present response may be empty.
    // Consumed by the handshake's certificate authentication.
    #[allow(dead_code)]
    pub(crate) fn ocsp_responses(&self) -> Vec<Option<Vec<u8>>> {
        self.entries
            .iter()
            .map(|e| {
                e.status
                    .as_ref()
                    .map(|s| s.ocsp_response.0.bytes().to_vec())
            })
            .collect()
    }

    /// The encoded `SignedCertificateTimestampList` of every entry, in chain
    /// order: `None` for an entry without the extension.
    // Consumed by the handshake's certificate authentication.
    #[allow(dead_code)]
    pub(crate) fn sct_lists(&self) -> Vec<Option<Vec<u8>>> {
        self.entries
            .iter()
            .map(|e| e.sct_list.as_ref().map(|l| l.bytes().to_vec()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use browntls_pki::CertificateDer;

    use super::super::{
        CertificateEntry, CertificateRequestExtensions, CertificateRequestPayloadTls13,
    };
    use super::*;
    use crate::msgs::base::PayloadU8;

    /// Two SCTs, `[0xaa]` and `[0xbb, 0xcc]`.
    const SCTS: &[u8] = &[0, 7, 0, 1, 0xaa, 0, 2, 0xbb, 0xcc];

    fn certs() -> [CertificateDer<'static>; 3] {
        [
            CertificateDer::from(vec![1, 2, 3]),
            CertificateDer::from(vec![4, 5]),
            CertificateDer::from(vec![6]),
        ]
    }

    #[test]
    fn sct_list_syntax() {
        assert_eq!(validate_sct_list(SCTS), Ok(()));
        assert_eq!(validate_sct_list(&[0, 3, 0, 1, 0xaa]), Ok(()));
        // No list at all, an empty list, and an empty SCT.
        assert!(validate_sct_list(&[]).is_err());
        assert_eq!(
            validate_sct_list(&[0, 0]),
            Err(InvalidMessage::IllegalEmptyList(
                "SignedCertificateTimestampList"
            ))
        );
        assert_eq!(
            validate_sct_list(&[0, 2, 0, 0]),
            Err(InvalidMessage::IllegalEmptyValue)
        );
        // The list is shorter or longer than its length says.
        assert_eq!(
            validate_sct_list(&[0, 4, 0, 1, 0xaa]),
            Err(InvalidMessage::MessageTooShort)
        );
        assert_eq!(
            validate_sct_list(&[0, 3, 0, 1, 0xaa, 0]),
            Err(InvalidMessage::TrailingData(
                "SignedCertificateTimestampList"
            ))
        );
        // An SCT runs past the list, or its length is cut short.
        assert_eq!(
            validate_sct_list(&[0, 3, 0, 2, 0xaa]),
            Err(InvalidMessage::MessageTooShort)
        );
        assert!(validate_sct_list(&[0, 4, 0, 1, 0xaa, 0]).is_err());
    }

    #[test]
    fn per_entry_evidence_roundtrip() {
        let certs = certs();
        let mut msg = CertificatePayloadTls13::new(certs.iter(), None);
        msg.set_ocsp(0, &[7, 8]);
        msg.set_ocsp(2, &[9]);
        msg.set_sct_list(0, SCTS);
        // Empty values and missing entries are ignored.
        msg.set_ocsp(1, &[]);
        msg.set_sct_list(1, &[]);
        msg.set_ocsp(3, &[1]);
        msg.set_sct_list(3, SCTS);

        let enc = msg.get_encoding();
        #[rustfmt::skip]
        let expected: &[u8] = &[
            0, // context
            0, 0, 53, // entries
            0, 0, 3, 1, 2, 3, // end entity
            0, 23, // its extensions
            0, 5, 0, 6, 1, 0, 0, 2, 7, 8, // status_request: ocsp, response
            0, 18, 0, 9, 0, 7, 0, 1, 0xaa, 0, 2, 0xbb, 0xcc, // SCT list
            0, 0, 2, 4, 5, 0, 0, // first intermediate, bare
            0, 0, 1, 6, // second intermediate
            0, 9, 0, 5, 0, 5, 1, 0, 0, 1, 9, // status_request
        ];
        assert_eq!(enc, expected);

        let back = CertificatePayloadTls13::read_bytes(&enc).unwrap();
        assert_eq!(back, msg);
        assert_eq!(
            back.ocsp_responses(),
            [Some(vec![7, 8]), None, Some(vec![9])]
        );
        assert_eq!(back.sct_lists(), [Some(SCTS.to_vec()), None, None]);
        assert_eq!(back.end_entity_ocsp(), [7, 8]);
        assert_eq!(back.into_certificate_chain().0, certs);
    }

    #[test]
    fn certificate_entry_rejects_malformed_sct_list() {
        // cert [1] with an SCT extension whose body is `body`.
        let entry = |body: &[u8]| {
            let mut bytes = vec![0, 0, 1, 1];
            let len = u8::try_from(body.len()).unwrap();
            bytes.extend([0, len + 4, 0, 18, 0, len]);
            bytes.extend(body);
            bytes
        };
        let well_formed = entry(SCTS);
        let good = CertificateEntry::read_bytes(&well_formed).unwrap();
        assert_eq!(good.sct_list.unwrap().bytes(), SCTS);
        assert!(CertificateEntry::read_bytes(&entry(&[])).is_err());
        assert_eq!(
            CertificateEntry::read_bytes(&entry(&[0, 0])),
            Err(InvalidMessage::IllegalEmptyList(
                "SignedCertificateTimestampList"
            ))
        );
        assert_eq!(
            CertificateEntry::read_bytes(&entry(&[0, 2, 0, 0])),
            Err(InvalidMessage::IllegalEmptyValue)
        );
        assert_eq!(
            CertificateEntry::read_bytes(&entry(&[0, 3, 0, 1, 0xaa, 0])),
            Err(InvalidMessage::TrailingData(
                "SignedCertificateTimestampList"
            ))
        );
    }

    #[test]
    fn certificate_request_status_and_sct_requests() {
        let request = CertificateRequestPayloadTls13 {
            context: PayloadU8::empty(),
            extensions: CertificateRequestExtensions {
                status_request: Some(()),
                sct_request: Some(()),
                ..Default::default()
            },
        };
        let enc = request.get_encoding();
        assert_eq!(enc, [0, 0, 8, 0, 5, 0, 0, 0, 18, 0, 0]);
        let back = CertificateRequestPayloadTls13::read_bytes(&enc).unwrap();
        assert_eq!(back, request);
        assert!(back.extensions.unknown.is_empty());

        // Each alone, and neither.
        let only_status = CertificateRequestExtensions::read_bytes(&[0, 4, 0, 5, 0, 0]).unwrap();
        assert_eq!(only_status.status_request, Some(()));
        assert_eq!(only_status.sct_request, None);
        let only_sct = CertificateRequestExtensions::read_bytes(&[0, 4, 0, 18, 0, 0]).unwrap();
        assert_eq!(only_sct.status_request, None);
        assert_eq!(only_sct.sct_request, Some(()));
        let neither = CertificateRequestExtensions::default();
        assert_eq!(neither.get_encoding(), [0, 0]);

        // RFC 8446 §4.4.2.1: both are empty in a CertificateRequest. A
        // ClientHello-style OCSP request body is not accepted.
        assert_eq!(
            CertificateRequestExtensions::read_bytes(&[0, 9, 0, 5, 0, 5, 1, 0, 0, 0, 0]),
            Err(InvalidMessage::TrailingData("extension"))
        );
        assert_eq!(
            CertificateRequestExtensions::read_bytes(&[0, 5, 0, 18, 0, 1, 0]),
            Err(InvalidMessage::TrailingData("extension"))
        );
        // Neither may appear twice.
        assert_eq!(
            CertificateRequestExtensions::read_bytes(&[0, 8, 0, 5, 0, 0, 0, 5, 0, 0]),
            Err(InvalidMessage::DuplicateExtension(5))
        );
        assert_eq!(
            CertificateRequestExtensions::read_bytes(&[0, 8, 0, 18, 0, 0, 0, 18, 0, 0]),
            Err(InvalidMessage::DuplicateExtension(18))
        );
    }
}
