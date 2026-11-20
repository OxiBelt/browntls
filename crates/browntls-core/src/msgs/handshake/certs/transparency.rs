//! The `transparency_info` extension (RFC 9162 §6.5) in a TLS 1.3
//! CertificateEntry and a TLS 1.2 ServerHello: a `TransItemList` (§6.3).
//!
//! The list is checked here, before any handshake state sees it, so that
//! nothing malformed reaches a certificate verifier: a list that does not
//! parse is `decode_error`. RFC 9162 §6.3 makes a `TransItemList`
//! non-empty, while §6.5 lets a server with nothing to send omit the
//! `extension_data` or send "an empty array"; both forms are accepted.

use browntls_pki::transparency::TransItemList;

use super::CertificatePayloadTls13;
use crate::error::InvalidMessage;
use crate::msgs::base::Payload;

/// Checks the `extension_data` of a server's `transparency_info`: empty,
/// an empty list (`00 00`), or a `TransItemList` every item of which parses
/// (RFC 9162 §6.3; items of unknown types are allowed).
pub(super) fn validate(bytes: &[u8]) -> Result<(), InvalidMessage> {
    if matches!(bytes, [] | [0, 0]) {
        return Ok(());
    }
    TransItemList::parse(bytes)
        .map(|_| ())
        .map_err(|_| InvalidMessage::InvalidTransItemList)
}

impl<'a> CertificatePayloadTls13<'a> {
    /// See [`validate`]; for the TLS 1.2 ServerHello extension.
    pub(crate) fn validate_transparency_info(bytes: &[u8]) -> Result<(), InvalidMessage> {
        validate(bytes)
    }

    /// Attaches `list`, an encoded `TransItemList`, to the end entity's
    /// entry (RFC 9162 §6.5). Does nothing for an empty list or chain.
    pub(crate) fn set_transparency_info(&mut self, list: &'a [u8]) {
        if let Some(entry) = self.entries.first_mut()
            && !list.is_empty()
        {
            entry.transparency_info = Some(Payload::Borrowed(list));
        }
    }

    /// The end entity's `transparency_info` body, if present.
    pub(crate) fn end_entity_transparency_info(&self) -> Option<&[u8]> {
        self.entries
            .first()
            .and_then(|e| e.transparency_info.as_ref())
            .map(|list| list.bytes())
    }

    /// Whether any entry carries `transparency_info`.
    pub(crate) fn has_transparency_info(&self) -> bool {
        self.entries.iter().any(|e| e.transparency_info.is_some())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use browntls_pki::CertificateDer;

    use super::super::CertificateEntry;
    use super::*;
    use crate::msgs::codec::Codec;
    use crate::msgs::enums::ExtensionType;
    use crate::msgs::handshake::{ClientExtensions, ServerExtensions};

    /// A list of one `x509_sct_v2` item (RFC 9162 §4.8) of log 1.3.101.80.1
    /// with a one-octet signature: syntactically valid.
    fn list() -> Vec<u8> {
        let mut item = vec![1, 2, 4, 0x2b, 0x65, 0x50, 1];
        item.extend(5u64.to_be_bytes());
        item.extend([0, 0, 0, 1, 0x55]);
        let mut out = Vec::new();
        out.extend(u16::try_from(item.len() + 2).unwrap().to_be_bytes());
        out.extend(u16::try_from(item.len()).unwrap().to_be_bytes());
        out.extend(item);
        out
    }

    #[test]
    fn list_syntax() {
        assert_eq!(validate(&[]), Ok(()));
        assert_eq!(validate(&[0, 0]), Ok(()));
        assert_eq!(validate(&list()), Ok(()));
        let mut trailing = list();
        trailing.push(0);
        for bad in [&[0][..], &[0, 1], &[0, 2, 0, 0], &trailing] {
            assert_eq!(validate(bad), Err(InvalidMessage::InvalidTransItemList));
        }
        // A truncated item.
        let short = list();
        assert_eq!(
            validate(&short[..short.len() - 1]),
            Err(InvalidMessage::InvalidTransItemList)
        );
    }

    #[test]
    fn client_hello_extension_is_empty() {
        let exts = ClientExtensions {
            transparency_info: Some(()),
            ..Default::default()
        };
        let enc = exts.get_encoding();
        assert_eq!(enc, [0, 4, 0, 52, 0, 0]);
        let back = ClientExtensions::read_bytes(&enc).unwrap();
        assert_eq!(back.transparency_info, Some(()));
        assert_eq!(back.present_types(), [ExtensionType::TransparencyInfo]);
        // RFC 9162 §6.5: a non-empty body is a decode error.
        let err = ClientExtensions::read_bytes(&[0, 5, 0, 52, 0, 1, 0]).unwrap_err();
        assert_eq!(err, InvalidMessage::TrailingData("extension"));
        assert_eq!(
            crate::enums::AlertDescription::from(err),
            crate::enums::AlertDescription::DecodeError
        );
    }

    #[test]
    fn server_hello_extension_round_trip() {
        for body in [list(), Vec::new(), vec![0, 0]] {
            let exts = ServerExtensions {
                transparency_info: Some(Payload::new(body.clone())),
                ..Default::default()
            };
            let back = ServerExtensions::read_bytes(&exts.get_encoding()).unwrap();
            assert_eq!(back, exts);
            assert_eq!(back.present_types(), [ExtensionType::TransparencyInfo]);
        }
        // A malformed list does not parse.
        assert_eq!(
            ServerExtensions::read_bytes(&[0, 5, 0, 52, 0, 1, 7]),
            Err(InvalidMessage::InvalidTransItemList)
        );
    }

    #[test]
    fn certificate_entry_round_trip() {
        let certs = [
            CertificateDer::from(vec![1, 2, 3]),
            CertificateDer::from(vec![4]),
        ];
        let body = list();
        let mut msg = CertificatePayloadTls13::new(certs.iter(), None);
        assert!(!msg.has_transparency_info());
        msg.set_transparency_info(&[]);
        assert!(!msg.has_transparency_info());
        msg.set_transparency_info(&body);
        let enc = msg.get_encoding();
        let back = CertificatePayloadTls13::read_bytes(&enc).unwrap();
        assert_eq!(back, msg);
        assert_eq!(back.end_entity_transparency_info(), Some(&body[..]));
        assert!(back.has_transparency_info());
        assert_eq!(back.entries[1].transparency_info, None);

        // On a non-end-entity entry it parses too; the handshake decides.
        let mut entry = CertificateEntry::new(CertificateDer::from(vec![9]));
        entry.transparency_info = Some(Payload::Borrowed(&[0, 0]));
        let enc = entry.get_encoding();
        assert_eq!(CertificateEntry::read_bytes(&enc).unwrap(), entry);

        // cert [1] with transparency_info holding one malformed octet.
        let bad = [0, 0, 1, 1, 0, 5, 0, 52, 0, 1, 7];
        assert_eq!(
            CertificateEntry::read_bytes(&bad),
            Err(InvalidMessage::InvalidTransItemList)
        );
    }

    #[test]
    fn certificate_request_extension_is_tolerated() {
        // RFC 9162 defines no CT for client certificates: a server's
        // CertificateRequest may carry the (empty) extension, which the
        // client keeps as an unanswered, permitted extension.
        let bytes = [0, 4, 0, 52, 0, 0];
        let exts =
            crate::msgs::handshake::CertificateRequestExtensions::read_bytes(&bytes).unwrap();
        assert_eq!(exts.unknown, [ExtensionType::TransparencyInfo]);
        assert_eq!(
            crate::tls13::extensions::first_disallowed(
                exts.unknown.iter().copied(),
                crate::tls13::extensions::Tls13Message::CertificateRequest,
            ),
            None
        );
    }
}
