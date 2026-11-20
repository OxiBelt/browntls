//! The CertificateURL handshake message (RFC 6066 §5), TLS 1.2 only.
//!
//! ```text
//! enum { individual_certs(0), pkipath(1), (255) } CertChainType;
//! struct {
//!     CertChainType type;
//!     URLAndHash url_and_hash_list<1..2^16-1>;
//! } CertificateURL;
//! struct {
//!     opaque url<1..2^16-1>;
//!     uint8 padding;
//!     opaque SHA1Hash[20];
//! } URLAndHash;
//! ```

use alloc::vec::Vec;

use crate::certificate_url::{CertChainType, CertificateUrl, SHA1_LEN};
use crate::error::InvalidMessage;
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader, encode_vec_u16, read_nonempty_vec_u16};

/// The value `padding` must have (RFC 6066 §5).
const PADDING: u8 = 0x01;

/// One `URLAndHash` as it is on the wire. The URL is not interpreted here:
/// the server's policy judges it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UrlAndHashEntry {
    pub(crate) url: Vec<u8>,
    pub(crate) sha1_hash: [u8; SHA1_LEN],
}

impl Codec<'_> for UrlAndHashEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        PayloadU16::encode_slice(&self.url, bytes);
        bytes.push(PADDING);
        bytes.extend_from_slice(&self.sha1_hash);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let url = PayloadU16::read(r)?.0;
        if url.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        if u8::read(r)? != PADDING {
            return Err(InvalidMessage::IllegalCertificateUrlPadding);
        }
        let sha1_hash = r
            .take(SHA1_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(InvalidMessage::MissingData("SHA1Hash"))?;
        Ok(Self { url, sha1_hash })
    }
}

/// A CertificateURL message body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateUrlPayload {
    pub(crate) chain_type: CertChainType,
    pub(crate) entries: Vec<UrlAndHashEntry>,
}

impl From<&CertificateUrl> for CertificateUrlPayload {
    fn from(urls: &CertificateUrl) -> Self {
        Self {
            chain_type: urls.chain_type(),
            entries: urls
                .entries()
                .iter()
                .map(|entry| UrlAndHashEntry {
                    url: entry.url().as_bytes().to_vec(),
                    sha1_hash: *entry.sha1_hash(),
                })
                .collect(),
        }
    }
}

impl Codec<'_> for CertificateUrlPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.chain_type.to_u8());
        encode_vec_u16(bytes, &self.entries);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let chain_type =
            CertChainType::from_u8(u8::read(r)?).ok_or(InvalidMessage::UnknownCertChainType)?;
        let entries = read_nonempty_vec_u16(r, "URLAndHash")?;
        // RFC 6066 §5: a pkipath list holds a single URL.
        if chain_type == CertChainType::PkiPath && entries.len() != 1 {
            return Err(InvalidMessage::IllegalPkiPathUrlCount);
        }
        Ok(Self {
            chain_type,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &[u8], fill: u8) -> UrlAndHashEntry {
        UrlAndHashEntry {
            url: url.to_vec(),
            sha1_hash: [fill; SHA1_LEN],
        }
    }

    #[test]
    fn round_trip_individual_certs() {
        let payload = CertificateUrlPayload {
            chain_type: CertChainType::IndividualCerts,
            entries: alloc::vec![entry(b"http://a/", 0x11), entry(b"http://b/c", 0x22)],
        };
        let enc = payload.get_encoding();
        // Type 0, then a list of (2 + 9 + 1 + 20) + (2 + 10 + 1 + 20) bytes.
        let mut expected = alloc::vec![0, 0, 65, 0, 9];
        expected.extend_from_slice(b"http://a/");
        expected.push(1);
        expected.extend([0x11; 20]);
        expected.extend([0, 10]);
        expected.extend_from_slice(b"http://b/c");
        expected.push(1);
        expected.extend([0x22; 20]);
        assert_eq!(enc, expected);
        assert_eq!(CertificateUrlPayload::read_bytes(&enc).unwrap(), payload);
    }

    #[test]
    fn round_trip_pkipath() {
        let payload = CertificateUrlPayload {
            chain_type: CertChainType::PkiPath,
            entries: alloc::vec![entry(b"http://p", 3)],
        };
        let enc = payload.get_encoding();
        assert_eq!(&enc[..5], [1, 0, 31, 0, 8]);
        assert_eq!(CertificateUrlPayload::read_bytes(&enc).unwrap(), payload);
    }

    #[test]
    fn malformed_bodies() {
        let good = entry(b"http://a", 7).get_encoding();
        let with = |typ: u8, entries: &[&[u8]]| {
            let mut out = alloc::vec![typ];
            let len: usize = entries.iter().map(|e| e.len()).sum();
            out.extend((len as u16).to_be_bytes());
            for e in entries {
                out.extend_from_slice(e);
            }
            out
        };
        let read = |bytes: &[u8]| CertificateUrlPayload::read_bytes(bytes).unwrap_err();
        assert_eq!(
            read(&with(2, &[&good])),
            InvalidMessage::UnknownCertChainType
        );
        assert_eq!(
            read(&with(0, &[])),
            InvalidMessage::IllegalEmptyList("URLAndHash")
        );
        let mut empty_url = alloc::vec![0, 0, 1];
        empty_url.extend([0; 20]);
        assert_eq!(
            read(&with(0, &[&empty_url])),
            InvalidMessage::IllegalEmptyValue
        );
        let mut bad_padding = good.clone();
        bad_padding[10] = 0;
        assert_eq!(
            read(&with(0, &[&bad_padding])),
            InvalidMessage::IllegalCertificateUrlPadding
        );
        assert_eq!(
            read(&with(1, &[&good, &good])),
            InvalidMessage::IllegalPkiPathUrlCount
        );
        let mut trailing = with(0, &[&good]);
        trailing.push(0);
        assert_eq!(read(&trailing), InvalidMessage::TrailingData("read_bytes"));
        assert_eq!(
            read(&with(0, &[&good[..good.len() - 1]])),
            InvalidMessage::MissingData("SHA1Hash")
        );
    }
}
