//! Reconstruction of the `TBSCertificate` a log signed for a precertificate
//! (RFC 6962 §3.2) from the final certificate, and the `digitally-signed`
//! input of an SCT.

use alloc::vec::Vec;

use super::{EMBEDDED_SCT_LIST_OID, SctError};
use crate::cert::Cert;
use crate::der::{self, Reader, tag};

/// `[3] EXPLICIT Extensions` of a `TBSCertificate`.
const EXTENSIONS_TAG: u8 = tag::context_constructed(3);

/// The parts of a certificate needed to verify embedded SCTs.
pub(super) struct PrecertTbs<'a> {
    /// The complete `TBSCertificate` without the embedded SCT list
    /// extension.
    pub(super) tbs: Vec<u8>,
    /// The `extnValue` contents of the SCT list extension, if present.
    pub(super) sct_list_extension: Option<&'a [u8]>,
}

/// Rebuilds the `TBSCertificate` of `cert` without its embedded SCT list
/// extension. Every other octet is copied as encoded; only the lengths of
/// the enclosing `Extensions`, `[3]` and `TBSCertificate` elements are
/// re-encoded (minimally, as DER). When the SCT list was the only extension
/// the `extensions` field is omitted, as RFC 5280 requires of an empty list.
///
/// A certificate without the extension yields its `TBSCertificate` unchanged.
pub(super) fn tbs_without_sct_list<'a>(cert: &Cert<'a>) -> Result<PrecertTbs<'a>, SctError> {
    let malformed = |_| SctError::MalformedCertificate;
    let tbs = der::read_all(cert.signed.data, |r| r.expect(tag::SEQUENCE)).map_err(malformed)?;

    // Locate the extensions field, which certificate parsing has checked to
    // be the last element of the TBSCertificate.
    let mut fields = Reader::new(tbs);
    let mut prefix_len = 0usize;
    let mut wrapped = None;
    while !fields.at_end() {
        let field = fields.tlv().map_err(malformed)?;
        if field.tag == EXTENSIONS_TAG {
            wrapped = Some(field.value);
            break;
        }
        prefix_len = prefix_len.saturating_add(field.raw.len());
    }
    let unchanged = || PrecertTbs {
        tbs: cert.signed.data.to_vec(),
        sct_list_extension: None,
    };
    let Some(wrapped) = wrapped else {
        return Ok(unchanged());
    };
    if !fields.at_end() {
        return Err(SctError::MalformedCertificate);
    }
    let prefix = tbs
        .get(..prefix_len)
        .ok_or(SctError::MalformedCertificate)?;
    let extensions = der::read_all(wrapped, |r| r.expect(tag::SEQUENCE)).map_err(malformed)?;

    // Find the single SCT list extension and the octets around it.
    let mut reader = Reader::new(extensions);
    let mut offset = 0usize;
    let mut found: Option<(usize, usize, &'a [u8])> = None;
    while !reader.at_end() {
        let raw = reader.expect_tlv(tag::SEQUENCE).map_err(malformed)?;
        let (id, value) = der::read_all(raw.value, |ext| {
            let id = ext.oid()?;
            ext.default_false_boolean()?;
            Ok((id, ext.expect(tag::OCTET_STRING)?))
        })
        .map_err(malformed)?;
        let end = offset.saturating_add(raw.raw.len());
        if id == EMBEDDED_SCT_LIST_OID {
            if found.is_some() {
                return Err(SctError::DuplicateSctExtension);
            }
            found = Some((offset, end, value));
        }
        offset = end;
    }
    let Some((start, end, value)) = found else {
        return Ok(unchanged());
    };
    let before = extensions
        .get(..start)
        .ok_or(SctError::MalformedCertificate)?;
    let after = extensions
        .get(end..)
        .ok_or(SctError::MalformedCertificate)?;

    let remaining = before.len().saturating_add(after.len());
    let mut field = Vec::new();
    if remaining != 0 {
        let sequence_len = header_len(remaining).saturating_add(remaining);
        push_header(&mut field, EXTENSIONS_TAG, sequence_len)?;
        push_header(&mut field, tag::SEQUENCE, remaining)?;
        field.extend_from_slice(before);
        field.extend_from_slice(after);
    }
    let contents_len = prefix.len().saturating_add(field.len());
    let mut out = Vec::with_capacity(contents_len.saturating_add(4));
    push_header(&mut out, tag::SEQUENCE, contents_len)?;
    out.extend_from_slice(prefix);
    out.extend_from_slice(&field);
    Ok(PrecertTbs {
        tbs: out,
        sct_list_extension: Some(value),
    })
}

/// The number of octets of a DER tag and length for `len` content octets
/// (`len` at most 65535).
fn header_len(len: usize) -> usize {
    match len {
        0..=0x7f => 2,
        0x80..=0xff => 3,
        _ => 4,
    }
}

/// Appends a DER tag and minimal definite length.
pub(super) fn push_header(out: &mut Vec<u8>, tag: u8, len: usize) -> Result<(), SctError> {
    // Removing an extension only shrinks elements that fitted the limit.
    let len16 = u16::try_from(len).map_err(|_| SctError::MalformedCertificate)?;
    out.push(tag);
    let [high, low] = len16.to_be_bytes();
    match len16 {
        0..=0x7f => out.push(low),
        0x80..=0xff => out.extend_from_slice(&[0x81, low]),
        _ => out.extend_from_slice(&[0x82, high, low]),
    }
    Ok(())
}

/// `LogEntryType` (RFC 6962 §3.1).
#[derive(Clone, Copy)]
pub(super) enum SignedEntry<'a> {
    /// `x509_entry`: the complete certificate.
    X509(&'a [u8]),
    /// `precert_entry`: the issuer key hash and the `TBSCertificate`.
    Precert {
        issuer_key_hash: &'a [u8; 32],
        tbs: &'a [u8],
    },
}

/// Offset of the timestamp in the signed input.
const TIMESTAMP_OFFSET: usize = 2;

/// The `digitally-signed` input of a version 1 SCT (RFC 6962 §3.2), built
/// once per entry and reused for every SCT over that entry: only the
/// timestamp and the trailing `CtExtensions` differ between SCTs.
pub(super) struct SignedInput {
    buffer: Vec<u8>,
    /// Length of everything before the `CtExtensions` vector.
    entry_end: usize,
}

impl SignedInput {
    /// Builds the input for `entry`.
    pub(super) fn new(entry: SignedEntry<'_>) -> Result<Self, SctError> {
        let (entry_type, key_hash, body): (u16, &[u8], &[u8]) = match entry {
            SignedEntry::X509(cert) => (0, &[], cert),
            SignedEntry::Precert {
                issuer_key_hash,
                tbs,
            } => (1, issuer_key_hash, tbs),
        };
        // `opaque<1..2^24-1>` for both `ASN.1Cert` and `TBSCertificate`.
        let body_len = u32::try_from(body.len())
            .ok()
            .filter(|len| (1..1 << 24).contains(len))
            .ok_or(SctError::MalformedCertificate)?;
        let mut buffer = Vec::with_capacity(body.len().saturating_add(128));
        // sct_version v1, signature_type certificate_timestamp.
        buffer.extend_from_slice(&[0, 0]);
        buffer.extend_from_slice(&[0; 8]);
        buffer.extend_from_slice(&entry_type.to_be_bytes());
        buffer.extend_from_slice(key_hash);
        buffer.extend_from_slice(body_len.to_be_bytes().get(1..).unwrap_or(&[]));
        buffer.extend_from_slice(body);
        let entry_end = buffer.len();
        Ok(Self { buffer, entry_end })
    }

    /// The input for an SCT with `timestamp_ms` and `extensions`.
    pub(super) fn message(&mut self, timestamp_ms: u64, extensions: &[u8]) -> Option<&[u8]> {
        let extensions_len = u16::try_from(extensions.len()).ok()?;
        self.buffer.truncate(self.entry_end);
        self.buffer
            .get_mut(TIMESTAMP_OFFSET..TIMESTAMP_OFFSET + 8)?
            .copy_from_slice(&timestamp_ms.to_be_bytes());
        self.buffer.extend_from_slice(&extensions_len.to_be_bytes());
        self.buffer.extend_from_slice(extensions);
        Some(&self.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn headers_are_minimal() {
        for (len, expected) in [
            (0usize, vec![0x30, 0x00]),
            (0x7f, vec![0x30, 0x7f]),
            (0x80, vec![0x30, 0x81, 0x80]),
            (0xff, vec![0x30, 0x81, 0xff]),
            (0x100, vec![0x30, 0x82, 0x01, 0x00]),
            (0xffff, vec![0x30, 0x82, 0xff, 0xff]),
        ] {
            let mut out = Vec::new();
            push_header(&mut out, tag::SEQUENCE, len).unwrap();
            assert_eq!(out, expected);
            assert_eq!(header_len(len), expected.len());
        }
        assert_eq!(
            push_header(&mut Vec::new(), tag::SEQUENCE, 0x1_0000),
            Err(SctError::MalformedCertificate)
        );
    }

    #[test]
    fn signed_input_layout() {
        let mut x509 = SignedInput::new(SignedEntry::X509(b"cert")).unwrap();
        assert_eq!(
            x509.message(0x0102_0304_0506_0708, b"xy").unwrap(),
            b"\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x04cert\x00\x02xy"
        );
        // Reuse replaces the timestamp and the extensions.
        assert_eq!(
            x509.message(1, b"").unwrap(),
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x04cert\x00\x00"
        );
        let hash = [0x11; 32];
        let mut precert = SignedInput::new(SignedEntry::Precert {
            issuer_key_hash: &hash,
            tbs: b"tbs",
        })
        .unwrap();
        let mut expected = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01".to_vec();
        expected.extend(hash);
        expected.extend(b"\x00\x00\x03tbs\x00\x00");
        assert_eq!(precert.message(2, b"").unwrap(), expected);
        assert!(SignedInput::new(SignedEntry::X509(b"")).is_err());
    }

    /// A DER element.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_header(&mut out, tag, contents.len()).unwrap();
        out.extend_from_slice(contents);
        out
    }

    fn extension(oid: &[u8], value: &[u8]) -> Vec<u8> {
        let contents = [tlv(tag::OID, oid), tlv(tag::OCTET_STRING, value)].concat();
        tlv(tag::SEQUENCE, &contents)
    }

    /// A syntactically valid certificate with a public key of `key_len`
    /// octets and the given extensions (`None` omits the field).
    fn certificate(key_len: usize, extensions: Option<&[Vec<u8>]>) -> Vec<u8> {
        let algorithm = tlv(tag::SEQUENCE, &tlv(tag::OID, &[0x2b, 0x65, 0x70]));
        let time = tlv(tag::UTC_TIME, b"240101000000Z");
        let mut key = vec![0u8];
        key.resize(key_len + 1, 0x5a);
        let mut tbs = [
            tlv(tag::context_constructed(0), &tlv(tag::INTEGER, &[2])),
            tlv(tag::INTEGER, &[1]),
            algorithm.clone(),
            tlv(tag::SEQUENCE, &[]),
            tlv(tag::SEQUENCE, &[time.clone(), time].concat()),
            tlv(tag::SEQUENCE, &[]),
            tlv(
                tag::SEQUENCE,
                &[algorithm.clone(), tlv(tag::BIT_STRING, &key)].concat(),
            ),
        ]
        .concat();
        if let Some(extensions) = extensions {
            tbs.extend(tlv(
                EXTENSIONS_TAG,
                &tlv(tag::SEQUENCE, &extensions.concat()),
            ));
        }
        let contents = [
            tlv(tag::SEQUENCE, &tbs),
            algorithm,
            tlv(tag::BIT_STRING, &[0, 1, 2, 3]),
        ]
        .concat();
        tlv(tag::SEQUENCE, &contents)
    }

    const OTHER_OID: &[u8] = &[0x2a, 0x03, 0x04];
    const OTHER_OID_2: &[u8] = &[0x2a, 0x03, 0x05];

    /// Removing the extension yields, octet for octet, the certificate
    /// that never had it, whatever length encodings change on the way.
    #[test]
    fn removes_the_sct_list_extension() {
        let sct = extension(EMBEDDED_SCT_LIST_OID, &tlv(tag::OCTET_STRING, &[0x77; 40]));
        let first = extension(OTHER_OID, &[0x05, 0x00]);
        let last = extension(OTHER_OID_2, &[0x04, 0x01, 0x09]);
        let layouts = [
            (vec![sct.clone()], None),
            (vec![sct.clone(), first.clone()], Some(vec![first.clone()])),
            (vec![first.clone(), sct.clone()], Some(vec![first.clone()])),
            (
                vec![first.clone(), sct.clone(), last.clone()],
                Some(vec![first.clone(), last.clone()]),
            ),
            (
                vec![last.clone(), first.clone(), sct.clone()],
                Some(vec![last.clone(), first.clone()]),
            ),
        ];
        // Key lengths sweep every element across the one-, two- and
        // three-octet length forms.
        for key_len in 1..=300 {
            for (with, without) in &layouts {
                let with = certificate(key_len, Some(with.as_slice()));
                let without = certificate(key_len, without.as_deref());
                let with = Cert::from_der(&with).unwrap();
                let without = Cert::from_der(&without).unwrap();
                let rebuilt = tbs_without_sct_list(&with).unwrap();
                assert_eq!(rebuilt.tbs, without.signed.data, "key length {key_len}");
                assert_eq!(
                    rebuilt.sct_list_extension,
                    Some(&tlv(tag::OCTET_STRING, &[0x77; 40])[..])
                );
            }
        }
    }

    #[test]
    fn leaves_other_certificates_unchanged() {
        for extensions in [
            None,
            Some(vec![]),
            Some(vec![extension(OTHER_OID, &[5, 0])]),
        ] {
            let der = certificate(32, extensions.as_deref());
            let cert = Cert::from_der(&der).unwrap();
            let rebuilt = tbs_without_sct_list(&cert).unwrap();
            assert_eq!(rebuilt.tbs, cert.signed.data);
            assert_eq!(rebuilt.sct_list_extension, None);
        }
    }

    #[test]
    fn rejects_a_second_sct_list_extension() {
        let sct = extension(EMBEDDED_SCT_LIST_OID, &[0x04, 0x00]);
        let der = certificate(32, Some(&[sct.clone(), sct][..]));
        let cert = Cert::from_der(&der).unwrap();
        assert_eq!(
            tbs_without_sct_list(&cert).map(|parts| parts.tbs),
            Err(SctError::DuplicateSctExtension)
        );
    }
}
