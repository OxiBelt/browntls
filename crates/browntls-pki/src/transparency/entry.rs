//! The log entry a version 2 SCT signs and a Merkle leaf hashes (RFC 9162
//! §4.7, §8.1.3), built once per entry type and reused for every SCT.

use alloc::vec::Vec;

use super::item::versioned_type;
use super::{HASH_SIZE, TransparencyError};

/// Offset of the timestamp: after the leaf prefix and the type.
const TIMESTAMP_OFFSET: usize = 3;

/// `0x00 || TransItem` of type `x509_entry_v2` or `precert_entry_v2`, of
/// which only the timestamp and the trailing `sct_extensions` differ
/// between SCTs.
///
/// The leading `0x00` is the leaf hash prefix (§2.1.1): the signed message
/// is the buffer without it, the leaf hash input the whole buffer.
pub(super) struct EntryInput {
    buffer: Vec<u8>,
    /// Length of everything before the `sct_extensions` vector.
    entry_end: usize,
}

impl EntryInput {
    /// The entry for a certificate (`precert` false) or a precertificate.
    pub(super) fn new(
        precert: bool,
        issuer_key_hash: &[u8; HASH_SIZE],
        tbs_certificate: &[u8],
    ) -> Result<Self, TransparencyError> {
        let entry_type = if precert {
            versioned_type::PRECERT_ENTRY_V2
        } else {
            versioned_type::X509_ENTRY_V2
        };
        // `opaque TBSCertificate<1..2^24-1>`.
        let tbs_len = u32::try_from(tbs_certificate.len())
            .ok()
            .filter(|len| (1..1 << 24).contains(len))
            .ok_or(TransparencyError::MalformedCertificate)?;
        let mut buffer = Vec::with_capacity(tbs_certificate.len().saturating_add(64));
        buffer.push(0x00);
        buffer.extend_from_slice(&entry_type.to_be_bytes());
        buffer.extend_from_slice(&[0; 8]);
        buffer.push(HASH_SIZE as u8);
        buffer.extend_from_slice(issuer_key_hash);
        buffer.extend_from_slice(tbs_len.to_be_bytes().get(1..).unwrap_or(&[]));
        buffer.extend_from_slice(tbs_certificate);
        let entry_end = buffer.len();
        Ok(Self { buffer, entry_end })
    }

    /// Sets the timestamp and the extensions of an SCT.
    pub(super) fn set(&mut self, timestamp_ms: u64, extensions: &[u8]) -> Option<()> {
        let extensions_len = u16::try_from(extensions.len()).ok()?;
        self.buffer.truncate(self.entry_end);
        self.buffer
            .get_mut(TIMESTAMP_OFFSET..TIMESTAMP_OFFSET + 8)?
            .copy_from_slice(&timestamp_ms.to_be_bytes());
        self.buffer.extend_from_slice(&extensions_len.to_be_bytes());
        self.buffer.extend_from_slice(extensions);
        Some(())
    }

    /// The serialized entry `TransItem`, which the SCT signs.
    pub(super) fn message(&self) -> &[u8] {
        self.buffer.get(1..).unwrap_or(&[])
    }

    /// `0x00 || TransItem`, the input of the leaf hash.
    pub(super) fn leaf_input(&self) -> &[u8] {
        &self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::super::item::{TimestampedCertificateEntryDataV2, TransItem};
    use super::super::{ArtifactExtensions, merkle};
    use super::*;

    #[test]
    fn matches_the_encoded_item() {
        let hash = [5u8; 32];
        for precert in [false, true] {
            let mut input = EntryInput::new(precert, &hash, b"\x30\x01\x00").unwrap();
            for (timestamp_ms, extensions) in [(7u64, &b""[..]), (u64::MAX, b"\x00\x01\x00\x00")] {
                input.set(timestamp_ms, extensions).unwrap();
                let entry = TimestampedCertificateEntryDataV2 {
                    timestamp_ms,
                    issuer_key_hash: &hash,
                    tbs_certificate: b"\x30\x01\x00",
                    sct_extensions: ArtifactExtensions::from_encoded(extensions).unwrap(),
                };
                let item = if precert {
                    TransItem::PrecertEntryV2(entry)
                } else {
                    TransItem::X509EntryV2(entry)
                };
                let encoded = item.encode().unwrap();
                assert_eq!(input.message(), encoded);
                fn sum(data: &[u8]) -> [u8; 32] {
                    let mut out = [0u8; 32];
                    for (i, b) in data.iter().enumerate() {
                        out[i % 32] ^= b.rotate_left(i as u32 % 8);
                    }
                    out
                }
                assert_eq!(sum(input.leaf_input()), merkle::leaf_hash(sum, &encoded));
            }
        }
        assert!(EntryInput::new(false, &hash, b"").is_err());
    }
}
