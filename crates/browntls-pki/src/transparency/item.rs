//! `TransItem` (RFC 9162 §4.5) and the structures it carries (§4.7 to
//! §4.12), parsed exactly and encoded.

use alloc::vec::Vec;
use core::fmt;

use super::codec::{ArtifactExtensions, Cursor, LogId, Malformed, MerklePath, put_vec};
use super::{HASH_SIZE, TransparencyError};
use crate::der::HexDebug;

/// `VersionedTransType` values (RFC 9162 §4.5, §10.2.3).
pub mod versioned_type {
    /// `x509_entry_v2`.
    pub const X509_ENTRY_V2: u16 = 0x0100;
    /// `precert_entry_v2`.
    pub const PRECERT_ENTRY_V2: u16 = 0x0101;
    /// `x509_sct_v2`.
    pub const X509_SCT_V2: u16 = 0x0102;
    /// `precert_sct_v2`.
    pub const PRECERT_SCT_V2: u16 = 0x0103;
    /// `signed_tree_head_v2`.
    pub const SIGNED_TREE_HEAD_V2: u16 = 0x0104;
    /// `consistency_proof_v2`.
    pub const CONSISTENCY_PROOF_V2: u16 = 0x0105;
    /// `inclusion_proof_v2`.
    pub const INCLUSION_PROOF_V2: u16 = 0x0106;
}

use versioned_type as vt;

/// `TimestampedCertificateEntryDataV2` (RFC 9162 §4.7): a log entry, the
/// body of `x509_entry_v2` and `precert_entry_v2` items. The serialized
/// `TransItem` holding it is what an SCT signs and what a Merkle leaf
/// hashes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TimestampedCertificateEntryDataV2<'a> {
    /// `timestamp`: milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// `issuer_key_hash`: SHA-256 of the issuer's DER
    /// `SubjectPublicKeyInfo`.
    pub issuer_key_hash: &'a [u8; HASH_SIZE],
    /// `tbs_certificate`: the DER `TBSCertificate` (1 to 2^24-1 octets).
    pub tbs_certificate: &'a [u8],
    /// `sct_extensions`, identical to those of the SCT.
    pub sct_extensions: ArtifactExtensions<'a>,
}

impl<'a> TimestampedCertificateEntryDataV2<'a> {
    fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        let timestamp_ms = cursor.u64()?;
        let issuer_key_hash =
            <&[u8; HASH_SIZE]>::try_from(cursor.vec8(HASH_SIZE)?).map_err(|_| Malformed)?;
        Ok(Self {
            timestamp_ms,
            issuer_key_hash,
            tbs_certificate: cursor.vec24()?,
            sct_extensions: ArtifactExtensions::read(cursor)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        put_vec(out, 1, HASH_SIZE, self.issuer_key_hash)?;
        put_vec(out, 3, 1, self.tbs_certificate)?;
        self.sct_extensions.write(out)
    }
}

impl fmt::Debug for TimestampedCertificateEntryDataV2<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimestampedCertificateEntryDataV2")
            .field("timestamp_ms", &self.timestamp_ms)
            .field("issuer_key_hash", &HexDebug(self.issuer_key_hash))
            .field("tbs_certificate_len", &self.tbs_certificate.len())
            .field("sct_extensions", &self.sct_extensions)
            .finish()
    }
}

/// `SignedCertificateTimestampDataV2` (RFC 9162 §4.8): the body of
/// `x509_sct_v2` and `precert_sct_v2` items.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignedCertificateTimestampDataV2<'a> {
    /// `log_id`.
    pub log_id: LogId<'a>,
    /// `timestamp`: milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// `sct_extensions`.
    pub sct_extensions: ArtifactExtensions<'a>,
    /// `signature` over the entry (1 to 65535 octets).
    pub signature: &'a [u8],
}

impl<'a> SignedCertificateTimestampDataV2<'a> {
    fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        Ok(Self {
            log_id: LogId::read(cursor)?,
            timestamp_ms: cursor.u64()?,
            sct_extensions: ArtifactExtensions::read(cursor)?,
            signature: cursor.vec16(1)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        self.log_id.write(out)?;
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        self.sct_extensions.write(out)?;
        put_vec(out, 2, 1, self.signature)
    }
}

impl fmt::Debug for SignedCertificateTimestampDataV2<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedCertificateTimestampDataV2")
            .field("log_id", &self.log_id)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("sct_extensions", &self.sct_extensions)
            .field("signature", &HexDebug(self.signature))
            .finish()
    }
}

/// `TreeHeadDataV2` (RFC 9162 §4.9): what a signed tree head signs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TreeHeadDataV2<'a> {
    /// `timestamp`: milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// `tree_size`: the number of entries in the tree.
    pub tree_size: u64,
    /// `root_hash`: the Merkle Tree Hash of the tree.
    pub root_hash: &'a [u8; HASH_SIZE],
    /// `sth_extensions`.
    pub sth_extensions: ArtifactExtensions<'a>,
}

impl<'a> TreeHeadDataV2<'a> {
    fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        let timestamp_ms = cursor.u64()?;
        let tree_size = cursor.u64()?;
        let root_hash =
            <&[u8; HASH_SIZE]>::try_from(cursor.vec8(HASH_SIZE)?).map_err(|_| Malformed)?;
        Ok(Self {
            timestamp_ms,
            tree_size,
            root_hash,
            sth_extensions: ArtifactExtensions::read(cursor)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(&self.tree_size.to_be_bytes());
        put_vec(out, 1, HASH_SIZE, self.root_hash)?;
        self.sth_extensions.write(out)
    }

    /// The encoding of the structure: the message a log signs for a signed
    /// tree head (RFC 9162 §4.10).
    ///
    /// # Errors
    ///
    /// [`TransparencyError::UnencodableItem`] if the extensions are too
    /// long to encode (never for parsed values).
    pub fn encode(&self) -> Result<Vec<u8>, TransparencyError> {
        let mut out =
            Vec::with_capacity(53usize.saturating_add(self.sth_extensions.as_bytes().len()));
        self.write(&mut out)?;
        Ok(out)
    }
}

impl fmt::Debug for TreeHeadDataV2<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreeHeadDataV2")
            .field("timestamp_ms", &self.timestamp_ms)
            .field("tree_size", &self.tree_size)
            .field("root_hash", &HexDebug(self.root_hash))
            .field("sth_extensions", &self.sth_extensions)
            .finish()
    }
}

/// `SignedTreeHeadDataV2` (RFC 9162 §4.10): the body of a
/// `signed_tree_head_v2` item.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignedTreeHeadDataV2<'a> {
    /// `log_id`.
    pub log_id: LogId<'a>,
    /// `tree_head`, the signed structure.
    pub tree_head: TreeHeadDataV2<'a>,
    /// `signature` over `tree_head` (1 to 65535 octets).
    pub signature: &'a [u8],
}

impl<'a> SignedTreeHeadDataV2<'a> {
    fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        Ok(Self {
            log_id: LogId::read(cursor)?,
            tree_head: TreeHeadDataV2::read(cursor)?,
            signature: cursor.vec16(1)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        self.log_id.write(out)?;
        self.tree_head.write(out)?;
        put_vec(out, 2, 1, self.signature)
    }
}

impl fmt::Debug for SignedTreeHeadDataV2<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedTreeHeadDataV2")
            .field("log_id", &self.log_id)
            .field("tree_head", &self.tree_head)
            .field("signature", &HexDebug(self.signature))
            .finish()
    }
}

/// `ConsistencyProofDataV2` (RFC 9162 §4.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsistencyProofDataV2<'a> {
    /// `log_id`.
    pub log_id: LogId<'a>,
    /// `tree_size_1`: the size of the older tree.
    pub tree_size_1: u64,
    /// `tree_size_2`: the size of the newer tree.
    pub tree_size_2: u64,
    /// `consistency_path`.
    pub consistency_path: MerklePath<'a>,
}

impl<'a> ConsistencyProofDataV2<'a> {
    fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        Ok(Self {
            log_id: LogId::read(cursor)?,
            tree_size_1: cursor.u64()?,
            tree_size_2: cursor.u64()?,
            consistency_path: MerklePath::read(cursor)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        self.log_id.write(out)?;
        out.extend_from_slice(&self.tree_size_1.to_be_bytes());
        out.extend_from_slice(&self.tree_size_2.to_be_bytes());
        self.consistency_path.write(out)
    }
}

/// `InclusionProofDataV2` (RFC 9162 §4.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InclusionProofDataV2<'a> {
    /// `log_id`.
    pub log_id: LogId<'a>,
    /// `tree_size`: the size of the tree the proof is for.
    pub tree_size: u64,
    /// `leaf_index`: the 0-based index of the entry.
    pub leaf_index: u64,
    /// `inclusion_path`.
    pub inclusion_path: MerklePath<'a>,
}

impl<'a> InclusionProofDataV2<'a> {
    fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        Ok(Self {
            log_id: LogId::read(cursor)?,
            tree_size: cursor.u64()?,
            leaf_index: cursor.u64()?,
            inclusion_path: MerklePath::read(cursor)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        self.log_id.write(out)?;
        out.extend_from_slice(&self.tree_size.to_be_bytes());
        out.extend_from_slice(&self.leaf_index.to_be_bytes());
        self.inclusion_path.write(out)
    }
}

/// A `TransItem` (RFC 9162 §4.5): a versioned CT structure.
///
/// Parsing is exact for the seven types RFC 9162 defines. Any other
/// `versioned_type` is kept as [`TransItem::Unknown`], which RFC 9162 §6.3
/// lets clients skip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransItem<'a> {
    /// `x509_entry_v2`: a log entry for a certificate.
    X509EntryV2(TimestampedCertificateEntryDataV2<'a>),
    /// `precert_entry_v2`: a log entry for a precertificate.
    PrecertEntryV2(TimestampedCertificateEntryDataV2<'a>),
    /// `x509_sct_v2`: an SCT for a certificate.
    X509SctV2(SignedCertificateTimestampDataV2<'a>),
    /// `precert_sct_v2`: an SCT for a precertificate.
    PrecertSctV2(SignedCertificateTimestampDataV2<'a>),
    /// `signed_tree_head_v2`.
    SignedTreeHeadV2(SignedTreeHeadDataV2<'a>),
    /// `consistency_proof_v2`.
    ConsistencyProofV2(ConsistencyProofDataV2<'a>),
    /// `inclusion_proof_v2`.
    InclusionProofV2(InclusionProofDataV2<'a>),
    /// A type RFC 9162 does not define, with its body uninterpreted.
    Unknown {
        /// The `versioned_type`; never one of [`versioned_type`]'s.
        versioned_type: u16,
        /// The octets after it.
        data: &'a [u8],
    },
}

impl<'a> TransItem<'a> {
    /// Parses one serialized `TransItem`, which must be exactly the
    /// structure its type defines.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::MalformedItem`] if `serialized` is shorter than
    /// a type, or a defined type's body has a vector out of its bounds, a
    /// hash of another length than [`HASH_SIZE`], a log ID that is not an
    /// object identifier, extensions that are not whole `Extension`
    /// structures, or octets left over.
    pub fn parse(serialized: &'a [u8]) -> Result<Self, TransparencyError> {
        Self::read(serialized).map_err(|_| TransparencyError::MalformedItem)
    }

    pub(super) fn read(serialized: &'a [u8]) -> Result<Self, Malformed> {
        let mut cursor = Cursor(serialized);
        let versioned_type = cursor.u16()?;
        let item = match versioned_type {
            vt::X509_ENTRY_V2 => {
                Self::X509EntryV2(TimestampedCertificateEntryDataV2::read(&mut cursor)?)
            }
            vt::PRECERT_ENTRY_V2 => {
                Self::PrecertEntryV2(TimestampedCertificateEntryDataV2::read(&mut cursor)?)
            }
            vt::X509_SCT_V2 => {
                Self::X509SctV2(SignedCertificateTimestampDataV2::read(&mut cursor)?)
            }
            vt::PRECERT_SCT_V2 => {
                Self::PrecertSctV2(SignedCertificateTimestampDataV2::read(&mut cursor)?)
            }
            vt::SIGNED_TREE_HEAD_V2 => {
                Self::SignedTreeHeadV2(SignedTreeHeadDataV2::read(&mut cursor)?)
            }
            vt::CONSISTENCY_PROOF_V2 => {
                Self::ConsistencyProofV2(ConsistencyProofDataV2::read(&mut cursor)?)
            }
            vt::INCLUSION_PROOF_V2 => {
                Self::InclusionProofV2(InclusionProofDataV2::read(&mut cursor)?)
            }
            _ => {
                return Ok(Self::Unknown {
                    versioned_type,
                    data: cursor.0,
                });
            }
        };
        cursor.finish()?;
        Ok(item)
    }

    /// The `versioned_type`.
    #[must_use]
    pub fn versioned_type(&self) -> u16 {
        match self {
            Self::X509EntryV2(_) => vt::X509_ENTRY_V2,
            Self::PrecertEntryV2(_) => vt::PRECERT_ENTRY_V2,
            Self::X509SctV2(_) => vt::X509_SCT_V2,
            Self::PrecertSctV2(_) => vt::PRECERT_SCT_V2,
            Self::SignedTreeHeadV2(_) => vt::SIGNED_TREE_HEAD_V2,
            Self::ConsistencyProofV2(_) => vt::CONSISTENCY_PROOF_V2,
            Self::InclusionProofV2(_) => vt::INCLUSION_PROOF_V2,
            Self::Unknown { versioned_type, .. } => *versioned_type,
        }
    }

    /// Whether the item is an SCT (`x509_sct_v2` or `precert_sct_v2`).
    #[must_use]
    pub fn is_sct(&self) -> bool {
        is_sct_type(self.versioned_type())
    }

    /// Serializes the item.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::UnencodableItem`] if a field is outside the
    /// bounds of its vector (an empty signature or `TBSCertificate`, more
    /// than 65535 octets of extensions, signature or path), or for an
    /// [`TransItem::Unknown`] item whose type RFC 9162 defines.
    pub fn encode(&self) -> Result<Vec<u8>, TransparencyError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    pub(super) fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        let versioned_type = self.versioned_type();
        out.extend_from_slice(&versioned_type.to_be_bytes());
        match self {
            Self::X509EntryV2(entry) | Self::PrecertEntryV2(entry) => entry.write(out),
            Self::X509SctV2(sct) | Self::PrecertSctV2(sct) => sct.write(out),
            Self::SignedTreeHeadV2(sth) => sth.write(out),
            Self::ConsistencyProofV2(proof) => proof.write(out),
            Self::InclusionProofV2(proof) => proof.write(out),
            Self::Unknown { data, .. } => {
                if is_defined_type(versioned_type) {
                    return Err(TransparencyError::UnencodableItem);
                }
                out.extend_from_slice(data);
                Ok(())
            }
        }
    }
}

/// Whether RFC 9162 defines `versioned_type`.
fn is_defined_type(versioned_type: u16) -> bool {
    (vt::X509_ENTRY_V2..=vt::INCLUSION_PROOF_V2).contains(&versioned_type)
}

/// Whether `versioned_type` is an SCT type.
pub(super) fn is_sct_type(versioned_type: u16) -> bool {
    matches!(versioned_type, vt::X509_SCT_V2 | vt::PRECERT_SCT_V2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const LOG: &[u8] = &[0x2b, 0x65, 0x50, 0x07];

    fn items() -> Vec<Vec<u8>> {
        let log_id = LogId::new(LOG).unwrap();
        let hash = [7u8; 32];
        let nodes = [[1u8; 32], [2; 32], [3; 32]];
        let extensions = ArtifactExtensions::from_encoded(b"\x00\x05\x00\x01z").unwrap();
        let entry = TimestampedCertificateEntryDataV2 {
            timestamp_ms: 1,
            issuer_key_hash: &hash,
            tbs_certificate: b"\x30\x00",
            sct_extensions: extensions,
        };
        let sct = SignedCertificateTimestampDataV2 {
            log_id,
            timestamp_ms: 2,
            sct_extensions: ArtifactExtensions::EMPTY,
            signature: b"sig",
        };
        let tree_head = TreeHeadDataV2 {
            timestamp_ms: 3,
            tree_size: 4,
            root_hash: &hash,
            sth_extensions: extensions,
        };
        [
            TransItem::X509EntryV2(entry),
            TransItem::PrecertEntryV2(entry),
            TransItem::X509SctV2(sct),
            TransItem::PrecertSctV2(sct),
            TransItem::SignedTreeHeadV2(SignedTreeHeadDataV2 {
                log_id,
                tree_head,
                signature: b"s",
            }),
            TransItem::ConsistencyProofV2(ConsistencyProofDataV2 {
                log_id,
                tree_size_1: 5,
                tree_size_2: 6,
                consistency_path: MerklePath::from_nodes(&nodes),
            }),
            TransItem::InclusionProofV2(InclusionProofDataV2 {
                log_id,
                tree_size: 7,
                leaf_index: 8,
                inclusion_path: MerklePath::from_nodes(&[]),
            }),
            TransItem::Unknown {
                versioned_type: 0xe000,
                data: b"",
            },
        ]
        .iter()
        .map(|item| item.encode().unwrap())
        .collect()
    }

    #[test]
    fn round_trips_and_rejects_every_truncation() {
        for (index, bytes) in items().iter().enumerate() {
            let item = TransItem::parse(bytes).unwrap();
            assert_eq!(&item.encode().unwrap(), bytes);
            assert_eq!(item.is_sct(), matches!(index, 2 | 3));
            if matches!(item, TransItem::Unknown { .. }) {
                continue;
            }
            for len in 0..bytes.len() {
                assert_eq!(
                    TransItem::parse(&bytes[..len]),
                    Err(TransparencyError::MalformedItem),
                    "item {index} truncated to {len}"
                );
            }
            let mut long = bytes.clone();
            long.push(0);
            assert_eq!(
                TransItem::parse(&long),
                Err(TransparencyError::MalformedItem)
            );
        }
    }

    #[test]
    fn layout_of_an_entry() {
        let hash = [9u8; 32];
        let entry = TransItem::PrecertEntryV2(TimestampedCertificateEntryDataV2 {
            timestamp_ms: 0x0102_0304_0506_0708,
            issuer_key_hash: &hash,
            tbs_certificate: b"tbs",
            sct_extensions: ArtifactExtensions::EMPTY,
        });
        let mut expected = vec![0x01, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 32];
        expected.extend(hash);
        expected.extend(b"\x00\x00\x03tbs\x00\x00");
        assert_eq!(entry.encode().unwrap(), expected);
    }

    #[test]
    fn unknown_types_are_opaque_but_not_impostors() {
        let item = TransItem::parse(b"\x00\x00anything").unwrap();
        assert_eq!(
            item,
            TransItem::Unknown {
                versioned_type: 0,
                data: b"anything"
            }
        );
        let impostor = TransItem::Unknown {
            versioned_type: vt::X509_SCT_V2,
            data: b"",
        };
        assert_eq!(impostor.encode(), Err(TransparencyError::UnencodableItem));
        assert_eq!(
            TransItem::parse(b"\x01"),
            Err(TransparencyError::MalformedItem)
        );
        // A hash of another length.
        let mut bad = items()[4].clone();
        let at = 2 + 1 + LOG.len() + 16;
        assert_eq!(bad[at], 32);
        bad[at] = 31;
        bad.remove(at + 1);
        assert_eq!(
            TransItem::parse(&bad),
            Err(TransparencyError::MalformedItem)
        );
    }
}
