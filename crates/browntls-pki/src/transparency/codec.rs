//! TLS presentation-language building blocks of RFC 9162 structures: a
//! cursor for exact parsing, vector encoding, and the field types shared by
//! several `TransItem` bodies (`LogID`, log artifact extensions and Merkle
//! paths).

use alloc::vec::Vec;
use core::fmt;

use super::{HASH_SIZE, TransparencyError};
use crate::der::{self, HexDebug, OidDebug};

/// A structure did not parse exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Malformed;

/// A cursor over TLS-encoded bytes.
#[derive(Clone, Debug)]
pub(super) struct Cursor<'a>(pub(super) &'a [u8]);

impl<'a> Cursor<'a> {
    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if n > self.0.len() {
            return Err(Malformed);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Malformed> {
        <&[u8; N]>::try_from(self.take(N)?).map_err(|_| Malformed)
    }

    pub(super) fn u16(&mut self) -> Result<u16, Malformed> {
        Ok(u16::from_be_bytes(*self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_be_bytes(*self.array()?))
    }

    /// An `opaque<min..max>` vector with a one-octet length.
    pub(super) fn vec8(&mut self, min: usize) -> Result<&'a [u8], Malformed> {
        let [len] = *self.array()?;
        let body = self.take(usize::from(len))?;
        if body.len() < min {
            return Err(Malformed);
        }
        Ok(body)
    }

    /// An `opaque<min..2^16-1>` vector.
    pub(super) fn vec16(&mut self, min: usize) -> Result<&'a [u8], Malformed> {
        let len = self.u16()?;
        let body = self.take(usize::from(len))?;
        if body.len() < min {
            return Err(Malformed);
        }
        Ok(body)
    }

    /// An `opaque<1..2^24-1>` vector.
    pub(super) fn vec24(&mut self) -> Result<&'a [u8], Malformed> {
        let [a, b, c] = *self.array()?;
        let len = u32::from_be_bytes([0, a, b, c]);
        let body = self.take(usize::try_from(len).map_err(|_| Malformed)?)?;
        if body.is_empty() {
            return Err(Malformed);
        }
        Ok(body)
    }

    pub(super) fn at_end(&self) -> bool {
        self.0.is_empty()
    }

    /// Fails unless every octet was read.
    pub(super) fn finish(&self) -> Result<(), Malformed> {
        if self.at_end() {
            Ok(())
        } else {
            Err(Malformed)
        }
    }
}

/// Appends an opaque vector of `data` with a length prefix of `width`
/// octets (1, 2 or 3), which must hold between `min` and the largest length
/// the prefix can express.
pub(super) fn put_vec(
    out: &mut Vec<u8>,
    width: usize,
    min: usize,
    data: &[u8],
) -> Result<(), TransparencyError> {
    let len = u32::try_from(data.len()).map_err(|_| TransparencyError::UnencodableItem)?;
    let max = match width {
        1 => 0xff,
        2 => 0xffff,
        _ => 0xff_ffff,
    };
    if data.len() < min || len > max {
        return Err(TransparencyError::UnencodableItem);
    }
    let bytes = len.to_be_bytes();
    let prefix = bytes
        .get(4usize.saturating_sub(width)..)
        .ok_or(TransparencyError::UnencodableItem)?;
    out.extend_from_slice(prefix);
    out.extend_from_slice(data);
    Ok(())
}

/// A log's ID (RFC 9162 §4.4): the DER encoding of the log's `OBJECT
/// IDENTIFIER` without its tag and length, 2 to 127 octets
/// (`opaque LogID<2..127>`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogId<'a>(&'a [u8]);

impl<'a> LogId<'a> {
    /// Shortest encoding of a log ID, in octets.
    pub const MIN_LEN: usize = 2;
    /// Longest encoding of a log ID, in octets.
    pub const MAX_LEN: usize = 127;

    /// A log ID from the contents of its `OBJECT IDENTIFIER`: for example
    /// `[0x2b, 0x65, 0x50, 0x00]` for 1.3.101.80.0. The full DER encoding
    /// is these octets preceded by `0x06` and their length.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::MalformedLogId`] unless `contents` holds 2 to
    /// 127 octets that encode an object identifier.
    pub fn new(contents: &'a [u8]) -> Result<Self, TransparencyError> {
        Self::check(contents).map_err(|_| TransparencyError::MalformedLogId)
    }

    pub(super) fn check(contents: &'a [u8]) -> Result<Self, Malformed> {
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&contents.len())
            || der::check_oid(contents).is_err()
        {
            return Err(Malformed);
        }
        Ok(Self(contents))
    }

    pub(super) fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        Self::check(cursor.vec8(Self::MIN_LEN)?)
    }

    pub(super) fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        put_vec(out, 1, Self::MIN_LEN, self.0)
    }

    /// The `OBJECT IDENTIFIER` contents.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Debug for LogId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LogId").field(&OidDebug(self.0)).finish()
    }
}

/// The log artifact extensions of an SCT or a tree head (RFC 9162 §4.6):
/// the contents of an `Extension extensions<0..2^16-1>` vector, exactly as
/// the log signed them.
///
/// Every value holds whole `Extension` structures. Whether they are in the
/// order RFC 9162 §4.8 and §4.9 require is a separate question
/// ([`Self::is_ordered`]): verification treats an SCT or tree head whose
/// extensions are not as invalid, not as malformed. RFC 9162 defines no
/// extension type, so ordered extensions are otherwise ignored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactExtensions<'a>(&'a [u8]);

impl<'a> ArtifactExtensions<'a> {
    /// No extension.
    pub const EMPTY: Self = Self(&[]);

    /// Extensions from the contents of the vector (without its two-octet
    /// length), for example to build an SCT.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::UnencodableItem`] unless `contents` is at most
    /// 65535 octets of whole `Extension` structures.
    pub fn from_encoded(contents: &'a [u8]) -> Result<Self, TransparencyError> {
        Self::check(contents).map_err(|_| TransparencyError::UnencodableItem)
    }

    fn check(contents: &'a [u8]) -> Result<Self, Malformed> {
        if contents.len() > 0xffff {
            return Err(Malformed);
        }
        let mut cursor = Cursor(contents);
        while !cursor.at_end() {
            cursor.u16()?;
            cursor.vec16(0)?;
        }
        Ok(Self(contents))
    }

    pub(super) fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        Self::check(cursor.vec16(0)?)
    }

    pub(super) fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        put_vec(out, 2, 0, self.0)
    }

    /// The vector contents, as signed.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The extensions, in encoding order.
    #[must_use]
    pub fn iter(&self) -> ArtifactExtensionIter<'a> {
        ArtifactExtensionIter(Cursor(self.0))
    }

    /// Whether the extension types strictly increase: ordered by type,
    /// smallest first, with no type repeated (RFC 9162 §4.8, §4.9).
    #[must_use]
    pub fn is_ordered(&self) -> bool {
        let mut previous: Option<u16> = None;
        for extension in self.iter() {
            if previous.is_some_and(|p| p >= extension.extension_type) {
                return false;
            }
            previous = Some(extension.extension_type);
        }
        true
    }
}

impl fmt::Debug for ArtifactExtensions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// One log artifact `Extension` (RFC 9162 §4.6).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactExtension<'a> {
    /// `extension_type`.
    pub extension_type: u16,
    /// `extension_data`.
    pub data: &'a [u8],
}

impl fmt::Debug for ArtifactExtension<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactExtension")
            .field("extension_type", &self.extension_type)
            .field("data", &HexDebug(self.data))
            .finish()
    }
}

/// An iterator over [`ArtifactExtensions`].
#[derive(Clone, Debug)]
pub struct ArtifactExtensionIter<'a>(Cursor<'a>);

impl<'a> Iterator for ArtifactExtensionIter<'a> {
    type Item = ArtifactExtension<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.at_end() {
            return None;
        }
        // Validated on construction; a failure (impossible) ends the
        // iteration.
        let read = (|| Ok::<_, Malformed>((self.0.u16()?, self.0.vec16(0)?)))();
        match read {
            Ok((extension_type, data)) => Some(ArtifactExtension {
                extension_type,
                data,
            }),
            Err(Malformed) => {
                self.0 = Cursor(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for ArtifactExtensionIter<'_> {}

/// Octets of one encoded `NodeHash` of SHA-256: its length and the hash.
const NODE_LEN: usize = 1 + HASH_SIZE;

/// The nodes of a Merkle inclusion or consistency path (RFC 9162 §2.1.3,
/// §2.1.4): `NodeHash path<0..2^16-1>` where every `NodeHash` is a SHA-256
/// hash of exactly [`HASH_SIZE`] octets.
#[derive(Clone, Copy)]
pub struct MerklePath<'a>(PathRepr<'a>);

#[derive(Clone, Copy, Debug)]
enum PathRepr<'a> {
    /// The vector contents as received, validated.
    Encoded(&'a [u8]),
    /// Nodes given by the application.
    Nodes(&'a [[u8; HASH_SIZE]]),
}

impl<'a> MerklePath<'a> {
    /// A path of the given nodes, from the leaf (or the older tree) towards
    /// the root.
    #[must_use]
    pub fn from_nodes(nodes: &'a [[u8; HASH_SIZE]]) -> Self {
        Self(PathRepr::Nodes(nodes))
    }

    pub(super) fn read(cursor: &mut Cursor<'a>) -> Result<Self, Malformed> {
        let contents = cursor.vec16(0)?;
        let mut nodes = Cursor(contents);
        while !nodes.at_end() {
            if nodes.vec8(0)?.len() != HASH_SIZE {
                return Err(Malformed);
            }
        }
        Ok(Self(PathRepr::Encoded(contents)))
    }

    pub(super) fn write(&self, out: &mut Vec<u8>) -> Result<(), TransparencyError> {
        let len = self.len().saturating_mul(NODE_LEN);
        let len = u16::try_from(len).map_err(|_| TransparencyError::UnencodableItem)?;
        out.extend_from_slice(&len.to_be_bytes());
        for node in self.iter() {
            out.push(HASH_SIZE as u8);
            out.extend_from_slice(node);
        }
        Ok(())
    }

    /// The number of nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.0 {
            PathRepr::Encoded(contents) => contents.len() / NODE_LEN,
            PathRepr::Nodes(nodes) => nodes.len(),
        }
    }

    /// Whether the path has no node.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The nodes, in path order.
    #[must_use]
    pub fn iter(&self) -> MerklePathIter<'a> {
        MerklePathIter(self.0)
    }
}

impl PartialEq for MerklePath<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for MerklePath<'_> {}

impl fmt::Debug for MerklePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|node| HexDebug(node)))
            .finish()
    }
}

/// An iterator over the nodes of a [`MerklePath`].
#[derive(Clone, Debug)]
pub struct MerklePathIter<'a>(PathRepr<'a>);

impl<'a> Iterator for MerklePathIter<'a> {
    type Item = &'a [u8; HASH_SIZE];

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            PathRepr::Nodes(nodes) => {
                let (first, rest) = nodes.split_first()?;
                *nodes = rest;
                Some(first)
            }
            PathRepr::Encoded(contents) => {
                // Validated on construction: each node is a length octet
                // of 32 and 32 octets.
                let (node, rest) = contents.split_at_checked(NODE_LEN)?;
                *contents = rest;
                node.get(1..)
                    .and_then(|hash| <&[u8; HASH_SIZE]>::try_from(hash).ok())
            }
        }
    }
}

impl core::iter::FusedIterator for MerklePathIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn vectors_are_exact() {
        let mut out = Vec::new();
        put_vec(&mut out, 1, 2, b"ab").unwrap();
        put_vec(&mut out, 2, 0, b"").unwrap();
        put_vec(&mut out, 3, 1, b"c").unwrap();
        assert_eq!(out, b"\x02ab\x00\x00\x00\x00\x01c");
        let mut cursor = Cursor(&out);
        assert_eq!(cursor.vec8(2), Ok(&b"ab"[..]));
        assert_eq!(cursor.vec16(0), Ok(&b""[..]));
        assert_eq!(cursor.vec24(), Ok(&b"c"[..]));
        assert!(cursor.finish().is_ok());
        assert_eq!(Cursor(b"\x01a").vec8(2), Err(Malformed));
        assert_eq!(Cursor(b"\x00\x00\x00").vec24(), Err(Malformed));
        assert_eq!(Cursor(b"\x00\x02a").vec16(0), Err(Malformed));
        for (width, min, len) in [(1, 0, 256), (2, 0, 65536), (1, 3, 2), (3, 1, 0)] {
            assert_eq!(
                put_vec(&mut Vec::new(), width, min, &vec![0; len]),
                Err(TransparencyError::UnencodableItem)
            );
        }
    }

    #[test]
    fn log_ids_are_object_identifiers() {
        assert!(LogId::new(&[0x2b, 0x65, 0x50, 0x00]).is_ok());
        for bad in [&[0x2b][..], &[0x2b, 0x80], &[0x2b, 0x81], &[0x80, 0x01]] {
            assert_eq!(LogId::new(bad), Err(TransparencyError::MalformedLogId));
        }
        let mut long = vec![0x2b; 127];
        assert!(LogId::new(&long).is_ok());
        long.push(0x2b);
        assert!(LogId::new(&long).is_err());
    }

    #[test]
    fn extension_order() {
        let ordered = b"\x00\x01\x00\x00\x00\x02\x00\x01x";
        let extensions = ArtifactExtensions::from_encoded(ordered).unwrap();
        assert!(extensions.is_ordered());
        assert_eq!(extensions.iter().count(), 2);
        let repeated = ArtifactExtensions::from_encoded(b"\x00\x01\x00\x00\x00\x01\x00\x00");
        assert!(!repeated.unwrap().is_ordered());
        let reversed = ArtifactExtensions::from_encoded(b"\x00\x02\x00\x00\x00\x01\x00\x00");
        assert!(!reversed.unwrap().is_ordered());
        assert!(ArtifactExtensions::from_encoded(b"\x00\x01\x00").is_err());
        assert!(ArtifactExtensions::EMPTY.is_ordered());
    }

    #[test]
    fn merkle_paths_round_trip() {
        let nodes = [[1u8; 32], [2; 32]];
        let path = MerklePath::from_nodes(&nodes);
        let mut out = Vec::new();
        path.write(&mut out).unwrap();
        assert_eq!(out.len(), 2 + 2 * NODE_LEN);
        let parsed = MerklePath::read(&mut Cursor(&out)).unwrap();
        assert_eq!(parsed, path);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.iter().collect::<Vec<_>>(), [&nodes[0], &nodes[1]]);
        // A node of another length.
        let mut short = out.clone();
        short[1] -= 1;
        short[2] = 31;
        short.pop();
        assert!(MerklePath::read(&mut Cursor(&short)).is_err());
    }
}
