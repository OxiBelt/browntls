//! Merkle Tree functions of RFC 9162 §2.1 over SHA-256, with the hash
//! injected: leaf and node hashes, the Merkle Tree Hash of a list of
//! entries (§2.1.1, computed as §2.1.2 describes), and the verification of
//! inclusion proofs (§2.1.3.2) and of consistency proofs (§2.1.4.2).
//!
//! The proof verifications follow the RFC algorithms step by step. Paths
//! longer than any tree with a 64-bit size can need are rejected before
//! anything is hashed, so a verification computes at most 65 hashes.

use alloc::vec::Vec;
use core::fmt;

use super::codec::MerklePath;
use super::{HASH_SIZE, Sha256};

/// Longest inclusion path of a tree of fewer than 2^64 leaves:
/// `ceil(log2(tree_size))`.
pub const MAX_INCLUSION_PATH_LEN: usize = 64;

/// Longest consistency path of a tree of fewer than 2^64 leaves:
/// `ceil(log2(tree_size)) + 1` (RFC 9162 §2.1.4.1).
pub const MAX_CONSISTENCY_PATH_LEN: usize = 65;

/// Why a Merkle proof does not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MerkleError {
    /// The leaf index is not below the tree size (§2.1.3.2 step 1).
    LeafIndexOutOfRange,
    /// The tree sizes of a consistency proof are not `0 < first <= second`.
    InvalidTreeSizes,
    /// The path is longer than [`MAX_INCLUSION_PATH_LEN`] or
    /// [`MAX_CONSISTENCY_PATH_LEN`].
    PathTooLong,
    /// A consistency path between different tree sizes is empty
    /// (§2.1.4.2 step 1), or one between equal sizes is not (§5.3).
    WrongPathLength,
    /// The path has more nodes than the tree sizes call for, or fewer
    /// (`sn` reached 0 before the end of the path, or did not reach it).
    PathLengthMismatch,
    /// The computed root differs from the expected one.
    RootMismatch,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for MerkleError {}

/// The hash of a leaf, `HASH(0x00 || entry)` (§2.1.1), where `entry` is a
/// serialized `TransItem` of type `x509_entry_v2` or `precert_entry_v2`
/// (§4.7).
#[must_use]
pub fn leaf_hash(sha256: Sha256, entry: &[u8]) -> [u8; HASH_SIZE] {
    let mut input = Vec::with_capacity(entry.len().saturating_add(1));
    input.push(0x00);
    input.extend_from_slice(entry);
    sha256(&input)
}

/// The hash of an interior node, `HASH(0x01 || left || right)` (§2.1.1).
#[must_use]
pub fn node_hash(
    sha256: Sha256,
    left: &[u8; HASH_SIZE],
    right: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut input = [0u8; 1 + 2 * HASH_SIZE];
    let (prefix, children) = input.split_at_mut(1);
    let (l, r) = children.split_at_mut(HASH_SIZE);
    prefix.copy_from_slice(&[0x01]);
    l.copy_from_slice(left);
    r.copy_from_slice(right);
    sha256(&input)
}

/// The Merkle Tree Hash `MTH(D_n)` of the entries `D_n` (§2.1.1), computed
/// with the stack algorithm of §2.1.2: `HASH()` for no entry. Memory is one
/// hash per level, whatever the number of entries.
#[must_use]
pub fn merkle_tree_hash<I>(sha256: Sha256, entries: I) -> [u8; HASH_SIZE]
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    root_from_leaf_hashes(
        sha256,
        entries
            .into_iter()
            .map(|entry| leaf_hash(sha256, entry.as_ref())),
    )
}

/// The Merkle Tree Hash of a tree whose leaf hashes (not entries) are
/// given, in order (§2.1.2): `HASH()` for no leaf.
#[must_use]
pub fn root_from_leaf_hashes<I>(sha256: Sha256, leaf_hashes: I) -> [u8; HASH_SIZE]
where
    I: IntoIterator<Item = [u8; HASH_SIZE]>,
{
    // At most one hash per bit of the index: 65 levels.
    let mut stack: Vec<[u8; HASH_SIZE]> = Vec::new();
    let mut index = 0u64;
    for leaf in leaf_hashes {
        // Step 2a.
        stack.push(leaf);
        // Step 2b: the number of consecutive 1s from the least significant
        // bit of the index.
        let merge_count = index.trailing_ones();
        // Step 2c.
        for _ in 0..merge_count {
            merge(sha256, &mut stack);
        }
        index = index.wrapping_add(1);
    }
    // Step 3.
    while stack.len() > 1 {
        merge(sha256, &mut stack);
    }
    // Step 4.
    stack.pop().unwrap_or_else(|| sha256(&[]))
}

/// Replaces the two top hashes of the stack with their node hash (§2.1.2
/// step 2c i to iii).
fn merge(sha256: Sha256, stack: &mut Vec<[u8; HASH_SIZE]>) {
    let (Some(right), Some(left)) = (stack.pop(), stack.pop()) else {
        return;
    };
    stack.push(node_hash(sha256, &left, &right));
}

/// Verifies that the leaf whose hash is `leaf_hash` is at `leaf_index` in
/// the tree of `tree_size` leaves whose root is `root_hash`, with the
/// algorithm of §2.1.3.2.
///
/// `tree_size` must be the size that a verified or trusted tree head carries
/// together with `root_hash`: a path does not bind the size, and the same
/// path can verify against the same root at other sizes.
///
/// # Errors
///
/// [`MerkleError::LeafIndexOutOfRange`], [`MerkleError::PathTooLong`]
/// (before hashing), [`MerkleError::PathLengthMismatch`] or
/// [`MerkleError::RootMismatch`].
pub fn verify_inclusion(
    sha256: Sha256,
    leaf_hash: &[u8; HASH_SIZE],
    leaf_index: u64,
    tree_size: u64,
    inclusion_path: MerklePath<'_>,
    root_hash: &[u8; HASH_SIZE],
) -> Result<(), MerkleError> {
    // Step 1.
    if leaf_index >= tree_size {
        return Err(MerkleError::LeafIndexOutOfRange);
    }
    if inclusion_path.len() > MAX_INCLUSION_PATH_LEN {
        return Err(MerkleError::PathTooLong);
    }
    // Step 2.
    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    // Step 3.
    let mut r = *leaf_hash;
    // Step 4.
    for p in inclusion_path.iter() {
        // Step 4a.
        if sn == 0 {
            return Err(MerkleError::PathLengthMismatch);
        }
        // Step 4b.
        if fn_ & 1 == 1 || fn_ == sn {
            // Step 4b i.
            r = node_hash(sha256, p, &r);
            // Step 4b ii.
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            // Step 4b, otherwise.
            r = node_hash(sha256, &r, p);
        }
        // Step 4c.
        fn_ >>= 1;
        sn >>= 1;
    }
    // Step 5.
    if sn != 0 {
        return Err(MerkleError::PathLengthMismatch);
    }
    if r != *root_hash {
        return Err(MerkleError::RootMismatch);
    }
    Ok(())
}

/// Verifies that the tree of `second` leaves with root `second_hash`
/// extends the tree of `first` leaves with root `first_hash`.
///
/// For `0 < first < second` this is the algorithm of §2.1.4.2. RFC 9162
/// §5.3 requires the proof between equal sizes to be empty: it then
/// verifies when the two roots are equal. A first tree of size 0 is
/// outside both and rejected, as is `first > second`.
///
/// `first` and `second` must be the sizes that verified or trusted tree
/// heads carry together with `first_hash` and `second_hash`: a path does
/// not bind the sizes.
///
/// # Errors
///
/// [`MerkleError::InvalidTreeSizes`], [`MerkleError::WrongPathLength`],
/// [`MerkleError::PathTooLong`] (before hashing),
/// [`MerkleError::PathLengthMismatch`] or [`MerkleError::RootMismatch`].
pub fn verify_consistency(
    sha256: Sha256,
    first: u64,
    second: u64,
    first_hash: &[u8; HASH_SIZE],
    second_hash: &[u8; HASH_SIZE],
    consistency_path: MerklePath<'_>,
) -> Result<(), MerkleError> {
    if first == 0 || first > second {
        return Err(MerkleError::InvalidTreeSizes);
    }
    if first == second {
        if !consistency_path.is_empty() {
            return Err(MerkleError::WrongPathLength);
        }
        return if first_hash == second_hash {
            Ok(())
        } else {
            Err(MerkleError::RootMismatch)
        };
    }
    // Step 1.
    if consistency_path.is_empty() {
        return Err(MerkleError::WrongPathLength);
    }
    if consistency_path.len() > MAX_CONSISTENCY_PATH_LEN {
        return Err(MerkleError::PathTooLong);
    }
    // Step 2: prepending first_hash makes it the first value of the path.
    let mut path = consistency_path.iter();
    let prepended = first.is_power_of_two();
    let head = if prepended {
        first_hash
    } else {
        path.next().ok_or(MerkleError::WrongPathLength)?
    };
    // Step 3.
    let mut fn_ = first - 1;
    let mut sn = second - 1;
    // Step 4.
    if fn_ & 1 == 1 {
        while fn_ & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
        }
    }
    // Step 5.
    let mut fr = *head;
    let mut sr = *head;
    // Step 6.
    for c in path {
        // Step 6a.
        if sn == 0 {
            return Err(MerkleError::PathLengthMismatch);
        }
        // Step 6b.
        if fn_ & 1 == 1 || fn_ == sn {
            // Step 6b i and ii.
            fr = node_hash(sha256, c, &fr);
            sr = node_hash(sha256, c, &sr);
            // Step 6b iii.
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            // Step 6b, otherwise.
            sr = node_hash(sha256, &sr, c);
        }
        // Step 6c.
        fn_ >>= 1;
        sn >>= 1;
    }
    // Step 7.
    if sn != 0 {
        return Err(MerkleError::PathLengthMismatch);
    }
    if fr != *first_hash || sr != *second_hash {
        return Err(MerkleError::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not a cryptographic hash: enough to tell inputs apart in tests that
    /// only check structure.
    fn toy(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut state = 0xcbf2_9ce4_8422_2325u64 ^ data.len() as u64;
        for (i, slot) in out.iter_mut().enumerate() {
            for &b in data {
                state = (state ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
            }
            state = state.wrapping_add(i as u64).wrapping_mul(0x0100_0000_01b3);
            *slot = (state >> 32) as u8;
        }
        out
    }

    #[test]
    fn hashes_are_domain_separated() {
        assert_eq!(merkle_tree_hash(toy, [[0u8; 0]; 0]), toy(&[]));
        assert_eq!(merkle_tree_hash(toy, [b"a"]), toy(b"\x00a"));
        let (a, b) = (leaf_hash(toy, b"a"), leaf_hash(toy, b"b"));
        let mut node = [1u8].to_vec();
        node.extend(a);
        node.extend(b);
        assert_eq!(node_hash(toy, &a, &b), toy(&node));
        assert_eq!(merkle_tree_hash(toy, [b"a", b"b"]), toy(&node));
    }

    #[test]
    fn bounds_are_checked_before_hashing() {
        fn refuse(_: &[u8]) -> [u8; 32] {
            panic!("hashed")
        }
        let nodes = [[0u8; 32]; 66];
        let root = [0u8; 32];
        assert_eq!(
            verify_inclusion(refuse, &root, 3, 3, MerklePath::from_nodes(&[]), &root),
            Err(MerkleError::LeafIndexOutOfRange)
        );
        assert_eq!(
            verify_inclusion(
                refuse,
                &root,
                0,
                u64::MAX,
                MerklePath::from_nodes(&nodes[..65]),
                &root
            ),
            Err(MerkleError::PathTooLong)
        );
        assert_eq!(
            verify_consistency(
                refuse,
                1,
                u64::MAX,
                &root,
                &root,
                MerklePath::from_nodes(&nodes)
            ),
            Err(MerkleError::PathTooLong)
        );
        assert_eq!(
            verify_consistency(refuse, 3, 3, &root, &root, MerklePath::from_nodes(&[])),
            Ok(())
        );
        assert_eq!(
            verify_consistency(refuse, 0, 3, &root, &root, MerklePath::from_nodes(&[])),
            Err(MerkleError::InvalidTreeSizes)
        );
    }
}
