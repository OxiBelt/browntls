//! What an application trusts for CT version 2, the limits of verification,
//! and what verification reports.

use core::fmt;

use super::codec::LogId;
use super::log::CtV2Log;
use super::{SctEntryType, SctSource, Sha256, TreeHead};
use crate::der::HexDebug;
use crate::types::SignatureVerificationAlgorithm;

/// Resource limits and acceptance options of [`CtV2Verifier`]
/// verification.
///
/// The defaults suit lists as servers and CAs send them: a few SCTs of
/// about 100 octets, with an inclusion proof of up to about 1 KiB and a
/// signed tree head each.
///
/// [`CtV2Verifier`]: super::CtV2Verifier
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CtV2Options {
    /// Largest `TransItemList`, in octets, accepted from one source.
    /// Default 8192.
    pub max_list_len: usize,
    /// Most items accepted over all sources of one verifier, of every type
    /// and counting those that are skipped. Default 32.
    pub max_items: usize,
    /// Most signature verifications (of SCTs and of tree heads) over all
    /// sources of one verifier. Default 16.
    pub max_signature_verifications: usize,
    /// Most SHA-256 computations for inclusion proofs over all sources of
    /// one verifier: one per leaf hash (whose input is a whole entry) and
    /// one per path node. Default 512, eight proofs in trees of 2^63
    /// entries.
    pub max_hash_operations: usize,
    /// Largest extensions of one SCT or tree head, in octets. Default 256.
    pub max_extensions_len: usize,
    /// Largest signature of one SCT or tree head, in octets. Default 128
    /// (a DER P-256 ECDSA signature is at most 72, an Ed25519 one 64).
    pub max_signature_len: usize,
    /// How far, in milliseconds, an SCT timestamp may lie after the
    /// verification time. Default 0: no timestamp from the future.
    pub future_tolerance_ms: u64,
}

impl Default for CtV2Options {
    fn default() -> Self {
        Self {
            max_list_len: 8192,
            max_items: 32,
            max_signature_verifications: 16,
            max_hash_operations: 512,
            max_extensions_len: 256,
            max_signature_len: 128,
            future_tolerance_ms: 0,
        }
    }
}

/// A tree head of a log that the application already trusts, for example
/// one it verified and checked for consistency with earlier ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrustedTreeHead<'a> {
    /// The log the tree head is of.
    pub log_id: LogId<'a>,
    /// The tree head.
    pub tree_head: TreeHead,
}

/// What an application trusts for Certificate Transparency version 2.
#[derive(Clone, Debug)]
pub struct CtV2Policy<'a> {
    /// The trusted logs. The first log with a given ID is used.
    pub logs: &'a [CtV2Log<'a>],
    /// Tree heads the application trusts, which inclusion proofs may be
    /// verified against without a signed tree head in the lists. A tree
    /// head of a log not in [`Self::logs`] is not used.
    pub trusted_tree_heads: &'a [TrustedTreeHead<'a>],
    /// Algorithms for log signatures: the one matching
    /// [`alg_id::ECDSA_SHA256`](crate::alg_id::ECDSA_SHA256) and a P-256
    /// key, and the one matching [`alg_id::ED25519`](crate::alg_id::ED25519).
    pub supported_sig_algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    /// SHA-256, for the issuer key hash and the Merkle tree.
    pub sha256: Sha256,
    /// Limits and options.
    pub options: CtV2Options,
}

/// Where a tree head used as inclusion evidence came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TreeHeadSource {
    /// [`CtV2Policy::trusted_tree_heads`].
    Trusted,
    /// A `signed_tree_head_v2` of a list from this source, whose signature
    /// was verified.
    Delivered(SctSource),
}

/// The proof that a verified SCT's entry is in its log (RFC 9162 §8.1.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct InclusionEvidence {
    /// The size of the tree the entry was shown in.
    pub tree_size: u64,
    /// The index of the entry in that tree.
    pub leaf_index: u64,
    /// The timestamp of the tree head, in milliseconds since the Unix
    /// epoch: never before the SCT's.
    pub tree_head_timestamp_ms: u64,
    /// Where the tree head came from.
    pub tree_head_source: TreeHeadSource,
    /// The source of the inclusion proof.
    pub proof_source: SctSource,
}

/// An SCT whose signature by a trusted log was verified for the
/// verifier's certificate. It owns its data, so it can outlive the
/// verifier, the policy and the lists.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifiedSctV2 {
    log_id: [u8; LogId::MAX_LEN],
    log_id_len: u8,
    log_index: usize,
    timestamp_ms: u64,
    entry_type: SctEntryType,
    source: SctSource,
    pub(super) inclusion: Option<InclusionEvidence>,
}

impl VerifiedSctV2 {
    pub(super) fn new(
        log_id: LogId<'_>,
        log_index: usize,
        timestamp_ms: u64,
        entry_type: SctEntryType,
        source: SctSource,
    ) -> Self {
        let id = log_id.as_bytes();
        let mut buffer = [0u8; LogId::MAX_LEN];
        let len = id.len().min(LogId::MAX_LEN);
        if let (Some(dst), Some(src)) = (buffer.get_mut(..len), id.get(..len)) {
            dst.copy_from_slice(src);
        }
        Self {
            log_id: buffer,
            log_id_len: u8::try_from(len).unwrap_or(0),
            log_index,
            timestamp_ms,
            entry_type,
            source,
            inclusion: None,
        }
    }

    /// The ID of the log that signed the SCT: the contents of its object
    /// identifier.
    #[must_use]
    pub fn log_id(&self) -> &[u8] {
        self.log_id
            .get(..usize::from(self.log_id_len))
            .unwrap_or(&[])
    }

    /// The position of the log in [`CtV2Policy::logs`].
    #[must_use]
    pub fn log_index(&self) -> usize {
        self.log_index
    }

    /// The SCT timestamp, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// The entry type the signature covers: [`SctEntryType::X509`] for an
    /// `x509_sct_v2`, [`SctEntryType::Precert`] for a `precert_sct_v2`.
    #[must_use]
    pub fn entry_type(&self) -> SctEntryType {
        self.entry_type
    }

    /// The source that first delivered the SCT.
    #[must_use]
    pub fn source(&self) -> SctSource {
        self.source
    }

    /// The proof of the SCT's inclusion in its log, if one verified.
    #[must_use]
    pub fn inclusion(&self) -> Option<InclusionEvidence> {
        self.inclusion
    }

    pub(super) fn same_sct(
        &self,
        log_index: usize,
        timestamp_ms: u64,
        entry: SctEntryType,
    ) -> bool {
        self.log_index == log_index && self.timestamp_ms == timestamp_ms && self.entry_type == entry
    }
}

impl fmt::Debug for VerifiedSctV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedSctV2")
            .field("log_id", &HexDebug(self.log_id()))
            .field("log_index", &self.log_index)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("entry_type", &self.entry_type)
            .field("source", &self.source)
            .field("inclusion", &self.inclusion)
            .finish()
    }
}

/// What became of the items of one source.
///
/// Every item of the list is counted in exactly one of the fields from
/// [`Self::verified`] to [`Self::unknown_type`]. The fields after them
/// count outcomes of this call, which may concern items of earlier calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CtV2Report {
    /// SCTs verified and added to the verifier's list.
    pub verified: usize,
    /// SCTs from a trusted log with the timestamp and entry type of an SCT
    /// already verified; not verified again. The key ignores the SCT
    /// extensions, so a second SCT that differs only there is counted here
    /// and an inclusion proof for its entry is not looked for.
    pub duplicate: usize,
    /// SCTs from a log that is not trusted.
    pub unknown_log: usize,
    /// SCTs from a trusted log, with a timestamp outside its validity
    /// window.
    pub outside_log_validity: usize,
    /// SCTs with a timestamp after the verification time and tolerance.
    pub future_timestamp: usize,
    /// SCTs whose extensions are not ordered by type without repetition
    /// (RFC 9162 §4.8).
    pub invalid_extensions: usize,
    /// SCTs with a signature the log's key does not verify.
    pub invalid_signature: usize,
    /// SCTs whose log's algorithm no algorithm of the policy verifies.
    pub unsupported_algorithm: usize,
    /// `x509_sct_v2` items in the certificate's extension, which may only
    /// hold SCTs for the precertificate (RFC 9162 §7.1.2).
    pub misplaced: usize,
    /// Signed tree heads of a trusted log, kept for inclusion proofs.
    pub tree_heads: usize,
    /// Inclusion proofs of a trusted log, kept to be matched with SCTs.
    pub inclusion_proofs: usize,
    /// Log entries, consistency proofs, and tree heads or inclusion proofs
    /// of a log that is not trusted.
    pub ignored: usize,
    /// Items of a type RFC 9162 does not define, skipped (§6.3).
    pub unknown_type: usize,
    /// Verified SCTs, of any source, whose inclusion was proven in this
    /// call.
    pub inclusion_proven: usize,
    /// Signed tree heads, of any source, whose signature was verified in
    /// this call.
    pub tree_heads_verified: usize,
    /// Signed tree heads, of any source, found invalid in this call: bad
    /// signature, misordered extensions or unsupported algorithm.
    pub tree_heads_invalid: usize,
}
