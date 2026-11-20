//! Certificate Transparency version 2.0 (RFC 9162): the `TransItem`
//! structures, Merkle proof verification, and the verification of the SCTs,
//! signed tree heads and inclusion proofs delivered with a certificate
//! against the CT logs an application trusts.
//!
//! This module is independent of TLS. It serves three kinds of caller:
//!
//! * A TLS client hands a [`CtV2Verifier`], bound to one certificate, the
//!   `TransItemList`s of the three RFC 9162 §6 delivery mechanisms, which
//!   RFC 9162 §8.1.1 requires clients to implement all of:
//!
//!   | Source | Method |
//!   |---|---|
//!   | TLS `transparency_info` extension (§6.5) | [`CtV2Verifier::verify_tls_extension`] |
//!   | OCSP `singleExtensions` (§7.1.1) | [`CtV2Verifier::verify_ocsp_response`] |
//!   | Certificate extension (§7.1.2) | [`CtV2Verifier::verify_embedded`] |
//!
//!   and gets back the [`VerifiedSctV2`]s, each with whether its inclusion
//!   in the log was proven ([`InclusionEvidence`]).
//! * A TLS server parses and assembles the lists it staples with
//!   [`TransItemList`] and [`TransItem`], and checks that a list holds an
//!   SCT ([`TransItemList::has_sct`], RFC 9162 §6.4).
//! * An auditor or monitor verifies signed tree heads, inclusion proofs and
//!   consistency proofs on its own ([`CtV2Log::verify_tree_head`],
//!   [`CtV2Log::verify_inclusion_proof`],
//!   [`CtV2Log::verify_consistency_proof`], and the functions of
//!   [`merkle`]).
//!
//! # Verification
//!
//! An SCT (`x509_sct_v2` or `precert_sct_v2`) signs a `TransItem` of type
//! `x509_entry_v2` or `precert_entry_v2` (§4.7, §8.1.3) holding the SCT's
//! timestamp and extensions, the SHA-256 digest of the issuer's
//! `SubjectPublicKeyInfo`, and a `TBSCertificate`:
//!
//! * for `x509_sct_v2`, the certificate's `TBSCertificate` unchanged;
//! * for `precert_sct_v2`, the `TBSCertificate` without the Transparency
//!   Information extension ([`TRANSPARENCY_INFO_OID`]) and without the
//!   version 1 SCT list extension
//!   ([`EMBEDDED_SCT_LIST_OID`](crate::sct::EMBEDDED_SCT_LIST_OID)), as
//!   §8.1.2 reconstructs it. The other octets are copied as encoded; only
//!   the lengths of the enclosing elements are re-encoded. When no other
//!   extension remains, the `extensions` field is omitted, as RFC 5280
//!   requires of an empty list and as version 1 does (§3.2 makes the
//!   precertificate's `TBSCertificate` that of the certificate without the
//!   Transparency Information extension, and a precertificate without
//!   extensions has no `[3]` field).
//!
//! The SCTs of a certificate extension must be for the precertificate
//! (§7.1.2): an `x509_sct_v2` found there is counted as misplaced and not
//! verified. SCTs from the TLS extension and OCSP may be of either type
//! (§7.1.1).
//!
//! An inclusion proof (`inclusion_proof_v2`) shows a verified SCT's entry
//! in its log (§8.1.5): its leaf is `HASH(0x00 || entry)` for the very
//! `TransItem` the SCT signs, checked with the algorithm of §2.1.3.2
//! against the root of a tree head of the same log and the same tree size.
//! The tree head is a `signed_tree_head_v2` delivered by any source of the
//! verifier, whose signature is then verified, or one the application
//! already trusts ([`CtV2Policy::trusted_tree_heads`]). A tree head older
//! than the SCT is not evidence for it, because a log signs a tree head no
//! older than every SCT in the tree (§4.10). Proofs and tree heads may come
//! from another source than the SCT: each verification call tries every
//! proof and tree head received so far against every verified SCT of the
//! same log that has no proven inclusion yet.
//!
//! Consistency proofs (`consistency_proof_v2`) and log entries in a list
//! are not used by the verifier and are counted as ignored; an auditor
//! verifies consistency with [`CtV2Log::verify_consistency_proof`]. Items of
//! a type RFC 9162 does not define are skipped (§6.3).
//!
//! # Caller contract
//!
//! This module verifies log signatures and Merkle proofs and nothing else:
//!
//! * The certificate must be the end entity of a path the caller validated,
//!   and the issuer key the key of its issuer in that path. Every version 2
//!   SCT covers the issuer key hash, so the issuer key is required.
//! * A Transparency Information list from OCSP must come from a response
//!   the caller authenticated and matched to this certificate
//!   ([`VerifiedOcspStatus::transparency_info`](crate::ocsp::VerifiedOcspStatus::transparency_info)).
//! * The CT logs, their IDs, keys, signature algorithms, validity windows
//!   and the tree heads the application trusts are its trust decision
//!   ([`CtV2Log`], [`CtV2Policy`]).
//! * How many SCTs, from which logs and with what inclusion evidence a
//!   connection needs (§8.1.6) is a policy for the caller to apply to
//!   [`CtV2Verifier::verified`]. RFC 9162 §8.1.6 forbids evaluating
//!   compliance unless the client offered both the `transparency_info` and
//!   `status_request` TLS extensions.
//!
//! Out of scope: the HTTP log client messages of §5 (fetching proofs or
//! tree heads from a log), log operation and submission, the entry fetching
//! of monitors, gossip, and the "final STH" log parameter (§4.1).
//!
//! # Algorithms
//!
//! SHA-256 is the only hash algorithm of the RFC 9162 registry (§10.2.1),
//! so every hash in an artifact is [`HASH_SIZE`] octets; any other length is
//! malformed. Log signatures are those of the §10.2.2 registry,
//! `ecdsa_secp256r1_sha256` and `ed25519` ([`LogSignatureAlgorithm`]): a
//! log's algorithm is derived from its key, and a log with another key type
//! cannot be configured.
//!
//! # Untrusted input and bounds
//!
//! Lists and the certificate are peer-controlled. A list is parsed exactly
//! and validated completely before any signature is checked, so a malformed
//! or oversized list contributes nothing. [`CtV2Options`] caps the size of
//! each list, of each SCT's and tree head's extensions and signature, and,
//! across all sources of one verifier, the number of items, of signature
//! verifications and of hash computations for proofs. An SCT or a tree head
//! naming an unknown log costs no signature verification, and a tree head
//! is only verified when a proof needs it. Merkle paths longer than a tree
//! of 2^64 leaves needs are rejected before hashing.
//!
//! This module contains no cryptography: signatures are verified through
//! [`SignatureVerificationAlgorithm`](crate::SignatureVerificationAlgorithm)
//! and SHA-256 is injected ([`Sha256`]). RFC 9162 publishes no hash or
//! signature test vector; the tests check self-consistency against the RFC
//! text.

use core::fmt;

use crate::der::HexDebug;

mod codec;
mod entry;
mod inclusion;
mod item;
mod list;
mod log;
pub mod merkle;
mod policy;
mod verifier;

pub use crate::sct::{SctEntryType, SctSource, Sha256};
pub use codec::{
    ArtifactExtension, ArtifactExtensionIter, ArtifactExtensions, LogId, MerklePath, MerklePathIter,
};
pub use item::{
    ConsistencyProofDataV2, InclusionProofDataV2, SignedCertificateTimestampDataV2,
    SignedTreeHeadDataV2, TimestampedCertificateEntryDataV2, TransItem, TreeHeadDataV2,
    versioned_type,
};
pub use list::{SerializedTransItems, TransItemList, TransItems};
pub use log::{CtV2Log, LogSignatureAlgorithm};
pub use merkle::MerkleError;
pub use policy::{
    CtV2Options, CtV2Policy, CtV2Report, InclusionEvidence, TreeHeadSource, TrustedTreeHead,
    VerifiedSctV2,
};
pub use verifier::CtV2Verifier;

/// Size of a hash in RFC 9162 structures: SHA-256, the only registered
/// algorithm (§10.2.1).
pub const HASH_SIZE: usize = 32;

/// `extnID` contents of the Transparency Information extension
/// (1.3.101.75, RFC 9162 §7.1), in certificates and OCSP single responses.
pub const TRANSPARENCY_INFO_OID: &[u8] = &[0x2b, 0x65, 0x4b];

/// The TLS `ExtensionType` of `transparency_info` (RFC 9162 §6.5).
pub const TRANSPARENCY_INFO_EXTENSION_TYPE: u16 = 52;

/// An error that rejects a source, a verifier input, or an artifact given
/// to a standalone verification.
///
/// Problems of a single item of a list (an unknown log, a bad signature, a
/// proof that does not verify) are not errors of the list: they are counted
/// in the [`CtV2Report`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransparencyError {
    /// A `TransItemList`, or the extension value wrapping it, is not exactly
    /// encoded (see [`TransItemList::parse`]).
    MalformedList,
    /// A serialized `TransItem` is not exactly encoded.
    MalformedItem,
    /// A list is longer than [`CtV2Options::max_list_len`].
    ListTooLarge,
    /// More items were presented, over all sources, than
    /// [`CtV2Options::max_items`].
    TooManyItems,
    /// The extensions or the signature of an SCT or a tree head exceed
    /// [`CtV2Options::max_extensions_len`] or
    /// [`CtV2Options::max_signature_len`].
    ItemTooLarge,
    /// Another signature verification would exceed
    /// [`CtV2Options::max_signature_verifications`].
    SignatureBudgetExceeded,
    /// Another proof would exceed [`CtV2Options::max_hash_operations`].
    HashBudgetExceeded,
    /// The issuer key is not a `SubjectPublicKeyInfo`.
    MalformedIssuerKey,
    /// A log ID is not the contents of an object identifier of 2 to 127
    /// octets.
    MalformedLogId,
    /// A log key is not a `SubjectPublicKeyInfo`.
    MalformedLogKey,
    /// A log key is neither a P-256 nor an Ed25519 key, the only keys of
    /// the RFC 9162 §10.2.2 algorithms.
    UnsupportedLogKey,
    /// The certificate could not be re-encoded without its transparency
    /// extensions.
    MalformedCertificate,
    /// The certificate has more than one Transparency Information or
    /// version 1 SCT list extension.
    DuplicateExtension,
    /// A value cannot be encoded: a field is outside its vector's bounds.
    UnencodableItem,
    /// An artifact names another log than the one verifying it.
    LogIdMismatch,
    /// A proof is for another tree size than the tree head given.
    TreeSizeMismatch,
    /// The extensions of an SCT or a tree head are not ordered by type
    /// without repetition (§4.8, §4.9).
    InvalidExtensions,
    /// The log's key does not verify the signature.
    InvalidSignature,
    /// No algorithm of the policy verifies the log's signature algorithm
    /// with its key.
    UnsupportedSignatureAlgorithm,
    /// A Merkle proof does not verify.
    InvalidProof(MerkleError),
}

impl fmt::Display for TransparencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for TransparencyError {}

impl From<MerkleError> for TransparencyError {
    fn from(error: MerkleError) -> Self {
        Self::InvalidProof(error)
    }
}

/// A tree head whose signature was verified, or that the application
/// trusts: the signed `TreeHeadDataV2` fields without the extensions.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TreeHead {
    /// `timestamp`: milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// `tree_size`.
    pub tree_size: u64,
    /// `root_hash`.
    pub root_hash: [u8; HASH_SIZE],
}

impl fmt::Debug for TreeHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreeHead")
            .field("timestamp_ms", &self.timestamp_ms)
            .field("tree_size", &self.tree_size)
            .field("root_hash", &HexDebug(&self.root_hash))
            .finish()
    }
}
