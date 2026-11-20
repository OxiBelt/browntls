//! The parameters of a CT version 2 log (RFC 9162 §4.1) an application
//! trusts, and the standalone verification of its artifacts.

use core::fmt;

use super::codec::LogId;
use super::item::{
    ConsistencyProofDataV2, InclusionProofDataV2, SignedCertificateTimestampDataV2,
    SignedTreeHeadDataV2,
};
use super::{HASH_SIZE, Sha256, TransparencyError, TreeHead, merkle};
use crate::alg_id::{self, AlgorithmIdentifier};
use crate::error::Error;
use crate::signed_data::{SignedData, Spki};
use crate::types::SignatureVerificationAlgorithm;

/// A log signature algorithm of the RFC 9162 §10.2.2 registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LogSignatureAlgorithm {
    /// `ecdsa_secp256r1_sha256` (0x0403): ECDSA over P-256 with SHA-256,
    /// the signature a DER `ECDSA-Sig-Value`.
    EcdsaSecp256r1Sha256,
    /// `ed25519` (0x0807): PureEdDSA over edwards25519.
    Ed25519,
}

impl LogSignatureAlgorithm {
    /// The TLS `SignatureScheme` value the registry gives the algorithm.
    #[must_use]
    pub fn signature_scheme(self) -> u16 {
        match self {
            Self::EcdsaSecp256r1Sha256 => 0x0403,
            Self::Ed25519 => 0x0807,
        }
    }

    /// The X.509 `AlgorithmIdentifier` the signatures are verified under.
    fn signature_alg_id(self) -> AlgorithmIdentifier {
        match self {
            Self::EcdsaSecp256r1Sha256 => alg_id::ECDSA_SHA256,
            Self::Ed25519 => alg_id::ED25519,
        }
    }

    /// The algorithm of a key with this `SubjectPublicKeyInfo` algorithm.
    fn for_key(spki_algorithm: &[u8]) -> Option<Self> {
        if alg_id::ECDSA_P256.matches_public_key(spki_algorithm) {
            Some(Self::EcdsaSecp256r1Sha256)
        } else if alg_id::ED25519.matches_public_key(spki_algorithm) {
            Some(Self::Ed25519)
        } else {
            None
        }
    }
}

/// A CT version 2 log the application trusts: its ID, its public key, the
/// signature algorithm the key implies, and the SCT timestamps it is
/// trusted for. Its hash algorithm is SHA-256.
#[derive(Clone, PartialEq, Eq)]
pub struct CtV2Log<'a> {
    id: LogId<'a>,
    /// `SubjectPublicKeyInfo`, complete or contents, checked to parse.
    spki: &'a [u8],
    algorithm: LogSignatureAlgorithm,
    /// First trusted SCT timestamp, in milliseconds.
    from_ms: u64,
    /// First SCT timestamp no longer trusted, in milliseconds.
    until_ms: u64,
}

impl<'a> CtV2Log<'a> {
    /// A log with the ID `log_id`, the contents of its `OBJECT IDENTIFIER`
    /// (RFC 9162 §4.4, see [`LogId::new`]), and the public key `spki`, a
    /// complete DER `SubjectPublicKeyInfo` or its contents. A P-256 key
    /// makes an `ecdsa_secp256r1_sha256` log and an Ed25519 key an
    /// `ed25519` log. Every SCT timestamp is trusted until
    /// [`Self::with_timestamp_window`] narrows that.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::MalformedLogId`],
    /// [`TransparencyError::MalformedLogKey`] if `spki` is neither form,
    /// [`TransparencyError::UnsupportedLogKey`] for any other key type.
    pub fn new(log_id: &'a [u8], spki: &'a [u8]) -> Result<Self, TransparencyError> {
        let id = LogId::new(log_id)?;
        let key =
            Spki::from_der_or_contents(spki).map_err(|_| TransparencyError::MalformedLogKey)?;
        let algorithm = LogSignatureAlgorithm::for_key(key.algorithm)
            .ok_or(TransparencyError::UnsupportedLogKey)?;
        Ok(Self {
            id,
            spki,
            algorithm,
            from_ms: 0,
            until_ms: u64::MAX,
        })
    }

    /// Trusts only SCTs whose timestamp, in milliseconds since the Unix
    /// epoch, is at least `from_ms` and less than `until_ms`: for example
    /// until the time a log was retired or distrusted. An empty window
    /// trusts no SCT. Tree heads are not limited by the window.
    #[must_use]
    pub fn with_timestamp_window(mut self, from_ms: u64, until_ms: u64) -> Self {
        self.from_ms = from_ms;
        self.until_ms = until_ms;
        self
    }

    /// The log ID.
    #[must_use]
    pub fn id(&self) -> LogId<'a> {
        self.id
    }

    /// The signature algorithm, derived from the key.
    #[must_use]
    pub fn signature_algorithm(&self) -> LogSignatureAlgorithm {
        self.algorithm
    }

    pub(super) fn trusts_timestamp(&self, timestamp_ms: u64) -> bool {
        (self.from_ms..self.until_ms).contains(&timestamp_ms)
    }

    /// Verifies a signature of the log over `message`.
    pub(super) fn verify_signature(
        &self,
        algs: &[&dyn SignatureVerificationAlgorithm],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        SignedData::from_parts(
            message,
            self.algorithm.signature_alg_id().as_bytes(),
            signature,
        )
        .verify_signature(algs, self.spki)
    }

    /// Verifies an SCT of this log over `entry`, a serialized `TransItem`
    /// of type `x509_entry_v2` or `precert_entry_v2` holding the SCT's
    /// timestamp and extensions (RFC 9162 §4.8): for example a submitter
    /// checking the SCT a log returned (§3).
    ///
    /// The log's timestamp window is not applied.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::LogIdMismatch`],
    /// [`TransparencyError::InvalidExtensions`] and the signature errors of
    /// [`Self::verify_tree_head`].
    pub fn verify_sct(
        &self,
        sct: &SignedCertificateTimestampDataV2<'_>,
        entry: &[u8],
        algs: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<(), TransparencyError> {
        if sct.log_id != self.id {
            return Err(TransparencyError::LogIdMismatch);
        }
        if !sct.sct_extensions.is_ordered() {
            return Err(TransparencyError::InvalidExtensions);
        }
        self.verify_signature(algs, entry, sct.signature)
            .map_err(signature_error)
    }

    /// Verifies a signed tree head of this log (RFC 9162 §4.10) and
    /// returns its tree head.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::LogIdMismatch`],
    /// [`TransparencyError::InvalidExtensions`],
    /// [`TransparencyError::UnsupportedSignatureAlgorithm`] if no algorithm
    /// of `algs` verifies the log's, [`TransparencyError::InvalidSignature`].
    pub fn verify_tree_head(
        &self,
        sth: &SignedTreeHeadDataV2<'_>,
        algs: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<TreeHead, TransparencyError> {
        if sth.log_id != self.id {
            return Err(TransparencyError::LogIdMismatch);
        }
        let head = &sth.tree_head;
        if !head.sth_extensions.is_ordered() {
            return Err(TransparencyError::InvalidExtensions);
        }
        let message = head.encode()?;
        self.verify_signature(algs, &message, sth.signature)
            .map_err(signature_error)?;
        Ok(TreeHead {
            timestamp_ms: head.timestamp_ms,
            tree_size: head.tree_size,
            root_hash: *head.root_hash,
        })
    }

    /// Verifies that the entry whose leaf hash is `leaf_hash`
    /// ([`merkle::leaf_hash`]) is in the tree of `tree_head`, a tree head of
    /// this log the caller verified or trusts, with an inclusion proof of
    /// this log (RFC 9162 §2.1.3.2).
    ///
    /// # Errors
    ///
    /// [`TransparencyError::LogIdMismatch`],
    /// [`TransparencyError::TreeSizeMismatch`] if the proof is for another
    /// tree size, [`TransparencyError::InvalidProof`].
    pub fn verify_inclusion_proof(
        &self,
        sha256: Sha256,
        proof: &InclusionProofDataV2<'_>,
        leaf_hash: &[u8; HASH_SIZE],
        tree_head: &TreeHead,
    ) -> Result<(), TransparencyError> {
        if proof.log_id != self.id {
            return Err(TransparencyError::LogIdMismatch);
        }
        if proof.tree_size != tree_head.tree_size {
            return Err(TransparencyError::TreeSizeMismatch);
        }
        merkle::verify_inclusion(
            sha256,
            leaf_hash,
            proof.leaf_index,
            proof.tree_size,
            proof.inclusion_path,
            &tree_head.root_hash,
        )?;
        Ok(())
    }

    /// Verifies that `newer` extends `older`, two tree heads of this log
    /// the caller verified or trusts, with a consistency proof of this log
    /// ([`merkle::verify_consistency`]).
    ///
    /// # Errors
    ///
    /// [`TransparencyError::LogIdMismatch`],
    /// [`TransparencyError::TreeSizeMismatch`] if the proof's sizes are not
    /// those of `older` and `newer`, [`TransparencyError::InvalidProof`].
    pub fn verify_consistency_proof(
        &self,
        sha256: Sha256,
        proof: &ConsistencyProofDataV2<'_>,
        older: &TreeHead,
        newer: &TreeHead,
    ) -> Result<(), TransparencyError> {
        if proof.log_id != self.id {
            return Err(TransparencyError::LogIdMismatch);
        }
        if proof.tree_size_1 != older.tree_size || proof.tree_size_2 != newer.tree_size {
            return Err(TransparencyError::TreeSizeMismatch);
        }
        merkle::verify_consistency(
            sha256,
            older.tree_size,
            newer.tree_size,
            &older.root_hash,
            &newer.root_hash,
            proof.consistency_path,
        )?;
        Ok(())
    }
}

/// The error of a signature the log's key does not verify.
pub(super) fn signature_error(error: Error) -> TransparencyError {
    match error {
        Error::UnsupportedSignatureAlgorithm | Error::UnsupportedSignatureAlgorithmForPublicKey => {
            TransparencyError::UnsupportedSignatureAlgorithm
        }
        _ => TransparencyError::InvalidSignature,
    }
}

impl fmt::Debug for CtV2Log<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtV2Log")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("from_ms", &self.from_ms)
            .field("until_ms", &self.until_ms)
            .finish_non_exhaustive()
    }
}
