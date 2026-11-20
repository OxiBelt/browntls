//! Matching received inclusion proofs and tree heads with verified SCTs
//! (RFC 9162 §8.1.5).

use super::item::TransItem;
use super::merkle::{self, MAX_INCLUSION_PATH_LEN};
use super::policy::{CtV2Report, InclusionEvidence, TreeHeadSource};
use super::verifier::{CtV2Verifier, HeadState};
use super::{HASH_SIZE, SctEntryType, TransparencyError, TreeHead};

impl CtV2Verifier<'_> {
    /// Tries every unresolved proof against every verified SCT of the same
    /// log without inclusion evidence that it was not tried against yet,
    /// once a tree head of the proof's tree size, no older than the SCT, is
    /// available.
    pub(super) fn resolve_inclusion(
        &mut self,
        report: &mut CtV2Report,
    ) -> Result<(), TransparencyError> {
        for p in 0..self.proofs.len() {
            let Some(proof) = self.proofs.get(p) else {
                break;
            };
            if proof.resolved {
                continue;
            }
            let (log_index, tree_size) = (proof.log_index, proof.tree_size);
            for s in 0..self.verified.len() {
                let Some(sct) = self.verified.get(s) else {
                    break;
                };
                let tried = self
                    .proofs
                    .get(p)
                    .is_none_or(|proof| proof.tried.contains(&s));
                if sct.inclusion.is_some() || sct.log_index() != log_index || tried {
                    continue;
                }
                let timestamp_ms = sct.timestamp_ms();
                let Some((head, head_source)) =
                    self.tree_head_for(log_index, tree_size, timestamp_ms, report)?
                else {
                    // A later source may deliver the tree head.
                    continue;
                };
                if let Some(proof) = self.proofs.get_mut(p) {
                    proof.tried.push(s);
                }
                if let Some(evidence) = self.prove(p, s, &head, head_source)? {
                    if let Some(sct) = self.verified.get_mut(s) {
                        sct.inclusion = Some(evidence);
                    }
                    if let Some(proof) = self.proofs.get_mut(p) {
                        proof.resolved = true;
                    }
                    report.inclusion_proven += 1;
                    break;
                }
            }
        }
        Ok(())
    }

    /// A tree head of the log at `log_index` for `tree_size`, no older than
    /// `timestamp_ms`: a trusted one, or a received one whose signature is
    /// verified here if it was not yet.
    fn tree_head_for(
        &mut self,
        log_index: usize,
        tree_size: u64,
        timestamp_ms: u64,
        report: &mut CtV2Report,
    ) -> Result<Option<(TreeHead, TreeHeadSource)>, TransparencyError> {
        let policy = self.policy;
        let Some(log) = policy.logs.get(log_index) else {
            return Ok(None);
        };
        let usable =
            |head: &TreeHead| head.tree_size == tree_size && head.timestamp_ms >= timestamp_ms;
        let trusted = policy
            .trusted_tree_heads
            .iter()
            .find(|trusted| trusted.log_id == log.id() && usable(&trusted.tree_head));
        if let Some(trusted) = trusted {
            return Ok(Some((trusted.tree_head, TreeHeadSource::Trusted)));
        }
        for stored in &mut self.tree_heads {
            if stored.log_index != log_index || stored.tree_size != tree_size {
                continue;
            }
            if let HeadState::Unverified = stored.state {
                let Ok(TransItem::SignedTreeHeadV2(sth)) = TransItem::parse(&stored.item) else {
                    stored.state = HeadState::Invalid;
                    report.tree_heads_invalid += 1;
                    continue;
                };
                // Misordered extensions cost no signature verification.
                if !sth.tree_head.sth_extensions.is_ordered() {
                    stored.state = HeadState::Invalid;
                    report.tree_heads_invalid += 1;
                    continue;
                }
                self.remaining_signatures = self
                    .remaining_signatures
                    .checked_sub(1)
                    .ok_or(TransparencyError::SignatureBudgetExceeded)?;
                stored.state = HeadState::Invalid;
                match log.verify_tree_head(&sth, policy.supported_sig_algs) {
                    Ok(head) => {
                        report.tree_heads_verified += 1;
                        stored.state = HeadState::Valid(head);
                    }
                    Err(_) => report.tree_heads_invalid += 1,
                }
            }
            if let HeadState::Valid(head) = stored.state
                && usable(&head)
            {
                return Ok(Some((head, TreeHeadSource::Delivered(stored.source))));
            }
        }
        Ok(None)
    }

    /// Checks proof `p` for the entry of verified SCT `s` against `head`.
    fn prove(
        &mut self,
        p: usize,
        s: usize,
        head: &TreeHead,
        tree_head_source: TreeHeadSource,
    ) -> Result<Option<InclusionEvidence>, TransparencyError> {
        let (Some(proof), Some(sct), Some(record)) = (
            self.proofs.get(p),
            self.verified.get(s),
            self.records.get(s),
        ) else {
            return Ok(None);
        };
        let Ok(TransItem::InclusionProofV2(data)) = TransItem::parse(&proof.item) else {
            return Ok(None);
        };
        let path_len = data.inclusion_path.len();
        // Failures found without hashing cost nothing.
        if data.leaf_index >= data.tree_size || path_len > MAX_INCLUSION_PATH_LEN {
            return Ok(None);
        }
        let needed = path_len.saturating_add(usize::from(record.leaf_hash.is_none()));
        self.remaining_hashes = self
            .remaining_hashes
            .checked_sub(needed)
            .ok_or(TransparencyError::HashBudgetExceeded)?;
        let sha256 = self.policy.sha256;
        let leaf_hash = match record.leaf_hash {
            Some(hash) => hash,
            None => {
                let precert = sct.entry_type() == SctEntryType::Precert;
                let (timestamp_ms, extensions) = (sct.timestamp_ms(), record.extensions.clone());
                let input = if precert {
                    &mut self.precert
                } else {
                    &mut self.x509
                };
                let Some(input) = input.as_mut() else {
                    return Ok(None);
                };
                input
                    .set(timestamp_ms, &extensions)
                    .ok_or(TransparencyError::ItemTooLarge)?;
                let hash: [u8; HASH_SIZE] = sha256(input.leaf_input());
                if let Some(record) = self.records.get_mut(s) {
                    record.leaf_hash = Some(hash);
                }
                hash
            }
        };
        let verified = merkle::verify_inclusion(
            sha256,
            &leaf_hash,
            data.leaf_index,
            data.tree_size,
            data.inclusion_path,
            &head.root_hash,
        );
        Ok(verified.ok().map(|()| InclusionEvidence {
            tree_size: data.tree_size,
            leaf_index: data.leaf_index,
            tree_head_timestamp_ms: head.timestamp_ms,
            tree_head_source,
            proof_source: proof.source,
        }))
    }
}
