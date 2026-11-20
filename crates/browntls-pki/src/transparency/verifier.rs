//! [`CtV2Verifier`]: the SCTs, tree heads and inclusion proofs delivered
//! with one certificate, from the three sources of RFC 9162 §6.

use alloc::vec::Vec;
use core::fmt;

use super::entry::EntryInput;
use super::item::{SignedCertificateTimestampDataV2, TransItem};
use super::list::TransItemList;
use super::log::CtV2Log;
use super::policy::{CtV2Policy, CtV2Report, VerifiedSctV2};
use super::{
    HASH_SIZE, SctEntryType, SctSource, TRANSPARENCY_INFO_OID, TransparencyError, TreeHead,
};
use crate::cert::Cert;
use crate::der::{self, tag};
use crate::error::Error;
use crate::sct::EMBEDDED_SCT_LIST_OID;
use crate::sct::precert::{RebuildError, tbs_without_extensions};
use crate::time::UnixTime;

/// What the verifier keeps of a verified SCT to compute its leaf hash.
pub(super) struct SctRecord {
    /// The SCT's extensions, as signed.
    pub(super) extensions: Vec<u8>,
    /// `HASH(0x00 || entry)`, once computed.
    pub(super) leaf_hash: Option<[u8; HASH_SIZE]>,
}

/// The verification state of a received signed tree head.
#[derive(Clone, Copy)]
pub(super) enum HeadState {
    Unverified,
    Valid(TreeHead),
    Invalid,
}

/// A `signed_tree_head_v2` of a trusted log, kept for inclusion proofs.
pub(super) struct StoredTreeHead {
    /// The serialized item.
    pub(super) item: Vec<u8>,
    pub(super) log_index: usize,
    pub(super) tree_size: u64,
    pub(super) source: SctSource,
    pub(super) state: HeadState,
}

/// An `inclusion_proof_v2` of a trusted log, kept to be matched with SCTs.
pub(super) struct StoredProof {
    /// The serialized item.
    pub(super) item: Vec<u8>,
    pub(super) log_index: usize,
    pub(super) tree_size: u64,
    pub(super) source: SctSource,
    /// Whether the proof showed the inclusion of an SCT.
    pub(super) resolved: bool,
    /// Indexes of the verified SCTs it was tried against.
    pub(super) tried: Vec<usize>,
}

/// Verifies the CT version 2 artifacts of one certificate, from any of the
/// three sources, under shared limits. See the [module
/// documentation](super).
pub struct CtV2Verifier<'a> {
    pub(super) policy: &'a CtV2Policy<'a>,
    cert: &'a Cert<'a>,
    issuer_key_hash: [u8; HASH_SIZE],
    /// Latest acceptable SCT timestamp, in milliseconds.
    latest_ms: u64,
    remaining_items: usize,
    pub(super) remaining_signatures: usize,
    pub(super) remaining_hashes: usize,
    pub(super) x509: Option<EntryInput>,
    pub(super) precert: Option<EntryInput>,
    /// The Transparency Information extension value of the certificate,
    /// once the precertificate entry is built.
    embedded: Option<Option<&'a [u8]>>,
    pub(super) verified: Vec<VerifiedSctV2>,
    /// Parallel to `verified`.
    pub(super) records: Vec<SctRecord>,
    pub(super) tree_heads: Vec<StoredTreeHead>,
    pub(super) proofs: Vec<StoredProof>,
}

impl<'a> CtV2Verifier<'a> {
    /// A verifier for `cert` at time `now`.
    ///
    /// `issuer_spki` is the public key of the certificate's issuer, as a
    /// complete DER `SubjectPublicKeyInfo` (such as
    /// [`Cert::subject_public_key_info`] of the issuer) or as its contents
    /// (such as
    /// [`TrustAnchor::subject_public_key_info`](crate::TrustAnchor::subject_public_key_info)).
    /// Every version 2 SCT signs its SHA-256 digest.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::MalformedIssuerKey`] if `issuer_spki` is
    /// neither form.
    pub fn new(
        policy: &'a CtV2Policy<'a>,
        cert: &'a Cert<'a>,
        issuer_spki: &[u8],
        now: UnixTime,
    ) -> Result<Self, TransparencyError> {
        let complete =
            crate::sct::complete_spki(issuer_spki).ok_or(TransparencyError::MalformedIssuerKey)?;
        let issuer_key_hash = (policy.sha256)(&complete);
        // The whole second of `now` has begun.
        let latest_ms = now
            .as_secs()
            .saturating_mul(1000)
            .saturating_add(999)
            .saturating_add(policy.options.future_tolerance_ms);
        Ok(Self {
            policy,
            cert,
            issuer_key_hash,
            latest_ms,
            remaining_items: policy.options.max_items,
            remaining_signatures: policy.options.max_signature_verifications,
            remaining_hashes: policy.options.max_hash_operations,
            x509: None,
            precert: None,
            embedded: None,
            verified: Vec::new(),
            records: Vec::new(),
            tree_heads: Vec::new(),
            proofs: Vec::new(),
        })
    }

    /// Verifies the `TransItemList` of the certificate's Transparency
    /// Information extension (RFC 9162 §7.1.2). Its SCTs must be
    /// `precert_sct_v2`. A certificate without the extension yields an
    /// empty report.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::MalformedCertificate`] or
    /// [`TransparencyError::DuplicateExtension`] if the precertificate
    /// cannot be reconstructed; [`TransparencyError::MalformedList`] if the
    /// extension value is not an `OCTET STRING` holding exactly one list;
    /// and the errors of [`Self::verify_tls_extension`].
    pub fn verify_embedded(&mut self) -> Result<CtV2Report, TransparencyError> {
        let Some(extn_value) = self.prepare_precert()? else {
            return Ok(CtV2Report::default());
        };
        let list = der::read_all(extn_value, |r| r.expect(tag::OCTET_STRING))
            .map_err(|_| TransparencyError::MalformedList)?;
        self.verify_list(list, SctSource::Embedded)
    }

    /// Verifies the `extension_data` of a TLS `transparency_info`
    /// extension (RFC 9162 §6.5): a `TransItemList`.
    ///
    /// RFC 9162 §6.5 lets a server with nothing to send omit the
    /// `extension_data` or send "an empty array", although §6.3 makes the
    /// list non-empty: empty `extension_data` and an empty list (`00 00`)
    /// both yield an empty report.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::ListTooLarge`],
    /// [`TransparencyError::MalformedList`],
    /// [`TransparencyError::ItemTooLarge`] or
    /// [`TransparencyError::TooManyItems`], in which case nothing of the
    /// list was used; [`TransparencyError::MalformedCertificate`] or
    /// [`TransparencyError::DuplicateExtension`] if the list has a
    /// `precert_sct_v2` and the precertificate cannot be reconstructed;
    /// [`TransparencyError::SignatureBudgetExceeded`] or
    /// [`TransparencyError::HashBudgetExceeded`], in which case what was
    /// verified before the limit remains in [`Self::verified`].
    pub fn verify_tls_extension(
        &mut self,
        extension_data: &[u8],
    ) -> Result<CtV2Report, TransparencyError> {
        if matches!(extension_data, [] | [0, 0]) {
            return Ok(CtV2Report::default());
        }
        self.verify_list(extension_data, SctSource::TlsExtension)
    }

    /// Verifies the `TransItemList` of the Transparency Information
    /// extension of the OCSP single response for this certificate (RFC 9162
    /// §7.1.1): the list itself, as
    /// [`SingleResponse::transparency_info`](crate::ocsp::SingleResponse::transparency_info)
    /// and
    /// [`VerifiedOcspStatus::transparency_info`](crate::ocsp::VerifiedOcspStatus::transparency_info)
    /// return it (the contents of the `OCTET STRING` in the extension
    /// value). The caller must have authenticated the response.
    ///
    /// # Errors
    ///
    /// Those of [`Self::verify_tls_extension`]; an empty list is malformed.
    pub fn verify_ocsp_response(
        &mut self,
        transparency_info: &[u8],
    ) -> Result<CtV2Report, TransparencyError> {
        self.verify_list(transparency_info, SctSource::OcspResponse)
    }

    /// The SCTs verified so far, in verification order, without repeats of
    /// a log, timestamp and entry type, each with its inclusion evidence
    /// if a proof verified.
    #[must_use]
    pub fn verified(&self) -> &[VerifiedSctV2] {
        &self.verified
    }

    /// Consumes the verifier, returning [`Self::verified`].
    #[must_use]
    pub fn into_verified(self) -> Vec<VerifiedSctV2> {
        self.verified
    }

    /// Builds the `precert_entry_v2` input once, and returns the value of
    /// the certificate's Transparency Information extension.
    fn prepare_precert(&mut self) -> Result<Option<&'a [u8]>, TransparencyError> {
        if let Some(embedded) = self.embedded {
            return Ok(embedded);
        }
        let rebuilt =
            tbs_without_extensions(self.cert, [TRANSPARENCY_INFO_OID, EMBEDDED_SCT_LIST_OID])
                .map_err(|error| match error {
                    RebuildError::Malformed => TransparencyError::MalformedCertificate,
                    RebuildError::Duplicate => TransparencyError::DuplicateExtension,
                })?;
        self.precert = Some(EntryInput::new(true, &self.issuer_key_hash, &rebuilt.tbs)?);
        let [embedded, _] = rebuilt.removed;
        self.embedded = Some(embedded);
        Ok(embedded)
    }

    /// The entry input of an SCT type, built if needed.
    fn input(&mut self, precert: bool) -> Result<&mut EntryInput, TransparencyError> {
        if precert {
            self.prepare_precert()?;
        } else if self.x509.is_none() {
            self.x509 = Some(EntryInput::new(
                false,
                &self.issuer_key_hash,
                self.cert.signed.data,
            )?);
        }
        let input = if precert {
            &mut self.precert
        } else {
            &mut self.x509
        };
        input
            .as_mut()
            .ok_or(TransparencyError::MalformedCertificate)
    }

    fn verify_list(
        &mut self,
        list: &[u8],
        source: SctSource,
    ) -> Result<CtV2Report, TransparencyError> {
        let options = &self.policy.options;
        if list.len() > options.max_list_len {
            return Err(TransparencyError::ListTooLarge);
        }
        let parsed = TransItemList::parse(list)?;
        let mut needs_precert = false;
        for item in parsed.iter() {
            let (extensions, signature) = match item {
                TransItem::X509SctV2(sct) => (sct.sct_extensions, sct.signature),
                TransItem::PrecertSctV2(sct) => {
                    needs_precert = true;
                    (sct.sct_extensions, sct.signature)
                }
                TransItem::SignedTreeHeadV2(sth) => (sth.tree_head.sth_extensions, sth.signature),
                _ => continue,
            };
            if extensions.as_bytes().len() > options.max_extensions_len
                || signature.len() > options.max_signature_len
            {
                return Err(TransparencyError::ItemTooLarge);
            }
        }
        self.remaining_items = self
            .remaining_items
            .checked_sub(parsed.len())
            .ok_or(TransparencyError::TooManyItems)?;
        // Reconstruct the precertificate before any signature is checked.
        if needs_precert {
            self.prepare_precert()?;
        }

        let mut report = CtV2Report::default();
        for serialized in parsed.serialized_items() {
            let Ok(item) = TransItem::parse(serialized) else {
                continue;
            };
            match item {
                TransItem::X509SctV2(sct) => self.verify_sct(&sct, false, source, &mut report)?,
                TransItem::PrecertSctV2(sct) => self.verify_sct(&sct, true, source, &mut report)?,
                TransItem::SignedTreeHeadV2(sth) => match self.log(sth.log_id.as_bytes()) {
                    Some((log_index, _)) => {
                        report.tree_heads += 1;
                        self.tree_heads.push(StoredTreeHead {
                            item: serialized.to_vec(),
                            log_index,
                            tree_size: sth.tree_head.tree_size,
                            source,
                            state: HeadState::Unverified,
                        });
                    }
                    None => report.ignored += 1,
                },
                TransItem::InclusionProofV2(proof) => match self.log(proof.log_id.as_bytes()) {
                    Some((log_index, _)) => {
                        report.inclusion_proofs += 1;
                        self.proofs.push(StoredProof {
                            item: serialized.to_vec(),
                            log_index,
                            tree_size: proof.tree_size,
                            source,
                            resolved: false,
                            tried: Vec::new(),
                        });
                    }
                    None => report.ignored += 1,
                },
                TransItem::Unknown { .. } => report.unknown_type += 1,
                _ => report.ignored += 1,
            }
        }
        self.resolve_inclusion(&mut report)?;
        Ok(report)
    }

    /// The first trusted log with ID `id`, and its position.
    pub(super) fn log(&self, id: &[u8]) -> Option<(usize, &'a CtV2Log<'a>)> {
        self.policy
            .logs
            .iter()
            .enumerate()
            .find(|(_, log)| log.id().as_bytes() == id)
    }

    fn verify_sct(
        &mut self,
        sct: &SignedCertificateTimestampDataV2<'_>,
        precert: bool,
        source: SctSource,
        report: &mut CtV2Report,
    ) -> Result<(), TransparencyError> {
        let entry_type = if precert {
            SctEntryType::Precert
        } else {
            SctEntryType::X509
        };
        if source == SctSource::Embedded && !precert {
            report.misplaced += 1;
            return Ok(());
        }
        let Some((log_index, log)) = self.log(sct.log_id.as_bytes()) else {
            report.unknown_log += 1;
            return Ok(());
        };
        if !log.trusts_timestamp(sct.timestamp_ms) {
            report.outside_log_validity += 1;
            return Ok(());
        }
        if sct.timestamp_ms > self.latest_ms {
            report.future_timestamp += 1;
            return Ok(());
        }
        if self
            .verified
            .iter()
            .any(|v| v.same_sct(log_index, sct.timestamp_ms, entry_type))
        {
            report.duplicate += 1;
            return Ok(());
        }
        if !sct.sct_extensions.is_ordered() {
            report.invalid_extensions += 1;
            return Ok(());
        }
        self.remaining_signatures = self
            .remaining_signatures
            .checked_sub(1)
            .ok_or(TransparencyError::SignatureBudgetExceeded)?;
        let algs = self.policy.supported_sig_algs;
        let extensions = sct.sct_extensions.as_bytes();
        let input = self.input(precert)?;
        input
            .set(sct.timestamp_ms, extensions)
            .ok_or(TransparencyError::ItemTooLarge)?;
        match log.verify_signature(algs, input.message(), sct.signature) {
            Ok(()) => {
                report.verified += 1;
                self.verified.push(VerifiedSctV2::new(
                    log.id(),
                    log_index,
                    sct.timestamp_ms,
                    entry_type,
                    source,
                ));
                self.records.push(SctRecord {
                    extensions: extensions.to_vec(),
                    leaf_hash: None,
                });
            }
            Err(
                Error::UnsupportedSignatureAlgorithm
                | Error::UnsupportedSignatureAlgorithmForPublicKey,
            ) => report.unsupported_algorithm += 1,
            Err(_) => report.invalid_signature += 1,
        }
        Ok(())
    }
}

impl fmt::Debug for CtV2Verifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtV2Verifier")
            .field("remaining_items", &self.remaining_items)
            .field("remaining_signatures", &self.remaining_signatures)
            .field("remaining_hashes", &self.remaining_hashes)
            .field("verified", &self.verified)
            .field("tree_heads", &self.tree_heads.len())
            .field("proofs", &self.proofs.len())
            .finish_non_exhaustive()
    }
}
