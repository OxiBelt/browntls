//! Path building under a revocation policy: the local evidence of every
//! candidate path, and the hand-over to live queries.

use alloc::vec::Vec;
use core::cell::RefCell;

use browntls_pki::crl::CertRevocationList;
use browntls_pki::{
    Cert, CertificateDer, ExpirationPolicy, KeyUsage, RevocationCheckDepth,
    RevocationOptionsBuilder, ServerName, SignatureVerificationAlgorithm, TrustAnchor, UnixTime,
    UnknownStatusPolicy, VerifiedPath,
};

use super::live::{DeferredPath, Live, PendingCert};
use super::sources::{DeliveredScts, IssuerRef, OcspContext, OcspVerdict, crlite_revoked};
use super::{RevocationData, RevocationPolicy};
use crate::error::{CertificateError, Error};
use crate::revocation::{PeerEvidence, RevocationCheck, RevocationStatus};
use crate::sync::Arc;
use crate::webpki::{ParsedCertificate, pki_error, verify_server_name};

/// Paths without complete local evidence that are kept for live queries.
const MAX_DEFERRED_PATHS: usize = 2;

/// The CRL configuration of a verifier.
pub(crate) struct CrlConfig<'a> {
    pub(crate) crls: &'a Arc<Vec<CertRevocationList<'static>>>,
    pub(crate) depth: RevocationCheckDepth,
    pub(crate) unknown_status: UnknownStatusPolicy,
    pub(crate) expiration: ExpirationPolicy,
}

/// One peer certificate chain to verify under a [`RevocationPolicy`].
pub(crate) struct PathRequest<'a> {
    pub(crate) end_entity: &'a ParsedCertificate<'a>,
    pub(crate) roots: &'a [TrustAnchor<'static>],
    /// The certificates the peer sent after the end entity, in its order.
    pub(crate) intermediates: &'a [CertificateDer<'a>],
    pub(crate) now: UnixTime,
    pub(crate) algs: &'static [&'static dyn SignatureVerificationAlgorithm],
    pub(crate) usage: KeyUsage,
    pub(crate) crls: CrlConfig<'a>,
    /// The name the end entity must be valid for, when verifying a server.
    pub(crate) server_name: Option<&'a ServerName<'a>>,
    /// Stapled evidence in the peer's order, starting with the end entity.
    pub(crate) evidence: PeerEvidence<'a>,
    /// Whether the caller can transport OCSP queries.
    pub(crate) allow_live: bool,
}

/// What local evidence establishes about one certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalStatus {
    Good,
    Revoked,
    Unknown,
    /// The stapled response is invalid, or a required one is missing.
    InvalidStaple,
}

/// The local status of the certificate at `position` of the peer's chain
/// (0 is the end entity) under one issuer key.
struct CachedStatus {
    position: usize,
    issuer_spki: Vec<u8>,
    status: LocalStatus,
}

#[derive(Default)]
struct State {
    end_entity_revoked: bool,
    invalid_staple: bool,
    cache: Vec<CachedStatus>,
    deferred: Vec<DeferredPath>,
}

struct Evaluation<'r, 'a> {
    policy: &'r RevocationPolicy,
    request: &'r PathRequest<'a>,
    crls: &'r [&'r CertRevocationList<'static>],
    data: Option<RevocationData>,
    state: RefCell<State>,
}

impl RevocationPolicy {
    /// Builds a path for `request` whose covered certificates are known not
    /// to be revoked, or reports what is still needed to decide.
    pub(crate) fn verify_path(&self, request: &PathRequest<'_>) -> Result<RevocationCheck, Error> {
        let crls: Vec<&CertRevocationList<'static>> = request.crls.crls.iter().collect();
        let crl_options = RevocationOptionsBuilder::new(&crls).ok().map(|builder| {
            builder
                .with_depth(request.crls.depth)
                .with_status_policy(request.crls.unknown_status)
                .with_expiration_policy(request.crls.expiration)
                .build()
        });
        let evaluation = Evaluation {
            policy: self,
            request,
            crls: &crls,
            // One generation serves the whole verification.
            data: self.data.as_ref().and_then(|source| source.current()),
            state: RefCell::new(State::default()),
        };
        let check_candidate = |path: &VerifiedPath<'_>| evaluation.check_candidate(path);
        let built = request
            .end_entity
            .0
            .verify_for_usage(
                request.algs,
                request.roots,
                request.intermediates,
                request.now,
                request.usage,
                crl_options,
                Some(&check_candidate),
            )
            .map(|_| ());
        let state = evaluation.state.take();

        let deferred = match built {
            Ok(()) => None,
            Err(error) => Some(deferred_paths(error, state)?),
        };
        if let Some(name) = request.server_name {
            verify_server_name(request.end_entity, name)?;
        }
        match deferred {
            None => Ok(RevocationCheck::Complete(Some(RevocationStatus::Good))),
            Some(paths) => Live::new(
                self.clone(),
                request.algs,
                Arc::clone(request.crls.crls),
                evaluation.data,
                paths,
                request.allow_live,
            )
            .advance(),
        }
    }
}

/// The paths that only lack revocation evidence, or the error that ends
/// verification.
fn deferred_paths(error: browntls_pki::Error, state: State) -> Result<Vec<DeferredPath>, Error> {
    use browntls_pki::Error as PkiError;

    // The end entity is part of every path, so no alternative can clear it.
    if state.end_entity_revoked {
        return Err(CertificateError::Revoked.into());
    }
    let budget_exhausted = matches!(
        error,
        PkiError::MaximumSignatureChecksExceeded
            | PkiError::MaximumPathBuildCallsExceeded
            | PkiError::MaximumNameConstraintComparisonsExceeded
    );
    if !budget_exhausted && !state.deferred.is_empty() {
        return Ok(state.deferred);
    }
    Err(match error {
        PkiError::UnknownRevocationStatus if state.invalid_staple => {
            CertificateError::InvalidOcspResponse.into()
        }
        other => pki_error(other),
    })
}

impl Evaluation<'_, '_> {
    /// Decides one otherwise valid path from local evidence. A rejection
    /// lets path building continue with alternatives.
    fn check_candidate(&self, path: &VerifiedPath<'_>) -> Result<(), browntls_pki::Error> {
        let presented = self.request.intermediates;
        let mut issuers = Vec::new();
        for der in path.intermediate_certificates() {
            let position = presented
                .iter()
                .position(|sent| core::ptr::eq(sent, der))
                .map(|index| index.saturating_add(1));
            issuers.push((position, Cert::try_from(der)?));
        }
        let end_entity: &Cert<'_> = path.end_entity();
        let covered = match self.policy.full_chain {
            true => issuers.len().saturating_add(1),
            false => 1,
        };

        let mut revoked = false;
        let mut invalid_staple = false;
        let mut pending = Vec::new();
        for index in 0..covered {
            let (position, subject) = match index.checked_sub(1).and_then(|i| issuers.get(i)) {
                Some((position, cert)) => (*position, cert),
                None => (Some(0), end_entity),
            };
            let issuer = match issuers.get(index) {
                Some((_, cert)) => IssuerRef::Cert(cert),
                None => IssuerRef::Anchor(path.anchor()),
            };
            let is_end_entity = index == 0;
            match self.local_status(is_end_entity, position, subject, &issuer)? {
                LocalStatus::Good => {}
                LocalStatus::Revoked => {
                    revoked = true;
                    if is_end_entity {
                        self.state.borrow_mut().end_entity_revoked = true;
                    }
                }
                LocalStatus::InvalidStaple => invalid_staple = true,
                LocalStatus::Unknown => pending.push(PendingCert {
                    der: subject.der().into_owned(),
                    issuer: issuer.to_owned(),
                    end_entity: is_end_entity,
                    tls_scts: position
                        .filter(|_| is_end_entity && self.data.is_some())
                        .and_then(|index| self.request.evidence.get(index))
                        .and_then(|evidence| evidence.scts)
                        .map(<[u8]>::to_vec),
                }),
            }
        }

        let mut state = self.state.borrow_mut();
        if revoked {
            return Err(browntls_pki::Error::CertRevoked);
        }
        if invalid_staple {
            state.invalid_staple = true;
            return Err(browntls_pki::Error::UnknownRevocationStatus);
        }
        if pending.is_empty() {
            return Ok(());
        }
        // Keep looking for a path that local evidence decides completely.
        if state.deferred.len() < MAX_DEFERRED_PATHS {
            state.deferred.push(pending);
        }
        Err(browntls_pki::Error::UnknownRevocationStatus)
    }

    /// The local status of `subject` under `issuer`, computed once per
    /// certificate and issuer key however many paths contain them.
    fn local_status(
        &self,
        is_end_entity: bool,
        position: Option<usize>,
        subject: &Cert<'_>,
        issuer: &IssuerRef<'_>,
    ) -> Result<LocalStatus, browntls_pki::Error> {
        let issuer_spki = issuer.spki_der();
        if let Some(position) = position
            && let Some(cached) = self
                .state
                .borrow()
                .cache
                .iter()
                .find(|entry| entry.position == position && entry.issuer_spki == issuer_spki)
        {
            return Ok(cached.status);
        }
        let status = self.evaluate(is_end_entity, position, subject, issuer)?;
        if let Some(position) = position {
            self.state.borrow_mut().cache.push(CachedStatus {
                position,
                issuer_spki,
                status,
            });
        }
        Ok(status)
    }

    fn evaluate(
        &self,
        is_end_entity: bool,
        position: Option<usize>,
        subject: &Cert<'_>,
        issuer: &IssuerRef<'_>,
    ) -> Result<LocalStatus, browntls_pki::Error> {
        let request = self.request;
        let evidence = position
            .and_then(|position| request.evidence.get(position))
            .copied()
            .unwrap_or_default();
        let mut good = self.cleared_by_crl(is_end_entity, subject);
        let mut revoked = false;

        // RFC 7633 defines the TLS feature extension of an end entity. In a
        // CA certificate it constrains the certificates issued below it,
        // which this policy does not enforce.
        let must_staple = is_end_entity && browntls_pki::ocsp::must_staple(subject)?;
        let mut staple_decides = false;
        let mut ocsp_scts = None;
        if let Some(response) = evidence.ocsp {
            let context = OcspContext {
                digests: &self.policy.digests,
                algs: request.algs,
                crls: self.crls,
                now: request.now,
            };
            match context.stapled(response, subject, issuer) {
                OcspVerdict::Good { sct_list } => {
                    good = true;
                    staple_decides = true;
                    ocsp_scts = sct_list;
                }
                OcspVerdict::Revoked => {
                    revoked = true;
                    staple_decides = true;
                }
                OcspVerdict::Unknown { sct_list } => ocsp_scts = sct_list,
                OcspVerdict::Unusable => {}
                OcspVerdict::Invalid => return Ok(LocalStatus::InvalidStaple),
            }
        }

        // CRLite describes end-entity certificates.
        if is_end_entity && let Some(data) = &self.data {
            let delivered = DeliveredScts {
                tls: evidence.scts,
                ocsp: ocsp_scts,
            };
            match crlite_revoked(
                data,
                &self.policy.digests,
                request.algs,
                subject,
                issuer,
                delivered,
                request.now,
            )? {
                Some(true) => revoked = true,
                Some(false) => good = true,
                None => {}
            }
        }

        Ok(if revoked {
            LocalStatus::Revoked
        } else if must_staple && !staple_decides {
            LocalStatus::InvalidStaple
        } else if good {
            LocalStatus::Good
        } else {
            LocalStatus::Unknown
        })
    }

    /// Whether path building checked `subject` against a current CRL of its
    /// issuer that covers every certificate of that issuer.
    ///
    /// Path building has verified the signature of each CRL of the issuer
    /// and rejected the path if one lists the certificate. A CRL with an
    /// issuing distribution point may cover only some certificates, and
    /// which ones is not visible here, so such a CRL can revoke but is not
    /// counted as evidence of good standing.
    fn cleared_by_crl(&self, is_end_entity: bool, subject: &Cert<'_>) -> bool {
        let checked = is_end_entity || self.request.crls.depth == RevocationCheckDepth::Chain;
        checked
            && self.crls.iter().any(|crl| {
                crl.issuer() == subject.issuer()
                    && crl.issuing_distribution_point().is_none()
                    && crl.this_update() <= self.request.now
                    && self.request.now < crl.next_update()
            })
    }
}
