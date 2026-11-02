//! Certificate path building and validation (RFC 5280 §6, RFC 4158).
//!
//! The search is depth-first from the end entity towards the trust anchors.
//! At each step the head of the partial path is checked on its own (validity,
//! basic constraints, key usage, extended key usage), then every trust anchor
//! whose subject is the head's issuer is tried (signatures, revocation, name
//! constraints, the caller's path check), then every intermediate whose
//! subject is the head's issuer is pushed and the search recurses.
//!
//! Work is bounded by the path depth, the number of signature checks, the
//! number of recursive build calls and the number of name constraint
//! comparisons; exhausting a budget ends the search. Any other failure only
//! rejects the current candidate, and the most specific rejection is reported
//! when no path succeeds.

use alloc::vec::Vec;
use core::iter;

use crate::UnixTime;
use crate::cert::{Cert, KU_CRL_SIGN, KU_KEY_CERT_SIGN};
use crate::crl::RevocationOptions;
use crate::der::Reader;
use crate::error::Error;
use crate::name;
use crate::signed_data::{self, Spki};
use crate::types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor};
use crate::verify::{EndEntityCert, KeyUsage, PathVerifier, VerifiedPath};

/// Maximum number of intermediate certificates in a path.
pub(crate) const MAX_INTERMEDIATES: usize = 6;

/// Work limits for one verification.
///
/// The signature limit follows the remediation for Go CVE-2018-16875, the
/// build-call limit mozilla::pkix, and the name-constraint limit Go's
/// `crypto/x509` default.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Budget {
    signatures: usize,
    build_calls: usize,
    name_constraint_comparisons: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            signatures: 100,
            build_calls: 200_000,
            name_constraint_comparisons: 250_000,
        }
    }
}

impl Budget {
    pub(crate) fn consume_signature(&mut self) -> Result<(), Error> {
        consume(&mut self.signatures, Error::MaximumSignatureChecksExceeded)
    }

    fn consume_build_call(&mut self) -> Result<(), Error> {
        consume(&mut self.build_calls, Error::MaximumPathBuildCallsExceeded)
    }

    pub(crate) fn consume_name_constraint_comparison(&mut self) -> Result<(), Error> {
        consume(
            &mut self.name_constraint_comparisons,
            Error::MaximumNameConstraintComparisonsExceeded,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_name_constraint_comparisons(n: usize) -> Self {
        Self {
            name_constraint_comparisons: n,
            ..Self::default()
        }
    }
}

fn consume(counter: &mut usize, exhausted: Error) -> Result<(), Error> {
    *counter = counter.checked_sub(1).ok_or(exhausted)?;
    Ok(())
}

/// The position of a certificate in a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    EndEntity,
    Issuer,
}

/// Why a candidate was abandoned: a fatal error ends the whole search.
#[derive(Debug)]
enum Fail {
    Fatal(Error),
    Reject(Error),
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        if e.is_fatal() {
            Self::Fatal(e)
        } else {
            Self::Reject(e)
        }
    }
}

impl Fail {
    fn into_error(self) -> Error {
        match self {
            Self::Fatal(e) | Self::Reject(e) => e,
        }
    }
}

type Attempt<T> = Result<T, Fail>;

/// Inputs to one path build.
pub(crate) struct ChainOptions<'a, 'p> {
    pub(crate) algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    pub(crate) trust_anchors: &'p [TrustAnchor<'p>],
    pub(crate) intermediates: &'p [CertificateDer<'p>],
    pub(crate) time: UnixTime,
    pub(crate) usage: KeyUsage,
    pub(crate) revocation: Option<RevocationOptions<'a>>,
    pub(crate) verify_path: Option<PathVerifier<'a>>,
}

/// The end entity plus the intermediates pushed so far, nearest first.
struct PartialPath<'p> {
    end_entity: &'p EndEntityCert<'p>,
    /// `(index into the caller's intermediates, parsed certificate)`.
    intermediates: Vec<(usize, Cert<'p>)>,
}

impl<'p> PartialPath<'p> {
    fn head(&self) -> &Cert<'p> {
        match self.intermediates.last() {
            Some((_, cert)) => cert,
            None => &self.end_entity.inner,
        }
    }

    fn role(&self) -> Role {
        if self.intermediates.is_empty() {
            Role::EndEntity
        } else {
            Role::Issuer
        }
    }

    /// Certificates from the head down to the end entity.
    fn nodes_from_head(&self) -> impl Iterator<Item = (Role, &Cert<'p>)> {
        self.intermediates
            .iter()
            .rev()
            .map(|(_, cert)| (Role::Issuer, cert))
            .chain(iter::once((Role::EndEntity, &self.end_entity.inner)))
    }

    /// Loop prevention (RFC 4158 §5.2): a certificate with the same subject
    /// and key as one already in the path adds nothing.
    fn contains_equivalent(&self, cert: &Cert<'_>) -> bool {
        self.nodes_from_head()
            .any(|(_, c)| c.subject == cert.subject && c.spki == cert.spki)
    }

    fn intermediate_ders(&self, all: &'p [CertificateDer<'p>]) -> Vec<&'p CertificateDer<'p>> {
        self.intermediates
            .iter()
            .filter_map(|(i, _)| all.get(*i))
            .collect()
    }
}

impl<'a, 'p> ChainOptions<'a, 'p> {
    /// Builds and verifies a path for `end_entity`.
    pub(crate) fn build(
        &self,
        end_entity: &'p EndEntityCert<'p>,
    ) -> Result<VerifiedPath<'p>, Error> {
        let mut path = PartialPath {
            end_entity,
            intermediates: Vec::new(),
        };
        let mut budget = Budget::default();
        match self.build_from(&mut path, 0, &mut budget) {
            Ok(anchor) => Ok(VerifiedPath::new(
                end_entity,
                path.intermediate_ders(self.intermediates),
                anchor,
            )),
            Err(fail) => Err(fail.into_error()),
        }
    }

    /// Extends `path` from its head to a trust anchor. `sub_ca_count` is the
    /// number of CA certificates below the head.
    fn build_from(
        &self,
        path: &mut PartialPath<'p>,
        sub_ca_count: usize,
        budget: &mut Budget,
    ) -> Attempt<&'p TrustAnchor<'p>> {
        let role = path.role();
        check_issuer_independent(path.head(), self.time, role, sub_ca_count, &self.usage)?;

        let mut error = Error::UnknownIssuer;

        for anchor in self
            .trust_anchors
            .iter()
            .filter(|anchor| anchor.subject.as_ref() == path.head().issuer)
        {
            match self.try_anchor(path, anchor, budget) {
                Ok(()) => return Ok(anchor),
                Err(Fail::Fatal(e)) => return Err(Fail::Fatal(e)),
                Err(Fail::Reject(e)) => error = error.most_specific(e),
            }
        }

        // Candidates whose subject key identifier matches the head's
        // authority key identifier are tried first; the hint only orders the
        // search, it never excludes a candidate.
        let hint = path
            .head()
            .authority_key_id
            .and_then(|aki| aki.key_identifier);
        let passes: &[Option<bool>] = match hint {
            Some(_) => &[Some(true), Some(false)],
            None => &[None],
        };
        for &hinted_pass in passes {
            for (index, der) in self.intermediates.iter().enumerate() {
                let cert = match Cert::from_der(der.as_ref()) {
                    Ok(cert) => cert,
                    Err(e) => {
                        if hinted_pass != Some(true) {
                            error = error.most_specific(e);
                        }
                        continue;
                    }
                };
                if let Some(want_hinted) = hinted_pass
                    && (cert.subject_key_id == hint) != want_hinted
                {
                    continue;
                }
                if cert.subject != path.head().issuer || path.contains_equivalent(&cert) {
                    continue;
                }

                budget.consume_build_call()?;
                if path.intermediates.len() >= MAX_INTERMEDIATES {
                    error = error.most_specific(Error::MaximumPathDepthExceeded);
                    continue;
                }
                let next_sub_ca_count = match role {
                    Role::EndEntity => sub_ca_count,
                    Role::Issuer => sub_ca_count + 1,
                };
                path.intermediates.push((index, cert));
                match self.build_from(path, next_sub_ca_count, budget) {
                    Ok(anchor) => return Ok(anchor),
                    Err(Fail::Fatal(e)) => return Err(Fail::Fatal(e)),
                    Err(Fail::Reject(e)) => {
                        path.intermediates.pop();
                        error = error.most_specific(e);
                    }
                }
            }
        }

        Err(Fail::Reject(error))
    }

    /// Checks the complete candidate path ending at `anchor`.
    fn try_anchor(
        &self,
        path: &PartialPath<'p>,
        anchor: &'p TrustAnchor<'p>,
        budget: &mut Budget,
    ) -> Attempt<()> {
        self.check_signatures_and_revocation(path, anchor, budget)?;
        check_name_constraints(path, anchor, budget)?;
        if let Some(verify) = self.verify_path {
            let candidate = VerifiedPath::new(
                path.end_entity,
                path.intermediate_ders(self.intermediates),
                anchor,
            );
            // The caller's rejection never ends the search.
            verify(&candidate).map_err(Fail::Reject)?;
        }
        Ok(())
    }

    /// Verifies each signature from the anchor down to the end entity, and
    /// the revocation status of each certificate when requested.
    fn check_signatures_and_revocation(
        &self,
        path: &PartialPath<'p>,
        anchor: &TrustAnchor<'_>,
        budget: &mut Budget,
    ) -> Attempt<()> {
        let mut issuer_spki: &[u8] = anchor.subject_public_key_info.as_ref();
        let mut issuer_subject: &[u8] = anchor.subject.as_ref();
        // Trust anchors carry no key usage; anchors may sign CRLs.
        let mut issuer_may_sign_crls = true;
        for (role, cert) in path.nodes_from_head() {
            let spki = Spki::from_contents(issuer_spki)?;
            signed_data::verify_signed_data(self.algs, &spki, &cert.signed, budget)?;
            if let Some(revocation) = &self.revocation {
                debug_assert_eq!(cert.issuer, issuer_subject);
                revocation.check(
                    cert,
                    role,
                    &spki,
                    issuer_may_sign_crls,
                    self.algs,
                    budget,
                    self.time,
                )?;
            }
            issuer_spki = cert.spki;
            issuer_subject = cert.subject;
            issuer_may_sign_crls = cert.key_usage_permits(KU_CRL_SIGN);
        }
        Ok(())
    }
}

/// Applies each issuer's name constraints to every certificate below it,
/// starting with the anchor's.
fn check_name_constraints(
    path: &PartialPath<'_>,
    anchor: &TrustAnchor<'_>,
    budget: &mut Budget,
) -> Result<(), Error> {
    let mut constraints: Option<&[u8]> = anchor.name_constraints.as_ref().map(AsRef::as_ref);
    for (i, (_, cert)) in path.nodes_from_head().enumerate() {
        if let Some(nc) = constraints {
            name::constraints::check(nc, path.nodes_from_head().skip(i).map(|(_, c)| c), budget)?;
        }
        constraints = cert.name_constraints;
    }
    Ok(())
}

/// Checks that depend only on the certificate and its position in the path.
fn check_issuer_independent(
    cert: &Cert<'_>,
    time: UnixTime,
    role: Role,
    sub_ca_count: usize,
    usage: &KeyUsage,
) -> Result<(), Error> {
    check_validity(cert, time)?;
    check_basic_constraints(cert, role, sub_ca_count)?;
    // RFC 5280 §6.1.4 (n): an issuer's KeyUsage, when present, must assert
    // keyCertSign. End-entity key usage is left to the protocol layer.
    if role == Role::Issuer && !cert.key_usage_permits(KU_KEY_CERT_SIGN) {
        return Err(Error::IssuerNotCertSigner);
    }
    check_eku(cert, usage)
}

// RFC 5280 §4.1.2.5; both bounds are inclusive.
fn check_validity(cert: &Cert<'_>, time: UnixTime) -> Result<(), Error> {
    if cert.not_before > cert.not_after {
        return Err(Error::InvalidCertValidity);
    }
    if time < cert.not_before {
        return Err(Error::CertNotValidYet {
            time,
            not_before: cert.not_before,
        });
    }
    if time > cert.not_after {
        return Err(Error::CertExpired {
            time,
            not_after: cert.not_after,
        });
    }
    Ok(())
}

// RFC 5280 §4.2.1.9 and §6.1.4 (k)-(m).
fn check_basic_constraints(cert: &Cert<'_>, role: Role, sub_ca_count: usize) -> Result<(), Error> {
    let (ca, path_len) = cert
        .basic_constraints
        .map_or((false, None), |bc| (bc.ca, bc.path_len));
    match (role, ca, path_len) {
        (Role::EndEntity, true, _) => Err(Error::CaUsedAsEndEntity),
        (Role::Issuer, false, _) => Err(Error::EndEntityUsedAsCa),
        (Role::Issuer, true, Some(max)) if sub_ca_count > usize::from(max) => {
            Err(Error::PathLenConstraintViolated)
        }
        _ => Ok(()),
    }
}

// RFC 5280 §4.2.1.12. Applied to every certificate in the path, so an
// intermediate carrying an EKU extension must also list the purpose.
fn check_eku(cert: &Cert<'_>, usage: &KeyUsage) -> Result<(), Error> {
    let Some(purposes) = cert.eku else {
        return if usage.is_required_if_present() {
            Ok(())
        } else {
            Err(Error::RequiredEkuNotFound)
        };
    };
    if purposes.is_empty() {
        return Err(Error::EmptyEkuExtension);
    }
    let mut reader = Reader::new(purposes);
    while !reader.at_end() {
        if reader.oid()? == usage.oid() {
            return Ok(());
        }
    }
    Err(Error::RequiredEkuNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_exhaustion_is_fatal() {
        let mut budget = Budget {
            signatures: 1,
            build_calls: 1,
            name_constraint_comparisons: 1,
        };
        assert_eq!(budget.consume_signature(), Ok(()));
        assert_eq!(
            budget.consume_signature(),
            Err(Error::MaximumSignatureChecksExceeded)
        );
        assert_eq!(budget.consume_build_call(), Ok(()));
        assert_eq!(
            budget.consume_build_call(),
            Err(Error::MaximumPathBuildCallsExceeded)
        );
        assert_eq!(budget.consume_name_constraint_comparison(), Ok(()));
        assert!(matches!(
            Fail::from(Error::MaximumNameConstraintComparisonsExceeded),
            Fail::Fatal(_)
        ));
        assert!(matches!(Fail::from(Error::UnknownIssuer), Fail::Reject(_)));
    }
}
