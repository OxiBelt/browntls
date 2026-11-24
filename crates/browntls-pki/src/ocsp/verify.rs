//! OCSP response validation (RFC 6960 sections 3.2 and 4.2.2.2, RFC 5019
//! sections 2.2 and 4).

use core::time::Duration;

use super::cert_ext::has_ocsp_nocheck;
use super::cert_id::CertId;
use super::response::{BasicResponse, CertStatus, OcspResponse, ResponderId, SingleResponse};
use super::{CertIdHash, CertIdHashers, OcspError, oid};
use crate::UnixTime;
use crate::cert::{Cert, KU_CRL_SIGN, KU_DIGITAL_SIGNATURE};
use crate::crl::CertRevocationList;
use crate::error::Error;
use crate::path::{Budget, Role};
use crate::signed_data::{self, Spki};
use crate::types::{SignatureVerificationAlgorithm, TrustAnchor};

/// Default tolerance for clock differences with the responder.
const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// Default bound on the age of a stapled response: the longest validity
/// interval the CA/Browser Forum baseline requirements allow for
/// subscriber certificates.
const DEFAULT_STAPLE_MAX_AGE: Duration = Duration::from_secs(10 * 24 * 60 * 60);

/// Default lifetime, from `thisUpdate`, of a response without `nextUpdate`.
const DEFAULT_VALIDITY_WITHOUT_NEXT_UPDATE: Duration = Duration::from_secs(24 * 60 * 60);

/// The issuer of the certificate whose status is checked: its name and
/// public key, which authenticate responses.
///
/// The caller is responsible for the issuer being genuine, typically
/// because it comes from a path that
/// [`EndEntityCert::verify_for_usage`](crate::EndEntityCert::verify_for_usage)
/// validated.
#[derive(Clone, Copy, Debug)]
pub struct OcspIssuer<'a> {
    /// Subject `Name` contents.
    subject: &'a [u8],
    /// `SubjectPublicKeyInfo`, complete or its contents.
    spki: &'a [u8],
    /// Whether the issuer's key usage allows it to sign CRLs.
    may_sign_crls: bool,
}

impl<'a> OcspIssuer<'a> {
    /// The issuer described by its certificate.
    #[must_use]
    pub fn from_cert(cert: &Cert<'a>) -> Self {
        Self {
            subject: cert.subject,
            spki: cert.spki,
            may_sign_crls: cert.key_usage_permits(KU_CRL_SIGN),
        }
    }

    /// The issuer described by a trust anchor.
    #[must_use]
    pub fn from_trust_anchor(anchor: &'a TrustAnchor<'_>) -> Self {
        Self::new(
            anchor.subject.as_ref(),
            anchor.subject_public_key_info.as_ref(),
        )
    }

    /// The issuer described by its subject `Name` contents (without the
    /// outer `SEQUENCE`) and its `SubjectPublicKeyInfo` (complete, or its
    /// contents). Such an issuer is taken to be allowed to sign CRLs.
    #[must_use]
    pub fn new(subject: &'a [u8], subject_public_key_info: &'a [u8]) -> Self {
        Self {
            subject,
            spki: subject_public_key_info,
            may_sign_crls: true,
        }
    }

    /// The subject `Name` contents.
    #[must_use]
    pub fn subject(&self) -> &'a [u8] {
        self.subject
    }

    /// The `SubjectPublicKeyInfo` as given.
    #[must_use]
    pub fn subject_public_key_info(&self) -> &'a [u8] {
        self.spki
    }
}

/// What a response must satisfy to be accepted.
///
/// Start from [`Self::stapled`] or [`Self::fetched`] and adjust the public
/// fields.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct OcspPolicy<'a> {
    /// Algorithms that may verify the response's and a responder
    /// certificate's signatures.
    pub supported_sig_algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    /// Digest functions for `CertID`s and `byKey` responder identifiers.
    pub hashers: CertIdHashers,
    /// The validation time.
    pub time: UnixTime,
    /// Tolerance applied to both ends of the response's validity interval
    /// (not to certificate or CRL validity). Five minutes by default.
    pub clock_skew: Duration,
    /// Whether a response without `nextUpdate` is rejected
    /// ([`OcspError::MissingNextUpdate`]). RFC 5019 section 2.2.4 requires
    /// the field.
    pub require_next_update: bool,
    /// The longest acceptable time since `thisUpdate`, whatever
    /// `nextUpdate` says.
    pub max_age: Option<Duration>,
    /// How long after `thisUpdate` a response without `nextUpdate` stays
    /// usable. One day by default.
    pub validity_without_next_update: Duration,
    /// CRLs that may show a responder certificate without
    /// `id-pkix-ocsp-nocheck` to be unrevoked. Only CRLs issued and signed
    /// by the certificate's issuer, current at [`Self::time`] and covering
    /// the responder certificate are used. Empty by default, which rejects
    /// such responder certificates.
    pub delegate_crls: &'a [&'a CertRevocationList<'a>],
    /// The nonce sent in the request. A response with a different nonce is
    /// rejected; one without a nonce is rejected only under
    /// [`Self::require_nonce`].
    pub expected_nonce: Option<&'a [u8]>,
    /// Whether the response must echo [`Self::expected_nonce`]. RFC 5019
    /// responders never do.
    pub require_nonce: bool,
}

impl<'a> OcspPolicy<'a> {
    /// The policy for a response stapled by a TLS peer: `nextUpdate` is
    /// optional, and the response must not be older than ten days.
    #[must_use]
    pub fn stapled(
        supported_sig_algs: &'a [&'a dyn SignatureVerificationAlgorithm],
        hashers: CertIdHashers,
        time: UnixTime,
    ) -> Self {
        Self {
            supported_sig_algs,
            hashers,
            time,
            clock_skew: DEFAULT_CLOCK_SKEW,
            require_next_update: false,
            max_age: Some(DEFAULT_STAPLE_MAX_AGE),
            validity_without_next_update: DEFAULT_VALIDITY_WITHOUT_NEXT_UPDATE,
            delegate_crls: &[],
            expected_nonce: None,
            require_nonce: false,
        }
    }

    /// The policy for a response fetched from a responder: `nextUpdate` is
    /// required and alone bounds the response's lifetime.
    #[must_use]
    pub fn fetched(
        supported_sig_algs: &'a [&'a dyn SignatureVerificationAlgorithm],
        hashers: CertIdHashers,
        time: UnixTime,
    ) -> Self {
        Self {
            require_next_update: true,
            max_age: None,
            ..Self::stapled(supported_sig_algs, hashers, time)
        }
    }
}

/// Who signed an authenticated response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OcspSigner {
    /// The certificate's issuer.
    Issuer,
    /// A responder certificate issued by the certificate's issuer for OCSP
    /// signing.
    Delegate {
        /// The responder certificate's `notAfter`.
        not_after: UnixTime,
        /// Whether the responder certificate carries
        /// `id-pkix-ocsp-nocheck`; otherwise a CRL showed it unrevoked.
        nocheck: bool,
    },
}

/// The authenticated status of one certificate, with what a cache or a
/// stapling server needs to decide how long to keep the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedOcspStatus<'a> {
    /// The certificate's status. [`CertStatus::Unknown`] and
    /// [`CertStatus::Revoked`] are authenticated answers.
    pub status: CertStatus,
    /// `thisUpdate` of the single response.
    pub this_update: UnixTime,
    /// `nextUpdate` of the single response.
    pub next_update: Option<UnixTime>,
    /// `producedAt` of the response.
    pub produced_at: UnixTime,
    /// When the status stops being acceptable under the policy that
    /// verified it: the earliest of `nextUpdate` (or `thisUpdate` plus
    /// [`OcspPolicy::validity_without_next_update`]), `thisUpdate` plus
    /// [`OcspPolicy::max_age`], the responder certificate's `notAfter` and
    /// the `nextUpdate` of the CRL that cleared the responder certificate.
    /// The clock skew allowance is not included.
    pub expires: UnixTime,
    /// Who signed the response.
    pub signer: OcspSigner,
    /// The hash algorithm of the matching `CertID`.
    pub cert_id_hash: CertIdHash,
    /// The signed certificate timestamp list of the matching single
    /// response (RFC 6962 section 3.3) in its TLS encoding, if present.
    /// The timestamps themselves are not verified.
    pub sct_list: Option<&'a [u8]>,
    /// The `TransItemList` of the RFC 9162 Transparency Information
    /// extension of the matching single response (RFC 9162 section 7.1.1),
    /// if present, for
    /// [`CtV2Verifier::verify_ocsp_response`](crate::transparency::CtV2Verifier::verify_ocsp_response).
    /// The items themselves are not verified.
    pub transparency_info: Option<&'a [u8]>,
    /// Whether the response echoed [`OcspPolicy::expected_nonce`].
    pub nonce_matched: bool,
}

/// Parses `der` and verifies it for `cert`: see [`OcspResponse::from_der`]
/// and [`OcspResponse::verify`].
///
/// # Errors
///
/// Those of the two functions.
pub fn verify_response<'a>(
    der: &'a [u8],
    cert: &Cert<'_>,
    issuer: &OcspIssuer<'_>,
    policy: &OcspPolicy<'_>,
) -> Result<VerifiedOcspStatus<'a>, OcspError> {
    OcspResponse::from_der(der)?.verify(cert, issuer, policy)
}

impl<'a> OcspResponse<'a> {
    /// Authenticates the response and returns the status it gives for
    /// `cert`, which `issuer` issued.
    ///
    /// 1. The response must be successful and contain exactly one single
    ///    response whose `CertID` (SHA-1 or SHA-256) names `cert`. A second
    ///    one, or an entry with the certificate's serial number under an
    ///    unknown hash algorithm beside it, is rejected as
    ///    [`OcspError::AmbiguousResponse`] whatever the statuses.
    /// 2. The signer named by the responder identifier must be `issuer`,
    ///    or a certificate in the response that `issuer` issued and
    ///    signed, that is within its validity period, has an explicit
    ///    `id-kp-OCSPSigning` extended key usage, a key usage permitting
    ///    signatures, and either `id-pkix-ocsp-nocheck` or a current CRL
    ///    among [`OcspPolicy::delegate_crls`] that does not list it.
    /// 3. The response signature must verify with that signer's key.
    /// 4. The validation time must lie within the response's validity as
    ///    the policy bounds it, and the nonce must satisfy the policy.
    ///
    /// Neither `cert`'s own validity nor `issuer`'s authority is checked.
    /// An issuer that signs responses itself is not required to assert a
    /// particular key usage.
    ///
    /// # Errors
    ///
    /// See [`OcspError`]. In particular
    /// [`OcspError::ResponderUnsuccessful`] for a response without status
    /// information, and [`OcspError::Expired`] or
    /// [`OcspError::NotYetValid`] for an authentic response outside its
    /// freshness window.
    pub fn verify(
        &self,
        cert: &Cert<'_>,
        issuer: &OcspIssuer<'_>,
        policy: &OcspPolicy<'_>,
    ) -> Result<VerifiedOcspStatus<'a>, OcspError> {
        let Some(basic) = &self.basic else {
            return Err(OcspError::ResponderUnsuccessful(self.status));
        };
        if cert.issuer != issuer.subject {
            return Err(OcspError::IssuerMismatch);
        }
        let issuer_spki =
            Spki::from_der_or_contents(issuer.spki).map_err(OcspError::BadIssuerKey)?;

        let single = matching_response(basic, cert, &issuer_spki, &policy.hashers)?;
        let mut budget = Budget::default();
        let (signer, signer_expiry) =
            authenticate(basic, issuer, &issuer_spki, policy, &mut budget)?;
        let expires = check_freshness(basic, &single, signer_expiry, policy)?;

        let nonce_matched = match (policy.expected_nonce, basic.nonce) {
            (Some(expected), Some(nonce)) if expected == nonce => true,
            (Some(_), Some(_)) => return Err(OcspError::NonceMismatch),
            (Some(_), None) if policy.require_nonce => return Err(OcspError::NonceMissing),
            _ => false,
        };

        Ok(VerifiedOcspStatus {
            status: single.status,
            this_update: single.this_update,
            next_update: single.next_update,
            produced_at: basic.produced_at,
            expires,
            signer,
            cert_id_hash: single.cert_id.hash.unwrap_or(CertIdHash::Sha1),
            sct_list: single.sct_list,
            transparency_info: single.transparency_info,
            nonce_matched,
        })
    }
}

/// Finds the one single response about `cert`.
///
/// Every single response carrying the certificate's serial number is
/// examined, so the answer never depends on the order of the entries:
///
/// * two entries naming the certificate (under the same or under different
///   hash algorithms, whatever their statuses) make the response ambiguous;
/// * so does an entry under a hash algorithm this crate does not know
///   beside a matching one, because it cannot be shown to be about another
///   issuer's certificate;
/// * an entry that needs a missing digest function reports that function,
///   for the same reason.
fn matching_response<'a>(
    basic: &BasicResponse<'a>,
    cert: &Cert<'_>,
    issuer_spki: &Spki<'_>,
    hashers: &CertIdHashers,
) -> Result<SingleResponse<'a>, OcspError> {
    // At most one identifier per algorithm is computed, whatever the
    // number of single responses.
    let mut sha1 = None;
    let mut sha256 = None;
    let mut unavailable = None;
    let mut unknown_algorithm = false;
    let mut found = None;
    for single in basic.responses() {
        if single.cert_id.serial != cert.serial {
            continue;
        }
        let Some(hash) = single.cert_id.hash else {
            unknown_algorithm = true;
            continue;
        };
        let slot = match hash {
            CertIdHash::Sha1 => &mut sha1,
            CertIdHash::Sha256 => &mut sha256,
        };
        if slot.is_none() {
            *slot = Some(CertId::compute(hash, hashers, cert, issuer_spki.key));
        }
        match slot {
            Some(Ok(expected)) if expected.matches(&single.cert_id) => {
                if found.is_some() {
                    return Err(OcspError::AmbiguousResponse);
                }
                found = Some(single);
            }
            Some(Err(error)) => {
                unavailable.get_or_insert_with(|| error.clone());
            }
            _ => {}
        }
    }
    if let Some(unavailable) = unavailable {
        return Err(unavailable);
    }
    match found {
        Some(_) if unknown_algorithm => Err(OcspError::AmbiguousResponse),
        Some(single) => Ok(single),
        None => Err(OcspError::NoMatchingResponse),
    }
}

/// Identifies the authorized signer of `basic` and verifies the response
/// signature with its key. Returns the signer and the time its
/// authorization ends, if it does.
fn authenticate(
    basic: &BasicResponse<'_>,
    issuer: &OcspIssuer<'_>,
    issuer_spki: &Spki<'_>,
    policy: &OcspPolicy<'_>,
    budget: &mut Budget,
) -> Result<(OcspSigner, Option<UnixTime>), OcspError> {
    let algs = policy.supported_sig_algs;
    let mut first_error = None;

    if responder_is(basic.responder_id, issuer.subject, issuer_spki, policy)? {
        match signed_data::verify_signed_data(algs, issuer_spki, &basic.signed, budget) {
            Ok(()) => return Ok((OcspSigner::Issuer, None)),
            Err(error) if error.is_fatal() => return Err(OcspError::BadSignature(error)),
            // A responder certificate may share the issuer's name.
            Err(error) => first_error = Some(OcspError::BadSignature(error)),
        }
    }

    for der in basic.certificates() {
        let attempt =
            authenticate_delegate(basic, der.as_ref(), issuer, issuer_spki, policy, budget);
        match attempt {
            Ok(Some(authorized)) => return Ok(authorized),
            // Not the certificate the responder identifier names.
            Ok(None) => {}
            Err(error) => {
                if is_budget_error(&error) {
                    return Err(error);
                }
                first_error.get_or_insert(error);
            }
        }
    }
    Err(first_error.unwrap_or(OcspError::UnknownResponder))
}

/// Whether `error` reports the exhausted signature budget, which ends the
/// search for a signer.
fn is_budget_error(error: &OcspError) -> bool {
    match error {
        OcspError::BadSignature(inner)
        | OcspError::DelegateInvalid(inner)
        | OcspError::DelegateCrl(inner) => inner.is_fatal(),
        _ => false,
    }
}

/// Whether `id` names the holder of `subject` and `spki`.
fn responder_is(
    id: ResponderId<'_>,
    subject: &[u8],
    spki: &Spki<'_>,
    policy: &OcspPolicy<'_>,
) -> Result<bool, OcspError> {
    match id {
        ResponderId::ByName(name) => Ok(name == subject),
        ResponderId::ByKey(hash) => {
            let key_hash = policy.hashers.digest(CertIdHash::Sha1, spki.key)?;
            Ok(key_hash.as_slice() == hash)
        }
    }
}

/// Checks whether the carried certificate `der` is the responder the
/// response names and, if so, that `issuer` authorized it and that it
/// signed the response. `Ok(None)` means it is another certificate.
fn authenticate_delegate(
    basic: &BasicResponse<'_>,
    der: &[u8],
    issuer: &OcspIssuer<'_>,
    issuer_spki: &Spki<'_>,
    policy: &OcspPolicy<'_>,
    budget: &mut Budget,
) -> Result<Option<(OcspSigner, Option<UnixTime>)>, OcspError> {
    // Certificates this crate cannot parse are not candidates: a response
    // may carry unrelated ones.
    let Ok(delegate) = Cert::from_der(der) else {
        return Ok(None);
    };
    let Ok(delegate_spki) = Spki::from_contents(delegate.spki) else {
        return Ok(None);
    };
    if !responder_is(basic.responder_id, delegate.subject, &delegate_spki, policy)? {
        return Ok(None);
    }

    // RFC 6960 section 4.2.2.2: the delegation certificate is issued
    // directly by the CA that issued the certificate in question.
    if delegate.issuer != issuer.subject {
        return Err(OcspError::DelegateNotIssuedByCa);
    }
    let algs = policy.supported_sig_algs;
    signed_data::verify_signed_data(algs, issuer_spki, &delegate.signed, budget)
        .map_err(OcspError::DelegateInvalid)?;
    let time = policy.time;
    if time < delegate.not_before {
        return Err(OcspError::DelegateInvalid(Error::CertNotValidYet {
            time,
            not_before: delegate.not_before,
        }));
    }
    if time > delegate.not_after {
        return Err(OcspError::DelegateInvalid(Error::CertExpired {
            time,
            not_after: delegate.not_after,
        }));
    }
    // The usage must be asserted explicitly: neither an absent extension
    // nor anyExtendedKeyUsage delegates OCSP signing.
    let ocsp_signer = delegate
        .extended_key_usage()
        .is_some_and(|mut purposes| purposes.any(|purpose| purpose == oid::KP_OCSP_SIGNING));
    if !ocsp_signer {
        return Err(OcspError::DelegateNotOcspSigner);
    }
    // RFC 9881 §5 further restricts the key usage of an ML-DSA key.
    if !delegate.key_usage_permits(KU_DIGITAL_SIGNATURE)
        || delegate.key_usage_allowed_for_public_key().is_err()
    {
        return Err(OcspError::DelegateKeyUsage);
    }

    let nocheck = has_ocsp_nocheck(&delegate).map_err(OcspError::DelegateInvalid)?;
    let mut expiry = delegate.not_after;
    if !nocheck {
        let crl_expiry = delegate_unrevoked(&delegate, issuer, issuer_spki, policy, budget)?;
        expiry = expiry.min(crl_expiry);
    }

    signed_data::verify_signed_data(algs, &delegate_spki, &basic.signed, budget)
        .map_err(OcspError::BadSignature)?;
    let signer = OcspSigner::Delegate {
        not_after: delegate.not_after,
        nocheck,
    };
    Ok(Some((signer, Some(expiry))))
}

/// Shows through the policy's CRLs that `delegate` is not revoked, and
/// returns the latest `nextUpdate` among the CRLs that show it.
fn delegate_unrevoked(
    delegate: &Cert<'_>,
    issuer: &OcspIssuer<'_>,
    issuer_spki: &Spki<'_>,
    policy: &OcspPolicy<'_>,
    budget: &mut Budget,
) -> Result<UnixTime, OcspError> {
    let time = policy.time;
    let mut cleared_until = None;
    for crl in policy
        .delegate_crls
        .iter()
        .filter(|crl| crl.issuer() == issuer.subject && crl.scope_covers(delegate, Role::EndEntity))
    {
        crl.verify_signature_budgeted(policy.supported_sig_algs, issuer_spki, budget)
            .map_err(OcspError::DelegateCrl)?;
        // A CRL that is no longer or not yet current proves nothing.
        if time >= crl.next_update() || time < crl.this_update() {
            continue;
        }
        if !issuer.may_sign_crls {
            return Err(OcspError::DelegateCrl(Error::IssuerNotCrlSigner));
        }
        let listed = crl
            .find_serial(delegate.serial)
            .map_err(OcspError::DelegateCrl)?;
        if listed.is_some() {
            return Err(OcspError::DelegateRevoked);
        }
        let next_update = crl.next_update();
        cleared_until = Some(cleared_until.map_or(next_update, |t: UnixTime| t.max(next_update)));
    }
    cleared_until.ok_or(OcspError::DelegateRevocationUnknown)
}

/// Checks the validation time against the response's validity interval
/// and returns when the status expires.
fn check_freshness(
    basic: &BasicResponse<'_>,
    single: &SingleResponse<'_>,
    signer_expiry: Option<UnixTime>,
    policy: &OcspPolicy<'_>,
) -> Result<UnixTime, OcspError> {
    let time = policy.time;
    let this_update = single.this_update;
    if single.next_update.is_some_and(|next| next < this_update) {
        return Err(OcspError::InvalidUpdateTimes);
    }
    if single.next_update.is_none() && policy.require_next_update {
        return Err(OcspError::MissingNextUpdate);
    }

    let not_before = this_update.max(basic.produced_at);
    if not_before > plus(time, policy.clock_skew) {
        return Err(OcspError::NotYetValid { time, not_before });
    }

    let mut expires = single
        .next_update
        .unwrap_or_else(|| plus(this_update, policy.validity_without_next_update));
    if let Some(max_age) = policy.max_age {
        expires = expires.min(plus(this_update, max_age));
    }
    if let Some(signer_expiry) = signer_expiry {
        expires = expires.min(signer_expiry);
    }
    if time > plus(expires, policy.clock_skew) {
        return Err(OcspError::Expired { time, expires });
    }
    Ok(expires)
}

/// `time` plus `duration`, saturating.
fn plus(time: UnixTime, duration: Duration) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(
        time.as_secs().saturating_add(duration.as_secs()),
    ))
}
