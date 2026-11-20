//! Signed Certificate Timestamps of Certificate Transparency version 1
//! (RFC 6962): verification of the SCTs delivered with a certificate
//! against the CT logs an application trusts.
//!
//! An [`SctVerifier`] is bound to one certificate and accepts SCTs from the
//! three RFC 6962 §3.3 sources:
//!
//! | Source | Method | Signed entry |
//! |---|---|---|
//! | X.509v3 extension of the certificate | [`SctVerifier::verify_embedded`] | `precert_entry` |
//! | TLS `signed_certificate_timestamp` extension | [`SctVerifier::verify_tls_extension`] | `x509_entry` |
//! | Stapled OCSP response extension | [`SctVerifier::verify_ocsp_extension`] | `x509_entry` |
//!
//! Each SCT whose log is trusted, whose timestamp the log's validity window
//! and the clock allow, and whose signature verifies is recorded as a
//! [`VerifiedSct`]: a log ID and a timestamp in milliseconds, which is the
//! input a CRLite filter needs to decide whether it covers the certificate.
//!
//! # Signed entries
//!
//! An SCT does not carry its entry type: RFC 6962 §3.2 leaves it "implicit
//! from the context in which the SCT is presented".
//!
//! * Embedded SCTs sign a `precert_entry`: the SHA-256 digest of the
//!   issuer's `SubjectPublicKeyInfo` and the certificate's `TBSCertificate`
//!   without the SCT list extension. The `TBSCertificate` is rebuilt from
//!   the exact octets of the certificate; only the lengths of the elements
//!   enclosing the removed extension are re-encoded. The issuer key is the
//!   key that signed the certificate, including when the precertificate was
//!   issued by a Precertificate Signing Certificate (the log then signs the
//!   entry as issued by the final issuer, RFC 6962 §3.2).
//! * SCTs from the TLS extension or an OCSP response sign an `x509_entry`:
//!   the complete certificate, as deployed verifiers interpret them.
//!   A CA may instead hand the server SCTs obtained for a precertificate,
//!   which the server can only deliver out of band. With
//!   [`SctOptions::allow_out_of_band_precert_entry`] such an SCT is also
//!   tried as a `precert_entry` over the same reconstruction when the
//!   `x509_entry` signature fails. This is off by default, needs the issuer
//!   key, and costs a second signature verification per such SCT.
//!
//! # Caller contract
//!
//! This module verifies log signatures and nothing else:
//!
//! * The certificate must be the end entity of a path the caller validated,
//!   and `issuer_spki` the key of its issuer in that path. A wrong issuer
//!   key only makes embedded SCTs fail.
//! * An OCSP SCT list must come from a response the caller authenticated
//!   and matched to this certificate. The SCT signatures themselves bind
//!   the list to the certificate.
//! * The CT logs, their keys and their validity windows are the
//!   application's trust decision ([`CtLog`]).
//! * How many SCTs, from which operators, a connection needs is a policy
//!   for the caller to apply to [`SctVerifier::verified`].
//!
//! # Untrusted input and bounds
//!
//! SCT lists and the certificate are peer-controlled. Lists are parsed with
//! exact lengths and validated completely before any signature is checked,
//! so a malformed or oversized list contributes nothing. [`SctOptions`] caps
//! the size of each list, of each SCT's extensions and signature, and, across
//! all sources of one verifier, the number of SCTs and of signature
//! verifications. An SCT naming an unknown log costs no signature
//! verification. Memory use is two copies of the certificate at most.
//!
//! This module contains no cryptography: signatures are verified through
//! [`SignatureVerificationAlgorithm`] and SHA-256 is injected ([`Sha256`]).

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use crate::alg_id::{self, AlgorithmIdentifier};
use crate::cert::Cert;
use crate::der::{self, HexDebug, tag};
use crate::error::Error;
use crate::signed_data::{SignedData, Spki};
use crate::time::UnixTime;
use crate::types::SignatureVerificationAlgorithm;

pub(crate) mod precert;
mod wire;

use precert::{SignedEntry, SignedInput};
use wire::{LOG_ID_LEN, Sct, SctList, SctV1};

/// SHA-256 of a message, supplied by a cryptography provider.
pub type Sha256 = fn(&[u8]) -> [u8; 32];

/// `extnID` contents of the certificate extension holding embedded SCTs
/// (1.3.6.1.4.1.11129.2.4.2, RFC 6962 §3.3).
pub const EMBEDDED_SCT_LIST_OID: &[u8] =
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

/// `extnID` contents of the OCSP `singleExtensions` extension holding SCTs
/// (1.3.6.1.4.1.11129.2.4.5, RFC 6962 §3.3).
pub const OCSP_SCT_LIST_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x05];

/// `HashAlgorithm.sha256` (RFC 5246 §7.4.1.4.1), the only hash RFC 6962
/// §2.1.4 allows.
const HASH_SHA256: u8 = 4;
/// `SignatureAlgorithm.rsa`: RSASSA-PKCS1-v1_5.
const SIGNATURE_RSA: u8 = 1;
/// `SignatureAlgorithm.ecdsa`.
const SIGNATURE_ECDSA: u8 = 3;

/// An error that rejects a whole SCT source or a verifier input.
///
/// Problems of a single SCT (unknown log, bad signature and so on) are not
/// errors: they are counted in the [`SctReport`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SctError {
    /// An SCT list, or the extension value wrapping it, is not exactly
    /// encoded: a truncated or overlong vector, an empty list or SCT, or
    /// bytes left over.
    MalformedList,
    /// An SCT list is longer than [`SctOptions::max_list_len`].
    ListTooLarge,
    /// More SCTs were presented, over all sources, than
    /// [`SctOptions::max_scts`].
    TooManyScts,
    /// The extensions or the signature of an SCT exceed
    /// [`SctOptions::max_sct_extensions_len`] or
    /// [`SctOptions::max_signature_len`].
    SctTooLarge,
    /// Verifying another SCT would exceed
    /// [`SctOptions::max_signature_verifications`].
    SignatureBudgetExceeded,
    /// The certificate has embedded SCTs but no issuer key was given.
    IssuerKeyRequired,
    /// The issuer key is not a `SubjectPublicKeyInfo`.
    MalformedIssuerKey,
    /// A CT log key is not a `SubjectPublicKeyInfo`.
    MalformedLogKey,
    /// A CT log key does not hash to the expected log ID.
    LogIdMismatch,
    /// The certificate could not be re-encoded without its SCT list.
    MalformedCertificate,
    /// The certificate has more than one SCT list extension.
    DuplicateSctExtension,
}

impl fmt::Display for SctError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for SctError {}

/// A CT log the application trusts: its public key, the log ID derived
/// from it, and the SCT timestamps it is trusted for.
#[derive(Clone, PartialEq, Eq)]
pub struct CtLog<'a> {
    id: [u8; LOG_ID_LEN],
    /// `SubjectPublicKeyInfo`, complete or contents, checked to parse.
    spki: &'a [u8],
    /// First trusted timestamp, in milliseconds.
    from_ms: u64,
    /// First timestamp no longer trusted, in milliseconds.
    until_ms: u64,
}

impl<'a> CtLog<'a> {
    /// A log with the public key `spki`, given as a complete DER
    /// `SubjectPublicKeyInfo` or as its contents. The log ID is the SHA-256
    /// digest of the complete encoding (RFC 6962 §3.2), so an ID can never
    /// be paired with another log's key. Every timestamp is trusted until
    /// [`Self::with_timestamp_window`] narrows that.
    ///
    /// # Errors
    ///
    /// [`SctError::MalformedLogKey`] if `spki` is neither form.
    pub fn new(spki: &'a [u8], sha256: Sha256) -> Result<Self, SctError> {
        let complete = complete_spki(spki).ok_or(SctError::MalformedLogKey)?;
        Ok(Self {
            id: sha256(&complete),
            spki,
            from_ms: 0,
            until_ms: u64::MAX,
        })
    }

    /// Checks that the key hashes to `id`, the log ID a log list gives.
    ///
    /// # Errors
    ///
    /// [`SctError::LogIdMismatch`] otherwise.
    pub fn with_expected_id(self, id: &[u8; 32]) -> Result<Self, SctError> {
        if self.id == *id {
            Ok(self)
        } else {
            Err(SctError::LogIdMismatch)
        }
    }

    /// Trusts only SCTs whose timestamp, in milliseconds since the Unix
    /// epoch, is at least `from_ms` and less than `until_ms`: for example
    /// until the time a log was retired or distrusted. An empty window
    /// trusts nothing.
    #[must_use]
    pub fn with_timestamp_window(mut self, from_ms: u64, until_ms: u64) -> Self {
        self.from_ms = from_ms;
        self.until_ms = until_ms;
        self
    }

    /// The log ID: the SHA-256 digest of the log's `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    fn trusts_timestamp(&self, timestamp_ms: u64) -> bool {
        (self.from_ms..self.until_ms).contains(&timestamp_ms)
    }
}

impl fmt::Debug for CtLog<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtLog")
            .field("id", &HexDebug(&self.id))
            .field("from_ms", &self.from_ms)
            .field("until_ms", &self.until_ms)
            .finish_non_exhaustive()
    }
}

/// Returns `spki` as a complete `SubjectPublicKeyInfo` `SEQUENCE`, adding
/// the header when only the contents were given.
pub(crate) fn complete_spki(spki: &[u8]) -> Option<Cow<'_, [u8]>> {
    let complete = der::read_all(spki, |r| r.expect(tag::SEQUENCE))
        .and_then(Spki::from_contents)
        .is_ok();
    if complete {
        return Some(Cow::Borrowed(spki));
    }
    Spki::from_contents(spki).ok()?;
    let mut out = Vec::with_capacity(spki.len().saturating_add(4));
    precert::push_header(&mut out, tag::SEQUENCE, spki.len()).ok()?;
    out.extend_from_slice(spki);
    Some(Cow::Owned(out))
}

/// Resource limits and acceptance options of SCT verification.
///
/// The defaults suit certificates as publicly trusted CAs issue them (a
/// handful of SCTs of about 120 octets each).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SctOptions {
    /// Largest `SignedCertificateTimestampList`, in octets, accepted from
    /// one source. Default 4096.
    pub max_list_len: usize,
    /// Most SCTs accepted over all sources of one verifier, counting those
    /// that are skipped. Default 24.
    pub max_scts: usize,
    /// Most signature verifications over all sources of one verifier.
    /// Default 12.
    pub max_signature_verifications: usize,
    /// Largest `CtExtensions` of one SCT, in octets. Version 1 defines no
    /// extension, but logs use the field (for example for a leaf index).
    /// Default 256.
    pub max_sct_extensions_len: usize,
    /// Largest signature of one SCT, in octets. Default 512 (RSA-4096).
    pub max_signature_len: usize,
    /// How far, in milliseconds, an SCT timestamp may lie after the
    /// verification time. Default 0: no timestamp from the future.
    pub future_tolerance_ms: u64,
    /// Whether an SCT from the TLS extension or an OCSP response whose
    /// `x509_entry` signature fails is also tried as a `precert_entry`
    /// (see the [module documentation](self)). Default `false`.
    pub allow_out_of_band_precert_entry: bool,
}

impl Default for SctOptions {
    fn default() -> Self {
        Self {
            max_list_len: 4096,
            max_scts: 24,
            max_signature_verifications: 12,
            max_sct_extensions_len: 256,
            max_signature_len: 512,
            future_tolerance_ms: 0,
            allow_out_of_band_precert_entry: false,
        }
    }
}

/// What an application trusts for Certificate Transparency.
#[derive(Clone, Debug)]
pub struct CtPolicy<'a> {
    /// The trusted logs. The first log with a given ID is used.
    pub logs: &'a [CtLog<'a>],
    /// Algorithms for log signatures. A log signs with ECDSA or
    /// RSASSA-PKCS1-v1_5, both over SHA-256 ([`alg_id::ECDSA_SHA256`],
    /// [`alg_id::RSA_PKCS1_SHA256`]); an algorithm is chosen by these
    /// identifiers and the log key's, as for certificate signatures.
    pub supported_sig_algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    /// SHA-256, for the issuer key hash.
    pub sha256: Sha256,
    /// Limits and options.
    pub options: SctOptions,
}

/// How an SCT reached the client (RFC 6962 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SctSource {
    /// The SCT list extension of the certificate.
    Embedded,
    /// The TLS `signed_certificate_timestamp` extension.
    TlsExtension,
    /// An extension of a stapled OCSP response.
    OcspResponse,
}

/// The log entry an SCT signature was verified over (RFC 6962 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SctEntryType {
    /// `x509_entry`: the complete certificate.
    X509,
    /// `precert_entry`: the issuer key hash and the `TBSCertificate`
    /// without the SCT list.
    Precert,
}

/// An SCT whose signature by a trusted log was verified for the
/// verifier's certificate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifiedSct {
    log_id: [u8; LOG_ID_LEN],
    timestamp_ms: u64,
    source: SctSource,
    entry_type: SctEntryType,
}

impl VerifiedSct {
    /// The ID of the log that signed the SCT.
    #[must_use]
    pub fn log_id(&self) -> &[u8; 32] {
        &self.log_id
    }

    /// The SCT timestamp, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// The source that first delivered the SCT.
    #[must_use]
    pub fn source(&self) -> SctSource {
        self.source
    }

    /// The entry type the signature covers.
    #[must_use]
    pub fn entry_type(&self) -> SctEntryType {
        self.entry_type
    }
}

impl fmt::Debug for VerifiedSct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedSct")
            .field("log_id", &HexDebug(&self.log_id))
            .field("timestamp_ms", &self.timestamp_ms)
            .field("source", &self.source)
            .field("entry_type", &self.entry_type)
            .finish()
    }
}

/// What became of the SCTs of one source. Every SCT of the list is counted
/// in exactly one field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SctReport {
    /// Verified and added to [`SctVerifier::verified`].
    pub verified: usize,
    /// From a trusted log with the timestamp of an SCT already verified;
    /// not verified again.
    pub duplicate: usize,
    /// From a log that is not trusted.
    pub unknown_log: usize,
    /// From a trusted log, with a timestamp outside its validity window.
    pub outside_log_validity: usize,
    /// With a timestamp after the verification time and tolerance.
    pub future_timestamp: usize,
    /// With a signature the log's key does not verify.
    pub invalid_signature: usize,
    /// Of a version other than 1, skipped.
    pub unsupported_version: usize,
    /// Signed with an algorithm RFC 6962 does not allow, or for which no
    /// supported algorithm matches the log's key.
    pub unsupported_algorithm: usize,
}

/// Verifies the SCTs of one certificate, from any of the three sources,
/// under shared limits. See the [module documentation](self).
pub struct SctVerifier<'a> {
    policy: &'a CtPolicy<'a>,
    cert: &'a Cert<'a>,
    issuer_key_hash: Option<[u8; 32]>,
    /// Latest acceptable timestamp, in milliseconds.
    latest_ms: u64,
    remaining_scts: usize,
    remaining_signatures: usize,
    x509: Option<SignedInput>,
    precert: Option<SignedInput>,
    verified: Vec<VerifiedSct>,
}

impl<'a> SctVerifier<'a> {
    /// A verifier for `cert` at time `now`.
    ///
    /// `issuer_spki` is the public key of the certificate's issuer, as a
    /// complete DER `SubjectPublicKeyInfo` (such as
    /// [`Cert::subject_public_key_info`] of the issuer) or as its contents
    /// (such as
    /// [`TrustAnchor::subject_public_key_info`](crate::TrustAnchor::subject_public_key_info)).
    /// It is required for embedded SCTs and for
    /// [`SctOptions::allow_out_of_band_precert_entry`].
    ///
    /// # Errors
    ///
    /// [`SctError::MalformedIssuerKey`] if `issuer_spki` is neither form.
    pub fn new(
        policy: &'a CtPolicy<'a>,
        cert: &'a Cert<'a>,
        issuer_spki: Option<&[u8]>,
        now: UnixTime,
    ) -> Result<Self, SctError> {
        let issuer_key_hash = issuer_spki
            .map(|spki| {
                complete_spki(spki)
                    .map(|complete| (policy.sha256)(&complete))
                    .ok_or(SctError::MalformedIssuerKey)
            })
            .transpose()?;
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
            remaining_scts: policy.options.max_scts,
            remaining_signatures: policy.options.max_signature_verifications,
            x509: None,
            precert: None,
            verified: Vec::new(),
        })
    }

    /// Verifies the SCTs embedded in the certificate, as `precert_entry`
    /// signatures. A certificate without the SCT list extension yields an
    /// empty report.
    ///
    /// # Errors
    ///
    /// [`SctError::IssuerKeyRequired`] if the certificate has the extension
    /// and the verifier no issuer key; [`SctError::DuplicateSctExtension`];
    /// [`SctError::MalformedList`] if the extension value is not an
    /// `OCTET STRING` holding exactly one list; and the errors of
    /// [`Self::verify_tls_extension`].
    pub fn verify_embedded(&mut self) -> Result<SctReport, SctError> {
        let Some(extn_value) = self.prepare_precert()? else {
            return Ok(SctReport::default());
        };
        if self.precert.is_none() {
            return Err(SctError::IssuerKeyRequired);
        }
        self.verify_list(unwrap_list(extn_value)?, SctSource::Embedded)
    }

    /// Verifies the `SignedCertificateTimestampList` of a TLS
    /// `signed_certificate_timestamp` extension (the `extension_data`), as
    /// `x509_entry` signatures.
    ///
    /// # Errors
    ///
    /// [`SctError::ListTooLarge`], [`SctError::MalformedList`],
    /// [`SctError::SctTooLarge`] or [`SctError::TooManyScts`], in which case
    /// no SCT of the list was verified; [`SctError::SignatureBudgetExceeded`],
    /// in which case the SCTs verified before the limit remain in
    /// [`Self::verified`].
    pub fn verify_tls_extension(&mut self, sct_list: &[u8]) -> Result<SctReport, SctError> {
        self.verify_list(sct_list, SctSource::TlsExtension)
    }

    /// Verifies the SCT list of an OCSP response, as `x509_entry`
    /// signatures. `extn_value` is the `extnValue` contents of the
    /// [`OCSP_SCT_LIST_OID`] extension of the `SingleResponse` for this
    /// certificate: a DER `OCTET STRING` holding the list. The caller must
    /// have authenticated the response.
    ///
    /// # Errors
    ///
    /// [`SctError::MalformedList`] if `extn_value` is not an `OCTET STRING`
    /// holding exactly one list, and the errors of
    /// [`Self::verify_tls_extension`].
    pub fn verify_ocsp_extension(&mut self, extn_value: &[u8]) -> Result<SctReport, SctError> {
        self.verify_list(unwrap_list(extn_value)?, SctSource::OcspResponse)
    }

    /// The SCTs verified so far, in verification order, without repeats of
    /// a log ID and timestamp.
    #[must_use]
    pub fn verified(&self) -> &[VerifiedSct] {
        &self.verified
    }

    /// Consumes the verifier, returning [`Self::verified`].
    #[must_use]
    pub fn into_verified(self) -> Vec<VerifiedSct> {
        self.verified
    }

    /// Builds the `precert_entry` input if an issuer key is known, and
    /// returns the value of the certificate's SCT list extension.
    fn prepare_precert(&mut self) -> Result<Option<&'a [u8]>, SctError> {
        let parts = precert::tbs_without_sct_list(self.cert)?;
        if let (None, Some(issuer_key_hash)) = (&self.precert, &self.issuer_key_hash) {
            self.precert = Some(SignedInput::new(SignedEntry::Precert {
                issuer_key_hash,
                tbs: &parts.tbs,
            })?);
        }
        Ok(parts.sct_list_extension)
    }

    fn verify_list(&mut self, list: &[u8], source: SctSource) -> Result<SctReport, SctError> {
        let policy = self.policy;
        let options = &policy.options;
        let (scts, count) = SctList::parse(list, options)?;
        self.remaining_scts = self
            .remaining_scts
            .checked_sub(count)
            .ok_or(SctError::TooManyScts)?;

        let with_precert = match source {
            SctSource::Embedded => true,
            SctSource::TlsExtension | SctSource::OcspResponse => {
                if self.x509.is_none() {
                    self.x509 = Some(SignedInput::new(SignedEntry::X509(self.cert.der))?);
                }
                if options.allow_out_of_band_precert_entry
                    && self.precert.is_none()
                    && self.issuer_key_hash.is_some()
                {
                    self.prepare_precert()?;
                }
                options.allow_out_of_band_precert_entry
            }
        };

        let mut report = SctReport::default();
        for sct in scts {
            let Sct::V1(sct) = sct else {
                report.unsupported_version += 1;
                continue;
            };
            let Some(log) = policy.logs.iter().find(|log| log.id == sct.log_id) else {
                report.unknown_log += 1;
                continue;
            };
            if !log.trusts_timestamp(sct.timestamp_ms) {
                report.outside_log_validity += 1;
            } else if sct.timestamp_ms > self.latest_ms {
                report.future_timestamp += 1;
            } else if self.is_verified(&sct) {
                report.duplicate += 1;
            } else {
                let Some(algorithm) = signature_algorithm(&sct) else {
                    report.unsupported_algorithm += 1;
                    continue;
                };
                let x509 = match source {
                    SctSource::Embedded => None,
                    SctSource::TlsExtension | SctSource::OcspResponse => self.x509.as_mut(),
                };
                let precert = self.precert.as_mut().filter(|_| with_precert);
                let entries = [(SctEntryType::X509, x509), (SctEntryType::Precert, precert)];
                let mut outcome = Err(Error::InvalidSignatureForPublicKey);
                for (entry_type, input) in entries {
                    let Some(input) = input else { continue };
                    self.remaining_signatures = self
                        .remaining_signatures
                        .checked_sub(1)
                        .ok_or(SctError::SignatureBudgetExceeded)?;
                    outcome = verify_sct(policy, log, &sct, algorithm, input).map(|()| entry_type);
                    // Only a signature the key rejects can be a signature
                    // over the other entry type.
                    if outcome != Err(Error::InvalidSignatureForPublicKey) {
                        break;
                    }
                }
                match outcome {
                    Ok(entry_type) => {
                        report.verified += 1;
                        self.verified.push(VerifiedSct {
                            log_id: sct.log_id,
                            timestamp_ms: sct.timestamp_ms,
                            source,
                            entry_type,
                        });
                    }
                    Err(
                        Error::UnsupportedSignatureAlgorithm
                        | Error::UnsupportedSignatureAlgorithmForPublicKey,
                    ) => report.unsupported_algorithm += 1,
                    Err(_) => report.invalid_signature += 1,
                }
            }
        }
        Ok(report)
    }

    fn is_verified(&self, sct: &SctV1<'_>) -> bool {
        self.verified
            .iter()
            .any(|v| v.log_id == sct.log_id && v.timestamp_ms == sct.timestamp_ms)
    }
}

impl fmt::Debug for SctVerifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SctVerifier")
            .field("remaining_scts", &self.remaining_scts)
            .field("remaining_signatures", &self.remaining_signatures)
            .field("verified", &self.verified)
            .finish_non_exhaustive()
    }
}

/// The contents of the DER `OCTET STRING` that wraps an SCT list in an
/// X.509 or OCSP extension value (RFC 6962 §3.3).
fn unwrap_list(extn_value: &[u8]) -> Result<&[u8], SctError> {
    der::read_all(extn_value, |r| r.expect(tag::OCTET_STRING)).map_err(|_| SctError::MalformedList)
}

/// The X.509 identifier of the `digitally-signed` algorithms of an SCT:
/// SHA-256 with ECDSA or RSA, as RFC 6962 §2.1.4 requires of logs.
fn signature_algorithm(sct: &SctV1<'_>) -> Option<AlgorithmIdentifier> {
    match (sct.hash_algorithm, sct.signature_algorithm) {
        (HASH_SHA256, SIGNATURE_ECDSA) => Some(alg_id::ECDSA_SHA256),
        (HASH_SHA256, SIGNATURE_RSA) => Some(alg_id::RSA_PKCS1_SHA256),
        _ => None,
    }
}

/// Verifies the signature of `sct` over `input` with the key of `log`.
fn verify_sct(
    policy: &CtPolicy<'_>,
    log: &CtLog<'_>,
    sct: &SctV1<'_>,
    algorithm: AlgorithmIdentifier,
    input: &mut SignedInput,
) -> Result<(), Error> {
    let message = input
        .message(sct.timestamp_ms, sct.extensions)
        .ok_or(Error::BadDer)?;
    SignedData::from_parts(message, algorithm.as_bytes(), sct.signature)
        .verify_signature(policy.supported_sig_algs, log.spki)
}
