//! Certificate revocation lists (RFC 5280 §5).
//!
//! CRLs are parsed into a borrowed form that scans entries on demand, or an
//! owned form that indexes entries by serial number. During path validation
//! a CRL applies to a certificate when its issuer matches and its issuing
//! distribution point (if any) covers the certificate; see
//! [`RevocationOptions`] for the policies that govern missing or expired
//! CRLs.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::UnixTime;
use crate::crl_der::{self, CertList, IssuingDistributionPoint};
use crate::der::Reader;
use crate::error::Error;
use crate::path::Budget;
use crate::signed_data::{self, SignedData, Spki};
use crate::types::SignatureVerificationAlgorithm;

/// A parsed CRL, borrowed or owned.
#[derive(Debug)]
#[non_exhaustive]
pub enum CertRevocationList<'a> {
    /// A CRL that owns its data.
    Owned(OwnedCertRevocationList),
    /// A CRL borrowing its data.
    Borrowed(BorrowedCertRevocationList<'a>),
}

impl CertRevocationList<'_> {
    /// The DER-encoded issuer name (the `Name` contents, without the outer
    /// SEQUENCE, as in [`TrustAnchor::subject`](crate::TrustAnchor::subject)).
    #[must_use]
    pub fn issuer(&self) -> &[u8] {
        match self {
            Self::Owned(c) => &c.issuer,
            Self::Borrowed(c) => c.list.issuer,
        }
    }

    /// The `issuingDistributionPoint` extension value, if present.
    #[must_use]
    pub fn issuing_distribution_point(&self) -> Option<&[u8]> {
        match self {
            Self::Owned(c) => c.issuing_distribution_point.as_deref(),
            Self::Borrowed(c) => c.list.issuing_distribution_point,
        }
    }

    /// `thisUpdate`.
    #[must_use]
    pub fn this_update(&self) -> UnixTime {
        match self {
            Self::Owned(c) => c.this_update,
            Self::Borrowed(c) => c.list.this_update,
        }
    }

    /// `nextUpdate`.
    #[must_use]
    pub fn next_update(&self) -> UnixTime {
        match self {
            Self::Owned(c) => c.next_update,
            Self::Borrowed(c) => c.list.next_update,
        }
    }

    /// Looks up a revoked certificate by its `serialNumber` contents (the
    /// INTEGER value as encoded, including any sign-protecting zero).
    ///
    /// # Errors
    ///
    /// Returns an error if a borrowed CRL contains a malformed entry.
    pub fn find_serial(&self, serial: &[u8]) -> Result<Option<BorrowedRevokedCert<'_>>, Error> {
        match self {
            Self::Owned(c) => Ok(c.revoked.get(serial).map(OwnedRevokedCert::borrow)),
            Self::Borrowed(c) => {
                for entry in c {
                    let entry = entry?;
                    if entry.serial_number == serial {
                        return Ok(Some(entry));
                    }
                }
                Ok(None)
            }
        }
    }

    /// Verifies the CRL signature with the issuer's SPKI, given either as a
    /// complete `SubjectPublicKeyInfo` or as its contents.
    ///
    /// # Errors
    ///
    /// Returns a signature error when verification fails.
    pub fn verify_signature(
        &self,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        issuer_spki: &[u8],
    ) -> Result<(), Error> {
        let spki = Spki::from_der_or_contents(issuer_spki)?;
        self.verify_signature_budgeted(supported_sig_algs, &spki, &mut Budget::default())
    }

    pub(crate) fn verify_signature_budgeted(
        &self,
        algs: &[&dyn SignatureVerificationAlgorithm],
        issuer_spki: &Spki<'_>,
        budget: &mut Budget,
    ) -> Result<(), Error> {
        signed_data::verify_signed_data(algs, issuer_spki, &self.signed_data(), budget).map_err(
            |e| match e {
                Error::UnsupportedSignatureAlgorithm => Error::UnsupportedCrlSignatureAlgorithm,
                Error::UnsupportedSignatureAlgorithmForPublicKey => {
                    Error::UnsupportedCrlSignatureAlgorithmForPublicKey
                }
                Error::InvalidSignatureForPublicKey => Error::InvalidCrlSignatureForPublicKey,
                other => other,
            },
        )
    }

    fn signed_data(&self) -> SignedData<'_> {
        match self {
            Self::Owned(c) => SignedData {
                data: &c.signed_data,
                algorithm: &c.signature_algorithm,
                signature: &c.signature,
            },
            Self::Borrowed(c) => c.list.signed,
        }
    }

    /// Whether this CRL's issuing distribution point, if any, covers `cert`.
    pub(crate) fn scope_covers(
        &self,
        cert: &crate::cert::Cert<'_>,
        role: crate::path::Role,
    ) -> bool {
        match self.issuing_distribution_point() {
            None => true,
            // Validated when the CRL was parsed, so this cannot fail.
            Some(idp) => {
                IssuingDistributionPoint::parse(idp).is_ok_and(|idp| idp.covers(cert, role))
            }
        }
    }
}

impl From<OwnedCertRevocationList> for CertRevocationList<'_> {
    fn from(c: OwnedCertRevocationList) -> Self {
        Self::Owned(c)
    }
}

impl<'a> From<BorrowedCertRevocationList<'a>> for CertRevocationList<'a> {
    fn from(c: BorrowedCertRevocationList<'a>) -> Self {
        Self::Borrowed(c)
    }
}

/// A CRL that owns its data, with revoked entries indexed by serial number.
#[derive(Clone, Debug)]
pub struct OwnedCertRevocationList {
    signed_data: Vec<u8>,
    signature_algorithm: Vec<u8>,
    signature: Vec<u8>,
    issuer: Vec<u8>,
    issuing_distribution_point: Option<Vec<u8>>,
    this_update: UnixTime,
    next_update: UnixTime,
    revoked: BTreeMap<Vec<u8>, OwnedRevokedCert>,
}

impl OwnedCertRevocationList {
    /// Parses a DER-encoded CRL, decoding every revoked entry.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unsupported CRLs.
    pub fn from_der(crl_der: &[u8]) -> Result<Self, Error> {
        BorrowedCertRevocationList::from_der(crl_der)?.to_owned()
    }

    /// The revoked certificates, ordered by serial number encoding.
    pub fn revoked_certs(&self) -> impl Iterator<Item = &OwnedRevokedCert> {
        self.revoked.values()
    }
}

/// A CRL borrowing its data.
#[derive(Debug)]
pub struct BorrowedCertRevocationList<'a> {
    list: CertList<'a>,
}

impl<'a> BorrowedCertRevocationList<'a> {
    /// Parses a DER-encoded CRL. Revoked entries are decoded lazily by
    /// [`CertRevocationList::find_serial`] and iteration.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unsupported CRLs.
    pub fn from_der(crl_der: &'a [u8]) -> Result<Self, Error> {
        CertList::parse(crl_der).map(|list| Self { list })
    }

    /// Copies into an owned CRL, decoding every revoked entry.
    ///
    /// # Errors
    ///
    /// Returns an error if any revoked entry is malformed or unsupported.
    pub fn to_owned(&self) -> Result<OwnedCertRevocationList, Error> {
        let mut revoked = BTreeMap::new();
        for entry in self {
            let entry = entry?;
            revoked.insert(entry.serial_number.to_vec(), entry.to_owned());
        }
        Ok(OwnedCertRevocationList {
            signed_data: self.list.signed.data.to_vec(),
            signature_algorithm: self.list.signed.algorithm.to_vec(),
            signature: self.list.signed.signature.to_vec(),
            issuer: self.list.issuer.to_vec(),
            issuing_distribution_point: self.list.issuing_distribution_point.map(<[u8]>::to_vec),
            this_update: self.list.this_update,
            next_update: self.list.next_update,
            revoked,
        })
    }
}

impl<'a> IntoIterator for &'a BorrowedCertRevocationList<'a> {
    type Item = Result<BorrowedRevokedCert<'a>, Error>;
    type IntoIter = RevokedCerts<'a>;

    fn into_iter(self) -> RevokedCerts<'a> {
        RevokedCerts {
            reader: Some(Reader::new(self.list.revoked)),
        }
    }
}

/// Iterator over the entries of a borrowed CRL; stops after the first error.
#[derive(Debug)]
pub struct RevokedCerts<'a> {
    reader: Option<Reader<'a>>,
}

impl<'a> Iterator for RevokedCerts<'a> {
    type Item = Result<BorrowedRevokedCert<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        if reader.at_end() {
            self.reader = None;
            return None;
        }
        let next = crl_der::read_revoked_cert(reader);
        if next.is_err() {
            self.reader = None;
        }
        Some(next)
    }
}

/// A revoked certificate entry borrowing from the CRL (RFC 5280 §5.1.2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BorrowedRevokedCert<'a> {
    /// `userCertificate` serial number contents, as encoded.
    pub serial_number: &'a [u8],
    /// `revocationDate`.
    pub revocation_date: UnixTime,
    /// `reasonCode` entry extension; absence means unspecified.
    pub reason_code: Option<RevocationReason>,
    /// `invalidityDate` entry extension.
    pub invalidity_date: Option<UnixTime>,
}

impl BorrowedRevokedCert<'_> {
    /// Copies into an owned entry.
    #[must_use]
    pub fn to_owned(&self) -> OwnedRevokedCert {
        OwnedRevokedCert {
            serial_number: self.serial_number.to_vec(),
            revocation_date: self.revocation_date,
            reason_code: self.reason_code,
            invalidity_date: self.invalidity_date,
        }
    }
}

/// A revoked certificate entry that owns its data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedRevokedCert {
    /// `userCertificate` serial number contents, as encoded.
    pub serial_number: Vec<u8>,
    /// `revocationDate`.
    pub revocation_date: UnixTime,
    /// `reasonCode` entry extension; absence means unspecified.
    pub reason_code: Option<RevocationReason>,
    /// `invalidityDate` entry extension.
    pub invalidity_date: Option<UnixTime>,
}

impl OwnedRevokedCert {
    /// Borrows the entry.
    #[must_use]
    pub fn borrow(&self) -> BorrowedRevokedCert<'_> {
        BorrowedRevokedCert {
            serial_number: &self.serial_number,
            revocation_date: self.revocation_date,
            reason_code: self.reason_code,
            invalidity_date: self.invalidity_date,
        }
    }
}

/// `CRLReason` (RFC 5280 §5.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    /// Only meaningful in delta CRLs, which are not supported.
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl TryFrom<u8> for RevocationReason {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        Ok(match value {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            _ => return Err(Error::UnsupportedRevocationReason),
        })
    }
}

/// Which certificates in a path are checked for revocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationCheckDepth {
    /// Only the end-entity certificate.
    EndEntity,
    /// Every certificate in the path except the trust anchor.
    Chain,
}

/// What to do when no authoritative CRL covers a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownStatusPolicy {
    /// Treat unknown status as not revoked.
    Allow,
    /// Fail with [`Error::UnknownRevocationStatus`].
    Deny,
}

/// What to do with CRLs whose `nextUpdate` has passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpirationPolicy {
    /// Fail with [`Error::CrlExpired`].
    Enforce,
    /// Use expired CRLs.
    Ignore,
}

/// Revocation checking configuration.
///
/// For each certificate within `depth`, every CRL whose issuer matches and
/// whose scope covers the certificate is consulted, after verifying its
/// signature with the issuer's key. A certificate listed by any such CRL is
/// revoked. Under [`ExpirationPolicy::Enforce`] expired CRLs are set aside;
/// if no current CRL remains the result is [`Error::CrlExpired`]. With no
/// applicable CRL at all, `status_policy` decides.
#[derive(Clone, Copy, Debug)]
pub struct RevocationOptions<'a> {
    /// CRLs to consult.
    pub crls: &'a [&'a CertRevocationList<'a>],
    /// Check depth.
    pub depth: RevocationCheckDepth,
    /// Unknown-status policy.
    pub status_policy: UnknownStatusPolicy,
    /// Expiration policy.
    pub expiration_policy: ExpirationPolicy,
}

/// Builder for [`RevocationOptions`].
#[derive(Clone, Copy, Debug)]
pub struct RevocationOptionsBuilder<'a> {
    opts: RevocationOptions<'a>,
}

/// At least one CRL is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrlsRequired;

impl<'a> RevocationOptionsBuilder<'a> {
    /// Starts with depth `Chain`, status policy `Deny`, expiration `Ignore`.
    ///
    /// # Errors
    ///
    /// Returns [`CrlsRequired`] if `crls` is empty.
    pub fn new(crls: &'a [&'a CertRevocationList<'a>]) -> Result<Self, CrlsRequired> {
        if crls.is_empty() {
            return Err(CrlsRequired);
        }
        Ok(Self {
            opts: RevocationOptions {
                crls,
                depth: RevocationCheckDepth::Chain,
                status_policy: UnknownStatusPolicy::Deny,
                expiration_policy: ExpirationPolicy::Ignore,
            },
        })
    }

    /// Sets the depth.
    #[must_use]
    pub fn with_depth(mut self, depth: RevocationCheckDepth) -> Self {
        self.opts.depth = depth;
        self
    }

    /// Sets the unknown-status policy.
    #[must_use]
    pub fn with_status_policy(mut self, p: UnknownStatusPolicy) -> Self {
        self.opts.status_policy = p;
        self
    }

    /// Sets the expiration policy.
    #[must_use]
    pub fn with_expiration_policy(mut self, p: ExpirationPolicy) -> Self {
        self.opts.expiration_policy = p;
        self
    }

    /// Builds the options.
    #[must_use]
    pub fn build(self) -> RevocationOptions<'a> {
        self.opts
    }
}

/// Validation time helper re-exported for CRL users.
pub type Time = UnixTime;
