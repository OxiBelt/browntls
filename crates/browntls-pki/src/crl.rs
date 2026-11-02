//! Certificate revocation lists (RFC 5280 §5).
//!
//! STUB: signatures fixed by the architecture; implementation in progress.

use alloc::vec::Vec;

use crate::error::Error;
use crate::{SignatureVerificationAlgorithm, UnixTime};

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
    /// The DER-encoded issuer name.
    #[must_use]
    pub fn issuer(&self) -> &[u8] {
        match self {
            Self::Owned(c) => &c.issuer,
            Self::Borrowed(c) => c.issuer,
        }
    }

    /// Verifies the CRL signature with the issuer's SPKI.
    ///
    /// # Errors
    ///
    /// Returns a signature error when verification fails.
    pub fn verify_signature(
        &self,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        issuer_spki: &[u8],
    ) -> Result<(), Error> {
        let _ = (supported_sig_algs, issuer_spki);
        Err(Error::InvalidCrlSignatureForPublicKey) // STUB
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

/// A CRL that owns its data.
#[derive(Clone, Debug)]
pub struct OwnedCertRevocationList {
    issuer: Vec<u8>,
}

impl OwnedCertRevocationList {
    /// Parses a DER-encoded CRL.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unsupported CRLs.
    pub fn from_der(crl_der: &[u8]) -> Result<Self, Error> {
        let _ = crl_der;
        Err(Error::BadDer) // STUB
    }
}

/// A CRL borrowing its data.
#[derive(Debug)]
pub struct BorrowedCertRevocationList<'a> {
    issuer: &'a [u8],
}

impl<'a> BorrowedCertRevocationList<'a> {
    /// Parses a DER-encoded CRL.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unsupported CRLs.
    pub fn from_der(crl_der: &'a [u8]) -> Result<Self, Error> {
        let _ = crl_der;
        Err(Error::BadDer) // STUB
    }

    /// Copies into an owned CRL.
    ///
    /// # Errors
    ///
    /// Infallible today; kept fallible for parity with re-parsing.
    pub fn to_owned(&self) -> Result<OwnedCertRevocationList, Error> {
        Ok(OwnedCertRevocationList {
            issuer: self.issuer.to_vec(),
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
