//! X.509 `Extensions` (RFC 5280 §4.1.2.9, §5.1.2.7, §5.3): the generic
//! [`Extension`] view of every extension of a certificate, and typed views
//! of the certificate extensions this crate decodes, returned by the
//! accessors of [`Cert`].
//!
//! | Extension (RFC 5280) | Accessor | Type |
//! |---|---|---|
//! | `subjectKeyIdentifier` (§4.2.1.2) | [`Cert::subject_key_identifier`] | `&[u8]` |
//! | `authorityKeyIdentifier` (§4.2.1.1) | [`Cert::authority_key_identifier`] | [`AuthorityKeyIdentifier`] |
//! | `keyUsage` (§4.2.1.3) | [`Cert::key_usage`] | [`KeyUsageFlags`] |
//! | `subjectAltName` (§4.2.1.6) | [`Cert::subject_alt_names`] | [`GeneralNames`] |
//! | `basicConstraints` (§4.2.1.9) | [`Cert::basic_constraints`] | [`BasicConstraints`] |
//! | `nameConstraints` (§4.2.1.10) | [`Cert::name_constraints`] | [`NameConstraints`] |
//! | `extKeyUsage` (§4.2.1.12) | [`Cert::extended_key_usage`] | [`KeyPurposeIdIter`] |
//! | `cRLDistributionPoints` (§4.2.1.13) | [`Cert::crl_distribution_points`] | [`CrlDistributionPoints`] |
//!
//! Each of these is decoded and validated when the certificate is parsed
//! (a malformed value or a second instance rejects the certificate), except
//! for the parts noted on each type that are only checked on access. Other
//! extensions, including the RFC 9345 `DelegationUsage` flag (see
//! [`EndEntityCert::has_delegation_usage`]), are available through
//! [`Cert::extensions`] and [`Cert::extension`] as undecoded
//! [`Extension`]s; [`oid`] has the identifiers of the decoded ones.
//!
//! [`Cert`]: crate::Cert
//! [`Cert::subject_key_identifier`]: crate::Cert::subject_key_identifier
//! [`Cert::authority_key_identifier`]: crate::Cert::authority_key_identifier
//! [`Cert::key_usage`]: crate::Cert::key_usage
//! [`Cert::subject_alt_names`]: crate::Cert::subject_alt_names
//! [`Cert::basic_constraints`]: crate::Cert::basic_constraints
//! [`Cert::name_constraints`]: crate::Cert::name_constraints
//! [`Cert::extended_key_usage`]: crate::Cert::extended_key_usage
//! [`Cert::crl_distribution_points`]: crate::Cert::crl_distribution_points
//! [`Cert::extensions`]: crate::Cert::extensions
//! [`Cert::extension`]: crate::Cert::extension
//! [`EndEntityCert::has_delegation_usage`]: crate::EndEntityCert::has_delegation_usage
//! [`GeneralNames`]: crate::name::GeneralNames

use core::fmt;

use crate::der::{self, HexDebug, OidDebug, Reader, tag};
use crate::error::Error;

mod crl_dp;
mod name_constraints;
mod typed;

pub use crl_dp::{CrlDistributionPoint, CrlDistributionPoints, DistributionPointName};
pub use name_constraints::{GeneralSubtrees, NameConstraints};
pub use typed::{
    AuthorityKeyIdentifier, BasicConstraints, KeyPurposeIdIter, KeyUsageBit, KeyUsageFlags,
};

/// Encoded `extnID`s (`OBJECT IDENTIFIER` contents) of the extensions this
/// crate decodes, for [`Cert::extension`](crate::Cert::extension).
pub mod oid {
    /// `id-ce-subjectKeyIdentifier` (2.5.29.14).
    pub const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
    /// `id-ce-keyUsage` (2.5.29.15).
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// `id-ce-subjectAltName` (2.5.29.17).
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    /// `id-ce-basicConstraints` (2.5.29.19).
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// `id-ce-nameConstraints` (2.5.29.30).
    pub const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
    /// `id-ce-cRLDistributionPoints` (2.5.29.31).
    pub const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];
    /// `id-ce-authorityKeyIdentifier` (2.5.29.35).
    pub const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];
    /// `id-ce-extKeyUsage` (2.5.29.37).
    pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// `DelegationUsage` (1.3.6.1.4.1.44363.44, RFC 9345 §4.2).
    pub const DELEGATION_USAGE: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2c];
}

/// How to treat an extension this crate does not implement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnknownExtensionPolicy {
    /// Reject critical unknown extensions (RFC 5280 §4.2); ignore others.
    Strict,
    /// Ignore unknown extensions even when critical. Used for trust anchors,
    /// whose extensions a relying party may ignore (RFC 5280 §6.2).
    IgnoreCritical,
}

/// One `Extension` (RFC 5280 §4.1): its identifier, criticality and
/// undecoded value. Borrows from the certificate.
///
/// The structure (an `OBJECT IDENTIFIER`, an optional `BOOLEAN` and an
/// `OCTET STRING`) is validated when the certificate is parsed; the value
/// is validated only for the extensions this crate decodes (listed in the
/// [module documentation](self)).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    /// `extnID` contents.
    pub(crate) id: &'a [u8],
    /// `critical`.
    pub(crate) critical: bool,
    /// `extnValue` contents (the DER encoding of the extension's own type).
    pub(crate) value: &'a [u8],
}

impl<'a> Extension<'a> {
    /// The `extnID` `OBJECT IDENTIFIER` contents (without tag and length),
    /// for comparison with the constants of [`oid`].
    #[must_use]
    pub fn extn_id(&self) -> &'a [u8] {
        self.id
    }

    /// The `critical` flag (absent means `false`). A certificate this
    /// crate parses has no critical extension it does not decode.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.critical
    }

    /// The `extnValue` `OCTET STRING` contents: the DER encoding of the
    /// extension's own type, including its outer tag and length.
    #[must_use]
    pub fn extn_value(&self) -> &'a [u8] {
        self.value
    }

    fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
        reader.nested(tag::SEQUENCE, |ext| {
            let id = ext.oid()?;
            let critical = ext.default_false_boolean()?;
            let value = ext.expect(tag::OCTET_STRING)?;
            Ok(Extension {
                id,
                critical,
                value,
            })
        })
    }

    /// Applies `policy` to an extension this crate does not implement.
    pub(crate) fn unsupported(&self, policy: UnknownExtensionPolicy) -> Result<(), Error> {
        match (policy, self.critical) {
            (UnknownExtensionPolicy::Strict, true) => Err(Error::UnsupportedCriticalExtension),
            _ => Ok(()),
        }
    }

    /// The last arc of `extnID` when it lies under `id-ce` (2.5.29) and
    /// fits in one octet, e.g. `Some(19)` for `basicConstraints`.
    pub(crate) fn id_ce_arc(&self) -> Option<u8> {
        match self.id {
            [0x55, 0x1d, arc] if arc & 0x80 == 0 => Some(*arc),
            _ => None,
        }
    }
}

impl fmt::Debug for Extension<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extension")
            .field("extn_id", &OidDebug(self.id))
            .field("critical", &self.critical)
            .field("extn_value", &HexDebug(self.value))
            .finish()
    }
}

/// An iterator over the extensions of a [`Cert`](crate::Cert), in encoding
/// order. The extensions were validated when the certificate was parsed,
/// so iteration cannot fail; work is linear in their total length.
#[derive(Clone)]
pub struct Extensions<'a> {
    reader: Reader<'a>,
}

impl<'a> Extensions<'a> {
    /// Iterates over the contents of a validated `SEQUENCE OF Extension`.
    pub(crate) fn new(contents: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(contents),
        }
    }
}

impl<'a> Iterator for Extensions<'a> {
    type Item = Extension<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }
        // Validated when the certificate was parsed; a failure (impossible)
        // ends the iteration rather than panicking.
        match Extension::read(&mut self.reader) {
            Ok(ext) => Some(ext),
            Err(_) => {
                self.reader = Reader::new(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for Extensions<'_> {}

impl fmt::Debug for Extensions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Walks the `SEQUENCE OF Extension` whose contents are `extensions`,
/// calling `f` for each. An empty sequence is accepted when `allow_empty`.
pub(crate) fn for_each<'a>(
    extensions: &'a [u8],
    allow_empty: bool,
    mut f: impl FnMut(Extension<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    if extensions.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(Error::MalformedExtensions)
        };
    }
    der::read_all(extensions, |reader| {
        while !reader.at_end() {
            f(Extension::read(reader)?)?;
        }
        Ok(())
    })
}

/// Stores a parsed extension value, rejecting a second occurrence of the
/// same extension (RFC 5280 §4.2: "MUST NOT include more than one instance
/// of a particular extension").
pub(crate) fn set_once<T>(
    slot: &mut Option<T>,
    parse: impl FnOnce() -> Result<T, Error>,
) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::MalformedExtensions);
    }
    *slot = Some(parse()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_extension() {
        // basicConstraints, critical, value SEQUENCE { TRUE }.
        let ext = b"\x30\x0f\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x05\x30\x03\x01\x01\xff";
        let mut seen = 0;
        for_each(ext, false, |e| {
            seen += 1;
            assert_eq!(e.id_ce_arc(), Some(19));
            assert!(e.critical);
            assert_eq!(e.value, b"\x30\x03\x01\x01\xff");
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, 1);
        assert_eq!(
            for_each(b"", false, |_| Ok(())),
            Err(Error::MalformedExtensions)
        );
        assert_eq!(for_each(b"", true, |_| Ok(())), Ok(()));
        // Truncated.
        assert_eq!(for_each(&ext[..10], true, |_| Ok(())), Err(Error::BadDer));
    }

    #[test]
    fn set_once_rejects_duplicates() {
        let mut slot = None;
        set_once(&mut slot, || Ok(1)).unwrap();
        assert_eq!(
            set_once(&mut slot, || Ok(2)),
            Err(Error::MalformedExtensions)
        );
        assert_eq!(slot, Some(1));
    }
}
