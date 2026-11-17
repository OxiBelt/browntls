//! Names: X.501 distinguished names ([`Name`], RFC 5280 §4.1.2.4),
//! `GeneralName`s ([`GeneralName`], RFC 5280 §4.2.1.6), and internally
//! reference identifier matching (RFC 6125) and name constraints (RFC 5280
//! §4.2.1.10).
//!
//! Everything here borrows from its input and is read with the crate's
//! strict DER rules. Inspecting names is separate from validating them for
//! a purpose: check a server name with
//! [`EndEntityCert::verify_is_valid_for_subject_name`], never by comparing
//! the values returned here.
//!
//! [`EndEntityCert::verify_is_valid_for_subject_name`]: crate::EndEntityCert::verify_is_valid_for_subject_name

pub(crate) mod constraints;
mod dns;
mod ip;
mod x500;

pub(crate) use dns::{is_valid_presented_dns_id, verify_dns_name};
pub(crate) use ip::verify_ip_address;
pub(crate) use x500::validate_rdn;
pub use x500::{
    AttributeIter, AttributeTypeAndValue, Name, RdnIter, RelativeDistinguishedName, attribute_type,
};

use core::fmt;

use crate::der::{HexDebug, Reader, tag};
use crate::error::Error;

/// One `GeneralName` (RFC 5280 §4.2.1.6), as found in `subjectAltName`,
/// name constraints, `authorityKeyIdentifier` and CRL distribution points.
///
/// The choice tag is checked (an unknown tag is malformed DER) but values
/// are returned as encoded: the `IA5String` forms may hold any octets, an
/// `iPAddress` may have any length, and a `directoryName` is not parsed.
/// [`Cert::valid_dns_names`] filters the `dNSName`s that are valid
/// presented identifiers.
///
/// Deliberately not `PartialEq`: a `GeneralName` means different things as
/// a presented identifier and as a constraint base, and DNS names compare
/// case-insensitively, so byte equality is not name equality.
///
/// [`Cert::valid_dns_names`]: crate::Cert::valid_dns_names
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum GeneralName<'a> {
    /// `rfc822Name [1] IA5String`: an email address.
    Rfc822Name(&'a [u8]),
    /// `dNSName [2] IA5String`.
    DnsName(&'a [u8]),
    /// `directoryName [4] Name`: the complete DER encoding of the `Name`
    /// (the tag is explicit, since `Name` is a `CHOICE`), not yet validated;
    /// parse it with [`Name::from_der`].
    DirectoryName(&'a [u8]),
    /// `uniformResourceIdentifier [6] IA5String`.
    UniformResourceIdentifier(&'a [u8]),
    /// `iPAddress [7] OCTET STRING`: 4 or 16 octets in a `subjectAltName`,
    /// an address and a mask (8 or 32 octets) in a name constraint.
    IpAddress(&'a [u8]),
    /// A choice this crate does not decode: `otherName [0]`,
    /// `x400Address [3]`, `ediPartyName [5]` or `registeredID [8]`.
    Other {
        /// The context-specific tag number: 0, 3, 5 or 8.
        tag: u8,
        /// The contents octets, as encoded.
        value: &'a [u8],
    },
}

impl<'a> GeneralName<'a> {
    /// Reads one `GeneralName`. Unknown choice tags are malformed.
    pub(crate) fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
        let tlv = reader.tlv()?;
        let value = tlv.value;
        Ok(match tlv.tag {
            t if t == tag::context_constructed(0) => Self::Other { tag: 0, value },
            t if t == tag::context(1) => Self::Rfc822Name(value),
            t if t == tag::context(2) => Self::DnsName(value),
            t if t == tag::context_constructed(3) => Self::Other { tag: 3, value },
            t if t == tag::context_constructed(4) => Self::DirectoryName(value),
            t if t == tag::context_constructed(5) => Self::Other { tag: 5, value },
            t if t == tag::context(6) => Self::UniformResourceIdentifier(value),
            t if t == tag::context(7) => Self::IpAddress(value),
            t if t == tag::context(8) => Self::Other { tag: 8, value },
            _ => return Err(Error::BadDer),
        })
    }
}

impl fmt::Debug for GeneralName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = |f: &mut fmt::Formatter<'_>, kind: &str, v: &[u8]| {
            write!(f, "{kind}(\"{}\")", v.escape_ascii())
        };
        match *self {
            Self::Rfc822Name(v) => text(f, "Rfc822Name", v),
            Self::DnsName(v) => text(f, "DnsName", v),
            Self::UniformResourceIdentifier(v) => text(f, "UniformResourceIdentifier", v),
            Self::DirectoryName(v) => match Name::from_der(v) {
                Ok(name) => f.debug_tuple("DirectoryName").field(&name).finish(),
                Err(_) => f.debug_tuple("DirectoryName").field(&HexDebug(v)).finish(),
            },
            Self::IpAddress(v) => f.debug_tuple("IpAddress").field(&HexDebug(v)).finish(),
            Self::Other { tag, value } => f
                .debug_struct("Other")
                .field("tag", &tag)
                .field("value", &HexDebug(value))
                .finish(),
        }
    }
}

/// An iterator over the entries of a `GeneralNames` sequence, such as the
/// `subjectAltName` of a [`Cert`](crate::Cert).
///
/// Entries are read lazily; the first malformed entry is returned as an
/// error and ends the iteration. A certificate's `subjectAltName` is
/// validated when the certificate is parsed, so iterating it never fails.
/// Work is linear in the length of the sequence.
#[derive(Clone)]
pub struct GeneralNames<'a> {
    reader: Option<Reader<'a>>,
}

impl<'a> GeneralNames<'a> {
    pub(crate) fn new(contents: Option<&'a [u8]>) -> Self {
        Self {
            reader: contents.map(Reader::new),
        }
    }
}

impl<'a> Iterator for GeneralNames<'a> {
    type Item = Result<GeneralName<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        if reader.at_end() {
            self.reader = None;
            return None;
        }
        let next = GeneralName::read(reader);
        if next.is_err() {
            self.reader = None;
        }
        Some(next)
    }
}

impl core::iter::FusedIterator for GeneralNames<'_> {}

impl fmt::Debug for GeneralNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Checks that `contents` is a well-formed (possibly empty) `GeneralNames`.
pub(crate) fn validate_general_names(contents: &[u8]) -> Result<(), Error> {
    GeneralNames::new(Some(contents)).try_for_each(|name| name.map(|_| ()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn general_names_iteration() {
        // dNSName "a", iPAddress 1.2.3.4, rfc822Name "x".
        let names = b"\x82\x01a\x87\x04\x01\x02\x03\x04\x81\x01x";
        assert_eq!(validate_general_names(names), Ok(()));
        let mut it = GeneralNames::new(Some(names));
        assert!(matches!(it.next(), Some(Ok(GeneralName::DnsName(b"a")))));
        assert!(matches!(it.next(), Some(Ok(GeneralName::IpAddress(_)))));
        assert!(matches!(it.next(), Some(Ok(GeneralName::Rfc822Name(b"x")))));
        assert!(it.next().is_none());
        assert!(GeneralNames::new(None).next().is_none());
        // Unknown choice: error once, then exhausted.
        let mut it = GeneralNames::new(Some(b"\x89\x00\x82\x01a"));
        assert!(matches!(it.next(), Some(Err(Error::BadDer))));
        assert!(it.next().is_none());
        assert_eq!(validate_general_names(b"\x82"), Err(Error::BadDer));
    }

    #[test]
    fn every_choice() {
        // otherName, x400Address, directoryName (CN=a), ediPartyName,
        // uniformResourceIdentifier, registeredID.
        let names: &[u8] = b"\xa0\x00\xa3\x00\xa4\x0e\x30\x0c\x31\x0a\x30\x08\x06\x03\x55\x04\x03\x0c\x01a\xa5\x00\x86\x03u:x\x88\x01\x2a";
        let all: alloc::vec::Vec<_> = GeneralNames::new(Some(names))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(all.len(), 6);
        assert!(matches!(all[0], GeneralName::Other { tag: 0, value: b"" }));
        assert!(matches!(all[1], GeneralName::Other { tag: 3, .. }));
        assert!(matches!(all[2], GeneralName::DirectoryName(d) if d.len() == 14));
        assert!(matches!(all[3], GeneralName::Other { tag: 5, .. }));
        assert!(matches!(
            all[4],
            GeneralName::UniformResourceIdentifier(b"u:x")
        ));
        assert!(matches!(
            all[5],
            GeneralName::Other {
                tag: 8,
                value: b"\x2a"
            }
        ));
        assert_eq!(
            format!("{:?}", all[2]),
            "DirectoryName(Name([[2.5.4.3=\"a\"]]))"
        );
        assert_eq!(
            format!("{:?}", all[4]),
            "UniformResourceIdentifier(\"u:x\")"
        );
        assert_eq!(format!("{:?}", all[5]), "Other { tag: 8, value: 2a }");
        // Primitive forms of constructed choices and vice versa.
        for bad in [
            &b"\x80\x00"[..],
            b"\xa1\x00",
            b"\xa2\x00",
            b"\x84\x00",
            b"\xa6\x00",
            b"\xa7\x00",
            b"\xa8\x00",
        ] {
            assert_eq!(
                validate_general_names(bad),
                Err(Error::BadDer),
                "{bad:02x?}"
            );
        }
    }
}
