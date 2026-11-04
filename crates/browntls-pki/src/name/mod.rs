//! Subject names: `GeneralName` decoding (RFC 5280 §4.2.1.6), reference
//! identifier matching (RFC 6125) and name constraints (RFC 5280 §4.2.1.10).

pub(crate) mod constraints;
mod dns;
mod ip;

pub(crate) use dns::verify_dns_name;
pub(crate) use ip::verify_ip_address;

use crate::der::{Reader, tag};
use crate::error::Error;

/// One `GeneralName`. Only the forms this crate matches carry their value;
/// other forms keep their tag number so that name constraints of the same
/// form can be detected and rejected.
///
/// Deliberately not `PartialEq`: a `GeneralName` means different things as a
/// presented identifier and as a constraint base.
#[derive(Clone, Copy, Debug)]
pub(crate) enum GeneralName<'a> {
    /// `dNSName [2] IA5String`.
    DnsName(&'a [u8]),
    /// `iPAddress [7] OCTET STRING` (4 or 16 octets; 8 or 32 in constraints).
    IpAddress(&'a [u8]),
    /// `directoryName [4] Name`; the value is not interpreted.
    DirectoryName,
    /// `uniformResourceIdentifier [6] IA5String`.
    Uri(&'a [u8]),
    /// `otherName [0]`, `rfc822Name [1]`, `x400Address [3]`,
    /// `ediPartyName [5]` or `registeredID [8]`: the tag number.
    Unsupported(u8),
}

impl<'a> GeneralName<'a> {
    /// Reads one `GeneralName`. Unknown choice tags are malformed.
    pub(crate) fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
        let tlv = reader.tlv()?;
        Ok(match tlv.tag {
            t if t == tag::context_constructed(0) => Self::Unsupported(0),
            t if t == tag::context(1) => Self::Unsupported(1),
            t if t == tag::context(2) => Self::DnsName(tlv.value),
            t if t == tag::context_constructed(3) => Self::Unsupported(3),
            t if t == tag::context_constructed(4) => Self::DirectoryName,
            t if t == tag::context_constructed(5) => Self::Unsupported(5),
            t if t == tag::context(6) => Self::Uri(tlv.value),
            t if t == tag::context(7) => Self::IpAddress(tlv.value),
            t if t == tag::context(8) => Self::Unsupported(8),
            _ => return Err(Error::BadDer),
        })
    }
}

/// Iterates over the contents of a `GeneralNames` sequence, yielding nothing
/// for `None` and stopping after the first malformed entry.
#[derive(Debug)]
pub(crate) struct GeneralNames<'a> {
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

/// Checks that `contents` is a well-formed (possibly empty) `GeneralNames`.
pub(crate) fn validate_general_names(contents: &[u8]) -> Result<(), Error> {
    GeneralNames::new(Some(contents)).try_for_each(|name| name.map(|_| ()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_names_iteration() {
        // dNSName "a", iPAddress 1.2.3.4, rfc822Name "x".
        let names = b"\x82\x01a\x87\x04\x01\x02\x03\x04\x81\x01x";
        assert_eq!(validate_general_names(names), Ok(()));
        let mut it = GeneralNames::new(Some(names));
        assert!(matches!(it.next(), Some(Ok(GeneralName::DnsName(b"a")))));
        assert!(matches!(it.next(), Some(Ok(GeneralName::IpAddress(_)))));
        assert!(matches!(it.next(), Some(Ok(GeneralName::Unsupported(1)))));
        assert!(it.next().is_none());
        assert!(GeneralNames::new(None).next().is_none());
        // Unknown choice: error once, then exhausted.
        let mut it = GeneralNames::new(Some(b"\x89\x00\x82\x01a"));
        assert!(matches!(it.next(), Some(Err(Error::BadDer))));
        assert!(it.next().is_none());
        assert_eq!(validate_general_names(b"\x82"), Err(Error::BadDer));
    }
}
