//! `NameConstraints` (RFC 5280 §4.2.1.10).

use core::fmt;

use crate::der::{self, Reader};
use crate::error::Error;
use crate::name::{GeneralName, constraints};

/// A `NameConstraints` extension (RFC 5280 §4.2.1.10): the permitted and
/// excluded subtrees a CA places on the names of the certificates below it.
///
/// Validated when the certificate is parsed (or by [`Self::from_contents`]):
/// at least one subtree list is present, each is non-empty, and each
/// `GeneralSubtree` holds only a well-formed `base` `GeneralName` (the
/// `minimum` and `maximum` fields RFC 5280 forbids are rejected), so
/// iteration cannot fail. The bases are returned as encoded; path
/// validation applies `dNSName` and `iPAddress` constraints and fails
/// closed on the other forms.
#[derive(Clone, Copy)]
pub struct NameConstraints<'a> {
    permitted: Option<&'a [u8]>,
    excluded: Option<&'a [u8]>,
}

impl<'a> NameConstraints<'a> {
    /// Parses the contents of a `NameConstraints` `SEQUENCE` (without its
    /// tag and length), such as [`TrustAnchor::name_constraints`].
    ///
    /// # Errors
    ///
    /// [`Error::MalformedNameConstraint`] when the contents are not valid
    /// as described above.
    ///
    /// [`TrustAnchor::name_constraints`]: crate::TrustAnchor::name_constraints
    pub fn from_contents(contents: &'a [u8]) -> Result<Self, Error> {
        constraints::validate(contents)?;
        Ok(Self::from_validated(contents))
    }

    /// Splits validated contents into the two lists.
    pub(crate) fn from_validated(contents: &'a [u8]) -> Self {
        let (permitted, excluded) = der::read_all(contents, constraints::split).unwrap_or_default();
        Self {
            permitted,
            excluded,
        }
    }

    /// `permittedSubtrees [0]`: names must fall in one subtree of their
    /// form when the list has any of that form.
    #[must_use]
    pub fn permitted_subtrees(&self) -> Option<GeneralSubtrees<'a>> {
        self.permitted.map(GeneralSubtrees::new)
    }

    /// `excludedSubtrees [1]`: names must fall in none of these subtrees.
    #[must_use]
    pub fn excluded_subtrees(&self) -> Option<GeneralSubtrees<'a>> {
        self.excluded.map(GeneralSubtrees::new)
    }
}

impl fmt::Debug for NameConstraints<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameConstraints")
            .field("permitted_subtrees", &self.permitted_subtrees())
            .field("excluded_subtrees", &self.excluded_subtrees())
            .finish()
    }
}

/// An iterator over the `base` names of a validated `GeneralSubtrees`
/// list.
#[derive(Clone)]
pub struct GeneralSubtrees<'a> {
    reader: Reader<'a>,
}

impl<'a> GeneralSubtrees<'a> {
    fn new(contents: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(contents),
        }
    }
}

impl<'a> Iterator for GeneralSubtrees<'a> {
    type Item = GeneralName<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }
        // Validated on parsing; a failure (impossible) ends the iteration.
        match constraints::read_subtree(&mut self.reader) {
            Ok(base) => Some(base),
            Err(_) => {
                self.reader = Reader::new(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for GeneralSubtrees<'_> {}

impl fmt::Debug for GeneralSubtrees<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn subtrees() {
        // Permitted dNSName "a.example" and iPAddress 10.0.0.0/8; excluded
        // dNSName "b.a.example".
        let nc = b"\xa0\x19\x30\x0b\x82\x09a.example\x30\x0a\x87\x08\x0a\0\0\0\xff\0\0\0\
            \xa1\x0f\x30\x0d\x82\x0bb.a.example";
        let parsed = NameConstraints::from_contents(nc).unwrap();
        let permitted: alloc::vec::Vec<_> = parsed.permitted_subtrees().unwrap().collect();
        assert_eq!(permitted.len(), 2);
        assert!(matches!(permitted[0], GeneralName::DnsName(b"a.example")));
        assert!(matches!(permitted[1], GeneralName::IpAddress(ip) if ip.len() == 8));
        assert_eq!(parsed.excluded_subtrees().unwrap().count(), 1);
        assert_eq!(
            format!("{parsed:?}"),
            "NameConstraints { permitted_subtrees: Some([DnsName(\"a.example\"), \
             IpAddress(0a000000ff000000)]), excluded_subtrees: Some([DnsName(\"b.a.example\")]) }"
        );
        let only_excluded = NameConstraints::from_contents(&nc[0x1b..]).unwrap();
        assert!(only_excluded.permitted_subtrees().is_none());
        for bad in [&b""[..], b"\xa0\x00", &nc[..10], b"\xa1\x02\x30\x00"] {
            assert_eq!(
                NameConstraints::from_contents(bad).err(),
                Some(Error::MalformedNameConstraint)
            );
        }
    }
}
