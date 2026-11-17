//! `CRLDistributionPoints` (RFC 5280 §4.2.1.13).

use core::fmt;

use crate::der::{self, HexDebug, Reader, tag};
use crate::error::Error;
use crate::name::{
    self, GeneralNames, RelativeDistinguishedName, validate_non_empty_general_names,
};

/// An iterator over the `DistributionPoint`s of a `cRLDistributionPoints`
/// extension.
///
/// When the certificate is parsed the extension is only checked to be a
/// non-empty `SEQUENCE OF SEQUENCE` (path validation interprets the points
/// it understands and skips the others). Each point is parsed strictly
/// here, when it is reached: a malformed point is returned as
/// [`Error::ExtensionValueInvalid`] and ends the iteration. Work is linear
/// in the length of the extension.
#[derive(Clone)]
pub struct CrlDistributionPoints<'a> {
    reader: Option<Reader<'a>>,
}

impl<'a> CrlDistributionPoints<'a> {
    /// Iterates over the contents of a `SEQUENCE OF DistributionPoint`.
    pub(crate) fn new(contents: &'a [u8]) -> Self {
        Self {
            reader: Some(Reader::new(contents)),
        }
    }
}

impl<'a> Iterator for CrlDistributionPoints<'a> {
    type Item = Result<CrlDistributionPoint<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        if reader.at_end() {
            self.reader = None;
            return None;
        }
        let next = reader
            .expect(tag::SEQUENCE)
            .and_then(CrlDistributionPoint::parse)
            .map_err(|_| Error::ExtensionValueInvalid);
        if next.is_err() {
            self.reader = None;
        }
        Some(next)
    }
}

impl core::iter::FusedIterator for CrlDistributionPoints<'_> {}

impl fmt::Debug for CrlDistributionPoints<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// One `DistributionPoint`: where to find a CRL that may cover the
/// certificate, which reasons it covers, and who issues it.
///
/// Parsed strictly: the fields appear in order, each at most once, at least
/// one of `distributionPoint` and `cRLIssuer` is present (RFC 5280
/// §4.2.1.13), `GeneralNames` are non-empty with every entry well formed,
/// a `nameRelativeToCRLIssuer` is a valid `RelativeDistinguishedName`
/// ([`Name`](crate::name::Name) rules), and `reasons` is a DER `BIT
/// STRING`.
#[derive(Clone, Copy)]
pub struct CrlDistributionPoint<'a> {
    name: Option<NameForm<'a>>,
    reasons: Option<&'a [u8]>,
    crl_issuer: Option<&'a [u8]>,
}

/// The validated contents of a `DistributionPointName`.
#[derive(Clone, Copy)]
enum NameForm<'a> {
    Full(&'a [u8]),
    Relative(&'a [u8]),
}

impl<'a> CrlDistributionPoint<'a> {
    fn parse(contents: &'a [u8]) -> Result<Self, Error> {
        der::read_all(contents, |r| {
            let name = r
                .optional(tag::context_constructed(0))?
                .map(read_name)
                .transpose()?;
            let reasons = match r.optional(tag::context(1))? {
                Some(bits) => Some(der::bit_string_flags(bits)?.bits()),
                None => None,
            };
            let crl_issuer = r.optional(tag::context_constructed(2))?;
            if let Some(names) = crl_issuer {
                validate_non_empty_general_names(names)?;
            }
            if name.is_none() && crl_issuer.is_none() {
                return Err(Error::BadDer);
            }
            Ok(Self {
                name,
                reasons,
                crl_issuer,
            })
        })
    }

    /// `distributionPoint [0]`: the name of the CRL.
    #[must_use]
    pub fn distribution_point(&self) -> Option<DistributionPointName<'a>> {
        self.name.map(|name| match name {
            NameForm::Full(names) => {
                DistributionPointName::FullName(GeneralNames::new(Some(names)))
            }
            NameForm::Relative(rdn) => DistributionPointName::NameRelativeToCrlIssuer(
                RelativeDistinguishedName::from_validated(rdn),
            ),
        })
    }

    /// `reasons [1] ReasonFlags`: the named-bit octets of the `BIT STRING`
    /// (bit 0, `unused`, is the most significant bit of the first octet;
    /// then `keyCompromise`, `cACompromise`, `affiliationChanged`,
    /// `superseded`, `cessationOfOperation`, `certificateHold`,
    /// `privilegeWithdrawn` and `aACompromise`), padding bits zero. Absent
    /// means every reason.
    #[must_use]
    pub fn reasons(&self) -> Option<&'a [u8]> {
        self.reasons
    }

    /// `cRLIssuer [2] GeneralNames`: the CRL's issuer when it is not the
    /// certificate's (an indirect CRL, which path validation does not
    /// support). Every entry is well formed, so iteration yields no error.
    #[must_use]
    pub fn crl_issuer(&self) -> Option<GeneralNames<'a>> {
        self.crl_issuer.map(|names| GeneralNames::new(Some(names)))
    }
}

impl fmt::Debug for CrlDistributionPoint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrlDistributionPoint")
            .field("distribution_point", &self.distribution_point())
            .field("reasons", &self.reasons.map(HexDebug))
            .field("crl_issuer", &self.crl_issuer())
            .finish()
    }
}

/// Reads the contents of `distributionPoint [0]`, which (`DistributionPointName`
/// being a `CHOICE`) hold one explicitly tagged choice.
fn read_name(contents: &[u8]) -> Result<NameForm<'_>, Error> {
    der::read_all(contents, |r| {
        let tlv = r.tlv()?;
        match tlv.tag {
            t if t == tag::context_constructed(0) => {
                validate_non_empty_general_names(tlv.value)?;
                Ok(NameForm::Full(tlv.value))
            }
            t if t == tag::context_constructed(1) => {
                name::validate_rdn(tlv.value)?;
                Ok(NameForm::Relative(tlv.value))
            }
            _ => Err(Error::BadDer),
        }
    })
}

/// `DistributionPointName` (RFC 5280 §4.2.1.13).
#[derive(Clone, Debug)]
pub enum DistributionPointName<'a> {
    /// `fullName [0] GeneralNames`, usually `uniformResourceIdentifier`s.
    /// Every entry is well formed, so iteration yields no error.
    FullName(GeneralNames<'a>),
    /// `nameRelativeToCRLIssuer [1]`: a name relative to the CRL issuer's
    /// distinguished name.
    NameRelativeToCrlIssuer(RelativeDistinguishedName<'a>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::GeneralName;
    use alloc::vec::Vec;

    fn parse_all(contents: &[u8]) -> Result<Vec<CrlDistributionPoint<'_>>, Error> {
        CrlDistributionPoints::new(contents).collect()
    }

    #[test]
    fn points() {
        // fullName URI "u"; then nameRelativeToCRLIssuer CN=a with reasons
        // keyCompromise and cRLIssuer dNSName "i".
        let dps = b"\x30\x07\xa0\x05\xa0\x03\x86\x01u\
            \x30\x1a\xa0\x0e\xa1\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03abc\
            \x81\x02\x06\x40\xa2\x04\x82\x02io";
        let points = parse_all(dps).unwrap();
        assert_eq!(points.len(), 2);
        let Some(DistributionPointName::FullName(mut names)) = points[0].distribution_point()
        else {
            panic!("full name");
        };
        assert!(matches!(
            names.next(),
            Some(Ok(GeneralName::UniformResourceIdentifier(b"u")))
        ));
        assert!(points[0].reasons().is_none() && points[0].crl_issuer().is_none());
        let Some(DistributionPointName::NameRelativeToCrlIssuer(rdn)) =
            points[1].distribution_point()
        else {
            panic!("relative name");
        };
        assert_eq!(rdn.iter().next().unwrap().as_str(), Some("abc"));
        assert_eq!(points[1].reasons(), Some(&[0x40][..]));
        assert!(matches!(
            points[1].crl_issuer().unwrap().next(),
            Some(Ok(GeneralName::DnsName(b"io")))
        ));
    }

    #[test]
    fn malformed_points() {
        for bad in [
            // Empty point: neither a name nor an issuer.
            &b"\x30\x00"[..],
            // Reasons only.
            b"\x30\x04\x81\x02\x07\x80",
            // Out of order.
            b"\x30\x0b\xa2\x04\x82\x02io\xa0\x03\xa0\x01\x86",
            // Empty fullName.
            b"\x30\x04\xa0\x02\xa0\x00",
            // Two choices in distributionPoint.
            b"\x30\x0a\xa0\x08\xa0\x03\x86\x01u\xa0\x01\x00",
            // Bad padding in reasons.
            b"\x30\x0b\xa0\x05\xa0\x03\x86\x01u\x81\x02\x07\x81",
            // Unknown field.
            b"\x30\x09\xa0\x05\xa0\x03\x86\x01u\x83\x00",
            // Empty RDN.
            b"\x30\x04\xa0\x02\xa1\x00",
            // Not a SEQUENCE.
            b"\x31\x00",
            // Truncated.
            b"\x30\x07\xa0\x05\xa0\x03\x86\x01",
        ] {
            assert_eq!(
                parse_all(bad).err(),
                Some(Error::ExtensionValueInvalid),
                "{bad:02x?}"
            );
        }
        // The first error ends the iteration.
        let mut it = CrlDistributionPoints::new(b"\x30\x00\x30\x07\xa0\x05\xa0\x03\x86\x01u");
        assert!(matches!(it.next(), Some(Err(_))));
        assert!(it.next().is_none());
    }
}
