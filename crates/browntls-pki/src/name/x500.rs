//! X.501 distinguished names (RFC 5280 §4.1.2.4): `Name`,
//! `RelativeDistinguishedName` and `AttributeTypeAndValue`.

use core::fmt;

use crate::der::{self, CERT_LEN_LIMIT, HexDebug, OidDebug, Reader, tag};
use crate::error::Error;

/// Encoded `AttributeType` OIDs (`OBJECT IDENTIFIER` contents) of common
/// name attributes (RFC 5280 §4.1.2.4, RFC 4519, RFC 2985), for comparison
/// with [`AttributeTypeAndValue::oid`].
pub mod attribute_type {
    /// `id-at-commonName` (2.5.4.3).
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    /// `id-at-serialNumber` (2.5.4.5).
    pub const SERIAL_NUMBER: &[u8] = &[0x55, 0x04, 0x05];
    /// `id-at-countryName` (2.5.4.6).
    pub const COUNTRY_NAME: &[u8] = &[0x55, 0x04, 0x06];
    /// `id-at-localityName` (2.5.4.7).
    pub const LOCALITY_NAME: &[u8] = &[0x55, 0x04, 0x07];
    /// `id-at-stateOrProvinceName` (2.5.4.8).
    pub const STATE_OR_PROVINCE_NAME: &[u8] = &[0x55, 0x04, 0x08];
    /// `id-at-organizationName` (2.5.4.10).
    pub const ORGANIZATION_NAME: &[u8] = &[0x55, 0x04, 0x0a];
    /// `id-at-organizationalUnitName` (2.5.4.11).
    pub const ORGANIZATIONAL_UNIT_NAME: &[u8] = &[0x55, 0x04, 0x0b];
    /// `id-domainComponent` (0.9.2342.19200300.100.1.25).
    pub const DOMAIN_COMPONENT: &[u8] =
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];
    /// `id-emailAddress` (1.2.840.113549.1.9.1, PKCS #9; deprecated in
    /// names by RFC 5280 in favour of an `rfc822Name` alternative name).
    pub const EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
}

/// Universal tags of the string types [`AttributeTypeAndValue::as_str`]
/// decodes.
const UTF8_STRING: u8 = 0x0c;
const NUMERIC_STRING: u8 = 0x12;
const PRINTABLE_STRING: u8 = 0x13;
const IA5_STRING: u8 = 0x16;
const VISIBLE_STRING: u8 = 0x1a;
/// `SET` / `SET OF` (always constructed).
const SET: u8 = 0x31;

/// An X.501 `Name` (RFC 5280 §4.1.2.4): an `RDNSequence`, such as the
/// issuer or subject of a certificate or CRL, a trust anchor's subject, a
/// `directoryName`, or a TLS `certificate_authorities` entry.
///
/// Parsing is eager and checks the structure down to each attribute
/// value's outer encoding, with DER's definite minimal lengths throughout:
/// every `RelativeDistinguishedName` must be a non-empty `SET OF` in DER
/// order (X.690 §11.6) without repeated attributes, every
/// `AttributeTypeAndValue` a `SEQUENCE` of a well-formed `OBJECT
/// IDENTIFIER` and exactly one element as the value. The value element may
/// have any tag but the reserved universal tag 0, in the primitive or
/// constructed form X.690 prescribes for universal tags; its contents are
/// not parsed (so a value need not be valid DER of its type), except for
/// what [`AttributeTypeAndValue::as_str`] checks. Names longer than 65535
/// octets are rejected, so parsing and every iteration are linear in at
/// most that many octets. Iterating a parsed `Name` cannot fail; everything
/// borrows from the input.
///
/// An empty `RDNSequence` is a valid `Name`.
#[derive(Clone, Copy)]
pub struct Name<'a> {
    contents: &'a [u8],
}

impl<'a> Name<'a> {
    /// Parses a complete DER `Name`: the `SEQUENCE` with its tag and length,
    /// as in a `directoryName` or a TLS `DistinguishedName`.
    ///
    /// # Errors
    ///
    /// [`Error::BadDer`] for malformed or non-DER input,
    /// [`Error::TrailingData`] for bytes after the `SEQUENCE`.
    pub fn from_der(der: &'a [u8]) -> Result<Self, Error> {
        let contents = der::read_all(der, |r| r.expect(tag::SEQUENCE))?;
        Self::from_contents(contents)
    }

    /// Parses the contents of a `Name` `SEQUENCE` (without its tag and
    /// length), as returned by [`Cert::issuer`], [`Cert::subject`] and
    /// [`CertRevocationList::issuer`] and held in [`TrustAnchor::subject`].
    ///
    /// # Errors
    ///
    /// As for [`Self::from_der`].
    ///
    /// [`Cert::issuer`]: crate::Cert::issuer
    /// [`Cert::subject`]: crate::Cert::subject
    /// [`CertRevocationList::issuer`]: crate::CertRevocationList::issuer
    /// [`TrustAnchor::subject`]: crate::TrustAnchor::subject
    pub fn from_contents(contents: &'a [u8]) -> Result<Self, Error> {
        if contents.len() > CERT_LEN_LIMIT {
            return Err(Error::BadDer);
        }
        der::read_all(contents, |r| {
            while !r.at_end() {
                validate_rdn(r.expect(SET)?)?;
            }
            Ok(())
        })?;
        Ok(Self { contents })
    }

    /// The `RelativeDistinguishedName`s, most significant (usually the
    /// country or domain component) first, as encoded.
    #[must_use]
    pub fn iter(&self) -> RdnIter<'a> {
        RdnIter {
            reader: Reader::new(self.contents),
        }
    }

    /// Every `AttributeTypeAndValue` of every `RelativeDistinguishedName`,
    /// in encoding order: for example, the common names are
    /// `name.attributes().filter(|a| a.oid() == attribute_type::COMMON_NAME)`.
    pub fn attributes(&self) -> impl Iterator<Item = AttributeTypeAndValue<'a>> + use<'a> {
        self.iter().flat_map(|rdn| rdn.iter())
    }
}

impl fmt::Debug for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Name(")?;
        f.debug_list().entries(self.iter()).finish()?;
        f.write_str(")")
    }
}

impl<'a> IntoIterator for &Name<'a> {
    type Item = RelativeDistinguishedName<'a>;
    type IntoIter = RdnIter<'a>;

    fn into_iter(self) -> RdnIter<'a> {
        self.iter()
    }
}

/// Checks the contents of a `RelativeDistinguishedName` `SET OF`: non-empty,
/// in DER order, of well-formed attributes, none repeated. X.501 does not
/// intend an RDN to hold the same value twice (`x509-cert` rejects it too);
/// two different complete encodings never compare equal in DER order, so
/// strictly ascending order rules out exactly the repeats.
pub(crate) fn validate_rdn(contents: &[u8]) -> Result<(), Error> {
    if contents.is_empty() {
        return Err(Error::BadDer);
    }
    der::read_all(contents, |r| {
        let mut previous: Option<&[u8]> = None;
        while !r.at_end() {
            let atv = r.expect_tlv(tag::SEQUENCE)?;
            read_attribute(atv.value)?;
            if previous.is_some_and(|p| p == atv.raw || !der::set_of_ordered(p, atv.raw)) {
                return Err(Error::BadDer);
            }
            previous = Some(atv.raw);
        }
        Ok(())
    })
}

/// Reads the contents of an `AttributeTypeAndValue` `SEQUENCE`.
fn read_attribute(contents: &[u8]) -> Result<AttributeTypeAndValue<'_>, Error> {
    der::read_all(contents, |r| {
        let oid = r.oid()?;
        let value = r.tlv()?;
        if !universal_form_ok(value.tag) {
            return Err(Error::BadDer);
        }
        Ok(AttributeTypeAndValue {
            oid,
            tag: value.tag,
            value: value.value,
        })
    })
}

/// Whether a value tag is acceptable in DER: universal tag 0 is reserved,
/// and universal types have a fixed form (X.690 §8, §10.2): `EXTERNAL`,
/// `EMBEDDED PDV`, `SEQUENCE`, `SET` and `CHARACTER STRING` constructed,
/// every other universal type primitive. Other classes may use either form.
fn universal_form_ok(t: u8) -> bool {
    if t & 0xc0 != 0 {
        return true;
    }
    let constructed = t & tag::CONSTRUCTED != 0;
    match t & 0x1f {
        0 => false,
        8 | 11 | 16 | 17 | 29 => constructed,
        _ => !constructed,
    }
}

/// An iterator over the `RelativeDistinguishedName`s of a [`Name`].
#[derive(Clone)]
pub struct RdnIter<'a> {
    reader: Reader<'a>,
}

impl<'a> Iterator for RdnIter<'a> {
    type Item = RelativeDistinguishedName<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }
        // Validated when the name was parsed; a failure (impossible) ends
        // the iteration rather than panicking.
        match self.reader.expect(SET) {
            Ok(contents) => Some(RelativeDistinguishedName { contents }),
            Err(_) => {
                self.reader = Reader::new(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for RdnIter<'_> {}

impl fmt::Debug for RdnIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// One `RelativeDistinguishedName`: a non-empty set of attributes, most
/// often a single one ("multi-valued" RDNs hold several, such as
/// `CN=x + UID=y`).
#[derive(Clone, Copy)]
pub struct RelativeDistinguishedName<'a> {
    contents: &'a [u8],
}

impl<'a> RelativeDistinguishedName<'a> {
    /// Wraps validated `SET OF` contents.
    pub(crate) fn from_validated(contents: &'a [u8]) -> Self {
        Self { contents }
    }

    /// The attributes, in DER (sorted) order.
    #[must_use]
    pub fn iter(&self) -> AttributeIter<'a> {
        AttributeIter {
            reader: Reader::new(self.contents),
        }
    }
}

impl fmt::Debug for RelativeDistinguishedName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a> IntoIterator for &RelativeDistinguishedName<'a> {
    type Item = AttributeTypeAndValue<'a>;
    type IntoIter = AttributeIter<'a>;

    fn into_iter(self) -> AttributeIter<'a> {
        self.iter()
    }
}

/// An iterator over the attributes of a [`RelativeDistinguishedName`].
#[derive(Clone)]
pub struct AttributeIter<'a> {
    reader: Reader<'a>,
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = AttributeTypeAndValue<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }
        match self.reader.expect(tag::SEQUENCE).and_then(read_attribute) {
            Ok(atv) => Some(atv),
            Err(_) => {
                self.reader = Reader::new(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for AttributeIter<'_> {}

impl fmt::Debug for AttributeIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// One `AttributeTypeAndValue`: an attribute type OID and a value whose
/// type depends on it (for the common attributes, a `DirectoryString`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AttributeTypeAndValue<'a> {
    oid: &'a [u8],
    tag: u8,
    value: &'a [u8],
}

impl<'a> AttributeTypeAndValue<'a> {
    /// The `type` `OBJECT IDENTIFIER` contents (without tag and length),
    /// for comparison with the constants of [`attribute_type`].
    #[must_use]
    pub fn oid(&self) -> &'a [u8] {
        self.oid
    }

    /// The tag octet of the value, such as `0x0c` for `UTF8String` or
    /// `0x13` for `PrintableString`.
    #[must_use]
    pub fn value_tag(&self) -> u8 {
        self.tag
    }

    /// The contents octets of the value (without tag and length), not
    /// interpreted.
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The value as a string, when it is one of the string types whose
    /// contents are a subset of UTF-8 and those contents are valid for the
    /// type: `UTF8String` (valid UTF-8), `PrintableString` (letters, digits,
    /// space and `'()+,-./:=?`), `IA5String` (ASCII, control characters
    /// included), `NumericString` (digits and space) and `VisibleString`
    /// (printable ASCII). `None` for other types, including
    /// `TeletexString`, `BMPString` and `UniversalString`, whose contents
    /// [`Self::value`] returns undecoded, and for contents invalid for
    /// their type. The string is returned as encoded: callers displaying it
    /// must escape control characters themselves.
    #[must_use]
    pub fn as_str(&self) -> Option<&'a str> {
        let valid = match self.tag {
            UTF8_STRING => true,
            NUMERIC_STRING => self.value.iter().all(|&b| b.is_ascii_digit() || b == b' '),
            PRINTABLE_STRING => self.value.iter().all(|&b| is_printable_char(b)),
            IA5_STRING => self.value.is_ascii(),
            VISIBLE_STRING => self.value.iter().all(|&b| (0x20..=0x7e).contains(&b)),
            _ => false,
        };
        if valid {
            core::str::from_utf8(self.value).ok()
        } else {
            None
        }
    }
}

/// The `PrintableString` character set (X.680 §41.4).
fn is_printable_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b)
}

impl fmt::Debug for AttributeTypeAndValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}=", OidDebug(self.oid))?;
        match self.as_str() {
            Some(s) => fmt::Debug::fmt(s, f),
            None => write!(f, "[{:02x}]{:?}", self.tag, HexDebug(self.value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec::Vec;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 0x80);
        let mut v = alloc::vec![tag, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    fn atv(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
        let mut body = tlv(0x06, oid);
        body.extend(tlv(tag, value));
        tlv(0x30, &body)
    }

    #[test]
    fn multi_valued_rdns() {
        let cn = atv(attribute_type::COMMON_NAME, UTF8_STRING, b"x");
        let c = atv(attribute_type::COUNTRY_NAME, PRINTABLE_STRING, b"FI");
        // DER order: the country (55 04 06) sorts after the common name
        // (55 04 03).
        let mut set = cn.clone();
        set.extend(&c);
        let mut name = tlv(0x31, &set);
        name.extend(tlv(0x31, &c));
        let parsed = Name::from_contents(&name).unwrap();
        let rdns: Vec<_> = parsed.iter().collect();
        assert_eq!(rdns.len(), 2);
        assert_eq!(rdns[0].iter().count(), 2);
        let all: Vec<_> = parsed.attributes().collect();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].oid(), attribute_type::COMMON_NAME);
        assert_eq!(all[0].as_str(), Some("x"));
        assert_eq!(all[1].value_tag(), PRINTABLE_STRING);
        assert_eq!(all[2].value(), b"FI");
        assert_eq!(
            format!("{parsed:?}"),
            "Name([[2.5.4.3=\"x\", 2.5.4.6=\"FI\"], [2.5.4.6=\"FI\"]])"
        );
        assert_eq!(
            Name::from_der(&tlv(0x30, &name))
                .unwrap()
                .attributes()
                .count(),
            3
        );

        // Out of order.
        let mut unordered = c.clone();
        unordered.extend(&cn);
        assert_eq!(
            Name::from_contents(&tlv(0x31, &unordered)).err(),
            Some(Error::BadDer)
        );
        // DER allows equal encodings in a SET OF, but an RDN must not repeat
        // an attribute.
        let mut twice = cn.clone();
        twice.extend(&cn);
        assert_eq!(
            Name::from_contents(&tlv(0x31, &twice)).err(),
            Some(Error::BadDer)
        );
        // The same type with different values is fine.
        let mut same_type = cn.clone();
        same_type.extend(atv(attribute_type::COMMON_NAME, UTF8_STRING, b"y"));
        assert!(Name::from_contents(&tlv(0x31, &same_type)).is_ok());
    }

    #[test]
    fn malformed() {
        let cn = atv(attribute_type::COMMON_NAME, UTF8_STRING, b"x");
        let good = tlv(0x31, &cn);
        assert!(Name::from_contents(&good).is_ok());
        assert!(Name::from_contents(&[]).is_ok());
        let mut extra_field = atv(attribute_type::COMMON_NAME, UTF8_STRING, b"x");
        extra_field[1] += 2;
        extra_field.extend([0x05, 0x00]);
        let cases: &[(&str, Vec<u8>)] = &[
            ("empty RDN", tlv(0x31, &[])),
            ("SEQUENCE for SET", tlv(0x30, &cn)),
            ("truncated", good[..good.len() - 1].to_vec()),
            ("non-minimal length", {
                let mut v = alloc::vec![0x31, 0x81, cn.len() as u8];
                v.extend(&cn);
                v
            }),
            (
                "missing value",
                tlv(0x31, &tlv(0x30, &tlv(0x06, &[0x55, 0x04, 0x03]))),
            ),
            ("third element", tlv(0x31, &extra_field)),
            (
                "bad OID",
                tlv(0x31, &atv(&[0x55, 0x80, 0x03], UTF8_STRING, b"x")),
            ),
            (
                "tag 0 value",
                tlv(0x31, &atv(attribute_type::COMMON_NAME, 0x00, b"")),
            ),
            (
                "constructed string",
                tlv(0x31, &atv(attribute_type::COMMON_NAME, 0x2c, b"")),
            ),
            (
                "primitive SEQUENCE",
                tlv(0x31, &atv(attribute_type::COMMON_NAME, 0x10, b"")),
            ),
        ];
        for (what, bytes) in cases {
            assert!(Name::from_contents(bytes).is_err(), "{what}");
        }
        let mut trailing = tlv(0x30, &good);
        trailing.push(0);
        assert_eq!(Name::from_der(&trailing).err(), Some(Error::TrailingData));
        assert_eq!(Name::from_der(&good).err(), Some(Error::BadDer));
        // Constructed values of other classes are fine.
        assert!(
            Name::from_contents(&tlv(0x31, &atv(attribute_type::COMMON_NAME, 0xa0, b""))).is_ok()
        );
    }

    #[test]
    fn strings() {
        let s = |tag, value: &'static [u8]| AttributeTypeAndValue {
            oid: attribute_type::COMMON_NAME,
            tag,
            value,
        };
        assert_eq!(s(UTF8_STRING, "é".as_bytes()).as_str(), Some("é"));
        assert_eq!(s(UTF8_STRING, b"\xff").as_str(), None);
        assert_eq!(s(PRINTABLE_STRING, b"A-z 0'?").as_str(), Some("A-z 0'?"));
        assert_eq!(s(PRINTABLE_STRING, b"a&b").as_str(), None);
        assert_eq!(s(PRINTABLE_STRING, b"a*b").as_str(), None);
        assert_eq!(s(IA5_STRING, b"a@b\x01").as_str(), Some("a@b\x01"));
        assert_eq!(s(IA5_STRING, b"\x80").as_str(), None);
        assert_eq!(s(NUMERIC_STRING, b"12 3").as_str(), Some("12 3"));
        assert_eq!(s(NUMERIC_STRING, b"1a").as_str(), None);
        assert_eq!(s(VISIBLE_STRING, b"a~").as_str(), Some("a~"));
        assert_eq!(s(VISIBLE_STRING, b"a\n").as_str(), None);
        // BMPString, TeletexString, UniversalString.
        for tag in [0x1e, 0x14, 0x1c] {
            assert_eq!(s(tag, b"\x00a").as_str(), None);
        }
        assert_eq!(format!("{:?}", s(0x1e, b"\x00a")), "2.5.4.3=[1e]0061");
        assert_eq!(
            format!("{:?}", s(UTF8_STRING, b"\"\n")),
            "2.5.4.3=\"\\\"\\n\""
        );
    }
}
