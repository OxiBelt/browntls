//! Strict DER (ITU-T X.690) reader for the ASN.1 subset used by X.509.
//!
//! Rules enforced: definite lengths only, low tag numbers only (0..=30),
//! minimal length encodings (at most four length octets), minimal `INTEGER`
//! encodings, the DER `BOOLEAN` forms, and correct `BIT STRING` padding.
//!
//! The reader never recurses on input-defined structure: every nesting level
//! is spelled out by the grammar in the calling parser, so nesting depth is
//! bounded by the code rather than by the input.

use crate::error::Error;

/// Tag bytes for the universal and context-specific classes used by X.509.
pub(crate) mod tag {
    /// `BOOLEAN`.
    pub(crate) const BOOLEAN: u8 = 0x01;
    /// `INTEGER`.
    pub(crate) const INTEGER: u8 = 0x02;
    /// `BIT STRING`.
    pub(crate) const BIT_STRING: u8 = 0x03;
    /// `OCTET STRING`.
    pub(crate) const OCTET_STRING: u8 = 0x04;
    /// `NULL`.
    pub(crate) const NULL: u8 = 0x05;
    /// `OBJECT IDENTIFIER`.
    pub(crate) const OID: u8 = 0x06;
    /// `ENUMERATED`.
    pub(crate) const ENUMERATED: u8 = 0x0a;
    /// `UTCTime`.
    pub(crate) const UTC_TIME: u8 = 0x17;
    /// `GeneralizedTime`.
    pub(crate) const GENERALIZED_TIME: u8 = 0x18;
    /// `SEQUENCE` (always constructed).
    pub(crate) const SEQUENCE: u8 = 0x30;
    /// Constructed-encoding bit.
    pub(crate) const CONSTRUCTED: u8 = 0x20;
    /// Context-specific class bits.
    pub(crate) const CONTEXT_SPECIFIC: u8 = 0x80;

    /// Context-specific primitive tag `[n] IMPLICIT`.
    pub(crate) const fn context(n: u8) -> u8 {
        CONTEXT_SPECIFIC | n
    }

    /// Context-specific constructed tag `[n]` (explicit, or implicit over a
    /// constructed type).
    pub(crate) const fn context_constructed(n: u8) -> u8 {
        CONTEXT_SPECIFIC | CONSTRUCTED | n
    }
}

/// Largest element contents length accepted while parsing certificates.
///
/// Certificates are small; capping element sizes at the two-octet long form
/// bounds work for pathological inputs.
pub(crate) const CERT_LEN_LIMIT: usize = 0xffff;

/// Largest element contents length accepted while parsing CRLs, which may
/// legitimately be several megabytes.
pub(crate) const CRL_LEN_LIMIT: usize = 0xffff_ffff;

/// Low-tag-number form covers tag numbers 0..=30; 31 marks the high form.
const HIGH_TAG_NUMBER_FORM: u8 = 0x1f;

/// A tag-length-value element: the tag, its contents, and the complete
/// encoding including the tag and length octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
    pub(crate) raw: &'a [u8],
}

/// A cursor over DER input. Copying the reader forks the position.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at the start of `input`.
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Whether every byte has been consumed.
    pub(crate) const fn at_end(&self) -> bool {
        self.input.is_empty()
    }

    /// Whether the next element starts with `tag`.
    pub(crate) fn peek(&self, tag: u8) -> bool {
        self.input.first() == Some(&tag)
    }

    /// Reads one byte.
    pub(crate) fn read_byte(&mut self) -> Result<u8, Error> {
        let (&b, rest) = self.input.split_first().ok_or(Error::BadDer)?;
        self.input = rest;
        Ok(b)
    }

    /// Reads exactly `n` bytes.
    pub(crate) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.input.len() {
            return Err(Error::BadDer);
        }
        let (head, rest) = self.input.split_at(n);
        self.input = rest;
        Ok(head)
    }

    /// Reads one element whose contents are at most `limit` bytes.
    pub(crate) fn tlv_limited(&mut self, limit: usize) -> Result<Tlv<'a>, Error> {
        let start = self.input;
        let tag = self.read_byte()?;
        if tag & HIGH_TAG_NUMBER_FORM == HIGH_TAG_NUMBER_FORM {
            return Err(Error::BadDer);
        }
        let length = self.read_length()?;
        if length > limit {
            return Err(Error::BadDer);
        }
        let value = self.read_bytes(length)?;
        let consumed = start.len() - self.input.len();
        let raw = start.get(..consumed).ok_or(Error::BadDer)?;
        Ok(Tlv { tag, value, raw })
    }

    /// Reads one element under the certificate size limit.
    pub(crate) fn tlv(&mut self) -> Result<Tlv<'a>, Error> {
        self.tlv_limited(CERT_LEN_LIMIT)
    }

    fn read_length(&mut self) -> Result<usize, Error> {
        let first = self.read_byte()?;
        if first < 0x80 {
            return Ok(usize::from(first));
        }
        let octets = first & 0x7f;
        // 0x80 is the indefinite form; 0xff is reserved; we accept at most
        // four length octets.
        if octets == 0 || octets > 4 {
            return Err(Error::BadDer);
        }
        let mut length: usize = 0;
        for i in 0..octets {
            let b = self.read_byte()?;
            // The long form must be minimal: no leading zero octet, and a
            // single octet must not express a value the short form covers.
            if i == 0 && (b == 0 || (octets == 1 && b < 0x80)) {
                return Err(Error::BadDer);
            }
            length = (length << 8) | usize::from(b);
        }
        Ok(length)
    }

    /// Reads an element and checks its tag, returning the contents.
    pub(crate) fn expect(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        self.expect_limited(tag, CERT_LEN_LIMIT)
    }

    /// Like [`Self::expect`] with an explicit contents length limit.
    pub(crate) fn expect_limited(&mut self, tag: u8, limit: usize) -> Result<&'a [u8], Error> {
        let tlv = self.tlv_limited(limit)?;
        if tlv.tag != tag {
            return Err(Error::BadDer);
        }
        Ok(tlv.value)
    }

    /// Like [`Self::expect`] but also returns the complete encoding.
    pub(crate) fn expect_tlv(&mut self, tag: u8) -> Result<Tlv<'a>, Error> {
        let tlv = self.tlv()?;
        if tlv.tag != tag {
            return Err(Error::BadDer);
        }
        Ok(tlv)
    }

    /// Reads an element with `tag` if one is next.
    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>, Error> {
        if self.peek(tag) {
            self.expect(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Reads an element with `tag` and parses its contents with `f`, which
    /// must consume them completely.
    pub(crate) fn nested<T>(
        &mut self,
        tag: u8,
        f: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let value = self.expect(tag)?;
        read_all(value, f)
    }

    /// Reads a `BOOLEAN`.
    pub(crate) fn boolean(&mut self) -> Result<bool, Error> {
        boolean_value(self.expect(tag::BOOLEAN)?)
    }

    /// Reads a `BOOLEAN DEFAULT FALSE`: absent means `false`.
    ///
    /// An explicitly encoded `FALSE` violates DER but is accepted for
    /// compatibility with deployed certificates, as other validators do.
    pub(crate) fn default_false_boolean(&mut self) -> Result<bool, Error> {
        if self.peek(tag::BOOLEAN) {
            self.boolean()
        } else {
            Ok(false)
        }
    }

    /// Reads an `INTEGER` of any sign, returning its two's-complement contents.
    pub(crate) fn integer(&mut self) -> Result<&'a [u8], Error> {
        let v = self.expect(tag::INTEGER)?;
        check_integer(v)?;
        Ok(v)
    }

    /// Reads a non-negative `INTEGER`, returning its magnitude without the
    /// sign-protecting leading zero.
    pub(crate) fn nonnegative_integer(&mut self) -> Result<&'a [u8], Error> {
        nonnegative_magnitude(self.integer()?)
    }

    /// Reads a non-negative `INTEGER` that fits in a byte.
    pub(crate) fn small_nonnegative_integer(&mut self) -> Result<u8, Error> {
        match *self.nonnegative_integer()? {
            [b] => Ok(b),
            _ => Err(Error::BadDer),
        }
    }

    /// Reads an `OBJECT IDENTIFIER`, returning its encoded contents.
    pub(crate) fn oid(&mut self) -> Result<&'a [u8], Error> {
        let v = self.expect(tag::OID)?;
        check_oid(v)?;
        Ok(v)
    }

    /// Reads a `BIT STRING` whose bit count is a whole number of octets,
    /// returning those octets. Used for signatures and public keys.
    pub(crate) fn bit_string_no_unused_bits(&mut self) -> Result<&'a [u8], Error> {
        let v = self.expect(tag::BIT_STRING)?;
        match v.split_first() {
            Some((0, bits)) => Ok(bits),
            _ => Err(Error::BadDer),
        }
    }
}

/// Parses `input` completely with `f`; leftover bytes are an error.
pub(crate) fn read_all<'a, T>(
    input: &'a [u8],
    f: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut reader = Reader::new(input);
    let value = f(&mut reader)?;
    if !reader.at_end() {
        return Err(Error::TrailingData);
    }
    Ok(value)
}

/// Interprets `BOOLEAN` contents.
pub(crate) fn boolean_value(v: &[u8]) -> Result<bool, Error> {
    match v {
        [0xff] => Ok(true),
        [0x00] => Ok(false),
        _ => Err(Error::BadDer),
    }
}

/// Checks that `INTEGER` contents are non-empty and minimally encoded.
pub(crate) fn check_integer(v: &[u8]) -> Result<(), Error> {
    match v {
        [] => Err(Error::BadDer),
        // A leading 0x00 is only needed before a byte with the top bit set;
        // a leading 0xff only before a byte with the top bit clear.
        [0x00, next, ..] if next & 0x80 == 0 => Err(Error::BadDer),
        [0xff, next, ..] if next & 0x80 != 0 => Err(Error::BadDer),
        _ => Ok(()),
    }
}

/// Returns the magnitude of non-negative `INTEGER` contents.
pub(crate) fn nonnegative_magnitude(v: &[u8]) -> Result<&[u8], Error> {
    match v {
        [0x00] => Ok(v),
        [0x00, rest @ ..] => Ok(rest),
        [first, ..] if first & 0x80 == 0 => Ok(v),
        _ => Err(Error::BadDer),
    }
}

/// Checks the structure of `OBJECT IDENTIFIER` contents: at least one
/// subidentifier, no truncated subidentifier, no non-minimal subidentifier.
pub(crate) fn check_oid(v: &[u8]) -> Result<(), Error> {
    if v.is_empty() {
        return Err(Error::BadDer);
    }
    let mut start = true;
    for &b in v {
        if start && b == 0x80 {
            return Err(Error::BadDer);
        }
        start = b & 0x80 == 0;
    }
    if start { Ok(()) } else { Err(Error::BadDer) }
}

/// Named bits of a `BIT STRING` (RFC 5280 `KeyUsage`, `ReasonFlags`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct BitFlags<'a> {
    bits: &'a [u8],
}

impl BitFlags<'_> {
    /// Whether bit `n` (0 = most significant bit of the first octet) is set.
    pub(crate) fn bit_set(&self, n: usize) -> bool {
        let shift = 7 - (n % 8);
        self.bits
            .get(n / 8)
            .is_some_and(|byte| (byte >> shift) & 1 == 1)
    }
}

/// Interprets `BIT STRING` contents as a set of flags, checking that the
/// unused-bit count is in range and that padding bits are zero.
pub(crate) fn bit_string_flags(v: &[u8]) -> Result<BitFlags<'_>, Error> {
    let (&unused, bits) = v.split_first().ok_or(Error::BadDer)?;
    if unused > 7 {
        return Err(Error::BadDer);
    }
    match bits.last() {
        None if unused != 0 => Err(Error::BadDer),
        Some(last) if unused > 0 && last & ((1u8 << unused) - 1) != 0 => Err(Error::BadDer),
        _ => Ok(BitFlags { bits }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        // Short form.
        let t = Reader::new(&[0x04, 0x02, 1, 2]).tlv().unwrap();
        assert_eq!((t.tag, t.value), (0x04, &[1u8, 2][..]));
        assert_eq!(t.raw.len(), 4);
        // Long form, one octet, minimal.
        let mut long = alloc::vec![0x04, 0x81, 0x80];
        long.extend(core::iter::repeat_n(0u8, 0x80));
        assert!(Reader::new(&long).tlv().is_ok());
        // Long form used where short form suffices.
        assert_eq!(
            Reader::new(&[0x04, 0x81, 0x01, 0]).tlv(),
            Err(Error::BadDer)
        );
        // Two octets with a leading zero.
        assert_eq!(
            Reader::new(&[0x04, 0x82, 0x00, 0x81]).tlv(),
            Err(Error::BadDer)
        );
        // Indefinite, reserved and oversized forms.
        for bad in [
            &[0x30u8, 0x80][..],
            &[0x30, 0xff],
            &[0x30, 0x85, 1, 1, 1, 1, 1],
        ] {
            assert_eq!(Reader::new(bad).tlv(), Err(Error::BadDer));
        }
        // Truncated contents.
        assert_eq!(Reader::new(&[0x04, 0x05, 1, 2]).tlv(), Err(Error::BadDer));
        // High tag number form.
        assert_eq!(Reader::new(&[0x1f, 0x01, 0x00]).tlv(), Err(Error::BadDer));
        // Limit.
        assert_eq!(
            Reader::new(&[0x04, 0x02, 1, 2]).tlv_limited(1),
            Err(Error::BadDer)
        );
    }

    #[test]
    fn integers() {
        assert_eq!(check_integer(&[]), Err(Error::BadDer));
        assert_eq!(check_integer(&[0x00, 0x7f]), Err(Error::BadDer));
        assert_eq!(check_integer(&[0xff, 0x80]), Err(Error::BadDer));
        assert_eq!(check_integer(&[0x00, 0x80]), Ok(()));
        assert_eq!(check_integer(&[0xff, 0x7f]), Ok(()));
        assert_eq!(check_integer(&[0x00]), Ok(()));
        assert_eq!(nonnegative_magnitude(&[0x00]), Ok(&[0x00][..]));
        assert_eq!(nonnegative_magnitude(&[0x00, 0x80]), Ok(&[0x80][..]));
        assert_eq!(nonnegative_magnitude(&[0x80]), Err(Error::BadDer));
        let mut r = Reader::new(&[0x02, 0x01, 0x02]);
        assert_eq!(r.small_nonnegative_integer(), Ok(2));
        let mut r = Reader::new(&[0x02, 0x02, 0x01, 0x00]);
        assert_eq!(r.small_nonnegative_integer(), Err(Error::BadDer));
    }

    #[test]
    fn oids() {
        assert_eq!(check_oid(&[]), Err(Error::BadDer));
        assert_eq!(check_oid(&[0x2b, 0x80, 0x01]), Err(Error::BadDer));
        assert_eq!(check_oid(&[0x2b, 0x81]), Err(Error::BadDer));
        assert_eq!(check_oid(&[0x2b, 0x81, 0x04, 0x00, 0x22]), Ok(()));
    }

    #[test]
    fn booleans_and_bit_strings() {
        assert_eq!(boolean_value(&[0xff]), Ok(true));
        assert_eq!(boolean_value(&[0x00]), Ok(false));
        assert_eq!(boolean_value(&[0x01]), Err(Error::BadDer));
        let mut r = Reader::new(&[0x02, 0x01, 0x00]);
        assert_eq!(r.default_false_boolean(), Ok(false));
        assert!(!r.at_end());

        assert!(bit_string_flags(&[8, 0xff]).is_err());
        assert!(bit_string_flags(&[1]).is_err());
        assert!(bit_string_flags(&[1, 0x01]).is_err());
        let flags = bit_string_flags(&[1, 0x06]).unwrap();
        assert!(flags.bit_set(5) && flags.bit_set(6) && !flags.bit_set(7));
        assert!(!flags.bit_set(100));
        let mut r = Reader::new(&[0x03, 0x02, 0x01, 0x00]);
        assert_eq!(r.bit_string_no_unused_bits(), Err(Error::BadDer));
    }

    #[test]
    fn read_all_rejects_trailing() {
        assert_eq!(
            read_all(&[0x05, 0x00, 0x00], |r| r.expect(0x05).map(|_| ())),
            Err(Error::TrailingData)
        );
        assert_eq!(
            Reader::new(&[0x30, 0x02, 0x05, 0x00]).nested(0x30, |r| r.expect(0x05).map(|_| ())),
            Ok(())
        );
    }
}
