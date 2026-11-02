//! Minimal DER (X.690) reading and writing for key and signature encodings.
//!
//! This is intentionally small: definite-length, single-byte tags, and lengths
//! up to `u32::MAX`. It rejects non-minimal lengths and non-minimal or negative
//! INTEGERs where positive values are expected.

use crate::Error;

/// Common universal tags.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER.
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING.
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING.
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL.
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER.
    pub const OID: u8 = 0x06;
    /// SEQUENCE (constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// Context-specific constructed tag `[n]`.
    #[must_use]
    pub const fn context_constructed(n: u8) -> u8 {
        0xa0 | n
    }
    /// Context-specific primitive tag `[n]`.
    #[must_use]
    pub const fn context_primitive(n: u8) -> u8 {
        0x80 | n
    }
}

/// A cursor over DER input.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Creates a reader over `input`.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Returns `true` when all input has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Returns the unread input.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.input
    }

    /// Returns the next tag without consuming it.
    #[must_use]
    pub fn peek_tag(&self) -> Option<u8> {
        self.input.first().copied()
    }

    /// Reads any TLV, returning `(tag, value)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] on truncated or non-DER input.
    pub fn read_any(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let (&t, rest) = self.input.split_first().ok_or(Error::InvalidEncoding)?;
        if t & 0x1f == 0x1f {
            return Err(Error::InvalidEncoding); // multi-byte tags unsupported
        }
        let (&l0, mut rest) = rest.split_first().ok_or(Error::InvalidEncoding)?;
        let len = if l0 < 0x80 {
            usize::from(l0)
        } else {
            let n = usize::from(l0 & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return Err(Error::InvalidEncoding);
            }
            let mut len = 0usize;
            for &b in &rest[..n] {
                len = (len << 8) | usize::from(b);
            }
            // Minimal encoding: no leading zero byte, and long form only >= 128.
            if rest[0] == 0 || len < 0x80 {
                return Err(Error::InvalidEncoding);
            }
            rest = &rest[n..];
            len
        };
        if rest.len() < len {
            return Err(Error::InvalidEncoding);
        }
        let (value, rest) = rest.split_at(len);
        self.input = rest;
        Ok((t, value))
    }

    /// Reads a TLV with the expected tag and returns its value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] on a tag mismatch or bad encoding.
    pub fn read(&mut self, expected: u8) -> Result<&'a [u8], Error> {
        let (t, v) = self.read_any()?;
        if t != expected {
            return Err(Error::InvalidEncoding);
        }
        Ok(v)
    }

    /// Reads an optional TLV: returns `None` if the next tag differs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] on bad encoding.
    pub fn read_optional(&mut self, expected: u8) -> Result<Option<&'a [u8]>, Error> {
        if self.peek_tag() == Some(expected) {
            self.read(expected).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Reads a SEQUENCE and returns a reader over its contents.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] on a tag mismatch or bad encoding.
    pub fn read_sequence(&mut self) -> Result<Reader<'a>, Error> {
        self.read(tag::SEQUENCE).map(Reader::new)
    }

    /// Reads a non-negative INTEGER and returns its big-endian magnitude with
    /// any leading sign octet removed (zero is returned as `[0]`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for negative or non-minimal values.
    pub fn read_positive_integer(&mut self) -> Result<&'a [u8], Error> {
        let v = self.read(tag::INTEGER)?;
        match v {
            [] => Err(Error::InvalidEncoding),
            [b] if *b & 0x80 != 0 => Err(Error::InvalidEncoding),
            [_] => Ok(v),
            [0, b, ..] if *b & 0x80 == 0 => Err(Error::InvalidEncoding),
            [0, rest @ ..] => Ok(rest),
            [b, ..] if *b & 0x80 != 0 => Err(Error::InvalidEncoding),
            _ => Ok(v),
        }
    }

    /// Reads a small non-negative INTEGER (fits in `u64`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for negative, non-minimal or large values.
    pub fn read_small_integer(&mut self) -> Result<u64, Error> {
        let v = self.read_positive_integer()?;
        if v.len() > 8 {
            return Err(Error::InvalidEncoding);
        }
        Ok(v.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// Reads a BIT STRING with no unused bits and returns its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] if bits are unused or encoding is bad.
    pub fn read_bit_string_octets(&mut self) -> Result<&'a [u8], Error> {
        match self.read(tag::BIT_STRING)? {
            [0, rest @ ..] => Ok(rest),
            _ => Err(Error::InvalidEncoding),
        }
    }

    /// Reads an OCTET STRING.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] on a tag mismatch or bad encoding.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], Error> {
        self.read(tag::OCTET_STRING)
    }

    /// Reads an OBJECT IDENTIFIER and returns its encoded contents.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] on a tag mismatch or bad encoding.
    pub fn read_oid(&mut self) -> Result<&'a [u8], Error> {
        self.read(tag::OID)
    }

    /// Fails unless all input has been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] when input remains.
    pub fn finish(self) -> Result<(), Error> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }
}

/// Parses `input` as exactly one SEQUENCE and applies `f` to its contents,
/// requiring both the outer input and the sequence contents to be consumed.
///
/// # Errors
///
/// Propagates errors from `f` and returns [`Error::InvalidEncoding`] for bad
/// encodings or trailing data.
pub fn parse_sequence<'a, T>(
    input: &'a [u8],
    f: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut outer = Reader::new(input);
    let mut inner = outer.read_sequence()?;
    let out = f(&mut inner)?;
    inner.finish()?;
    outer.finish()?;
    Ok(out)
}

/// A fixed-capacity DER writer (no allocation).
#[derive(Debug)]
pub struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    /// Creates a writer over `out`.
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the written bytes.
    #[must_use]
    pub fn finish(self) -> &'a [u8] {
        &self.out[..self.len]
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(Error::InvalidLength)?;
        if end > self.out.len() {
            return Err(Error::InvalidLength);
        }
        self.out[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    /// Writes a tag and length header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if the buffer is too small.
    pub fn header(&mut self, tag: u8, len: usize) -> Result<(), Error> {
        self.push(&[tag])?;
        let bytes = (len as u64).to_be_bytes();
        if len < 0x80 {
            self.push(&bytes[7..])
        } else {
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            let n = 8 - skip;
            // n <= 8 so the cast cannot truncate.
            #[allow(clippy::cast_possible_truncation)]
            self.push(&[0x80 | n as u8])?;
            self.push(&bytes[skip..])
        }
    }

    /// Writes a complete TLV.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if the buffer is too small.
    pub fn tlv(&mut self, tag: u8, value: &[u8]) -> Result<(), Error> {
        self.header(tag, value.len())?;
        self.push(value)
    }

    /// Writes a non-negative INTEGER from a big-endian magnitude, stripping
    /// leading zeros and adding a sign octet when needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if the buffer is too small.
    pub fn positive_integer(&mut self, magnitude: &[u8]) -> Result<(), Error> {
        let skip = magnitude.iter().take_while(|&&b| b == 0).count();
        let m = &magnitude[skip..];
        if m.is_empty() {
            return self.tlv(tag::INTEGER, &[0]);
        }
        if m[0] & 0x80 != 0 {
            self.header(tag::INTEGER, m.len() + 1)?;
            self.push(&[0])?;
            self.push(m)
        } else {
            self.tlv(tag::INTEGER, m)
        }
    }

    /// Length of the encoding of a non-negative INTEGER with this magnitude.
    #[must_use]
    pub fn positive_integer_len(magnitude: &[u8]) -> usize {
        let skip = magnitude.iter().take_while(|&&b| b == 0).count();
        let m = &magnitude[skip..];
        let content = if m.is_empty() {
            1
        } else {
            m.len() + usize::from(m[0] & 0x80 != 0)
        };
        header_len(content) + content
    }
}

/// Length of a tag + length header for `content_len` bytes of content.
#[must_use]
pub fn header_len(content_len: usize) -> usize {
    if content_len < 0x80 {
        2
    } else {
        let bytes = (content_len as u64).to_be_bytes();
        2 + 8 - bytes.iter().take_while(|&&b| b == 0).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        let mut r = Reader::new(&[0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x7f]);
        assert_eq!(r.read_positive_integer().unwrap(), &[0x80]);
        assert_eq!(r.read_small_integer().unwrap(), 0x7f);
        assert!(r.finish().is_ok());
        assert!(
            Reader::new(&[0x02, 0x01, 0x80])
                .read_positive_integer()
                .is_err()
        );
        assert!(
            Reader::new(&[0x02, 0x02, 0x00, 0x01])
                .read_positive_integer()
                .is_err()
        );
        assert!(Reader::new(&[0x02, 0x00]).read_positive_integer().is_err());
        assert!(Reader::new(&[0x02, 0x81, 0x01, 0x00]).read_any().is_err()); // non-minimal length
    }

    #[test]
    fn writer_roundtrip() {
        let mut buf = [0u8; 300];
        let mut w = Writer::new(&mut buf);
        w.positive_integer(&[0x00, 0x00, 0xff]).unwrap();
        w.tlv(tag::OCTET_STRING, &[7u8; 200]).unwrap();
        let out = w.finish();
        let mut r = Reader::new(out);
        assert_eq!(r.read_positive_integer().unwrap(), &[0xff]);
        assert_eq!(r.read_octet_string().unwrap().len(), 200);
        assert!(r.finish().is_ok());
        assert_eq!(Writer::positive_integer_len(&[0xff]), 4);
    }
}
