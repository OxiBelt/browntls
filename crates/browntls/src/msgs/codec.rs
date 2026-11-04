//! The TLS presentation-language codec (RFC 8446 §3).
//!
//! Every parser is bounded: list lengths are checked against the remaining
//! input before anything is allocated, element counts are capped, and the
//! top-level `read_bytes` rejects trailing data.

use alloc::vec::Vec;
use core::fmt::Debug;

use crate::error::InvalidMessage;

/// A cursor over a byte slice.
#[derive(Debug)]
pub struct Reader<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    /// Starts reading at the beginning of `bytes`.
    pub fn init(bytes: &'a [u8]) -> Self {
        Self {
            buffer: bytes,
            cursor: 0,
        }
    }

    /// The unread remainder.
    pub fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buffer[self.cursor..];
        self.cursor = self.buffer.len();
        rest
    }

    /// Takes `length` bytes, or `None` if that many are not available.
    pub fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        if self.left() < length {
            return None;
        }
        let current = self.cursor;
        self.cursor += length;
        Some(&self.buffer[current..current + length])
    }

    /// Whether any bytes remain.
    pub fn any_left(&self) -> bool {
        self.cursor < self.buffer.len()
    }

    /// Fails if any bytes remain.
    pub fn expect_empty(&self, name: &'static str) -> Result<(), InvalidMessage> {
        if self.any_left() {
            Err(InvalidMessage::TrailingData(name))
        } else {
            Ok(())
        }
    }

    /// Bytes consumed so far.
    pub fn used(&self) -> usize {
        self.cursor
    }

    /// Bytes remaining.
    pub fn left(&self) -> usize {
        self.buffer.len() - self.cursor
    }

    /// Takes `length` bytes as a sub-reader.
    pub fn sub(&mut self, length: usize) -> Result<Self, InvalidMessage> {
        match self.take(length) {
            Some(bytes) => Ok(Reader::init(bytes)),
            None => Err(InvalidMessage::MessageTooShort),
        }
    }
}

/// Encoding and decoding of a wire type.
pub trait Codec<'a>: Debug + Sized {
    /// Appends the encoding of `self` to `bytes`.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Decodes one value from `r`.
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage>;

    /// The encoding of `self` as a fresh vector.
    fn get_encoding(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }

    /// Decodes a value that must occupy exactly `bytes`.
    fn read_bytes(bytes: &'a [u8]) -> Result<Self, InvalidMessage> {
        let mut reader = Reader::init(bytes);
        Self::read(&mut reader).and_then(|r| {
            reader.expect_empty("read_bytes")?;
            Ok(r)
        })
    }
}

impl Codec<'_> for u8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match r.take(1) {
            Some(&[byte]) => Ok(byte),
            _ => Err(InvalidMessage::MissingData("u8")),
        }
    }
}

pub(crate) fn put_u16(v: u16, out: &mut [u8]) {
    out[..2].copy_from_slice(&v.to_be_bytes());
}

impl Codec<'_> for u16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match r.take(2) {
            Some(&[b0, b1]) => Ok(Self::from_be_bytes([b0, b1])),
            _ => Err(InvalidMessage::MissingData("u16")),
        }
    }
}

/// A 24-bit unsigned integer, used for handshake message and certificate lengths.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct u24(pub(crate) u32);

impl u24 {
    pub(crate) const MAX: u32 = 0xff_ffff;

    pub(crate) fn from_usize(v: usize) -> Option<Self> {
        u32::try_from(v).ok().filter(|v| *v <= Self::MAX).map(Self)
    }
}

impl From<u24> for usize {
    #[inline]
    fn from(v: u24) -> Self {
        v.0 as Self
    }
}

impl Codec<'_> for u24 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let be = self.0.to_be_bytes();
        bytes.extend_from_slice(&be[1..]);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match r.take(3) {
            Some(&[a, b, c]) => Ok(Self(u32::from_be_bytes([0, a, b, c]))),
            _ => Err(InvalidMessage::MissingData("u24")),
        }
    }
}

impl Codec<'_> for u32 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match r.take(4) {
            Some(&[a, b, c, d]) => Ok(Self::from_be_bytes([a, b, c, d])),
            _ => Err(InvalidMessage::MissingData("u32")),
        }
    }
}

pub(crate) fn put_u64(v: u64, bytes: &mut [u8]) {
    bytes[..8].copy_from_slice(&v.to_be_bytes());
}

impl Codec<'_> for u64 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match r.take(8) {
            Some(&[a, b, c, d, e, f, g, h]) => Ok(Self::from_be_bytes([a, b, c, d, e, f, g, h])),
            _ => Err(InvalidMessage::MissingData("u64")),
        }
    }
}

/// The size of a length prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListLength {
    U8,
    U16,
    U24 { max: usize, error: InvalidMessage },
}

impl ListLength {
    fn size(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U24 { .. } => 3,
        }
    }
}

/// A `Vec<u8>` that is being filled with a length-prefixed item; the length
/// is patched in when the buffer is dropped.
pub(crate) struct LengthPrefixedBuffer<'a> {
    pub(crate) buf: &'a mut Vec<u8>,
    len_offset: usize,
    size: ListLength,
}

impl<'a> LengthPrefixedBuffer<'a> {
    pub(crate) fn new(size: ListLength, buf: &'a mut Vec<u8>) -> Self {
        let len_offset = buf.len();
        buf.extend(core::iter::repeat_n(0xff, size.size()));
        Self {
            buf,
            len_offset,
            size,
        }
    }
}

impl Drop for LengthPrefixedBuffer<'_> {
    fn drop(&mut self) {
        let len = self.buf.len() - self.len_offset - self.size.size();
        match self.size {
            ListLength::U8 => {
                // Encoders only produce items that fit their declared prefix;
                // saturate rather than corrupt the stream if that is violated.
                let len = u8::try_from(len).unwrap_or(u8::MAX);
                self.buf[self.len_offset] = len;
            }
            ListLength::U16 => {
                let len = u16::try_from(len).unwrap_or(u16::MAX);
                put_u16(len, &mut self.buf[self.len_offset..]);
            }
            ListLength::U24 { .. } => {
                let len = u24::from_usize(len).unwrap_or(u24(u24::MAX));
                let be = len.0.to_be_bytes();
                self.buf[self.len_offset..self.len_offset + 3].copy_from_slice(&be[1..]);
            }
        }
    }
}

/// Encodes a list of items with the given length prefix size.
pub(crate) fn encode_list<'a, T: Codec<'a>>(size: ListLength, items: &[T], bytes: &mut Vec<u8>) {
    let nest = LengthPrefixedBuffer::new(size, bytes);
    for i in items {
        i.encode(nest.buf);
    }
}

/// Reads the length prefix and returns a sub-reader over exactly that many bytes.
pub(crate) fn read_list_prefix<'a>(
    size: ListLength,
    r: &mut Reader<'a>,
) -> Result<Reader<'a>, InvalidMessage> {
    let len = match size {
        ListLength::U8 => usize::from(u8::read(r)?),
        ListLength::U16 => usize::from(u16::read(r)?),
        ListLength::U24 { max, error } => {
            let len = usize::from(u24::read(r)?);
            if len > max {
                return Err(error);
            }
            len
        }
    };
    r.sub(len)
}

/// Decodes a list of items from a length-prefixed sub-reader. The element
/// count is implicitly bounded by the prefix size and the input length; the
/// caller may further restrict the count with `max_items` (0 = unbounded).
pub(crate) fn read_list<'a, T: Codec<'a>>(
    size: ListLength,
    r: &mut Reader<'a>,
    max_items: usize,
) -> Result<Vec<T>, InvalidMessage> {
    let mut sub = read_list_prefix(size, r)?;
    let mut ret = Vec::new();
    while sub.any_left() {
        if max_items != 0 && ret.len() >= max_items {
            return Err(InvalidMessage::MessageTooLarge);
        }
        ret.push(T::read(&mut sub)?);
    }
    Ok(ret)
}

/// Helper for the `u8`-prefixed vector-of-T pattern.
pub(crate) fn encode_vec_u8<'a, T: Codec<'a>>(bytes: &mut Vec<u8>, items: &[T]) {
    encode_list(ListLength::U8, items, bytes);
}

/// Helper for the `u16`-prefixed vector-of-T pattern.
pub(crate) fn encode_vec_u16<'a, T: Codec<'a>>(bytes: &mut Vec<u8>, items: &[T]) {
    encode_list(ListLength::U16, items, bytes);
}

/// Helper for the `u24`-prefixed vector-of-T pattern.
pub(crate) fn encode_vec_u24<'a, T: Codec<'a>>(bytes: &mut Vec<u8>, items: &[T]) {
    encode_list(
        ListLength::U24 {
            max: usize::MAX,
            error: InvalidMessage::MessageTooLarge,
        },
        items,
        bytes,
    );
}

pub(crate) fn read_vec_u8<'a, T: Codec<'a>>(r: &mut Reader<'a>) -> Result<Vec<T>, InvalidMessage> {
    read_list(ListLength::U8, r, 0)
}

pub(crate) fn read_vec_u16<'a, T: Codec<'a>>(r: &mut Reader<'a>) -> Result<Vec<T>, InvalidMessage> {
    read_list(ListLength::U16, r, 0)
}

pub(crate) fn read_vec_u24<'a, T: Codec<'a>>(
    r: &mut Reader<'a>,
    max_bytes: usize,
    error: InvalidMessage,
) -> Result<Vec<T>, InvalidMessage> {
    read_list(
        ListLength::U24 {
            max: max_bytes,
            error,
        },
        r,
        0,
    )
}

/// Reads a `u16`-prefixed list that must be non-empty.
pub(crate) fn read_nonempty_vec_u16<'a, T: Codec<'a>>(
    r: &mut Reader<'a>,
    name: &'static str,
) -> Result<Vec<T>, InvalidMessage> {
    let v = read_vec_u16::<T>(r)?;
    if v.is_empty() {
        return Err(InvalidMessage::IllegalEmptyList(name));
    }
    Ok(v)
}

/// Reads a `u8`-prefixed list that must be non-empty.
pub(crate) fn read_nonempty_vec_u8<'a, T: Codec<'a>>(
    r: &mut Reader<'a>,
    name: &'static str,
) -> Result<Vec<T>, InvalidMessage> {
    let v = read_vec_u8::<T>(r)?;
    if v.is_empty() {
        return Err(InvalidMessage::IllegalEmptyList(name));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_roundtrip() {
        for v in [0u8, 1, 255] {
            assert_eq!(u8::read_bytes(&v.get_encoding()).unwrap(), v);
        }
        for v in [0u16, 1, 0x1234, 0xffff] {
            assert_eq!(u16::read_bytes(&v.get_encoding()).unwrap(), v);
        }
        for v in [0u32, 1, 0x12_3456, u24::MAX] {
            assert_eq!(u24::read_bytes(&u24(v).get_encoding()).unwrap(), u24(v));
        }
        assert_eq!(u24(0x12_3456).get_encoding(), [0x12, 0x34, 0x56]);
        for v in [0u32, 0x1234_5678, u32::MAX] {
            assert_eq!(u32::read_bytes(&v.get_encoding()).unwrap(), v);
        }
        for v in [0u64, 0x0123_4567_89ab_cdef, u64::MAX] {
            assert_eq!(u64::read_bytes(&v.get_encoding()).unwrap(), v);
        }
    }

    #[test]
    fn short_input_is_missing_data() {
        assert_eq!(
            u16::read_bytes(&[1]),
            Err(InvalidMessage::MissingData("u16"))
        );
        assert_eq!(
            u24::read_bytes(&[1, 2]),
            Err(InvalidMessage::MissingData("u24"))
        );
        assert_eq!(
            u32::read_bytes(&[1, 2, 3]),
            Err(InvalidMessage::MissingData("u32"))
        );
        assert_eq!(
            u64::read_bytes(&[0; 7]),
            Err(InvalidMessage::MissingData("u64"))
        );
    }

    #[test]
    fn trailing_data_is_rejected() {
        assert_eq!(
            u8::read_bytes(&[1, 2]),
            Err(InvalidMessage::TrailingData("read_bytes"))
        );
    }

    #[test]
    fn lists_roundtrip_and_check_bounds() {
        let items = [1u16, 2, 3];
        let mut bytes = Vec::new();
        encode_vec_u8(&mut bytes, &items);
        assert_eq!(bytes, [6, 0, 1, 0, 2, 0, 3]);
        let back: Vec<u16> = read_vec_u8(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(back, items);

        let mut bytes = Vec::new();
        encode_vec_u16(&mut bytes, &items);
        assert_eq!(bytes, [0, 6, 0, 1, 0, 2, 0, 3]);
        let back: Vec<u16> = read_vec_u16(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(back, items);

        let mut bytes = Vec::new();
        encode_vec_u24(&mut bytes, &items);
        assert_eq!(bytes, [0, 0, 6, 0, 1, 0, 2, 0, 3]);
        let back: Vec<u16> = read_vec_u24(
            &mut Reader::init(&bytes),
            6,
            InvalidMessage::MessageTooLarge,
        )
        .unwrap();
        assert_eq!(back, items);
        assert_eq!(
            read_vec_u24::<u16>(
                &mut Reader::init(&bytes),
                5,
                InvalidMessage::MessageTooLarge
            ),
            Err(InvalidMessage::MessageTooLarge)
        );

        // length prefix larger than the data: must not panic or allocate
        assert_eq!(
            read_vec_u16::<u16>(&mut Reader::init(&[0xff, 0xff, 0, 1])),
            Err(InvalidMessage::MessageTooShort)
        );
        // odd number of bytes for u16 items
        assert_eq!(
            read_vec_u8::<u16>(&mut Reader::init(&[3, 0, 1, 0])),
            Err(InvalidMessage::MissingData("u16"))
        );
        // element cap
        assert_eq!(
            read_list::<u16>(ListLength::U8, &mut Reader::init(&[6, 0, 1, 0, 2, 0, 3]), 2),
            Err(InvalidMessage::MessageTooLarge)
        );
    }

    #[test]
    fn nonempty_lists() {
        assert_eq!(
            read_nonempty_vec_u16::<u16>(&mut Reader::init(&[0, 0]), "x"),
            Err(InvalidMessage::IllegalEmptyList("x"))
        );
        assert_eq!(
            read_nonempty_vec_u8::<u8>(&mut Reader::init(&[0]), "y"),
            Err(InvalidMessage::IllegalEmptyList("y"))
        );
        assert_eq!(
            read_nonempty_vec_u8::<u8>(&mut Reader::init(&[1, 7]), "y").unwrap(),
            [7]
        );
    }

    #[test]
    fn reader_sub_and_rest() {
        let mut r = Reader::init(&[1, 2, 3, 4]);
        let mut s = r.sub(2).unwrap();
        assert_eq!(s.rest(), [1, 2]);
        assert_eq!(r.used(), 2);
        assert_eq!(r.left(), 2);
        assert!(r.sub(3).is_err());
        assert_eq!(r.rest(), [3, 4]);
        assert!(!r.any_left());
        assert!(r.expect_empty("r").is_ok());
    }
}
