//! Opaque byte payloads with the common TLS length prefixes.

use alloc::vec::Vec;
use core::fmt;

use super::codec::{Codec, Reader, u24};
use crate::error::InvalidMessage;

/// An arbitrary, unknown-content, u8-length-prefixed or unprefixed payload.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum Payload<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl Codec<'_> for Payload<'_> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self::Owned(r.rest().to_vec()))
    }
}

impl<'a> Payload<'a> {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Borrowed(bytes) => bytes.to_vec(),
            Self::Owned(bytes) => bytes,
        }
    }

    pub(crate) fn into_owned(self) -> Payload<'static> {
        Payload::Owned(self.into_vec())
    }

    pub(crate) fn new(bytes: impl Into<Vec<u8>>) -> Payload<'static> {
        Payload::Owned(bytes.into())
    }

    pub(crate) fn empty() -> Payload<'static> {
        Payload::Owned(Vec::new())
    }

    pub(crate) fn read(r: &mut Reader<'a>) -> Self {
        Self::Borrowed(r.rest())
    }
}

impl fmt::Debug for Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, self.bytes())
    }
}

/// An arbitrary, unknown-content, u8-length-prefixed payload.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct PayloadU8(pub(crate) Vec<u8>);

impl PayloadU8 {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Codec<'_> for PayloadU8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Callers guarantee the payload fits a u8 length; saturating here
        // can never produce a parseable-but-wrong message, only a rejected one.
        (u8::try_from(self.0.len()).unwrap_or(u8::MAX)).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = usize::from(u8::read(r)?);
        let mut sub = r.sub(len)?;
        Ok(Self(sub.rest().to_vec()))
    }
}

impl fmt::Debug for PayloadU8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

/// An arbitrary, unknown-content, u16-length-prefixed payload.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct PayloadU16(pub(crate) Vec<u8>);

impl PayloadU16 {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (u16::try_from(slice.len()).unwrap_or(u16::MAX)).encode(bytes);
        bytes.extend_from_slice(slice);
    }
}

impl Codec<'_> for PayloadU16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = usize::from(u16::read(r)?);
        let mut sub = r.sub(len)?;
        Ok(Self(sub.rest().to_vec()))
    }
}

impl fmt::Debug for PayloadU16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

/// An arbitrary, unknown-content, u24-length-prefixed payload.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PayloadU24<'a>(pub(crate) Payload<'a>);

impl PayloadU24<'_> {
    pub(crate) fn into_owned(self) -> PayloadU24<'static> {
        PayloadU24(self.0.into_owned())
    }
}

impl<'a> Codec<'a> for PayloadU24<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let inner = self.0.bytes();
        u24::from_usize(inner.len())
            .unwrap_or(u24(u24::MAX))
            .encode(bytes);
        bytes.extend_from_slice(inner);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = usize::from(u24::read(r)?);
        let mut sub = r.sub(len)?;
        Ok(Self(Payload::read(&mut sub)))
    }
}

impl fmt::Debug for PayloadU24<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub(crate) fn hex(f: &mut fmt::Formatter<'_>, payload: &[u8]) -> fmt::Result {
    for b in payload {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_roundtrip() {
        let p8 = PayloadU8::new(alloc::vec![1, 2, 3]);
        assert_eq!(p8.get_encoding(), [3, 1, 2, 3]);
        assert_eq!(PayloadU8::read_bytes(&[3, 1, 2, 3]).unwrap(), p8);
        assert_eq!(
            PayloadU8::read_bytes(&[4, 1, 2, 3]),
            Err(InvalidMessage::MessageTooShort)
        );

        let p16 = PayloadU16::new(alloc::vec![1, 2, 3]);
        assert_eq!(p16.get_encoding(), [0, 3, 1, 2, 3]);
        assert_eq!(PayloadU16::read_bytes(&[0, 3, 1, 2, 3]).unwrap(), p16);

        let p24 = PayloadU24(Payload::Borrowed(&[1, 2, 3]));
        assert_eq!(p24.get_encoding(), [0, 0, 3, 1, 2, 3]);
        assert_eq!(
            PayloadU24::read_bytes(&[0, 0, 3, 1, 2, 3]).unwrap().0.bytes(),
            [1, 2, 3]
        );

        assert_eq!(alloc::format!("{p8:?}"), "010203");
        assert_eq!(Payload::new(alloc::vec![9u8]).into_vec(), [9]);
    }
}
