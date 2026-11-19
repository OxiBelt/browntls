//! Bounds-checked cursor over an encoded filter.

use super::CrliteError;

/// A forward-only reader. Every method fails with
/// [`CrliteError::Truncated`] instead of reading past the end.
pub(super) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], CrliteError> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(CrliteError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], CrliteError> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(CrliteError::Truncated)?;
        self.rest = tail;
        Ok(*head)
    }

    pub(super) fn u8(&mut self) -> Result<u8, CrliteError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    pub(super) fn u16_be(&mut self) -> Result<u16, CrliteError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(super) fn u32_be(&mut self) -> Result<u32, CrliteError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64_be(&mut self) -> Result<u64, CrliteError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn u64_le(&mut self) -> Result<u64, CrliteError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A byte that encodes a boolean as exactly 0 or 1.
    pub(super) fn bool(&mut self) -> Result<bool, CrliteError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CrliteError::Malformed),
        }
    }

    /// Checks that `count` items of at least `min_item_len` encoded bytes
    /// each can still follow, so that a count may size an allocation.
    pub(super) fn expect_items(
        &self,
        count: usize,
        min_item_len: usize,
    ) -> Result<(), CrliteError> {
        match count.checked_mul(min_item_len) {
            Some(len) if len <= self.rest.len() => Ok(()),
            _ => Err(CrliteError::Truncated),
        }
    }

    pub(super) fn finish(&self) -> Result<(), CrliteError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(CrliteError::TrailingData)
        }
    }
}
