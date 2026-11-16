//! A cursor over fuzzer input for the API-sequence harnesses.
//!
//! Every read succeeds: a read past the end yields zeros or an empty slice,
//! so that any input is a valid program of operations and a mutation that
//! shortens the input only shortens the program.

/// Fuzzer input consumed from the front.
#[derive(Clone, Copy, Debug)]
pub struct Input<'a> {
    data: &'a [u8],
}

impl<'a> Input<'a> {
    /// Wraps `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Whether nothing is left.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }

    /// Consumes and returns everything that is left.
    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.data)
    }

    /// The next byte, or zero.
    pub fn byte(&mut self) -> u8 {
        crate::take_byte(&mut self.data)
    }

    /// The next byte's low bit.
    pub fn bool(&mut self) -> bool {
        self.byte() & 1 != 0
    }

    /// The next byte reduced modulo `n` (`n` must not be zero).
    pub fn choose(&mut self, n: usize) -> usize {
        usize::from(self.byte()) % n
    }

    /// A reference to one of `items`, chosen by the next byte.
    pub fn pick<'t, T>(&mut self, items: &'t [T]) -> &'t T {
        &items[self.choose(items.len())]
    }

    /// The next two bytes, big-endian, or zero-padded.
    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    /// The next four bytes, big-endian, or zero-padded.
    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    /// The next eight bytes, big-endian, or zero-padded.
    pub fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }

    /// The next `N` bytes, zero-padded when fewer are left.
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let bytes = self.bytes(N);
        out[..bytes.len()].copy_from_slice(bytes);
        out
    }

    /// Up to `n` bytes (fewer when the input runs out).
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.data.split_at(n.min(self.data.len()));
        self.data = tail;
        head
    }

    /// A field with a 16-bit big-endian length prefix (clamped to what is
    /// left).
    pub fn field(&mut self) -> &'a [u8] {
        crate::take_field(&mut self.data)
    }

    /// A field with an 8-bit length prefix (clamped to what is left).
    pub fn short_field(&mut self) -> &'a [u8] {
        let n = usize::from(self.byte());
        self.bytes(n)
    }
}

/// Appends `bytes` to `out` with the 16-bit length prefix [`Input::field`]
/// reads.
pub fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes[..usize::from(len)]);
}

/// Appends `bytes` to `out` with the 8-bit length prefix
/// [`Input::short_field`] reads.
pub fn put_short_field(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
    out.push(len);
    out.extend_from_slice(&bytes[..usize::from(len)]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_past_the_end_are_zero_or_empty() {
        let mut input = Input::new(&[1, 2, 3]);
        assert_eq!(input.u16(), 0x0102);
        assert_eq!(input.u32(), 0x0300_0000);
        assert_eq!(input.byte(), 0);
        assert!(input.field().is_empty());
        assert!(input.is_empty());
    }

    #[test]
    fn fields_round_trip() {
        let mut out = Vec::new();
        put_field(&mut out, b"abc");
        put_short_field(&mut out, b"de");
        let mut input = Input::new(&out);
        assert_eq!(input.field(), b"abc");
        assert_eq!(input.short_field(), b"de");
    }
}
