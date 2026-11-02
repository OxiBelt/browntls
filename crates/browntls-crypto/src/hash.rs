//! SHA-2 hash functions (FIPS 180-4): SHA-256, SHA-384 and SHA-512.
//!
//! The compression function is chosen when a hasher is created: a portable
//! implementation, or an accelerated backend when the CPU supports one.

mod sha256;
mod sha512;

pub use sha256::Sha256;
pub use sha512::{Sha384, Sha512};

/// The largest digest output length, in bytes.
pub const MAX_OUTPUT_LEN: usize = 64;
/// The largest digest block length, in bytes.
pub const MAX_BLOCK_LEN: usize = 128;

/// A streaming hash function.
pub trait Digest: Clone + Send + Sync + 'static {
    /// Output length in bytes.
    const OUTPUT_LEN: usize;
    /// Internal block length in bytes.
    const BLOCK_LEN: usize;
    /// The digest output.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Copy + core::fmt::Debug + PartialEq + Eq;

    /// Starts a new hash computation.
    fn new() -> Self;
    /// Absorbs `data`.
    fn update(&mut self, data: &[u8]);
    /// Finishes the computation and returns the digest.
    fn finalize(self) -> Self::Output;

    /// Hashes `data` in one call.
    #[must_use]
    fn digest(data: &[u8]) -> Self::Output {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// Buffers input into whole blocks and applies MD-style padding.
#[derive(Clone)]
struct BlockBuffer<const B: usize> {
    buf: [u8; B],
    len: usize,
}

impl<const B: usize> BlockBuffer<B> {
    const fn new() -> Self {
        Self {
            buf: [0; B],
            len: 0,
        }
    }

    /// Feeds `data`, calling `compress` with runs of whole blocks.
    fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8])) {
        if self.len > 0 {
            let take = (B - self.len).min(data.len());
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
            if self.len < B {
                return;
            }
            compress(&self.buf);
            self.len = 0;
        }
        let whole = data.len() - data.len() % B;
        if whole > 0 {
            compress(&data[..whole]);
        }
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    /// Applies padding with a big-endian bit length of `LEN_BYTES` bytes.
    fn finish<const LEN_BYTES: usize>(&mut self, bit_len: u128, mut compress: impl FnMut(&[u8])) {
        self.buf[self.len] = 0x80;
        self.buf[self.len + 1..].fill(0);
        if self.len + 1 > B - LEN_BYTES {
            compress(&self.buf);
            self.buf.fill(0);
        }
        let len = bit_len.to_be_bytes();
        self.buf[B - LEN_BYTES..].copy_from_slice(&len[16 - LEN_BYTES..]);
        compress(&self.buf);
        self.len = 0;
    }
}

impl<const B: usize> Drop for BlockBuffer<B> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}
