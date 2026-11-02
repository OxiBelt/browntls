//! Hash functions.

use alloc::boxed::Box;

pub use crate::msgs::enums::HashAlgorithm;

/// A hash function.
pub trait Hash: Send + Sync {
    /// Starts an incremental computation.
    fn start(&self) -> Box<dyn Context>;

    /// Hashes `data` in one call.
    fn hash(&self, data: &[u8]) -> Output;

    /// The digest length in bytes.
    fn output_len(&self) -> usize;

    /// Which algorithm this is.
    fn algorithm(&self) -> HashAlgorithm;

    /// Whether the implementation is FIPS validated.
    fn fips(&self) -> bool {
        false
    }
}

/// A hash output of at most 64 bytes.
#[derive(Clone)]
pub struct Output {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl Output {
    /// Wraps `bytes`, which must be at most [`Self::MAX_LEN`] long.
    pub fn new(bytes: &[u8]) -> Self {
        let mut output = Self {
            buf: [0u8; Self::MAX_LEN],
            used: bytes.len().min(Self::MAX_LEN),
        };
        output.buf[..output.used].copy_from_slice(&bytes[..output.used]);
        output
    }

    /// The largest digest supported.
    pub const MAX_LEN: usize = 64;
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl core::fmt::Debug for Output {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        crate::msgs::base::hex(f, self.as_ref())
    }
}

/// An incremental hash computation.
pub trait Context: Send + Sync {
    /// Finishes a copy of the computation, leaving this one usable.
    fn fork_finish(&self) -> Output;

    /// Copies the computation.
    fn fork(&self) -> Box<dyn Context>;

    /// Finishes the computation.
    fn finish(self: Box<Self>) -> Output;

    /// Absorbs `data`.
    fn update(&mut self, data: &[u8]);
}
