//! Hash functions: SHA-2 (FIPS 180-4) and SHA-3 / SHAKE (FIPS 202).
//!
//! Each compression / permutation function dispatches at run time to the best
//! available backend (see the crate-level table). The portable backends are
//! the reference against which every accelerated backend is tested.

mod sha256;
pub mod sha3;
mod sha512;

pub use sha3::{Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, ShakeReader};
pub use sha256::{Sha224, Sha256};
pub use sha512::{Sha384, Sha512};

/// Maximum digest length of any [`HashFunction`] in this crate.
pub const MAX_OUTPUT_LEN: usize = 64;
/// Maximum block length of any [`HashFunction`] in this crate (SHA3-224 rate
/// is 144 bytes).
pub const MAX_BLOCK_LEN: usize = 144;

/// A fixed-size digest (`[u8; N]`).
pub trait Output:
    AsRef<[u8]> + AsMut<[u8]> + Copy + core::fmt::Debug + PartialEq + Eq + Send + Sync + 'static
{
    /// An all-zero value.
    fn zeroed() -> Self;
}

impl<const N: usize> Output for [u8; N] {
    fn zeroed() -> Self {
        [0; N]
    }
}

/// A fixed-output-length cryptographic hash function.
pub trait HashFunction: Clone + Default {
    /// Digest length in bytes.
    const OUTPUT_LEN: usize;
    /// Block length in bytes (the HMAC block size).
    const BLOCK_LEN: usize;
    /// The digest type (`[u8; OUTPUT_LEN]`).
    type Output: Output;

    /// Starts a new hash computation.
    #[must_use]
    fn new() -> Self {
        Self::default()
    }

    /// Absorbs `data`.
    fn update(&mut self, data: &[u8]);

    /// Completes the computation and returns the digest.
    #[must_use]
    fn finalize(self) -> Self::Output;

    /// Hashes `data` in one call.
    #[must_use]
    fn digest(data: &[u8]) -> Self::Output {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// Identifies a hash function at run time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
}

impl HashAlgorithm {
    /// Digest length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha224 => 28,
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
}

/// A run-time selected hash computation (used by the TLS transcript hash,
/// which only learns the hash after cipher-suite negotiation).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum DynHash {
    /// SHA-224.
    Sha224(Sha224),
    /// SHA-256.
    Sha256(Sha256),
    /// SHA-384.
    Sha384(Sha384),
    /// SHA-512.
    Sha512(Sha512),
    /// SHA3-256.
    Sha3_256(Sha3_256),
    /// SHA3-384.
    Sha3_384(Sha3_384),
    /// SHA3-512.
    Sha3_512(Sha3_512),
}

/// A digest of at most [`MAX_OUTPUT_LEN`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynOutput {
    buf: [u8; MAX_OUTPUT_LEN],
    len: usize,
}

impl DynOutput {
    /// Copies `bytes` (at most [`MAX_OUTPUT_LEN`]) into a new output.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is longer than [`MAX_OUTPUT_LEN`].
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        let mut buf = [0u8; MAX_OUTPUT_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Self {
            buf,
            len: bytes.len(),
        }
    }
}

impl AsRef<[u8]> for DynOutput {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl DynHash {
    /// Starts a new computation of `alg`.
    #[must_use]
    pub fn new(alg: HashAlgorithm) -> Self {
        match alg {
            HashAlgorithm::Sha224 => Self::Sha224(Sha224::new()),
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
            HashAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
            HashAlgorithm::Sha3_256 => Self::Sha3_256(Sha3_256::new()),
            HashAlgorithm::Sha3_384 => Self::Sha3_384(Sha3_384::new()),
            HashAlgorithm::Sha3_512 => Self::Sha3_512(Sha3_512::new()),
        }
    }

    /// The algorithm being computed.
    #[must_use]
    pub fn algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Sha224(_) => HashAlgorithm::Sha224,
            Self::Sha256(_) => HashAlgorithm::Sha256,
            Self::Sha384(_) => HashAlgorithm::Sha384,
            Self::Sha512(_) => HashAlgorithm::Sha512,
            Self::Sha3_256(_) => HashAlgorithm::Sha3_256,
            Self::Sha3_384(_) => HashAlgorithm::Sha3_384,
            Self::Sha3_512(_) => HashAlgorithm::Sha3_512,
        }
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha224(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
            Self::Sha3_256(h) => h.update(data),
            Self::Sha3_384(h) => h.update(data),
            Self::Sha3_512(h) => h.update(data),
        }
    }

    /// Completes the computation.
    #[must_use]
    pub fn finalize(self) -> DynOutput {
        match self {
            Self::Sha224(h) => DynOutput::new(&h.finalize()),
            Self::Sha256(h) => DynOutput::new(&h.finalize()),
            Self::Sha384(h) => DynOutput::new(&h.finalize()),
            Self::Sha512(h) => DynOutput::new(&h.finalize()),
            Self::Sha3_256(h) => DynOutput::new(&h.finalize()),
            Self::Sha3_384(h) => DynOutput::new(&h.finalize()),
            Self::Sha3_512(h) => DynOutput::new(&h.finalize()),
        }
    }

    /// Hashes `data` in one call.
    #[must_use]
    pub fn digest(alg: HashAlgorithm, data: &[u8]) -> DynOutput {
        let mut h = Self::new(alg);
        h.update(data);
        h.finalize()
    }
}

/// Shared Merkle–Damgård block buffering for the SHA-2 family.
#[derive(Clone)]
pub(crate) struct BlockBuffer<const B: usize> {
    pub(crate) buf: [u8; B],
    pub(crate) len: usize,
}

impl<const B: usize> Default for BlockBuffer<B> {
    fn default() -> Self {
        Self {
            buf: [0; B],
            len: 0,
        }
    }
}

impl<const B: usize> BlockBuffer<B> {
    /// Feeds `data`, invoking `compress` on runs of complete blocks
    /// (`blocks.len()` is always a multiple of `B`).
    #[inline]
    pub(crate) fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8])) {
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
        let full = data.len() - data.len() % B;
        if full > 0 {
            compress(&data[..full]);
        }
        let rest = &data[full..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }
}
