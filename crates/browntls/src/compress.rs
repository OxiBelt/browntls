//! Certificate compression (RFC 8879).
//!
//! The library ships no compression algorithm; integrators plug in
//! implementations of [`CertCompressor`] and [`CertDecompressor`]. With
//! none configured, the extension is neither offered nor accepted.

use alloc::vec::Vec;
use core::fmt::Debug;

use crate::enums::CertificateCompressionAlgorithm;

/// Decompresses a received `CompressedCertificate`.
pub trait CertDecompressor: Debug + Send + Sync {
    /// Decompresses `input` into `output`, which is exactly the declared
    /// uncompressed length; fails unless `output` is filled completely.
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed>;

    /// The algorithm implemented.
    fn algorithm(&self) -> CertificateCompressionAlgorithm;
}

/// Compresses a `Certificate` message for sending.
pub trait CertCompressor: Debug + Send + Sync {
    /// Compresses `input` at `level`.
    fn compress(
        &self,
        input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed>;

    /// The algorithm implemented.
    fn algorithm(&self) -> CertificateCompressionAlgorithm;
}

/// How hard a compressor should try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// Compress quickly; used for per-connection, uncacheable payloads.
    Interactive,
    /// Compress thoroughly; used when the result is cached and reused.
    Amortized,
}

/// A decompressor could not reproduce the declared output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompressionFailed;

/// A compressor failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionFailed;

/// The compressors enabled by default: none.
pub fn default_cert_compressors() -> &'static [&'static dyn CertCompressor] {
    &[]
}

/// The decompressors enabled by default: none.
pub fn default_cert_decompressors() -> &'static [&'static dyn CertDecompressor] {
    &[]
}

/// Caches compressed certificate messages so a server does not recompress
/// the same chain for every connection.
#[derive(Debug, Default)]
pub struct CompressionCache {
    #[cfg(feature = "std")]
    entries: std::sync::Mutex<Vec<CacheEntry>>,
}

#[cfg(feature = "std")]
#[derive(Debug)]
struct CacheEntry {
    algorithm: CertificateCompressionAlgorithm,
    original: Vec<u8>,
    compressed: Vec<u8>,
}

/// At most this many distinct (algorithm, message) pairs are cached.
#[cfg(feature = "std")]
const MAX_CACHE_ENTRIES: usize = 4;

impl CompressionCache {
    /// Returns a cached compression of `original`, or compresses, caches and
    /// returns it. Without `std` nothing is cached.
    pub(crate) fn compression_for(
        &self,
        compressor: &dyn CertCompressor,
        original: &[u8],
    ) -> Result<Vec<u8>, CompressionFailed> {
        #[cfg(feature = "std")]
        {
            if let Ok(entries) = self.entries.lock()
                && let Some(hit) = entries
                    .iter()
                    .find(|e| e.algorithm == compressor.algorithm() && e.original == original)
            {
                return Ok(hit.compressed.clone());
            }
            let compressed = compressor.compress(original.to_vec(), CompressionLevel::Amortized)?;
            if let Ok(mut entries) = self.entries.lock() {
                if entries.len() >= MAX_CACHE_ENTRIES {
                    entries.remove(0);
                }
                entries.push(CacheEntry {
                    algorithm: compressor.algorithm(),
                    original: original.to_vec(),
                    compressed: compressed.clone(),
                });
            }
            Ok(compressed)
        }
        #[cfg(not(feature = "std"))]
        {
            compressor.compress(original.to_vec(), CompressionLevel::Interactive)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Reverse;

    impl CertCompressor for Reverse {
        fn compress(
            &self,
            mut input: Vec<u8>,
            _level: CompressionLevel,
        ) -> Result<Vec<u8>, CompressionFailed> {
            input.reverse();
            Ok(input)
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }

    #[test]
    fn cache_reuses_result() {
        let cache = CompressionCache::default();
        let a = cache.compression_for(&Reverse, &[1, 2, 3]).unwrap();
        assert_eq!(a, [3, 2, 1]);
        let b = cache.compression_for(&Reverse, &[1, 2, 3]).unwrap();
        assert_eq!(a, b);
        for i in 0..10u8 {
            cache.compression_for(&Reverse, &[i]).unwrap();
        }
        assert!(default_cert_compressors().is_empty());
        assert!(default_cert_decompressors().is_empty());
    }
}
