//! Certificate compression (RFC 8879).
//!
//! Integrators plug in implementations of [`CertCompressor`] and
//! [`CertDecompressor`]. The crate ships one pair per algorithm of RFC 8879,
//! each behind a Cargo feature and backed by a pure-Rust crate:
//!
//! | Feature | Item | Backing crate |
//! |---|---|---|
//! | `zlib` | `ZLIB` | `miniz_oxide` |
//! | `brotli` (needs `std`) | `BROTLI` | `brotli` |
//! | `zstd` | `ZSTD` | `ruzstd` |
//!
//! An enabled algorithm is part of [`default_cert_compressors`] and
//! [`default_cert_decompressors`], which new configurations start with. With
//! no such feature and nothing configured, the extension is neither offered
//! nor accepted.
//!
//! # Limits on received messages
//!
//! A `CompressedCertificate` is expanded only when its declared
//! `uncompressed_length` is non-zero and no larger than both
//! [`MAX_DECOMPRESSED_CERTIFICATE_SIZE`] and the configuration's
//! `cert_decompression_limit`; the output buffer has exactly that length, the
//! decompressor must fill it exactly, and anything else ends the handshake
//! with `bad_certificate` (RFC 8879 §4). The built-in decompressors write
//! into that buffer only and also reject trailing input.

use alloc::vec::Vec;
use core::fmt::Debug;

use crate::common_state::CommonState;
use crate::enums::{AlertDescription, CertificateCompressionAlgorithm};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::codec::Codec;
use crate::msgs::handshake::{
    CertificatePayloadTls13, CompressedCertificatePayload, MAX_CERTIFICATE_SIZE_LIMIT,
};

#[cfg(feature = "brotli")]
mod brotli;
#[cfg(feature = "zlib")]
mod zlib;
#[cfg(feature = "zstd")]
mod zstd;

#[cfg(feature = "brotli")]
pub use self::brotli::{BROTLI, Brotli};
#[cfg(feature = "zlib")]
pub use self::zlib::{ZLIB, Zlib};
#[cfg(feature = "zstd")]
pub use self::zstd::{ZSTD, Zstd};

/// The largest `uncompressed_length` ever accepted, whatever a configuration
/// allows: the size limit of an uncompressed Certificate message (64 KiB).
pub const MAX_DECOMPRESSED_CERTIFICATE_SIZE: usize = MAX_CERTIFICATE_SIZE_LIMIT;

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

/// The compressors enabled by default, in preference order: Brotli, zlib,
/// then Zstandard, each present when its Cargo feature is enabled.
///
/// Zstandard comes last because the built-in encoder has a single, fast
/// level.
pub fn default_cert_compressors() -> &'static [&'static dyn CertCompressor] {
    DEFAULT_COMPRESSORS
}

static DEFAULT_COMPRESSORS: &[&dyn CertCompressor] = &[
    #[cfg(feature = "brotli")]
    &BROTLI,
    #[cfg(feature = "zlib")]
    &ZLIB,
    #[cfg(feature = "zstd")]
    &ZSTD,
];

/// The decompressors enabled by default, in the order they are offered:
/// Brotli, zlib, then Zstandard, each present when its Cargo feature is
/// enabled.
pub fn default_cert_decompressors() -> &'static [&'static dyn CertDecompressor] {
    DEFAULT_DECOMPRESSORS
}

static DEFAULT_DECOMPRESSORS: &[&dyn CertDecompressor] = &[
    #[cfg(feature = "brotli")]
    &BROTLI,
    #[cfg(feature = "zlib")]
    &ZLIB,
    #[cfg(feature = "zstd")]
    &ZSTD,
];

/// Returns `compressed` when it is shorter than `input`; a compressor that
/// would not shrink the message reports failure and the message goes out
/// uncompressed.
#[cfg(any(feature = "zlib", feature = "brotli", feature = "zstd"))]
fn smaller_than(input: &[u8], compressed: Vec<u8>) -> Result<Vec<u8>, CompressionFailed> {
    if compressed.len() < input.len() {
        Ok(compressed)
    } else {
        Err(CompressionFailed)
    }
}

/// Why a received `CompressedCertificate` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertDecompressionError {
    /// The algorithm is not one we offered (`illegal_parameter`).
    UnofferedAlgorithm,
    /// The declared length is zero or over a limit, or the data does not
    /// expand to exactly that length (`bad_certificate`).
    Invalid,
}

/// Expands a received `CompressedCertificate` (RFC 8879 §4) into the encoded
/// Certificate message body.
///
/// `limit` is the configured maximum; [`MAX_DECOMPRESSED_CERTIFICATE_SIZE`]
/// applies as well. The output buffer is allocated once, at the declared
/// length, and only after that length passed both limits.
pub(crate) fn decompress_certificate(
    decompressors: &[&'static dyn CertDecompressor],
    limit: usize,
    compressed: &CompressedCertificatePayload<'_>,
) -> Result<Vec<u8>, CertDecompressionError> {
    let decompressor = decompressors
        .iter()
        .find(|d| d.algorithm() == compressed.alg)
        .ok_or(CertDecompressionError::UnofferedAlgorithm)?;
    let len = usize::try_from(compressed.uncompressed_len)
        .map_err(|_| CertDecompressionError::Invalid)?;
    if len == 0 || len > limit.min(MAX_DECOMPRESSED_CERTIFICATE_SIZE) {
        return Err(CertDecompressionError::Invalid);
    }
    let mut output = alloc::vec![0u8; len];
    decompressor
        .decompress(compressed.compressed.0.bytes(), &mut output)
        .map_err(|_| CertDecompressionError::Invalid)?;
    Ok(output)
}

/// Expands a received `CompressedCertificate` and parses the Certificate
/// message inside, sending the alert RFC 8879 §4 requires on failure.
pub(crate) fn receive_compressed_certificate(
    common: &mut CommonState,
    decompressors: &[&'static dyn CertDecompressor],
    limit: usize,
    compressed: &CompressedCertificatePayload<'_>,
) -> Result<CertificatePayloadTls13<'static>, Error> {
    let body = match decompress_certificate(decompressors, limit, compressed) {
        Ok(body) => body,
        Err(CertDecompressionError::UnofferedAlgorithm) => {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedCertCompression,
            ));
        }
        Err(CertDecompressionError::Invalid) => {
            return Err(common.send_fatal_alert(
                AlertDescription::BadCertificate,
                PeerMisbehaved::InvalidCertCompression,
            ));
        }
    };
    CertificatePayloadTls13::read_bytes(&body)
        .map(CertificatePayloadTls13::into_owned)
        .map_err(|_| {
            common.send_fatal_alert(
                AlertDescription::BadCertificate,
                PeerMisbehaved::InvalidCertCompression,
            )
        })
}

/// Compresses an encoded Certificate message body with the first of
/// `compressors` that `offered` contains. `None` means the message is sent
/// uncompressed: nothing in common, or the compressor failed.
pub(crate) fn compress_certificate(
    compressors: &[&'static dyn CertCompressor],
    cache: &CompressionCache,
    offered: &[CertificateCompressionAlgorithm],
    encoded: &[u8],
) -> Option<CompressedCertificatePayload<'static>> {
    let compressor = compressors
        .iter()
        .find(|c| offered.contains(&c.algorithm()))?;
    let uncompressed_len = u32::try_from(encoded.len()).ok()?;
    let compressed = cache.compression_for(*compressor, encoded).ok()?;
    Some(CompressedCertificatePayload {
        alg: compressor.algorithm(),
        uncompressed_len,
        compressed: crate::msgs::base::PayloadU24(crate::msgs::base::Payload::new(compressed)),
    })
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
    use crate::msgs::base::{Payload, PayloadU24};

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
    }

    #[test]
    fn defaults_follow_features() {
        let expected: &[CertificateCompressionAlgorithm] = &[
            #[cfg(feature = "brotli")]
            CertificateCompressionAlgorithm::Brotli,
            #[cfg(feature = "zlib")]
            CertificateCompressionAlgorithm::Zlib,
            #[cfg(feature = "zstd")]
            CertificateCompressionAlgorithm::Zstd,
        ];
        let compressors: Vec<_> = default_cert_compressors()
            .iter()
            .map(|c| c.algorithm())
            .collect();
        let decompressors: Vec<_> = default_cert_decompressors()
            .iter()
            .map(|d| d.algorithm())
            .collect();
        assert_eq!(compressors, expected);
        assert_eq!(decompressors, expected);
    }

    #[test]
    fn unoffered_algorithm_is_refused() {
        let payload = CompressedCertificatePayload {
            alg: CertificateCompressionAlgorithm::Zlib,
            uncompressed_len: 4,
            compressed: PayloadU24(Payload::Borrowed(&[1, 2, 3, 4])),
        };
        assert_eq!(
            decompress_certificate(&[], 1024, &payload),
            Err(CertDecompressionError::UnofferedAlgorithm)
        );
    }

    /// A decompressor that records the buffer length it was handed.
    #[derive(Debug)]
    struct Probe(core::sync::atomic::AtomicUsize);

    impl CertDecompressor for Probe {
        fn decompress(&self, _input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
            self.0
                .store(output.len(), core::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }

    #[test]
    fn declared_length_is_bounded_before_decompression() {
        static PROBE: Probe = Probe(core::sync::atomic::AtomicUsize::new(usize::MAX));
        let called = || PROBE.0.load(core::sync::atomic::Ordering::SeqCst);
        let payload = |uncompressed_len| CompressedCertificatePayload {
            alg: CertificateCompressionAlgorithm::Zlib,
            uncompressed_len,
            compressed: PayloadU24(Payload::Borrowed(&[0])),
        };
        let hard = u32::try_from(MAX_DECOMPRESSED_CERTIFICATE_SIZE).unwrap();

        // zero, over the configured limit, over the hard cap whatever the
        // configured limit: refused without calling the decompressor
        for (limit, len) in [
            (1024, 0),
            (1024, 1025),
            (usize::MAX, hard + 1),
            (usize::MAX, 0x00ff_ffff),
            (0, 1),
        ] {
            assert_eq!(
                decompress_certificate(&[&PROBE], limit, &payload(len)),
                Err(CertDecompressionError::Invalid),
                "limit {limit} len {len}"
            );
            assert_eq!(called(), usize::MAX);
        }

        // at a limit: the buffer has exactly the declared length
        assert_eq!(
            decompress_certificate(&[&PROBE], 1024, &payload(1024))
                .unwrap()
                .len(),
            1024
        );
        assert_eq!(called(), 1024);
        assert_eq!(
            decompress_certificate(&[&PROBE], usize::MAX, &payload(hard))
                .unwrap()
                .len(),
            MAX_DECOMPRESSED_CERTIFICATE_SIZE
        );
    }

    /// Something certificate-like: structured, moderately redundant.
    #[cfg(any(feature = "zlib", feature = "brotli", feature = "zstd"))]
    fn sample(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        (0..len)
            .map(|i| {
                if i % 16 != 0 {
                    b"browntls test certificate "[i % 26]
                } else {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[0]
                }
            })
            .collect()
    }

    #[cfg(any(feature = "zlib", feature = "brotli", feature = "zstd"))]
    fn check_builtin(compressor: &dyn CertCompressor, decompressor: &dyn CertDecompressor) {
        assert_eq!(compressor.algorithm(), decompressor.algorithm());

        for len in [64, 1500, 5000, MAX_DECOMPRESSED_CERTIFICATE_SIZE] {
            let plain = sample(len);
            for level in [CompressionLevel::Interactive, CompressionLevel::Amortized] {
                let compressed = compressor.compress(plain.clone(), level).unwrap();
                assert!(compressed.len() < plain.len());

                // exact length: round trip
                let mut output = alloc::vec![0u8; len];
                decompressor.decompress(&compressed, &mut output).unwrap();
                assert_eq!(output, plain);

                // RFC 8879 §4: any other declared length fails, whether the
                // data would overflow the buffer or leave it short
                for wrong in [1, len - 1, len + 1, len * 2] {
                    let mut output = alloc::vec![0u8; wrong];
                    assert_eq!(
                        decompressor.decompress(&compressed, &mut output),
                        Err(DecompressionFailed),
                        "{len} bytes into {wrong}"
                    );
                }

                // truncated, extended and corrupted input fails
                let mut output = alloc::vec![0u8; len];
                for cut in [0, 1, compressed.len() / 2, compressed.len() - 1] {
                    assert_eq!(
                        decompressor.decompress(&compressed[..cut], &mut output),
                        Err(DecompressionFailed)
                    );
                }
                let mut extended = compressed.clone();
                extended.push(0);
                assert_eq!(
                    decompressor.decompress(&extended, &mut output),
                    Err(DecompressionFailed)
                );
                let mut doubled = compressed.clone();
                doubled.extend_from_slice(&compressed);
                assert_eq!(
                    decompressor.decompress(&doubled, &mut output),
                    Err(DecompressionFailed)
                );
            }
        }

        // incompressible input is reported as a failure, so the caller
        // sends the message uncompressed
        assert_eq!(
            compressor.compress(alloc::vec![0x5a], CompressionLevel::Amortized),
            Err(CompressionFailed)
        );

        // highly compressible data far beyond the buffer: refused, and the
        // buffer is all the output there is
        let bomb = compressor
            .compress(alloc::vec![0u8; 4 << 20], CompressionLevel::Interactive)
            .unwrap();
        assert!(bomb.len() < 64 << 10);
        for len in [1, 1024, MAX_DECOMPRESSED_CERTIFICATE_SIZE] {
            let mut output = alloc::vec![0u8; len];
            assert_eq!(
                decompressor.decompress(&bomb, &mut output),
                Err(DecompressionFailed)
            );
        }

        // through the message-level entry point, with both limits
        let plain = sample(3000);
        let compressed = compressor
            .compress(plain.clone(), CompressionLevel::Amortized)
            .unwrap();
        let payload = |uncompressed_len| CompressedCertificatePayload {
            alg: compressor.algorithm(),
            uncompressed_len,
            compressed: PayloadU24(Payload::new(compressed.clone())),
        };
        struct Leak;
        impl Leak {
            fn of(d: &dyn CertDecompressor) -> &'static dyn CertDecompressor {
                // the built-ins are unit structs behind statics
                match d.algorithm() {
                    #[cfg(feature = "zlib")]
                    CertificateCompressionAlgorithm::Zlib => &ZLIB,
                    #[cfg(feature = "brotli")]
                    CertificateCompressionAlgorithm::Brotli => &BROTLI,
                    #[cfg(feature = "zstd")]
                    CertificateCompressionAlgorithm::Zstd => &ZSTD,
                    other => panic!("no built-in for {other:?}"),
                }
            }
        }
        let list = [Leak::of(decompressor)];
        assert_eq!(
            decompress_certificate(&list, 3000, &payload(3000)).unwrap(),
            plain
        );
        for (limit, len) in [(2999, 3000), (3000, 2999), (usize::MAX, 3001), (0, 3000)] {
            assert_eq!(
                decompress_certificate(&list, limit, &payload(len)),
                Err(CertDecompressionError::Invalid)
            );
        }
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn zlib_builtin() {
        check_builtin(&ZLIB, &ZLIB);
        // a raw DEFLATE stream (no zlib header) is not zlib
        let raw = miniz_oxide::deflate::compress_to_vec(&sample(1500), 6);
        let mut output = alloc::vec![0u8; 1500];
        assert_eq!(ZLIB.decompress(&raw, &mut output), Err(DecompressionFailed));
        // a wrong Adler-32 trailer fails
        let mut bad = ZLIB
            .compress(sample(1500), CompressionLevel::Interactive)
            .unwrap();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(ZLIB.decompress(&bad, &mut output), Err(DecompressionFailed));
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn brotli_builtin() {
        check_builtin(&BROTLI, &BROTLI);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_builtin() {
        check_builtin(&ZSTD, &ZSTD);

        let mut output = alloc::vec![0u8; 1500];
        // a skippable frame before the data is refused
        let mut skippable = alloc::vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        skippable.extend(
            ZSTD.compress(sample(1500), CompressionLevel::Interactive)
                .unwrap(),
        );
        assert_eq!(
            ZSTD.decompress(&skippable, &mut output),
            Err(DecompressionFailed)
        );
        // a frame declaring a 1 GiB window is refused: magic, descriptor
        // (no single segment, no content size), window descriptor
        // (exponent 20), then an empty last raw block
        let huge_window = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xa0, 0x01, 0x00, 0x00];
        assert_eq!(
            ZSTD.decompress(&huge_window, &mut output),
            Err(DecompressionFailed)
        );
    }
}
