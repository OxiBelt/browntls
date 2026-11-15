//! zlib (RFC 1950) certificate compression, backed by `miniz_oxide`.

use alloc::boxed::Box;
use alloc::vec::Vec;

use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::{
    TINFL_FLAG_PARSE_ZLIB_HEADER, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
};
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

use super::{
    CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel, DecompressionFailed,
    smaller_than,
};
use crate::enums::CertificateCompressionAlgorithm;

/// zlib certificate compression and decompression (RFC 8879 §3, algorithm 1).
///
/// Decompression verifies the Adler-32 trailer and fails on a stream that is
/// truncated, longer than the caller's buffer, or followed by further bytes.
/// The caller's buffer is the back-reference window; the only other memory
/// is the decoder state, of a fixed size (about 11 KiB).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Zlib;

/// The zlib compressor and decompressor.
pub static ZLIB: Zlib = Zlib;

impl CertDecompressor for Zlib {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let mut state = Box::<DecompressorOxide>::default();
        // All of the input is present (no "has more input" flag), and the
        // output buffer is the whole output, so the back-reference window is
        // the buffer itself and nothing else is allocated.
        let (status, consumed, written) = decompress(
            &mut state,
            input,
            output,
            0,
            TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        match status {
            TINFLStatus::Done if consumed == input.len() && written == output.len() => Ok(()),
            _ => Err(DecompressionFailed),
        }
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

impl CertCompressor for Zlib {
    fn compress(
        &self,
        input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        let level = match level {
            CompressionLevel::Interactive => 3,
            CompressionLevel::Amortized => 9,
        };
        smaller_than(&input, compress_to_vec_zlib(&input, level))
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}
