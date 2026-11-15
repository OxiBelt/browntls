//! Brotli (RFC 7932) certificate compression, backed by the `brotli` crate.

use alloc::vec::Vec;

use brotli::enc::BrotliEncoderParams;
use brotli::{
    BrotliCompress, BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc, HuffmanCode,
};

use super::{
    CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel, DecompressionFailed,
    smaller_than,
};
use crate::enums::CertificateCompressionAlgorithm;

/// Brotli certificate compression and decompression (RFC 8879 §3, algorithm 2).
///
/// Decompression writes into the caller's buffer only and fails on a stream
/// that is truncated, longer than the buffer, or followed by further bytes.
/// Large-window streams (beyond RFC 7932) are refused, which bounds the
/// decoder's own sliding window at 16 MiB whatever the stream declares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Brotli;

/// The Brotli compressor and decompressor.
pub static BROTLI: Brotli = Brotli;

impl CertDecompressor for Brotli {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        // `new_strict` keeps RFC 7932 window sizes (at most 2^24 - 16).
        let mut state = BrotliState::new_strict(
            HeapAlloc::<u8>::new(0),
            HeapAlloc::<u32>::new(0),
            HeapAlloc::<HuffmanCode>::new(HuffmanCode::default()),
        );
        let (mut available_in, mut input_offset) = (input.len(), 0);
        let (mut available_out, mut output_offset) = (output.len(), 0);
        let mut total_out = 0;
        // One call suffices: the whole input and the whole output are
        // present, so anything but success means a bad or oversized stream.
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            input,
            &mut available_out,
            &mut output_offset,
            output,
            &mut total_out,
            &mut state,
        );
        match result {
            BrotliResult::ResultSuccess if available_in == 0 && available_out == 0 => Ok(()),
            _ => Err(DecompressionFailed),
        }
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Brotli
    }
}

impl CertCompressor for Brotli {
    fn compress(
        &self,
        input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        let params = BrotliEncoderParams {
            quality: match level {
                CompressionLevel::Interactive => 4,
                CompressionLevel::Amortized => 11,
            },
            size_hint: input.len(),
            ..Default::default()
        };
        let mut output = Vec::with_capacity(input.len() / 2);
        BrotliCompress(&mut input.as_slice(), &mut output, &params)
            .map_err(|_| CompressionFailed)?;
        smaller_than(&input, output)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Brotli
    }
}
