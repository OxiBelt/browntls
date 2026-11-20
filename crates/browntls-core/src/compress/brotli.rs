//! Brotli (RFC 7932) certificate compression, backed by the `brotli` crate.

use alloc::vec::Vec;

use brotli::enc::BrotliEncoderParams;
use brotli::{
    Allocator, BrotliCompress, BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc,
    HuffmanCode,
};

use super::{
    CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel, DecompressionFailed,
    smaller_than,
};
use crate::enums::CertificateCompressionAlgorithm;

/// Brotli certificate compression and decompression (RFC 8879 §3, algorithm 2).
///
/// Decompression fails on a stream that is truncated, longer than the
/// caller's buffer, or followed by further bytes. Large-window streams
/// (beyond RFC 7932) are refused.
///
/// The decoder keeps its own sliding window besides the caller's buffer, and
/// sizes it from what the stream declares. Its byte allocations go through
/// an allocator that refuses any request larger than a stream producing the
/// expected output can need (that length rounded up to a power of two, at
/// least 16 KiB, plus 1 KiB), so a stream
/// that announces megabytes fails before that memory exists. What remains
/// is bounded by the format: the window, at most the expected length rounded
/// up to a power of two, and the prefix code tables, at most 256 per
/// category whatever the output length.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Brotli;

/// The Brotli compressor and decompressor.
pub static BROTLI: Brotli = Brotli;

impl CertDecompressor for Brotli {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        decompress(input, output).0
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Brotli
    }
}

/// The largest single byte allocation the decoder may make for an output of
/// `output_len` bytes.
///
/// The decoder's sliding window grows with the data: for a stream whose
/// total output is `output_len` it never exceeds that length rounded up to a
/// power of two (and at least 1 KiB), plus a fixed write-ahead margin below
/// 1 KiB. Its other byte allocations are context maps, at most 64 bytes for
/// each of at most 256 block types (16 KiB). Anything larger can only come
/// from a stream that declares more output than expected.
fn byte_allocation_limit(output_len: usize) -> usize {
    output_len
        .checked_next_power_of_two()
        .unwrap_or(usize::MAX)
        .max(16 * 1024)
        .saturating_add(1024)
}

/// A byte allocator that hands out nothing above a limit; the decoder
/// reports a failed allocation as a decoding error. It also records the
/// most bytes it had outstanding.
struct LimitedAlloc {
    inner: HeapAlloc<u8>,
    limit: usize,
    live: usize,
    peak: usize,
}

impl Allocator<u8> for LimitedAlloc {
    type AllocatedMemory = <HeapAlloc<u8> as Allocator<u8>>::AllocatedMemory;

    fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
        if len > self.limit {
            // The empty cell is what a failed allocation looks like.
            return Self::AllocatedMemory::default();
        }
        self.live = self.live.saturating_add(len);
        self.peak = self.peak.max(self.live);
        self.inner.alloc_cell(len)
    }

    fn free_cell(&mut self, data: Self::AllocatedMemory) {
        self.live = self
            .live
            .saturating_sub(brotli::SliceWrapper::slice(&data).len());
        self.inner.free_cell(data);
    }
}

/// Decompresses `input` into exactly `output`; also returns the most bytes
/// the decoder's byte allocator had outstanding.
fn decompress(input: &[u8], output: &mut [u8]) -> (Result<(), DecompressionFailed>, usize) {
    // `new_strict` keeps RFC 7932 window sizes (at most 2^24 - 16).
    let mut state = BrotliState::new_strict(
        LimitedAlloc {
            inner: HeapAlloc::<u8>::new(0),
            limit: byte_allocation_limit(output.len()),
            live: 0,
            peak: 0,
        },
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
    let result = match result {
        BrotliResult::ResultSuccess if available_in == 0 && available_out == 0 => Ok(()),
        _ => Err(DecompressionFailed),
    };
    (result, state.alloc_u8.peak)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream of a few bytes that announces 16 MiB: the largest window
    /// (WBITS 24), then a meta-block that is not the last, uncompressed,
    /// with MLEN 2^24, of which only ten bytes are present.
    const ANNOUNCES_16_MIB: [u8; 14] = [0xcf, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    #[test]
    fn a_declared_window_is_not_allocated() {
        for len in [
            1,
            10,
            1024,
            crate::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE,
        ] {
            let mut output = alloc::vec![0u8; len];
            let (result, peak) = decompress(&ANNOUNCES_16_MIB, &mut output);
            assert_eq!(result, Err(DecompressionFailed));
            // nothing was allocated for it at all
            assert_eq!(peak, 0, "output of {len} bytes");
        }
    }

    #[test]
    fn honest_streams_fit_the_allocation_limit() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for len in [
            1usize,
            2,
            100,
            1023,
            1024,
            1025,
            4096,
            20_000,
            65_535,
            crate::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE,
        ] {
            // half text, half noise, so that every quality has work to do
            let plain: Vec<u8> = (0..len)
                .map(|i| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    if i % 2 == 0 {
                        b"certificate"[i % 11]
                    } else {
                        state.to_le_bytes()[0] & 0x3f
                    }
                })
                .collect();
            for quality in [0, 1, 4, 9, 11] {
                for lgwin in [10, 16, 22, 24] {
                    let params = BrotliEncoderParams {
                        quality,
                        lgwin,
                        ..Default::default()
                    };
                    let mut compressed = Vec::new();
                    BrotliCompress(&mut plain.as_slice(), &mut compressed, &params).unwrap();
                    let mut output = alloc::vec![0u8; len];
                    let (result, peak) = decompress(&compressed, &mut output);
                    assert_eq!(result, Ok(()), "{len} bytes, q{quality}, lgwin {lgwin}");
                    assert_eq!(output, plain);
                    // window plus context maps, never the declared 2^lgwin
                    assert!(
                        peak <= 2 * byte_allocation_limit(len),
                        "{len} bytes, q{quality}, lgwin {lgwin}: {peak}"
                    );
                }
            }
        }
    }
}
