//! Zstandard (RFC 8878) certificate compression, backed by `ruzstd`.

use alloc::vec::Vec;

use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use ruzstd::encoding::{CompressionLevel as ZstdLevel, compress_to_vec};
use ruzstd::io::Read;

use super::{
    CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel, DecompressionFailed,
    smaller_than,
};
use crate::enums::CertificateCompressionAlgorithm;

/// The largest window a received frame may declare: the 8 MiB that RFC 8878
/// §3.1.1.1.2 recommends decoders support. The decoder keeps up to one
/// window of output before releasing any, so this also bounds what a frame
/// can make it hold.
const MAX_WINDOW_SIZE: u64 = 8 * 1024 * 1024;

/// Zstandard certificate compression and decompression (RFC 8879 §3,
/// algorithm 3).
///
/// Decompression accepts exactly one Zstandard frame without a dictionary:
/// no skippable frames, no second frame, no trailing bytes. A frame that
/// declares a content size other than the expected length, or a window above
/// 8 MiB, is refused before any block is decoded. Decoding proceeds block by
/// block and stops once the decoder releases more than the expected output,
/// which it does for whatever exceeds the declared window: a hostile frame
/// costs at most one window plus one block (128 KiB) of memory. The content
/// checksum, when present, is not verified (the handshake transcript
/// authenticates the message).
///
/// Compression uses the one level `ruzstd` implements (comparable to zstd
/// level 1) for both [`CompressionLevel`]s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Zstd;

/// The Zstandard compressor and decompressor.
pub static ZSTD: Zstd = Zstd;

impl CertDecompressor for Zstd {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let mut source = input;
        let mut decoder = FrameDecoder::new();
        decoder.set_max_window_size(MAX_WINDOW_SIZE);
        // Fails for a skippable frame, a dictionary ID or a large window.
        decoder.init(&mut source).map_err(|_| DecompressionFailed)?;
        // Zero means "not declared" here; the expected length is never zero.
        let declared = decoder.content_size();
        if declared != 0 && usize::try_from(declared) != Ok(output.len()) {
            return Err(DecompressionFailed);
        }

        let mut filled = 0;
        loop {
            // One block yields at most 128 KiB.
            let finished = decoder
                .decode_blocks(&mut source, BlockDecodingStrategy::UptoBlocks(1))
                .map_err(|_| DecompressionFailed)?;
            // Until the frame ends, only output beyond the window can be
            // collected; whatever can be must still fit.
            if decoder.can_collect() > output.len() - filled {
                return Err(DecompressionFailed);
            }
            filled += decoder
                .read(&mut output[filled..])
                .map_err(|_| DecompressionFailed)?;
            if finished {
                break;
            }
        }
        if filled == output.len() && decoder.can_collect() == 0 && source.is_empty() {
            Ok(())
        } else {
            Err(DecompressionFailed)
        }
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}

impl CertCompressor for Zstd {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        smaller_than(
            &input,
            compress_to_vec(input.as_slice(), ZstdLevel::Fastest),
        )
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}
