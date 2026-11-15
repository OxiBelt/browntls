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

/// The largest window a received frame may declare: 128 KiB, the block size
/// limit of the format.
///
/// The decoder allocates the window when it reads the frame header and
/// releases no output until it holds more than a window, so the window is
/// what a frame can make it hold whatever the expected length. Certificate
/// messages are at most 64 KiB: a one-shot encoder that knows the size
/// writes a single-segment frame, whose window is the content size, and the
/// built-in encoder declares 128 KiB. A streaming encoder that was not told
/// the size declares more (libzstd: at least 512 KiB) and is refused; RFC
/// 8878 §3.1.1.1.2 would have decoders accept up to 8 MiB, which is the
/// deviation this limit makes.
const MAX_WINDOW_SIZE: u64 = 128 * 1024;

/// Zstandard certificate compression and decompression (RFC 8879 §3,
/// algorithm 3).
///
/// Decompression accepts exactly one Zstandard frame without a dictionary:
/// no skippable frames, no second frame, no trailing bytes. A frame that
/// declares a content size other than the expected length, or a window above
/// 128 KiB, is refused before any block is decoded. Decoding then proceeds
/// block by block and stops once the decoder releases more than the expected
/// output.
///
/// The decoder works in its own buffer, not the caller's: besides the
/// expected output it holds at most the declared window plus one block
/// (128 KiB each) and its entropy tables. The content checksum, when
/// present, is not verified (the handshake transcript authenticates the
/// message).
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
        // Fails for a skippable frame, a dictionary ID or a window above the
        // limit; allocates the window otherwise.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame without a content size: `window_descriptor`, then `blocks`
    /// RLE blocks of 128 KiB each (four bytes apiece), the last one marked.
    fn rle_frame(window_descriptor: u8, blocks: u32) -> Vec<u8> {
        let mut frame = alloc::vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, window_descriptor];
        for i in 0..blocks {
            let last = u32::from(i + 1 == blocks);
            let header = (128 * 1024) << 3 | 1 << 1 | last;
            frame.extend_from_slice(&header.to_le_bytes()[..3]);
            frame.push(0x5a);
        }
        frame
    }

    /// A single-segment frame: the content size is declared and is the
    /// window; one raw block.
    fn single_segment_frame(content: &[u8]) -> Vec<u8> {
        let mut frame = alloc::vec![0x28, 0xb5, 0x2f, 0xfd];
        match content.len() {
            len @ 0..=255 => frame.extend_from_slice(&[0x20, len as u8]),
            len => {
                frame.push(0x60);
                frame.extend_from_slice(&((len - 256) as u16).to_le_bytes());
            }
        }
        let header = (content.len() as u32) << 3 | 1;
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(content);
        frame
    }

    #[test]
    fn frames_declaring_a_large_window_are_refused_unread() {
        // 8 MiB (exponent 13) filled by 64 blocks, in 262 bytes
        let bomb = rle_frame(13 << 3, 64);
        assert_eq!(bomb.len(), 262);
        // 256 KiB, the smallest window above the limit with this mantissa
        let just_over = rle_frame(8 << 3, 1);
        // 128 KiB + 1/8: the mantissa counts too
        let mantissa = rle_frame(7 << 3 | 1, 1);
        for frame in [&bomb, &just_over, &mantissa] {
            for len in [1, 1024, crate::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE] {
                let mut output = alloc::vec![0u8; len];
                assert_eq!(
                    ZSTD.decompress(frame, &mut output),
                    Err(DecompressionFailed)
                );
                // refused at the header: nothing was written
                assert!(output.iter().all(|b| *b == 0));
            }
        }
    }

    #[test]
    fn output_beyond_the_expected_length_stops_decoding() {
        // the largest accepted window, and far more blocks than fit
        let frame = rle_frame(7 << 3, 64);
        for len in [1, 1024, crate::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE] {
            let mut output = alloc::vec![0u8; len];
            assert_eq!(
                ZSTD.decompress(&frame, &mut output),
                Err(DecompressionFailed)
            );
        }
        // one block is 128 KiB, twice the largest expected length
        let frame = rle_frame(7 << 3, 1);
        let mut output = alloc::vec![0u8; crate::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE];
        assert_eq!(
            ZSTD.decompress(&frame, &mut output),
            Err(DecompressionFailed)
        );
    }

    #[test]
    fn single_segment_frames_declare_their_content_size() {
        for len in [1usize, 200, 255, 256, 5000, 65_535, 65_536] {
            let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let frame = single_segment_frame(&content);

            let mut output = alloc::vec![0u8; len];
            ZSTD.decompress(&frame, &mut output).unwrap();
            assert_eq!(output, content, "{len} bytes");

            // the declared size must be the expected length, either way
            for wrong in [len - 1, len + 1] {
                if wrong == 0 {
                    continue;
                }
                let mut output = alloc::vec![0u8; wrong];
                assert_eq!(
                    ZSTD.decompress(&frame, &mut output),
                    Err(DecompressionFailed),
                    "{len} bytes into {wrong}"
                );
                assert!(output.iter().all(|b| *b == 0));
            }

            // a frame that declares the expected length but holds less
            let mut short = single_segment_frame(&content[..len - 1]);
            match len {
                0..=255 => short[5] = len as u8,
                256 => continue, // the header form changes with the length
                _ => short[5..7].copy_from_slice(&((len - 256) as u16).to_le_bytes()),
            }
            let mut output = alloc::vec![0u8; len];
            assert_eq!(
                ZSTD.decompress(&short, &mut output),
                Err(DecompressionFailed)
            );
        }
    }

    #[test]
    fn the_built_in_encoder_stays_within_the_window_limit() {
        for len in [
            64usize,
            5000,
            crate::compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE,
        ] {
            let plain: Vec<u8> = (0..len).map(|i| b"certificate"[i % 11]).collect();
            let frame = ZSTD
                .compress(plain.clone(), CompressionLevel::Amortized)
                .unwrap();
            let mut output = alloc::vec![0u8; len];
            ZSTD.decompress(&frame, &mut output).unwrap();
            assert_eq!(output, plain);
        }
    }
}
