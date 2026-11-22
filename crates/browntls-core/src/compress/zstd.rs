//! Zstandard (RFC 8878) certificate compression, backed by `ruzstd`.

mod frame;

use alloc::vec::Vec;

use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use ruzstd::encoding::{CompressionLevel as ZstdLevel, compress_to_vec};
use ruzstd::io::Read;

use super::{
    CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel, DecompressionFailed,
    smaller_than,
};
use crate::enums::CertificateCompressionAlgorithm;

const DEFAULT_MAX_FRAME_WINDOW: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_HISTORY_WINDOW: usize = 128 * 1024;
const MAX_DECODER_WINDOW: usize = 128 * 1024;
const MAX_FRAMES: usize = 64;

/// Resource limits for Zstandard frame decoding.
///
/// The advertised frame window is checked before decoding. The decoder's
/// history allocation is separately capped; large non-single-segment windows
/// can be virtually clamped to 128 KiB only when the frame's maximum accepted
/// output fits in that amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZstdDecompressionLimits {
    max_frame_window: usize,
    max_history_window: usize,
}

impl ZstdDecompressionLimits {
    /// Creates limits in bytes. Zero limits are invalid; all other `usize`
    /// values are accepted. The advertised-window limit is compared with the
    /// parsed frame window. Decoder history is clamped to 128 KiB because that
    /// is ruzstd's configured maximum for this adapter; increasing it above
    /// that value does not increase allocation. Large advertised windows are
    /// accepted only under the bounded-output rule documented on [`Zstd`].
    pub const fn new(max_frame_window: usize, max_history_window: usize) -> Option<Self> {
        if max_frame_window == 0 || max_history_window == 0 {
            None
        } else {
            Some(Self {
                max_frame_window,
                max_history_window,
            })
        }
    }
}

impl Default for ZstdDecompressionLimits {
    fn default() -> Self {
        Self {
            max_frame_window: DEFAULT_MAX_FRAME_WINDOW,
            max_history_window: DEFAULT_MAX_HISTORY_WINDOW,
        }
    }
}

/// Zstandard certificate compression and decompression (RFC 8879 §3,
/// algorithm 3).
///
/// Decoding accepts up to 64 concatenated data frames, with no non-zero
/// dictionary ID, skippable frames, or trailing bytes. It verifies every
/// present content checksum. The default advertised window limit is 8 MiB;
/// ruzstd's history window and block scratch remain separately bounded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Zstd;

/// The Zstandard compressor and decompressor.
pub static ZSTD: Zstd = Zstd;

impl Zstd {
    /// Decompresses with explicit advertised-frame and decoder-history limits.
    ///
    /// The output slice is an independent hard bound and must be filled
    /// exactly. The frame header is checked before ruzstd initialization; each
    /// block's allocation-driving fields are checked before that block decodes.
    pub fn decompress_with_limits(
        &self,
        input: &[u8],
        output: &mut [u8],
        limits: ZstdDecompressionLimits,
    ) -> Result<(), DecompressionFailed> {
        if input.is_empty() {
            return Err(DecompressionFailed);
        }
        let max_frame_window = limits.max_frame_window as u64;
        let max_history_window = limits.max_history_window as u64;
        let effective_history = max_history_window.min(MAX_DECODER_WINDOW as u64);
        let mut input_offset = 0usize;
        let mut output_offset = 0usize;
        let mut frame_count = 0usize;

        while input_offset < input.len() {
            if frame_count == MAX_FRAMES {
                return Err(DecompressionFailed);
            }
            let frame = frame::parse(input, input_offset).ok_or(DecompressionFailed)?;
            if frame.window > max_frame_window {
                return Err(DecompressionFailed);
            }
            let remaining = output.len() - output_offset;
            if frame
                .content_size
                .is_some_and(|size| size > remaining as u64)
            {
                return Err(DecompressionFailed);
            }
            let output_bound = frame.content_size.map_or(remaining, |size| {
                usize::try_from(size).map_or(remaining, |size| remaining.min(size))
            });
            let frame_output_limit = output_offset
                .checked_add(output_bound)
                .ok_or(DecompressionFailed)?;
            let clamp = frame.window > effective_history;
            if clamp
                && (frame.window <= 128 * 1024
                    || effective_history < 128 * 1024
                    || output_bound > 128 * 1024)
            {
                return Err(DecompressionFailed);
            }

            let mut header = frame.header;
            if clamp {
                frame::clamp_large_window(&frame, &mut header);
            }
            let mut header_input = &header[..frame.header_len];
            let mut decoder = FrameDecoder::new();
            decoder.set_max_window_size(effective_history);
            decoder
                .init(&mut header_input)
                .map_err(|_| DecompressionFailed)?;
            if !header_input.is_empty() || decoder.content_size() != frame.content_size.unwrap_or(0)
            {
                return Err(DecompressionFailed);
            }

            let frame_output_start = output_offset;
            let mut source = &input[frame.body_start..];
            let max_block_size = usize::try_from(frame.window.min(MAX_DECODER_WINDOW as u64))
                .map_err(|_| DecompressionFailed)?;
            let mut block_offset = frame.body_start;
            loop {
                let block = frame::preflight_block(input, block_offset, max_block_size)
                    .ok_or(DecompressionFailed)?;
                if block.min_output > frame_output_limit - output_offset {
                    return Err(DecompressionFailed);
                }
                let input_before = source.len();
                let finished = decoder
                    .decode_blocks(&mut source, BlockDecodingStrategy::UptoBlocks(1))
                    .map_err(|_| DecompressionFailed)?;
                let consumed = input_before - source.len();
                let expected_consumed =
                    block.end - block_offset + usize::from(block.last && frame.checksum) * 4;
                if consumed != expected_consumed || finished != block.last {
                    return Err(DecompressionFailed);
                }
                let available = frame_output_limit - output_offset;
                if decoder.can_collect() > available {
                    return Err(DecompressionFailed);
                }
                output_offset += decoder
                    .read(&mut output[output_offset..frame_output_limit])
                    .map_err(|_| DecompressionFailed)?;
                if finished {
                    break;
                }
                block_offset = block.end;
            }
            // The final block releases all remaining history at once.
            if decoder.can_collect() != 0 {
                return Err(DecompressionFailed);
            }
            let frame_output_len = output_offset - frame_output_start;
            if frame
                .content_size
                .is_some_and(|size| size != frame_output_len as u64)
            {
                return Err(DecompressionFailed);
            }
            if frame.checksum {
                let frame_output = &output[frame_output_start..output_offset];
                let checksum = twox_hash::XxHash64::oneshot(0, frame_output) as u32;
                if decoder.get_checksum_from_data() != Some(checksum) {
                    return Err(DecompressionFailed);
                }
            }

            input_offset = input.len() - source.len();
            frame_count += 1;
        }

        if output_offset == output.len() {
            Ok(())
        } else {
            Err(DecompressionFailed)
        }
    }
}

impl CertDecompressor for Zstd {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        self.decompress_with_limits(input, output, ZstdDecompressionLimits::default())
    }

    fn decompress_with_zstd_limits(
        &self,
        input: &[u8],
        output: &mut [u8],
        limits: ZstdDecompressionLimits,
    ) -> Result<(), DecompressionFailed> {
        self.decompress_with_limits(input, output, limits)
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

    /// A no-content-size frame with RLE blocks of 128 KiB each.
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

    /// A single-segment frame holding a raw block.
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
    fn limits_are_independent_and_zero_is_invalid() {
        assert!(ZstdDecompressionLimits::new(0, 1).is_none());
        assert!(ZstdDecompressionLimits::new(1, 0).is_none());
        assert_eq!(
            ZstdDecompressionLimits::default(),
            ZstdDecompressionLimits::new(8 * 1024 * 1024, 128 * 1024).unwrap()
        );
        assert_eq!(
            ZstdDecompressionLimits::new(usize::MAX, usize::MAX)
                .unwrap()
                .max_history_window,
            usize::MAX
        );
    }

    #[test]
    fn large_advertised_window_is_clamped_only_for_bounded_output() {
        let content = b"small frame";
        let mut frame = rle_frame(13 << 3, 1);
        // Replace the single 128 KiB RLE block with a short raw block.
        frame.truncate(6);
        frame.extend_from_slice(&((content.len() as u32) << 3 | 1).to_le_bytes()[..3]);
        frame.extend_from_slice(content);
        let mut output = alloc::vec![0; content.len()];
        ZSTD.decompress(&frame, &mut output).unwrap();
        assert_eq!(output, content);

        let bomb = rle_frame(13 << 3, 64);
        let mut output = alloc::vec![0; 64 * 1024];
        assert_eq!(
            ZSTD.decompress(&bomb, &mut output),
            Err(DecompressionFailed)
        );
    }

    #[test]
    fn concatenated_frames_are_exact_and_capped_at_64() {
        let mut frames = single_segment_frame(b"first");
        frames.extend_from_slice(&single_segment_frame(b"second"));
        let mut output = alloc::vec![0; 11];
        ZSTD.decompress(&frames, &mut output).unwrap();
        assert_eq!(&output, b"firstsecond");

        for suffix in [&[0][..], &[0x50, 0x2a, 0x4d, 0x18][..]] {
            let mut invalid = frames.clone();
            invalid.extend_from_slice(suffix);
            assert_eq!(
                ZSTD.decompress(&invalid, &mut output),
                Err(DecompressionFailed)
            );
        }

        let frame = single_segment_frame(b"x");
        let many = frame.repeat(65);
        let mut output = alloc::vec![0; 65];
        assert_eq!(
            ZSTD.decompress(&many, &mut output),
            Err(DecompressionFailed)
        );
    }

    #[test]
    fn frame_unused_descriptor_bit_is_ignored_but_reserved_bit_is_rejected() {
        let mut frame = single_segment_frame(b"unused");
        frame[4] |= 0x10;
        let mut output = alloc::vec![0; 6];
        ZSTD.decompress(&frame, &mut output).unwrap();
        assert_eq!(&output, b"unused");

        frame[4] |= 0x08;
        assert_eq!(
            ZSTD.decompress(&frame, &mut output),
            Err(DecompressionFailed)
        );
    }

    #[test]
    fn frame_block_envelope_bounds_raw_and_no_sequence_literals() {
        let mut raw = rle_frame(0, 1);
        let raw_header = ((1025u32) << 3) | 1;
        raw[6..9].copy_from_slice(&raw_header.to_le_bytes()[..3]);
        raw[9] = 0x5a;
        assert!(frame::preflight_block(&raw, 6, 1024).is_none());

        // RLE literals regenerate 1025 bytes, followed by zero sequences.
        // ruzstd's no-sequence path would append these without its normal
        // sequence-execution block-output limit.
        let mut compressed = alloc::vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00];
        let compressed_block_header = (4u32 << 3) | (2 << 1) | 1;
        compressed.extend_from_slice(&compressed_block_header.to_le_bytes()[..3]);
        compressed.extend_from_slice(&[0x15, 0x40, 0x5a, 0x00]);
        assert!(frame::preflight_block(&compressed, 6, 1024).is_none());
    }

    #[test]
    fn sequence_minimum_match_lengths_are_included_in_block_bound() {
        // One literal plus one sequence, whose match must contribute at least
        // three output bytes. A 3-byte frame block cannot contain both.
        let block = [0x08, b'x', 1, 0];
        assert!(frame::preflight_compressed_block(&block, 3).is_none());
    }

    #[test]
    fn legal_zero_dictionary_id_and_nonzero_id() {
        let mut frame = single_segment_frame(b"dict id");
        frame[4] |= 1;
        frame.insert(5, 0);
        let mut output = alloc::vec![0; 7];
        ZSTD.decompress(&frame, &mut output).unwrap();

        frame[5] = 1;
        assert_eq!(
            ZSTD.decompress(&frame, &mut output),
            Err(DecompressionFailed)
        );
    }

    #[test]
    fn streaming_large_window_respects_configured_advertised_cap() {
        let content = b"small";
        let mut frame = rle_frame(13 << 3, 1);
        frame.truncate(6);
        frame.extend_from_slice(&((content.len() as u32) << 3 | 1).to_le_bytes()[..3]);
        frame.extend_from_slice(content);
        let limits = ZstdDecompressionLimits::new(8 * 1024 * 1024, 128 * 1024).unwrap();
        let mut output = alloc::vec![0; content.len()];
        ZSTD.decompress_with_limits(&frame, &mut output, limits)
            .unwrap();
        let restrictive = ZstdDecompressionLimits::new(1024 * 1024, 128 * 1024).unwrap();
        assert_eq!(
            ZSTD.decompress_with_limits(&frame, &mut output, restrictive),
            Err(DecompressionFailed)
        );
    }

    #[test]
    fn libzstd_one_shot_and_streaming_fixtures_decode_with_checksum_verification() {
        let expected = b"libzstd certificate fixture: ".repeat(1024);
        let fixtures = [
            include_bytes!("../../tests/fixtures/cert_compression/zstd/one-shot.zst").as_slice(),
            include_bytes!("../../tests/fixtures/cert_compression/zstd/streaming-checksum.zst")
                .as_slice(),
        ];
        let streaming = fixtures[1];
        let frame = frame::parse(streaming, 0).unwrap();
        assert!(frame.checksum);
        assert!(frame.window > 128 * 1024);
        assert!(frame.window <= 8 * 1024 * 1024);

        for fixture in fixtures {
            let mut output = alloc::vec![0; expected.len()];
            ZSTD.decompress(fixture, &mut output).unwrap();
            assert_eq!(output, expected);
            for wrong_len in [expected.len() - 1, expected.len() + 1] {
                let mut output = alloc::vec![0; wrong_len];
                assert_eq!(
                    ZSTD.decompress(fixture, &mut output),
                    Err(DecompressionFailed),
                    "accepted output length {wrong_len}"
                );
            }
            for end in 0..fixture.len() {
                assert_eq!(
                    ZSTD.decompress(&fixture[..end], &mut output),
                    Err(DecompressionFailed),
                    "accepted {end}-byte prefix"
                );
            }
        }

        let mut bad_checksum = streaming.to_vec();
        let last = bad_checksum.len() - 1;
        bad_checksum[last] ^= 1;
        let mut output = alloc::vec![0; expected.len()];
        assert_eq!(
            ZSTD.decompress(&bad_checksum, &mut output),
            Err(DecompressionFailed)
        );

        let mut concatenated = streaming.to_vec();
        concatenated.extend_from_slice(streaming);
        let mut output = alloc::vec![0; expected.len() * 2];
        ZSTD.decompress(&concatenated, &mut output).unwrap();
        assert_eq!(output, expected.repeat(2));
        concatenated.truncate(streaming.len());
        concatenated.extend_from_slice(&bad_checksum);
        assert_eq!(
            ZSTD.decompress(&concatenated, &mut output),
            Err(DecompressionFailed)
        );
    }

    #[test]
    fn built_in_encoder_round_trips_and_large_declared_windows_fail_early() {
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
        for frame in [rle_frame(13 << 3, 64), rle_frame(8 << 3, 1)] {
            let mut output = alloc::vec![0; 1024];
            assert_eq!(
                ZSTD.decompress(&frame, &mut output),
                Err(DecompressionFailed)
            );
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }
}
