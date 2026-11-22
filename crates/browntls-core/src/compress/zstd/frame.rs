//! Bounded parsing of the Zstandard frame and block envelopes.

#[cfg(test)]
use alloc::vec::Vec;

const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const MAX_BLOCK_SIZE: usize = 128 * 1024;
const MAX_BLOCK_SEQUENCES: usize = MAX_BLOCK_SIZE / 3;

#[derive(Clone, Copy)]
pub(super) struct Frame {
    pub header: [u8; 18],
    pub header_len: usize,
    pub body_start: usize,
    pub window: u64,
    pub content_size: Option<u64>,
    pub checksum: bool,
}

pub(super) struct Block {
    pub end: usize,
    pub last: bool,
    pub min_output: usize,
}

/// Parse and validate a frame header without scanning ahead into its blocks.
pub(super) fn parse(input: &[u8], start: usize) -> Option<Frame> {
    let bytes = input.get(start..)?;
    if bytes.get(..4)? != MAGIC {
        return None;
    }
    let descriptor = *bytes.get(4)?;
    // RFC 8878 requires reserved bit 3 to be zero. Bit 4 is unused and a
    // decoder must ignore it, even though conforming encoders set it to zero.
    if descriptor & 0x08 != 0 {
        return None;
    }
    let single_segment = descriptor & 0x20 != 0;
    let checksum = descriptor & 0x04 != 0;
    let dict_len = match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let fcs_flag = descriptor >> 6;
    let fcs_len = match fcs_flag {
        0 if single_segment => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut header_len = 5usize;
    let mut window_descriptor = None;
    if !single_segment {
        window_descriptor = Some(*bytes.get(header_len)?);
        header_len += 1;
    }
    let dict_end = header_len.checked_add(dict_len)?;
    let dict = bytes.get(header_len..dict_end)?;
    if dict.iter().any(|byte| *byte != 0) {
        return None;
    }
    header_len = dict_end;
    let fcs_end = header_len.checked_add(fcs_len)?;
    let fcs_bytes = bytes.get(header_len..fcs_end)?;
    let content_size = if fcs_len == 0 {
        None
    } else {
        let mut value = 0u64;
        for (shift, byte) in fcs_bytes.iter().enumerate() {
            value |= u64::from(*byte) << (shift * 8);
        }
        if fcs_len == 2 {
            value += 256;
        }
        Some(value)
    };
    header_len = fcs_end;
    let window = if single_segment {
        content_size?
    } else {
        let descriptor = window_descriptor?;
        let base = 1u64.checked_shl(10 + u32::from(descriptor >> 3))?;
        base.checked_add((base / 8) * u64::from(descriptor & 7))?
    };
    if single_segment && content_size.is_none() {
        return None;
    }

    // Keep the original frame header byte-for-byte. The caller may change only
    // the window descriptor after this real header has passed validation.
    let mut header = [0u8; 18];
    header[..header_len].copy_from_slice(bytes.get(..header_len)?);

    Some(Frame {
        header,
        header_len,
        body_start: start.checked_add(header_len)?,
        window,
        content_size,
        checksum,
    })
}

/// Preflight only the next block so output overflow can stop later input work.
pub(super) fn preflight_block(input: &[u8], offset: usize, max_block_size: usize) -> Option<Block> {
    let header = input.get(offset..offset.checked_add(3)?)?;
    let word = u32::from(header[0]) | (u32::from(header[1]) << 8) | (u32::from(header[2]) << 16);
    let last = word & 1 != 0;
    let kind = (word >> 1) & 3;
    let size = (word >> 3) as usize;
    if kind == 3 || size > max_block_size {
        return None;
    }
    let body_start = offset.checked_add(3)?;
    let payload_size = match kind {
        0 | 2 => size,
        1 => 1,
        _ => return None,
    };
    let end = body_start.checked_add(payload_size)?;
    let payload = input.get(body_start..end)?;
    let min_output = match kind {
        0 | 1 => size,
        2 => preflight_compressed_block(payload, max_block_size)?,
        _ => return None,
    };
    Some(Block {
        end,
        last,
        min_output,
    })
}

pub(super) fn preflight_compressed_block(block: &[u8], max_block_size: usize) -> Option<usize> {
    let first = *block.first()?;
    let kind = first & 3;
    let size_format = (first >> 2) & 3;
    let literal_header_len = match kind {
        0 | 1 => match size_format {
            0 | 2 => 1,
            1 => 2,
            _ => 3,
        },
        2 | 3 => match size_format {
            0 | 1 => 3,
            2 => 4,
            _ => 5,
        },
        _ => return None,
    };
    let header = block.get(..literal_header_len)?;
    let regenerated = match kind {
        0 | 1 => match size_format {
            0 | 2 => usize::from(first >> 3),
            1 => (usize::from(first) >> 4) | (usize::from(header[1]) << 4),
            _ => {
                (usize::from(first) >> 4)
                    | (usize::from(header[1]) << 4)
                    | (usize::from(header[2]) << 12)
            }
        },
        _ => match size_format {
            0 | 1 => (usize::from(first) >> 4) | ((usize::from(header[1]) & 0x3f) << 4),
            2 => {
                (usize::from(first) >> 4)
                    | (usize::from(header[1]) << 4)
                    | ((usize::from(header[2]) & 3) << 12)
            }
            _ => {
                (usize::from(first) >> 4)
                    | (usize::from(header[1]) << 4)
                    | ((usize::from(header[2]) & 0x3f) << 12)
            }
        },
    };
    if regenerated > max_block_size {
        return None;
    }
    let literal_payload_len = match kind {
        0 => regenerated,
        1 => 1,
        _ => match size_format {
            0 | 1 => (usize::from(header[1] >> 6)) | (usize::from(header[2]) << 2),
            2 => (usize::from(header[2] >> 2)) | (usize::from(header[3]) << 6),
            _ => {
                (usize::from(header[2] >> 6))
                    | (usize::from(header[3]) << 2)
                    | (usize::from(header[4]) << 10)
            }
        },
    };
    let seq_start = literal_header_len.checked_add(literal_payload_len)?;
    let sequence_header = block.get(seq_start..)?;
    let (count, seq_header_len) = match *sequence_header.first()? {
        0 => (0usize, 1usize),
        value @ 1..=127 => (usize::from(value), 2),
        value @ 128..=254 => {
            let second = *sequence_header.get(1)?;
            let count = (usize::from(value - 128) << 8) | usize::from(second);
            (count, if count == 0 { 2 } else { 3 })
        }
        255 => {
            let low = usize::from(*sequence_header.get(1)?);
            let high = usize::from(*sequence_header.get(2)?);
            (low | (high << 8) | 0x7f00, 4)
        }
    };
    let min_output = count.checked_mul(3)?.checked_add(regenerated)?;
    if count > MAX_BLOCK_SEQUENCES || min_output > max_block_size {
        return None;
    }
    sequence_header.get(..seq_header_len)?;
    Some(min_output)
}

pub(super) fn clamp_large_window(frame: &Frame, header: &mut [u8; 18]) {
    if frame.window > 128 * 1024 {
        // A non-single-segment window descriptor immediately follows the
        // frame descriptor. 128 KiB is exactly exponent 7, mantissa 0.
        header[5] = 7 << 3;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_sequence_count_that_would_overallocate() {
        // Compressed literals with a short body, followed by a three-byte
        // sequence count of 0x7f00. The outer block stays within spec bounds.
        let mut block = Vec::from([0x03, 0x00, 0x00]);
        block.extend_from_slice(&[0xff, 0xff, 0xff, 0x00]);
        assert!(preflight_compressed_block(&block, MAX_BLOCK_SIZE).is_none());
    }
}
