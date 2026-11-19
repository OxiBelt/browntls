//! Memory bound of the built-in certificate decompressors (RFC 8879) on
//! short streams (a few hundred bytes, about 52 KB for zlib) that announce
//! megabytes of output.
//!
//! The decoders allocate through the global allocator, so the bound is
//! observed from outside: the peak resident set size the kernel records for
//! the process (`VmHWM` in `/proc/self/status`) must not move by more than a
//! fixed amount while a hostile stream is refused. This target holds a single
//! test so that nothing else runs in the process, and ends with a control
//! that shows the measurement would have seen the allocation.

#![cfg(all(
    target_os = "linux",
    any(feature = "zlib", feature = "brotli", feature = "zstd")
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls::compress::{self, CertDecompressor, DecompressionFailed};

/// The process's peak resident set size in KiB, if the kernel reports it.
fn peak_rss_kib() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// What refusing a hostile stream may add to the peak, in KiB. The streams
/// below made the unbounded decoders allocate 8 to 16 MiB.
const ALLOWED_GROWTH_KIB: usize = 1024;

/// A Brotli stream that announces 16 MiB: the largest window (WBITS 24),
/// then an uncompressed meta-block, not the last, with MLEN 2^24, of which
/// ten bytes are present.
#[cfg(feature = "brotli")]
const BROTLI_ANNOUNCES_16_MIB: [u8; 14] = [0xcf, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/// A Zstandard frame without a content size: `window_descriptor`, then
/// `blocks` RLE blocks of 128 KiB each (four bytes apiece).
#[cfg(feature = "zstd")]
fn zstd_rle_frame(window_descriptor: u8, blocks: u32) -> Vec<u8> {
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, window_descriptor];
    for i in 0..blocks {
        let last = u32::from(i + 1 == blocks);
        let header = (128 * 1024) << 3 | 1 << 1 | last;
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.push(0x5a);
    }
    frame
}

/// A zlib stream of stored blocks holding 8 MiB would be 8 MiB long; a run
/// of zeros compresses to about 52 KB instead. Built with fixed-Huffman
/// blocks by hand to keep the compressor's own memory out of the picture:
/// one literal zero, then length-258 distance-1 matches.
#[cfg(feature = "zlib")]
fn zlib_zeros(matches: usize) -> Vec<u8> {
    // Bits are packed least significant first; Huffman codes most
    // significant bit first (RFC 1951 §3.1.1).
    struct Bits(Vec<u8>, u32, u32);
    impl Bits {
        fn put(&mut self, value: u32, count: u32) {
            for i in 0..count {
                self.1 |= (value >> i & 1) << self.2;
                self.2 += 1;
                if self.2 == 8 {
                    self.0.push(self.1 as u8);
                    (self.1, self.2) = (0, 0);
                }
            }
        }
        fn code(&mut self, code: u32, count: u32) {
            for i in (0..count).rev() {
                self.put(code >> i & 1, 1);
            }
        }
    }
    let mut bits = Bits(vec![0x78, 0x01], 0, 0);
    bits.put(1, 1); // BFINAL
    bits.put(1, 2); // BTYPE: fixed Huffman
    bits.code(0x30, 8); // literal 0
    for _ in 0..matches {
        bits.code(0xc5, 8); // length symbol 285: 258 bytes
        bits.code(0, 5); // distance symbol 0: 1 byte back
    }
    bits.code(0, 7); // end of block
    if bits.2 != 0 {
        bits.put(0, 8 - bits.2);
    }
    // The Adler-32 trailer is never reached: the output is refused first.
    bits.0.extend_from_slice(&[0, 0, 0, 0]);
    bits.0
}

#[test]
fn hostile_streams_do_not_move_the_peak() {
    let Some(start) = peak_rss_kib() else {
        eprintln!("skipped: /proc/self/status has no VmHWM");
        return;
    };

    let cases: Vec<(&str, &'static dyn CertDecompressor, Vec<u8>)> = vec![
        #[cfg(feature = "brotli")]
        (
            "brotli, 16 MiB announced",
            &compress::BROTLI,
            BROTLI_ANNOUNCES_16_MIB.to_vec(),
        ),
        // an 8 MiB window filled by 64 blocks
        #[cfg(feature = "zstd")]
        (
            "zstd, 8 MiB window",
            &compress::ZSTD,
            zstd_rle_frame(13 << 3, 64),
        ),
        // the largest accepted window and 8 MiB of blocks
        #[cfg(feature = "zstd")]
        (
            "zstd, 128 KiB window",
            &compress::ZSTD,
            zstd_rle_frame(7 << 3, 64),
        ),
        #[cfg(feature = "zlib")]
        ("zlib, 8 MiB of zeros", &compress::ZLIB, zlib_zeros(32_512)),
    ];

    // The largest buffer a handshake can ask for, touched before measuring.
    let mut output = vec![0xa5u8; compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE];
    for (name, decompressor, stream) in &cases {
        assert!(stream.len() < 64 * 1024, "{name}");
        for len in [1, 4096, output.len()] {
            let before = peak_rss_kib().unwrap();
            let result = decompressor.decompress(stream, &mut output[..len]);
            let grew = peak_rss_kib().unwrap() - before;
            eprintln!("{name}: {len}-byte buffer, peak grew {grew} KiB");
            assert_eq!(result, Err(DecompressionFailed), "{name}");
            assert!(
                grew <= ALLOWED_GROWTH_KIB,
                "{name}: peak grew {grew} KiB with a {len}-byte buffer"
            );
        }
    }

    // A peak only ever rises, so a large allocation early on would hide
    // later ones: the bound holds for all cases together as well.
    let total = peak_rss_kib().unwrap() - start;
    assert!(
        total <= ALLOWED_GROWTH_KIB,
        "peak grew {total} KiB over all cases"
    );

    // Control: the same measurement sees an allocation of the size the
    // streams announce, so the bound above is not vacuous.
    let before = peak_rss_kib().unwrap();
    let ballast = vec![1u8; 8 << 20];
    assert_eq!(
        ballast.iter().map(|b| usize::from(*b)).sum::<usize>(),
        8 << 20
    );
    drop(ballast);
    let grew = peak_rss_kib().unwrap() - before;
    eprintln!("control: 8 MiB allocation, peak grew {grew} KiB (start {start} KiB)");
    assert!(
        grew >= 6 * 1024,
        "control allocation not observed: {grew} KiB"
    );
}
