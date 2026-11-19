//! The checks must pass an ideal generator and catch known-bad ones.
//!
//! Every generator here is deterministic, so these tests cannot flake.

#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;

const N: usize = 1 << 14;

/// SplitMix64: a deterministic stand-in for an ideal generator.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Analyses `N` samples of `stream` made sequentially by `make(i, rng, out)`.
fn analyse(stream: Stream, mut make: impl FnMut(usize, &mut SplitMix, &mut [u8])) -> Report {
    let len = stream.len();
    let mut raw = vec![0u8; N * len];
    let mut rng = SplitMix(0x0123_4567_89ab_cdef);
    for (i, out) in raw.chunks_mut(len).enumerate() {
        make(i, &mut rng, out);
    }
    analyze(&Samples::from_raw(stream, raw))
}

fn failed(report: &Report, check: &str) -> bool {
    report.failures.iter().any(|f| f.starts_with(check))
}

fn assert_fails(report: &Report, expected: &[&str]) {
    assert!(!report.passed(), "{report:#?}");
    for check in expected {
        assert!(failed(report, check), "{check} did not fail: {report:#?}");
    }
}

#[test]
fn ideal_generator_passes() {
    let report = analyse(Stream::new("ideal", 32), |_, rng, out| rng.fill(out));
    assert!(report.passed(), "{report:#?}");
    assert!(
        report.lines.iter().all(|l| !l.starts_with("[skip]")),
        "{report:#?}"
    );
}

#[test]
fn masked_bits_are_ignored() {
    // X25519-style clamping on raw output: the fixed bits must not count.
    let stream = Stream::new("clamped", 32).fixed(0, 0x07).fixed(31, 0xc0);
    let report = analyse(stream, |_, rng, out| {
        rng.fill(out);
        out[0] &= 0xf8;
        out[31] = (out[31] & 0x7f) | 0x40;
    });
    assert!(report.passed(), "{report:#?}");
    assert_eq!(report.free_bits, 256 - 5);
}

#[test]
fn packing_keeps_free_bits_in_order() {
    let mask = [0xff, 0x0f, 0x81];
    let mut out = [0u8; 2];
    pack_one(&[0xab, 0xcd, 0x81], &mask, &mut out);
    // 0xab, then the low nibble 0xd, then bits 7 and 0 of 0x81 (1, 1).
    assert_eq!(out, [0xab, 0b1101_1100]);
}

#[test]
fn stuck_bit_is_caught() {
    let report = analyse(Stream::new("stuck", 32), |_, rng, out| {
        rng.fill(out);
        out[3] |= 0x20;
    });
    assert_fails(&report, &["bit frequency"]);
}

#[test]
fn unfilled_tail_is_caught() {
    let report = analyse(Stream::new("short fill", 32), |_, rng, out| {
        rng.fill(&mut out[..24]);
        out[24..].fill(0);
    });
    assert_fails(&report, &["bit frequency", "byte distribution"]);
}

#[test]
fn biased_byte_is_caught() {
    let report = analyse(Stream::new("biased", 32), |_, rng, out| {
        rng.fill(out);
        if rng.next() % 64 == 0 {
            out[5] = 0;
        }
    });
    assert_fails(&report, &["byte distribution"]);
}

#[test]
fn a_rare_count_of_an_ideal_generator_passes() {
    // Seen on CI from a P-384 key share: 4096 samples of 96 free bytes, one
    // value 46 times at one position (16 expected). An ideal generator
    // makes such a count in about 1 of 60,000 analyses, far above `ALPHA`.
    const SAMPLES: usize = 4096;
    let stream = Stream::new("rare count", 96);
    let mut raw = vec![0u8; SAMPLES * 96];
    let mut rng = SplitMix(0x0123_4567_89ab_cdef);
    for (i, out) in raw.chunks_mut(96).enumerate() {
        rng.fill(out);
        if i < 46 {
            out[49] = 0xd7;
        } else if out[49] == 0xd7 {
            out[49] = 0xd6;
        }
    }
    let report = analyze(&Samples::from_raw(stream, raw));
    assert!(report.passed(), "{report:#?}");
}

#[test]
fn low_entropy_seed_is_caught() {
    // A 20-bit seed expanded by a good PRNG: every window is uniform, but
    // samples repeat.
    let report = analyse(Stream::new("20-bit seed", 32), |_, rng, out| {
        let seed = rng.next() & 0xf_ffff;
        SplitMix(seed).fill(out);
    });
    assert_fails(&report, &["duplicates"]);
}

#[test]
fn small_value_set_is_caught() {
    // Each 32-bit word drawn from 2^12 values: no duplicates of whole
    // samples, but windows collide far too often.
    let report = analyse(Stream::new("small set", 32), |_, rng, out| {
        for chunk in out.chunks_mut(4) {
            let v = (rng.next() & 0xfff) as u32;
            let mut s = SplitMix(u64::from(v));
            s.fill(chunk);
        }
    });
    assert_fails(&report, &["window collisions"]);
}

#[test]
fn copied_half_is_caught() {
    let report = analyse(Stream::new("copied half", 32), |_, rng, out| {
        rng.fill(&mut out[..16]);
        let (a, b) = out.split_at_mut(16);
        b.copy_from_slice(a);
    });
    assert_fails(&report, &["byte lags"]);
}

#[test]
fn distant_copy_is_caught() {
    // A block copied beyond the byte-lag range shows up as equal windows.
    let report = analyse(Stream::new("copied block", 64), |_, rng, out| {
        rng.fill(&mut out[..32]);
        let (a, b) = out.split_at_mut(32);
        b.copy_from_slice(a);
    });
    assert_fails(&report, &["window repeats"]);
}

#[test]
fn byte_period_is_caught() {
    let report = analyse(Stream::new("period 3", 32), |_, rng, out| {
        rng.fill(out);
        for j in 3..out.len() {
            if j % 2 == 0 {
                out[j] = out[j - 3];
            }
        }
    });
    assert_fails(&report, &["byte lags"]);
}

#[test]
fn slowly_changing_state_is_caught() {
    // Each sample is the previous one with one byte replaced.
    let mut prev = [0u8; 32];
    SplitMix(7).fill(&mut prev);
    let report = analyse(Stream::new("one byte per draw", 32), |_, rng, out| {
        let r = rng.next();
        prev[(r % 32) as usize] = (r >> 8) as u8;
        out.copy_from_slice(&prev);
    });
    assert_fails(&report, &["consecutive distance", "window collisions"]);
}

#[test]
fn counter_is_caught() {
    let report = analyse(Stream::new("counter", 32), |i, _, out| {
        out.fill(0);
        out[24..].copy_from_slice(&(i as u64).to_be_bytes());
    });
    assert_fails(&report, &["bit frequency", "byte distribution"]);
}

#[test]
fn collect_fills_every_stream_in_parallel() {
    let streams = [Stream::new("a", 8), Stream::new("b", 3)];
    let samples = collect(1000, &streams, |out| {
        out[0].fill(0xaa);
        out[1].fill(0x55);
        Ok(())
    })
    .unwrap();
    assert_eq!(samples[0].count(), 1000);
    assert_eq!(samples[1].count(), 1000);
    assert!((0..1000).all(|i| samples[0].sample(i) == [0xaa; 8]));
    assert!((0..1000).all(|i| samples[1].sample(i) == [0x55; 3]));
}

#[test]
fn collect_reports_generator_errors() {
    let streams = [Stream::new("a", 8)];
    let res = collect(100, &streams, |_| Err("boom".into()));
    assert_eq!(res.err().as_deref(), Some("boom"));
}

#[test]
fn window_geometry() {
    assert_eq!(window_width(1 << 14, 256), 19);
    assert_eq!(window_width(1 << 22, 256), 32);
    assert_eq!(window_width(64, 256), 16);
    assert_eq!(
        window_offsets(256, 32),
        (0..8).map(|k| k * 32).collect::<Vec<_>>()
    );
    let wide = window_offsets(4096, 32);
    assert_eq!(wide.len(), MAX_WINDOWS);
    assert!(wide.windows(2).all(|w| w[1] - w[0] >= 32));
    assert!(wide.last().copied().unwrap() + 32 <= 4096);
}
