//! Statistical checks that generated secret material has high entropy.
//!
//! Test tooling for browntls, not a published crate. Each test in `tests/`
//! draws a large number of samples from one public generator (a private key,
//! a seed, a nonce, a key share, a handshake secret, ...), keeps the bits that
//! the specification leaves free (clamped or range-limited bits are masked
//! out), and runs every check below on them. A check fails when its
//! statistic would occur with probability below [`ALPHA`] for an ideal
//! generator, after a Bonferroni correction over the tests inside the check.
//!
//! | Check | Statistic | Catches |
//! | --- | --- | --- |
//! | duplicates | equal samples after sorting | entropy below about `2 log2(N)` bits, repeated or cached keys |
//! | bit frequency | `z` of the ones count per free bit | stuck, unfilled or biased bits |
//! | byte distribution | chi-square and the largest count per byte position | biased byte values; gives the per-byte Shannon and min-entropy floors |
//! | window collisions | collisions of `w`-bit windows across samples (Poisson) | low collision entropy (Rényi order 2) inside a window, values drawn from a small set |
//! | window repeats | equal windows inside one sample (Poisson) | halves or blocks copied within a key |
//! | byte lags | equal bytes at distance 1..=16 inside a sample | periodic or repeated byte patterns |
//! | consecutive distance | Hamming distance between consecutive samples | counters, near-duplicates and slowly changing state |
//!
//! Statistical tests only bound *visible* structure. A generator that
//! expands a 64-bit seed through a hash passes every check at any feasible
//! sample count; the duplicate check detects seeds below about `2 log2(N)`
//! bits (44 bits at `N = 2^22`). The checks complement, and do not replace,
//! review of how the generator obtains its entropy.
//!
//! The sample count comes from [`SAMPLES_ENV`] (default [`SMOKE_SAMPLES`] so
//! that `cargo test --workspace` stays fast); the CI workflow sets millions.

#![allow(clippy::cast_precision_loss)]

pub mod stats;

use std::fmt::Write as _;
use std::io::Write as _;
use std::ops::Range;

/// Environment variable with the base sample count.
pub const SAMPLES_ENV: &str = "BROWNTLS_ENTROPY_SAMPLES";
/// Environment variable overriding the number of worker threads.
pub const THREADS_ENV: &str = "BROWNTLS_ENTROPY_THREADS";
/// Base sample count when [`SAMPLES_ENV`] is unset: a smoke run.
pub const SMOKE_SAMPLES: usize = 1 << 14;
/// False-alarm probability of one check on one stream for an ideal generator.
///
/// A full CI run evaluates a few hundred (stream, check) pairs, so a
/// spurious failure is expected about once in a million runs.
pub const ALPHA: f64 = 1e-9;

/// Most windows examined per stream by the window checks.
const MAX_WINDOWS: usize = 16;
/// Largest lag of the byte-lag check.
const MAX_LAG: usize = 16;
/// Packed byte positions examined by the byte-lag check.
const LAG_SPAN: usize = 64;

/// The base sample count: [`SAMPLES_ENV`] or [`SMOKE_SAMPLES`].
#[must_use]
pub fn base_samples() -> usize {
    std::env::var(SAMPLES_ENV)
        .ok()
        .and_then(|v| v.trim().replace('_', "").parse().ok())
        .unwrap_or(SMOKE_SAMPLES)
}

/// The sample count for a generator `divisor` times as costly as the
/// cheapest ones: `base_samples() / divisor`, at least `min`.
#[must_use]
pub fn sample_count(divisor: usize, min: usize) -> usize {
    (base_samples() / divisor.max(1)).max(min)
}

/// Worker threads: [`THREADS_ENV`] or the available parallelism.
#[must_use]
pub fn threads() -> usize {
    std::env::var(THREADS_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .or_else(|| std::thread::available_parallelism().ok().map(usize::from))
        .unwrap_or(1)
        .max(1)
}

/// One kind of sample: its length and which bits are free.
#[derive(Clone, Debug)]
pub struct Stream {
    name: String,
    /// Per byte, the bits that must be uniformly random.
    mask: Vec<u8>,
}

impl Stream {
    /// A `len`-byte sample whose bits are all free.
    #[must_use]
    pub fn new(name: impl Into<String>, len: usize) -> Self {
        Self {
            name: name.into(),
            mask: vec![0xff; len],
        }
    }

    /// Marks `bits` of byte `byte` as fixed by the specification (for
    /// example clamped), so they are excluded from every check.
    #[must_use]
    pub fn fixed(mut self, byte: usize, bits: u8) -> Self {
        self.mask[byte] &= !bits;
        self
    }

    /// Keeps only the bits in `free` of byte `byte`.
    #[must_use]
    pub fn only(mut self, byte: usize, free: u8) -> Self {
        self.mask[byte] &= free;
        self
    }

    /// The stream's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The sample length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mask.len()
    }

    /// Whether samples are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mask.is_empty()
    }

    /// The number of free bits per sample.
    #[must_use]
    pub fn free_bits(&self) -> usize {
        self.mask.iter().map(|m| m.count_ones() as usize).sum()
    }
}

/// `n` raw samples of one stream.
#[derive(Debug)]
pub struct Samples {
    stream: Stream,
    n: usize,
    raw: Vec<u8>,
}

impl Samples {
    /// Wraps `raw`, which holds `raw.len() / stream.len()` samples.
    #[must_use]
    pub fn from_raw(stream: Stream, raw: Vec<u8>) -> Self {
        let n = raw.len().checked_div(stream.len()).unwrap_or(0);
        Self { stream, n, raw }
    }

    /// The stream.
    #[must_use]
    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    /// The number of samples.
    #[must_use]
    pub fn count(&self) -> usize {
        self.n
    }

    /// Sample `i`.
    #[must_use]
    pub fn sample(&self, i: usize) -> &[u8] {
        let len = self.stream.len();
        &self.raw[i * len..(i + 1) * len]
    }
}

/// Splits `0..n` into at most `threads` contiguous ranges.
fn ranges(n: usize, threads: usize) -> Vec<Range<usize>> {
    let per = n.div_ceil(threads.max(1)).max(1);
    (0..n)
        .step_by(per)
        .map(|start| start..(start + per).min(n))
        .collect()
}

/// Runs `f` over `0..n` split across the worker threads.
fn par_map<T: Send>(n: usize, f: impl Fn(Range<usize>) -> T + Sync) -> Vec<T> {
    let parts = ranges(n, threads());
    std::thread::scope(|s| {
        let handles: Vec<_> = parts
            .into_iter()
            .map(|r| {
                let f = &f;
                s.spawn(move || f(r))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

/// Draws `n` samples of every stream in `streams` from `generate`, which
/// fills one sample of each stream per call (in `streams` order). Calls run
/// in parallel on the worker threads.
///
/// # Errors
///
/// The first error `generate` returns.
pub fn collect<F>(n: usize, streams: &[Stream], generate: F) -> Result<Vec<Samples>, String>
where
    F: Fn(&mut [&mut [u8]]) -> Result<(), String> + Sync,
{
    let lens: Vec<usize> = streams.iter().map(Stream::len).collect();
    let mut buffers: Vec<Vec<u8>> = lens.iter().map(|&l| vec![0u8; n * l]).collect();
    let parts = ranges(n, threads());
    // per_thread[t][s]: the samples of stream `s` that thread `t` fills.
    let mut per_thread: Vec<Vec<&mut [u8]>> = parts.iter().map(|_| Vec::new()).collect();
    for (buf, &len) in buffers.iter_mut().zip(&lens) {
        let mut rest: &mut [u8] = buf;
        for (t, r) in parts.iter().enumerate() {
            let (head, tail) = rest.split_at_mut(r.len() * len);
            per_thread[t].push(head);
            rest = tail;
        }
    }
    std::thread::scope(|s| {
        let handles: Vec<_> = per_thread
            .into_iter()
            .zip(&parts)
            .map(|(mut chunks, r)| {
                let generate = &generate;
                let lens = &lens;
                let count = r.len();
                s.spawn(move || -> Result<(), String> {
                    for i in 0..count {
                        let mut views: Vec<&mut [u8]> = chunks
                            .iter_mut()
                            .zip(lens)
                            .map(|(c, &l)| &mut c[i * l..(i + 1) * l])
                            .collect();
                        generate(&mut views)?;
                    }
                    Ok(())
                })
            })
            .collect();
        handles
            .into_iter()
            .try_for_each(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
    })?;
    Ok(streams
        .iter()
        .cloned()
        .zip(buffers)
        .map(|(stream, raw)| Samples::from_raw(stream, raw))
        .collect())
}

/// The free bits of every sample, packed most significant bit first.
struct Packed {
    n: usize,
    /// Free bits per sample.
    bits: usize,
    /// Bytes per packed sample (`bits.div_ceil(8)`).
    width: usize,
    data: Vec<u8>,
    /// For each packed bit, its `(byte, bit)` in the raw sample (bit 7 is
    /// the most significant).
    origin: Vec<(usize, u8)>,
}

impl Packed {
    fn new(s: &Samples) -> Self {
        let mask = &s.stream.mask;
        let mut origin = Vec::new();
        for (j, &m) in mask.iter().enumerate() {
            for b in (0..8u8).rev() {
                if m >> b & 1 == 1 {
                    origin.push((j, b));
                }
            }
        }
        let bits = origin.len();
        let width = bits.div_ceil(8);
        let n = s.n;
        let mut data = vec![0u8; n * width];
        let parts: Vec<Vec<u8>> = par_map(n, |r| {
            let mut out = vec![0u8; r.len() * width];
            for (k, i) in r.enumerate() {
                pack_one(s.sample(i), mask, &mut out[k * width..(k + 1) * width]);
            }
            out
        });
        let mut offset = 0;
        for p in parts {
            data[offset..offset + p.len()].copy_from_slice(&p);
            offset += p.len();
        }
        Self {
            n,
            bits,
            width,
            data,
            origin,
        }
    }

    fn sample(&self, i: usize) -> &[u8] {
        &self.data[i * self.width..(i + 1) * self.width]
    }

    /// `w <= 32` packed bits of sample `i` starting at bit `off`.
    fn window(&self, i: usize, off: usize, w: usize) -> u32 {
        let s = self.sample(i);
        let mut v = 0u64;
        for k in 0..8 {
            let byte = s.get(off / 8 + k).copied().unwrap_or(0);
            v |= u64::from(byte) << (56 - 8 * k);
        }
        ((v << (off % 8)) >> (64 - w)) as u32
    }

    fn describe_bit(&self, i: usize) -> String {
        let (byte, bit) = self.origin[i];
        format!("byte {byte} bit {bit}")
    }
}

/// Appends the bits of `raw` selected by `mask` to `out`, MSB first.
fn pack_one(raw: &[u8], mask: &[u8], out: &mut [u8]) {
    let mut acc: u32 = 0;
    let mut nacc = 0u32;
    let mut pos = 0;
    for (&b, &m) in raw.iter().zip(mask) {
        let (val, k) = if m == 0xff {
            (u32::from(b), 8)
        } else {
            let mut v = 0u32;
            let mut k = 0;
            for bit in (0..8).rev() {
                if m >> bit & 1 == 1 {
                    v = v << 1 | u32::from(b >> bit & 1);
                    k += 1;
                }
            }
            (v, k)
        };
        acc = acc << k | val;
        nacc += k;
        while nacc >= 8 {
            nacc -= 8;
            out[pos] = (acc >> nacc) as u8;
            pos += 1;
        }
        acc &= (1 << nacc) - 1;
    }
    if nacc > 0 {
        out[pos] = (acc << (8 - nacc)) as u8;
    }
}

/// The outcome of every check on one stream.
#[derive(Debug, Clone)]
pub struct Report {
    /// The stream's name.
    pub name: String,
    /// Samples examined.
    pub n: usize,
    /// Free bits per sample.
    pub free_bits: usize,
    /// One line per check.
    pub lines: Vec<String>,
    /// Failed checks, with details.
    pub failures: Vec<String>,
    /// Lowest per-byte min-entropy observed and its floor, in bits.
    pub min_entropy: Option<(f64, f64)>,
    /// Lowest per-byte Shannon entropy observed and its floor, in bits.
    pub shannon: Option<(f64, f64)>,
    /// Lowest collision entropy of a window, its floor, and the window width.
    pub collision: Option<(f64, f64, usize)>,
}

impl Report {
    /// Whether every check passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    fn record(&mut self, name: &str, ok: bool, detail: String) {
        let tag = if ok { "pass" } else { "FAIL" };
        self.lines.push(format!("[{tag}] {name}: {detail}"));
        if !ok {
            self.failures.push(format!("{name}: {detail}"));
        }
    }

    fn skip(&mut self, name: &str, why: &str) {
        self.lines.push(format!("[skip] {name}: {why}"));
    }
}

/// Runs every check on `samples`.
#[must_use]
pub fn analyze(samples: &Samples) -> Report {
    let p = Packed::new(samples);
    let mut report = Report {
        name: samples.stream.name.clone(),
        n: p.n,
        free_bits: p.bits,
        lines: Vec::new(),
        failures: Vec::new(),
        min_entropy: None,
        shannon: None,
        collision: None,
    };
    if p.n < 2 || p.bits == 0 {
        report.failures.push("no samples or no free bits".into());
        return report;
    }
    check_duplicates(&p, &mut report);
    let hist = histograms(&p);
    check_bits(&p, &hist, &mut report);
    check_bytes(&p, &hist, &mut report);
    check_windows(&p, &mut report);
    check_lags(&p, &mut report);
    check_consecutive(&p, &mut report);
    report
}

fn check_duplicates(p: &Packed, r: &mut Report) {
    const NAME: &str = "duplicates";
    let n = p.n as f64;
    // log2 of the expected number of equal pairs for an ideal generator.
    let log2_expected = (n * (n - 1.0) / 2.0).log2() - p.bits as f64;
    let mut idx: Vec<u32> = (0..p.n as u32).collect();
    idx.sort_unstable_by(|&a, &b| p.sample(a as usize).cmp(p.sample(b as usize)));
    let dups = idx
        .windows(2)
        .filter(|w| p.sample(w[0] as usize) == p.sample(w[1] as usize))
        .count();
    if log2_expected > -30.0 {
        // Too few free bits for duplicates to be implausible: report only.
        r.skip(
            NAME,
            &format!(
                "{dups} equal pairs; an ideal generator expects 2^{log2_expected:.1}, too many to judge"
            ),
        );
        return;
    }
    r.record(
        NAME,
        dups == 0,
        format!("{dups} duplicate samples (ideal expectation 2^{log2_expected:.0})"),
    );
}

/// Per packed byte position, the histogram of its values.
fn histograms(p: &Packed) -> Vec<[u64; 256]> {
    let parts = par_map(p.n, |range| {
        let mut h = vec![[0u64; 256]; p.width];
        for i in range {
            for (pos, &b) in p.sample(i).iter().enumerate() {
                h[pos][usize::from(b)] += 1;
            }
        }
        h
    });
    let mut total = vec![[0u64; 256]; p.width];
    for h in parts {
        for (t, x) in total.iter_mut().zip(h) {
            for (a, b) in t.iter_mut().zip(x) {
                *a += b;
            }
        }
    }
    total
}

fn check_bits(p: &Packed, hist: &[[u64; 256]], r: &mut Report) {
    const NAME: &str = "bit frequency";
    let n = p.n as f64;
    let zc = stats::z_two_sided(ALPHA, p.bits);
    let mut worst = (0.0f64, 0usize);
    let mut bad = Vec::new();
    for i in 0..p.bits {
        let shift = 7 - (i % 8);
        let ones: u64 = hist[i / 8]
            .iter()
            .enumerate()
            .filter(|(v, _)| v >> shift & 1 == 1)
            .map(|(_, &c)| c)
            .sum();
        let z = (2.0 * ones as f64 - n) / n.sqrt();
        if z.abs() > worst.0.abs() {
            worst = (z, i);
        }
        if z.abs() > zc {
            bad.push(format!(
                "{} is 1 in {:.4} of samples (z = {z:.1})",
                p.describe_bit(i),
                ones as f64 / n
            ));
        }
    }
    let detail = format!(
        "{} free bits, largest |z| = {:.2} at {} (limit {zc:.2})",
        p.bits,
        worst.0.abs(),
        p.describe_bit(worst.1)
    );
    if bad.is_empty() {
        r.record(NAME, true, detail);
    } else {
        bad.truncate(8);
        r.record(NAME, false, format!("{detail}; {}", bad.join("; ")));
    }
}

fn check_bytes(p: &Packed, hist: &[[u64; 256]], r: &mut Report) {
    const NAME: &str = "byte distribution";
    let full = p.bits / 8;
    let n = p.n as f64;
    let expected = n / 256.0;
    if full == 0 || expected < 5.0 {
        r.skip(NAME, "needs whole free bytes and at least 1280 samples");
        return;
    }
    let df = 255.0;
    let chi_crit = stats::chi2_from_z(stats::z_one_sided(ALPHA, full), df);
    let sigma = (n * (1.0 / 256.0) * (255.0 / 256.0)).sqrt();
    let max_crit = expected + stats::z_one_sided(ALPHA, full * 256) * sigma;
    let h_floor = stats::shannon_from_chi2(chi_crit, 256.0, n);
    let hmin_floor = -(max_crit / n).log2();
    let mut worst_chi = (0.0f64, 0usize);
    let mut worst_max = (0u64, 0usize);
    let mut min_h = f64::INFINITY;
    let mut bad = Vec::new();
    for (pos, h) in hist.iter().take(full).enumerate() {
        let chi: f64 = h
            .iter()
            .map(|&c| {
                let d = c as f64 - expected;
                d * d / expected
            })
            .sum();
        let max = h.iter().copied().max().unwrap_or(0);
        min_h = min_h.min(stats::shannon_bits(h, p.n as u64));
        if chi > worst_chi.0 {
            worst_chi = (chi, pos);
        }
        if max > worst_max.0 {
            worst_max = (max, pos);
        }
        if chi > chi_crit || max as f64 > max_crit {
            let value = h.iter().position(|&c| c == max).unwrap_or(0);
            bad.push(format!(
                "packed byte {pos} (from {}): chi2 = {chi:.0}, value {value:#04x} in {:.5} of samples",
                p.describe_bit(pos * 8),
                max as f64 / n
            ));
        }
    }
    let min_entropy = -(worst_max.0 as f64 / n).log2();
    r.min_entropy = Some((min_entropy, hmin_floor));
    r.shannon = Some((min_h, h_floor));
    let detail = format!(
        "{full} free bytes; min-entropy >= {min_entropy:.4} bits/byte (floor {hmin_floor:.4}), \
         Shannon >= {min_h:.6} bits/byte (floor {h_floor:.6}), largest chi2 = {:.0} (limit {chi_crit:.0})",
        worst_chi.0
    );
    if bad.is_empty() {
        r.record(NAME, true, detail);
    } else {
        bad.truncate(8);
        r.record(NAME, false, format!("{detail}; {}", bad.join("; ")));
    }
}

/// The window width: about 2^8 expected collisions per window, 16 to 32 bits.
fn window_width(n: usize, bits: usize) -> usize {
    let log2n = (n as f64).log2();
    let w = (2.0 * log2n - 9.0).ceil();
    (w.clamp(16.0, 32.0) as usize).min(bits)
}

/// The window offsets: up to [`MAX_WINDOWS`] non-overlapping windows spread
/// over the free bits.
fn window_offsets(bits: usize, w: usize) -> Vec<usize> {
    let count = (bits / w).clamp(1, MAX_WINDOWS);
    if count == 1 {
        return vec![0];
    }
    let stride = (bits - w) / (count - 1);
    (0..count).map(|k| k * stride).collect()
}

/// The smallest `k` with `P(X >= k) < p` for `X ~ Poisson(lambda)`.
fn poisson_upper_crit(lambda: f64, p: f64) -> u64 {
    let mut k = lambda.ceil() as u64;
    let step = (lambda.sqrt().ceil() as u64).max(1);
    while stats::poisson_sf(k, lambda) >= p {
        k += step;
    }
    while k > 0 && stats::poisson_sf(k - 1, lambda) < p {
        k -= 1;
    }
    k
}

fn check_windows(p: &Packed, r: &mut Report) {
    const NAME: &str = "window collisions";
    const REPEATS: &str = "window repeats";
    if p.bits < 16 {
        r.skip(NAME, "fewer than 16 free bits");
        return;
    }
    let w = window_width(p.n, p.bits);
    let offsets = window_offsets(p.bits, w);
    let wcount = offsets.len();
    let n = p.n as f64;
    let space = 2f64.powi(w as i32);
    let pairs = n * (n - 1.0) / 2.0;
    let lambda = pairs / space;
    let tail = ALPHA / (2.0 * wcount as f64);
    let hi = poisson_upper_crit(lambda, tail);
    // Collision entropy H2 = -log2(sum p_i^2), estimated as log2(pairs / collisions).
    let h2_floor = (pairs / hi as f64).log2();

    // Window values, one column per window.
    let columns: Vec<Vec<u32>> = offsets
        .iter()
        .map(|&off| (0..p.n).map(|i| p.window(i, off, w)).collect())
        .collect();

    let counts: Vec<u64> = std::thread::scope(|s| {
        let handles: Vec<_> = columns
            .iter()
            .map(|col| {
                s.spawn(move || {
                    let mut v = col.clone();
                    v.sort_unstable();
                    let mut collisions = 0u64;
                    let mut run = 1u64;
                    for k in 1..v.len() {
                        if v[k] == v[k - 1] {
                            run += 1;
                        } else {
                            collisions += run * (run - 1) / 2;
                            run = 1;
                        }
                    }
                    collisions + run * (run - 1) / 2
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    });

    let mut bad = Vec::new();
    let mut min_h2 = f64::INFINITY;
    for (k, &c) in counts.iter().enumerate() {
        let h2 = if c == 0 {
            f64::INFINITY
        } else {
            (pairs / c as f64).log2()
        };
        min_h2 = min_h2.min(h2);
        let low = stats::poisson_cdf(c, lambda);
        let high = stats::poisson_sf(c, lambda);
        if high < tail || low < tail {
            bad.push(format!(
                "window at {} has {c} collisions (expected {lambda:.0}, H2 = {h2:.2} of {w} bits)",
                p.describe_bit(offsets[k])
            ));
        }
    }
    r.collision = Some((min_h2, h2_floor, w));
    let detail = format!(
        "{wcount} windows of {w} bits; collisions {}..={} (expected {lambda:.0}, limit {hi}); \
         collision entropy >= {min_h2:.3} bits per window (floor {h2_floor:.3})",
        counts.iter().min().copied().unwrap_or(0),
        counts.iter().max().copied().unwrap_or(0)
    );
    if bad.is_empty() {
        r.record(NAME, true, detail);
    } else {
        bad.truncate(8);
        r.record(NAME, false, format!("{detail}; {}", bad.join("; ")));
    }

    // Equal windows inside one sample.
    if wcount < 2 {
        r.skip(REPEATS, "a single window");
        return;
    }
    let pair_count = (wcount * (wcount - 1) / 2) as f64;
    let lambda = n * pair_count / space;
    let repeats: u64 = par_map(p.n, |range| {
        let mut c = 0u64;
        for i in range {
            for a in 0..wcount {
                for b in a + 1..wcount {
                    if columns[a][i] == columns[b][i] {
                        c += 1;
                    }
                }
            }
        }
        c
    })
    .into_iter()
    .sum();
    let crit = poisson_upper_crit(lambda, ALPHA);
    r.record(
        REPEATS,
        repeats < crit,
        format!("{repeats} equal window pairs inside samples (expected {lambda:.3}, limit {crit})"),
    );
}

fn check_lags(p: &Packed, r: &mut Report) {
    const NAME: &str = "byte lags";
    let span = (p.bits / 8).min(LAG_SPAN);
    if span < 2 {
        r.skip(NAME, "fewer than two whole free bytes");
        return;
    }
    let lags = (span - 1).min(MAX_LAG);
    let counts: Vec<Vec<u64>> = par_map(p.n, |range| {
        let mut c = vec![0u64; lags + 1];
        for i in range {
            let s = &p.sample(i)[..span];
            for d in 1..=lags {
                c[d] += s.iter().zip(&s[d..]).filter(|(a, b)| a == b).count() as u64;
            }
        }
        c
    });
    let zc = stats::z_two_sided(ALPHA, lags);
    let mut worst = (0.0f64, 0usize);
    let mut bad = Vec::new();
    for d in 1..=lags {
        let equal: u64 = counts.iter().map(|c| c[d]).sum();
        // The indicators are pairwise independent for an ideal generator.
        let trials = (p.n * (span - d)) as f64;
        let q = 1.0 / 256.0;
        let z = (equal as f64 - trials * q) / (trials * q * (1.0 - q)).sqrt();
        if z.abs() > worst.0.abs() {
            worst = (z, d);
        }
        if z.abs() > zc {
            bad.push(format!(
                "lag {d}: equal bytes in {:.5} of positions (z = {z:.1})",
                equal as f64 / trials
            ));
        }
    }
    let detail = format!(
        "lags 1..={lags} over {span} bytes, largest |z| = {:.2} at lag {} (limit {zc:.2})",
        worst.0.abs(),
        worst.1
    );
    if bad.is_empty() {
        r.record(NAME, true, detail);
    } else {
        r.record(NAME, false, format!("{detail}; {}", bad.join("; ")));
    }
}

fn check_consecutive(p: &Packed, r: &mut Report) {
    const NAME: &str = "consecutive distance";
    let total: u64 = par_map(p.n - 1, |range| {
        let mut t = 0u64;
        for i in range {
            t += p
                .sample(i)
                .iter()
                .zip(p.sample(i + 1))
                .map(|(a, b)| u64::from((a ^ b).count_ones()))
                .sum::<u64>();
        }
        t
    })
    .into_iter()
    .sum();
    let pairs = (p.n - 1) as f64;
    let bits = p.bits as f64;
    let z = (total as f64 - pairs * bits / 2.0) / (pairs * bits / 4.0).sqrt();
    let zc = stats::z_two_sided(ALPHA, 1);
    r.record(
        NAME,
        z.abs() <= zc,
        format!(
            "mean Hamming distance {:.4} of {} free bits (z = {z:.2}, limit {zc:.2})",
            total as f64 / pairs,
            p.bits
        ),
    );
}

/// Formats `reports` for the log.
#[must_use]
pub fn render(title: &str, reports: &[Report]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "== {title}");
    for r in reports {
        let verdict = if r.passed() { "ok" } else { "FAILED" };
        let _ = writeln!(
            out,
            "-- {} ({} samples, {} free bits): {verdict}",
            r.name, r.n, r.free_bits
        );
        for line in &r.lines {
            let _ = writeln!(out, "   {line}");
        }
    }
    out
}

/// Appends a Markdown table of `reports` to `$GITHUB_STEP_SUMMARY`, if set.
fn write_summary(title: &str, reports: &[Report]) {
    let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let mut md = String::new();
    let _ = writeln!(md, "### {title}\n");
    let _ = writeln!(
        md,
        "| Stream | Samples | Free bits | Min-entropy/byte (floor) | Shannon/byte (floor) | Collision entropy/window (floor) | Result |"
    );
    let _ = writeln!(md, "| --- | ---: | ---: | --- | --- | --- | --- |");
    for r in reports {
        let me = r
            .min_entropy
            .map_or("n/a".into(), |(v, f)| format!("{v:.3} ({f:.3})"));
        let sh = r
            .shannon
            .map_or("n/a".into(), |(v, f)| format!("{v:.5} ({f:.5})"));
        let h2 = r
            .collision
            .map_or("n/a".into(), |(v, f, w)| format!("{v:.2}/{w} ({f:.2})"));
        let verdict = if r.passed() { "pass" } else { "**FAIL**" };
        let _ = writeln!(
            md,
            "| {} | {} | {} | {me} | {sh} | {h2} | {verdict} |",
            r.name, r.n, r.free_bits
        );
    }
    md.push('\n');
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(path) {
        let _ = f.write_all(md.as_bytes());
    }
}

/// Analyses `samples`, prints the reports and appends them to the GitHub
/// job summary.
///
/// # Errors
///
/// Every failed check of every stream.
pub fn judge(title: &str, samples: &[Samples]) -> Result<Vec<Report>, String> {
    let started = std::time::Instant::now();
    let reports: Vec<Report> = samples.iter().map(analyze).collect();
    println!("{}", render(title, &reports));
    println!(
        "   ({} threads; analysis {:.1?})",
        threads(),
        started.elapsed()
    );
    write_summary(title, &reports);
    let failures: Vec<String> = reports
        .iter()
        .flat_map(|r| r.failures.iter().map(move |f| format!("{}: {f}", r.name)))
        .collect();
    if failures.is_empty() {
        Ok(reports)
    } else {
        Err(format!(
            "{title}: {} failed check(s):\n{}",
            failures.len(),
            failures.join("\n")
        ))
    }
}

/// Draws `n` samples of each stream from `generate` and [`judge`]s them.
///
/// # Errors
///
/// A generator error, or every failed check of every stream.
pub fn run<F>(title: &str, n: usize, streams: &[Stream], generate: F) -> Result<Vec<Report>, String>
where
    F: Fn(&mut [&mut [u8]]) -> Result<(), String> + Sync,
{
    let started = std::time::Instant::now();
    let samples = collect(n, streams, generate)?;
    println!(
        "== {title}: generated {n} samples in {:.1?}",
        started.elapsed()
    );
    judge(title, &samples)
}

/// [`run`], panicking with every failure: the entry point for tests.
///
/// # Panics
///
/// On a generator error or a failed check.
#[allow(clippy::panic)]
#[track_caller]
pub fn check<F>(title: &str, n: usize, streams: &[Stream], generate: F)
where
    F: Fn(&mut [&mut [u8]]) -> Result<(), String> + Sync,
{
    if let Err(e) = run(title, n, streams, generate) {
        panic!("{e}");
    }
}

/// Converts any displayable error into the `String` errors of [`run`].
pub fn err<E: core::fmt::Debug>(e: E) -> String {
    format!("{e:?}")
}

#[cfg(test)]
mod tests;
