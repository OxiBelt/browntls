//! Throughput of record protection under load, with and without load-aware
//! backend routing (`accel::load`).
//!
//! ```sh
//! cargo run --release -p browntls-crypto --example load -- --threads 8 --seconds 3
//! ```
//!
//! Each thread seals records with its own key (ChaCha20-Poly1305 by default,
//! AES-256-GCM with `--cipher aes`). The run is repeated with routing
//! disabled and enabled; with `--fixed <alternate>:<percent>` a third run
//! pins that share on an alternate backend, which shows what a shift costs
//! or gains here. The output shows the total throughput, the phases the
//! stream went through and where the work went. More threads than CPUs
//! (`--threads`) make the machine overloaded. Numbers describe this machine
//! at this moment only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use browntls_crypto::accel::load::{self, Config, Phase};
use browntls_crypto::accel::{self, Algorithm};
use browntls_crypto::aead::Aead;
use browntls_crypto::chacha::ChaCha20Poly1305;
use browntls_crypto::gcm::Aes256Gcm;

#[derive(Clone, Copy, PartialEq)]
enum Cipher {
    ChaCha,
    Aes,
}

impl Cipher {
    fn algorithm(self) -> Algorithm {
        match self {
            Self::ChaCha => Algorithm::ChaCha20,
            Self::Aes => Algorithm::Aes,
        }
    }

    /// The stream of the family that the benchmark's records belong to
    /// (AES-256-GCM records are the AES family's second stream).
    fn lane(self) -> usize {
        match self {
            Self::ChaCha => 0,
            Self::Aes => 1,
        }
    }
}

struct Options {
    threads: usize,
    seconds: f64,
    record: usize,
    cipher: Cipher,
    fixed: Option<(usize, u8)>,
    threshold: u8,
}

fn options() -> Options {
    let mut o = Options {
        threads: std::thread::available_parallelism().map_or(1, usize::from),
        seconds: 2.0,
        record: 16384,
        cipher: Cipher::ChaCha,
        fixed: None,
        threshold: Config::DEFAULT.threshold_percent,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| panic!("{arg} needs a value"));
        match arg.as_str() {
            "--threads" => o.threads = value().parse().expect("--threads"),
            "--seconds" => o.seconds = value().parse().expect("--seconds"),
            "--record" => o.record = value().parse().expect("--record"),
            "--threshold" => o.threshold = value().parse().expect("--threshold"),
            "--cipher" => {
                o.cipher = match value().as_str() {
                    "chacha" => Cipher::ChaCha,
                    "aes" => Cipher::Aes,
                    other => panic!("unknown cipher {other} (chacha, aes)"),
                }
            }
            "--fixed" => {
                let v = value();
                let (alternate, percent) =
                    v.split_once(':').expect("--fixed <alternate>:<percent>");
                o.fixed = Some((
                    alternate.parse().expect("alternate"),
                    percent.parse().expect("percent"),
                ));
            }
            other => panic!(
                "unknown argument {other}; options: --threads N --seconds S --record BYTES \
                 --cipher chacha|aes --threshold PERCENT --fixed ALTERNATE:PERCENT"
            ),
        }
    }
    o
}

fn seal_loop<A: Aead>(record: usize, stop: &AtomicBool, bytes: &AtomicU64, id: usize) {
    let mut key = vec![7u8; A::KEY_LEN];
    key[0] = id as u8;
    let aead = A::new(&key).unwrap();
    let mut buf = vec![0u8; record];
    let mut n = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&n.to_le_bytes());
        let tag = aead
            .seal_in_place(&nonce, b"record header", &mut buf)
            .unwrap();
        std::hint::black_box(tag);
        n += 1;
        if n.is_multiple_of(64) {
            bytes.fetch_add(64 * record as u64, Ordering::Relaxed);
        }
    }
}

/// One measured run: returns MB/s and prints what the stream did.
fn run(o: &Options, label: &str) -> f64 {
    let stop = AtomicBool::new(false);
    let bytes = AtomicU64::new(0);
    let alg = o.cipher.algorithm();
    let mut phases = [0u32; 4];
    let mut share_sum = 0u64;
    let mut polls = 0u64;
    let start = Instant::now();
    std::thread::scope(|scope| {
        for id in 0..o.threads {
            let (stop, bytes) = (&stop, &bytes);
            scope.spawn(move || match o.cipher {
                Cipher::ChaCha => seal_loop::<ChaCha20Poly1305>(o.record, stop, bytes, id),
                Cipher::Aes => seal_loop::<Aes256Gcm>(o.record, stop, bytes, id),
            });
        }
        while start.elapsed().as_secs_f64() < o.seconds {
            std::thread::sleep(Duration::from_millis(5));
            if let Some(s) = load::status(alg, o.cipher.lane()) {
                let i = match s.phase {
                    Phase::Steady => 0,
                    Phase::Probing => 1,
                    Phase::Shifting => 2,
                    _ => 3,
                };
                phases[i] += 1;
                share_sum += u64::from(s.shifted_percent);
                polls += 1;
            }
        }
        stop.store(true, Ordering::Relaxed);
    });
    let elapsed = start.elapsed().as_secs_f64();
    let rate = bytes.load(Ordering::Relaxed) as f64 / elapsed / 1e6;
    println!(
        "{label}: {rate:.0} MB/s total, {:.0} MB/s per thread",
        rate / o.threads as f64
    );
    if polls > 0 && load::config().is_some() {
        println!(
            "  phases seen (5 ms polls): steady {}, probing {}, shifting {}, fixed {}; \
             mean shifted share {}%",
            phases[0],
            phases[1],
            phases[2],
            phases[3],
            share_sum / polls
        );
    }
    if let Some(s) = load::status(alg, o.cipher.lane()) {
        println!("  {s}");
    }
    rate
}

fn main() {
    let o = options();
    let alg = o.cipher.algorithm();
    println!(
        "{} threads on {} CPUs, {}-byte records, {} s per run",
        o.threads,
        std::thread::available_parallelism().map_or(1, usize::from),
        o.record,
        o.seconds
    );
    println!("{}", accel::status(alg));

    let off = run(&o, "routing off");
    load::enable(Config {
        threshold_percent: o.threshold,
        ..Config::DEFAULT
    })
    .expect("routing needs the std feature");
    let on = run(&o, "routing on ");
    println!("  on/off: {:+.1}%", (on / off - 1.0) * 100.0);
    if let Some((alternate, percent)) = o.fixed {
        match load::set_fixed(alg, o.cipher.lane(), alternate, percent) {
            Ok(()) => {
                let fixed = run(&o, "fixed share");
                println!("  fixed/off: {:+.1}%", (fixed / off - 1.0) * 100.0);
            }
            Err(_) => println!("no alternate {alternate} for {alg} here"),
        }
    }
    load::disable();
}
