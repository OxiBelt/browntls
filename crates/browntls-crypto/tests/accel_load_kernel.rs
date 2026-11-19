//! Kernel TLS at the head of the routing order (`accel::load::kernel`):
//! where new connections are placed, driven with synthetic costs as a
//! driver would report them.
//!
//! Routing state is process-wide, so everything runs in one test function
//! (each integration test file is its own process).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::accel::Algorithm;
use browntls_crypto::accel::load::kernel::{self, Place, Records};
use browntls_crypto::accel::load::{self, Config, Phase, StreamStatus};

/// The length of the simulated writes: one full record.
const WRITE: usize = 16384;
/// Writes per simulated connection.
const WRITES: usize = 32;
const RECORDS: Records = Records::Aes256Gcm;

/// One write on a connection at `place` that costs `ps` picoseconds per
/// byte, reported if the stream wants it timed.
fn write(records: Records, place: Place, ps: u64) {
    if let Some(sample) = kernel::sample(records, place, WRITE) {
        sample.done(WRITE, ps * WRITE as u64 / 1000);
    }
}

/// Places `n` new connections one after the other, each writing `WRITES`
/// records at the cost of its place, and returns how many stayed in
/// userspace.
fn connections(n: usize, kernel_ps: u64, userspace_ps: u64) -> usize {
    let mut userspace = 0;
    for _ in 0..n {
        let place = kernel::place(RECORDS);
        let ps = match place {
            Place::Kernel => kernel_ps,
            Place::Userspace => {
                userspace += 1;
                userspace_ps
            }
        };
        for _ in 0..WRITES {
            write(RECORDS, place, ps);
        }
    }
    userspace
}

fn status() -> StreamStatus {
    kernel::status(RECORDS).unwrap()
}

/// Whether `cost` is within 2% of `ps`.
fn near(cost: Option<u64>, ps: u64) -> bool {
    cost.is_some_and(|c| c.abs_diff(ps) <= ps / 50)
}

#[test]
fn kernel_tls_heads_the_routing_order() {
    let backends: Vec<StreamStatus> = load::status_all().collect();

    // Not active: every connection stays with the backends, nothing is
    // timed or reported, with routing disabled or enabled.
    for enabled in [false, true] {
        if enabled {
            load::enable(Config::DEFAULT).unwrap();
        }
        assert!(!kernel::is_active());
        for records in Records::ALL {
            assert_eq!(kernel::place(records), Place::Userspace);
            assert_eq!(kernel::status(records), None);
            for place in [Place::Kernel, Place::Userspace] {
                assert!(kernel::sample(records, place, WRITE).is_none());
            }
            assert_eq!(kernel::set_fixed(records, 50), Err(Error::Unsupported));
        }
        assert_eq!(kernel::status_all().count(), 0);
    }
    load::disable();

    // Active without load-aware routing: the order alone decides, so
    // every connection goes to the kernel and nothing is timed.
    kernel::activate();
    assert!(kernel::is_active());
    for records in Records::ALL {
        assert_eq!(kernel::place(records), Place::Kernel);
        assert!(kernel::sample(records, Place::Kernel, WRITE).is_none());
        assert_eq!(kernel::set_fixed(records, 50), Err(Error::Unsupported));
        let s = kernel::status(records).unwrap();
        println!("{s}");
        assert_eq!((s.algorithm, s.lane), (records.algorithm(), records.lane()));
        assert_eq!(
            (s.primary, s.alternate, s.alternates),
            ("kernel TLS", None, 1)
        );
        assert_eq!(
            (s.phase, s.shifted_percent, s.unit),
            (Phase::Steady, 0, "byte")
        );
        assert_eq!((s.primary_cost, s.baseline_cost), (None, None));
    }
    assert_eq!(
        kernel::status_all().map(|s| s.name).collect::<Vec<_>>(),
        [
            "connections (128-bit key)",
            "connections (256-bit key)",
            "connections"
        ]
    );
    assert_eq!(Records::ChaCha20Poly1305.algorithm(), Algorithm::ChaCha20);
    // The backends' streams are reported as before.
    assert_eq!(load::status_all().collect::<Vec<_>>(), backends);

    // With routing: the kernel takes every connection while its writes
    // cost what they usually do.
    load::enable(Config::DEFAULT).unwrap();
    assert_eq!(connections(400, 300, 360), 0);
    let s = status();
    assert_eq!((s.phase, s.alternate), (Phase::Steady, None));
    assert!(
        near(s.primary_cost, 300) && near(s.baseline_cost, 300),
        "{s}"
    );
    // Writes too short to time are not reported, and a timed write that
    // the socket cut short is ignored.
    for place in [Place::Kernel, Place::Userspace] {
        assert!((0..1000).all(|_| kernel::sample(RECORDS, place, 4095).is_none()));
    }
    let sample = (0..1000)
        .find_map(|_| kernel::sample(RECORDS, Place::Kernel, WRITE))
        .expect("one long write in sixteen is timed");
    println!("{sample:?}");
    sample.done(4095, u64::MAX);
    assert_eq!(status(), s);

    // The kernel's writes become twice as slow and userspace measures
    // cheaper: new connections stay there, up to the configured share.
    connections(1500, 600, 360);
    let s = status();
    println!("{s}");
    assert_eq!(
        (s.phase, s.alternate, s.shifted_percent),
        (Phase::Shifting, Some("userspace"), 90)
    );
    assert!(near(s.alternate_cost, 360), "{s}");
    assert!(
        near(s.baseline_cost, 300),
        "the baseline did not follow: {s}"
    );
    let kept = connections(2000, 600, 360);
    assert!(kept.abs_diff(1800) < 90, "{kept} of 2000");
    // Another thread places by the same share, on a schedule of its own.
    let elsewhere = std::thread::spawn(|| {
        (0..2000)
            .filter(|_| kernel::place(RECORDS) == Place::Userspace)
            .count()
    })
    .join()
    .unwrap();
    assert!(elsewhere.abs_diff(1800) < 90, "{elsewhere} of 2000");
    // The other kinds of record work are placed by their own streams.
    assert_eq!(kernel::place(Records::Aes128Gcm), Place::Kernel);
    assert_eq!(
        kernel::status(Records::ChaCha20Poly1305).unwrap().phase,
        Phase::Steady
    );

    // The kernel recovers: every new connection goes to it again.
    connections(3000, 300, 360);
    let s = status();
    assert_eq!(
        (s.phase, s.alternate, s.shifted_percent),
        (Phase::Steady, None, 0)
    );
    assert_eq!(connections(200, 300, 360), 0);

    // Slow again, and the connections that are to measure userspace write
    // too little at a time to be timed: after the first 64 of them one
    // new connection in eight stays there, and when the kernel's writes
    // stop too the probe ends by the number of connections placed.
    for _ in 0..10_000 {
        if status().phase != Phase::Steady {
            break;
        }
        write(RECORDS, Place::Kernel, 600);
    }
    let s = status();
    assert_eq!((s.phase, s.alternate), (Phase::Probing, Some("userspace")));
    let placed = |n: usize| {
        (0..n)
            .filter(|_| kernel::place(RECORDS) == Place::Userspace)
            .inspect(|_| assert!(kernel::sample(RECORDS, Place::Userspace, 4095).is_none()))
            .count()
    };
    assert_eq!(placed(64), 64);
    let kept = placed(4032);
    assert!(kept.abs_diff(504) < 100, "{kept} of 4032");
    assert_eq!(status().phase, Phase::Probing);
    assert_eq!(placed(1000), 0);
    let s = status();
    assert_eq!((s.phase, s.alternate), (Phase::Steady, None));
    // The kernel is back at its usual cost.
    connections(3000, 300, 360);
    assert_eq!(status().phase, Phase::Steady);

    // Slow again, but userspace is slower still: a few connections
    // measure it, nothing is shifted, and the level is accepted.
    let kept = connections(1500, 600, 900);
    assert!((1..40).contains(&kept), "{kept} of 1500");
    let s = status();
    assert_eq!((s.phase, s.alternate), (Phase::Steady, None));
    assert!(near(s.baseline_cost, 600), "{s}");
    assert_eq!(connections(500, 600, 900), 0);

    // A share fixed by hand.
    assert_eq!(kernel::set_fixed(RECORDS, 101), Err(Error::Unsupported));
    for (percent, tolerance) in [(100, 0), (0, 0), (25, 60)] {
        kernel::set_fixed(RECORDS, percent).unwrap();
        let s = status();
        assert_eq!(
            (s.phase, s.alternate, s.shifted_percent),
            (Phase::Fixed, Some("userspace"), percent)
        );
        let kept = connections(1000, 600, 900);
        assert!(
            kept.abs_diff(10 * usize::from(percent)) <= tolerance,
            "{percent}%: {kept} of 1000"
        );
    }
    kernel::clear_fixed(RECORDS);
    assert_eq!(status().phase, Phase::Steady);
    assert!(status().primary_cost.is_some());
    // Ending a share that is not fixed changes nothing.
    let s = status();
    kernel::clear_fixed(RECORDS);
    assert_eq!(status(), s);

    // Disabling routing forgets the statistics and any share; the order
    // still holds.
    kernel::set_fixed(RECORDS, 100).unwrap();
    load::disable();
    let s = status();
    assert_eq!(
        (s.phase, s.alternate, s.shifted_percent),
        (Phase::Steady, None, 0)
    );
    assert_eq!((s.primary_cost, s.baseline_cost), (None, None));
    assert_eq!(connections(100, 600, 900), 0);
    assert_eq!(status(), s);

    // Deactivating takes the kernel out of the order and forgets as well,
    // and a write that was being timed is not reported afterwards.
    load::enable(Config::DEFAULT).unwrap();
    kernel::set_fixed(RECORDS, 0).unwrap();
    connections(100, 300, 360);
    assert!(status().primary_cost.is_some());
    let late = (0..1000)
        .find_map(|_| kernel::sample(RECORDS, Place::Kernel, WRITE))
        .unwrap();
    kernel::deactivate();
    late.done(WRITE, 5000);
    assert!(!kernel::is_active());
    assert_eq!(kernel::place(RECORDS), Place::Userspace);
    assert_eq!(kernel::status(RECORDS), None);
    kernel::activate();
    let s = status();
    assert_eq!((s.phase, s.primary_cost), (Phase::Steady, None));
    kernel::deactivate();
    load::disable();
    assert_eq!(load::status_all().collect::<Vec<_>>(), backends);
}
