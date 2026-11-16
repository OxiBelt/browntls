//! Load-aware routing between backends (`accel::load`).
//!
//! Routing state is process-wide, so everything runs in one test function
//! (each integration test file is its own process).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::Error;
use browntls_crypto::accel::load::{self, Config, Phase};
use browntls_crypto::accel::{self, Acceleration, Algorithm, Kind, Policy};
use browntls_crypto::aead::Aead as _;
use browntls_crypto::chacha::{self, ChaCha20Poly1305, PolyBackend};
use browntls_crypto::curve25519::x25519;

/// Record lengths around the size from which calls are timed.
const LENGTHS: [usize; 6] = [0, 1, 63, 4095, 4096, 16384];

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + 7) as u8).collect()
}

/// Seals and opens records of every length under `key`, returning the
/// ciphertexts and tags.
fn records(aead: &ChaCha20Poly1305, rounds: usize) -> Vec<(Vec<u8>, [u8; 16])> {
    let mut out = Vec::new();
    for round in 0..rounds {
        for len in LENGTHS {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&((round * 100_000 + len) as u64).to_le_bytes());
            let mut buf = data(len);
            let tag = aead.seal_in_place(&nonce, b"aad", &mut buf).unwrap();
            let sealed = buf.clone();
            aead.open_in_place(&nonce, b"aad", &mut buf, &tag).unwrap();
            assert_eq!(buf, data(len));
            // A forged record is rejected whatever backend it meets.
            let mut forged = sealed.clone();
            let mut bad = tag;
            bad[0] ^= 1;
            assert_eq!(
                aead.open_in_place(&nonce, b"aad", &mut forged, &bad),
                Err(Error::DecryptFailed)
            );
            assert!(forged.iter().all(|&b| b == 0));
            out.push((sealed, tag));
        }
    }
    out
}

fn x25519_outputs() -> Vec<[u8; 32]> {
    (0..64u8)
        .map(|i| x25519::x25519(&[i.wrapping_mul(37) | 1; 32], &[i.wrapping_add(9); 32]))
        .collect()
}

fn status(alg: Algorithm) -> load::StreamStatus {
    load::status(alg, 0).unwrap()
}

#[test]
fn load_aware_routing() {
    const KEY: [u8; 32] = [9; 32];
    const ROUNDS: usize = 48;

    // Disabled by default: no configuration, steady streams, no routing.
    assert_eq!(load::config(), None);
    assert_eq!(
        load::set_fixed(Algorithm::ChaCha20, 0, 0, 50),
        Err(Error::Unsupported)
    );
    for s in load::status_all() {
        println!("{s}");
        assert_eq!(
            (s.phase, s.alternate, s.shifted_percent),
            (Phase::Steady, None, 0)
        );
        assert_eq!(s.primary, accel::status(s.algorithm).backend);
        assert_eq!(load::status(s.algorithm, s.lane), Some(s));
    }
    assert_eq!(load::lanes(Algorithm::ChaCha20), 1);
    assert_eq!(load::lanes(Algorithm::X25519), 1);
    assert_eq!(load::status(Algorithm::ChaCha20, 1), None);
    for alg in Algorithm::ALL {
        assert_eq!(
            load::status_all().filter(|s| s.algorithm == alg).count(),
            load::lanes(alg)
        );
    }

    let aead = ChaCha20Poly1305::new(&KEY).unwrap();
    let baseline = records(&aead, ROUNDS);
    let kx_baseline = x25519_outputs();
    assert_eq!(
        status(Algorithm::ChaCha20).primary_cost,
        None,
        "nothing is timed while disabled"
    );

    // Enabling clamps the configuration and keeps results identical.
    load::enable(Config {
        threshold_percent: 0,
        max_shift_percent: 255,
        portable: true,
    })
    .unwrap();
    assert_eq!(
        load::config(),
        Some(Config {
            threshold_percent: 20,
            max_shift_percent: 93,
            portable: true,
        })
    );
    load::enable(Config::DEFAULT).unwrap();
    assert_eq!(load::config(), Some(Config::DEFAULT));
    assert_eq!(records(&aead, ROUNDS), baseline);
    assert_eq!(x25519_outputs(), kx_baseline);
    // Long records and every key exchange were timed.
    let s = status(Algorithm::ChaCha20);
    println!("{s}");
    assert!(s.primary_cost.is_some() && s.baseline_cost.is_some(), "{s}");
    assert_eq!(s.unit, "byte");
    let s = status(Algorithm::X25519);
    println!("{s}");
    assert!(s.primary_cost.is_some(), "{s}");
    assert_eq!((s.name, s.unit), ("derive", "op"));

    // Fixed shares: every alternate, at every share, gives the same bytes,
    // through keys created before and after the share was set and through
    // clones. The share reported is the share set.
    for alg in [Algorithm::ChaCha20, Algorithm::X25519] {
        let alternates = status(alg).alternates;
        assert_eq!(
            load::set_fixed(alg, 0, alternates, 50),
            Err(Error::Unsupported)
        );
        assert_eq!(load::set_fixed(alg, 1, 0, 50), Err(Error::Unsupported));
        assert_eq!(load::set_fixed(alg, 0, 0, 101), Err(Error::Unsupported));
        for alternate in 0..alternates {
            for percent in [100, 50, 1, 0] {
                load::set_fixed(alg, 0, alternate, percent).unwrap();
                let s = status(alg);
                println!("{s}");
                assert_eq!(s.phase, Phase::Fixed);
                assert_eq!(s.shifted_percent, percent);
                assert!(s.alternate.is_some_and(|a| a != s.primary), "{s}");
                assert_eq!(records(&aead, ROUNDS), baseline, "{s}");
                assert_eq!(records(&aead.clone(), ROUNDS), baseline, "{s}");
                let fresh = ChaCha20Poly1305::new(&KEY).unwrap();
                assert_eq!(records(&fresh, ROUNDS), baseline, "{s}");
                assert_eq!(x25519_outputs(), kx_baseline, "{s}");
                // The alternate was really used: it has a measured cost.
                if percent == 100 {
                    assert!(status(alg).alternate_cost.is_some(), "{s}");
                }
            }
        }
        load::clear_fixed(alg, 0);
        load::clear_fixed(alg, 7);
        assert_eq!(status(alg).phase, Phase::Steady);
    }

    // A key created with explicit backends is never rerouted.
    if status(Algorithm::ChaCha20).alternates > 0 {
        load::set_fixed(Algorithm::ChaCha20, 0, 0, 100).unwrap();
        let pinned =
            ChaCha20Poly1305::with_backends(&KEY, chacha::Backend::best(), PolyBackend::best())
                .unwrap();
        assert_eq!(records(&pinned, 2), records(&aead, 2));
        assert_eq!(pinned.backends().0, chacha::Backend::best());
        load::clear_fixed(Algorithm::ChaCha20, 0);
    }

    // Policies bound the alternates: with SIMD forbidden no SIMD backend
    // takes work, and with the portable backend excluded as well nothing is
    // left to shift to.
    accel::set_kind(Algorithm::ChaCha20, Kind::Simd, Acceleration::None).unwrap();
    let s = status(Algorithm::ChaCha20);
    assert_eq!((s.primary, s.alternates), ("portable", 0), "{s}");
    assert_eq!(
        load::set_fixed(Algorithm::ChaCha20, 0, 0, 50),
        Err(Error::Unsupported)
    );
    assert_eq!(
        records(&aead, 2),
        records(&ChaCha20Poly1305::new(&KEY).unwrap(), 2)
    );
    accel::set_policy(Algorithm::ChaCha20, Policy::PREFERRED).unwrap();
    load::enable(Config {
        portable: false,
        ..Config::DEFAULT
    })
    .unwrap();
    for s in load::status_all() {
        let accelerated = accel::status(s.algorithm).available.any();
        assert!(s.alternates == 0 || accelerated, "{s}");
    }
    // X25519 has at most the portable alternate.
    assert_eq!(status(Algorithm::X25519).alternates, 0);
    load::enable(Config::DEFAULT).unwrap();

    // A fixed share made under one policy is ignored under another, and the
    // policy is obeyed at once.
    if status(Algorithm::X25519).alternates > 0 {
        load::set_fixed(Algorithm::X25519, 0, 0, 100).unwrap();
        accel::set_policy(Algorithm::X25519, Policy::NONE).unwrap();
        let s = status(Algorithm::X25519);
        assert_eq!(
            (s.phase, s.primary, s.alternates),
            (Phase::Steady, "portable", 0),
            "{s}"
        );
        assert_eq!(x25519_outputs(), kx_baseline);
        // The portable ladder ran, as the policy says: its cost was
        // measured, as the primary's.
        assert!(status(Algorithm::X25519).primary_cost.is_some());
        accel::set_policy(Algorithm::X25519, Policy::PREFERRED).unwrap();
        // The share is in force again under the policy it was made for.
        assert_eq!(status(Algorithm::X25519).phase, Phase::Fixed);
        load::clear_fixed(Algorithm::X25519, 0);
    }

    // Additional data beyond a record header is not counted in a record's
    // length, so such records are routed but not timed.
    {
        load::disable();
        load::enable(Config::DEFAULT).unwrap();
        let aad = vec![0u8; 16384];
        let mut reference = data(8192);
        let tag =
            ChaCha20Poly1305::with_backends(&KEY, chacha::Backend::best(), PolyBackend::best())
                .unwrap()
                .seal_in_place(&[3; 12], &aad, &mut reference)
                .unwrap();
        for _ in 0..256 {
            let mut buf = data(8192);
            assert_eq!(aead.seal_in_place(&[3; 12], &aad, &mut buf).unwrap(), tag);
            assert_eq!(buf, reference);
            aead.open_in_place(&[3; 12], &aad, &mut buf, &tag).unwrap();
        }
        assert_eq!(status(Algorithm::ChaCha20).primary_cost, None);
    }

    // Concurrent use: threads sealing while shares change, and while routing
    // is switched off and on, see the same bytes. The shares keep changing
    // until every worker has completed several rounds under them.
    {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        const WORKERS: usize = 4;
        const ROUNDS_EACH: usize = 8;
        let stop = AtomicBool::new(false);
        let rounds = [const { AtomicUsize::new(0) }; WORKERS];
        let alternates = status(Algorithm::ChaCha20).alternates;
        std::thread::scope(|scope| {
            for done in &rounds {
                let (stop, aead, baseline, kx) = (&stop, &aead, &baseline, &kx_baseline);
                scope.spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        assert_eq!(records(aead, 2), baseline[..2 * LENGTHS.len()]);
                        assert_eq!(&x25519_outputs(), kx);
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            let mut i = 0usize;
            while rounds
                .iter()
                .any(|r| r.load(Ordering::Relaxed) < ROUNDS_EACH)
            {
                if alternates > 0 {
                    let _ =
                        load::set_fixed(Algorithm::ChaCha20, 0, i % alternates, (i % 101) as u8);
                }
                let _ = load::set_fixed(Algorithm::X25519, 0, 0, (i % 101) as u8);
                if i.is_multiple_of(97) {
                    load::clear_fixed(Algorithm::ChaCha20, 0);
                }
                if i % 500 == 499 {
                    load::disable();
                    load::enable(Config::DEFAULT).unwrap();
                }
                i += 1;
                std::thread::yield_now();
            }
            stop.store(true, Ordering::Relaxed);
        });
        load::clear_fixed(Algorithm::X25519, 0);
    }

    // Disabling forgets shares and statistics.
    if status(Algorithm::ChaCha20).alternates > 0 {
        load::set_fixed(Algorithm::ChaCha20, 0, 0, 100).unwrap();
    }
    load::disable();
    assert_eq!(load::config(), None);
    for s in load::status_all() {
        assert_eq!(
            (s.phase, s.shifted_percent, s.primary_cost, s.baseline_cost),
            (Phase::Steady, 0, None, None),
            "{s}"
        );
    }
    assert_eq!(records(&aead, ROUNDS), baseline);
    assert_eq!(x25519_outputs(), kx_baseline);
}
