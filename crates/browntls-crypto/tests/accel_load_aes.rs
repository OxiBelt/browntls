//! Load-aware routing of AES-GCM records between AES backends
//! (`accel::load`).
//!
//! Routing state and policies are process-wide, so everything runs in one
//! test function (each integration test file is its own process).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};

use browntls_crypto::Error;
use browntls_crypto::accel::load::{self, Config, Phase, StreamStatus};
use browntls_crypto::accel::{self, Acceleration, Algorithm, Policy};
use browntls_crypto::aead::Aead;
use browntls_crypto::aes;
use browntls_crypto::gcm::{Aes128Gcm, Aes256Gcm, GhashBackend};

/// Record lengths around the block size, the widths of the vector backends
/// and the size from which calls are timed.
const LENGTHS: [usize; 10] = [0, 1, 15, 16, 17, 511, 512, 4095, 4096, 16384];
/// A record header: short enough for the long records to be timed.
const AAD: &[u8] = b"record header";
/// Rounds of [`LENGTHS`] after which a timed call is all but certain (192
/// long records, each timed with probability 1/16).
const ROUNDS: usize = 48;

/// What the test needs of the two AES-GCM types besides [`Aead`].
trait Gcm: Aead + Sync {
    const NAME: &'static str;
    /// The stream of the AES family its records belong to.
    const LANE: usize;
    const STREAM: &'static str;
    fn pinned(key: &[u8], aes: aes::Backend, ghash: GhashBackend) -> Self;
    fn pair(&self) -> (aes::Backend, GhashBackend);
}

impl Gcm for Aes128Gcm {
    const NAME: &'static str = "AES-128-GCM";
    const LANE: usize = 0;
    const STREAM: &'static str = "records (128-bit key)";

    fn pinned(key: &[u8], aes: aes::Backend, ghash: GhashBackend) -> Self {
        Self::with_backends(key.try_into().unwrap(), aes, ghash).unwrap()
    }

    fn pair(&self) -> (aes::Backend, GhashBackend) {
        self.backends()
    }
}

impl Gcm for Aes256Gcm {
    const NAME: &'static str = "AES-256-GCM";
    const LANE: usize = 1;
    const STREAM: &'static str = "records (256-bit key)";

    fn pinned(key: &[u8], aes: aes::Backend, ghash: GhashBackend) -> Self {
        Self::with_backends(key.try_into().unwrap(), aes, ghash).unwrap()
    }

    fn pair(&self) -> (aes::Backend, GhashBackend) {
        self.backends()
    }
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + 7) as u8).collect()
}

type Records = Vec<(Vec<u8>, [u8; 16])>;

/// Seals and opens records of every length under `aead`, returning the
/// ciphertexts and tags. A record with a forged tag is rejected, and its
/// buffer wiped, whatever backend it meets.
fn records<A: Aead>(aead: &A, rounds: usize) -> Records {
    let mut out = Vec::new();
    for round in 0..rounds {
        for len in LENGTHS {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&((round * 100_000 + len) as u64).to_le_bytes());
            let mut buf = data(len);
            let tag = aead.seal_in_place(&nonce, AAD, &mut buf).unwrap();
            let sealed = buf.clone();
            aead.open_in_place(&nonce, AAD, &mut buf, &tag).unwrap();
            assert_eq!(buf, data(len));
            let mut forged = sealed.clone();
            let mut bad = tag;
            bad[round % 16] ^= 1 << (len % 8);
            assert_eq!(
                aead.open_in_place(&nonce, AAD, &mut forged, &bad),
                Err(Error::DecryptFailed)
            );
            assert!(forged.iter().all(|&b| b == 0));
            out.push((sealed, tag));
        }
    }
    out
}

/// The stream of the key size under test (set by `check`).
static LANE: AtomicUsize = AtomicUsize::new(0);

fn lane() -> usize {
    LANE.load(Ordering::Relaxed)
}

fn status() -> StreamStatus {
    load::status(Algorithm::Aes, lane()).unwrap()
}

/// Forgets the stream's statistics and shares.
fn restart(config: Config) {
    load::disable();
    load::enable(config).unwrap();
}

/// Forgets the statistics, then fixes `percent` of the records on
/// `alternate`.
fn fix(alternate: usize, percent: u8) -> StreamStatus {
    restart(Config::DEFAULT);
    load::set_fixed(Algorithm::Aes, lane(), alternate, percent).unwrap();
    let s = status();
    assert_eq!((s.phase, s.shifted_percent), (Phase::Fixed, percent), "{s}");
    assert!(s.alternate.is_some_and(|a| a != s.primary), "{s}");
    s
}

/// Runs records under `aead`, which must equal `baseline`, until the
/// stream's status satisfies `seen` (which calls are timed is random).
fn run_until<A: Aead>(
    aead: &A,
    baseline: &Records,
    seen: impl Fn(&StreamStatus) -> bool,
) -> StreamStatus {
    for _ in 0..16 {
        assert_eq!(&records(aead, ROUNDS), baseline);
        let s = status();
        if seen(&s) {
            return s;
        }
    }
    panic!("not reached: {}", status());
}

/// With every record fixed on `alternate`, a key that holds no expanded key
/// for it gives the same records on its primary: the alternate's cost is
/// not measured. If the key has other alternates (`routed`) its records are
/// timed on the primary; a key without any never reaches the routing code,
/// so nothing is measured at all.
fn stays_on_primary<A: Aead>(
    aead: &A,
    baseline: &Records,
    alternate: usize,
    routed: bool,
    what: &str,
) {
    fix(alternate, 100);
    let s = run_until(aead, baseline, |s| s.primary_cost.is_some() || !routed);
    println!("{what}: {s}");
    assert_eq!(s.primary_cost.is_some(), routed, "{what}: {s}");
    assert_eq!(s.alternate_cost, None, "{what}: {s}");
}

/// With every record fixed on `alternate`, a key created while routing was
/// enabled gives the same records on that alternate: only the alternate's
/// cost is measured.
fn runs_on_alternate<A: Aead>(aead: &A, baseline: &Records, alternate: usize, what: &str) {
    fix(alternate, 100);
    let s = run_until(aead, baseline, |s| s.alternate_cost.is_some());
    println!("{what}: {s}");
    assert_eq!(s.primary_cost, None, "{what}: {s}");
}

fn check<A: Gcm>(key: &[u8]) {
    LANE.store(A::LANE, Ordering::Relaxed);
    println!("{} with {}", A::NAME, accel::status(Algorithm::Aes));
    assert_eq!(load::config(), None);
    assert_eq!(accel::policy(Algorithm::Aes), Policy::PREFERRED);
    assert_eq!(accel::policy(Algorithm::Ghash), Policy::PREFERRED);
    let selected = (aes::Backend::select(), GhashBackend::select());

    // The records, without routing. A key made now has no alternates.
    let early = A::new(key).unwrap();
    assert_eq!(early.pair(), selected);
    let baseline = records(&early, ROUNDS);
    let portable = A::pinned(key, aes::Backend::Soft, GhashBackend::Soft);
    assert_eq!(records(&portable, 1), baseline[..LENGTHS.len()]);
    let s = status();
    assert_eq!((s.name, s.unit), (A::STREAM, "byte"));
    assert_eq!(s.primary_cost, None, "nothing is timed while disabled");

    // Enabled and steady: the same records. Long ones are timed, unless
    // the selected backend has no alternate: a key without alternates does
    // not reach the routing code.
    load::enable(Config::DEFAULT).unwrap();
    let alternates = status().alternates;
    let routed = A::new(key).unwrap();
    assert_eq!(routed.pair(), selected);
    let timed = |s: &StreamStatus| s.primary_cost.is_some() == (alternates > 0);
    let s = run_until(&routed, &baseline, timed);
    println!("{s}");
    assert_eq!(s.phase, Phase::Steady);
    assert_eq!(s.primary, accel::status(Algorithm::Aes).backend);
    assert_eq!(s.alternates, alternates);
    assert_eq!(s.baseline_cost.is_some(), alternates > 0, "{s}");
    assert_eq!(
        load::set_fixed(Algorithm::Aes, lane(), alternates, 50),
        Err(Error::Unsupported)
    );

    // Fixed shares on every alternate. The statistics show where the
    // records ran: all of them on the alternate at 100%, none at 0%, and on
    // both in between; the bytes are the same wherever they ran.
    let pinned = A::pinned(key, selected.0, selected.1);
    for alternate in 0..alternates {
        runs_on_alternate(&routed, &baseline, alternate, "created while enabled");
        // A key created before routing was enabled, and one created for
        // explicit backends, hold no other expanded key.
        stays_on_primary(
            &early,
            &baseline,
            alternate,
            false,
            "created while disabled",
        );
        stays_on_primary(&pinned, &baseline, alternate, false, "explicit backends");
        assert_eq!(pinned.pair(), selected);

        fix(alternate, 50);
        let both = |s: &StreamStatus| s.primary_cost.is_some() && s.alternate_cost.is_some();
        println!("{}", run_until(&routed, &baseline, both));
        fix(alternate, 1);
        assert_eq!(records(&routed, ROUNDS), baseline);
        // A key created under the share behaves like one created before it.
        assert_eq!(records(&A::new(key).unwrap(), 4), baseline[..40]);
        assert_eq!(records(&early, 4), baseline[..40]);
        fix(alternate, 0);
        let s = run_until(&routed, &baseline, |s| s.primary_cost.is_some());
        assert_eq!(s.alternate_cost, None, "{s}");
    }
    load::clear_fixed(Algorithm::Aes, lane());
    assert_eq!(status().phase, Phase::Steady);

    // A key holds the alternates of the configuration it was created
    // under: one made while the portable backend was excluded is not moved
    // to it later.
    restart(Config {
        portable: false,
        ..Config::DEFAULT
    });
    let accelerated_only = A::new(key).unwrap();
    let without_portable = status().alternates;
    restart(Config::DEFAULT);
    assert!(without_portable <= alternates);
    if without_portable < alternates {
        let what = "created without the portable alternate";
        let last = alternates - 1;
        stays_on_primary(
            &accelerated_only,
            &baseline,
            last,
            without_portable > 0,
            what,
        );
        assert_eq!(status().alternate, Some("portable"));
    }
    for alternate in 0..without_portable {
        let what = "created without the portable alternate";
        runs_on_alternate(&accelerated_only, &baseline, alternate, what);
    }

    // Additional data beyond a record header is not counted in a record's
    // length, so such records are routed but not timed.
    for percent in [0, 100] {
        restart(Config::DEFAULT);
        if alternates > 0 {
            load::set_fixed(Algorithm::Aes, lane(), 0, percent).unwrap();
        }
        let aad = vec![0u8; 16384];
        let mut reference = data(8192);
        let tag = pinned
            .seal_in_place(&[3; 12], &aad, &mut reference)
            .unwrap();
        for _ in 0..256 {
            let mut buf = data(8192);
            assert_eq!(routed.seal_in_place(&[3; 12], &aad, &mut buf).unwrap(), tag);
            assert_eq!(buf, reference);
            routed
                .open_in_place(&[3; 12], &aad, &mut buf, &tag)
                .unwrap();
            assert_eq!(buf, data(8192));
        }
        let s = status();
        assert_eq!((s.primary_cost, s.alternate_cost), (None, None), "{s}");
    }
    restart(Config::DEFAULT);

    // The AES policy changes after keys were created: existing keys stay
    // correct (and on the backend they were created for), a share fixed
    // under the old policy is ignored, and new keys follow the new policy,
    // alternates included.
    if alternates > 0 {
        load::set_fixed(Algorithm::Aes, lane(), 0, 100).unwrap();
    }
    for policy in [
        Policy::new(Acceleration::None, Acceleration::Preferred),
        Policy::new(Acceleration::Preferred, Acceleration::None),
        Policy::NONE,
    ] {
        accel::set_policy(Algorithm::Aes, policy).unwrap();
        let primary = aes::Backend::select();
        let s = status();
        println!("AES policy {policy}: {s}");
        assert_eq!(s.primary, accel::status(Algorithm::Aes).backend);
        if primary != selected.0 {
            assert_eq!(s.phase, Phase::Steady, "{s}");
        }
        for old in [&routed, &early, &pinned, &accelerated_only] {
            assert_eq!(records(old, 4), baseline[..40], "AES policy {policy}");
            assert_eq!(old.pair(), selected);
        }
        let fresh = A::new(key).unwrap();
        assert_eq!(fresh.pair(), (primary, selected.1));
        assert_eq!(records(&fresh, 4), baseline[..40], "AES policy {policy}");
        if primary != selected.0 {
            // Every alternate the new policy leaves takes the new key's
            // records; the keys of the old policy are not routed at all.
            let what = format!("created under AES policy {policy}");
            for alternate in 0..s.alternates {
                runs_on_alternate(&fresh, &baseline, alternate, &what);
                stays_on_primary(&routed, &baseline, alternate, false, "default AES policy");
            }
            load::clear_fixed(Algorithm::Aes, lane());
            // Back under the default policy that key is the one left alone.
            accel::set_policy(Algorithm::Aes, Policy::PREFERRED).unwrap();
            for alternate in 0..alternates {
                stays_on_primary(&fresh, &baseline, alternate, false, &what);
            }
            restart(Config::DEFAULT);
            if alternates > 0 {
                load::set_fixed(Algorithm::Aes, lane(), 0, 100).unwrap();
            }
        }
    }
    accel::set_policy(Algorithm::Aes, Policy::NONE).unwrap();
    assert_eq!(status().alternates, 0, "nothing follows the portable code");
    assert_eq!(
        load::set_fixed(Algorithm::Aes, lane(), 0, 50),
        Err(Error::Unsupported)
    );
    accel::set_policy(Algorithm::Aes, Policy::PREFERRED).unwrap();
    if alternates > 0 {
        // The share is in force again under the policy it was made for.
        assert_eq!(status().phase, Phase::Fixed);
    }
    restart(Config::DEFAULT);

    // The GHASH policy decides what runs beside an alternate AES backend.
    // With only the portable GHASH permitted every alternate still takes
    // records, each with that one.
    accel::set_policy(Algorithm::Ghash, Policy::NONE).unwrap();
    let soft_ghash = A::new(key).unwrap();
    assert_eq!(soft_ghash.pair(), (selected.0, GhashBackend::Soft));
    for alternate in 0..alternates {
        runs_on_alternate(&soft_ghash, &baseline, alternate, "portable GHASH");
    }
    // With SIMD required for GHASH (where the CPU can do that), an AES
    // backend whose own class of GHASH uses no SIMD has no companion and is
    // not an alternate of keys created now. Keys created earlier keep the
    // companions of their time.
    let simd = Policy::new(Acceleration::Required, Acceleration::Preferred);
    if accel::set_policy(Algorithm::Ghash, simd).is_ok() {
        let simd_ghash = A::new(key).unwrap();
        assert_eq!(simd_ghash.pair(), (selected.0, GhashBackend::select()));
        let names: Vec<&str> = (0..alternates)
            .map(|alternate| fix(alternate, 100).alternate.unwrap())
            .collect();
        let without_simd = |name: &str| matches!(name, "AES-NI" | "FEAT_AES" | "Zkne" | "portable");
        let kept = names.iter().any(|name| !without_simd(name));
        for (alternate, name) in names.iter().enumerate() {
            let what = format!("SIMD GHASH, {name}");
            if without_simd(name) {
                stays_on_primary(&simd_ghash, &baseline, alternate, kept, &what);
            } else {
                runs_on_alternate(&simd_ghash, &baseline, alternate, &what);
            }
            runs_on_alternate(&soft_ghash, &baseline, alternate, "portable GHASH, kept");
            runs_on_alternate(&routed, &baseline, alternate, "default GHASH, kept");
        }
    }
    accel::set_policy(Algorithm::Ghash, Policy::PREFERRED).unwrap();
    restart(Config::DEFAULT);

    // Concurrent use: threads sealing with shared keys and creating keys of
    // their own while shares change, and while routing is switched off and
    // on, see the same bytes. The shares keep changing until every worker
    // has completed several rounds under them.
    {
        use std::sync::atomic::AtomicBool;
        const WORKERS: usize = 4;
        const ROUNDS_EACH: usize = 8;
        let stop = AtomicBool::new(false);
        let rounds = [const { AtomicUsize::new(0) }; WORKERS];
        std::thread::scope(|scope| {
            for done in &rounds {
                let (stop, routed, early, baseline) = (&stop, &routed, &early, &baseline);
                scope.spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let short = &baseline[..2 * LENGTHS.len()];
                        assert_eq!(records(routed, 2), short);
                        assert_eq!(records(early, 2), short);
                        assert_eq!(records(&A::new(key).unwrap(), 2), short);
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
                        load::set_fixed(Algorithm::Aes, lane(), i % alternates, (i % 101) as u8);
                }
                if i.is_multiple_of(97) {
                    load::clear_fixed(Algorithm::Aes, lane());
                }
                if i % 500 == 499 {
                    restart(Config {
                        portable: i % 1000 == 499,
                        ..Config::DEFAULT
                    });
                }
                i += 1;
                std::thread::yield_now();
            }
            stop.store(true, Ordering::Relaxed);
        });
    }

    // Disabling forgets shares and statistics, and every key still gives
    // the same records.
    load::enable(Config::DEFAULT).unwrap();
    if alternates > 0 {
        load::set_fixed(Algorithm::Aes, lane(), 0, 100).unwrap();
    }
    load::disable();
    assert_eq!(load::config(), None);
    let s = status();
    assert_eq!(
        (s.phase, s.shifted_percent, s.primary_cost, s.baseline_cost),
        (Phase::Steady, 0, None, None),
        "{s}"
    );
    for aead in [&routed, &early, &pinned, &accelerated_only, &soft_ghash] {
        assert_eq!(records(aead, 4), baseline[..40]);
    }
    assert_eq!(records(&A::new(key).unwrap(), ROUNDS), baseline);
    assert_eq!(status().primary_cost, None);
}

#[test]
fn load_aware_aes_gcm_routing() {
    assert_eq!(load::lanes(Algorithm::Aes), 2, "one stream per key size");
    assert_eq!(load::lanes(Algorithm::Ghash), 0, "GHASH follows AES");
    assert_eq!(load::status(Algorithm::Aes, 2), None);
    let key: [u8; 32] = core::array::from_fn(|i| (i * 13 + 5) as u8);
    check::<Aes128Gcm>(&key[..16]);
    check::<Aes256Gcm>(&key);
    load::disable();
}
