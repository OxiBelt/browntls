//! CRLite answers on filters produced by the reference implementation.
//!
//! `tests/data/crlite` holds Clubcards built and encoded by Mozilla's
//! `clubcard` and `clubcard-crlite` crates, and the answer those crates give
//! for each query in `expected.txt` (see the README there).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use browntls_pki::UnixTime;
use browntls_pki::crlite::{
    CrliteDelta, CrliteEncoding, CrliteFilter, CrliteFilterStatus, CrliteKey, CrliteLayer,
    CrliteLimits, CrliteSct, CrliteSnapshot, CrliteSnapshotSource, CrliteStatus,
};
use core::time::Duration;
use sha2::{Digest, Sha256};

const FULL_V3: &[u8] = include_bytes!("data/crlite/full-v3.clubcard");
const FULL_V4: &[u8] = include_bytes!("data/crlite/full-v4.clubcard");
const DELTA_V4: &[u8] = include_bytes!("data/crlite/delta-v4.clubcard");
const EXPECTED: &str = include_str!("data/crlite/expected.txt");

struct Vector {
    issuer: [u8; 32],
    serial: Vec<u8>,
    sct: CrliteSct,
    full: CrliteFilterStatus,
    delta: CrliteFilterStatus,
}

impl Vector {
    /// The key as a caller derives it: SHA-256 over issuer hash and serial.
    fn key(&self) -> CrliteKey<'_> {
        let mut hasher = Sha256::new();
        hasher.update(self.issuer);
        hasher.update(&self.serial);
        CrliteKey::new(self.issuer, &self.serial, hasher.finalize().into())
    }
}

fn status(name: &str) -> CrliteFilterStatus {
    match name {
        "revoked" => CrliteFilterStatus::Revoked,
        "good" => CrliteFilterStatus::Good,
        "not-enrolled" => CrliteFilterStatus::NotEnrolled,
        "not-covered" => CrliteFilterStatus::NotCovered,
        other => panic!("unknown status {other}"),
    }
}

fn vectors() -> Vec<Vector> {
    let tag = |field: &str| [u8::from_str_radix(field, 16).unwrap(); 32];
    EXPECTED
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let [issuer, serial, log, timestamp, full, delta] = fields[..] else {
                panic!("malformed vector {line:?}");
            };
            Vector {
                issuer: tag(issuer),
                serial: if serial == "-" {
                    Vec::new()
                } else {
                    hex::decode(serial).unwrap()
                },
                sct: CrliteSct::from_verified(tag(log), timestamp.parse().unwrap()),
                full: status(full),
                delta: status(delta),
            }
        })
        .collect()
}

fn time(seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
}

#[test]
fn filters_agree_with_the_reference() {
    let limits = CrliteLimits::DEFAULT;
    let full_v3 = CrliteFilter::decode(FULL_V3, &limits).unwrap();
    let full_v4 = CrliteFilter::decode(FULL_V4, &limits).unwrap();
    let delta = CrliteFilter::decode(DELTA_V4, &limits).unwrap();
    assert_eq!(full_v3.encoding(), CrliteEncoding::V3);
    assert_eq!(full_v4.encoding(), CrliteEncoding::V4);
    assert_eq!((full_v3.issuer_count(), full_v3.coverage_len()), (5, 2));
    assert_eq!((full_v4.issuer_count(), full_v4.coverage_len()), (5, 2));
    assert_eq!((delta.issuer_count(), delta.coverage_len()), (2, 2));

    let vectors = vectors();
    assert!(vectors.len() > 500);
    let mut seen = BTreeMap::new();
    for vector in &vectors {
        let key = vector.key();
        let scts = [vector.sct];
        assert_eq!(
            full_v3.status(&key, &scts),
            vector.full,
            "{:x?}",
            vector.serial
        );
        assert_eq!(
            full_v4.status(&key, &scts),
            vector.full,
            "{:x?}",
            vector.serial
        );
        assert_eq!(
            delta.status(&key, &scts),
            vector.delta,
            "{:x?}",
            vector.serial
        );
        *seen.entry(format!("{:?}", vector.full)).or_insert(0) += 1;
    }
    // The vectors exercise every answer.
    assert_eq!(seen.len(), 4, "{seen:?}");
    assert!(seen.values().all(|count| *count >= 10), "{seen:?}");
}

#[test]
fn snapshot_combines_full_and_delta_by_precedence() {
    for full in [FULL_V3, FULL_V4] {
        let snapshot = CrliteSnapshot::new(
            &CrliteSnapshotSource {
                generation: 7,
                expiry: time(3_000),
                full: CrliteLayer {
                    effective: time(1_000),
                    clubcard: full,
                },
                deltas: &[CrliteDelta {
                    number: 1,
                    layer: CrliteLayer {
                        effective: time(2_000),
                        clubcard: DELTA_V4,
                    },
                }],
                delta_tip: 1,
            },
            &CrliteLimits::DEFAULT,
        )
        .unwrap();
        assert_eq!(snapshot.delta_count(), 1);

        let mut seen = BTreeMap::new();
        for vector in &vectors() {
            use CrliteFilterStatus as Layer;
            let live = match (vector.full, vector.delta) {
                (Layer::Revoked, _) | (_, Layer::Revoked) => CrliteStatus::Revoked,
                (Layer::Good, _) | (_, Layer::Good) => CrliteStatus::Good,
                (Layer::NotEnrolled, _) | (_, Layer::NotEnrolled) => CrliteStatus::NotEnrolled,
                (Layer::NotCovered, Layer::NotCovered) => CrliteStatus::NotCovered,
            };
            let stale = match live {
                CrliteStatus::Revoked => CrliteStatus::Revoked,
                _ => CrliteStatus::Expired,
            };
            let key = vector.key();
            let scts = [vector.sct];
            assert_eq!(snapshot.status(&key, &scts, time(2_999)), live);
            assert_eq!(snapshot.status(&key, &scts, time(3_000)), stale);
            *seen
                .entry(format!("{:?}+{:?}", vector.full, vector.delta))
                .or_insert(0) += 1;
        }
        // Both orders of disagreement between the layers occur: a delta
        // revokes what the full filter calls good, and a delta calls good or
        // unknown what the full filter revokes.
        for pair in [
            "Good+Revoked",
            "Revoked+NotEnrolled",
            "Revoked+NotCovered",
            "NotEnrolled+Revoked",
            "NotCovered+Revoked",
            "NotEnrolled+Good",
            "Good+NotEnrolled",
            "NotEnrolled+NotCovered",
            "NotCovered+NotCovered",
        ] {
            assert!(seen.contains_key(pair), "{pair} missing from {seen:?}");
        }
    }
}
