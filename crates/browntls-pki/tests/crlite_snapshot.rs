//! CRLite snapshot validation, metadata and status precedence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_pki::UnixTime;
use browntls_pki::crlite::{
    CrliteDelta, CrliteError, CrliteKey, CrliteLayer, CrliteLimit, CrliteLimits, CrliteSct,
    CrliteSnapshot, CrliteSnapshotSource, CrliteStatus,
};
use core::time::Duration;

const LIMITS: CrliteLimits = CrliteLimits::DEFAULT;
const LOG: [u8; 32] = [0xa1; 32];
const OTHER_LOG: [u8; 32] = [0xb2; 32];
const ISSUER: [u8; 32] = [0x11; 32];
const OTHER_ISSUER: [u8; 32] = [0x22; 32];

/// What a test filter says about every serial of one issuer.
#[derive(Clone, Copy)]
enum Verdict {
    Good,
    Revoked,
}

/// A V4 filter covering every timestamp of `log`, in which each listed
/// issuer has an empty block: all of its serials are good, or (inverted) all
/// are revoked.
fn filter(log: [u8; 32], issuers: &[([u8; 32], Verdict)]) -> Vec<u8> {
    let mut out = vec![4, 0, 0, 1];
    out.extend(log);
    out.extend(0u64.to_be_bytes());
    out.extend(u64::MAX.to_be_bytes());
    out.extend(u32::try_from(issuers.len()).unwrap().to_be_bytes());
    for (issuer, verdict) in issuers {
        out.extend(issuer);
        out.extend([0; 17]);
        out.push(matches!(verdict, Verdict::Revoked).into());
        out.extend([0; 2]);
    }
    out.extend([0; 5]);
    out
}

fn time(seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
}

/// Numbers the layers 1, 2, 3, ... as the deltas of a full filter.
fn numbered<'a>(layers: &[CrliteLayer<'a>]) -> Vec<CrliteDelta<'a>> {
    (1..)
        .zip(layers)
        .map(|(number, layer)| CrliteDelta {
            number,
            layer: *layer,
        })
        .collect()
}

/// The tip a channel states when `deltas` is everything it lists.
fn tip(deltas: &[CrliteDelta<'_>]) -> u32 {
    u32::try_from(deltas.len()).unwrap()
}

/// A snapshot effective at 100, 200, ... per layer and expiring at 10 000.
fn snapshot(layers: &[Vec<u8>]) -> Result<CrliteSnapshot, CrliteError> {
    let layers: Vec<CrliteLayer<'_>> = (1..)
        .zip(layers)
        .map(|(n, clubcard)| CrliteLayer {
            effective: time(100 * n),
            clubcard,
        })
        .collect();
    let deltas = numbered(&layers[1..]);
    CrliteSnapshot::new(
        &CrliteSnapshotSource {
            generation: 1,
            expiry: time(10_000),
            full: layers[0],
            deltas: &deltas,
            delta_tip: tip(&deltas),
        },
        &LIMITS,
    )
}

fn status(snapshot: &CrliteSnapshot, issuer: [u8; 32], log: [u8; 32], now: u64) -> CrliteStatus {
    let key = CrliteKey::new(issuer, &[1, 2, 3], [0x5a; 32]);
    snapshot.status(&key, &[CrliteSct::from_verified(log, 1)], time(now))
}

#[test]
fn snapshot_is_shareable_and_exposes_its_metadata() {
    fn shareable<T: Send + Sync + 'static>() {}
    shareable::<CrliteSnapshot>();

    let full = filter(LOG, &[(ISSUER, Verdict::Good)]);
    let delta = filter(LOG, &[]);
    let source = CrliteSnapshotSource {
        generation: 42,
        expiry: time(900),
        full: CrliteLayer {
            effective: time(100),
            clubcard: &full,
        },
        deltas: &numbered(&[
            CrliteLayer {
                effective: time(200),
                clubcard: &delta,
            },
            CrliteLayer {
                effective: time(201),
                clubcard: &delta,
            },
        ]),
        delta_tip: 2,
    };
    let snapshot = CrliteSnapshot::new(&source, &LIMITS).unwrap();
    assert_eq!(snapshot.generation(), 42);
    assert_eq!(snapshot.expiry(), time(900));
    assert_eq!(snapshot.effective(), time(201));
    assert_eq!(snapshot.delta_count(), 2);
    assert!(!snapshot.is_expired(time(0)));
    assert!(!snapshot.is_expired(time(899)));
    assert!(snapshot.is_expired(time(900)));
    assert!(snapshot.is_expired(time(u64::MAX)));

    let full_only = CrliteSnapshot::new(
        &CrliteSnapshotSource {
            deltas: &[],
            delta_tip: 0,
            ..source
        },
        &LIMITS,
    )
    .unwrap();
    assert_eq!(full_only.delta_count(), 0);
    assert_eq!(full_only.effective(), time(100));

    let newer = CrliteSnapshot::new(
        &CrliteSnapshotSource {
            generation: 43,
            ..source
        },
        &LIMITS,
    )
    .unwrap();
    assert!(newer.supersedes(&snapshot));
    assert!(!snapshot.supersedes(&newer));
    assert!(!snapshot.supersedes(&snapshot));
}

#[test]
fn layers_must_be_ordered_and_expire_later() {
    let card = filter(LOG, &[]);
    let build = |full: u64, deltas: &[u64], expiry: u64| {
        let deltas: Vec<CrliteLayer<'_>> = deltas
            .iter()
            .map(|at| CrliteLayer {
                effective: time(*at),
                clubcard: &card,
            })
            .collect();
        let deltas = numbered(&deltas);
        CrliteSnapshot::new(
            &CrliteSnapshotSource {
                generation: 0,
                expiry: time(expiry),
                full: CrliteLayer {
                    effective: time(full),
                    clubcard: &card,
                },
                deltas: &deltas,
                delta_tip: tip(&deltas),
            },
            &LIMITS,
        )
        .map(|_| ())
    };
    assert_eq!(build(10, &[11, 12, 13], 14), Ok(()));
    assert_eq!(build(10, &[], 11), Ok(()));
    // A delta may not precede or coincide with its predecessor.
    assert_eq!(build(10, &[10], 99), Err(CrliteError::LayerOutOfOrder));
    assert_eq!(build(10, &[9], 99), Err(CrliteError::LayerOutOfOrder));
    assert_eq!(build(10, &[11, 11], 99), Err(CrliteError::LayerOutOfOrder));
    assert_eq!(
        build(10, &[12, 11, 13], 99),
        Err(CrliteError::LayerOutOfOrder)
    );
    // The snapshot must outlive its newest layer.
    assert_eq!(
        build(10, &[], 10),
        Err(CrliteError::ExpiryNotAfterEffective)
    );
    assert_eq!(build(10, &[], 0), Err(CrliteError::ExpiryNotAfterEffective));
    assert_eq!(
        build(10, &[20], 20),
        Err(CrliteError::ExpiryNotAfterEffective)
    );
    assert_eq!(
        build(10, &[20], 15),
        Err(CrliteError::ExpiryNotAfterEffective)
    );
}

#[test]
fn deltas_must_be_contiguous_and_reach_the_authenticated_tip() {
    let card = filter(LOG, &[]);
    // Deltas with the given numbers, effective in the order given.
    let build = |numbers: &[u32], delta_tip: u32| {
        let deltas: Vec<CrliteDelta<'_>> = (11..)
            .zip(numbers)
            .map(|(at, number)| CrliteDelta {
                number: *number,
                layer: CrliteLayer {
                    effective: time(at),
                    clubcard: &card,
                },
            })
            .collect();
        CrliteSnapshot::new(
            &CrliteSnapshotSource {
                generation: 0,
                expiry: time(99),
                full: CrliteLayer {
                    effective: time(10),
                    clubcard: &card,
                },
                deltas: &deltas,
                delta_tip,
            },
            &LIMITS,
        )
        .map(|snapshot| snapshot.delta_count())
    };
    let out_of_sequence = Err(CrliteError::DeltaOutOfSequence);
    let tip_mismatch = Err(CrliteError::DeltaTipMismatch);

    assert_eq!(build(&[], 0), Ok(0));
    assert_eq!(build(&[1], 1), Ok(1));
    assert_eq!(build(&[1, 2, 3, 4], 4), Ok(4));

    // A delta missing from the middle.
    assert_eq!(build(&[1, 3], 3), out_of_sequence);
    assert_eq!(build(&[1, 3], 2), out_of_sequence);
    assert_eq!(build(&[1, 2, 4, 5], 5), out_of_sequence);
    // The first delta missing.
    assert_eq!(build(&[2], 2), out_of_sequence);
    assert_eq!(build(&[2, 3], 3), out_of_sequence);
    assert_eq!(build(&[0], 0), out_of_sequence);
    assert_eq!(build(&[0, 1], 1), out_of_sequence);
    // Repeated or reordered deltas.
    assert_eq!(build(&[1, 1], 1), out_of_sequence);
    assert_eq!(build(&[1, 2, 2], 2), out_of_sequence);
    assert_eq!(build(&[2, 1], 2), out_of_sequence);
    assert_eq!(build(&[1, 3, 2], 3), out_of_sequence);
    assert_eq!(build(&[u32::MAX], u32::MAX), out_of_sequence);

    // Deltas missing from the end: the channel lists more than were given.
    assert_eq!(build(&[], 1), tip_mismatch);
    assert_eq!(build(&[1], 2), tip_mismatch);
    assert_eq!(build(&[1, 2], 4), tip_mismatch);
    assert_eq!(build(&[1, 2], u32::MAX), tip_mismatch);
    // Deltas the channel does not list.
    assert_eq!(build(&[1], 0), tip_mismatch);
    assert_eq!(build(&[1, 2, 3], 2), tip_mismatch);
}

#[test]
fn snapshot_limits_and_layer_errors_reject_the_whole_snapshot() {
    let card = filter(LOG, &[(ISSUER, Verdict::Good)]);
    let layers = [
        CrliteLayer {
            effective: time(1),
            clubcard: &card,
        },
        CrliteLayer {
            effective: time(2),
            clubcard: &card,
        },
        CrliteLayer {
            effective: time(3),
            clubcard: &card,
        },
    ];
    let build = |deltas: &[CrliteLayer<'_>], limits: CrliteLimits| {
        let deltas = numbered(deltas);
        let source = CrliteSnapshotSource {
            generation: 0,
            expiry: time(99),
            full: layers[0],
            deltas: &deltas,
            delta_tip: tip(&deltas),
        };
        CrliteSnapshot::new(&source, &limits).map(|_| ())
    };
    let exceeded = |limit| Err(CrliteError::LimitExceeded(limit));

    assert_eq!(
        build(
            &layers[1..],
            CrliteLimits {
                max_deltas: 2,
                ..LIMITS
            }
        ),
        Ok(())
    );
    assert_eq!(
        build(
            &layers[1..],
            CrliteLimits {
                max_deltas: 1,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::Deltas)
    );
    assert_eq!(
        build(
            &[],
            CrliteLimits {
                max_deltas: 0,
                ..LIMITS
            }
        ),
        Ok(())
    );

    let total = 3 * card.len();
    assert_eq!(
        build(
            &layers[1..],
            CrliteLimits {
                max_total_len: total,
                ..LIMITS
            }
        ),
        Ok(())
    );
    assert_eq!(
        build(
            &layers[1..],
            CrliteLimits {
                max_total_len: total - 1,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::TotalLen)
    );
    assert_eq!(
        build(
            &layers[1..],
            CrliteLimits {
                max_layer_len: card.len() - 1,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::LayerLen)
    );

    // One malformed layer, wherever it is, fails the snapshot.
    let broken = &card[..card.len() - 1];
    for at in 0..3 {
        let mut layers = layers;
        layers[at].clubcard = broken;
        let source = CrliteSnapshotSource {
            generation: 0,
            expiry: time(99),
            full: layers[0],
            deltas: &numbered(&layers[1..]),
            delta_tip: 2,
        };
        assert_eq!(
            CrliteSnapshot::new(&source, &LIMITS).unwrap_err(),
            CrliteError::Truncated
        );
    }
}

#[test]
fn revoked_takes_precedence_in_either_layer() {
    let good = filter(LOG, &[(ISSUER, Verdict::Good)]);
    let revoked = filter(LOG, &[(ISSUER, Verdict::Revoked)]);
    let silent = filter(LOG, &[]);
    for layers in [
        vec![revoked.clone()],
        vec![revoked.clone(), good.clone()],
        vec![good.clone(), revoked.clone()],
        vec![good.clone(), revoked.clone(), good.clone(), silent.clone()],
        vec![silent.clone(), good.clone(), good.clone(), revoked.clone()],
    ] {
        let snapshot = snapshot(&layers).unwrap();
        assert_eq!(status(&snapshot, ISSUER, LOG, 500), CrliteStatus::Revoked);
        // A different issuer is unaffected.
        assert_eq!(
            status(&snapshot, OTHER_ISSUER, LOG, 500),
            CrliteStatus::NotEnrolled
        );
    }
}

#[test]
fn unanswerable_statuses_are_distinct() {
    let good = filter(LOG, &[(ISSUER, Verdict::Good)]);
    let silent = filter(LOG, &[]);
    let elsewhere = filter(OTHER_LOG, &[(OTHER_ISSUER, Verdict::Good)]);

    // Good needs one covering filter with data; the others may be silent.
    for layers in [
        vec![good.clone()],
        vec![silent.clone(), good.clone()],
        vec![good.clone(), silent.clone(), elsewhere.clone()],
    ] {
        let snapshot = snapshot(&layers).unwrap();
        assert_eq!(status(&snapshot, ISSUER, LOG, 500), CrliteStatus::Good);
    }

    let snapshot = snapshot(&[silent, elsewhere]).unwrap();
    // Covered by the first layer, whose index lacks the issuer.
    assert_eq!(
        status(&snapshot, ISSUER, LOG, 500),
        CrliteStatus::NotEnrolled
    );
    // The second layer has the issuer but does not cover this log.
    assert_eq!(
        status(&snapshot, OTHER_ISSUER, LOG, 500),
        CrliteStatus::NotEnrolled
    );
    assert_eq!(
        status(&snapshot, OTHER_ISSUER, OTHER_LOG, 500),
        CrliteStatus::Good
    );
    assert_eq!(
        status(&snapshot, ISSUER, [0xc3; 32], 500),
        CrliteStatus::NotCovered
    );
    let key = CrliteKey::new(ISSUER, &[1], [0; 32]);
    assert_eq!(
        snapshot.status(&key, &[], time(500)),
        CrliteStatus::NotCovered
    );
}

#[test]
fn expired_early_and_missing_snapshots_answer_as_documented() {
    let layers = [
        filter(LOG, &[(ISSUER, Verdict::Good)]),
        filter(LOG, &[(OTHER_ISSUER, Verdict::Revoked)]),
    ];
    let snapshot = snapshot(&layers).unwrap();
    let key = CrliteKey::new(ISSUER, &[1], [0; 32]);
    let scts = [CrliteSct::from_verified(LOG, 1)];

    assert_eq!(status(&snapshot, ISSUER, LOG, 9_999), CrliteStatus::Good);
    for now in [10_000, 10_001, u64::MAX] {
        // No stale filter vouches for a certificate ...
        assert_eq!(status(&snapshot, ISSUER, LOG, now), CrliteStatus::Expired);
        assert_eq!(
            status(&snapshot, [0x33; 32], LOG, now),
            CrliteStatus::Expired
        );
        assert_eq!(
            status(&snapshot, ISSUER, OTHER_LOG, now),
            CrliteStatus::Expired
        );
        assert_eq!(snapshot.status(&key, &[], time(now)), CrliteStatus::Expired);
        // ... but a revocation it recorded still stands.
        assert_eq!(
            status(&snapshot, OTHER_ISSUER, LOG, now),
            CrliteStatus::Revoked
        );
    }

    // Before the newest layer is effective, only negative evidence is usable.
    for now in [0, 99, 100, 199] {
        assert_eq!(
            status(&snapshot, ISSUER, LOG, now),
            CrliteStatus::NotYetEffective
        );
        assert_eq!(
            status(&snapshot, OTHER_ISSUER, LOG, now),
            CrliteStatus::Revoked
        );
        assert_eq!(
            status(&snapshot, [0x33; 32], LOG, now),
            CrliteStatus::NotYetEffective
        );
        assert_eq!(
            status(&snapshot, ISSUER, OTHER_LOG, now),
            CrliteStatus::NotYetEffective
        );
    }

    assert_eq!(
        CrliteSnapshot::status_of(None, &key, &scts, time(500)),
        CrliteStatus::Missing
    );
    assert_eq!(
        CrliteSnapshot::status_of(Some(&snapshot), &key, &scts, time(500)),
        CrliteStatus::Good
    );
    assert_eq!(
        CrliteSnapshot::status_of(Some(&snapshot), &key, &scts, time(10_000)),
        CrliteStatus::Expired
    );
}
