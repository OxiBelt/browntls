//! Snapshot construction and reference lookups over bounded Clubcard inputs.

use browntls_core::revocation::RevocationDigests;
use browntls_pki::crlite::{
    CrliteDelta, CrliteEncoding, CrliteFilter, CrliteKey, CrliteLayer, CrliteLimits, CrliteSct,
    CrliteSnapshot, CrliteSnapshotSource, CrliteStatus,
};

use super::fixtures::time;

pub(super) const FULL_V3: &[u8] =
    include_bytes!("../../../crates/browntls-pki/tests/data/crlite/full-v3.clubcard");
pub(super) const FULL_V4: &[u8] =
    include_bytes!("../../../crates/browntls-pki/tests/data/crlite/full-v4.clubcard");
const DELTA_V4: &[u8] =
    include_bytes!("../../../crates/browntls-pki/tests/data/crlite/delta-v4.clubcard");

const LIMITS: CrliteLimits = CrliteLimits {
    max_layer_len: 64 * 1024,
    ..CrliteLimits::DEFAULT
};

pub(super) fn filter(bytes: &[u8]) {
    let Ok(filter) = CrliteFilter::decode(bytes, &LIMITS) else {
        return;
    };
    let issuer = bytes
        .get(..32)
        .and_then(|v| v.try_into().ok())
        .unwrap_or([0; 32]);
    let serial = bytes.get(32..40).unwrap_or(&[0]);
    let digest = (RevocationDigests::native().sha256)(&[issuer.as_slice(), serial].concat());
    let key = CrliteKey::new(issuer, serial, digest);
    let timestamp = bytes
        .get(40..48)
        .and_then(|v| v.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0);
    let _ = filter.status(&key, &[CrliteSct::from_verified(issuer, timestamp)]);
    if bytes == FULL_V3 || bytes == FULL_V4 {
        let expected = if bytes == FULL_V3 {
            CrliteEncoding::V3
        } else {
            CrliteEncoding::V4
        };
        assert_eq!(filter.encoding(), expected);
        assert_eq!((filter.issuer_count(), filter.coverage_len()), (5, 2));
    }
}

pub(super) fn snapshot(generation: u64) -> CrliteSnapshot {
    build_snapshot(FULL_V4, generation, 1).unwrap()
}

fn build_snapshot(
    full: &[u8],
    generation: u64,
    delta_number: u32,
) -> Result<CrliteSnapshot, browntls_pki::crlite::CrliteError> {
    CrliteSnapshot::new(
        &CrliteSnapshotSource {
            generation,
            expiry: time(3000),
            full: CrliteLayer {
                effective: time(1000),
                clubcard: full,
            },
            deltas: &[CrliteDelta {
                number: delta_number,
                layer: CrliteLayer {
                    effective: time(2000),
                    clubcard: DELTA_V4,
                },
            }],
            delta_tip: 1,
        },
        &LIMITS,
    )
}

pub(super) fn run(bytes: &[u8]) {
    let Some((&number, full)) = bytes.split_first() else {
        let current = snapshot(2);
        assert!(current.supersedes(&snapshot(1)));
        assert_eq!(current.generation(), 2);
        assert_eq!(current.effective(), time(2000));
        assert_eq!(current.expiry(), time(3000));
        assert_eq!(current.delta_count(), 1);
        assert!(current.is_expired(time(3000)));

        // The reference full filter lists this serial as good and the delta
        // marks it revoked (see tests/data/crlite/expected.txt).
        let issuer = [0x11; 32];
        let serial = [0x11, 0x00, 0x03];
        let digest = (RevocationDigests::native().sha256)(&[issuer.as_slice(), &serial].concat());
        let key = CrliteKey::new(issuer, &serial, digest);
        let scts = [CrliteSct::from_verified([0xa1; 32], 1500)];
        assert_eq!(
            current.status(&key, &scts, time(2500)),
            CrliteStatus::Revoked
        );
        assert_eq!(
            CrliteSnapshot::status_of(Some(&current), &key, &scts, time(2500)),
            CrliteStatus::Revoked
        );
        return;
    };
    let full = if full.is_empty() { FULL_V4 } else { full };
    let result = build_snapshot(full, 1, u32::from(number));
    if number != 1 {
        assert!(matches!(
            result,
            Err(browntls_pki::crlite::CrliteError::DeltaOutOfSequence)
        ));
    }
}
