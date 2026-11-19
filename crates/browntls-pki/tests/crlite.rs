//! CRLite filter decoding and queries on filters encoded by the test itself.
//!
//! The encoders and the bit-by-bit membership oracle below are written from
//! the wire format and the filter's definition, independently of the crate's
//! decoder. Vectors produced by the reference implementation are checked in
//! `crlite_reference.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_pki::crlite::{
    CrliteEncoding, CrliteError, CrliteFilter, CrliteFilterStatus, CrliteKey, CrliteLimit,
    CrliteLimits, CrliteSct,
};

const LIMITS: CrliteLimits = CrliteLimits::DEFAULT;
const LOG: [u8; 32] = [0xa1; 32];
const ISSUER: [u8; 32] = [0x11; 32];

#[derive(Clone)]
struct Entry {
    issuer: [u8; 32],
    approx_m: u64,
    rank: u64,
    approx_offset: u64,
    exact_m: u64,
    exact_offset: u64,
    inverted: u8,
    exceptions: Vec<Vec<u8>>,
}

impl Entry {
    /// An empty block: nothing is encoded, so every serial is good.
    fn empty(issuer: [u8; 32]) -> Self {
        Self {
            issuer,
            approx_m: 0,
            rank: 0,
            approx_offset: 0,
            exact_m: 0,
            exact_offset: 0,
            inverted: 0,
            exceptions: Vec::new(),
        }
    }

    /// A block of issuer `[tag; 32]` from `[approx_m, rank, approx_offset,
    /// exact_m, exact_offset, inverted]`.
    fn block(tag: u8, fields: [u64; 6]) -> Self {
        let [
            approx_m,
            rank,
            approx_offset,
            exact_m,
            exact_offset,
            inverted,
        ] = fields;
        Self {
            issuer: [tag; 32],
            approx_m,
            rank,
            approx_offset,
            exact_m,
            exact_offset,
            inverted: u8::try_from(inverted).unwrap(),
            exceptions: Vec::new(),
        }
    }
}

#[derive(Clone, Default)]
struct Card {
    coverage: Vec<([u8; 32], u64, u64)>,
    index: Vec<Entry>,
    approx: Vec<Vec<u64>>,
    exact: Vec<u64>,
}

impl Card {
    /// One log covering every timestamp and the given index.
    fn with_index(index: Vec<Entry>) -> Self {
        Self {
            coverage: vec![(LOG, 0, u64::MAX)],
            index,
            ..Self::default()
        }
    }

    fn v4(&self) -> Vec<u8> {
        let u32_of = |value: u64| u32::try_from(value).unwrap().to_be_bytes();
        let mut out = vec![4, 0];
        out.extend(u16::try_from(self.coverage.len()).unwrap().to_be_bytes());
        for (log, low, high) in &self.coverage {
            out.extend(log);
            out.extend(low.to_be_bytes());
            out.extend(high.to_be_bytes());
        }
        out.extend(u32_of(self.index.len() as u64));
        for entry in &self.index {
            out.extend(entry.issuer);
            out.extend(u32_of(entry.approx_m));
            out.push(u8::try_from(entry.rank).unwrap());
            out.extend(u32_of(entry.approx_offset));
            out.extend(u32_of(entry.exact_m));
            out.extend(u32_of(entry.exact_offset));
            out.push(entry.inverted);
            out.extend(u16::try_from(entry.exceptions.len()).unwrap().to_be_bytes());
            for serial in &entry.exceptions {
                out.push(u8::try_from(serial.len()).unwrap());
                out.extend(serial);
            }
        }
        out.push(u8::try_from(self.approx.len()).unwrap());
        for column in self.approx.iter().chain([&self.exact]) {
            out.extend(u32_of(column.len() as u64));
            for word in column {
                out.extend(word.to_be_bytes());
            }
        }
        out
    }

    fn v3(&self) -> Vec<u8> {
        let len = |value: usize| (value as u64).to_le_bytes();
        let mut out = vec![3, 0];
        out.extend(len(self.coverage.len()));
        for (log, low, high) in &self.coverage {
            out.extend(log);
            out.extend(low.to_le_bytes());
            out.extend(high.to_le_bytes());
        }
        out.extend(len(self.index.len()));
        for entry in &self.index {
            out.extend(len(32));
            out.extend(entry.issuer);
            out.extend(entry.approx_m.to_le_bytes());
            out.extend(entry.exact_m.to_le_bytes());
            out.extend(entry.rank.to_le_bytes());
            out.extend(entry.approx_offset.to_le_bytes());
            out.extend(entry.exact_offset.to_le_bytes());
            out.push(entry.inverted);
            out.extend(len(entry.exceptions.len()));
            for serial in &entry.exceptions {
                out.extend(len(serial.len()));
                out.extend(serial);
            }
        }
        out.extend(len(self.approx.len()));
        for column in self.approx.iter().chain([&self.exact]) {
            out.extend(len(column.len()));
            for word in column {
                out.extend(word.to_le_bytes());
            }
        }
        out
    }

    fn both(&self) -> [Vec<u8>; 2] {
        [self.v3(), self.v4()]
    }
}

fn decode(bytes: &[u8]) -> Result<CrliteFilter, CrliteError> {
    CrliteFilter::decode(bytes, &LIMITS)
}

fn covered() -> [CrliteSct; 1] {
    [CrliteSct::from_verified(LOG, 1_000)]
}

/// SplitMix64, for reproducible test data.
struct Rng(u64);

impl Rng {
    fn word(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn digest(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.as_chunks_mut::<8>().0 {
            chunk.copy_from_slice(&self.word().to_le_bytes());
        }
        out
    }
}

/// Bit `index` of a column; bits past its end are zero.
fn bit(column: &[u64], index: u64) -> u64 {
    column
        .get(usize::try_from(index / 64).unwrap())
        .map_or(0, |word| (word >> (index % 64)) & 1)
}

/// The filter's definition, one bit at a time: whether the block encodes the
/// query as revoked.
fn oracle(card: &Card, entry: &Entry, digest: &[u8; 32], serial: &[u8]) -> bool {
    let coefficient = |j: u64| {
        let byte = digest[usize::try_from(j / 8).unwrap()];
        j == 0 || (byte >> (j % 8)) & 1 == 1
    };
    let position = u64::from_le_bytes(digest[24..].try_into().unwrap());
    let even = |column: &[u64], start: u64| {
        (0..256)
            .filter(|j| coefficient(*j))
            .fold(0, |sum, j| sum ^ bit(column, start + j))
            == 0
    };
    let member = entry.approx_m != 0
        && card
            .approx
            .iter()
            .take(usize::try_from(entry.rank).unwrap())
            .all(|column| even(column, entry.approx_offset + position % entry.approx_m))
        && even(
            &card.exact,
            entry.exact_offset + position % entry.exact_m.max(1),
        )
        && !entry.exceptions.iter().any(|exception| exception == serial);
    member != (entry.inverted == 1)
}

#[test]
fn empty_filters_cover_nothing() {
    for bytes in Card::default().both() {
        let filter = decode(&bytes).unwrap();
        assert_eq!(filter.issuer_count(), 0);
        assert_eq!(filter.coverage_len(), 0);
        let key = CrliteKey::new(ISSUER, &[1], [0; 32]);
        assert_eq!(
            filter.status(&key, &covered()),
            CrliteFilterStatus::NotCovered
        );
    }
    assert_eq!(
        decode(&Card::default().v3()).unwrap().encoding(),
        CrliteEncoding::V3
    );
    assert_eq!(
        decode(&Card::default().v4()).unwrap().encoding(),
        CrliteEncoding::V4
    );
}

#[test]
fn empty_blocks_answer_for_the_whole_issuer() {
    let mut all_revoked = Entry::empty([0x22; 32]);
    all_revoked.inverted = 1;
    let card = Card::with_index(vec![Entry::empty(ISSUER), all_revoked]);
    for bytes in card.both() {
        let filter = decode(&bytes).unwrap();
        let status = |issuer| {
            let key = CrliteKey::new(issuer, &[7, 7], [0x5a; 32]);
            filter.status(&key, &covered())
        };
        assert_eq!(status(ISSUER), CrliteFilterStatus::Good);
        assert_eq!(status([0x22; 32]), CrliteFilterStatus::Revoked);
        assert_eq!(status([0x33; 32]), CrliteFilterStatus::NotEnrolled);
    }
}

#[test]
fn coverage_is_decided_per_log_and_inclusive_interval() {
    let mut card = Card::with_index(vec![Entry::empty(ISSUER)]);
    card.coverage = vec![([0xb2; 32], 10, 10), (LOG, 100, 200)];
    for bytes in card.both() {
        let filter = decode(&bytes).unwrap();
        assert_eq!(filter.coverage_len(), 2);
        let key = CrliteKey::new(ISSUER, &[1], [0; 32]);
        let status = |scts: &[([u8; 32], u64)]| {
            let scts: Vec<CrliteSct> = scts
                .iter()
                .map(|(log, time)| CrliteSct::from_verified(*log, *time))
                .collect();
            filter.status(&key, &scts)
        };
        let (good, not_covered) = (CrliteFilterStatus::Good, CrliteFilterStatus::NotCovered);
        assert_eq!(status(&[]), not_covered);
        assert_eq!(status(&[(LOG, 99)]), not_covered);
        assert_eq!(status(&[(LOG, 100)]), good);
        assert_eq!(status(&[(LOG, 200)]), good);
        assert_eq!(status(&[(LOG, 201)]), not_covered);
        assert_eq!(status(&[([0xb2; 32], 9)]), not_covered);
        assert_eq!(status(&[([0xb2; 32], 10)]), good);
        assert_eq!(status(&[([0xb2; 32], 11)]), not_covered);
        // A timestamp of one log is not valid for another.
        assert_eq!(status(&[([0xb2; 32], 150), ([0xc3; 32], 150)]), not_covered);
        // One covered timestamp among uncovered ones suffices.
        assert_eq!(status(&[([0xc3; 32], 150), (LOG, 99), (LOG, 150)]), good);
        // An unknown issuer is reported only once the certificate is covered.
        let stranger = CrliteKey::new([0x77; 32], &[1], [0; 32]);
        assert_eq!(filter.status(&stranger, &[]), not_covered);
        assert_eq!(
            filter.status(&stranger, &[CrliteSct::from_verified(LOG, 150)]),
            CrliteFilterStatus::NotEnrolled
        );
    }
}

#[test]
fn queries_match_the_bitwise_definition() {
    let mut rng = Rng(7);
    let column = |rng: &mut Rng, words: usize| (0..words).map(|_| rng.word()).collect::<Vec<_>>();
    const MAX: u64 = u32::MAX as u64;
    let mut card = Card {
        coverage: vec![(LOG, 0, u64::MAX)],
        approx: vec![
            column(&mut rng, 9),
            column(&mut rng, 6),
            column(&mut rng, 2),
        ],
        exact: column(&mut rng, 7),
        index: vec![
            // Rank 0: only the exact filter decides.
            Entry::block(1, [100, 0, 0, 180, 3, 0]),
            // Word-aligned start (m = 1) and a start inside a word.
            Entry::block(2, [1, 1, 64, 1, 128, 0]),
            Entry::block(3, [1, 1, 77, 0, 33, 1]),
            // Windows that run past the end of shorter columns read zeros.
            Entry::block(4, [300, 3, 250, 400, 100, 0]),
            Entry::block(5, [50, 2, 500, 64, 440, 1]),
            // Entirely past the end: every product is zero.
            Entry::block(6, [9, 3, 100_000, 9, MAX, 0]),
            Entry::block(7, [MAX, 1, MAX, MAX, 0, 0]),
        ],
    };
    card.index[5].exceptions = vec![vec![9]];
    let filters = card.both().map(|bytes| decode(&bytes).unwrap());
    let mut revoked = 0;
    for entry in &card.index {
        for round in 0..400u16 {
            let digest = rng.digest();
            let serial = [9, (round >> 8) as u8, round as u8];
            let serial = if round == 0 {
                &serial[..1]
            } else {
                &serial[..]
            };
            let expected = if oracle(&card, entry, &digest, serial) {
                revoked += 1;
                CrliteFilterStatus::Revoked
            } else {
                CrliteFilterStatus::Good
            };
            let key = CrliteKey::new(entry.issuer, serial, digest);
            for filter in &filters {
                assert_eq!(
                    filter.status(&key, &covered()),
                    expected,
                    "{:?}",
                    entry.issuer[0]
                );
            }
        }
    }
    // The data exercises both answers many times.
    assert!((400..2400).contains(&revoked), "{revoked}");
}

#[test]
fn exceptions_override_the_matrices() {
    // All-zero matrices encode every query, so only exceptions are not members.
    let exceptions = vec![
        vec![0x80],
        vec![],
        vec![0x01, 0x02],
        vec![0xff; 255],
        vec![0x01],
    ];
    let mut plain = Entry::empty(ISSUER);
    plain.approx_m = 10;
    plain.exact_m = 10;
    plain.exceptions = exceptions.clone();
    let mut inverted = plain.clone();
    inverted.issuer = [0x22; 32];
    inverted.inverted = 1;
    // A neighbour's exceptions must not leak into another block.
    let mut neighbour = plain.clone();
    neighbour.issuer = [0x33; 32];
    neighbour.exceptions = vec![vec![0x42]];
    let card = Card::with_index(vec![inverted, neighbour, plain]);
    for bytes in card.both() {
        let filter = decode(&bytes).unwrap();
        let status = |issuer, serial: &[u8]| {
            filter.status(&CrliteKey::new(issuer, serial, [0x3c; 32]), &covered())
        };
        let (good, revoked) = (CrliteFilterStatus::Good, CrliteFilterStatus::Revoked);
        for serial in &exceptions {
            assert_eq!(status(ISSUER, serial), good);
            assert_eq!(status([0x22; 32], serial), revoked);
            assert_eq!(status([0x33; 32], serial), revoked);
        }
        for serial in [
            &[0x02][..],
            &[0x01, 0x02, 0x03],
            &[0x01, 0x03],
            &[0xff; 254],
            &[0x42],
        ] {
            assert_eq!(status(ISSUER, serial), revoked);
            assert_eq!(status([0x22; 32], serial), good);
        }
        assert_eq!(status([0x33; 32], &[0x42]), good);
    }
}

#[test]
fn entry_order_is_irrelevant_and_duplicates_are_rejected() {
    let mut revoked = Entry::empty([0x05; 32]);
    revoked.inverted = 1;
    let entries = vec![Entry::empty([0x09; 32]), revoked, Entry::empty([0x01; 32])];
    let mut card = Card::with_index(entries);
    card.coverage = vec![([0xee; 32], 5, 6), (LOG, 0, 2_000), ([0x01; 32], 1, 1)];
    for bytes in card.both() {
        let filter = decode(&bytes).unwrap();
        for (issuer, expected) in [
            ([0x01; 32], CrliteFilterStatus::Good),
            ([0x05; 32], CrliteFilterStatus::Revoked),
            ([0x09; 32], CrliteFilterStatus::Good),
        ] {
            let key = CrliteKey::new(issuer, &[1], [0; 32]);
            for log in [[0xee; 32], [0x01; 32], LOG] {
                let sct = [CrliteSct::from_verified(
                    log,
                    if log == [0xee; 32] { 5 } else { 1 },
                )];
                assert_eq!(filter.status(&key, &sct), expected);
            }
        }
    }

    let mut duplicate_issuer = card.clone();
    duplicate_issuer.index.push(Entry::empty([0x09; 32]));
    let mut duplicate_log = card.clone();
    duplicate_log.coverage.push((LOG, 7, 8));
    for (card, error) in [
        (duplicate_issuer, CrliteError::DuplicateIssuer),
        (duplicate_log, CrliteError::DuplicateLog),
    ] {
        for bytes in card.both() {
            assert_eq!(decode(&bytes).unwrap_err(), error);
        }
    }
}

/// A filter with every kind of field populated.
fn sample() -> Card {
    let mut entry = Entry::empty(ISSUER);
    entry.approx_m = 40;
    entry.rank = 2;
    entry.exact_m = 50;
    entry.exceptions = vec![vec![1, 2, 3], vec![]];
    Card {
        coverage: vec![(LOG, 1, 2)],
        index: vec![entry, Entry::empty([0x22; 32])],
        approx: vec![vec![1, 2], vec![3]],
        exact: vec![4, 5, 6],
    }
}

#[test]
fn header_is_checked() {
    assert_eq!(decode(&[]).unwrap_err(), CrliteError::Truncated);
    assert_eq!(decode(&[4]).unwrap_err(), CrliteError::Truncated);
    for version in [0u8, 1, 2, 5, 0xff] {
        let mut bytes = sample().v4();
        bytes[0] = version;
        assert_eq!(
            decode(&bytes).unwrap_err(),
            CrliteError::UnsupportedVersion(version)
        );
    }
    for mut bytes in sample().both() {
        bytes[1] = 1;
        assert_eq!(decode(&bytes).unwrap_err(), CrliteError::Malformed);
    }
    // A V3 body is not a V4 body, and the reverse.
    let (mut v3, mut v4) = (sample().v3(), sample().v4());
    v3[0] = 4;
    v4[0] = 3;
    assert!(decode(&v3).is_err());
    assert!(decode(&v4).is_err());
}

#[test]
fn every_truncation_and_extension_is_rejected() {
    for bytes in sample().both() {
        decode(&bytes).unwrap();
        for len in 0..bytes.len() {
            assert_eq!(
                decode(&bytes[..len]).unwrap_err(),
                CrliteError::Truncated,
                "{len}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode(&longer).unwrap_err(), CrliteError::TrailingData);
    }
}

#[test]
fn invalid_field_values_are_rejected() {
    let reject = |card: &Card, error: CrliteError| {
        for bytes in card.both() {
            assert_eq!(decode(&bytes).unwrap_err(), error);
        }
    };

    let mut card = sample();
    card.index[0].inverted = 2;
    reject(&card, CrliteError::Malformed);

    let mut card = sample();
    card.coverage[0] = (LOG, 3, 2);
    reject(&card, CrliteError::InvalidCoverageInterval);
    card.coverage[0] = (LOG, 2, 2);
    for bytes in card.both() {
        decode(&bytes).unwrap();
    }

    // A block may not consult more columns than the filter has.
    let mut card = sample();
    card.index[1].rank = 3;
    reject(&card, CrliteError::RankOutOfRange);
    card.index[1].rank = 2;
    for bytes in card.both() {
        decode(&bytes).unwrap();
    }

    // V3 can state sizes that neither V4 nor the query arithmetic admits.
    for field in 0..4 {
        let mut card = sample();
        let mut set = |value: u64| {
            let entry = &mut card.index[0];
            match field {
                0 => entry.approx_m = value,
                1 => entry.approx_offset = value,
                2 => entry.exact_m = value,
                _ => entry.exact_offset = value,
            }
            decode(&card.v3()).map(|_| ())
        };
        assert_eq!(
            set(u64::from(u32::MAX) + 1),
            Err(CrliteError::OffsetOutOfRange)
        );
        assert_eq!(set(u64::from(u32::MAX)), Ok(()));
    }
    let mut card = sample();
    card.index[0].rank = 256;
    assert_eq!(
        decode(&card.v3()).unwrap_err(),
        CrliteError::LimitExceeded(CrliteLimit::Rank)
    );

    // V3 issuer identifiers and exception serials carry 64-bit lengths.
    let v3 = Card::with_index(vec![Entry::empty(ISSUER)]).v3();
    let issuer_len = 2 + 8 + 48 + 8;
    assert_eq!(v3[issuer_len], 32);
    for len in [0u8, 31, 33] {
        let mut bytes = v3.clone();
        bytes[issuer_len] = len;
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            CrliteError::Malformed | CrliteError::Truncated
        ));
    }
    let mut card = Card::with_index(vec![Entry::empty(ISSUER)]);
    card.index[0].exceptions = vec![vec![0; 256]];
    assert_eq!(decode(&card.v3()).unwrap_err(), CrliteError::Malformed);
}

#[test]
fn limits_are_enforced() {
    let limited = |card: &Card, limits: CrliteLimits| {
        let [v3, v4] = card
            .both()
            .map(|bytes| CrliteFilter::decode(&bytes, &limits).map(|_| ()));
        assert_eq!(v3, v4);
        v4
    };
    let exceeded = |limit| Err(CrliteError::LimitExceeded(limit));
    let card = sample();

    let len = card.v4().len().max(card.v3().len());
    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_layer_len: len,
                ..LIMITS
            }
        ),
        Ok(())
    );
    assert_eq!(
        CrliteFilter::decode(
            &card.v4(),
            &CrliteLimits {
                max_layer_len: card.v4().len() - 1,
                ..LIMITS
            }
        )
        .unwrap_err(),
        CrliteError::LimitExceeded(CrliteLimit::LayerLen)
    );

    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_coverage_logs: 1,
                ..LIMITS
            }
        ),
        Ok(())
    );
    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_coverage_logs: 0,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::CoverageLogs)
    );
    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_issuers: 2,
                ..LIMITS
            }
        ),
        Ok(())
    );
    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_issuers: 1,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::Issuers)
    );
    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_exceptions: 2,
                ..LIMITS
            }
        ),
        Ok(())
    );
    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_exceptions: 1,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::Exceptions)
    );
    // The rank limit applies to blocks and to the number of columns.
    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_rank: 2,
                ..LIMITS
            }
        ),
        Ok(())
    );
    assert_eq!(
        limited(
            &card,
            CrliteLimits {
                max_rank: 1,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::Rank)
    );
    let mut columns_only = card.clone();
    columns_only.index[0].rank = 0;
    assert_eq!(
        limited(
            &columns_only,
            CrliteLimits {
                max_rank: 1,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::Rank)
    );

    // The exception limit counts across blocks.
    let mut spread = Card::with_index(vec![Entry::empty(ISSUER), Entry::empty([0x22; 32])]);
    spread.index[0].exceptions = vec![vec![1]];
    spread.index[1].exceptions = vec![vec![2]];
    assert_eq!(
        limited(
            &spread,
            CrliteLimits {
                max_exceptions: 1,
                ..LIMITS
            }
        ),
        exceeded(CrliteLimit::Exceptions)
    );
}

#[test]
fn counts_without_data_are_rejected_before_allocating() {
    // Each count claims far more items than bytes follow; with permissive
    // limits the only thing standing between it and an allocation is the
    // check against the remaining input.
    let open = CrliteLimits {
        max_layer_len: usize::MAX,
        max_total_len: usize::MAX,
        max_deltas: usize::MAX,
        max_coverage_logs: usize::MAX,
        max_issuers: usize::MAX,
        max_rank: u8::MAX,
        max_exceptions: usize::MAX,
    };
    let truncated = |bytes: &[u8]| {
        assert_eq!(
            CrliteFilter::decode(bytes, &open).unwrap_err(),
            CrliteError::Truncated
        );
    };
    let max = [0xff; 8];

    // V4: coverage, index, exceptions, approximate column words, exact words.
    truncated(&[&[4, 0][..], &max[..2]].concat());
    truncated(&[&[4, 0, 0, 0][..], &max[..4]].concat());
    let mut entry = Card::with_index(vec![Entry::empty(ISSUER)]).v4();
    entry.truncate(entry.len() - 1 - 4 - 2);
    truncated(&[&entry[..], &max[..2]].concat());
    truncated(&[&[4, 0, 0, 0, 0, 0, 0, 0, 1][..], &max[..4]].concat());
    truncated(&[&[4, 0, 0, 0, 0, 0, 0, 0, 0][..], &max[..4]].concat());

    // V3: the same counts, as 64-bit values.
    for count in [u64::MAX, 1 << 61, 1 << 32, 2] {
        let count = count.to_le_bytes();
        let zero = [0u8; 8];
        truncated(&[&[3, 0][..], &count].concat());
        truncated(&[&[3, 0][..], &zero, &count].concat());
        let mut entry = Card::with_index(vec![Entry::empty(ISSUER)]).v3();
        entry.truncate(entry.len() - 8 - 8 - 8);
        truncated(&[&entry[..], &count].concat());
        truncated(&[&[3, 0][..], &zero, &zero, &count].concat());
        truncated(&[&[3, 0][..], &zero, &zero, &[1, 0, 0, 0, 0, 0, 0, 0], &count].concat());
        truncated(&[&[3, 0][..], &zero, &zero, &zero, &count].concat());
    }
}

#[test]
fn corrupted_filters_never_panic() {
    let mut rng = Rng(99);
    let mut accepted = 0;
    for original in sample().both() {
        for _ in 0..20_000 {
            let mut bytes = original.clone();
            for _ in 0..=rng.word() % 3 {
                let at = usize::try_from(rng.word() % bytes.len() as u64).unwrap();
                bytes[at] = if rng.word().is_multiple_of(2) {
                    rng.word() as u8
                } else {
                    bytes[at] ^ (1 << (rng.word() % 8))
                };
            }
            if let Ok(filter) = decode(&bytes) {
                accepted += 1;
                for issuer in [ISSUER, [0x22; 32]] {
                    let digest = rng.digest();
                    let key = CrliteKey::new(issuer, &[1, 2, 3], digest);
                    let scts = [
                        CrliteSct::from_verified(LOG, 1),
                        CrliteSct::from_verified(LOG, rng.word()),
                    ];
                    let _ = filter.status(&key, &scts);
                }
            }
        }
    }
    assert!(accepted > 1_000, "{accepted}");
}
