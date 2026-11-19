//! One decoded Clubcard and its membership query.
//!
//! A Clubcard holds, per issuer ("block"), a slice of two GF(2) matrices: the
//! approximate filter X with `rank` columns and the exact filter Y with one
//! column. A certificate hashes to a 256-bit coefficient vector `a` and a
//! start position `s`; it is encoded as a member when the 256 bits of every
//! consulted column starting at `s` have an even inner product with `a`.
//! Members that could not be encoded this way are listed as exceptions, and a
//! block may be stored inverted (encoding the non-revoked set).

use alloc::vec::Vec;
use core::fmt;

use super::reader::Reader;
use super::{
    CrliteEncoding, CrliteError, CrliteFilterStatus, CrliteKey, CrliteLimit, CrliteLimits,
    CrliteSct, v3, v4,
};

/// Number of 64-bit limbs in a query's coefficient vector.
const LIMBS: usize = 4;

/// The timestamps of one CT log for which the filter is authoritative.
#[derive(Clone, Copy)]
struct Coverage {
    log_id: [u8; 32],
    low: u64,
    high: u64,
}

/// Index entry of one issuer.
#[derive(Clone, Copy)]
struct Block {
    issuer: [u8; 32],
    approx_m: u32,
    approx_offset: u32,
    exact_m: u32,
    exact_offset: u32,
    rank: u8,
    inverted: bool,
    /// This block's range in `CrliteFilter::exceptions`.
    exceptions_start: usize,
    exceptions_len: usize,
}

/// One exception serial, as a range of `CrliteFilter::serials`.
#[derive(Clone, Copy)]
struct Exception {
    start: usize,
    len: u8,
}

/// Index entry fields as read from the wire, before range checks.
pub(super) struct RawBlock {
    pub(super) issuer: [u8; 32],
    pub(super) approx_m: u64,
    pub(super) approx_rank: u64,
    pub(super) approx_offset: u64,
    pub(super) exact_m: u64,
    pub(super) exact_offset: u64,
    pub(super) inverted: bool,
}

/// A decoded, validated Clubcard.
///
/// The filter is immutable. Its memory use is proportional to the length of
/// the encoding it was decoded from.
pub struct CrliteFilter {
    encoding: CrliteEncoding,
    /// Sorted by log identifier, without duplicates.
    coverage: Vec<Coverage>,
    /// Sorted by issuer, without duplicates.
    blocks: Vec<Block>,
    /// Each block's range is sorted by serial.
    exceptions: Vec<Exception>,
    serials: Vec<u8>,
    approx: Vec<Vec<u64>>,
    exact: Vec<u64>,
}

impl fmt::Debug for CrliteFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrliteFilter")
            .field("encoding", &self.encoding)
            .field("coverage_len", &self.coverage.len())
            .field("issuer_count", &self.blocks.len())
            .field("exception_count", &self.exceptions.len())
            .field("approx_columns", &self.approx.len())
            .field("exact_words", &self.exact.len())
            .finish()
    }
}

impl CrliteFilter {
    /// Decodes and validates one Clubcard in encoding V3 or V4.
    ///
    /// # Errors
    ///
    /// Returns the first violation found; see [`CrliteError`]. No partially
    /// decoded filter is ever returned.
    pub fn decode(bytes: &[u8], limits: &CrliteLimits) -> Result<Self, CrliteError> {
        if bytes.len() > limits.max_layer_len {
            return Err(CrliteError::LimitExceeded(CrliteLimit::LayerLen));
        }
        let mut reader = Reader::new(bytes);
        let version = reader.u8()?;
        let encoding = match version {
            3 => CrliteEncoding::V3,
            4 => CrliteEncoding::V4,
            other => return Err(CrliteError::UnsupportedVersion(other)),
        };
        if reader.u8()? != 0 {
            return Err(CrliteError::Malformed);
        }
        let mut builder = FilterBuilder::new(encoding, limits);
        match encoding {
            CrliteEncoding::V3 => v3::decode(&mut reader, &mut builder)?,
            CrliteEncoding::V4 => v4::decode(&mut reader, &mut builder)?,
        }
        reader.finish()?;
        builder.finish()
    }

    /// The encoding this filter was decoded from.
    #[must_use]
    pub const fn encoding(&self) -> CrliteEncoding {
        self.encoding
    }

    /// Number of issuers the filter has data for.
    #[must_use]
    pub fn issuer_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of CT logs in the filter's coverage.
    #[must_use]
    pub fn coverage_len(&self) -> usize {
        self.coverage.len()
    }

    /// Looks up one certificate.
    ///
    /// The certificate is covered when at least one of `scts` lies in the
    /// coverage interval of its log. Work is linear in `scts.len()` and
    /// otherwise logarithmic in the filter's size, plus at most
    /// [`CrliteLimits::max_rank`] column evaluations.
    #[must_use]
    pub fn status(&self, key: &CrliteKey<'_>, scts: &[CrliteSct]) -> CrliteFilterStatus {
        if !scts.iter().any(|sct| self.covers(sct)) {
            return CrliteFilterStatus::NotCovered;
        }
        let Some(block) = self.block(&key.issuer) else {
            return CrliteFilterStatus::NotEnrolled;
        };
        if self.encodes(block, key) != block.inverted {
            CrliteFilterStatus::Revoked
        } else {
            CrliteFilterStatus::Good
        }
    }

    fn covers(&self, sct: &CrliteSct) -> bool {
        self.coverage
            .binary_search_by(|entry| entry.log_id.cmp(&sct.log_id))
            .ok()
            .and_then(|at| self.coverage.get(at))
            .is_some_and(|entry| entry.low <= sct.timestamp_ms && sct.timestamp_ms <= entry.high)
    }

    fn block(&self, issuer: &[u8; 32]) -> Option<&Block> {
        let at = self
            .blocks
            .binary_search_by(|block| block.issuer.cmp(issuer))
            .ok()?;
        self.blocks.get(at)
    }

    /// Whether the block's matrices encode the key, before inversion.
    fn encodes(&self, block: &Block, key: &CrliteKey<'_>) -> bool {
        // Every query evaluates to zero on an empty block, which nevertheless
        // encodes nothing.
        if block.approx_m == 0 {
            return false;
        }
        let coefficients = coefficients(&key.query);
        let position = coefficients[LIMBS - 1];

        let start = u64::from(block.approx_offset) + position % u64::from(block.approx_m);
        for column in self.approx.iter().take(usize::from(block.rank)) {
            if odd_product(column, start, &coefficients) {
                return false;
            }
        }

        let start = u64::from(block.exact_offset) + position % u64::from(block.exact_m.max(1));
        if odd_product(&self.exact, start, &coefficients) {
            return false;
        }

        !self.is_exception(block, key.serial)
    }

    fn is_exception(&self, block: &Block, serial: &[u8]) -> bool {
        let Some(exceptions) = self
            .exceptions
            .get(block.exceptions_start..)
            .and_then(|tail| tail.get(..block.exceptions_len))
        else {
            return false;
        };
        exceptions
            .binary_search_by(|exception| serial_of(&self.serials, exception).cmp(serial))
            .is_ok()
    }
}

/// The serial bytes of an exception; empty if the range is invalid, which
/// construction rules out.
fn serial_of<'a>(serials: &'a [u8], exception: &Exception) -> &'a [u8] {
    serials
        .get(exception.start..)
        .and_then(|tail| tail.get(..usize::from(exception.len)))
        .unwrap_or(&[])
}

/// Splits a query digest into little-endian limbs and sets the lowest
/// coefficient, as the filter's hash function requires.
fn coefficients(digest: &[u8; 32]) -> [u64; LIMBS] {
    let mut limbs = [0u64; LIMBS];
    for (limb, bytes) in limbs.iter_mut().zip(digest.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*bytes);
    }
    limbs[0] |= 1;
    limbs
}

/// The 64 bits of `column` starting at bit `bit`. Bits beyond the end of the
/// column are zero: encoders drop trailing zero words.
fn window(column: &[u64], bit: u64) -> u64 {
    let Ok(limb) = usize::try_from(bit / 64) else {
        return 0;
    };
    let low = column.get(limb).copied().unwrap_or(0);
    let shift = bit % 64;
    if shift == 0 {
        return low;
    }
    let high = limb
        .checked_add(1)
        .and_then(|next| column.get(next))
        .copied()
        .unwrap_or(0);
    (low >> shift) | (high << (64 - shift))
}

/// Whether the inner product over GF(2) of `coefficients` with the 256 bits
/// of `column` starting at bit `start` is one.
///
/// `start` is below 2^33 (two 32-bit values are added to form it), so the
/// additions cannot overflow.
fn odd_product(column: &[u64], start: u64, coefficients: &[u64; LIMBS]) -> bool {
    let mut bits = 0u64;
    let mut bit = start;
    for coefficient in coefficients {
        bits ^= window(column, bit) & coefficient;
        bit += 64;
    }
    bits.count_ones() % 2 == 1
}

/// Accumulates the parts of a filter while a decoder reads them, enforcing
/// limits before each allocation.
pub(super) struct FilterBuilder<'a> {
    limits: &'a CrliteLimits,
    filter: CrliteFilter,
}

impl<'a> FilterBuilder<'a> {
    fn new(encoding: CrliteEncoding, limits: &'a CrliteLimits) -> Self {
        Self {
            limits,
            filter: CrliteFilter {
                encoding,
                coverage: Vec::new(),
                blocks: Vec::new(),
                exceptions: Vec::new(),
                serials: Vec::new(),
                approx: Vec::new(),
                exact: Vec::new(),
            },
        }
    }

    /// Announces the number of coverage entries that follow.
    pub(super) fn begin_coverage(&mut self, count: usize) -> Result<(), CrliteError> {
        if count > self.limits.max_coverage_logs {
            return Err(CrliteError::LimitExceeded(CrliteLimit::CoverageLogs));
        }
        reserve(&mut self.filter.coverage, count)
    }

    pub(super) fn coverage(
        &mut self,
        log_id: [u8; 32],
        low: u64,
        high: u64,
    ) -> Result<(), CrliteError> {
        if low > high {
            return Err(CrliteError::InvalidCoverageInterval);
        }
        push(&mut self.filter.coverage, Coverage { log_id, low, high })
    }

    /// Announces the number of index entries that follow.
    pub(super) fn begin_index(&mut self, count: usize) -> Result<(), CrliteError> {
        if count > self.limits.max_issuers {
            return Err(CrliteError::LimitExceeded(CrliteLimit::Issuers));
        }
        reserve(&mut self.filter.blocks, count)
    }

    /// Adds an index entry; its exceptions follow through
    /// [`Self::exceptions`] and [`Self::exception`].
    pub(super) fn block(&mut self, raw: &RawBlock) -> Result<(), CrliteError> {
        let rank = u8::try_from(raw.approx_rank)
            .ok()
            .filter(|rank| *rank <= self.limits.max_rank)
            .ok_or(CrliteError::LimitExceeded(CrliteLimit::Rank))?;
        let size = |value: u64| u32::try_from(value).map_err(|_| CrliteError::OffsetOutOfRange);
        let block = Block {
            issuer: raw.issuer,
            approx_m: size(raw.approx_m)?,
            approx_offset: size(raw.approx_offset)?,
            exact_m: size(raw.exact_m)?,
            exact_offset: size(raw.exact_offset)?,
            rank,
            inverted: raw.inverted,
            exceptions_start: self.filter.exceptions.len(),
            exceptions_len: 0,
        };
        push(&mut self.filter.blocks, block)
    }

    /// Announces the number of exceptions of the block added last.
    pub(super) fn exceptions(&mut self, count: usize) -> Result<(), CrliteError> {
        let total = self.filter.exceptions.len().checked_add(count);
        if total.is_none_or(|total| total > self.limits.max_exceptions) {
            return Err(CrliteError::LimitExceeded(CrliteLimit::Exceptions));
        }
        reserve(&mut self.filter.exceptions, count)
    }

    /// Adds an exception serial to the block added last.
    pub(super) fn exception(&mut self, serial: &[u8]) -> Result<(), CrliteError> {
        let len = u8::try_from(serial.len()).map_err(|_| CrliteError::Malformed)?;
        let block = self
            .filter
            .blocks
            .last_mut()
            .ok_or(CrliteError::Malformed)?;
        let start = self.filter.serials.len();
        reserve(&mut self.filter.serials, serial.len())?;
        self.filter.serials.extend_from_slice(serial);
        push(&mut self.filter.exceptions, Exception { start, len })?;
        block.exceptions_len += 1;
        Ok(())
    }

    /// Announces the number of approximate-filter columns that follow.
    pub(super) fn begin_columns(&mut self, count: usize) -> Result<(), CrliteError> {
        if count > usize::from(self.limits.max_rank) {
            return Err(CrliteError::LimitExceeded(CrliteLimit::Rank));
        }
        reserve(&mut self.filter.approx, count)
    }

    pub(super) fn column(&mut self, words: Vec<u64>) -> Result<(), CrliteError> {
        push(&mut self.filter.approx, words)
    }

    pub(super) fn exact(&mut self, words: Vec<u64>) {
        self.filter.exact = words;
    }

    /// Establishes the invariants that queries rely on.
    fn finish(self) -> Result<CrliteFilter, CrliteError> {
        let mut filter = self.filter;

        filter.coverage.sort_unstable_by_key(|entry| entry.log_id);
        if filter
            .coverage
            .windows(2)
            .any(|pair| pair[0].log_id == pair[1].log_id)
        {
            return Err(CrliteError::DuplicateLog);
        }

        filter.blocks.sort_unstable_by_key(|block| block.issuer);
        if filter
            .blocks
            .windows(2)
            .any(|pair| pair[0].issuer == pair[1].issuer)
        {
            return Err(CrliteError::DuplicateIssuer);
        }

        let serials = &filter.serials;
        for block in &filter.blocks {
            if usize::from(block.rank) > filter.approx.len() {
                return Err(CrliteError::RankOutOfRange);
            }
            let exceptions = filter
                .exceptions
                .get_mut(block.exceptions_start..)
                .and_then(|tail| tail.get_mut(..block.exceptions_len))
                .ok_or(CrliteError::Malformed)?;
            exceptions.sort_unstable_by(|left, right| {
                serial_of(serials, left).cmp(serial_of(serials, right))
            });
        }
        Ok(filter)
    }
}

/// Reads `count` 64-bit words with the given byte order.
pub(super) fn words(
    reader: &mut Reader<'_>,
    count: usize,
    decode: fn([u8; 8]) -> u64,
) -> Result<Vec<u64>, CrliteError> {
    let len = count.checked_mul(8).ok_or(CrliteError::Truncated)?;
    let bytes = reader.take(len)?;
    let mut words = Vec::new();
    reserve(&mut words, count)?;
    words.extend(bytes.as_chunks::<8>().0.iter().map(|chunk| decode(*chunk)));
    Ok(words)
}

fn reserve<T>(vec: &mut Vec<T>, additional: usize) -> Result<(), CrliteError> {
    vec.try_reserve_exact(additional)
        .map_err(|_| CrliteError::AllocationFailed)
}

fn push<T>(vec: &mut Vec<T>, value: T) -> Result<(), CrliteError> {
    if vec.len() == vec.capacity() {
        reserve(vec, 1)?;
    }
    vec.push(value);
    Ok(())
}
