//! Clubcard encoding V3: fixed-width little-endian fields.
//!
//! V3 is the serialization the first Clubcard release produced by deriving
//! it from its in-memory structures: every integer and every length is a
//! little-endian `uint64`, booleans are one byte, fixed-size arrays have no
//! length, and maps and sequences are prefixed by their entry count.
//!
//! ```text
//! struct {
//!     opaque log_id[32];
//!     uint64 low;
//!     uint64 high;
//! } Coverage;
//!
//! struct {
//!     uint64 issuer_len;             /* 32 */
//!     opaque issuer[issuer_len];
//!     uint64 approx_filter_m;
//!     uint64 exact_filter_m;
//!     uint64 approx_filter_rank;
//!     uint64 approx_filter_offset;
//!     uint64 exact_filter_offset;
//!     uint8  inverted;
//!     uint64 exception_count;
//!     struct {
//!         uint64 len;
//!         opaque serial[len];
//!     } exceptions[exception_count];
//! } IndexEntry;
//!
//! struct {
//!     uint64 word_count;
//!     uint64 words[word_count];
//! } Column;
//!
//! struct {
//!     uint8      version;            /* 3 */
//!     uint8      reserved;           /* 0 */
//!     uint64     coverage_count;
//!     Coverage   coverage[coverage_count];
//!     uint64     index_count;
//!     IndexEntry index[index_count];
//!     uint64     approx_column_count;
//!     Column     approx_filter[approx_column_count];
//!     Column     exact_filter;
//! } ClubcardV3;
//! ```
//!
//! The caller has consumed `version` and `reserved`. Note that the two `m`
//! fields precede the rank here, unlike in V4.

use alloc::vec::Vec;

use super::CrliteError;
use super::filter::{FilterBuilder, RawBlock, words};
use super::reader::Reader;

/// Encoded size of a `Coverage`.
const COVERAGE_LEN: usize = 48;
/// Encoded size of an `IndexEntry` without exceptions.
const MIN_INDEX_ENTRY_LEN: usize = 89;
/// Encoded size of the smallest exception or column: its length.
const LENGTH_LEN: usize = 8;

pub(super) fn decode(
    reader: &mut Reader<'_>,
    builder: &mut FilterBuilder<'_>,
) -> Result<(), CrliteError> {
    let count = length(reader)?;
    reader.expect_items(count, COVERAGE_LEN)?;
    builder.begin_coverage(count)?;
    for _ in 0..count {
        let log_id = reader.array()?;
        let low = reader.u64_le()?;
        let high = reader.u64_le()?;
        builder.coverage(log_id, low, high)?;
    }

    let count = length(reader)?;
    reader.expect_items(count, MIN_INDEX_ENTRY_LEN)?;
    builder.begin_index(count)?;
    for _ in 0..count {
        if reader.u64_le()? != 32 {
            return Err(CrliteError::Malformed);
        }
        let issuer = reader.array()?;
        let approx_m = reader.u64_le()?;
        let exact_m = reader.u64_le()?;
        let approx_rank = reader.u64_le()?;
        let approx_offset = reader.u64_le()?;
        let exact_offset = reader.u64_le()?;
        let inverted = reader.bool()?;
        builder.block(&RawBlock {
            issuer,
            approx_m,
            approx_rank,
            approx_offset,
            exact_m,
            exact_offset,
            inverted,
        })?;

        let exceptions = length(reader)?;
        reader.expect_items(exceptions, LENGTH_LEN)?;
        builder.exceptions(exceptions)?;
        for _ in 0..exceptions {
            let len = length(reader)?;
            builder.exception(reader.take(len)?)?;
        }
    }

    let columns = length(reader)?;
    reader.expect_items(columns, LENGTH_LEN)?;
    builder.begin_columns(columns)?;
    for _ in 0..columns {
        let column = column(reader)?;
        builder.column(column)?;
    }
    let exact = column(reader)?;
    builder.exact(exact);
    Ok(())
}

fn column(reader: &mut Reader<'_>) -> Result<Vec<u64>, CrliteError> {
    let count = length(reader)?;
    words(reader, count, u64::from_le_bytes)
}

/// A count that must be matched by encoded bytes, so one that does not fit
/// the address space is necessarily truncated.
fn length(reader: &mut Reader<'_>) -> Result<usize, CrliteError> {
    usize::try_from(reader.u64_le()?).map_err(|_| CrliteError::Truncated)
}
