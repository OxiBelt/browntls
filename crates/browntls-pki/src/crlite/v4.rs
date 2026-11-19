//! Clubcard encoding V4: big-endian integers and TLS-style length prefixes.
//!
//! ```text
//! struct {
//!     opaque log_id[32];
//!     uint64 low;
//!     uint64 high;
//! } Coverage;
//!
//! struct {
//!     opaque issuer[32];
//!     uint32 approx_filter_m;
//!     uint8  approx_filter_rank;
//!     uint32 approx_filter_offset;
//!     uint32 exact_filter_m;
//!     uint32 exact_filter_offset;
//!     uint8  inverted;
//!     uint16 exception_count;
//!     opaque exceptions<0..255>[exception_count];
//! } IndexEntry;
//!
//! struct {
//!     uint32 word_count;
//!     uint64 words[word_count];
//! } Column;
//!
//! struct {
//!     uint8      version;            /* 4 */
//!     uint8      reserved;           /* 0 */
//!     uint16     coverage_count;
//!     Coverage   coverage[coverage_count];
//!     uint32     index_count;
//!     IndexEntry index[index_count];
//!     uint8      approx_column_count;
//!     Column     approx_filter[approx_column_count];
//!     Column     exact_filter;
//! } ClubcardV4;
//! ```
//!
//! The caller has consumed `version` and `reserved`.

use alloc::vec::Vec;

use super::CrliteError;
use super::filter::{FilterBuilder, RawBlock, words};
use super::reader::Reader;

/// Encoded size of a `Coverage`.
const COVERAGE_LEN: usize = 48;
/// Encoded size of an `IndexEntry` without exceptions.
const MIN_INDEX_ENTRY_LEN: usize = 52;

pub(super) fn decode(
    reader: &mut Reader<'_>,
    builder: &mut FilterBuilder<'_>,
) -> Result<(), CrliteError> {
    let count = usize::from(reader.u16_be()?);
    reader.expect_items(count, COVERAGE_LEN)?;
    builder.begin_coverage(count)?;
    for _ in 0..count {
        let log_id = reader.array()?;
        let low = reader.u64_be()?;
        let high = reader.u64_be()?;
        builder.coverage(log_id, low, high)?;
    }

    let count = length(reader.u32_be()?)?;
    reader.expect_items(count, MIN_INDEX_ENTRY_LEN)?;
    builder.begin_index(count)?;
    for _ in 0..count {
        let issuer = reader.array()?;
        let approx_m = reader.u32_be()?;
        let approx_rank = reader.u8()?;
        let approx_offset = reader.u32_be()?;
        let exact_m = reader.u32_be()?;
        let exact_offset = reader.u32_be()?;
        let inverted = reader.bool()?;
        builder.block(&RawBlock {
            issuer,
            approx_m: u64::from(approx_m),
            approx_rank: u64::from(approx_rank),
            approx_offset: u64::from(approx_offset),
            exact_m: u64::from(exact_m),
            exact_offset: u64::from(exact_offset),
            inverted,
        })?;

        let exceptions = usize::from(reader.u16_be()?);
        reader.expect_items(exceptions, 1)?;
        builder.exceptions(exceptions)?;
        for _ in 0..exceptions {
            let len = usize::from(reader.u8()?);
            builder.exception(reader.take(len)?)?;
        }
    }

    let columns = usize::from(reader.u8()?);
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
    let count = length(reader.u32_be()?)?;
    words(reader, count, u64::from_be_bytes)
}

/// A count that must be matched by encoded bytes, so one that does not fit
/// the address space is necessarily truncated.
fn length(count: u32) -> Result<usize, CrliteError> {
    usize::try_from(count).map_err(|_| CrliteError::Truncated)
}
