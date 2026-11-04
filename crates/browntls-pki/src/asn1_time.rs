//! `UTCTime` and `GeneralizedTime` decoding (RFC 5280 §4.1.2.5).
//!
//! Only the forms RFC 5280 permits are accepted: `YYMMDDHHMMSSZ` for
//! `UTCTime` and `YYYYMMDDHHMMSSZ` for `GeneralizedTime`, with no fractional
//! seconds and no local time offsets. `UTCTime` years 50..=99 are 1950..=1999
//! and 00..=49 are 2000..=2049. Dates before the Unix epoch are rejected.

use crate::UnixTime;
use crate::der::{Reader, tag};
use crate::error::Error;

/// Reads a `Time` value (`UTCTime` or `GeneralizedTime`).
pub(crate) fn read_time(reader: &mut Reader<'_>) -> Result<UnixTime, Error> {
    let tlv = reader.tlv().map_err(|_| Error::BadDerTime)?;
    let (digits, year): (&[u8], u64) = match (tlv.tag, tlv.value) {
        (tag::UTC_TIME, [y0, y1, rest @ ..]) if rest.len() == 11 => {
            let yy = two_digits(*y0, *y1, 0, 99)?;
            (rest, if yy >= 50 { 1900 + yy } else { 2000 + yy })
        }
        (tag::GENERALIZED_TIME, [y0, y1, y2, y3, rest @ ..]) if rest.len() == 11 => {
            let hi = two_digits(*y0, *y1, 0, 99)?;
            let lo = two_digits(*y2, *y3, 0, 99)?;
            (rest, hi * 100 + lo)
        }
        _ => return Err(Error::BadDerTime),
    };
    let [m0, m1, d0, d1, h0, h1, i0, i1, s0, s1, b'Z'] = *digits else {
        return Err(Error::BadDerTime);
    };
    let month = two_digits(m0, m1, 1, 12)?;
    let day = two_digits(d0, d1, 1, days_in_month(year, month))?;
    let hour = two_digits(h0, h1, 0, 23)?;
    let minute = two_digits(i0, i1, 0, 59)?;
    let second = two_digits(s0, s1, 0, 59)?;
    unix_time(year, month, day, hour, minute, second)
}

fn two_digits(hi: u8, lo: u8, min: u64, max: u64) -> Result<u64, Error> {
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        return Err(Error::BadDerTime);
    }
    let value = u64::from(hi - b'0') * 10 + u64::from(lo - b'0');
    if value < min || value > max {
        return Err(Error::BadDerTime);
    }
    Ok(value)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        _ => 28,
    }
}

/// Days from 0000-03-01 in the proleptic Gregorian calendar, counting
/// before the given year's 1 January. `year >= 1`.
fn days_before_year(year: u64) -> u64 {
    let y = year - 1;
    y * 365 + y / 4 - y / 100 + y / 400
}

/// Days from 1 January of `year` to 1 January 1970 (positive for years
/// at or after the epoch).
const DAYS_BEFORE_EPOCH: u64 = 1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400;

fn unix_time(
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
) -> Result<UnixTime, Error> {
    if year < 1970 {
        return Err(Error::BadDerTime);
    }
    let mut days = days_before_year(year) - DAYS_BEFORE_EPOCH;
    for m in 1..month {
        days += days_in_month(year, m);
    }
    days += day - 1;
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Ok(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
        secs,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> Result<u64, Error> {
        read_time(&mut Reader::new(bytes)).map(|t| t.as_secs())
    }

    #[test]
    fn utc_and_generalized() {
        // 2017-04-17T15:08:36Z
        assert_eq!(parse(b"\x17\x0d170417150836Z"), Ok(1_492_441_716));
        assert_eq!(parse(b"\x18\x0f20170417150836Z"), Ok(1_492_441_716));
        // Epoch and a 1999 UTCTime.
        assert_eq!(parse(b"\x17\x0d700101000000Z"), Ok(0));
        assert_eq!(parse(b"\x17\x0d991231235959Z"), Ok(946_684_799));
        // 2000-02-29 is a leap day; 2100-02-29 is not.
        assert_eq!(parse(b"\x18\x0f20000229000000Z"), Ok(951_782_400));
        assert_eq!(parse(b"\x18\x0f21000229000000Z"), Err(Error::BadDerTime));
        // 4096-01-01 (rcgen default notAfter).
        assert_eq!(parse(b"\x18\x0f40960101000000Z"), Ok(67_090_118_400));
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            &b"\x17\x0d690101000000Z"[..], // before the epoch
            b"\x17\x0c70010100000Z",       // too short
            b"\x17\x0e7001010000000Z",     // too long
            b"\x17\x0d700101000000+",      // bad zone
            b"\x17\x0d701301000000Z",      // month 13
            b"\x17\x0d700132000000Z",      // day 32
            b"\x17\x0d700101240000Z",      // hour 24
            b"\x17\x0d700101006000Z",      // minute 60
            b"\x17\x0d700101000060Z",      // leap second
            b"\x17\x0d7001010000a0Z",      // non-digit
            b"\x18\x0d700101000000Z",      // generalized with two-digit year
            b"\x18\x1120170417150836.5Z",  // fractional seconds
            b"\x04\x0d700101000000Z",      // wrong tag
            b"\x17",                       // truncated
        ] {
            assert_eq!(parse(bad), Err(Error::BadDerTime), "{bad:?}");
        }
    }
}
