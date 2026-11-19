//! TLS presentation-language parsing of `SignedCertificateTimestampList`
//! (RFC 6962 §3.2, §3.3).
//!
//! Every length is checked exactly: a vector must fill its enclosing
//! vector, and a version 1 SCT must fill its `SerializedSCT`. Nothing is
//! copied; the views borrow from the list.

use super::{SctError, SctOptions};

/// `Version.v1` (RFC 6962 §3.2).
const VERSION_V1: u8 = 0;
/// Length of a `LogID`: a SHA-256 digest.
pub(super) const LOG_ID_LEN: usize = 32;

/// One `SerializedSCT` of a list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sct<'a> {
    /// A version 1 `SignedCertificateTimestamp`.
    V1(SctV1<'a>),
    /// Another version: opaque to a version 1 client, which skips it.
    UnknownVersion,
}

/// A version 1 SCT (RFC 6962 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SctV1<'a> {
    pub(super) log_id: [u8; LOG_ID_LEN],
    /// Milliseconds since the Unix epoch.
    pub(super) timestamp_ms: u64,
    /// `CtExtensions` contents, exactly as signed.
    pub(super) extensions: &'a [u8],
    /// `HashAlgorithm` of the `digitally-signed` struct (RFC 5246 §7.4.1.4.1).
    pub(super) hash_algorithm: u8,
    /// `SignatureAlgorithm` of the `digitally-signed` struct.
    pub(super) signature_algorithm: u8,
    pub(super) signature: &'a [u8],
}

/// A cursor over TLS-encoded bytes.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SctError> {
        if n > self.0.len() {
            return Err(SctError::MalformedList);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SctError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| SctError::MalformedList)
    }

    fn u8(&mut self) -> Result<u8, SctError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    /// An `opaque<0..2^16-1>` vector.
    fn vec16(&mut self) -> Result<&'a [u8], SctError> {
        let len = u16::from_be_bytes(self.array()?);
        self.take(usize::from(len))
    }

    fn at_end(&self) -> bool {
        self.0.is_empty()
    }
}

/// An iterator over a list whose outer structure [`SctList::parse`] has
/// validated.
#[derive(Clone, Copy, Debug)]
pub(super) struct SctList<'a> {
    /// The `sct_list` vector contents: one or more `SerializedSCT`.
    entries: &'a [u8],
}

impl<'a> SctList<'a> {
    /// Validates a complete `SignedCertificateTimestampList` against the
    /// size limits of `options` and returns its entries with their count.
    ///
    /// The whole list is validated before anything is returned, so a
    /// malformed or oversized list contributes no SCT.
    pub(super) fn parse(list: &'a [u8], options: &SctOptions) -> Result<(Self, usize), SctError> {
        if list.len() > options.max_list_len {
            return Err(SctError::ListTooLarge);
        }
        let mut outer = Cursor(list);
        let entries = outer.vec16()?;
        // `sct_list<1..2^16-1>`: not empty, and nothing after it.
        if entries.is_empty() || !outer.at_end() {
            return Err(SctError::MalformedList);
        }
        let parsed = Self { entries };
        let mut count = 0usize;
        let mut cursor = Cursor(entries);
        while !cursor.at_end() {
            match read_sct(&mut cursor)? {
                Sct::V1(sct)
                    if sct.extensions.len() > options.max_sct_extensions_len
                        || sct.signature.len() > options.max_signature_len =>
                {
                    return Err(SctError::SctTooLarge);
                }
                Sct::V1(_) | Sct::UnknownVersion => {}
            }
            count = count.saturating_add(1);
        }
        Ok((parsed, count))
    }
}

impl<'a> Iterator for SctList<'a> {
    type Item = Sct<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.entries.is_empty() {
            return None;
        }
        let mut cursor = Cursor(self.entries);
        // Validated by `parse`; a failure (impossible) ends the iteration.
        let sct = read_sct(&mut cursor).ok();
        self.entries = if sct.is_some() { cursor.0 } else { &[] };
        sct
    }
}

/// Reads one `SerializedSCT<1..2^16-1>`.
fn read_sct<'a>(list: &mut Cursor<'a>) -> Result<Sct<'a>, SctError> {
    let serialized = list.vec16()?;
    let mut sct = Cursor(serialized);
    // An empty `SerializedSCT` has no version: malformed.
    if sct.u8()? != VERSION_V1 {
        return Ok(Sct::UnknownVersion);
    }
    let log_id = sct.array()?;
    let timestamp_ms = u64::from_be_bytes(sct.array()?);
    let extensions = sct.vec16()?;
    let hash_algorithm = sct.u8()?;
    let signature_algorithm = sct.u8()?;
    let signature = sct.vec16()?;
    if !sct.at_end() {
        return Err(SctError::MalformedList);
    }
    Ok(Sct::V1(SctV1 {
        log_id,
        timestamp_ms,
        extensions,
        hash_algorithm,
        signature_algorithm,
        signature,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn serialized(extensions: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut sct = vec![VERSION_V1];
        sct.extend([0xab; LOG_ID_LEN]);
        sct.extend(0x0102_0304_0506_0708u64.to_be_bytes());
        sct.extend((extensions.len() as u16).to_be_bytes());
        sct.extend(extensions);
        sct.extend([4, 3]);
        sct.extend((signature.len() as u16).to_be_bytes());
        sct.extend(signature);
        sct
    }

    fn list(scts: &[Vec<u8>]) -> Vec<u8> {
        let mut entries = Vec::new();
        for sct in scts {
            entries.extend((sct.len() as u16).to_be_bytes());
            entries.extend(sct);
        }
        let mut out = (entries.len() as u16).to_be_bytes().to_vec();
        out.extend(entries);
        out
    }

    fn parse(list: &[u8]) -> Result<Vec<Sct<'_>>, SctError> {
        let (parsed, count) = SctList::parse(list, &SctOptions::default())?;
        let scts: Vec<_> = parsed.collect();
        assert_eq!(scts.len(), count);
        Ok(scts)
    }

    #[test]
    fn parses_v1_and_skips_other_versions() {
        let bytes = list(&[serialized(b"ext", b"sig"), vec![1, 0xde, 0xad], vec![0xff]]);
        let scts = parse(&bytes).unwrap();
        assert_eq!(
            scts[0],
            Sct::V1(SctV1 {
                log_id: [0xab; LOG_ID_LEN],
                timestamp_ms: 0x0102_0304_0506_0708,
                extensions: b"ext",
                hash_algorithm: 4,
                signature_algorithm: 3,
                signature: b"sig",
            })
        );
        assert_eq!(scts[1..], [Sct::UnknownVersion, Sct::UnknownVersion]);
    }

    #[test]
    fn rejects_inexact_lengths() {
        let good = list(&[serialized(b"", b"sig")]);
        assert!(parse(&good).is_ok());
        // Every truncation, and trailing bytes after the list.
        for len in 0..good.len() {
            assert_eq!(parse(&good[..len]), Err(SctError::MalformedList), "{len}");
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(parse(&trailing), Err(SctError::MalformedList));
        // An empty list and an empty SerializedSCT.
        assert_eq!(parse(&[0, 0]), Err(SctError::MalformedList));
        assert_eq!(parse(&[0, 2, 0, 0]), Err(SctError::MalformedList));
        // Bytes after the signature inside a version 1 SCT.
        let mut long = serialized(b"", b"sig");
        long.push(0);
        assert_eq!(parse(&list(&[long])), Err(SctError::MalformedList));
        // A signature vector that claims more than the SCT holds.
        let mut short = serialized(b"", b"sig");
        short.pop();
        assert_eq!(parse(&list(&[short])), Err(SctError::MalformedList));
        // A malformed entry after a valid one rejects the whole list.
        let mixed = list(&[serialized(b"", b"sig"), vec![VERSION_V1, 1, 2]]);
        assert_eq!(parse(&mixed), Err(SctError::MalformedList));
    }

    #[test]
    fn enforces_size_limits() {
        let options = SctOptions {
            max_list_len: 64,
            max_sct_extensions_len: 2,
            max_signature_len: 4,
            ..SctOptions::default()
        };
        let parse = |bytes: &[u8]| SctList::parse(bytes, &options).map(|(_, count)| count);
        assert_eq!(parse(&list(&[serialized(b"12", b"1234")])), Ok(1));
        assert_eq!(
            parse(&list(&[serialized(b"123", b"1234")])),
            Err(SctError::SctTooLarge)
        );
        assert_eq!(
            parse(&list(&[serialized(b"12", b"12345")])),
            Err(SctError::SctTooLarge)
        );
        assert_eq!(
            parse(&list(&[serialized(b"", b"1"), serialized(b"", b"1")])),
            Err(SctError::ListTooLarge)
        );
    }
}
