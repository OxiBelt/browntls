//! X.509 `Extensions` (RFC 5280 §4.1.2.9, §5.1.2.7, §5.3) shared by the
//! certificate and CRL parsers.

use crate::der::{self, Reader, tag};
use crate::error::Error;

/// How to treat an extension this crate does not implement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnknownExtensionPolicy {
    /// Reject critical unknown extensions (RFC 5280 §4.2); ignore others.
    Strict,
    /// Ignore unknown extensions even when critical. Used for trust anchors,
    /// whose extensions a relying party may ignore (RFC 5280 §6.2).
    IgnoreCritical,
}

/// One decoded `Extension`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Extension<'a> {
    /// `extnID` contents.
    pub(crate) id: &'a [u8],
    /// `critical`.
    pub(crate) critical: bool,
    /// `extnValue` contents (the DER encoding of the extension's own type).
    pub(crate) value: &'a [u8],
}

impl<'a> Extension<'a> {
    fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
        reader.nested(tag::SEQUENCE, |ext| {
            let id = ext.oid()?;
            let critical = ext.default_false_boolean()?;
            let value = ext.expect(tag::OCTET_STRING)?;
            Ok(Extension {
                id,
                critical,
                value,
            })
        })
    }

    /// Applies `policy` to an extension this crate does not implement.
    pub(crate) fn unsupported(&self, policy: UnknownExtensionPolicy) -> Result<(), Error> {
        match (policy, self.critical) {
            (UnknownExtensionPolicy::Strict, true) => Err(Error::UnsupportedCriticalExtension),
            _ => Ok(()),
        }
    }

    /// The last arc of `extnID` when it lies under `id-ce` (2.5.29) and
    /// fits in one octet, e.g. `Some(19)` for `basicConstraints`.
    pub(crate) fn id_ce_arc(&self) -> Option<u8> {
        match self.id {
            [0x55, 0x1d, arc] if arc & 0x80 == 0 => Some(*arc),
            _ => None,
        }
    }
}

/// Walks the `SEQUENCE OF Extension` whose contents are `extensions`,
/// calling `f` for each. An empty sequence is accepted when `allow_empty`.
pub(crate) fn for_each<'a>(
    extensions: &'a [u8],
    allow_empty: bool,
    mut f: impl FnMut(Extension<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    if extensions.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(Error::MalformedExtensions)
        };
    }
    der::read_all(extensions, |reader| {
        while !reader.at_end() {
            f(Extension::read(reader)?)?;
        }
        Ok(())
    })
}

/// Stores a parsed extension value, rejecting a second occurrence of the
/// same extension (RFC 5280 §4.2: "MUST NOT include more than one instance
/// of a particular extension").
pub(crate) fn set_once<T>(
    slot: &mut Option<T>,
    parse: impl FnOnce() -> Result<T, Error>,
) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::MalformedExtensions);
    }
    *slot = Some(parse()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_extension() {
        // basicConstraints, critical, value SEQUENCE { TRUE }.
        let ext = b"\x30\x0f\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x05\x30\x03\x01\x01\xff";
        let mut seen = 0;
        for_each(ext, false, |e| {
            seen += 1;
            assert_eq!(e.id_ce_arc(), Some(19));
            assert!(e.critical);
            assert_eq!(e.value, b"\x30\x03\x01\x01\xff");
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, 1);
        assert_eq!(
            for_each(b"", false, |_| Ok(())),
            Err(Error::MalformedExtensions)
        );
        assert_eq!(for_each(b"", true, |_| Ok(())), Ok(()));
        // Truncated.
        assert_eq!(for_each(&ext[..10], true, |_| Ok(())), Err(Error::BadDer));
    }

    #[test]
    fn set_once_rejects_duplicates() {
        let mut slot = None;
        set_once(&mut slot, || Ok(1)).unwrap();
        assert_eq!(
            set_once(&mut slot, || Ok(2)),
            Err(Error::MalformedExtensions)
        );
        assert_eq!(slot, Some(1));
    }
}
