//! `TransItemList` (RFC 9162 §6.3): the list a TLS extension, an OCSP
//! response or a certificate carries.

use alloc::vec::Vec;
use core::fmt;

use super::TransparencyError;
use super::codec::{Cursor, Malformed};
use super::item::{TransItem, is_sct_type};

/// A validated `TransItemList`, borrowing from its encoding:
///
/// ```text
/// opaque SerializedTransItem<1..2^16-1>;
/// struct { SerializedTransItem trans_item_list<1..2^16-1>; } TransItemList;
/// ```
///
/// [`Self::parse`] validates every item, so iteration cannot fail. Items of
/// a type RFC 9162 does not define are kept as [`TransItem::Unknown`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransItemList<'a> {
    /// The `trans_item_list` vector contents.
    items: &'a [u8],
    len: usize,
}

impl<'a> TransItemList<'a> {
    /// Parses a complete `TransItemList`. The whole list is validated
    /// before anything is returned: one malformed item rejects it.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::MalformedList`] for an empty list or item, a
    /// vector that does not fill its enclosing one, octets after the list,
    /// or an item that [`TransItem::parse`] rejects.
    pub fn parse(list: &'a [u8]) -> Result<Self, TransparencyError> {
        Self::read(list).map_err(|_| TransparencyError::MalformedList)
    }

    fn read(list: &'a [u8]) -> Result<Self, Malformed> {
        let mut outer = Cursor(list);
        let items = outer.vec16(1)?;
        outer.finish()?;
        let mut cursor = Cursor(items);
        let mut len = 0usize;
        while !cursor.at_end() {
            TransItem::read(cursor.vec16(1)?)?;
            len = len.saturating_add(1);
        }
        Ok(Self { items, len })
    }

    /// The number of items (at least one).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the list has no item: never, for a parsed list.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The items, in list order.
    #[must_use]
    pub fn iter(&self) -> TransItems<'a> {
        TransItems(self.serialized_items())
    }

    /// The serialized items, in list order, each exactly as received.
    #[must_use]
    pub fn serialized_items(&self) -> SerializedTransItems<'a> {
        SerializedTransItems(Cursor(self.items))
    }

    /// Whether the list holds an SCT (`x509_sct_v2` or `precert_sct_v2`),
    /// as RFC 9162 §6.4 requires of every list a TLS server sends.
    #[must_use]
    pub fn has_sct(&self) -> bool {
        self.serialized_items().any(|item| {
            matches!(item, [high, low, ..] if is_sct_type(u16::from_be_bytes([*high, *low])))
        })
    }

    /// Encodes a `TransItemList` of already serialized items, for example
    /// items a log returned.
    ///
    /// # Errors
    ///
    /// [`TransparencyError::UnencodableItem`] for no item, an empty item,
    /// an item over 65535 octets or a list over 65535 octets in all.
    /// Items are not parsed: use [`Self::parse`] on the result to validate
    /// them.
    pub fn encode(serialized_items: &[&[u8]]) -> Result<Vec<u8>, TransparencyError> {
        let mut contents = Vec::new();
        for item in serialized_items {
            super::codec::put_vec(&mut contents, 2, 1, item)?;
        }
        let mut out = Vec::with_capacity(contents.len().saturating_add(2));
        super::codec::put_vec(&mut out, 2, 1, &contents)?;
        Ok(out)
    }

    /// Serializes `items` and encodes them as a `TransItemList`.
    ///
    /// # Errors
    ///
    /// Those of [`TransItem::encode`] and [`Self::encode`].
    pub fn encode_items(items: &[TransItem<'_>]) -> Result<Vec<u8>, TransparencyError> {
        let serialized = items
            .iter()
            .map(TransItem::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let borrowed: Vec<&[u8]> = serialized.iter().map(Vec::as_slice).collect();
        Self::encode(&borrowed)
    }
}

impl<'a> IntoIterator for &TransItemList<'a> {
    type Item = TransItem<'a>;
    type IntoIter = TransItems<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for TransItemList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// An iterator over the serialized items of a [`TransItemList`].
#[derive(Clone, Debug)]
pub struct SerializedTransItems<'a>(Cursor<'a>);

impl<'a> Iterator for SerializedTransItems<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.at_end() {
            return None;
        }
        // Validated by `TransItemList::parse`; a failure (impossible) ends
        // the iteration.
        match self.0.vec16(1) {
            Ok(item) => Some(item),
            Err(Malformed) => {
                self.0 = Cursor(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for SerializedTransItems<'_> {}

/// An iterator over the items of a [`TransItemList`].
#[derive(Clone, Debug)]
pub struct TransItems<'a>(SerializedTransItems<'a>);

impl<'a> Iterator for TransItems<'a> {
    type Item = TransItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let serialized = self.0.next()?;
        // Validated by `TransItemList::parse`.
        match TransItem::read(serialized) {
            Ok(item) => Some(item),
            Err(Malformed) => {
                self.0 = SerializedTransItems(Cursor(&[]));
                None
            }
        }
    }
}

impl core::iter::FusedIterator for TransItems<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn lists_are_exact_and_non_empty() {
        let unknown = b"\xf0\x00opaque";
        let sct_type = b"\x01\x02";
        let list = TransItemList::encode(&[unknown]).unwrap();
        let parsed = TransItemList::parse(&list).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(!parsed.is_empty());
        assert!(!parsed.has_sct());
        assert_eq!(
            parsed.serialized_items().collect::<Vec<_>>(),
            [&unknown[..]]
        );
        for len in 0..list.len() {
            assert_eq!(
                TransItemList::parse(&list[..len]),
                Err(TransparencyError::MalformedList)
            );
        }
        let mut trailing = list.clone();
        trailing.push(0);
        assert!(TransItemList::parse(&trailing).is_err());
        assert!(TransItemList::parse(&[0, 0]).is_err());
        assert!(TransItemList::parse(&[0, 2, 0, 0]).is_err());
        // A malformed SCT after a valid item rejects the whole list.
        let list = TransItemList::encode(&[unknown, sct_type]).unwrap();
        assert!(TransItemList::parse(&list).is_err());
        assert_eq!(
            TransItemList::encode(&[]),
            Err(TransparencyError::UnencodableItem)
        );
        assert_eq!(
            TransItemList::encode(&[b""]),
            Err(TransparencyError::UnencodableItem)
        );
        let big = vec![0xf0; 0x8000];
        assert_eq!(
            TransItemList::encode(&[&big, &big]),
            Err(TransparencyError::UnencodableItem)
        );
    }
}
