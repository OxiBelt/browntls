//! The two buffers an unbuffered stream owns: TLS bytes received and not yet
//! processed (with the plaintext of the record decrypted last, in place), and
//! TLS bytes encoded and not yet written.

use std::fmt;
use std::io;
use std::ops::Range;

/// The size of a record header (RFC 9846 §5.1): type, version, length.
const HEADER_LEN: usize = 5;

/// The largest record `browntls-core` accepts, header included: 2^14 bytes of
/// plaintext and the 2048 bytes of expansion TLS 1.2 allows a ciphertext
/// (RFC 5246 §6.2.3), which covers TLS 1.3's 256 too.
pub(crate) const MAX_RECORD_LEN: usize = HEADER_LEN + 16_384 + 2048;

/// Received TLS bytes.
///
/// One allocation, made at the first read and never grown: `buf[start..end]`
/// is what the connection has not processed yet, and `plain` the unread
/// plaintext of the record it decrypted last, which lies before `start`.
/// Bytes only move when a partly received record is in the way of the rest
/// of it, and never while plaintext is unread.
pub(crate) struct Incoming {
    buf: Vec<u8>,
    start: usize,
    end: usize,
    plain: Range<usize>,
}

impl Incoming {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            end: 0,
            plain: 0..0,
        }
    }

    /// A buffer that starts with `received`, bytes not processed yet.
    pub(crate) fn with_received(mut received: Vec<u8>) -> Self {
        let end = received.len();
        if end == 0 {
            return Self::new();
        }
        received.resize(end.max(MAX_RECORD_LEN), 0);
        Self {
            buf: received,
            start: 0,
            end,
            plain: 0..0,
        }
    }

    /// The received bytes the connection has not processed yet.
    pub(crate) fn unprocessed(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// [`Self::unprocessed`], for the connection to decrypt in place.
    pub(crate) fn unprocessed_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }

    /// The connection processed `discard` bytes from the front of
    /// [`Self::unprocessed`], and left `plain` (a range of that slice,
    /// within those bytes) as application data to read.
    pub(crate) fn processed(&mut self, discard: usize, plain: Option<Range<usize>>) {
        let discard = discard.min(self.end - self.start);
        if let Some(plain) = plain
            && plain.start <= plain.end
            && plain.end <= discard
        {
            self.plain = self.start + plain.start..self.start + plain.end;
        }
        self.start += discard;
    }

    /// The unread plaintext of the record decrypted last.
    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.buf[self.plain.clone()]
    }

    /// Marks `amt` bytes of [`Self::plaintext`] as read.
    pub(crate) fn consume(&mut self, amt: usize) {
        self.plain.start = (self.plain.start + amt).min(self.plain.end);
    }

    /// Room for more TLS bytes from the transport, after what was received.
    ///
    /// The caller has read all the plaintext. A partly received record moves
    /// to the front when the rest of it would not fit behind it. Fails when
    /// the buffer is full of bytes the connection does not take, which a
    /// record within [`MAX_RECORD_LEN`] cannot cause.
    pub(crate) fn spare_mut(&mut self) -> io::Result<&mut [u8]> {
        debug_assert!(self.plain.is_empty(), "plaintext unread");
        if self.buf.is_empty() {
            self.buf = vec![0; MAX_RECORD_LEN];
        }
        self.plain = 0..0;
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.start > 0 && self.buf.len() - self.end < self.missing() {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received TLS record does not fit the buffer",
            ));
        }
        Ok(&mut self.buf[self.end..])
    }

    /// How many more bytes complete the record at the front of
    /// [`Self::unprocessed`]; what is left of a header while that is not
    /// complete, and a full record for a length no record may have (the
    /// connection refuses it).
    fn missing(&self) -> usize {
        let pending = self.unprocessed();
        let Some(length) = pending.get(3..HEADER_LEN) else {
            return HEADER_LEN - pending.len();
        };
        let record = HEADER_LEN + usize::from(u16::from_be_bytes([length[0], length[1]]));
        record.min(MAX_RECORD_LEN).saturating_sub(pending.len())
    }

    /// The transport filled `n` bytes of [`Self::spare_mut`].
    pub(crate) fn received(&mut self, n: usize) {
        self.end = (self.end + n).min(self.buf.len());
    }

    /// Takes the unread plaintext and the unprocessed TLS bytes out.
    pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.plaintext().to_vec(), self.unprocessed().to_vec())
    }
}

/// Lengths only: the buffer holds application plaintext.
impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("unprocessed", &(self.end - self.start))
            .field("plaintext", &self.plain.len())
            .finish()
    }
}

/// Encoded TLS bytes on their way to the transport: `buf[start..end]` is
/// not written yet. Grows to what one write needs and is reused.
pub(crate) struct Outgoing {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl Outgoing {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            end: 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// How many bytes are not written yet.
    pub(crate) fn len(&self) -> usize {
        self.end - self.start
    }

    /// The bytes not written yet.
    pub(crate) fn unsent(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// The transport took `n` bytes of [`Self::unsent`].
    pub(crate) fn advance(&mut self, n: usize) {
        self.start = (self.start + n).min(self.end);
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// The room behind the unsent bytes.
    pub(crate) fn spare_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.end..]
    }

    /// Makes [`Self::spare_mut`] at least `additional` bytes long.
    pub(crate) fn reserve(&mut self, additional: usize) {
        if self.buf.len() - self.end >= additional {
            return;
        }
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        let needed = self.end.saturating_add(additional);
        if self.buf.len() < needed {
            self.buf.resize(needed, 0);
        }
    }

    /// `n` bytes of [`Self::spare_mut`] were filled.
    pub(crate) fn commit(&mut self, n: usize) {
        self.end = (self.end + n).min(self.buf.len());
    }

    /// Takes the unsent bytes out.
    pub(crate) fn into_unsent(self) -> Vec<u8> {
        self.unsent().to_vec()
    }
}

impl fmt::Debug for Outgoing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outgoing")
            .field("unsent", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn fill(incoming: &mut Incoming, bytes: &[u8]) {
        let spare = incoming.spare_mut().unwrap();
        spare[..bytes.len()].copy_from_slice(bytes);
        incoming.received(bytes.len());
    }

    #[test]
    fn plaintext_stays_in_place_until_read() {
        let mut incoming = Incoming::new();
        fill(&mut incoming, b"hdr..PLAINTEXTtagnext");
        // A 17-byte record whose plaintext is bytes 5..14.
        incoming.processed(17, Some(5..14));
        assert_eq!(incoming.plaintext(), b"PLAINTEXT");
        assert_eq!(incoming.unprocessed(), b"next");
        incoming.consume(5);
        assert_eq!(incoming.plaintext(), b"TEXT");
        incoming.consume(100);
        assert!(incoming.plaintext().is_empty());
        assert_eq!(incoming.unprocessed(), b"next");
    }

    #[test]
    fn a_plaintext_range_outside_the_record_is_ignored() {
        let mut incoming = Incoming::new();
        fill(&mut incoming, b"0123456789");
        incoming.processed(4, Some(2..6));
        assert!(incoming.plaintext().is_empty());
        assert_eq!(incoming.unprocessed(), b"456789");
        incoming.processed(100, None);
        assert!(incoming.unprocessed().is_empty());
    }

    #[test]
    fn a_partial_record_moves_only_when_the_rest_does_not_fit() {
        let mut incoming = Incoming::new();
        // A whole small record, then the header of a 16 384-byte one.
        let mut bytes = vec![23, 3, 3, 0, 1, 0xaa];
        bytes.extend_from_slice(&[23, 3, 3, 0x40, 0x00, 1, 2, 3]);
        fill(&mut incoming, &bytes);
        incoming.processed(6, None);
        // 16 381 bytes are missing and fit behind the eight received.
        let spare = incoming.spare_mut().unwrap().len();
        assert_eq!(spare, MAX_RECORD_LEN - bytes.len());
        assert_eq!(incoming.unprocessed(), &bytes[6..]);

        // Near the end of the buffer the partial record moves to the front.
        let mut incoming = Incoming::new();
        let filler = vec![0u8; MAX_RECORD_LEN - 8];
        fill(&mut incoming, &filler);
        fill(&mut incoming, &[23, 3, 3, 0x40, 0x00, 1, 2, 3]);
        incoming.processed(filler.len(), None);
        let spare = incoming.spare_mut().unwrap().len();
        assert_eq!(spare, MAX_RECORD_LEN - 8);
        assert_eq!(incoming.unprocessed(), &[23, 3, 3, 0x40, 0x00, 1, 2, 3]);
    }

    #[test]
    fn a_full_buffer_nothing_is_taken_from_is_an_error() {
        let mut incoming = Incoming::new();
        let filler = vec![0u8; MAX_RECORD_LEN];
        fill(&mut incoming, &filler);
        assert!(incoming.spare_mut().is_err());
        incoming.processed(MAX_RECORD_LEN, None);
        assert_eq!(incoming.spare_mut().unwrap().len(), MAX_RECORD_LEN);
    }

    #[test]
    fn a_buffer_made_from_received_bytes_has_room_for_a_record() {
        let mut incoming = Incoming::with_received(b"leftover".to_vec());
        assert_eq!(incoming.unprocessed(), b"leftover");
        assert_eq!(incoming.spare_mut().unwrap().len(), MAX_RECORD_LEN - 8);
        // More than a record's worth is kept whole.
        let mut incoming = Incoming::with_received(vec![7; MAX_RECORD_LEN + 100]);
        assert_eq!(incoming.unprocessed().len(), MAX_RECORD_LEN + 100);
        assert!(incoming.spare_mut().is_err());
        assert!(Incoming::with_received(Vec::new()).unprocessed().is_empty());
    }

    #[test]
    fn outgoing_keeps_unsent_bytes_in_order() {
        let mut outgoing = Outgoing::new();
        assert!(outgoing.is_empty());
        outgoing.reserve(5);
        outgoing.spare_mut()[..5].copy_from_slice(b"first");
        outgoing.commit(5);
        outgoing.advance(2);
        outgoing.reserve(64);
        assert!(outgoing.spare_mut().len() >= 64);
        outgoing.spare_mut()[..6].copy_from_slice(b"second");
        outgoing.commit(6);
        assert_eq!(outgoing.unsent(), b"rstsecond");
        assert_eq!(outgoing.len(), 9);
        outgoing.advance(100);
        assert!(outgoing.is_empty());
        assert!(outgoing.into_unsent().is_empty());
    }
}
