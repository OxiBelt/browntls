//! Reassembly of fragmented, reordered handshake messages (RFC 9147 §5.5).
//!
//! Fragments arrive in records of some epoch, possibly duplicated,
//! reordered and overlapping. The [`Reassembler`] buffers them per
//! `message_seq` and hands out whole messages in order, in the TLS 1.3
//! encoding (type, 24-bit length, body) that the transcript covers (RFC 9147
//! §5.2).
//!
//! Everything pushed here is attacker controlled, so memory and work are
//! bounded: a window of [`WINDOW`] message sequence numbers, a largest
//! message, a total of buffered bytes, and at most [`MAX_HOLES`] missing
//! ranges per message.
//!
//! Where fragments overlap, the bytes received first are kept and later
//! ones are not compared with them (RFC 9147 §5.5 makes the check
//! optional).

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use super::wire::{HandshakeHeader, TLS_HANDSHAKE_HEADER_LEN};

/// How many messages, from `next_receive_seq` on, may be buffered. A flight
/// holds at most a handful of messages; RFC 9147 §5.2 allows discarding
/// those further ahead, which the peer then retransmits.
pub(crate) const WINDOW: u16 = 16;

/// The most missing ranges a message may have. A fragment that would split
/// a range when the message has this many is dropped (and later
/// retransmitted), so that tiny scattered fragments cannot make each
/// insertion costly. Contiguous fragments in any order stay well below it.
pub(crate) const MAX_HOLES: usize = 32;

/// The largest message body the TLS encoding can carry (24-bit length).
const MAX_ENCODABLE: u32 = 0xff_ffff;

/// What became of a pushed fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fragment {
    /// Stored, possibly adding nothing new (a duplicate of buffered bytes,
    /// or of a complete message not yet popped).
    Accepted,
    /// For a message already delivered (`message_seq` below
    /// `next_receive_seq`): a retransmission.
    Old,
    /// Refused: outside the window, inconsistent with what is buffered,
    /// over a bound, or malformed.
    Dropped,
}

/// The receiving side of handshake messages: see the module documentation.
#[derive(Debug)]
pub(crate) struct Reassembler {
    /// Wider than `message_seq` so that message 0xffff can be delivered:
    /// after it nothing more is.
    next: u32,
    /// Sorted by `seq`, all within the window.
    messages: Vec<Message>,
    /// The sum of the body lengths of `messages`.
    buffered: usize,
    max_message_len: usize,
    max_buffered: usize,
}

impl Reassembler {
    /// `max_message_len` is the largest message body accepted and
    /// `max_buffered` the most body bytes buffered across messages.
    pub(crate) fn new(max_message_len: usize, max_buffered: usize) -> Self {
        Self {
            next: 0,
            messages: Vec::new(),
            buffered: 0,
            max_message_len,
            max_buffered,
        }
    }

    /// The `message_seq` of the next message to deliver; `u16::MAX` once
    /// message 0xffff was delivered (none can follow it).
    pub(crate) fn next_receive_seq(&self) -> u16 {
        u16::try_from(self.next).unwrap_or(u16::MAX)
    }

    /// Whether message `seq` was delivered already.
    pub(crate) fn is_old(&self, seq: u16) -> bool {
        u32::from(seq) < self.next
    }

    /// Sets `next_receive_seq`, before anything was pushed: a server that
    /// continues a stateless HelloRetryRequest expects message 1 (RFC 9147
    /// §5.1). Whatever is buffered outside the new window is discarded.
    pub(crate) fn set_next_receive_seq(&mut self, seq: u16) {
        self.next = u32::from(seq);
        let next = self.next;
        let mut freed = 0;
        self.messages.retain(|message| {
            let keep = in_window(next, message.seq);
            if !keep {
                freed += message.len();
            }
            keep
        });
        self.buffered = self.buffered.saturating_sub(freed);
    }

    /// Takes the fragment that `header` describes. `fragment` must be the
    /// `fragment_length` bytes following `header` in the record and `epoch`
    /// is the record's.
    pub(crate) fn push(
        &mut self,
        header: &HandshakeHeader,
        fragment: &[u8],
        epoch: u64,
    ) -> Fragment {
        let Some(span) = self.check(header, fragment) else {
            return Fragment::Dropped;
        };
        if u32::from(header.message_seq) < self.next {
            return Fragment::Old;
        }
        if !in_window(self.next, header.message_seq) {
            return Fragment::Dropped;
        }
        if span.is_empty() && header.length != 0 {
            // Nothing to store, nor anything to check against.
            return Fragment::Accepted;
        }

        let found = self
            .messages
            .binary_search_by_key(&header.message_seq, |message| message.seq);
        let at = match found {
            Ok(at) => {
                let Some(message) = self.messages.get_mut(at) else {
                    return Fragment::Dropped;
                };
                if epoch == message.epoch {
                    if message.typ() != header.typ || message.body_len() != header.length {
                        return Fragment::Dropped;
                    }
                    return message.fill(span, fragment);
                }
                if epoch < message.epoch {
                    return Fragment::Dropped;
                }
                // A higher epoch is authenticated, unlike (say) the
                // plaintext epoch: what was buffered may be an injection
                // that must not block the real message.
                let len = message.len();
                self.messages.remove(at);
                self.buffered = self.buffered.saturating_sub(len);
                at
            }
            Err(at) => at,
        };

        let Some(message) = self.start(header, span, fragment, epoch) else {
            return Fragment::Dropped;
        };
        self.buffered += message.len();
        self.messages.insert(at, message);
        Fragment::Accepted
    }

    /// The next in-order message, if complete: its epoch and its TLS
    /// encoding (four-byte header and body).
    pub(crate) fn peek(&self) -> Option<(u64, &[u8])> {
        let message = self.messages.first()?;
        if u32::from(message.seq) != self.next || !message.holes.is_empty() {
            return None;
        }
        Some((message.epoch, &message.encoded))
    }

    /// Consumes the message [`Self::peek`] returned and advances
    /// `next_receive_seq`. Does nothing if there is none.
    pub(crate) fn pop(&mut self) {
        if self.peek().is_none() {
            return;
        }
        let message = self.messages.remove(0);
        self.buffered = self.buffered.saturating_sub(message.len());
        self.next += 1;
    }

    /// Discards whatever is buffered of message `next_receive_seq`, without
    /// advancing: it came under the wrong epoch, and the peer will
    /// retransmit it.
    pub(crate) fn drop_next(&mut self) {
        if self.next_is_buffered() {
            let message = self.messages.remove(0);
            self.buffered = self.buffered.saturating_sub(message.len());
        }
    }

    /// Whether anything is buffered (partial or future messages).
    #[cfg(test)]
    pub(crate) fn has_buffered(&self) -> bool {
        !self.messages.is_empty()
    }

    /// Whether the next message has some but not all of its bytes, or a
    /// later message is buffered while the next is missing: signs of
    /// disruption that warrant an ACK (RFC 9147 §7.1).
    pub(crate) fn has_gap(&self) -> bool {
        match self.messages.first() {
            None => false,
            Some(message) if u32::from(message.seq) == self.next => !message.holes.is_empty(),
            Some(_) => true,
        }
    }

    fn next_is_buffered(&self) -> bool {
        self.messages
            .first()
            .is_some_and(|message| u32::from(message.seq) == self.next)
    }

    /// The body range the fragment covers, if it is well formed and within
    /// the size limit.
    fn check(&self, header: &HandshakeHeader, fragment: &[u8]) -> Option<Range<u32>> {
        let end = header.fragment_offset.checked_add(header.fragment_length)?;
        let well_formed = end <= header.length
            && header.length <= MAX_ENCODABLE
            && usize::try_from(header.fragment_length).ok()? == fragment.len()
            && usize::try_from(header.length).ok()? <= self.max_message_len;
        well_formed.then_some(header.fragment_offset..end)
    }

    /// A new message holding its first fragment, if its buffer fits.
    fn start(
        &self,
        header: &HandshakeHeader,
        span: Range<u32>,
        fragment: &[u8],
        epoch: u64,
    ) -> Option<Message> {
        let len = usize::try_from(header.length).ok()?;
        if self.buffered.checked_add(len)? > self.max_buffered {
            return None;
        }
        let total = TLS_HANDSHAKE_HEADER_LEN.checked_add(len)?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(total).ok()?;
        encoded.push(header.typ);
        encoded.extend_from_slice(&header.length.to_be_bytes()[1..]);

        let mut message = Message {
            seq: header.message_seq,
            epoch,
            encoded,
            holes: Vec::new(),
        };
        if span.start == 0 && span.end == header.length {
            // The common case: the whole message in one fragment.
            message.encoded.extend_from_slice(fragment);
            return Some(message);
        }
        message.encoded.resize(total, 0);
        message.holes.push(0..header.length);
        match message.fill(span, fragment) {
            Fragment::Accepted => Some(message),
            _ => None,
        }
    }
}

/// Whether `seq` lies in the window that starts at `next`.
fn in_window(next: u32, seq: u16) -> bool {
    u32::from(seq)
        .checked_sub(next)
        .is_some_and(|ahead| ahead < u32::from(WINDOW))
}

/// A message being reassembled, or complete and not yet popped.
struct Message {
    seq: u16,
    /// The epoch of the records its fragments came in.
    epoch: u64,
    /// The TLS encoding: type, 24-bit length, then the body, whose missing
    /// bytes are zero.
    encoded: Vec<u8>,
    /// The missing body ranges: sorted, disjoint, non-empty and not
    /// adjacent. Empty once the message is complete.
    holes: Vec<Range<u32>>,
}

impl Message {
    fn typ(&self) -> u8 {
        self.encoded.first().copied().unwrap_or_default()
    }

    fn body_len(&self) -> u32 {
        self.len() as u32
    }

    /// The body length, which counts against the buffered bytes.
    fn len(&self) -> usize {
        self.encoded.len().saturating_sub(TLS_HANDSHAKE_HEADER_LEN)
    }

    /// Copies the bytes of `fragment` (covering `span` of the body) that
    /// are still missing. `Dropped` if that would leave too many holes.
    fn fill(&mut self, span: Range<u32>, fragment: &[u8]) -> Fragment {
        // The holes that `span` overlaps are `first..last`.
        let first = self.holes.partition_point(|hole| hole.end <= span.start);
        let last = self.holes.partition_point(|hole| hole.start < span.end);
        if first >= last {
            // Nothing new: a duplicate, or a complete message.
            return Fragment::Accepted;
        }
        let (Some(head), Some(tail)) = (self.holes.get(first), self.holes.get(last - 1)) else {
            return Fragment::Dropped;
        };
        let left = (head.start < span.start).then_some(head.start..span.start);
        let right = (span.end < tail.end).then_some(span.end..tail.end);
        let count = self.holes.len() - (last - first)
            + usize::from(left.is_some())
            + usize::from(right.is_some());
        if count > MAX_HOLES {
            return Fragment::Dropped;
        }

        for hole in self.holes.get(first..last).unwrap_or_default() {
            let from = hole.start.max(span.start);
            let to = hole.end.min(span.end);
            let source = (from - span.start) as usize..(to - span.start) as usize;
            let target =
                from as usize + TLS_HANDSHAKE_HEADER_LEN..to as usize + TLS_HANDSHAKE_HEADER_LEN;
            match (self.encoded.get_mut(target), fragment.get(source)) {
                (Some(target), Some(source)) => target.copy_from_slice(source),
                _ => return Fragment::Dropped,
            }
        }
        self.holes
            .splice(first..last, left.into_iter().chain(right));
        Fragment::Accepted
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("seq", &self.seq)
            .field("epoch", &self.epoch)
            .field("typ", &self.typ())
            .field("len", &self.len())
            .field("holes", &self.holes)
            .finish()
    }
}

#[cfg(test)]
mod tests;
