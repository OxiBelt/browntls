//! Sending handshake messages reliably (RFC 9147 §5.8, §7): fragmenting
//! them into records that fit a datagram, tracking which records carried
//! which fragments, retransmitting what was not acknowledged, and the
//! timers that drive it.
//!
//! The messages of the main handshake form flights: everything we queue
//! between two messages of the peer. A flight stays until the peer's next
//! flight acknowledges it implicitly or an ACK covers all of it. The
//! client's final flight and every post-handshake message (epoch 3 and
//! later) need an ACK (RFC 9147 §7.1).

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::Range;
use core::time::Duration;

use super::state::{APPLICATION_EPOCH, Dtls, MAX_ACKS};
use super::wire::{self, HandshakeHeader, RecordNumber};
use crate::common_state::Side;
use crate::enums::{AlertDescription, ContentType, HandshakeType};
use crate::error::Error;
use crate::log::trace;
use crate::msgs::enums::AlertLevel;

/// The first retransmission timeout (RFC 9147 §5.8.2).
pub(super) const INITIAL_TIMEOUT: Duration = Duration::from_secs(1);

/// The retransmission timeout doubles up to this (RFC 9147 §5.8.2).
const MAX_TIMEOUT: Duration = Duration::from_secs(60);

/// How many consecutive timeouts without any acknowledgement end the
/// connection: about five minutes with the default timers.
const MAX_RETRANSMISSIONS: u32 = 9;

/// How many sent records are remembered for matching acknowledgements.
const MAX_SENT_RECORDS: usize = 256;

/// A handshake message of ours awaiting acknowledgement.
struct OutMessage {
    message_seq: u16,
    /// The sending epoch it was queued under, and is (re)sent under.
    epoch: u64,
    typ: u8,
    body: Vec<u8>,
    /// Sent at epoch 3 or later: a post-handshake message, acknowledged
    /// only explicitly.
    post_handshake: bool,
    /// Parts not yet acknowledged, as ranges of `0..span`, where the span
    /// of an empty message is one, so that it is sent once.
    unacked: Vec<Range<u32>>,
    /// Parts to (re)transmit at the next opportunity.
    pending: Vec<Range<u32>>,
}

/// Which fragment a record we sent carried.
struct SentRecord {
    number: RecordNumber,
    message_seq: u16,
    range: Range<u32>,
}

/// The outgoing half of the DTLS engine.
pub(super) struct Outgoing {
    next_send_seq: u16,
    messages: Vec<OutMessage>,
    sent: VecDeque<SentRecord>,
    initial_timeout: Duration,
    timeout: Duration,
    /// When the retransmission timer fires, if it runs.
    deadline: Option<Duration>,
    /// Timeouts since the last acknowledgement.
    retransmissions: u32,
    /// The peer sent a message since our last flight: the next message of
    /// the main handshake we queue starts a new flight.
    flight_closed: bool,
    flight_started_this_input: bool,
    /// After a fatal alert, or once either side closed, no handshake
    /// message is sent again.
    pub(super) abandoned: bool,
    /// We closed with our last flight unacknowledged: that flight alone is
    /// still retransmitted, each time followed by close_notify again.
    pub(super) closing: bool,
    /// The peer closed before our last flight was completely sent: it is
    /// sent once, then abandoned.
    pub(super) sending_last: bool,
}

impl Outgoing {
    pub(super) fn new(initial_timeout: Duration) -> Self {
        Self {
            next_send_seq: 0,
            messages: Vec::new(),
            sent: VecDeque::new(),
            initial_timeout,
            timeout: initial_timeout,
            deadline: None,
            retransmissions: 0,
            flight_closed: true,
            flight_started_this_input: false,
            abandoned: false,
            closing: false,
            sending_last: false,
        }
    }

    #[cfg(feature = "tls12")]
    pub(super) fn next_send_seq(&self) -> u16 {
        self.next_send_seq
    }

    pub(super) fn set_next_send_seq(&mut self, seq: u16) {
        self.next_send_seq = seq;
    }

    /// The current retransmission timeout.
    pub(super) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(super) fn begin_input(&mut self) {
        self.flight_started_this_input = false;
    }

    /// Whether a flight of the main handshake awaits acknowledgement.
    pub(super) fn has_flight(&self) -> bool {
        self.messages.iter().any(|m| !m.post_handshake)
    }

    pub(super) fn flight_started_this_input(&self) -> bool {
        self.flight_started_this_input
    }

    /// Whether a message queued under `epoch` awaits acknowledgement.
    pub(super) fn has_unacknowledged(&self, epoch: u64) -> bool {
        self.messages.iter().any(|m| m.epoch == epoch)
    }

    /// Each CID message category has its own one-outstanding-message gate.
    pub(super) fn has_type(&self, typ: HandshakeType) -> bool {
        self.messages.iter().any(|m| m.typ == u8::from(typ))
    }

    pub(super) fn abandon(&mut self) {
        self.abandoned = true;
        self.messages.clear();
        self.sent.clear();
        self.deadline = None;
    }

    /// The peer sent the next message of the main handshake, so it has
    /// our flight (RFC 9147 §7).
    pub(super) fn flight_acknowledged_implicitly(&mut self) {
        self.flight_closed = true;
        let before = self.messages.len();
        self.messages.retain(|m| m.post_handshake);
        if self.messages.len() != before {
            self.progress();
        }
    }

    /// Schedules every unacknowledged part of the flight for sending.
    pub(super) fn retransmit_flight(&mut self) {
        for message in self.messages.iter_mut().filter(|m| !m.post_handshake) {
            message.pending = message.unacked.clone();
        }
    }

    /// Something was acknowledged: the timers start over.
    fn progress(&mut self) {
        self.retransmissions = 0;
        if self.messages.is_empty() {
            self.deadline = None;
            self.timeout = self.initial_timeout;
        }
    }

    /// Whether no handshake message is queued any more: the connection
    /// failed or closed. A KeyUpdate would then never be sent, so its keys
    /// must not be used either.
    pub(super) fn stopped(&self) -> bool {
        self.abandoned || self.closing || self.sending_last
    }

    fn has_pending(&self) -> bool {
        self.messages.iter().any(|m| !m.pending.is_empty())
    }
}

impl Dtls {
    #[cfg(feature = "tls12")]
    pub(crate) fn outgoing_hello_seq(&self) -> u16 {
        self.out.next_send_seq.saturating_sub(1)
    }

    /// Queues a handshake message (in its TLS encoding: type, 24-bit
    /// length, body) under the current sending epoch.
    pub(crate) fn queue_handshake(&mut self, encoded: &[u8]) {
        if encoded.first() == Some(&u8::from(HandshakeType::ClientHello)) {
            self.client_hello = encoded.to_vec();
        }
        let out = &mut self.out;
        let Some((&typ, rest)) = encoded.split_first() else {
            return;
        };
        let Some(body) = rest.get(wire::TLS_HANDSHAKE_HEADER_LEN - 1..) else {
            return;
        };
        if out.stopped() {
            return;
        }
        let epoch = self.write.last().map_or(0, |w| w.epoch);
        let post_handshake = epoch >= APPLICATION_EPOCH;
        if !post_handshake && out.flight_closed {
            out.flight_closed = false;
            out.flight_started_this_input = true;
            out.retransmissions = 0;
            out.deadline = None;
        }
        let message_seq = out.next_send_seq;
        let Some(next) = message_seq.checked_add(1) else {
            // RFC 9147 §5.2: message_seq does not wrap.
            self.broken = true;
            return;
        };
        out.next_send_seq = next;
        trace!(
            "DTLS queued message {} type {} at epoch {}",
            message_seq, typ, epoch
        );
        let span = (body.len() as u32).max(1);
        out.messages.push(OutMessage {
            message_seq,
            epoch,
            typ,
            body: body.to_vec(),
            post_handshake,
            unacked: alloc::vec![0..span],
            pending: alloc::vec![0..span],
        });
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn queue_v12_ccs(&mut self) {
        self.out.messages.push(OutMessage {
            message_seq: u16::MAX,
            epoch: 0,
            typ: 0,
            body: alloc::vec![1],
            post_handshake: false,
            unacked: alloc::vec![0..1],
            pending: alloc::vec![0..1],
        });
    }

    /// Appends the next datagram to send to `out`: a due ACK, handshake
    /// fragments and queued alerts, within the datagram size. Returns
    /// whether anything was appended.
    pub(crate) fn write_datagram(
        &mut self,
        out: &mut Vec<u8>,
        now: Duration,
    ) -> Result<bool, Error> {
        if self.broken {
            return Err(Error::EncryptError);
        }
        self.check_cid_mtu(self.settings.mtu)?;
        let start = out.len();
        let mtu = self.settings.mtu;
        let space = |out: &Vec<u8>| mtu.saturating_sub(out.len() - start);

        if self.ack_due.is_some_and(|due| due <= now) {
            self.ack_due = None;
            self.write_ack(out, space(out))?;
        }

        let wrote = self.write_fragments(out, start)?;
        if wrote && self.out.deadline.is_none() && !self.is_hrr_only() && !self.out.sending_last {
            self.out.deadline = Some(now + self.out.timeout);
        }
        let close = (AlertLevel::Warning, AlertDescription::CloseNotify);
        if wrote && self.out.closing && !self.alerts.contains(&close) {
            self.alerts.push_back(close);
        }
        if self.out.sending_last && !self.out.has_pending() {
            self.abandon_flights();
        }

        // Alerts go last: the peer reads nothing after a close_notify
        // (RFC 9846 §6.1), so what shares its datagram must come first.
        while let Some(&(level, description)) = self.alerts.front() {
            let epoch = self.write_epoch();
            let fits = self
                .record_len(epoch, 2)
                .is_some_and(|len| len <= space(out));
            if !fits && out.len() > start {
                break;
            }
            if description == AlertDescription::CloseNotify
                && out.len() > start
                && self.out.has_pending()
            {
                // The rest of what was queued before it comes first.
                break;
            }
            self.alerts.pop_front();
            self.seal_record(
                out,
                epoch,
                ContentType::Alert,
                &[u8::from(level), u8::from(description)],
            )?;
            if description == AlertDescription::CloseNotify {
                self.close_sent();
            }
        }
        Ok(out.len() > start)
    }

    /// Our close_notify is sent: the peer reads nothing after it (RFC 9846
    /// §6.1), so nothing more is queued or retransmitted, except a
    /// client's last flight, which the server needs to complete its
    /// handshake: until acknowledged, it is retransmitted with
    /// close_notify after it.
    fn close_sent(&mut self) {
        if self.holds_last_flight() && !self.out.sending_last {
            self.out.messages.retain(|m| !m.post_handshake);
            self.out.closing = true;
        } else {
            self.abandon_flights();
        }
    }

    /// The peer's close_notify was read: nothing it sends is read any
    /// more, its ACKs included, so nothing is retransmitted. A client
    /// whose last flight is not completely sent yet still sends it once,
    /// so that the server can complete its handshake. An ACK we owe is
    /// still sent.
    pub(super) fn peer_closed(&mut self) {
        if self.out.sending_last {
            return;
        }
        if self.holds_last_flight() && self.out.has_pending() && !self.out.closing {
            self.out.sending_last = true;
            self.out.deadline = None;
        } else {
            self.abandon_flights();
        }
    }

    /// Whether we are a client whose unacknowledged flight holds its
    /// Finished: the last flight of the handshake.
    fn holds_last_flight(&self) -> bool {
        let finished = u8::from(HandshakeType::Finished);
        self.side
            == if self.is_v12() {
                Side::Server
            } else {
                Side::Client
            }
            && self
                .out
                .messages
                .iter()
                .any(|m| !m.post_handshake && m.typ == finished)
    }

    /// Writes an ACK of what is to be acknowledged, if it fits `space`.
    ///
    /// RFC 9147 §7: during the handshake an ACK is sent in an epoch at
    /// least that of the records it covers, so records of later epochs wait;
    /// afterwards it is sent in our highest sending epoch whatever the
    /// epochs of the peer's records.
    fn write_ack(&mut self, out: &mut Vec<u8>, space: usize) -> Result<(), Error> {
        let epoch = self.write_epoch();
        let numbers: Vec<RecordNumber> = self
            .acks
            .iter()
            .filter(|n| n.epoch <= epoch || epoch >= APPLICATION_EPOCH)
            .copied()
            .collect();
        if numbers.is_empty() {
            return Ok(());
        }
        let Some(room) = self.record_room(epoch, space) else {
            return Ok(());
        };
        let count = (room.saturating_sub(2) / wire::RECORD_NUMBER_LEN).min(MAX_ACKS);
        if count == 0 {
            return Ok(());
        }
        // The most recent records matter most.
        let numbers = &numbers[numbers.len().saturating_sub(count)..];
        let mut body = Vec::with_capacity(2 + numbers.len() * wire::RECORD_NUMBER_LEN);
        wire::put_ack(&mut body, numbers);
        self.seal_record(out, epoch, ContentType::Ack, &body)?;
        Ok(())
    }

    /// Writes pending handshake fragments, one per record, until the
    /// datagram is full. Returns whether any was written.
    fn write_fragments(&mut self, out: &mut Vec<u8>, start: usize) -> Result<bool, Error> {
        let mtu = self.settings.mtu;
        let mut wrote = false;
        let mut index = 0;
        while index < self.out.messages.len() {
            let message = &self.out.messages[index];
            let Some(range) = message.pending.first().cloned() else {
                index += 1;
                continue;
            };
            let epoch = message.epoch;
            #[cfg(feature = "tls12")]
            if self.is_v12() && message.typ == 0 {
                if self
                    .record_len(0, 1)
                    .is_none_or(|len| len > mtu.saturating_sub(out.len() - start))
                {
                    break;
                }
                self.seal_record(out, 0, ContentType::ChangeCipherSpec, &[1])?;
                self.out.messages[index].pending.clear();
                index += 1;
                wrote = true;
                continue;
            }
            let space = mtu.saturating_sub(out.len() - start);
            let room = self
                .record_room(epoch, space)
                .unwrap_or(0)
                .saturating_sub(wire::HANDSHAKE_HEADER_LEN);
            if room == 0 {
                break;
            }
            let message = &self.out.messages[index];
            let take = range.len().min(room) as u32;
            let piece = range.start..range.start + take;
            let body_len = message.body.len() as u32;
            let bytes = &message.body
                [(piece.start.min(body_len) as usize)..(piece.end.min(body_len) as usize)];
            let header = HandshakeHeader {
                typ: message.typ,
                length: body_len,
                message_seq: message.message_seq,
                fragment_offset: piece.start.min(body_len),
                fragment_length: bytes.len() as u32,
            };
            let mut content = Vec::with_capacity(wire::HANDSHAKE_HEADER_LEN + bytes.len());
            content.extend_from_slice(&header.encode());
            content.extend_from_slice(bytes);
            let message_seq = message.message_seq;
            let number = self.seal_record(out, epoch, ContentType::Handshake, &content)?;
            remove_range(&mut self.out.messages[index].pending, &piece);
            self.out.sent.push_back(SentRecord {
                number,
                message_seq,
                range: piece,
            });
            if self.out.sent.len() > MAX_SENT_RECORDS {
                self.out.sent.pop_front();
            }
            wrote = true;
        }
        Ok(wrote)
    }

    /// A server's flight of a HelloRetryRequest alone is not retransmitted
    /// on a timer: a stateless server could not (RFC 9147 §3.1), and the
    /// client's retransmitted ClientHello asks for it again.
    pub(crate) fn is_hrr_only(&self) -> bool {
        self.side == Side::Server
            && self.out.messages.len() == 1
            && self.out.messages.iter().all(|m| {
                m.epoch == 0
                    && !m.post_handshake
                    && (m.typ == u8::from(HandshakeType::ServerHello)
                        || m.typ == u8::from(HandshakeType::HelloVerifyRequest))
            })
    }

    /// Processes the record numbers of a protected ACK. Unprotected ACKs,
    /// which anyone could forge, are ignored: they could only spare us
    /// retransmitting a hello.
    pub(super) fn on_ack(&mut self, numbers: impl Iterator<Item = RecordNumber>) {
        let mut newest: Option<RecordNumber> = None;
        for number in numbers {
            let Some(at) = self.out.sent.iter().position(|s| s.number == number) else {
                continue;
            };
            let Some(sent) = self.out.sent.remove(at) else {
                continue;
            };
            if let Some(message) = self
                .out
                .messages
                .iter_mut()
                .find(|m| m.message_seq == sent.message_seq)
            {
                remove_range(&mut message.unacked, &sent.range);
                remove_range(&mut message.pending, &sent.range);
            }
            newest = Some(newest.map_or(number, |n| n.max(number)));
        }
        let Some(newest) = newest else {
            return;
        };
        trace!("DTLS acknowledged up to {:?}", newest);
        self.out.messages.retain(|m| !m.unacked.is_empty());
        // RFC 9147 §7.2: what was sent before the newest acknowledged
        // record and is still unacknowledged was lost; send it again now.
        let (lost, kept): (Vec<SentRecord>, Vec<SentRecord>) =
            self.out.sent.drain(..).partition(|s| s.number < newest);
        self.out.sent = kept.into();
        for sent in lost {
            if let Some(message) = self
                .out
                .messages
                .iter_mut()
                .find(|m| m.message_seq == sent.message_seq)
            {
                let still_unacked: Vec<Range<u32>> = message
                    .unacked
                    .iter()
                    .filter_map(|r| intersect(r, &sent.range))
                    .collect();
                for range in still_unacked {
                    add_range(&mut message.pending, range);
                }
            }
        }
        self.out.progress();
        self.switch_write_epoch_when_acknowledged();
        self.prune_write_epochs();
    }

    /// When the engine next needs [`Self::handle_timeout`].
    pub(crate) fn next_timeout(&self) -> Option<Duration> {
        let ack = self.ack_due.filter(|_| !self.acks.is_empty());
        match (self.out.deadline, ack) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Acts on expired timers: an ACK that is due is left for the next
    /// datagram, and on a retransmission timeout everything unacknowledged
    /// is sent again with the timeout doubled (RFC 9147 §5.8.2).
    pub(crate) fn handle_timeout(&mut self, now: Duration) -> Result<(), Error> {
        if self.out.deadline.is_none_or(|deadline| deadline > now) {
            return Ok(());
        }
        self.out.deadline = None;
        self.out.retransmissions += 1;
        if self.out.retransmissions > MAX_RETRANSMISSIONS
            && (self.out.closing || (self.is_v12() && self.holds_last_flight()))
        {
            // We closed: the server may have finished and read our
            // close_notify, after which it acknowledges nothing.
            self.abandon_flights();
            return Ok(());
        }
        if self.out.retransmissions > MAX_RETRANSMISSIONS {
            self.out.abandon();
            return Err(Error::General(
                "DTLS peer acknowledged nothing after repeated retransmissions".into(),
            ));
        }
        self.out.timeout = (self.out.timeout * 2).min(MAX_TIMEOUT);
        for message in &mut self.out.messages {
            message.pending = message.unacked.clone();
        }
        Ok(())
    }

    /// Whether something is waiting to be sent now.
    pub(crate) fn wants_write(&self, now: Duration) -> bool {
        !self.alerts.is_empty()
            || self.out.has_pending()
            || (self.ack_due.is_some_and(|due| due <= now) && !self.acks.is_empty())
    }
}

/// Removes `cut` from the ordered, disjoint ranges of `set`.
fn remove_range(set: &mut Vec<Range<u32>>, cut: &Range<u32>) {
    let mut result = Vec::with_capacity(set.len() + 1);
    for r in set.drain(..) {
        if r.end <= cut.start || r.start >= cut.end {
            result.push(r);
            continue;
        }
        if r.start < cut.start {
            result.push(r.start..cut.start);
        }
        if r.end > cut.end {
            result.push(cut.end..r.end);
        }
    }
    *set = result;
}

/// Adds `range` to the ordered, disjoint ranges of `set`, merging.
fn add_range(set: &mut Vec<Range<u32>>, range: Range<u32>) {
    if range.is_empty() {
        return;
    }
    let mut merged = range;
    let mut result = Vec::with_capacity(set.len() + 1);
    for r in set.drain(..) {
        if r.end < merged.start || r.start > merged.end {
            result.push(r);
        } else {
            merged = merged.start.min(r.start)..merged.end.max(r.end);
        }
    }
    let at = result
        .iter()
        .position(|r| r.start > merged.start)
        .unwrap_or(result.len());
    result.insert(at, merged);
    *set = result;
}

fn intersect(a: &Range<u32>, b: &Range<u32>) -> Option<Range<u32>> {
    let r = a.start.max(b.start)..a.end.min(b.end);
    (!r.is_empty()).then_some(r)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn range_sets() {
        let mut set = alloc::vec![0..100];
        remove_range(&mut set, &(10..20));
        assert_eq!(set, [0..10, 20..100]);
        remove_range(&mut set, &(0..10));
        assert_eq!(set, vec![20..100]);
        add_range(&mut set, 5..25);
        assert_eq!(set, vec![5..100]);
        remove_range(&mut set, &(50..150));
        add_range(&mut set, 60..70);
        assert_eq!(set, [5..50, 60..70]);
        add_range(&mut set, 50..60);
        assert_eq!(set, vec![5..70]);
        assert_eq!(intersect(&(0..10), &(5..20)), Some(5..10));
        assert_eq!(intersect(&(0..10), &(10..20)), None);
    }
}
