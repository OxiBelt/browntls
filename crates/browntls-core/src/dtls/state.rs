//! The DTLS state of a connection: the epochs and their keys, records
//! coming in, and the parts of the engine shared with [`super::flight`],
//! which sends handshake messages and makes them reliable.
//!
//! The TLS 1.3 state machines drive this through four hooks: handshake
//! messages and alerts to send ([`Dtls::queue_handshake`],
//! [`Dtls::queue_alert`]) and the traffic secrets of each new epoch
//! ([`Dtls::set_write_secret`], [`Dtls::set_read_secret`]). Everything
//! else (records, fragments, acknowledgements, timers) stays here.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;
use core::time::Duration;

use super::flight::Outgoing;
use super::keys::RecordKeys;
use super::reassembly::{Fragment, Reassembler};
use super::replay::ReplayWindow;
use super::wire::{self, HandshakeHeader, Header, RecordNumber};
use crate::common_state::Side;
use crate::crypto::tls13::OkmBlock;
use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, InvalidMessage};
use crate::log::trace;
use crate::msgs::enums::AlertLevel;
use crate::msgs::handshake::MAX_HANDSHAKE_SIZE;
use crate::msgs::message::MAX_PLAINTEXT_LEN;
use crate::tls13::Tls13CipherSuite;

#[cfg(test)]
mod tests;

/// The datagram size used unless the caller sets another: small enough
/// for any IPv6 path (1280 bytes) after the IP and UDP headers.
pub(crate) const DEFAULT_MTU: usize = 1200;

/// The smallest datagram size accepted: a stateless HelloRetryRequest
/// and an ACK must fit one datagram.
pub(crate) const MIN_MTU: usize = 256;

/// The largest datagram size accepted (the largest UDP payload over IPv4).
pub(crate) const MAX_MTU: usize = 65_507;

/// How many keyed receiving epochs are kept. Four is the most the two
/// epoch bits of the unified header tell apart (RFC 9147 §4.2.2).
const MAX_READ_EPOCHS: usize = 4;

/// How many record numbers an ACK of ours lists at most.
pub(super) const MAX_ACKS: usize = 32;

/// How many handshake bytes are buffered for reassembly at most: two of
/// the largest messages.
const MAX_REASSEMBLY_BUFFER: usize = 2 * MAX_HANDSHAKE_SIZE as usize;

/// The first epoch of protected records in a connection without 0-RTT
/// (RFC 9147 §6.1).
const HANDSHAKE_EPOCH: u64 = 2;

/// The epoch of the first application traffic keys (RFC 9147 §6.1).
pub(super) const APPLICATION_EPOCH: u64 = 3;

/// The keys and next sequence number of one sending epoch.
pub(super) struct WriteEpoch {
    pub(super) epoch: u64,
    /// `None` for epoch 0, which is not protected.
    pub(super) keys: Option<RecordKeys>,
    pub(super) next_seq: u64,
}

/// The keys and replay state of one receiving epoch.
struct ReadEpoch {
    epoch: u64,
    keys: RecordKeys,
    window: ReplayWindow,
    /// Records that failed to authenticate under these keys.
    failures: u64,
}

/// Settings chosen when the connection is created.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) versions: super::Versions,
    pub(crate) mtu: usize,
    pub(crate) initial_timeout: Duration,
    pub(crate) peer_address: Vec<u8>,
    pub(crate) require_cookie: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            versions: super::Versions::default(),
            mtu: DEFAULT_MTU,
            initial_timeout: super::flight::INITIAL_TIMEOUT,
            peer_address: Vec::new(),
            require_cookie: true,
        }
    }
}

/// What [`Dtls::read_record`] found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Incoming {
    /// The datagram holds no further record this endpoint can delimit.
    End,
    /// The record was dropped, or the engine dealt with it entirely
    /// (handshake fragments, acknowledgements).
    Handled,
    /// An alert for the state machine.
    Alert(AlertLevel, AlertDescription),
    /// Application data: its plaintext, decrypted in place, within the
    /// datagram.
    ApplicationData(Range<usize>),
    #[cfg(feature = "tls12")]
    ChangeCipherSpec,
}

/// The DTLS side of a connection's
/// [`CommonState`](crate::common_state::CommonState).
pub(crate) struct Dtls {
    pub(super) side: Side,
    pub(super) version: Option<ProtocolVersion>,
    pub(crate) received_seq: u16,
    pub(crate) client_hello: Vec<u8>,
    #[cfg(feature = "tls12")]
    pub(super) v12: super::v12::State,
    pub(super) settings: Settings,
    /// Sending epochs still needed: the current one (last) and any that
    /// unacknowledged handshake messages were queued under.
    pub(super) write: Vec<WriteEpoch>,
    /// Keys of ours that a KeyUpdate introduced: used once every message
    /// queued before them is acknowledged (RFC 9147 §8).
    pub(super) pending_write: Option<WriteEpoch>,
    /// Keyed receiving epochs, oldest first; the last is the current one.
    read: Vec<ReadEpoch>,
    /// Whether a record from the peer authenticated: from then on,
    /// unprotected alerts and acknowledgements are ignored.
    pub(super) peer_authenticated: bool,
    /// The highest record sequence number of an unprotected ClientHello
    /// received: a server's unprotected records continue from it, so that
    /// a server answering after a stateless HelloRetryRequest does not
    /// reuse its record numbers.
    client_hello_seq: Option<u64>,
    /// When the peer's repetitions last made us retransmit.
    peer_triggered_retransmission: Option<Duration>,
    pub(super) out: Outgoing,
    reassembler: Reassembler,
    /// Records of the peer's current flight (or of its post-handshake
    /// messages) to acknowledge, in increasing order.
    pub(super) acks: Vec<RecordNumber>,
    /// When the acknowledgements are to be sent.
    pub(super) ack_due: Option<Duration>,
    /// Alerts to send, once each, under the current sending epoch.
    pub(super) alerts: VecDeque<(AlertLevel, AlertDescription)>,
    /// During the processing of one datagram: whether the peer
    /// retransmitted a handshake message already delivered.
    saw_retransmission: bool,
    /// During the processing of one datagram: whether a handshake record
    /// of the peer was accepted.
    saw_handshake: bool,
    /// The record key derivation failed (a suite without DTLS record
    /// protection); the connection cannot continue.
    pub(super) broken: bool,
}

impl Dtls {
    pub(crate) fn new(side: Side, settings: Settings) -> Self {
        Self {
            side,
            version: None,
            received_seq: 0,
            client_hello: Vec::new(),
            #[cfg(feature = "tls12")]
            v12: super::v12::State::default(),
            out: Outgoing::new(settings.initial_timeout),
            settings,
            write: alloc::vec![WriteEpoch {
                epoch: 0,
                keys: None,
                next_seq: 0,
            }],
            pending_write: None,
            read: Vec::new(),
            peer_authenticated: false,
            client_hello_seq: None,
            peer_triggered_retransmission: None,
            reassembler: Reassembler::new(MAX_HANDSHAKE_SIZE as usize, MAX_REASSEMBLY_BUFFER),
            acks: Vec::new(),
            ack_due: None,
            alerts: VecDeque::new(),
            saw_retransmission: false,
            saw_handshake: false,
            broken: false,
        }
    }

    /// A server only, before anything is processed: the handshake
    /// continues a stateless HelloRetryRequest (RFC 9147 §5.1), so the
    /// ClientHello to come has `message_seq` 1 and so has our ServerHello.
    pub(crate) fn continue_after_stateless_retry(&mut self) {
        self.reassembler.set_next_receive_seq(1);
        self.out.set_next_send_seq(1);
    }

    /// The peer's transport address as the caller gave it (opaque bytes),
    /// which a server binds its HelloRetryRequest cookies to (RFC 9147
    /// §5.1). Empty on a client.
    pub(crate) fn peer_address(&self) -> &[u8] {
        &self.settings.peer_address
    }

    /// A server only: whether a ClientHello without a valid cookie is
    /// answered with a HelloRetryRequest carrying one (RFC 9147 §5.1),
    /// which is the default.
    pub(crate) fn require_cookie(&self) -> bool {
        self.settings.require_cookie
    }

    /// The largest handshake message (with its four-byte TLS header) that
    /// goes out unfragmented in one datagram of unprotected records. A
    /// first ClientHello should fit, so that a server can answer it
    /// without keeping state (RFC 9147 §5.1).
    pub(crate) fn max_unfragmented_handshake(&self) -> usize {
        (self.settings.mtu - wire::PLAINTEXT_HEADER_LEN).min(MAX_PLAINTEXT_LEN)
            - wire::HANDSHAKE_HEADER_LEN
            + wire::TLS_HANDSHAKE_HEADER_LEN
    }

    pub(crate) fn allows(&self, version: ProtocolVersion) -> bool {
        self.settings.versions.allows(version)
    }

    pub(crate) fn is_v12(&self) -> bool {
        self.version == Some(ProtocolVersion::TLSv1_2)
    }

    pub(crate) fn select_version(&mut self, version: ProtocolVersion) {
        self.version = Some(version);
        if self.is_v12() {
            self.acks.clear();
            self.ack_due = None;
        }
    }

    pub(crate) fn mtu(&self) -> usize {
        self.settings.mtu
    }

    pub(crate) fn set_mtu(&mut self, mtu: usize) -> Result<(), Error> {
        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
            return Err(Error::General(alloc::format!(
                "DTLS datagram size {mtu} is outside {MIN_MTU}..={MAX_MTU}"
            )));
        }
        self.settings.mtu = mtu;
        Ok(())
    }

    /// Queues an alert, sent once under the current sending epoch. A
    /// fatal alert ends every retransmission.
    pub(crate) fn queue_alert(&mut self, level: AlertLevel, description: AlertDescription) {
        if level == AlertLevel::Fatal {
            self.abandon();
        }
        self.alerts.push_back((level, description));
    }

    /// The connection failed: nothing more is sent but queued alerts.
    pub(super) fn abandon(&mut self) {
        self.out.abandon();
        self.acks.clear();
        self.ack_due = None;
    }

    /// Either side closed: our flights are never retransmitted again, as
    /// what the peer sends after its close_notify is not read and what we
    /// send after ours is not read either (RFC 9846 §6.1). An ACK we owe
    /// is still sent.
    pub(super) fn abandon_flights(&mut self) {
        self.out.abandon();
    }

    /// The traffic secret of the next sending epoch: the handshake secret
    /// starts epoch 2, the first application secret epoch 3, and every
    /// later one (a KeyUpdate of ours) the epoch after. The keys of a
    /// KeyUpdate wait until it is acknowledged (RFC 9147 §8).
    pub(crate) fn set_write_secret(&mut self, suite: &'static Tls13CipherSuite, secret: &OkmBlock) {
        let Some(keys) = RecordKeys::derive(suite, secret) else {
            self.broken = true;
            return;
        };
        let current = self.write_epoch();
        if current >= APPLICATION_EPOCH && self.out.stopped() {
            // The KeyUpdate announcing these keys was not sent (either
            // side closed, or the connection failed): keep the current
            // ones.
            return;
        }
        let epoch = match self.pending_write.as_ref() {
            Some(pending) => pending.epoch + 1,
            None if current == 0 => HANDSHAKE_EPOCH,
            None => current + 1,
        };
        let next = WriteEpoch {
            epoch,
            keys: Some(keys),
            next_seq: 0,
        };
        if current >= APPLICATION_EPOCH {
            // A second KeyUpdate before the first is acknowledged is
            // prevented by the caller; should one come, its keys replace
            // the pending ones, which were never used.
            self.pending_write = Some(next);
            self.switch_write_epoch_when_acknowledged();
        } else {
            self.write.push(next);
        }
    }

    /// The traffic secret of the next receiving epoch (see
    /// [`Self::set_write_secret`]). The keys of earlier epochs stay
    /// usable for reordered and retransmitted records, up to four epochs.
    pub(crate) fn set_read_secret(&mut self, suite: &'static Tls13CipherSuite, secret: &OkmBlock) {
        let Some(keys) = RecordKeys::derive(suite, secret) else {
            self.broken = true;
            return;
        };
        let epoch = match self.read.last() {
            Some(last) => last.epoch + 1,
            None => HANDSHAKE_EPOCH,
        };
        self.read.push(ReadEpoch {
            epoch,
            keys,
            window: ReplayWindow::new(),
            failures: 0,
        });
        if self.read.len() > MAX_READ_EPOCHS {
            self.read.remove(0);
        }
    }

    /// The epoch of the records we send now.
    pub(crate) fn write_epoch(&self) -> u64 {
        self.write.last().map_or(0, |w| w.epoch)
    }

    /// The epoch the peer's handshake messages must arrive under now.
    pub(crate) fn read_epoch(&self) -> u64 {
        #[cfg(feature = "tls12")]
        if self.is_v12() {
            return u64::from(self.v12.read_active);
        }
        self.read.last().map_or(0, |r| r.epoch)
    }

    /// Whether a KeyUpdate of ours awaits acknowledgement; no other may
    /// be sent meanwhile (RFC 9147 §5.8.4).
    pub(crate) fn key_update_pending(&self) -> bool {
        self.pending_write.is_some()
    }

    /// Notes the start of the processing of a datagram.
    pub(crate) fn begin_input(&mut self) {
        self.saw_retransmission = false;
        self.saw_handshake = false;
        self.out.begin_input();
    }

    /// Reads the record at `*at` in `datagram` and moves `*at` past it.
    ///
    /// Records that do not authenticate, are replayed, or arrive in an
    /// epoch that cannot carry them are dropped (RFC 9147 §4.5.2). An
    /// error is returned only for a record that authenticated but breaks
    /// the protocol, or when too many records failed to authenticate
    /// (RFC 9147 §4.5.3).
    pub(crate) fn read_record(
        &mut self,
        datagram: &mut [u8],
        at: &mut usize,
        handshaking: bool,
    ) -> Result<Incoming, Error> {
        let base = *at;
        let Some(rest) = datagram.get(base..) else {
            return Ok(Incoming::End);
        };
        let Some(record) = wire::parse_record(rest, 0) else {
            *at = datagram.len();
            return Ok(Incoming::End);
        };
        *at = base + record.body.end;
        let body = base + record.body.start..base + record.body.end;
        match record.header {
            Header::Plaintext {
                typ,
                version,
                epoch,
                seq,
            } => {
                #[cfg(not(feature = "tls12"))]
                let _ = version;
                // Unprotected records exist only in epoch 0; others are
                // DTLS 1.2 records or noise.
                #[cfg(feature = "tls12")]
                if self.is_v12() {
                    return self.read_v12(typ, version, epoch, seq, datagram, body, handshaking);
                }
                if epoch != 0 || body.len() > MAX_PLAINTEXT_LEN {
                    return Ok(Incoming::Handled);
                }
                let number = RecordNumber { epoch: 0, seq };
                self.read_plaintext(typ, number, &datagram[body], handshaking)
            }
            Header::Unified {
                epoch_bits, seq, ..
            } => {
                let record_end = base + record.body.end;
                self.read_protected(
                    &mut datagram[base..record_end],
                    epoch_bits,
                    seq,
                    record.body,
                    base,
                )
            }
        }
    }

    pub(super) fn read_plaintext(
        &mut self,
        typ: ContentType,
        number: RecordNumber,
        body: &[u8],
        handshaking: bool,
    ) -> Result<Incoming, Error> {
        match typ {
            ContentType::Handshake if self.accepts_plaintext_handshake(handshaking) => {
                // An unprotected record proves nothing: a malformed one is
                // dropped, not an error.
                let _ = self.read_handshake_fragments(body, number, false);
                Ok(Incoming::Handled)
            }
            // A peer that cannot complete the handshake may say so before
            // it has keys. Only fatal error alerts count: an unprotected
            // warning, close_notify or user_canceled (at any level), which
            // anyone can forge, would otherwise end a handshake that then
            // never fails.
            ContentType::Alert if !self.peer_authenticated => Ok(match body {
                [level, description]
                    if AlertLevel::from(*level) == AlertLevel::Fatal
                        && !matches!(
                            AlertDescription::from(*description),
                            AlertDescription::CloseNotify | AlertDescription::UserCanceled
                        ) =>
                {
                    Incoming::Alert(AlertLevel::Fatal, AlertDescription::from(*description))
                }
                _ => Incoming::Handled,
            }),
            _ => Ok(Incoming::Handled),
        }
    }

    /// Whether unprotected handshake records are still read: until the
    /// handshake completed and our last flight was acknowledged (until
    /// then the peer's retransmissions tell us to retransmit).
    fn accepts_plaintext_handshake(&self, handshaking: bool) -> bool {
        handshaking || self.out.has_flight()
    }

    fn read_protected(
        &mut self,
        record: &mut [u8],
        epoch_bits: u8,
        seq: Range<usize>,
        body: Range<usize>,
        base: usize,
    ) -> Result<Incoming, Error> {
        // The newest keyed epoch with these low bits; with at most four
        // retained there is at most one.
        let Some(index) = self
            .read
            .iter()
            .rposition(|r| r.epoch & 3 == u64::from(epoch_bits))
        else {
            return Ok(Incoming::Handled);
        };
        let read = &mut self.read[index];
        if body.len() > read.keys.max_ciphertext_len() {
            return Ok(Incoming::Handled);
        }
        let expected = read.window.highest().map_or(0, |h| h.saturating_add(1));
        let Some(opened) = read.keys.open(record, seq, body, expected) else {
            read.failures += 1;
            if read.failures > read.keys.integrity_limit() {
                return Err(Error::DecryptError);
            }
            return Ok(Incoming::Handled);
        };
        if !read.window.is_new(opened.seq) {
            return Ok(Incoming::Handled);
        }
        read.window.mark(opened.seq);
        let number = RecordNumber {
            epoch: read.epoch,
            seq: opened.seq,
        };
        self.peer_authenticated = true;
        let content = opened.content;
        trace!("DTLS read {:?} {:?}", number, opened.typ);
        match opened.typ {
            ContentType::Handshake => {
                self.read_handshake_fragments(&record[content], number, true)?;
                Ok(Incoming::Handled)
            }
            ContentType::Ack => {
                let numbers =
                    wire::read_ack(&record[content]).ok_or(InvalidMessage::MessageTooShort)?;
                self.on_ack(numbers);
                Ok(Incoming::Handled)
            }
            ContentType::Alert => match &record[content] {
                [level, description] => Ok(Incoming::Alert(
                    AlertLevel::from(*level),
                    AlertDescription::from(*description),
                )),
                _ => Err(InvalidMessage::MessageTooShort.into()),
            },
            // RFC 9147 §5.8.1: application data only follows the Finished
            // that installs its keys, in epoch 3 or later.
            ContentType::ApplicationData if number.epoch >= APPLICATION_EPOCH => Ok(
                Incoming::ApplicationData(base + content.start..base + content.end),
            ),
            typ => Err(Error::InappropriateMessage {
                expect_types: alloc::vec![
                    ContentType::Handshake,
                    ContentType::Alert,
                    ContentType::Ack,
                    ContentType::ApplicationData,
                ],
                got_type: typ,
            }),
        }
    }

    /// Hands the fragments of a handshake record to the reassembler, and
    /// notes what the record calls for: an acknowledgement, or (for a
    /// retransmission of something already delivered) a retransmission
    /// of ours.
    pub(super) fn read_handshake_fragments(
        &mut self,
        mut body: &[u8],
        number: RecordNumber,
        authenticated: bool,
    ) -> Result<(), Error> {
        let mut accepted = false;
        let mut old = false;
        let mut dropped = false;
        while !body.is_empty() {
            let Some((header, fragment, rest)) = HandshakeHeader::read(body) else {
                return Err(InvalidMessage::MessageTooShort.into());
            };
            body = rest;
            if !authenticated && !self.buffers_plaintext(&header) {
                // At most a sign that the peer repeats what we have.
                if self.reassembler.is_old(header.message_seq) {
                    old = true;
                }
                dropped = true;
                continue;
            }
            let client_hello = header.typ == u8::from(HandshakeType::ClientHello);
            match self.reassembler.push(&header, fragment, number.epoch) {
                Fragment::Accepted => {
                    accepted = true;
                    if !authenticated && client_hello && !fragment.is_empty() {
                        self.note_client_hello_seq(number.seq);
                    }
                }
                Fragment::Old => old = true,
                Fragment::Dropped => dropped = true,
            }
        }
        // RFC 9147 §7 acknowledges records only when every fragment was
        // processed or buffered. An unprotected repetition proves nothing.
        if !dropped && (accepted || (old && authenticated)) {
            self.saw_handshake = true;
            self.note_ack(number);
        }
        if old {
            self.saw_retransmission = true;
        }
        Ok(())
    }

    /// Whether an unprotected fragment may be buffered: only the peer's
    /// hello (RFC 9147 §6.1), only as the next message we expect, and only
    /// until protected records arrive, so that forged fragments cannot
    /// take the place of protected messages or fill the buffer. A forged
    /// hello that wins the race against the real one can still stall the
    /// handshake until it times out, as with any unprotected hello.
    fn buffers_plaintext(&self, header: &HandshakeHeader) -> bool {
        if self.is_v12() {
            return self.read_epoch() == 0 && header.typ != u8::from(HandshakeType::Finished);
        }
        if self.side == Side::Client
            && self.allows(ProtocolVersion::TLSv1_2)
            && self.read_epoch() == 0
            && header.typ == u8::from(HandshakeType::HelloVerifyRequest)
        {
            return header.message_seq == self.reassembler.next_receive_seq();
        }
        let hello = match self.side {
            Side::Client => HandshakeType::ServerHello,
            Side::Server => HandshakeType::ClientHello,
        };
        self.read_epoch() == 0
            && header.typ == u8::from(hello)
            && header.message_seq == self.reassembler.next_receive_seq()
    }

    /// Notes the record number of a fragment of the ClientHello we are
    /// about to answer: our unprotected records continue after it. Only
    /// until we sent one, so that later input, which may be forged, never
    /// moves our numbers.
    fn note_client_hello_seq(&mut self, seq: u64) {
        let unsent = self
            .write
            .iter()
            .find(|w| w.epoch == 0)
            .is_none_or(|w| w.next_seq == 0);
        // Capped, so that a forged number leaves plenty to send with.
        let seq = seq.min(wire::MAX_SEQ / 2);
        if self.side == Side::Server && unsent {
            self.client_hello_seq = Some(self.client_hello_seq.map_or(seq, |s| s.max(seq)));
        }
    }

    /// Records `number` to acknowledge, keeping the list ordered and
    /// bounded (the oldest are dropped first).
    fn note_ack(&mut self, number: RecordNumber) {
        if let Err(at) = self.acks.binary_search(&number) {
            self.acks.insert(at, number);
            if self.acks.len() > MAX_ACKS {
                self.acks.remove(0);
            }
        }
    }

    pub(super) fn v12_last_sender(&self) -> Side {
        #[cfg(feature = "tls12")]
        if self.v12.resuming {
            return Side::Client;
        }
        Side::Server
    }

    /// The next complete handshake message of the peer that may be
    /// processed now, in its TLS encoding, with the epoch it came in.
    ///
    /// A message must arrive under the current receiving epoch: one that
    /// was buffered under an earlier epoch (for example an unprotected
    /// message where a protected one belongs) is discarded, and the peer
    /// retransmits it. Taking a message of the main handshake from the
    /// peer acknowledges our previous flight (RFC 9147 §7).
    pub(crate) fn next_message(&mut self) -> Option<(u64, Vec<u8>)> {
        let (epoch, bytes) = self.reassembler.peek()?;
        let read_epoch = self.read_epoch();
        // A peer keeps sending under its old keys until its KeyUpdate is
        // acknowledged (RFC 9147 §8), so after the handshake any
        // application epoch up to the current one will do.
        let current = epoch == read_epoch || (APPLICATION_EPOCH..read_epoch).contains(&epoch);
        if !current {
            self.reassembler.drop_next();
            return None;
        }
        let message = bytes.to_vec();
        self.received_seq = self.reassembler.next_receive_seq();
        self.reassembler.pop();
        let boundary = matches!(
            message.first().copied().map(HandshakeType::from),
            Some(
                HandshakeType::ServerHelloDone
                    | HandshakeType::Finished
                    | HandshakeType::HelloVerifyRequest
                    | HandshakeType::ClientHello
            )
        );
        if epoch < APPLICATION_EPOCH && (!self.is_v12() || boundary) {
            self.out.flight_acknowledged_implicitly();
            if !self.is_v12() {
                self.prune_write_epochs();
            }
        }
        Some((epoch, message))
    }

    /// After a datagram was processed and the state machine has answered:
    /// decides when to acknowledge what came in (RFC 9147 §7.1) and
    /// whether to retransmit our flight (RFC 9147 §5.8.1).
    pub(crate) fn end_input(&mut self, handshaking: bool, now: Duration) {
        if self.out.flight_started_this_input() {
            // A new flight may be retransmitted at the peer's request at
            // once, whatever happened to the previous one.
            self.peer_triggered_retransmission = None;
        }
        if self.saw_retransmission {
            if self.out.has_flight() {
                // The peer has not seen our answer to what it repeated.
                // Repetitions, which anyone can forge, earn at most one
                // retransmission per timeout: no amplification.
                let due = self
                    .peer_triggered_retransmission
                    .is_none_or(|last| now >= last.saturating_add(self.out.timeout()));
                if due {
                    self.peer_triggered_retransmission = Some(now);
                    self.out.retransmit_flight();
                }
                return;
            }
            if self.uses_acknowledgements() {
                self.ack_due = Some(now);
            }
            return;
        }
        if !self.uses_acknowledgements() || !self.saw_handshake {
            return;
        }
        if self.out.flight_started_this_input() {
            // Our new flight acknowledges the peer's implicitly.
            self.acks.clear();
            self.ack_due = None;
        } else if !handshaking || self.reassembler.has_gap() {
            self.ack_due = Some(now);
        } else {
            let soon = now + self.out.timeout() / 4;
            self.ack_due = Some(self.ack_due.map_or(soon, |due| due.min(soon)));
        }
    }

    fn uses_acknowledgements(&self) -> bool {
        // A DTLS 1.2-only endpoint cannot emit a DTLS 1.3 ACK while
        // assembling a fragmented initial or retried ClientHello.
        !self.is_v12() && self.allows(ProtocolVersion::TLSv1_3)
    }

    /// The server's unprotected records continue the sequence numbers of
    /// the client's unprotected ClientHello records.
    pub(super) fn plaintext_seq_floor(&self) -> u64 {
        match self.side {
            Side::Server => self.client_hello_seq.unwrap_or(0),
            Side::Client => 0,
        }
    }

    /// Our next KeyUpdate's keys come into use once no message queued
    /// before them is unacknowledged.
    pub(super) fn switch_write_epoch_when_acknowledged(&mut self) {
        let current = self.write_epoch();
        // Once flights are abandoned nothing gets acknowledged any more:
        // the peer may never have seen the KeyUpdate.
        if self.out.stopped() || self.out.has_unacknowledged(current) {
            return;
        }
        if let Some(next) = self.pending_write.take() {
            trace!("DTLS sending epoch {} now", next.epoch);
            self.write.push(next);
            self.prune_write_epochs();
        }
    }

    /// Forgets sending epochs that are neither current nor needed for a
    /// retransmission.
    pub(super) fn prune_write_epochs(&mut self) {
        let current = self.write_epoch();
        let out = &self.out;
        self.write
            .retain(|w| w.epoch == current || out.has_unacknowledged(w.epoch));
    }

    /// The sending epoch `epoch`, if it is still kept.
    pub(super) fn write_state(&mut self, epoch: u64) -> Option<&mut WriteEpoch> {
        self.write.iter_mut().find(|w| w.epoch == epoch)
    }

    /// Seals one record of `content` into `out` under `epoch`.
    pub(super) fn seal_record(
        &mut self,
        out: &mut Vec<u8>,
        epoch: u64,
        typ: ContentType,
        content: &[u8],
    ) -> Result<RecordNumber, Error> {
        if content.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::EncryptError);
        }
        #[cfg(feature = "tls12")]
        if self.is_v12() && epoch == 1 {
            return self.seal_v12(out, typ, content);
        }
        let floor = self.plaintext_seq_floor();
        let Some(write) = self.write_state(epoch) else {
            return Err(Error::EncryptError);
        };
        if epoch == 0 {
            write.next_seq = write.next_seq.max(floor);
        }
        let number = RecordNumber {
            epoch,
            seq: write.next_seq,
        };
        if number.seq > wire::MAX_SEQ {
            return Err(Error::EncryptError);
        }
        match &write.keys {
            None => {
                let len = u16::try_from(content.len()).map_err(|_| Error::EncryptError)?;
                wire::put_plaintext_header(out, typ, ProtocolVersion::DTLSv1_2, 0, number.seq, len);
                out.extend_from_slice(content);
            }
            Some(keys) => keys.seal(out, number, typ, content, &[])?,
        }
        write.next_seq += 1;
        trace!("DTLS sealed {:?} {:?}", number, typ);
        Ok(number)
    }

    /// The bytes one record under `epoch` takes to carry `content_len`
    /// bytes, if the epoch is still kept.
    pub(super) fn record_len(&self, epoch: u64, content_len: usize) -> Option<usize> {
        if content_len > MAX_PLAINTEXT_LEN {
            return None;
        }
        #[cfg(feature = "tls12")]
        if self.is_v12() && epoch == 1 {
            return self
                .v12
                .enc
                .as_ref()
                .map(|enc| wire::PLAINTEXT_HEADER_LEN + enc.encrypted_payload_len(content_len));
        }
        let write = self.write.iter().find(|w| w.epoch == epoch)?;
        Some(match &write.keys {
            None => wire::PLAINTEXT_HEADER_LEN + content_len,
            Some(keys) => keys.sealed_len(content_len, 0),
        })
    }

    /// The most content one record under `epoch` carries within `space`.
    pub(super) fn record_room(&self, epoch: u64, space: usize) -> Option<usize> {
        #[cfg(feature = "tls12")]
        if self.is_v12() && epoch == 1 {
            let overhead = self.record_len(epoch, 0)?;
            return space
                .checked_sub(overhead)
                .map(|room| room.min(MAX_PLAINTEXT_LEN));
        }
        let write = self.write.iter().find(|w| w.epoch == epoch)?;
        let room = match &write.keys {
            None => space.checked_sub(wire::PLAINTEXT_HEADER_LEN),
            Some(keys) => keys.content_room(space, 0),
        }?;
        Some(room.min(MAX_PLAINTEXT_LEN))
    }

    /// The most application data one record of the current sending epoch
    /// carries in one datagram, once application data may be sent.
    pub(crate) fn max_application_data(&self) -> Option<usize> {
        let epoch = self.write_epoch();
        if epoch < APPLICATION_EPOCH && !(self.is_v12() && epoch == 1) {
            return None;
        }
        self.record_room(epoch, self.settings.mtu)
    }

    /// Seals `data` as one application data record under the current
    /// sending epoch, appended to `out` as a datagram of its own.
    ///
    /// Returns whether the confidentiality limit of the keys is near, so
    /// that the caller updates them (RFC 9147 §4.5.3).
    pub(crate) fn seal_application_data(
        &mut self,
        out: &mut Vec<u8>,
        data: &[u8],
    ) -> Result<bool, Error> {
        let epoch = self.write_epoch();
        #[cfg(feature = "tls12")]
        if self.is_v12() {
            if epoch != 1 {
                return Err(Error::HandshakeNotComplete);
            }
            if self
                .record_len(epoch, data.len())
                .is_none_or(|len| len > self.settings.mtu)
            {
                return Err(Error::EncryptError);
            }
            self.seal_record(out, epoch, ContentType::ApplicationData, data)?;
            return Ok(false);
        }
        let (limit, next_seq) = match self.write.last() {
            Some(WriteEpoch {
                keys: Some(keys),
                next_seq,
                ..
            }) if epoch >= APPLICATION_EPOCH => (keys.confidentiality_limit(), *next_seq),
            _ => return Err(Error::HandshakeNotComplete),
        };
        if next_seq >= limit {
            return Err(Error::EncryptError);
        }
        if self
            .record_len(epoch, data.len())
            .is_none_or(|len| len > self.settings.mtu)
        {
            return Err(Error::General(alloc::format!(
                "{} bytes of application data do not fit one DTLS datagram",
                data.len()
            )));
        }
        self.seal_record(out, epoch, ContentType::ApplicationData, data)?;
        // Ask for new keys with a margin: the KeyUpdate itself and its
        // retransmissions use the current keys until it is acknowledged.
        Ok(next_seq + 1 >= limit.saturating_sub(limit / 8))
    }
}

impl fmt::Debug for Dtls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dtls")
            .field("side", &self.side)
            .field("write_epoch", &self.write_epoch())
            .field("read_epoch", &self.read_epoch())
            .finish_non_exhaustive()
    }
}
