//! What `tls_tokio_unbuffered` checks: the bookkeeping of each side, the
//! properties of every result, and the state a connection comes to rest in.

use std::io::{self, IoSlice};
use std::ops::DerefMut;
use std::sync::Arc;

use browntls::SideData;
use browntls::unbuffered::{
    ConnectionState, EncodeError, InsufficientSizeError, UnbufferedConnectionCommon,
    UnbufferedStatus,
};

use super::world::{
    CLIENT, MAX_GATHER, MAX_WRITE, Manual, ManualConnection, SERVER, Side, Stream, World,
};
use crate::tls_conn::setup::assert_prefix;

/// The largest record, header included: what a stream's receive buffer
/// holds.
pub(super) const MAX_RECORD_LEN: usize = 5 + 16_384 + 2048;
/// The 0-RTT data the server configurations accept.
const MAX_EARLY_DATA: usize = 1024;
/// Key updates without application data between them that a peer accepts.
const KEY_UPDATE_BUDGET: u32 = 6;
/// Rounds of a pump with the transport's `Pending` pattern in force.
const PATTERN_ROUNDS: usize = 12;
/// Rounds after which a connection that still moves is taken to spin.
const ROUND_LIMIT: usize = 1 << 14;
/// Reads per side and round.
const READS_PER_ROUND: usize = 256;
/// States one call of the hand-driven connection may go through.
const MANUAL_STEPS: usize = 1 << 16;

/// What the harness saw of one side.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Notes {
    /// A future or stream operation returned an error.
    pub(super) errored: bool,
    /// A read failed for good: later reads return no data.
    pub(super) read_failed: bool,
    /// A read reported a TLS failure: writes fail too.
    pub(super) tls_failed: bool,
    /// A read returned the end of the stream.
    pub(super) eof: bool,
    /// Shutdown was called.
    pub(super) shut: bool,
}

/// What an input reached; the seed tests read it.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Stats {
    /// Handshake futures that returned a stream.
    pub(super) handshakes: u32,
    /// Times an undisturbed connection came to rest with everything
    /// delivered.
    pub(super) delivered: u32,
    /// Streams taken apart and driven by hand.
    pub(super) manual: u32,
    /// The most TLS bytes a stream held unwritten.
    pub(super) unsent: usize,
    /// Stream failures that stayed failures.
    pub(super) sticky: u32,
    /// Accessor calls on a waiting `Connect` and on a waiting `Accept`.
    pub(super) waiting: [u32; 2],
    /// Futures made fallible, of the client and of the server.
    pub(super) fallible: [u32; 2],
}

/// The kind of call an error came from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
    Read,
    Write,
    Flush,
}

/// How many bytes a vectored write of an unbuffered stream takes.
pub(super) fn vectored_take(bufs: &[IoSlice<'_>]) -> usize {
    let mut filled = bufs.iter().filter(|buf| !buf.is_empty());
    let Some(first) = filled.next() else {
        return 0;
    };
    if first.len() >= MAX_GATHER || filled.next().is_none() {
        first.len().min(MAX_WRITE)
    } else {
        bufs.iter()
            .map(|buf| buf.len())
            .sum::<usize>()
            .min(MAX_GATHER)
    }
}

/// The number behind `name` where it occurs last in a `Debug` output.
fn debug_number(debug: &str, name: &str) -> usize {
    let (_, rest) = debug.rsplit_once(name).expect("a length in Debug");
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    rest[..digits].parse().expect("a number")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// What a hand-driven connection came to.
enum Rest {
    NeedInput,
    PeerClosed,
    Failed,
}

/// Handles one state of a hand-driven connection: plaintext goes to
/// `plain` (0-RTT data to `early`), records the connection wants sent to
/// `out`. Returns where the connection came to rest, if it did.
fn handle<D>(
    state: Result<ConnectionState<'_, '_, D>, browntls::Error>,
    out: &mut Vec<u8>,
    plain: &mut Vec<u8>,
    early: &mut Vec<u8>,
) -> Option<Rest>
where
    D: SideData,
{
    match state {
        Err(_) => Some(Rest::Failed),
        Ok(ConnectionState::ReadTraffic(record)) => {
            plain.extend_from_slice(record.payload());
            None
        }
        Ok(ConnectionState::ReadEarlyData(record)) => {
            early.extend_from_slice(record.payload());
            None
        }
        Ok(ConnectionState::EncodeTlsData(mut encoder)) => {
            let start = out.len();
            let mut room = 1024;
            loop {
                out.resize(start + room, 0);
                match encoder.encode(&mut out[start..]) {
                    Ok(n) => {
                        out.truncate(start + n);
                        return None;
                    }
                    Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size }))
                        if required_size > room =>
                    {
                        room = required_size
                    }
                    Err(_) => {
                        out.truncate(start);
                        return Some(Rest::Failed);
                    }
                }
            }
        }
        Ok(ConnectionState::TransmitTlsData(transmit)) => {
            transmit.done();
            None
        }
        Ok(ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_)) => {
            Some(Rest::NeedInput)
        }
        Ok(ConnectionState::PeerClosed | ConnectionState::Closed) => Some(Rest::PeerClosed),
        Ok(_) => Some(Rest::Failed),
    }
}

/// Processes `incoming` as far as it goes, as the caller of
/// `TlsStream::into_parts` would.
fn drive<C, D>(
    conn: &mut C,
    incoming: &mut Vec<u8>,
    out: &mut Vec<u8>,
    plain: &mut Vec<u8>,
    early: &mut Vec<u8>,
) -> Rest
where
    C: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    for _ in 0..MANUAL_STEPS {
        let UnbufferedStatus { discard, state } = conn.process_tls_records(incoming);
        let rest = handle(state, out, plain, early);
        incoming.drain(..discard.min(incoming.len()));
        if let Some(rest) = rest {
            return rest;
        }
    }
    panic!("a connection driven by hand never came to rest");
}

/// `refresh_traffic_keys` through the unbuffered API. Returns whether a
/// KeyUpdate was queued.
fn refresh<C, D>(conn: &mut C) -> bool
where
    C: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    match conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::WriteTraffic(writer)) => writer.refresh_traffic_keys().is_ok(),
        _ => false,
    }
}

impl World {
    /// Neither the input nor an earlier failure explains an error now.
    fn calm(&self) -> bool {
        !self.disturbed
            && !self.lenient
            && self.sides.iter().all(Side::established)
            && !self.notes.iter().any(|notes| notes.errored)
    }

    /// Records an error a stream returned.
    pub(super) fn failed(&mut self, side: usize, call: Call, err: &io::Error) {
        let unbuffered = matches!(&self.sides[side], Side::Ready(stream) if stream.unbuffered());
        if unbuffered {
            // After its own close_notify a side's transport is shut: what
            // it may still owe the peer cannot be flushed.
            let after_shutdown = self.notes[side].shut && call != Call::Read;
            assert!(
                !self.calm() || after_shutdown,
                "an undisturbed stream failed: {err}"
            );
            if call == Call::Read {
                if self.notes[side].read_failed {
                    self.stats.sticky += 1;
                }
                let tls = err
                    .get_ref()
                    .is_some_and(|inner| inner.is::<browntls::Error>());
                let final_kind = matches!(
                    err.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                );
                self.notes[side].read_failed |= tls || final_kind;
                self.notes[side].tls_failed |= tls;
            }
        }
        self.notes[side].errored = true;
    }

    /// All the 0-RTT data the server accepted: taken, and still in the
    /// stream.
    fn early_data(&self) -> Vec<u8> {
        let mut early = self.early.clone();
        if let Side::Ready(Stream::Server(stream)) = &self.sides[SERVER] {
            early.extend_from_slice(stream.early_data());
        }
        early
    }

    /// What was read is what the peer wrote, in order. With `complete`,
    /// the server has read everything the client wrote.
    fn check_server(&self, complete: bool) {
        let (sent, got) = (&self.sent[CLIENT], &self.received[SERVER]);
        let early = self.early_data();
        assert!(
            early.len() <= MAX_EARLY_DATA,
            "{} bytes of 0-RTT",
            early.len()
        );
        if !self.early_attempted {
            assert!(early.is_empty(), "0-RTT data from a client that sent none");
            assert_prefix(got, sent, "server read");
            assert!(
                !complete || got.len() == sent.len(),
                "the server misses data"
            );
            return;
        }
        // Accepted 0-RTT data is kept apart, and ordinary data follows it.
        // Declined 0-RTT data is sent again as ordinary data, or dropped.
        assert_prefix(&early, sent, "0-RTT data");
        let rest = &sent[early.len()..];
        let ok = if complete {
            rest == got || early.is_empty() && sent.ends_with(got)
        } else {
            rest.starts_with(got) || early.is_empty() && contains(sent, got)
        };
        assert!(
            ok,
            "server read {} bytes the client did not send so",
            got.len()
        );
    }

    /// Records were forged: what a side reads is no longer what its peer
    /// wrote.
    fn forged(&self) -> bool {
        self.forgeable && self.disturbed
    }

    pub(super) fn check(&self) {
        if self.forged() {
            return;
        }
        assert_prefix(&self.received[CLIENT], &self.sent[SERVER], "client read");
        self.check_server(false);
    }

    /// `side` read the end of the stream: the peer closed, and nothing it
    /// wrote before is missing (a truncated stream is an error instead).
    pub(super) fn ended(&mut self, side: usize) {
        self.notes[side].eof = true;
        if self.forged() {
            return;
        }
        assert!(
            self.notes[1 - side].shut,
            "end of stream without the peer's close_notify"
        );
        if side == CLIENT {
            assert!(
                self.received[CLIENT] == self.sent[SERVER],
                "the client's stream ended early"
            );
        } else {
            self.check_server(true);
        }
    }

    /// The lengths of what an unbuffered stream holds stay within bounds.
    pub(super) fn audit(&mut self, side: usize) {
        let debug = match &self.sides[side] {
            Side::Ready(Stream::Client(stream)) => format!("{stream:?}"),
            Side::Ready(Stream::Server(stream)) => format!("{stream:?}"),
            _ => return,
        };
        let unsent = debug_number(&debug, "unsent: ");
        self.stats.unsent = self.stats.unsent.max(unsent);
        // One write's records, then the records reads owe the peer (16 KiB
        // and one more flight). Small fragments multiply the overhead.
        let unsent_limit = match self.knobs.fragment {
            0 => 128 * 1024,
            _ => 512 * 1024,
        };
        assert!(unsent <= unsent_limit, "{unsent} bytes unwritten");
        let unprocessed = debug_number(&debug, "unprocessed: ");
        assert!(
            unprocessed <= self.unprocessed_limit,
            "{unprocessed} bytes unprocessed"
        );
        let plaintext = debug_number(&debug, "plaintext: ");
        assert!(plaintext <= MAX_GATHER, "{plaintext} bytes of plaintext");
        let early = debug_number(&debug, "early_data: ");
        assert!(early <= MAX_EARLY_DATA, "{early} bytes of 0-RTT data");
    }

    /// The bytes that moved, and everything else a round can change.
    fn progress(&self) -> (u64, [usize; 5], [u8; 2], [Notes; 2]) {
        let wire = self.wire.borrow();
        (
            wire.moved,
            [
                wire.lanes[0].bytes.len(),
                wire.lanes[1].bytes.len(),
                self.received[0].len(),
                self.received[1].len(),
                self.early.len(),
            ],
            [self.sides[0].stage(), self.sides[1].stage()],
            self.notes,
        )
    }

    fn round(&mut self, style: u8) {
        for side in [CLIENT, SERVER] {
            self.poll_handshake(side);
            self.drive_manual(side);
            self.flush(side, false);
            let buffered = style >> side & 1 != 0;
            // Reads go on while they return data or take bytes off the wire
            // (a failed stream may take them one at a time).
            for _ in 0..READS_PER_ROUND {
                let moved = self.wire.borrow().moved;
                if !self.read(side, buffered, MAX_GATHER) && self.wire.borrow().moved == moved {
                    break;
                }
            }
        }
    }

    /// Polls both sides: some rounds with the transport's `Pending`
    /// pattern, then, with a transport that only waits for bytes or room,
    /// until two rounds change nothing. A connection that never gets there
    /// spins.
    pub(super) fn pump(&mut self, style: u8) {
        for _ in 0..PATTERN_ROUNDS {
            self.round(style);
        }
        self.wire.borrow_mut().settling = true;
        let (mut quiet, mut rounds) = (0, 0);
        while quiet < 2 {
            let before = self.progress();
            self.round(style);
            let after = self.progress();
            quiet = if after == before { quiet + 1 } else { 0 };
            rounds += 1;
            assert!(
                rounds < ROUND_LIMIT,
                "the connection never comes to rest: {before:?} then {after:?}"
            );
        }
        self.wire.borrow_mut().settling = false;
        self.at_rest();
    }

    /// Nothing moves any more. On a connection the input did not disturb,
    /// with both ends alive and no error reported, a stall is a failure:
    /// the handshake is complete, nothing waits on the wire or in a
    /// stream, and each side read all the peer wrote.
    fn at_rest(&mut self) {
        let alive = !self.sides.iter().any(|side| matches!(side, Side::Gone));
        if self.disturbed || !alive || self.notes.iter().any(|notes| notes.errored) {
            return;
        }
        assert!(
            self.sides.iter().all(Side::established),
            "the handshake stalled (stages {:?})",
            self.sides.each_ref().map(Side::stage)
        );
        for reader in [CLIENT, SERVER] {
            let waiting = self.wire.borrow().lanes[1 - reader].bytes.len();
            assert!(
                waiting == 0 || self.notes[reader].eof,
                "{waiting} bytes wait for side {reader}"
            );
            let debug = match &self.sides[reader] {
                Side::Ready(Stream::Client(stream)) => format!("{stream:?}"),
                Side::Ready(Stream::Server(stream)) => format!("{stream:?}"),
                _ => continue,
            };
            let unsent = debug_number(&debug, "unsent: ");
            assert!(
                unsent == 0,
                "{unsent} bytes of side {reader} stay unwritten"
            );
        }
        assert!(
            self.received[CLIENT] == self.sent[SERVER],
            "the client misses data"
        );
        self.check_server(true);
        self.stats.delivered += 1;
    }

    /// Feeds a connection taken out of its stream what arrived for it.
    fn drive_manual(&mut self, side: usize) {
        let Side::Manual(manual) = &mut self.sides[side] else {
            return;
        };
        if manual.done {
            return;
        }
        self.wire.borrow_mut().take_all(side, &mut manual.incoming);
        let (mut out, mut plain, mut early) = (Vec::new(), Vec::new(), Vec::new());
        let incoming = &mut manual.incoming;
        let rest = match &mut manual.connection {
            ManualConnection::Client(conn) => {
                drive(conn, incoming, &mut out, &mut plain, &mut early)
            }
            ManualConnection::Server(conn) => {
                drive(conn, incoming, &mut out, &mut plain, &mut early)
            }
        };
        manual.done = !matches!(rest, Rest::NeedInput);
        if !out.is_empty() {
            let mut wire = self.wire.borrow_mut();
            if wire.lanes[side].push(&out) {
                wire.moved += out.len() as u64;
            }
        }
        self.received[side].extend_from_slice(&plain);
        self.early.extend_from_slice(&early);
        self.check();
        match rest {
            Rest::NeedInput => {}
            Rest::PeerClosed => self.ended(side),
            Rest::Failed => {
                assert!(!self.calm(), "an undisturbed connection failed by hand");
                self.notes[side].errored = true;
            }
        }
    }

    /// Takes an unbuffered stream apart and goes on by hand with what it
    /// held: nothing it buffered may be lost.
    pub(super) fn take_apart(&mut self, side: usize) {
        if !matches!(&self.sides[side], Side::Ready(stream) if stream.unbuffered()) {
            return;
        }
        let Side::Ready(stream) = std::mem::replace(&mut self.sides[side], Side::Gone) else {
            return;
        };
        let (plaintext, incoming, outgoing, early, connection) = match stream {
            Stream::Client(stream) => {
                let parts = stream.into_parts();
                let _ = format!("{parts:?}");
                (
                    parts.plaintext,
                    parts.incoming_tls,
                    parts.outgoing_tls,
                    parts.early_data,
                    ManualConnection::Client(parts.connection),
                )
            }
            Stream::Server(stream) => {
                let parts = stream.into_parts();
                let _ = format!("{parts:?}");
                (
                    parts.plaintext,
                    parts.incoming_tls,
                    parts.outgoing_tls,
                    parts.early_data,
                    ManualConnection::Server(parts.connection),
                )
            }
            Stream::BufferedClient(_) | Stream::BufferedServer(_) => return,
        };
        assert!(plaintext.len() <= MAX_GATHER && incoming.len() <= self.unprocessed_limit);
        self.received[side].extend_from_slice(&plaintext);
        self.early.extend_from_slice(&early);
        // What the stream had not written goes out before anything else.
        {
            let mut wire = self.wire.borrow_mut();
            if wire.lanes[side].push(&outgoing) {
                wire.moved += outgoing.len() as u64;
            }
        }
        self.stats.manual += 1;
        self.sides[side] = Side::Manual(Box::new(Manual {
            connection,
            incoming,
            // After the end of the stream nothing more is processed.
            done: self.notes[side].eof,
        }));
        self.check();
    }

    /// `refresh_traffic_keys` on a side's connection.
    pub(super) fn key_update(&mut self, side: usize) {
        let Side::Ready(stream) = &mut self.sides[side] else {
            return;
        };
        let queued = match stream {
            Stream::Client(stream) => refresh(stream.get_mut().1),
            Stream::Server(stream) => refresh(stream.get_mut().1),
            Stream::BufferedClient(stream) => stream.get_mut().1.refresh_traffic_keys().is_ok(),
            Stream::BufferedServer(stream) => stream.get_mut().1.refresh_traffic_keys().is_ok(),
        };
        self.key_updates += u32::from(queued);
        // A peer refuses requests without end.
        self.lenient |= self.key_updates > KEY_UPDATE_BUDGET;
    }

    /// The server asks for a certificate after the handshake.
    pub(super) fn request_client_auth(&mut self) {
        let asked = match &mut self.sides[SERVER] {
            Side::Ready(Stream::Server(stream)) => stream.get_mut().1.request_client_auth(),
            Side::Ready(Stream::BufferedServer(stream)) => stream.get_mut().1.request_client_auth(),
            _ => return,
        };
        // Whether the client can answer is the configurations' business.
        self.lenient |= asked.is_ok();
    }

    /// The server's accepted 0-RTT data is taken out, once.
    pub(super) fn take_early_data(&mut self) {
        if let Side::Ready(Stream::Server(stream)) = &mut self.sides[SERVER] {
            let shown = stream.early_data().to_vec();
            let taken = stream.take_early_data();
            assert!(shown == taken, "early_data and take_early_data differ");
            assert!(stream.early_data().is_empty(), "0-RTT data taken twice");
            self.early.extend_from_slice(&taken);
        }
        self.check();
    }

    /// Every accessor of a side's future or stream.
    pub(super) fn accessors(&mut self, side: usize) {
        assert!(Arc::ptr_eq(self.acceptor.config(), &self.server_config));
        let _ = self.connector.config().alpn_protocols.len();
        let _ = format!("{:?} {:?}", self.connector, self.acceptor);
        let label = b"EXPORTER-browntls-fuzz";
        let exporter = match &mut self.sides[side] {
            Side::Handshaking(handshake) => {
                use super::world::Handshake;
                let transport = match &mut **handshake {
                    Handshake::Connect(f) => {
                        self.stats.waiting[CLIENT] += 1;
                        let _ = format!("{f:?}");
                        f.get_mut().map(|io| io.side) == f.get_ref().map(|io| io.side)
                            && f.get_ref().is_some()
                    }
                    Handshake::Accept(f) => {
                        self.stats.waiting[SERVER] += 1;
                        let _ = format!("{f:?}");
                        f.get_mut().map(|io| io.side) == f.get_ref().map(|io| io.side)
                            && f.get_ref().is_some()
                    }
                    Handshake::FallibleConnect(f) => !format!("{f:?}").is_empty(),
                    Handshake::FallibleAccept(f) => !format!("{f:?}").is_empty(),
                    Handshake::BufferedConnect(_) | Handshake::BufferedAccept(_) => true,
                };
                assert!(transport, "a waiting future has no transport");
                None
            }
            Side::Lazy(lazy, _) => {
                let _ = format!("{lazy:?}");
                None
            }
            Side::Ready(stream) => {
                assert!(stream.io().is_write_vectored());
                match stream {
                    Stream::Client(stream) => {
                        let side = stream.get_mut().0.side;
                        assert_eq!(side, stream.get_ref().0.side);
                        let conn = stream.get_ref().1;
                        assert!(!conn.is_handshaking(), "a stream before its handshake");
                        let _ = (conn.alpn_protocol(), conn.protocol_version());
                        conn.export_keying_material([0; 32], label, None).ok()
                    }
                    Stream::Server(stream) => {
                        let side = stream.get_mut().0.side;
                        assert_eq!(side, stream.get_ref().0.side);
                        let conn = stream.get_ref().1;
                        assert!(!conn.is_handshaking(), "a stream before its handshake");
                        let _ = (conn.alpn_protocol(), conn.server_name());
                        conn.export_keying_material([0; 32], label, None).ok()
                    }
                    Stream::BufferedClient(stream) => {
                        let conn = stream.get_ref().1;
                        (!conn.is_handshaking())
                            .then(|| conn.export_keying_material([0; 32], label, None).ok())
                            .flatten()
                    }
                    Stream::BufferedServer(stream) => stream
                        .get_ref()
                        .1
                        .export_keying_material([0; 32], label, None)
                        .ok(),
                }
            }
            _ => None,
        };
        if exporter.is_some() {
            self.exporters[side] = exporter;
        }
        if let [Some(client), Some(server)] = self.exporters {
            assert!(
                client == server,
                "the sides derive different exporter values"
            );
        }
        self.audit(side);
    }
}
