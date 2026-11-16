//! The buffered connection API: `ClientConnection`, `ServerConnection`,
//! `Connection`, `ConnectionCommon`, `CommonState`, `Acceptor`, `Stream` and
//! `StreamOwned`, driven between a genuine client and server in the same
//! process (real cryptography, both providers).
//!
//! Input: a 5-byte configuration header ([`setup::Knobs`]: versions,
//! providers, builder entry points, client authentication, resumption,
//! ALPN, early data, cipher suite and group choice, fragment size), the
//! arguments of the first connection (see [`Op::Reconnect`]), then up to 64
//! operations, each a selector byte and its arguments: move bytes between
//! the peers (in fuzzed chunks, optionally corrupted, dropped, replayed or
//! with bytes inserted), write and read application and early data through
//! every interface, close, rotate keys, export keying material, change
//! buffer limits, request post-handshake client authentication, run
//! `complete_io` and the stream adapters over an in-memory transport,
//! reconnect (resumption, 0-RTT, the `Acceptor` path), feed an `Acceptor`
//! fuzzed bytes, extract the traffic secrets, and call every accessor.
//!
//! Checked properties:
//! * application data (and 0-RTT data) one side reads is always a prefix of
//!   what the other side's writer accepted, whatever happened on the wire;
//!   once both peers are idle with nothing corrupted and nothing failed, it
//!   is all of it;
//! * both sides export the same keying material, channel binding and early
//!   keying material, and extract matching traffic secrets;
//! * both sides agree on version, suite, ALPN, handshake kind and group,
//!   and see each other's certificates;
//! * `IoState` matches what `reader()` and `write_tls` then deliver;
//! * nothing panics, whatever the bytes delivered.
//!
//! Handshake randomness comes from the operating system, so ciphertexts
//! differ between executions; the fuzzed operations and corruptions do
//! reproduce.

pub(crate) mod setup;

use std::io::{BufRead, IoSlice, Read, Write};
use std::sync::Arc;

use browntls::server::{Accepted, Acceptor, ServerConnection};
use browntls::{
    ClientConfig, ClientConnection, CommonState, Connection, ConnectionCommon, ServerConfig,
    SideData, Stream, StreamOwned,
};

use self::setup::{Knobs, assert_prefix, assert_same_secrets, server_name};
use crate::input::{Input, put_field, put_short_field};

const MAX_OPS: usize = 64;

const MAX_CONNECTIONS: usize = 4;
const CLIENT: usize = 0;
const SERVER: usize = 1;

/// The operations; the selector byte is reduced modulo their number.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Op {
    /// `side, write chunk, damage, position (u16), read chunk (u16, 0: no
    /// limit), limit (u16, 0: none)[, inserted bytes]`: `write_tls` from `side`, damage the bytes
    /// in flight, then `read_tls` and `process_new_packets` on the peer.
    Transfer,
    /// Exchange everything until both sides are idle.
    Pump,
    /// `side, method, data`: `writer()` write or write_vectored.
    Write,
    /// `side, method, size`: `reader()` read, `BufRead` or `read_to_end`.
    Read,
    /// `data`: `ClientConnection::early_data` write.
    EarlyWrite,
    /// `size`: `ServerConnection::early_data` read.
    EarlyRead,
    /// `side`: `send_close_notify`.
    CloseNotify,
    /// `side`: `refresh_traffic_keys`.
    RefreshKeys,
    /// `label, flags, context, length (u16)`: exporters on both sides.
    Export,
    /// `tls_exporter_channel_binding` on both sides.
    ChannelBinding,
    /// `side, kind, limit (u16)`: `set_buffer_limit`.
    BufferLimit,
    /// `ServerConnection::request_client_auth`.
    PostHandshakeAuth,
    /// Every accessor on both sides; agreement once both are connected.
    Accessors,
    /// `side, read chunk, write chunk, would block`: `complete_io`.
    CompleteIo,
    /// `side, owned, action, data, read chunk, write chunk, would block`.
    Stream,
    /// Connection arguments: a new pair from the same configurations.
    Reconnect,
    /// `chunk, into connection, bytes (field)`: a standalone `Acceptor`.
    Acceptor,
    /// `via enum`: `dangerous_extract_secrets` on both sides.
    Extract,
    /// `side, bytes (field)`: raw bytes delivered to `side`.
    Inject,
    /// Pump, then check that all data arrived.
    Check,
    /// `data`: `ServerConnection::set_resumption_data`.
    ResumptionData,
}

const OPS: usize = Op::ResumptionData as usize + 1;

const ALL_OPS: [Op; OPS] = [
    Op::Transfer,
    Op::Pump,
    Op::Write,
    Op::Read,
    Op::EarlyWrite,
    Op::EarlyRead,
    Op::CloseNotify,
    Op::RefreshKeys,
    Op::Export,
    Op::ChannelBinding,
    Op::BufferLimit,
    Op::PostHandshakeAuth,
    Op::Accessors,
    Op::CompleteIo,
    Op::Stream,
    Op::Reconnect,
    Op::Acceptor,
    Op::Extract,
    Op::Inject,
    Op::Check,
    Op::ResumptionData,
];

// ------------------------------------------------------------- transports

/// An in-memory transport for one side: reads what the peer wrote, writes
/// toward the peer, in chunks of at most the given sizes.
struct Pipe<'a> {
    inbound: &'a mut Vec<u8>,
    outbound: &'a mut Vec<u8>,
    read_chunk: usize,
    write_chunk: usize,
    /// When nothing is left: `WouldBlock` rather than end of file.
    would_block: bool,
}

impl Read for Pipe<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inbound.is_empty() && !buf.is_empty() {
            return if self.would_block {
                Err(std::io::ErrorKind::WouldBlock.into())
            } else {
                Ok(0)
            };
        }
        let n = buf.len().min(self.read_chunk).min(self.inbound.len());
        buf[..n].copy_from_slice(&self.inbound[..n]);
        self.inbound.drain(..n);
        Ok(n)
    }
}

impl Write for Pipe<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.write_chunk);
        self.outbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A sink that takes at most `limit` bytes per call (zero included).
struct Limited<'a>(&'a mut Vec<u8>, usize);

impl Write for Limited<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.1);
        self.0.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A chunk size from a byte: 1 to 4096, small values likely.
fn chunk(byte: u8) -> usize {
    match byte {
        0 => 4096,
        1..=127 => usize::from(byte),
        _ => usize::from(byte - 127) * 32,
    }
}

// ------------------------------------------------------------------ state

/// Arguments of [`Op::Reconnect`] (and of the first connection).
#[derive(Default)]
struct ConnectArgs<'a> {
    /// Bit 0 the server comes from an `Acceptor`, bit 1 the client uses
    /// `new_with_alpn`, bit 2 resumption data is set, bit 3 the server
    /// rejects early data, bits 4-7 the acceptor's read chunk.
    flags: u8,
    /// One-byte length-prefixed protocol names (with bit 1).
    alpn: &'a [u8],
    /// With bit 2.
    resumption_data: &'a [u8],
}

impl<'a> ConnectArgs<'a> {
    fn read(input: &mut Input<'a>) -> Self {
        let flags = input.byte();
        let alpn = if flags & 2 != 0 {
            input.short_field()
        } else {
            &[]
        };
        let resumption_data = if flags & 4 != 0 {
            input.short_field()
        } else {
            &[]
        };
        Self {
            flags,
            alpn,
            resumption_data,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.flags);
        if self.flags & 2 != 0 {
            put_short_field(out, self.alpn);
        }
        if self.flags & 4 != 0 {
            put_short_field(out, self.resumption_data);
        }
    }
}

/// Splits `bytes` into ALPN protocol names, each with a one-byte length.
fn alpn_list(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some((&len, rest)) = bytes.split_first() {
        let (name, rest) = rest.split_at(usize::from(len).min(rest.len()));
        out.push(name.to_vec());
        bytes = rest;
    }
    out
}

struct World {
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    /// Index [`CLIENT`] holds a `Connection::Client`, [`SERVER`] a
    /// `Connection::Server`; `None` once consumed or refused.
    conns: [Option<Connection>; 2],
    /// `wire[s]`: bytes side `s` wrote that its peer has not read.
    wire: [Vec<u8>; 2],
    /// `sent[s]`: application data side `s`'s writer accepted.
    sent: [Vec<u8>; 2],
    /// `recv[s]`: application data the peer read from side `s`.
    recv: [Vec<u8>; 2],
    early_sent: Vec<u8>,
    early_recv: Vec<u8>,
    /// Bytes on the wire were changed, dropped, replayed or invented.
    corrupted: bool,
    failed: [bool; 2],
    closed: [bool; 2],
    connections: usize,
    /// Every value given to `set_resumption_data` (and the default).
    resumption_data: Vec<Vec<u8>>,
}

impl World {
    fn new(knobs: Knobs) -> Option<Self> {
        let client_config = Arc::new(knobs.client_config()?);
        let server_config = Arc::new(knobs.server_config()?);
        Some(Self {
            client_config,
            server_config,
            conns: [None, None],
            wire: [Vec::new(), Vec::new()],
            sent: [Vec::new(), Vec::new()],
            recv: [Vec::new(), Vec::new()],
            early_sent: Vec::new(),
            early_recv: Vec::new(),
            corrupted: false,
            failed: [false; 2],
            closed: [false; 2],
            connections: 0,
            resumption_data: vec![Vec::new()],
        })
    }

    fn client(&mut self) -> Option<&mut ClientConnection> {
        match self.conns[CLIENT].as_mut()? {
            Connection::Client(c) => Some(c),
            Connection::Server(_) => None,
        }
    }

    fn server(&mut self) -> Option<&mut ServerConnection> {
        match self.conns[SERVER].as_mut()? {
            Connection::Server(s) => Some(s),
            Connection::Client(_) => None,
        }
    }

    /// Replaces the pair with a new client and server.
    fn connect(&mut self, args: &ConnectArgs<'_>) {
        if self.connections >= MAX_CONNECTIONS {
            return;
        }
        self.connections += 1;
        self.conns = [None, None];
        self.wire = [Vec::new(), Vec::new()];
        self.sent = [Vec::new(), Vec::new()];
        self.recv = [Vec::new(), Vec::new()];
        self.early_sent.clear();
        self.early_recv.clear();
        self.corrupted = false;
        self.failed = [false; 2];
        self.closed = [false; 2];

        let client = if args.flags & 2 != 0 {
            ClientConnection::new_with_alpn(
                self.client_config.clone(),
                server_name(),
                alpn_list(args.alpn),
            )
        } else {
            ClientConnection::new(self.client_config.clone(), server_name())
        };
        let Ok(client) = client else {
            return;
        };
        self.conns[CLIENT] = Some(Connection::from(client));

        let server = if args.flags & 1 != 0 {
            self.flush(CLIENT, usize::MAX);
            const CHUNKS: [usize; 16] = [
                4096, 1, 2, 3, 5, 8, 13, 64, 100, 256, 300, 512, 1000, 1500, 2000, 3000,
            ];
            self.accept(CHUNKS[usize::from(args.flags >> 4)])
        } else {
            match ServerConnection::new(self.server_config.clone()) {
                Ok(mut server) => {
                    if args.flags & 8 != 0 {
                        // Before any ClientHello, as documented.
                        server.reject_early_data();
                    }
                    Some(server)
                }
                Err(_) => None,
            }
        };
        let Some(mut server) = server else {
            self.failed[SERVER] = true;
            return;
        };
        if args.flags & 4 != 0 {
            server.set_resumption_data(args.resumption_data);
            self.resumption_data.push(args.resumption_data.to_vec());
        }
        self.conns[SERVER] = Some(Connection::from(server));
        self.process(SERVER);
    }

    /// The `Acceptor` path: reads the client's first flight in chunks of
    /// `chunk` bytes, then continues with the server configuration.
    fn accept(&mut self, chunk: usize) -> Option<ServerConnection> {
        let mut acceptor = Acceptor::default();
        for _ in 0..4096 {
            let wire = &mut self.wire[CLIENT];
            let n = chunk.min(wire.len());
            let mut piece = &wire[..n];
            let read = acceptor.read_tls(&mut piece);
            let used = n - piece.len();
            wire.drain(..used);
            match acceptor.accept() {
                Ok(None) => {
                    if read.is_err() || used == 0 {
                        return None;
                    }
                }
                Ok(Some(accepted)) => {
                    check_client_hello(&accepted);
                    return match accepted.into_connection(self.server_config.clone()) {
                        Ok(server) => Some(server),
                        Err((_, mut alert)) => {
                            let _ = alert.write_all(&mut self.wire[SERVER]);
                            None
                        }
                    };
                }
                Err((_, mut alert)) => {
                    let _ = alert.write_all(&mut self.wire[SERVER]);
                    return None;
                }
            }
        }
        None
    }

    /// `write_tls` from `side` until nothing is left (or `limit` per call
    /// lets nothing through). Returns whether bytes moved.
    fn flush(&mut self, side: usize, limit: usize) -> bool {
        let Some(conn) = self.conns[side].as_mut() else {
            return false;
        };
        let before = self.wire[side].len();
        for _ in 0..64 {
            if !conn.wants_write() {
                break;
            }
            match conn.write_tls(&mut Limited(&mut self.wire[side], limit)) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        self.wire[side].len() != before
    }

    /// Delivers up to `limit` bytes of the peer's output to `to`, `chunk`
    /// bytes per `read_tls`, processing as it goes. Returns whether bytes
    /// moved.
    fn deliver(&mut self, to: usize, chunk: usize, limit: usize) -> bool {
        let from = 1 - to;
        let mut left = limit.min(self.wire[from].len());
        let mut moved = false;
        let mut stalled = 0;
        for _ in 0..512 {
            if left == 0 || self.failed[to] || stalled > 1 {
                break;
            }
            let Some(conn) = self.conns[to].as_mut() else {
                break;
            };
            let n = chunk.min(left);
            let mut piece = &self.wire[from][..n];
            // A full plaintext buffer refuses more; processing empties it.
            let _ = conn.read_tls(&mut piece);
            let used = n - piece.len();
            self.wire[from].drain(..used);
            left -= used;
            moved |= used > 0;
            stalled = if used == 0 { stalled + 1 } else { 0 };
            self.process(to);
        }
        moved
    }

    /// `process_new_packets` on `side`, then the `IoState` checks with every
    /// byte of plaintext read out.
    fn process(&mut self, side: usize) {
        let Some(conn) = self.conns[side].as_mut() else {
            return;
        };
        match conn.process_new_packets() {
            Ok(io) => {
                assert_eq!(io.tls_bytes_to_write() > 0, conn.wants_write());
                let plaintext = io.plaintext_bytes_to_read();
                let closed = io.peer_has_closed();
                let read = self.read_with(side, 0, 0);
                assert_eq!(read, plaintext, "IoState::plaintext_bytes_to_read");
                if closed {
                    let conn = self.conns[side].as_mut().expect("connection");
                    assert!(matches!(conn.reader().read(&mut [0u8; 8]), Ok(0)));
                }
            }
            Err(_) => self.failed[side] = true,
        }
    }

    /// Reads the buffered plaintext of `side` with `method` (0: `read`,
    /// 1: `BufRead`, 2: `read_to_end`): all of it, or about `size` bytes
    /// when that is not zero. Returns the number of bytes read.
    fn read_with(&mut self, side: usize, method: u8, size: usize) -> usize {
        let Some(conn) = self.conns[side].as_mut() else {
            return 0;
        };
        let from = 1 - side;
        let before = self.recv[from].len();
        let mut want = if size == 0 { usize::MAX } else { size };
        let mut buf = [0u8; 512];
        for _ in 0..256 {
            if want == 0 {
                break;
            }
            let mut reader = conn.reader();
            let n = match method % 3 {
                0 => {
                    let n = want.min(buf.len());
                    match reader.read(&mut buf[..n]) {
                        Ok(n) => {
                            self.recv[from].extend_from_slice(&buf[..n]);
                            n
                        }
                        Err(_) => 0,
                    }
                }
                1 => match reader.fill_buf() {
                    Ok(chunk) => {
                        let n = chunk.len().min(want);
                        self.recv[from].extend_from_slice(&chunk[..n]);
                        reader.consume(n);
                        n
                    }
                    Err(_) => 0,
                },
                _ => {
                    let mut all = Vec::new();
                    let _ = reader.read_to_end(&mut all);
                    self.recv[from].extend_from_slice(&all);
                    want = all.len();
                    all.len()
                }
            };
            if n == 0 {
                break;
            }
            want -= n;
        }
        assert_prefix(&self.recv[from], &self.sent[from], "application data");
        self.recv[from].len() - before
    }

    /// Exchanges bytes until both sides are idle.
    fn pump(&mut self) {
        for _ in 0..32 {
            let mut moved = false;
            for side in [CLIENT, SERVER] {
                moved |= self.flush(side, usize::MAX);
            }
            for side in [SERVER, CLIENT] {
                moved |= self.deliver(side, usize::MAX, usize::MAX);
            }
            if !moved {
                break;
            }
        }
        for side in [CLIENT, SERVER] {
            self.process(side);
        }
    }

    /// Whether both sides completed the handshake and nothing has gone
    /// wrong, so that they must agree.
    fn healthy(&self) -> bool {
        !self.corrupted
            && !self.failed[CLIENT]
            && !self.failed[SERVER]
            && self
                .conns
                .iter()
                .all(|c| c.as_ref().is_some_and(|c| !c.is_handshaking()))
    }

    fn check(&mut self) {
        self.pump();
        if !self.healthy() {
            return;
        }
        for side in [CLIENT, SERVER] {
            if !self.closed[side] {
                assert_eq!(
                    self.recv[side], self.sent[side],
                    "application data lost on an intact connection"
                );
            }
        }
        let accepted = self.client().is_some_and(|c| c.is_early_data_accepted());
        if accepted && !self.closed[CLIENT] {
            self.early_read(usize::MAX);
            assert_eq!(self.early_recv, self.early_sent, "accepted early data lost");
        }
    }

    fn early_read(&mut self, size: usize) {
        let Some(server) = self.server() else {
            return;
        };
        let Some(mut reader) = server.early_data() else {
            return;
        };
        let _ = format!("{reader:?}");
        let mut buf = vec![0u8; size.min(4096)];
        let mut got = Vec::new();
        for _ in 0..64 {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
            if size != usize::MAX {
                break;
            }
        }
        self.early_recv.extend_from_slice(&got);
        assert_prefix(&self.early_recv, &self.early_sent, "early data");
    }

    fn export(&mut self, label: &[u8], context: Option<&[u8]>, len: usize, early: bool) {
        let mut out: [Option<Vec<u8>>; 2] = [None, None];
        for side in [CLIENT, SERVER] {
            let Some(conn) = self.conns[side].as_ref() else {
                continue;
            };
            let buf = vec![0u8; len];
            let result = if early {
                conn.export_early_keying_material(buf, label, context)
            } else {
                conn.export_keying_material(buf, label, context)
            };
            out[side] = result.ok();
        }
        if let [Some(c), Some(s)] = &out {
            // The early exporter depends on the ClientHello the server saw.
            if !early || !self.corrupted {
                assert_eq!(c, s, "exporters disagree (early: {early})");
            }
        }
    }

    fn channel_binding(&mut self) {
        let mut out = [None, None];
        for side in [CLIENT, SERVER] {
            let Some(conn) = self.conns[side].as_ref() else {
                continue;
            };
            let binding = conn.tls_exporter_channel_binding().ok();
            if let Some(binding) = binding {
                let exported = conn
                    .export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", Some(&[]))
                    .expect("exporter failed where the channel binding succeeded");
                assert_eq!(binding, exported);
            }
            out[side] = binding;
        }
        if let [Some(c), Some(s)] = out {
            assert_eq!(c, s, "channel bindings disagree");
        }
    }

    fn accessors(&mut self) {
        for conn in self.conns.iter().flatten() {
            let _ = (
                conn.wants_write(),
                conn.wants_read(),
                conn.is_handshaking(),
                conn.peer_certificates().map(<[_]>::len),
                conn.alpn_protocol(),
                conn.negotiated_cipher_suite(),
                conn.negotiated_key_exchange_group().map(|g| g.name()),
                conn.protocol_version(),
                conn.handshake_kind(),
                conn.external_psk_identity(),
                conn.fips(),
            );
        }
        if let Some(client) = self.client() {
            let _ = (
                client.tls13_tickets_received(),
                client.delegated_credential().is_some(),
                client.post_handshake_auth_responses(),
                client.is_early_data_accepted(),
                client.fips(),
                client.ech_status(),
            );
        }
        let resumption_data = self.resumption_data.clone();
        if let Some(server) = self.server() {
            let _ = (
                server.server_name().map(str::len),
                server.fips(),
                server.ech_status(),
                server.post_handshake_auth_offered(),
                server.post_handshake_auth_status(),
            );
            if let Some(data) = server.received_resumption_data() {
                assert!(
                    resumption_data.iter().any(|d| d == data),
                    "resumption data that was never stored"
                );
            }
        }
        if !self.healthy() {
            return;
        }
        let pki = setup::Pki::get();
        let [Some(c), Some(s)] = &self.conns else {
            return;
        };
        assert_eq!(c.protocol_version(), s.protocol_version());
        assert_eq!(
            c.negotiated_cipher_suite().map(|s| s.suite()),
            s.negotiated_cipher_suite().map(|s| s.suite())
        );
        assert_eq!(c.alpn_protocol(), s.alpn_protocol());
        if let Some(alpn) = c.alpn_protocol() {
            assert!(self.server_config.alpn_protocols.iter().any(|p| p == alpn));
        }
        assert_eq!(c.handshake_kind(), s.handshake_kind());
        if let (Some(a), Some(b)) = (
            c.negotiated_key_exchange_group(),
            s.negotiated_key_exchange_group(),
        ) {
            assert_eq!(a.name(), b.name());
        }
        assert_eq!(c.peer_certificates(), Some(&pki.server_chain[..]));
        if let Some(certs) = s.peer_certificates() {
            assert_eq!(certs, &pki.client_chain[..]);
        }
        if let Connection::Server(server) = s {
            assert_eq!(server.server_name(), Some("localhost"));
        }
    }

    fn post_handshake_auth(&mut self) {
        let Some(server) = self.server() else {
            return;
        };
        let _ = server.post_handshake_auth_offered();
        let _ = server.request_client_auth();
        let _ = server.post_handshake_auth_status();
    }

    /// Whether `complete_io` (also called by the stream adapters while
    /// handshaking) is left out: during a handshake it is only driven
    /// between genuine peers that have not closed; damaged and invented
    /// bytes reach a handshaking connection through `read_tls`.
    fn skip_complete_io(&self, side: usize) -> bool {
        self.conns[side]
            .as_ref()
            .is_some_and(|c| c.is_handshaking())
            && (self.corrupted || self.closed[1 - side])
    }

    fn complete_io(&mut self, side: usize, read: usize, write: usize, would_block: bool) {
        if self.skip_complete_io(side) {
            return;
        }
        let [w0, w1] = &mut self.wire;
        let (inbound, outbound) = if side == CLIENT { (w1, w0) } else { (w0, w1) };
        let Some(conn) = self.conns[side].as_mut() else {
            return;
        };
        let mut pipe = Pipe {
            inbound,
            outbound,
            read_chunk: read,
            write_chunk: write,
            would_block,
        };
        if let Err(err) = conn.complete_io(&mut pipe)
            && err.kind() == std::io::ErrorKind::InvalidData
        {
            self.failed[side] = true;
        }
        self.process(side);
    }

    /// One action on a `Stream` or `StreamOwned` over a [`Pipe`].
    fn stream(&mut self, side: usize, owned: bool, action: u8, data: &[u8], pipe: PipeArgs) {
        if self.skip_complete_io(side) {
            return;
        }
        let Some(conn) = self.conns[side].take() else {
            return;
        };
        let [w0, w1] = &mut self.wire;
        let (inbound, outbound) = if side == CLIENT { (w1, w0) } else { (w0, w1) };
        let pipe = Pipe {
            inbound,
            outbound,
            read_chunk: pipe.read,
            write_chunk: pipe.write,
            would_block: pipe.would_block,
        };
        let from = 1 - side;
        let (sent, recv) = (&mut self.sent[side], &mut self.recv[from]);
        let conn = match conn {
            Connection::Client(c) => {
                Connection::from(stream_action(c, pipe, owned, action, data, sent, recv))
            }
            Connection::Server(s) => {
                Connection::from(stream_action(s, pipe, owned, action, data, sent, recv))
            }
        };
        self.conns[side] = Some(conn);
        assert_prefix(&self.recv[from], &self.sent[from], "stream data");
        self.process(side);
    }

    fn extract(&mut self, via_enum: bool) {
        self.pump();
        let healthy = self.healthy() && !self.closed[CLIENT] && !self.closed[SERVER];
        let [c, s] = [self.conns[CLIENT].take(), self.conns[SERVER].take()];
        let extract = |conn: Option<Connection>| {
            let conn = conn?;
            if via_enum {
                return conn.dangerous_extract_secrets().ok();
            }
            match conn {
                Connection::Client(c) => c.dangerous_extract_secrets().ok(),
                Connection::Server(s) => s.dangerous_extract_secrets().ok(),
            }
        };
        let (c, s) = (extract(c), extract(s));
        if let (Some(c), Some(s)) = (c, s)
            && healthy
        {
            assert_same_secrets(&c.tx, &s.rx);
            assert_same_secrets(&s.tx, &c.rx);
        }
    }
}

/// How a [`Pipe`] behaves.
#[derive(Clone, Copy)]
struct PipeArgs {
    read: usize,
    write: usize,
    would_block: bool,
}

impl PipeArgs {
    fn read(input: &mut Input<'_>) -> Self {
        Self {
            read: chunk(input.byte()),
            write: chunk(input.byte()),
            would_block: input.bool(),
        }
    }
}

/// One action on a stream adapter; returns the connection.
fn stream_action<C, S>(
    mut conn: C,
    mut pipe: Pipe<'_>,
    owned: bool,
    action: u8,
    data: &[u8],
    sent: &mut Vec<u8>,
    recv: &mut Vec<u8>,
) -> C
where
    C: std::ops::DerefMut + std::ops::Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn act<T: Read + Write>(
        stream: &mut T,
        action: u8,
        data: &[u8],
        sent: &mut Vec<u8>,
        recv: &mut Vec<u8>,
    ) {
        match action % 4 {
            0 => {
                if let Ok(n) = stream.write(data) {
                    sent.extend_from_slice(&data[..n]);
                }
            }
            1 => {
                let mut buf = vec![0u8; data.len().max(1)];
                if let Ok(n) = stream.read(&mut buf) {
                    recv.extend_from_slice(&buf[..n]);
                }
            }
            2 => {
                let mid = usize::from(action >> 2).min(data.len());
                let (a, b) = data.split_at(mid);
                if let Ok(n) = stream.write_vectored(&[IoSlice::new(a), IoSlice::new(b)]) {
                    sent.extend_from_slice(&data[..n]);
                }
            }
            _ => {
                let _ = stream.flush();
            }
        }
    }

    if owned {
        let mut stream = StreamOwned::new(conn, pipe);
        let read_chunk = stream.get_ref().read_chunk;
        stream.get_mut().read_chunk = read_chunk.max(1);
        act(&mut stream, action, data, sent, recv);
        let (conn, _pipe) = stream.into_parts();
        conn
    } else {
        let mut stream = Stream::new(&mut conn, &mut pipe);
        if action & 0x80 != 0 {
            let _ = stream.complete_prior_io();
        } else {
            act(&mut stream, action, data, sent, recv);
        }
        conn
    }
}

/// Calls every `ClientHello` accessor.
fn check_client_hello(accepted: &Accepted) {
    let hello = accepted.client_hello();
    let _ = (
        hello.server_name().map(str::len),
        hello.signature_schemes().len(),
        hello.alpn().map(Iterator::count),
        hello.cipher_suites().len(),
        hello.certificate_authorities().map(<[_]>::len),
        hello.named_groups().map(<[_]>::len),
        hello.client_cert_types().map(<[_]>::len),
        hello.server_cert_types().map(<[_]>::len),
    );
    let _ = format!("{accepted:?}");
}

/// A standalone `Acceptor` fed `bytes` in `chunk`-byte pieces.
fn acceptor(bytes: &[u8], chunk: usize, config: Option<Arc<ServerConfig>>) {
    let mut acceptor = Acceptor::default();
    let mut rest = bytes;
    let mut sink = Vec::new();
    for _ in 0..64 {
        let n = chunk.min(rest.len());
        let mut piece = &rest[..n];
        let _ = acceptor.read_tls(&mut piece);
        rest = &rest[n - piece.len()..];
        match acceptor.accept() {
            Ok(None) => {
                if n == 0 {
                    break;
                }
            }
            Ok(Some(accepted)) => {
                check_client_hello(&accepted);
                if let Some(config) = config {
                    match accepted.into_connection(config) {
                        Ok(mut conn) => {
                            let _ = conn.process_new_packets();
                            let _ = conn.write_tls(&mut sink);
                        }
                        Err((_, mut alert)) => {
                            let _ = alert.write(&mut Limited(&mut sink, 3));
                            let _ = alert.write_all(&mut sink);
                        }
                    }
                }
                // The acceptor is spent now.
                assert!(acceptor.read_tls(&mut &b"\x16"[..]).is_err());
                break;
            }
            Err((_, mut alert)) => {
                let _ = alert.write(&mut Limited(&mut sink, 3));
                let _ = alert.write_all(&mut sink);
                let _ = format!("{alert:?}");
                break;
            }
        }
    }
    if let Err((_, mut alert)) = acceptor.accept() {
        let _ = alert.write_all(&mut sink);
    }
    let _ = format!("{acceptor:?}");
}

/// Damages the bytes in flight: `damage % 8 < 4` leaves them alone,
/// otherwise flips a bit, drops a range, replays a range or inserts bytes
/// (read from `input`) at `pos`. Returns whether anything changed.
pub(crate) fn damage(wire: &mut Vec<u8>, damage: u8, pos: usize, input: &mut Input<'_>) -> bool {
    if wire.is_empty() || damage % 8 < 4 {
        return false;
    }
    let at = pos % wire.len();
    let n = usize::from(damage >> 3).min(wire.len() - at).max(1);
    match damage % 4 {
        0 => wire[at] ^= 1 << (damage >> 5),
        1 => {
            wire.drain(at..at + n);
        }
        2 => {
            let copy = wire[at..at + n].to_vec();
            wire.splice(at..at, copy);
        }
        _ => {
            let bytes = input.short_field();
            wire.splice(at..at, bytes.iter().copied());
        }
    }
    true
}

/// The `tls_conn` fuzz target.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let knobs = Knobs::read(&mut input);
    let Some(mut world) = World::new(knobs) else {
        return;
    };
    let args = ConnectArgs::read(&mut input);
    world.connect(&args);

    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match ALL_OPS[input.choose(OPS)] {
            Op::Transfer => {
                let side = usize::from(input.bool());
                let write_chunk = chunk(input.byte());
                let how = input.byte();
                let pos = usize::from(input.u16());
                let read_chunk = match input.u16() {
                    0 => usize::MAX,
                    n => usize::from(n),
                };
                let limit = match input.u16() {
                    0 => usize::MAX,
                    n => usize::from(n),
                };
                world.flush(side, write_chunk);
                world.corrupted |= damage(&mut world.wire[side], how, pos, &mut input);
                world.deliver(1 - side, read_chunk, limit);
            }
            Op::Pump => world.pump(),
            Op::Write => {
                let side = usize::from(input.bool());
                let method = input.byte();
                let data = input.short_field();
                let Some(conn) = world.conns[side].as_mut() else {
                    continue;
                };
                let accepted = if method & 1 == 0 {
                    conn.writer().write(data)
                } else {
                    let mid = usize::from(method >> 1).min(data.len());
                    let (a, b) = data.split_at(mid);
                    conn.writer()
                        .write_vectored(&[IoSlice::new(a), IoSlice::new(b)])
                };
                let _ = conn.writer().flush();
                if let Ok(n) = accepted {
                    assert!(n <= data.len());
                    world.sent[side].extend_from_slice(&data[..n]);
                }
            }
            Op::Read => {
                let side = usize::from(input.bool());
                let method = input.byte();
                let size = usize::from(input.byte());
                world.read_with(side, method, size);
            }
            Op::EarlyWrite => {
                let data = input.short_field();
                let Some(client) = world.client() else {
                    continue;
                };
                let Some(mut early) = client.early_data() else {
                    continue;
                };
                let left = early.bytes_left();
                let _ = format!("{early:?}");
                if let Ok(n) = early.write(data) {
                    assert!(n <= left && n <= data.len());
                    assert_eq!(early.bytes_left(), left - n);
                    world.early_sent.extend_from_slice(&data[..n]);
                }
            }
            Op::EarlyRead => {
                let size = usize::from(input.byte()).max(1);
                world.early_read(size);
            }
            Op::CloseNotify => {
                let side = usize::from(input.bool());
                if let Some(conn) = world.conns[side].as_mut() {
                    conn.send_close_notify();
                    world.closed[side] = true;
                }
            }
            Op::RefreshKeys => {
                let side = usize::from(input.bool());
                if let Some(conn) = world.conns[side].as_mut() {
                    let _ = conn.refresh_traffic_keys();
                }
            }
            Op::Export => {
                let label = input.short_field();
                let flags = input.byte();
                let context = input.short_field();
                let len = usize::from(input.u16()) % 1200;
                let context = (flags & 1 != 0).then_some(context);
                world.export(label, context, len, flags & 2 != 0);
            }
            Op::ChannelBinding => world.channel_binding(),
            Op::BufferLimit => {
                let side = usize::from(input.bool());
                let kind = input.byte();
                let limit = usize::from(input.u16());
                let limit = (kind & 1 != 0).then_some(limit);
                match (kind & 2 != 0, world.conns[side].as_mut()) {
                    (true, Some(conn)) => conn.set_buffer_limit(limit),
                    (false, Some(Connection::Client(c))) => {
                        let common: &mut CommonState = c;
                        common.set_buffer_limit(limit);
                    }
                    (false, Some(Connection::Server(s))) => {
                        let common: &mut ConnectionCommon<_> = s;
                        common.set_buffer_limit(limit);
                    }
                    _ => {}
                }
            }
            Op::PostHandshakeAuth => world.post_handshake_auth(),
            Op::Accessors => world.accessors(),
            Op::CompleteIo => {
                let side = usize::from(input.bool());
                let pipe = PipeArgs::read(&mut input);
                world.complete_io(side, pipe.read, pipe.write, pipe.would_block);
            }
            Op::Stream => {
                let side = usize::from(input.bool());
                let owned = input.bool();
                let action = input.byte();
                let data = input.short_field();
                let pipe = PipeArgs::read(&mut input);
                world.stream(side, owned, action, data, pipe);
            }
            Op::Reconnect => {
                let args = ConnectArgs::read(&mut input);
                world.connect(&args);
            }
            Op::Acceptor => {
                let chunk = chunk(input.byte());
                let config = input.bool().then(|| world.server_config.clone());
                acceptor(input.field(), chunk, config);
            }
            Op::Extract => {
                let via_enum = input.bool();
                world.extract(via_enum);
            }
            Op::Inject => {
                let side = usize::from(input.bool());
                let bytes = input.field();
                world.wire[1 - side].extend_from_slice(bytes);
                world.corrupted = true;
                world.deliver(side, usize::MAX, usize::MAX);
            }
            Op::Check => world.check(),
            Op::ResumptionData => {
                let data = input.short_field();
                if let Some(server) = world.server() {
                    server.set_resumption_data(data);
                    world.resumption_data.push(data.to_vec());
                }
            }
        }
    }
    world.accessors();
    world.check();
}

// ------------------------------------------------------------------ seeds

/// Builds one seed: knobs, first connection, then operations.
struct Seed(Vec<u8>);

impl Seed {
    fn new(knobs: [u8; 5], connect: &ConnectArgs<'_>) -> Self {
        let mut out = knobs.to_vec();
        connect.write(&mut out);
        Self(out)
    }

    fn op(mut self, op: Op, args: &[u8]) -> Self {
        self.0.push(op as u8);
        self.0.extend_from_slice(args);
        self
    }

    fn write(mut self, side: u8, method: u8, data: &[u8]) -> Self {
        self.0.extend_from_slice(&[Op::Write as u8, side, method]);
        put_short_field(&mut self.0, data);
        self
    }

    /// [`Op::Transfer`] with the given damage, position and read chunk,
    /// write chunk and limit unrestricted.
    fn transfer(self, side: u8, how: u8, pos: u8, read: u8) -> Self {
        self.op(Op::Transfer, &[side, 0, how, 0, pos, 0, read, 0, 0])
    }

    fn reconnect(mut self, args: &ConnectArgs<'_>) -> Self {
        self.0.push(Op::Reconnect as u8);
        args.write(&mut self.0);
        self
    }

    /// A conversation over a connected pair, through most operations.
    fn conversation(self) -> Self {
        self.op(Op::Pump, &[])
            .op(Op::Accessors, &[])
            .write(0, 0, b"hello from the client")
            .write(1, 7, b"hello from the server")
            .transfer(0, 0, 0, 0)
            .transfer(1, 0, 0, 3)
            .op(Op::Read, &[1, 0, 4])
            .op(Op::Read, &[1, 1, 0])
            .op(Op::Read, &[0, 2, 0])
            .op(
                Op::Export,
                &[4, b't', b'e', b's', b't', 1, 2, b'c', b'x', 0, 32],
            )
            .op(Op::Export, &[0, 0, 0, 0, 0])
            .op(Op::ChannelBinding, &[])
            .op(Op::RefreshKeys, &[0])
            .op(Op::Pump, &[])
            .op(Op::Check, &[])
    }
}

/// Starting inputs for `tls_conn`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let plain = ConnectArgs::default();
    let resume = ConnectArgs {
        flags: 4 | 2,
        alpn: b"\x04fuzz\x02h2",
        resumption_data: b"state",
    };
    let accept = ConnectArgs {
        flags: 1 | 0x30,
        ..ConnectArgs::default()
    };
    let mut seeds = Vec::new();

    // Each version, provider pair and builder entry point.
    let flags = [0x00u8, 0x01, 0x02, 0x05, 0x0a, 0x1d, 0x2e, 0x33];
    let auth = [0x40u8, 0x41, 0x80, 0x0e, 0x13, 0x22, 0xc0, 0x00];
    for (flags, auth) in flags.into_iter().zip(auth) {
        seeds.push(Seed::new([flags, auth, 0, 0, 0], &plain).conversation().0);
    }

    // Single suites, group choices, fragment sizes.
    for (suite, groups, fragment) in [
        (1u8, 0x23u8, 0u8),
        (2, 0x31, 20),
        (3, 0x44, 255),
        (4, 0, 1),
        (5, 0, 0),
        (6, 0, 0),
        (7, 0x88, 0),
        (8, 0, 0),
    ] {
        let seed = Seed::new([0x00, 0x40, suite, groups, fragment], &plain).conversation();
        seeds.push(seed.0);
    }

    // Resumption with 0-RTT, read on the server; the Acceptor path.
    let seed = Seed::new([0x41 | 0x80, 0x44, 0, 0, 0], &resume)
        .conversation()
        .op(Op::CloseNotify, &[0])
        .op(Op::CloseNotify, &[1])
        .op(Op::Pump, &[])
        .reconnect(&resume)
        .op(Op::EarlyWrite, &[5, b'e', b'a', b'r', b'l', b'y'])
        .op(Op::Export, &[1, b'x', 2, 0, 0, 16])
        .transfer(0, 0, 0, 0)
        .op(Op::EarlyRead, &[3])
        .op(Op::EarlyRead, &[200])
        .op(Op::Export, &[1, b'x', 2, 0, 0, 16])
        .op(Op::Accessors, &[])
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[])
        .op(Op::Check, &[])
        .op(Op::Extract, &[0])
        .reconnect(&accept)
        .op(Op::Pump, &[])
        .op(Op::Accessors, &[])
        .op(Op::Extract, &[1]);
    seeds.push(seed.0);
    let seed = Seed::new([0x41, 0x04, 0, 0, 0], &accept)
        .conversation()
        .op(Op::Extract, &[1]);
    seeds.push(seed.0);
    let seed = Seed::new([0x41, 0x00, 0, 0, 0], &plain)
        .op(Op::Pump, &[])
        .reconnect(&ConnectArgs {
            flags: 8,
            ..ConnectArgs::default()
        })
        .op(Op::EarlyWrite, &[2, b'h', b'i'])
        .op(Op::Pump, &[])
        .op(Op::EarlyRead, &[9])
        .op(Op::Check, &[]);
    seeds.push(seed.0);

    // Post-handshake authentication, with and without a certificate.
    for auth in [0x03u8, 0x02, 0x01] {
        let seed = Seed::new([0x01, auth, 0, 0, 0], &plain)
            .op(Op::Pump, &[])
            .op(Op::PostHandshakeAuth, &[])
            .op(Op::Pump, &[])
            .op(Op::Accessors, &[])
            .op(Op::PostHandshakeAuth, &[])
            .op(Op::Check, &[]);
        seeds.push(seed.0);
    }

    // complete_io and the stream adapters, borrowed and owned.
    let mut seed = Seed::new([0x00, 0x40, 0, 0, 0], &plain);
    for (side, args) in [
        (0u8, [0u8, 0, 0]),
        (1, [0, 0, 0]),
        (0, [0, 0, 0]),
        (1, [7, 3, 1]),
    ] {
        seed = seed.op(Op::CompleteIo, &[side, args[0], args[1], args[2]]);
    }
    for (side, owned, action) in [
        (0u8, 0u8, 0x80u8),
        (1, 0, 0x80),
        (0, 0, 0),
        (0, 1, 2 | 8),
        (1, 1, 1),
        (1, 0, 3),
        (1, 0, 0),
        (0, 1, 1),
        (0, 0, 1),
    ] {
        seed = seed.op(
            Op::Stream,
            &[side, owned, action, 4, b'd', b'a', b't', b'a', 0, 0, 0],
        );
    }
    seeds.push(seed.op(Op::Check, &[]).0);

    // Buffer limits, damaged and invented bytes, resumption data.
    let seed = Seed::new([0x00, 0x00, 0, 0, 0], &plain)
        .op(Op::BufferLimit, &[0, 3, 0, 10])
        .op(Op::BufferLimit, &[1, 1, 0, 0])
        .op(Op::BufferLimit, &[0, 0, 0, 0])
        .op(Op::ResumptionData, &[3, b'a', b'b', b'c'])
        .write(0, 0, b"limited")
        .op(Op::Pump, &[])
        .op(Op::BufferLimit, &[1, 2, 0, 0])
        .write(1, 0, b"unlimited")
        .transfer(1, 4, 9, 0)
        .transfer(0, 5 | 8, 1, 0)
        .transfer(1, 6, 0, 0)
        .transfer(0, 7, 2, 0)
        .op(Op::Inject, &[0, 0, 5, 0x15, 3, 3, 0, 2])
        .op(Op::Accessors, &[]);
    let mut bytes = seed.0;
    // The inserted bytes of the last transfer follow its arguments.
    let at = bytes.len() - 10;
    bytes.splice(at..at, [2, 0x17, 0x03]);
    seeds.push(bytes);
    let seed = Seed::new([0x02, 0x00, 0, 0, 0], &plain)
        .transfer(0, 4, 50, 0)
        .op(Op::Pump, &[]);
    seeds.push(seed.0);

    // A genuine ClientHello for the standalone acceptor, and garbage.
    let hello = {
        let config = Knobs::default().client_config().expect("client config");
        let mut client = ClientConnection::new(Arc::new(config), server_name()).expect("client");
        let mut out = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut out).expect("write");
        }
        out
    };
    for (chunk, into) in [(0u8, 1u8), (40, 0), (3, 1)] {
        let mut seed = Seed::new([0; 5], &plain).0;
        seed.extend_from_slice(&[Op::Acceptor as u8, chunk, into]);
        put_field(&mut seed, &hello);
        seeds.push(seed);
    }
    for garbage in [&[0x16, 3, 1, 0, 4, 1, 0, 0, 0][..], &[0x17, 3, 3, 0, 1, 0]] {
        let mut seed = Seed::new([0; 5], &plain).0;
        seed.extend_from_slice(&[Op::Acceptor as u8, 0, 1]);
        put_field(&mut seed, garbage);
        seeds.push(seed);
    }

    // The acceptor path with a refused configuration (an invalid fragment
    // size), and a client refused by `new_with_alpn` (an empty protocol).
    seeds.push(Seed::new([0, 0, 0, 0, 1], &accept).op(Op::Pump, &[]).0);
    let refused = ConnectArgs {
        flags: 2,
        alpn: b"\x00",
        ..ConnectArgs::default()
    };
    seeds.push(Seed::new([0; 5], &refused).0);
    seeds
}
