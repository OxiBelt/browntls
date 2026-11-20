//! The unbuffered connection API: `UnbufferedClientConnection`,
//! `UnbufferedServerConnection`, `UnbufferedConnectionCommon` and every
//! state `process_tls_records` hands out, driven between a genuine client
//! and server in the same process (real cryptography, both providers).
//!
//! Input: the 5-byte configuration header of `tls_conn`
//! (`tls_conn::setup::Knobs`), the arguments of the first connection
//! (see [`Op::Reconnect`]), then up to 64 operations: one
//! `process_tls_records` step or a run of them on either side with fuzzed
//! output buffer sizes (the `InsufficientSize` paths), application data,
//! 0-RTT data and actions (`encrypt`, `queue_close_notify`,
//! `refresh_traffic_keys`, `done` or not, which payload accessor);
//! delivery of a fuzzed amount of the transmitted bytes, optionally
//! damaged, replayed or with bytes inserted; raw bytes; exporters,
//! accessors, resumption data, early data refusal, post-handshake client
//! authentication requests, reconnection (resumption and 0-RTT), secret
//! extraction, and the `UnbufferedAcceptor` (see `acceptor`).
//!
//! Checked properties:
//! * application and 0-RTT data a side reads is a prefix of what the peer
//!   encrypted, whatever happened to the bytes in between; once both sides
//!   are idle with nothing damaged or failed, it is all of it;
//! * a buffer reported too small really is, and the size it asks for is
//!   enough; 0-RTT data beyond `bytes_left` is refused;
//! * both sides export the same keying material, extract matching traffic
//!   secrets, and agree on the negotiated parameters;
//! * a post-handshake client authentication the server reports as
//!   authenticated was answered by the client, with its certificate;
//! * nothing panics.

mod acceptor;
mod seeds;

use std::sync::Arc;

use browntls_core::client::{ClientConnectionData, UnbufferedClientConnection};
use browntls_core::ech::EchStatus;
use browntls_core::server::{
    PostHandshakeAuthStatus, ServerConnectionData, UnbufferedServerConnection,
};
use browntls_core::unbuffered::{
    ConnectionState, EarlyDataError, EncodeError, EncryptError, InsufficientSizeError,
    TransmitTlsData, UnbufferedConnectionCommon,
};
use browntls_core::{ClientConfig, CommonState, ServerConfig, SideData};

use crate::input::{Input, put_short_field};
use crate::tls_conn::setup::{
    Knobs, Pki, assert_prefix, assert_same_secrets, check_cached_info, server_name,
};
use seeds::Seed;
pub use seeds::seeds;

const MAX_OPS: usize = 64;
const MAX_CONNECTIONS: usize = 4;
const CLIENT: usize = 0;
const SERVER: usize = 1;
/// The output buffer used when the input does not choose one.
const BIG: usize = 20_000;

#[derive(Clone, Copy)]
#[repr(u8)]
enum Op {
    /// `side, step arguments`: one `process_tls_records`.
    Step,
    /// `side, step arguments`: steps until the side waits for input.
    Drive,
    /// `from, amount (u16, 0: all), damage, position (u16)[, bytes]`:
    /// moves transmitted bytes into the peer's input buffer.
    Deliver,
    /// Drive both sides and deliver everything until idle.
    Pump,
    /// `label, flags, context, length (u16)`: exporters (regular and
    /// early) and the channel binding on both sides.
    Export,
    /// Every accessor; agreement once both are connected.
    Accessors,
    /// Connection arguments: a new pair from the same configurations.
    Reconnect,
    /// `dangerous_extract_secrets` on both sides.
    Extract,
    /// `side, bytes (field)`: raw bytes appended to `side`'s input.
    Inject,
    /// Pump, then check that all data arrived.
    Check,
    /// `data`: `set_resumption_data` on the server.
    ResumptionData,
    /// `reject_early_data` on the server.
    RejectEarlyData,
    /// `request_client_auth` on the server (RFC 9846 §4.7.2).
    PostHandshakeAuth,
    /// `chunk, flags`: the server's input through an `UnbufferedAcceptor`.
    Accept,
}

const OPS: usize = Op::Accept as usize + 1;

const ALL_OPS: [Op; OPS] = [
    Op::Step,
    Op::Drive,
    Op::Deliver,
    Op::Pump,
    Op::Export,
    Op::Accessors,
    Op::Reconnect,
    Op::Extract,
    Op::Inject,
    Op::Check,
    Op::ResumptionData,
    Op::RejectEarlyData,
    Op::PostHandshakeAuth,
    Op::Accept,
];

/// What one step does with the state it gets.
#[derive(Clone, Copy, Default)]
struct StepArgs<'a> {
    /// Bit 0: retry an `InsufficientSize` with the size asked for.
    /// Bit 1: do not call `TransmitTlsData::done`.
    /// Bit 2: `may_encrypt_app_data` on `TransmitTlsData`.
    /// Bit 3: `may_encrypt_early_data` on `TransmitTlsData`.
    /// Bits 4-6: on `WriteTraffic`, nothing, `encrypt`,
    /// `queue_close_notify`, `refresh_traffic_keys`, encrypt then close,
    /// encrypt then refresh.
    /// Bit 7: format the state with `Debug`; read payloads through
    /// `payload_mut` / `into_payload` instead of `payload`.
    flags: u8,
    /// Output buffer size (0: big enough for anything).
    cap: u16,
    data: &'a [u8],
}

const RETRY: u8 = 1;

impl<'a> StepArgs<'a> {
    fn read(input: &mut Input<'a>) -> Self {
        Self {
            flags: input.byte(),
            cap: input.u16(),
            data: input.short_field(),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.flags);
        out.extend_from_slice(&self.cap.to_be_bytes());
        put_short_field(out, self.data);
    }

    fn cap(&self) -> usize {
        match self.cap {
            0 => BIG,
            n => usize::from(n),
        }
    }

    fn retry(&self) -> bool {
        self.flags & RETRY != 0
    }
}

/// The state a step saw.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Seen {
    Nothing,
    Busy,
    Rest,
}

/// One side's buffers, borrowed from the [`World`] for a step.
struct SideIo<'a> {
    inbuf: &'a mut Vec<u8>,
    /// Bytes transmitted toward the peer.
    wire: &'a mut Vec<u8>,
    /// Application data encrypted.
    sent: &'a mut Vec<u8>,
    /// Application data received from the peer.
    recv: &'a mut Vec<u8>,
    /// Client: 0-RTT data encrypted. Server: 0-RTT data received.
    early: &'a mut Vec<u8>,
    failed: &'a mut bool,
    closed: &'a mut bool,
}

/// Encrypts with `f` into a buffer of `cap` bytes, retrying once with the
/// size asked for when allowed. Returns the bytes produced, or `None`.
fn encrypt_into<E>(
    mut f: impl FnMut(&mut [u8]) -> Result<usize, E>,
    mut insufficient: impl FnMut(&E) -> Option<usize>,
    cap: usize,
    retry: bool,
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; cap];
    match f(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            Some(buf)
        }
        Err(err) => {
            let required = insufficient(&err)?;
            assert!(required > cap, "{required} bytes required, {cap} given");
            if !retry {
                return None;
            }
            let mut buf = vec![0u8; required];
            let n = f(&mut buf).ok()?;
            assert!(n <= required);
            buf.truncate(n);
            Some(buf)
        }
    }
}

fn encrypt_insufficient(err: &EncryptError) -> Option<usize> {
    let _ = err.to_string();
    match err {
        EncryptError::InsufficientSize(InsufficientSizeError { required_size }) => {
            Some(*required_size)
        }
        _ => None,
    }
}

/// The side-specific part of `TransmitTlsData`: 0-RTT data for clients.
trait EarlyData: SideData + Sized {
    fn early(
        _transmit: &mut TransmitTlsData<'_, Self>,
        _args: &StepArgs<'_>,
        _io: &mut SideIo<'_>,
    ) {
    }
}

impl EarlyData for ServerConnectionData {}

impl EarlyData for ClientConnectionData {
    fn early(transmit: &mut TransmitTlsData<'_, Self>, args: &StepArgs<'_>, io: &mut SideIo<'_>) {
        let Some(mut early) = transmit.may_encrypt_early_data() else {
            return;
        };
        if args.flags & 0x80 != 0 {
            let _ = format!("{early:?}");
        }
        let left = early.bytes_left();
        let data = args.data;
        let mut refused = false;
        let out = encrypt_into(
            |buf| early.encrypt(data, buf),
            |err: &EarlyDataError| {
                let _ = err.to_string();
                match err {
                    EarlyDataError::ExceededAllowedEarlyData => {
                        refused = true;
                        None
                    }
                    EarlyDataError::Encrypt(e) => encrypt_insufficient(e),
                    _ => None,
                }
            },
            args.cap(),
            args.retry(),
        );
        if data.len() > left {
            assert!(out.is_none() && refused, "0-RTT data beyond bytes_left");
        }
        if let Some(out) = out {
            io.wire.extend_from_slice(&out);
            io.early.extend_from_slice(data);
            assert_eq!(early.bytes_left(), left - data.len());
        }
    }
}

/// Encrypts `args.data` as application data through `encrypt`.
fn send_app_data<D: SideData>(
    write: &mut browntls_core::unbuffered::WriteTraffic<'_, D>,
    args: &StepArgs<'_>,
    io: &mut SideIo<'_>,
) {
    let data = args.data;
    if let Some(out) = encrypt_into(
        |buf| write.encrypt(data, buf),
        encrypt_insufficient,
        args.cap(),
        args.retry(),
    ) {
        io.wire.extend_from_slice(&out);
        io.sent.extend_from_slice(data);
    }
}

/// One `process_tls_records` on `conn`, acting on the state per `args`.
fn step<D: EarlyData>(
    conn: &mut UnbufferedConnectionCommon<D>,
    args: &StepArgs<'_>,
    io: &mut SideIo<'_>,
) -> Seen {
    let status = conn.process_tls_records(&mut io.inbuf[..]);
    let discard = status.discard;
    let variant = args.flags & 0x80 != 0;
    if variant {
        let _ = format!("{status:?}");
    }
    let seen = match status.state {
        Err(err) => {
            let _ = err.to_string();
            *io.failed = true;
            Seen::Rest
        }
        Ok(ConnectionState::ReadTraffic(mut record)) => {
            let _ = format!("{record:?}");
            if variant {
                let n = record.payload_mut().len();
                assert_eq!(n, record.payload().len());
                io.recv.extend_from_slice(record.into_payload());
            } else {
                io.recv.extend_from_slice(record.payload());
            }
            Seen::Busy
        }
        Ok(ConnectionState::ReadEarlyData(mut record)) => {
            let _ = format!("{record:?}");
            if variant {
                let n = record.payload_mut().len();
                assert_eq!(n, record.payload().len());
                io.early.extend_from_slice(record.into_payload());
            } else {
                io.early.extend_from_slice(record.payload());
            }
            Seen::Busy
        }
        Ok(ConnectionState::EncodeTlsData(mut encode)) => {
            let _ = format!("{encode:?}");
            let mut buf = vec![0u8; args.cap()];
            for _ in 0..16 {
                match encode.encode(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        assert!(n <= buf.len());
                        io.wire.extend_from_slice(&buf[..n]);
                    }
                    Err(err) => {
                        let _ = err.to_string();
                        let EncodeError::InsufficientSize(InsufficientSizeError { required_size }) =
                            err
                        else {
                            break;
                        };
                        assert!(required_size > buf.len());
                        if !args.retry() {
                            break;
                        }
                        buf = vec![0u8; required_size];
                        let n = encode.encode(&mut buf);
                        assert_eq!(n, Ok(required_size), "the size asked for is not enough");
                        io.wire.extend_from_slice(&buf);
                    }
                }
            }
            Seen::Busy
        }
        Ok(ConnectionState::TransmitTlsData(mut transmit)) => {
            let _ = format!("{transmit:?}");
            if args.flags & 4 != 0
                && let Some(mut write) = transmit.may_encrypt_app_data()
            {
                send_app_data(&mut write, args, io);
            }
            if args.flags & 8 != 0 {
                D::early(&mut transmit, args, io);
            }
            if args.flags & 2 == 0 {
                transmit.done();
            }
            Seen::Busy
        }
        Ok(ConnectionState::WriteTraffic(mut write)) => {
            let _ = format!("{write:?}");
            let action = (args.flags >> 4) & 7;
            if matches!(action, 1 | 4 | 5) {
                send_app_data(&mut write, args, io);
            }
            match action {
                2 | 4 => {
                    if let Some(out) = encrypt_into(
                        |buf| write.queue_close_notify(buf),
                        encrypt_insufficient,
                        args.cap(),
                        args.retry(),
                    ) {
                        io.wire.extend_from_slice(&out);
                        *io.closed = true;
                    }
                }
                3 | 5 => {
                    let _ = write.refresh_traffic_keys();
                }
                _ => {}
            }
            Seen::Rest
        }
        Ok(ConnectionState::PeerClosed) => Seen::Busy,
        Ok(state) => {
            let _ = format!("{state:?}");
            Seen::Rest
        }
    };
    io.inbuf.drain(..discard);
    seen
}

struct World {
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    client: Option<UnbufferedClientConnection>,
    server: Option<UnbufferedServerConnection>,
    /// `inbuf[s]`: bytes delivered to side `s`, not yet discarded.
    inbuf: [Vec<u8>; 2],
    /// `wire[s]`: bytes side `s` transmitted that were not delivered.
    wire: [Vec<u8>; 2],
    /// `sent[s]`: application data side `s` encrypted.
    sent: [Vec<u8>; 2],
    /// `recv[s]`: application data the peer received from side `s`.
    recv: [Vec<u8>; 2],
    early_sent: Vec<u8>,
    early_recv: Vec<u8>,
    corrupted: bool,
    failed: [bool; 2],
    closed: [bool; 2],
    connections: usize,
    resumption_data: Vec<Vec<u8>>,
}

impl World {
    fn new(knobs: Knobs) -> Option<Self> {
        Some(Self {
            client_config: Arc::new(knobs.client_config()?),
            server_config: Arc::new(knobs.server_config()?),
            client: None,
            server: None,
            inbuf: [Vec::new(), Vec::new()],
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

    /// Connection arguments: bit 0 `new_with_alpn` (a one-byte-prefixed
    /// list follows), bit 1 resumption data (a short field follows), bit 2
    /// the server rejects early data.
    fn connect(&mut self, input: &mut Input<'_>) {
        let flags = input.byte();
        let alpn = if flags & 1 != 0 {
            input.short_field()
        } else {
            &[]
        };
        let data = if flags & 2 != 0 {
            input.short_field()
        } else {
            &[]
        };
        if self.connections >= MAX_CONNECTIONS {
            return;
        }
        self.connections += 1;
        self.inbuf = [Vec::new(), Vec::new()];
        self.wire = [Vec::new(), Vec::new()];
        self.sent = [Vec::new(), Vec::new()];
        self.recv = [Vec::new(), Vec::new()];
        self.early_sent.clear();
        self.early_recv.clear();
        self.corrupted = false;
        self.failed = [false; 2];
        self.closed = [false; 2];

        self.client = if flags & 1 != 0 {
            let mut list = Vec::new();
            let mut rest = alpn;
            while let Some((&len, tail)) = rest.split_first() {
                let (name, tail) = tail.split_at(usize::from(len).min(tail.len()));
                list.push(name.to_vec());
                rest = tail;
            }
            UnbufferedClientConnection::new_with_alpn(
                self.client_config.clone(),
                server_name(),
                list,
            )
        } else {
            UnbufferedClientConnection::new(self.client_config.clone(), server_name())
        }
        .ok();
        self.server = UnbufferedServerConnection::new(self.server_config.clone()).ok();
        if let Some(server) = &mut self.server {
            if flags & 2 != 0 {
                server.set_resumption_data(data);
                self.resumption_data.push(data.to_vec());
            }
            if flags & 4 != 0 {
                server.reject_early_data();
            }
        }
    }

    fn step(&mut self, side: usize, args: &StepArgs<'_>) -> Seen {
        let peer = 1 - side;
        let [sent0, sent1] = &mut self.sent;
        let [recv0, recv1] = &mut self.recv;
        let (sent, recv) = if side == CLIENT {
            (sent0, recv1)
        } else {
            (sent1, recv0)
        };
        let mut io = SideIo {
            inbuf: &mut self.inbuf[side],
            wire: &mut self.wire[side],
            sent,
            recv,
            early: if side == CLIENT {
                &mut self.early_sent
            } else {
                &mut self.early_recv
            },
            failed: &mut self.failed[side],
            closed: &mut self.closed[side],
        };
        let seen = match side {
            CLIENT => match &mut self.client {
                Some(conn) => step(conn, args, &mut io),
                None => Seen::Nothing,
            },
            _ => match &mut self.server {
                Some(conn) => step(conn, args, &mut io),
                None => Seen::Nothing,
            },
        };
        assert_prefix(&self.recv[peer], &self.sent[peer], "application data");
        assert_prefix(&self.early_recv, &self.early_sent, "early data");
        seen
    }

    /// Steps `side` until it waits for input, at most 64 times. Returns
    /// whether it made progress: transmitted anything or consumed input.
    fn drive(&mut self, side: usize, args: &StepArgs<'_>) -> bool {
        let before = (self.wire[side].len(), self.inbuf[side].len());
        for _ in 0..64 {
            if self.step(side, args) != Seen::Busy {
                break;
            }
        }
        (self.wire[side].len(), self.inbuf[side].len()) != before
    }

    /// Moves up to `amount` transmitted bytes of `from` to its peer.
    fn deliver(&mut self, from: usize, amount: usize) -> bool {
        let n = amount.min(self.wire[from].len());
        let bytes: Vec<u8> = self.wire[from].drain(..n).collect();
        self.inbuf[1 - from].extend_from_slice(&bytes);
        n > 0
    }

    /// Drives both sides and delivers everything until nothing moves.
    ///
    /// A side counts as moving while it consumes input, not only while it
    /// transmits: a peer that queued many records (up to 64 per `Drive`
    /// that never calls `TransmitTlsData::done`) needs more than one
    /// 64-step `drive` to read them, and stopping earlier would report
    /// data the receiver simply had not processed yet as lost. The bound
    /// covers the most records an input can queue (64 operations of 64
    /// steps, each encrypting at most 255 bytes) with room to spare, so
    /// running out of rounds means the connections never settle (a
    /// livelock), which is reported as such rather than as lost data.
    fn pump(&mut self) {
        let args = StepArgs {
            flags: RETRY,
            ..StepArgs::default()
        };
        for _ in 0..1024 {
            let mut moved = false;
            for side in [CLIENT, SERVER] {
                moved |= self.drive(side, &args);
                moved |= self.deliver(side, usize::MAX);
            }
            if !moved {
                return;
            }
        }
        panic!("connections did not settle after 1024 pump rounds");
    }

    fn commons(&self) -> [Option<&CommonState>; 2] {
        [
            self.client.as_deref().map(|c| &**c),
            self.server.as_deref().map(|s| &**s),
        ]
    }

    fn healthy(&self) -> bool {
        !self.corrupted
            && !self.failed.contains(&true)
            && self
                .commons()
                .iter()
                .all(|c| c.is_some_and(|c| !c.is_handshaking()))
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
        if self
            .client
            .as_ref()
            .is_some_and(|c| c.is_early_data_accepted())
        {
            assert_eq!(self.early_recv, self.early_sent, "accepted early data lost");
        }
    }

    fn export(&self, label: &[u8], context: Option<&[u8]>, len: usize) {
        let c = self.client.as_ref().and_then(|c| {
            c.export_keying_material(vec![0u8; len], label, context)
                .ok()
        });
        let s = self.server.as_ref().and_then(|s| {
            s.export_keying_material(vec![0u8; len], label, context)
                .ok()
        });
        if let (Some(c), Some(s)) = (c, s) {
            assert_eq!(c, s, "exporters disagree");
        }
        // The early exporter: equal once the server has accepted 0-RTT
        // (the client loses it if the server rejects it).
        let c = self.client.as_ref().and_then(|c| {
            c.export_early_keying_material(vec![0u8; len], label, context)
                .ok()
        });
        let s = self.server.as_ref().and_then(|s| {
            s.export_early_keying_material(vec![0u8; len], label, context)
                .ok()
        });
        if let (Some(c), Some(s)) = (c, s)
            && !self.corrupted
        {
            assert_eq!(c, s, "early exporters disagree");
        }
        // RFC 9266 channel binding: the exporter with a fixed label.
        let bindings = [
            self.client
                .as_ref()
                .and_then(|c| c.tls_exporter_channel_binding().ok()),
            self.server
                .as_ref()
                .and_then(|s| s.tls_exporter_channel_binding().ok()),
        ];
        if let [Some(c), Some(s)] = bindings {
            assert_eq!(c, s, "channel bindings disagree");
        }
        if let (Some(binding), Some(client)) = (bindings[0], &self.client) {
            let exported = client
                .export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", Some(&[]))
                .expect("the exporter that gave the binding");
            assert_eq!(binding, exported);
        }
    }

    fn accessors(&self) {
        for common in self.commons().into_iter().flatten() {
            let _ = (
                common.wants_write(),
                common.wants_read(),
                common.is_handshaking(),
                common.peer_certificates().map(<[_]>::len),
                common.alpn_protocol(),
                common.negotiated_cipher_suite(),
                common.negotiated_key_exchange_group().map(|g| g.name()),
                common.protocol_version(),
                common.handshake_kind(),
                common.external_psk_identity(),
                common.fips(),
            );
        }
        if let Some(client) = &self.client {
            let _ = (
                client.tls13_tickets_received(),
                client.is_early_data_accepted(),
                client.post_handshake_auth_responses(),
                client.fips(),
                format!("{client:?}"),
            );
            // The configurations never enable either.
            assert!(client.delegated_credential().is_none());
            assert_eq!(client.ech_status(), EchStatus::NotOffered);
        }
        if let Some(server) = &self.server {
            let _ = (
                server.server_name().map(str::len),
                server.fips(),
                server.post_handshake_auth_offered(),
                format!("{server:?}"),
            );
            assert_eq!(server.ech_status(), EchStatus::NotOffered);
            if let Some(data) = server.received_resumption_data() {
                assert!(
                    self.resumption_data.iter().any(|d| d == data),
                    "resumption data that was never stored"
                );
            }
        }
        if !self.healthy() {
            return;
        }
        let [Some(c), Some(s)] = self.commons() else {
            return;
        };
        let pki = Pki::get();
        assert_eq!(c.protocol_version(), s.protocol_version());
        assert_eq!(
            c.negotiated_cipher_suite().map(|s| s.suite()),
            s.negotiated_cipher_suite().map(|s| s.suite())
        );
        assert_eq!(c.alpn_protocol(), s.alpn_protocol());
        assert_eq!(c.handshake_kind(), s.handshake_kind());
        check_cached_info(
            &self.client_config,
            c.cached_info_replaced(),
            s.cached_info_replaced(),
        );
        assert_eq!(c.peer_certificates(), Some(&pki.server_chain[..]));
        if let Some(certs) = s.peer_certificates() {
            assert_eq!(certs, &pki.client_chain[..]);
        }
        let server = self.server.as_ref().expect("server");
        assert_eq!(server.server_name(), Some("localhost"));
        if server.post_handshake_auth_status() == Some(PostHandshakeAuthStatus::Authenticated) {
            let client = self.client.as_ref().expect("client");
            assert!(client.post_handshake_auth_responses() > 0);
            assert_eq!(s.peer_certificates(), Some(&pki.client_chain[..]));
        }
    }

    /// `request_client_auth`: refused unless the TLS 1.3 handshake is
    /// complete and the client offered `post_handshake_auth`; never two at
    /// a time.
    fn post_handshake_auth(&mut self) {
        let Some(server) = &mut self.server else {
            return;
        };
        let offered = server.post_handshake_auth_offered();
        let before = server.post_handshake_auth_status();
        match server.request_client_auth() {
            Ok(()) => {
                assert!(offered && !server.is_handshaking());
                assert_ne!(before, Some(PostHandshakeAuthStatus::Requested));
                assert_eq!(
                    server.post_handshake_auth_status(),
                    Some(PostHandshakeAuthStatus::Requested)
                );
                assert!(server.request_client_auth().is_err());
            }
            Err(_) => assert_eq!(server.post_handshake_auth_status(), before),
        }
    }

    fn extract(&mut self) {
        self.pump();
        let healthy = self.healthy() && !self.closed.contains(&true);
        let c = self
            .client
            .take()
            .and_then(|c| c.dangerous_extract_secrets().ok());
        let s = self
            .server
            .take()
            .and_then(|s| s.dangerous_extract_secrets().ok());
        if let (Some(c), Some(s)) = (c, s)
            && healthy
        {
            assert_same_secrets(&c.tx, &s.rx);
            assert_same_secrets(&s.tx, &c.rx);
        }
    }
}

/// The `tls_unbuffered` fuzz target.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let Some(mut world) = World::new(Knobs::read(&mut input)) else {
        return;
    };
    world.connect(&mut input);

    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match ALL_OPS[input.choose(OPS)] {
            Op::Step => {
                let side = usize::from(input.bool());
                let args = StepArgs::read(&mut input);
                world.step(side, &args);
            }
            Op::Drive => {
                let side = usize::from(input.bool());
                let args = StepArgs::read(&mut input);
                world.drive(side, &args);
            }
            Op::Deliver => {
                let from = usize::from(input.bool());
                let amount = match input.u16() {
                    0 => usize::MAX,
                    n => usize::from(n),
                };
                let how = input.byte();
                let pos = usize::from(input.u16());
                let n = amount.min(world.wire[from].len());
                let mut bytes: Vec<u8> = world.wire[from].drain(..n).collect();
                world.corrupted |= crate::tls_conn::damage(&mut bytes, how, pos, &mut input);
                world.inbuf[1 - from].extend_from_slice(&bytes);
            }
            Op::Pump => world.pump(),
            Op::Export => {
                let label = input.short_field();
                let flags = input.byte();
                let context = input.short_field();
                let len = usize::from(input.u16()) % 1200;
                world.export(label, (flags & 1 != 0).then_some(context), len);
            }
            Op::Accessors => world.accessors(),
            Op::Reconnect => world.connect(&mut input),
            Op::Extract => world.extract(),
            Op::Inject => {
                let side = usize::from(input.bool());
                world.inbuf[side].extend_from_slice(input.field());
                world.corrupted = true;
            }
            Op::Check => world.check(),
            Op::ResumptionData => {
                let data = input.short_field();
                if let Some(server) = &mut world.server {
                    server.set_resumption_data(data);
                    world.resumption_data.push(data.to_vec());
                }
            }
            Op::RejectEarlyData => {
                if let Some(server) = &mut world.server {
                    server.reject_early_data();
                }
            }
            Op::PostHandshakeAuth => world.post_handshake_auth(),
            Op::Accept => world.accept(&mut input),
        }
    }
    world.accessors();
    world.check();
}
