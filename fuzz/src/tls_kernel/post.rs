//! After the handover: the offloaded side ([`Offloaded`]) and its userspace
//! peer, driven by fuzzed operations.

use std::io::{Read, Write};

use browntls_core::client::ClientConnectionData;
use browntls_core::server::ServerConnectionData;
use browntls_core::{Connection, ContentType, ProtocolVersion, SideData, SupportedCipherSuite};

use super::sim::{Offloaded, is_key_update};
use super::{Flow, MAX_OPS};
use crate::input::Input;
use crate::tls_conn::setup::assert_prefix;

/// The operations after the handover; the selector byte is reduced modulo
/// their number.
#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum Op {
    /// `repeat, data (short field)`: the peer writes `data` `repeat + 1`
    /// times.
    PeerWrite,
    /// The peer's `refresh_traffic_keys`.
    PeerRefresh,
    /// The peer's `send_close_notify`.
    PeerClose,
    /// The peer, a server, asks for a client certificate.
    PeerAuth,
    /// `amount (u16, 0: all)`: the peer's records into the kernel.
    PeerToKernel,
    /// `amount (u16, 0: all)`: the kernel's records to the peer.
    KernelToPeer,
    /// `repeat, data (short field)`: the kernel sends `data` `repeat + 1`
    /// times.
    Send,
    /// `refresh_traffic_keys`.
    Refresh,
    /// `mode, count`: `records_sent` (mode 0: a byte, 1: the
    /// confidentiality limit less a u16, 2: the limit plus a u16, 3: a u64,
    /// otherwise `u64::MAX`).
    RecordsSent,
    /// `application_data_received`.
    AppReceived,
    /// `send_close_notify`.
    Close,
    /// `type, mode, payload (short field)`: `handle_record` with a fuzzed
    /// record that the peer did not send (mode 1: a KeyUpdate, 2: a
    /// KeyUpdate followed by the payload, 3: an alert).
    Handle,
    /// `flag`: the side-specific calls.
    Extras,
    /// Every accessor and `Debug`.
    Accessors,
    /// Exchange everything until both sides are idle.
    Pump,
    /// Pump, then check that all data arrived.
    Check,
}

const OPS: usize = Op::Check as usize + 1;

const ALL_OPS: [Op; OPS] = [
    Op::PeerWrite,
    Op::PeerRefresh,
    Op::PeerClose,
    Op::PeerAuth,
    Op::PeerToKernel,
    Op::KernelToPeer,
    Op::Send,
    Op::Refresh,
    Op::RecordsSent,
    Op::AppReceived,
    Op::Close,
    Op::Handle,
    Op::Extras,
    Op::Accessors,
    Op::Pump,
    Op::Check,
];

/// The calls only one side has.
pub(super) trait KernelSide: SideData + Sized {
    fn extras(off: &mut Offloaded<Self>, flag: u8);
}

impl KernelSide for ClientConnectionData {
    fn extras(off: &mut Offloaded<Self>, _flag: u8) {
        let tickets = off.conn.tls13_tickets_received();
        if !off.tls13() {
            assert_eq!(tickets, 0, "TLS 1.2 tickets counted as TLS 1.3 ones");
        }
    }
}

impl KernelSide for ServerConnectionData {
    fn extras(off: &mut Offloaded<Self>, flag: u8) {
        let _ = off.conn.post_handshake_auth_status();
        if flag & 1 != 0 {
            let before_failed = off.failed;
            if let Err(err) = off.conn.request_client_auth() {
                let _ = err.to_string();
            }
            off.drain(Some(0), false, before_failed);
        }
    }
}

/// The offloaded side, its peer and the data in flight.
struct Post<D> {
    off: Offloaded<D>,
    peer: Connection,
    /// The peer's records not yet given to the kernel.
    peer_wire: Vec<u8>,
    /// Peer to offloaded side (received data is in `off.app_in`).
    down_sent: Vec<u8>,
    /// Offloaded side to peer.
    up: Flow,
    peer_failed: bool,
    peer_closed: bool,
}

/// Runs the operations after a handover.
pub(super) fn run<D: KernelSide>(
    off: Offloaded<D>,
    peer: Connection,
    peer_wire: Vec<u8>,
    down_sent: Vec<u8>,
    up: Flow,
    input: &mut Input<'_>,
    ops: &mut usize,
) {
    let mut post = Post {
        off,
        peer,
        peer_wire,
        down_sent,
        up,
        peer_failed: false,
        peer_closed: false,
    };
    while !input.is_empty() && *ops < MAX_OPS {
        *ops += 1;
        let op = ALL_OPS[input.choose(OPS)];
        post.op(op, input);
        post.check_prefixes();
    }
    post.pump();
    post.check_prefixes();
}

/// `data` repeated `repeat + 1` times, at most 40000 bytes.
fn repeated(input: &mut Input<'_>) -> Vec<u8> {
    let repeat = usize::from(input.byte()) + 1;
    let data = input.short_field();
    let mut out = Vec::new();
    for _ in 0..repeat {
        if out.len() + data.len() > 40_000 {
            break;
        }
        out.extend_from_slice(data);
    }
    out
}

fn confidentiality_limit(suite: SupportedCipherSuite) -> u64 {
    match suite {
        SupportedCipherSuite::Tls13(s) => s.common.confidentiality_limit,
        SupportedCipherSuite::Tls12(s) => s.common.confidentiality_limit,
    }
}

impl<D: KernelSide> Post<D> {
    fn op(&mut self, op: Op, input: &mut Input<'_>) {
        match op {
            Op::PeerWrite => {
                let data = repeated(input);
                if let Ok(n) = self.peer.writer().write(&data) {
                    self.down_sent.extend_from_slice(&data[..n]);
                }
            }
            Op::PeerRefresh => {
                let _ = self.peer.refresh_traffic_keys();
            }
            Op::PeerClose => {
                self.peer.send_close_notify();
                self.peer_closed = true;
            }
            Op::PeerAuth => {
                if let Connection::Server(server) = &mut self.peer {
                    let _ = server.request_client_auth();
                    let _ = server.post_handshake_auth_status();
                }
            }
            Op::PeerToKernel => {
                let amount = input.u16();
                self.peer_to_kernel(usize::from(amount));
            }
            Op::KernelToPeer => {
                let amount = input.u16();
                self.kernel_to_peer(usize::from(amount));
            }
            Op::Send => {
                let data = repeated(input);
                if self.off.send(&data) {
                    self.up.sent.extend_from_slice(&data);
                }
            }
            Op::Refresh => {
                let before_failed = self.off.failed;
                let tls13 = self.off.tls13();
                let result = self.off.conn.refresh_traffic_keys();
                if !tls13 {
                    assert!(result.is_err(), "TLS 1.2 refreshed its keys");
                }
                self.off.drain(Some(0), false, before_failed);
            }
            Op::RecordsSent => {
                let limit = confidentiality_limit(self.off.conn.negotiated_cipher_suite());
                let records = match input.byte() {
                    0 => u64::from(input.byte()),
                    1 => limit.saturating_sub(u64::from(input.u16())),
                    2 => limit.saturating_add(u64::from(input.u16())),
                    3 => input.u64(),
                    _ => u64::MAX,
                };
                let before_failed = self.off.failed;
                if let Err(err) = self.off.conn.records_sent(records) {
                    let _ = err.to_string();
                }
                self.off.drain(Some(0), false, before_failed);
            }
            Op::AppReceived => {
                self.off.conn.application_data_received();
                assert!(!self.off.conn.has_output());
            }
            Op::Close => {
                let before_failed = self.off.failed;
                self.off.conn.send_close_notify();
                assert!(!self.off.conn.may_send_application_data());
                self.off.drain(Some(0), false, before_failed);
            }
            Op::Handle => self.handle(input),
            Op::Extras => {
                let flag = input.byte();
                D::extras(&mut self.off, flag);
            }
            Op::Accessors => self.accessors(),
            Op::Pump => self.pump(),
            Op::Check => self.check(),
        }
    }

    fn handle(&mut self, input: &mut Input<'_>) {
        const TYPES: [ContentType; 5] = [
            ContentType::Handshake,
            ContentType::Alert,
            ContentType::ApplicationData,
            ContentType::ChangeCipherSpec,
            ContentType::Heartbeat,
        ];
        let selector = input.byte();
        let typ = match TYPES.get(usize::from(selector)) {
            Some(typ) => *typ,
            None => ContentType::from(selector),
        };
        let mode = input.byte();
        let field = input.short_field();
        let payload = match mode % 4 {
            1 => vec![24, 0, 0, 1, field.first().map_or(0, |b| b & 1)],
            2 => [&[24, 0, 0, 1, 0][..], field].concat(),
            3 => vec![
                field.first().copied().unwrap_or(1),
                field.get(1).copied().unwrap_or(0),
            ],
            _ => field.to_vec(),
        };
        if typ != ContentType::ApplicationData {
            self.off.desynced = true;
        }
        let _ = self.off.handle(typ, &payload);
        if typ == ContentType::Handshake && is_key_update(&payload) {
            let _ = self.off.conn.may_send_application_data();
        }
    }

    fn accessors(&mut self) {
        let conn = &self.off.conn;
        let version = conn.protocol_version();
        let suite = conn.negotiated_cipher_suite();
        assert_eq!(conn.common_state().protocol_version(), Some(version));
        assert_eq!(
            conn.common_state()
                .negotiated_cipher_suite()
                .map(|s| s.suite()),
            Some(suite.suite())
        );
        assert!(!conn.common_state().is_handshaking());
        let max = conn.max_tx_payload_len();
        assert_eq!(max, conn.common_state().max_tx_payload_len());
        if let Some(max) = max {
            let floor = if version == ProtocolVersion::TLSv1_3 {
                63
            } else {
                64
            };
            assert!((floor..super::sim::MAX_PAYLOAD as u16).contains(&max));
        }
        assert!(!conn.has_output(), "outputs left undrained");
        let _ = (conn.may_send_application_data(), conn.peer_has_closed());
        let _ = format!("{suite:?} {:?}", conn.common_state());
        self.off.check_debug(&format!("{conn:?} {conn:#?}"));
        D::extras(&mut self.off, 0);
    }

    /// The peer's queued records, written out.
    fn peer_flush(&mut self) {
        while self.peer.wants_write() {
            if self.peer.write_tls(&mut self.peer_wire).is_err() {
                break;
            }
        }
    }

    fn peer_to_kernel(&mut self, amount: usize) {
        self.peer_flush();
        let n = match amount {
            0 => self.peer_wire.len(),
            n => n.min(self.peer_wire.len()),
        };
        let bytes: Vec<u8> = self.peer_wire.drain(..n).collect();
        self.off.receive(&bytes);
    }

    fn kernel_to_peer(&mut self, amount: usize) {
        let n = match amount {
            0 => self.off.wire_out.len(),
            n => n.min(self.off.wire_out.len()),
        };
        let bytes: Vec<u8> = self.off.wire_out.drain(..n).collect();
        if !self.peer_failed {
            self.peer_failed = !peer_receive(&mut self.peer, &bytes, &mut self.up.recv);
        }
    }

    /// Exchanges everything until nothing moves.
    fn pump(&mut self) {
        for _ in 0..32 {
            self.peer_flush();
            let moved = !self.peer_wire.is_empty() || !self.off.wire_out.is_empty();
            self.peer_to_kernel(0);
            self.kernel_to_peer(0);
            if !moved {
                break;
            }
        }
    }

    fn check(&mut self) {
        self.pump();
        let off = &self.off;
        if off.desynced || off.failed || off.closed || self.peer_failed || self.peer_closed {
            return;
        }
        if !off.conn.may_send_application_data() || off.conn.peer_has_closed() {
            return;
        }
        assert_eq!(off.app_in, self.down_sent, "peer to kernel: data lost");
        assert_eq!(self.up.recv, self.up.sent, "kernel to peer: data lost");
    }

    fn check_prefixes(&self) {
        assert_prefix(&self.off.app_in, &self.down_sent, "peer to kernel");
        assert_prefix(&self.up.recv, &self.up.sent, "kernel to peer");
    }
}

/// Gives `bytes` to `peer` and reads what it decrypts into `recv`. Returns
/// `false` once the peer failed.
pub(super) fn peer_receive(peer: &mut Connection, mut bytes: &[u8], recv: &mut Vec<u8>) -> bool {
    while !bytes.is_empty() {
        match peer.read_tls(&mut bytes) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => {
                let _ = peer.reader().read_to_end(recv);
                if peer.read_tls(&mut bytes).is_err() {
                    return false;
                }
            }
        }
        if peer.process_new_packets().is_err() {
            let _ = peer.reader().read_to_end(recv);
            return false;
        }
        let _ = peer.reader().read_to_end(recv);
    }
    true
}
