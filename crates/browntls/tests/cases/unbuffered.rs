// Shared cases, included by `tests/unbuffered.rs` (RustCrypto provider) and
// `tests/unbuffered_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.

use std::io::{Read, Write};
use std::sync::Arc;

use browntls::client::{ClientConnectionData, UnbufferedClientConnection};
use browntls::server::{ServerConnectionData, UnbufferedServerConnection};
use browntls::unbuffered::{
    ConnectionState, EarlyDataError, EncodeError, EncryptError, InsufficientSizeError,
    TransmitTlsData, UnbufferedConnectionCommon,
};
use browntls::{
    ClientConfig, ClientConnection, Error, HandshakeKind, ProtocolVersion, ServerConfig,
    ServerConnection, SideData, version,
};
use common::*;

// ---------------------------------------------------------------- plumbing

/// How received TLS bytes reach an unbuffered connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Feed {
    /// Everything the peer sent at once.
    Whole,
    /// One byte per `process_tls_records` round.
    ByteByByte,
}

/// Sends 0-RTT data from a [`TransmitTlsData`] state; only clients can.
trait EarlyWriter: SideData + Sized {
    fn write_early(
        _transmit: &mut TransmitTlsData<'_, Self>,
        _data: &mut Vec<u8>,
        _out: &mut Vec<u8>,
    ) {
    }
}

impl EarlyWriter for ServerConnectionData {}

impl EarlyWriter for ClientConnectionData {
    fn write_early(
        transmit: &mut TransmitTlsData<'_, Self>,
        data: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) {
        if data.is_empty() {
            return;
        }
        let Some(mut early) = transmit.may_encrypt_early_data() else {
            return;
        };
        assert!(early.bytes_left() >= data.len());
        let mut buf = vec![0u8; 1];
        let n = loop {
            match early.encrypt(data, &mut buf) {
                Ok(n) => break n,
                Err(EarlyDataError::Encrypt(EncryptError::InsufficientSize(
                    InsufficientSizeError { required_size },
                ))) => buf.resize(required_size, 0),
                Err(e) => panic!("early data: {e:?}"),
            }
        };
        out.extend_from_slice(&buf[..n]);
        data.clear();
    }
}

/// An unbuffered connection plus the caller-side buffers the tests keep.
struct Unbuffered<C> {
    conn: C,
    feed: Feed,
    /// Received TLS bytes not yet discarded.
    incoming: Vec<u8>,
    /// Peer bytes not yet handed to `incoming` (byte-by-byte feeding).
    pending: Vec<u8>,
    /// Encoded TLS bytes to send.
    outgoing: Vec<u8>,
    /// Size of the scratch buffer offered to `encode`/`encrypt`; starts
    /// tiny so every write goes through the `InsufficientSize` path.
    out_size: usize,
    insufficient_seen: usize,
    received: Vec<u8>,
    received_early: Vec<u8>,
    /// Application data to send at the next `WriteTraffic`.
    to_send: Vec<u8>,
    /// 0-RTT data to send after the ClientHello.
    early_to_send: Vec<u8>,
    close_requested: bool,
    refresh_requested: bool,
    peer_closed: bool,
    closed: bool,
    blocked: bool,
    writable: bool,
    error: Option<Error>,
    states: Vec<&'static str>,
}

impl<C> Unbuffered<C> {
    fn new(conn: C, feed: Feed) -> Self {
        Self {
            conn,
            feed,
            incoming: Vec::new(),
            pending: Vec::new(),
            outgoing: Vec::new(),
            out_size: 1,
            insufficient_seen: 0,
            received: Vec::new(),
            received_early: Vec::new(),
            to_send: Vec::new(),
            early_to_send: Vec::new(),
            close_requested: false,
            refresh_requested: false,
            peer_closed: false,
            closed: false,
            blocked: false,
            writable: false,
            error: None,
            states: Vec::new(),
        }
    }
}

impl<C, D> Unbuffered<C>
where
    C: std::ops::DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: EarlyWriter,
{
    /// Runs `process_tls_records` until the connection needs input.
    fn run(&mut self) {
        if self.error.is_some() {
            return;
        }
        for _ in 0..10_000 {
            let status = self.conn.process_tls_records(&mut self.incoming);
            let discard = status.discard;
            let mut stop = false;
            match status.state {
                Ok(ConnectionState::ReadTraffic(r)) => {
                    self.states.push("ReadTraffic");
                    self.received.extend_from_slice(r.payload());
                }
                Ok(ConnectionState::ReadEarlyData(r)) => {
                    self.states.push("ReadEarlyData");
                    self.received_early.extend_from_slice(r.payload());
                }
                Ok(ConnectionState::EncodeTlsData(mut e)) => {
                    self.states.push("EncodeTlsData");
                    let mut buf = vec![0u8; self.out_size];
                    match e.encode(&mut buf) {
                        Ok(n) => {
                            assert!(n > 0, "EncodeTlsData with nothing queued");
                            self.outgoing.extend_from_slice(&buf[..n]);
                        }
                        Err(EncodeError::InsufficientSize(InsufficientSizeError {
                            required_size,
                        })) => {
                            assert!(required_size > self.out_size);
                            self.insufficient_seen += 1;
                            self.out_size = required_size;
                        }
                        Err(e) => panic!("{e:?}"),
                    }
                }
                Ok(ConnectionState::TransmitTlsData(mut t)) => {
                    self.states.push("TransmitTlsData");
                    D::write_early(&mut t, &mut self.early_to_send, &mut self.outgoing);
                    t.done();
                }
                Ok(ConnectionState::BlockedHandshake) => {
                    self.states.push("BlockedHandshake");
                    self.blocked = true;
                    stop = true;
                }
                Ok(ConnectionState::WriteTraffic(mut w)) => {
                    self.states.push("WriteTraffic");
                    self.blocked = false;
                    self.writable = true;
                    if !self.to_send.is_empty() {
                        let data = std::mem::take(&mut self.to_send);
                        let mut buf = vec![0u8; self.out_size];
                        let n = loop {
                            match w.encrypt(&data, &mut buf) {
                                Ok(n) => break n,
                                Err(EncryptError::InsufficientSize(InsufficientSizeError {
                                    required_size,
                                })) => {
                                    assert!(required_size > buf.len());
                                    self.insufficient_seen += 1;
                                    buf.resize(required_size, 0);
                                }
                                Err(e) => panic!("encrypt: {e:?}"),
                            }
                        };
                        self.outgoing.extend_from_slice(&buf[..n]);
                    } else if self.refresh_requested {
                        self.refresh_requested = false;
                        w.refresh_traffic_keys().unwrap();
                    } else if self.close_requested {
                        self.close_requested = false;
                        let mut buf = vec![0u8; 1];
                        let n = match w.queue_close_notify(&mut buf) {
                            Ok(n) => n,
                            Err(EncryptError::InsufficientSize(InsufficientSizeError {
                                required_size,
                            })) => {
                                buf.resize(required_size, 0);
                                w.queue_close_notify(&mut buf).unwrap()
                            }
                            Err(e) => panic!("close: {e:?}"),
                        };
                        self.outgoing.extend_from_slice(&buf[..n]);
                    } else {
                        stop = true;
                    }
                }
                Ok(ConnectionState::PeerClosed) => {
                    self.states.push("PeerClosed");
                    self.peer_closed = true;
                }
                Ok(ConnectionState::Closed) => {
                    self.states.push("Closed");
                    self.closed = true;
                    stop = true;
                }
                Ok(other) => panic!("unexpected state {other:?}"),
                Err(e) => {
                    self.states.push("Err");
                    self.error = Some(e);
                    stop = true;
                }
            }
            self.incoming.drain(..discard);
            if stop {
                return;
            }
        }
        panic!("unbuffered connection did not settle");
    }
}

/// One side of an in-memory connection, buffered or not.
trait Endpoint {
    /// TLS bytes to send to the peer.
    fn take_output(&mut self) -> Vec<u8>;
    /// Delivers TLS bytes from the peer.
    fn give_input(&mut self, bytes: &[u8]);
    fn failed(&self) -> bool;
    fn describe(&self) -> String;
    fn handshaking(&self) -> bool;
    fn send(&mut self, data: &[u8]);
    fn take_received(&mut self) -> Vec<u8>;
}

impl<C, D> Endpoint for Unbuffered<C>
where
    C: std::ops::DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: EarlyWriter,
{
    fn take_output(&mut self) -> Vec<u8> {
        self.run();
        std::mem::take(&mut self.outgoing)
    }

    fn give_input(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        match self.feed {
            Feed::Whole => {
                self.incoming.append(&mut self.pending);
                self.run();
            }
            Feed::ByteByByte => {
                while !self.pending.is_empty() {
                    let b = self.pending.remove(0);
                    self.incoming.push(b);
                    self.run();
                }
                self.run();
            }
        }
    }

    fn failed(&self) -> bool {
        self.error.is_some()
    }

    fn describe(&self) -> String {
        format!("{:?} after {:?}", self.error, self.states)
    }

    fn handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn send(&mut self, data: &[u8]) {
        self.to_send.extend_from_slice(data);
        self.run();
    }

    fn take_received(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.received)
    }
}

/// A buffered browntls connection.
struct Buffered<C> {
    conn: C,
    received: Vec<u8>,
    error: Option<Error>,
}

impl<C> Buffered<C> {
    fn new(conn: C) -> Self {
        Self {
            conn,
            received: Vec::new(),
            error: None,
        }
    }
}

impl<C, D> Endpoint for Buffered<C>
where
    C: std::ops::DerefMut<Target = browntls::ConnectionCommon<D>>,
    D: SideData,
{
    fn take_output(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut out).unwrap();
        }
        out
    }

    fn give_input(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && self.error.is_none() {
            match self.conn.read_tls(&mut bytes) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Other => {}
                Err(e) => panic!("read_tls: {e}"),
            }
            if let Err(e) = self.conn.process_new_packets() {
                self.error = Some(e);
            }
            match self.conn.reader().read_to_end(&mut self.received) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("read: {e}"),
            }
        }
    }

    fn failed(&self) -> bool {
        self.error.is_some()
    }

    fn describe(&self) -> String {
        format!("{:?}", self.error)
    }

    fn handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn send(&mut self, data: &[u8]) {
        let mut written = 0;
        while written < data.len() {
            written += self.conn.writer().write(&data[written..]).unwrap();
        }
    }

    fn take_received(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.received)
    }
}

/// Moves bytes both ways until neither side has anything to send.
fn pump(client: &mut dyn Endpoint, server: &mut dyn Endpoint) {
    for _ in 0..64 {
        let to_server = client.take_output();
        if !to_server.is_empty() {
            server.give_input(&to_server);
        }
        let to_client = server.take_output();
        if !to_client.is_empty() {
            client.give_input(&to_client);
        }
        if to_server.is_empty() && to_client.is_empty() {
            return;
        }
        if client.failed() || server.failed() {
            // Deliver the alerts, then stop.
            let a = client.take_output();
            server.give_input(&a);
            let b = server.take_output();
            client.give_input(&b);
            return;
        }
    }
    panic!("pump did not settle");
}

fn handshake(client: &mut dyn Endpoint, server: &mut dyn Endpoint) {
    pump(client, server);
    assert!(
        !client.failed() && !server.failed(),
        "handshake failed: client {}, server {}",
        client.describe(),
        server.describe()
    );
    assert!(!client.handshaking() && !server.handshaking());
}

/// Sends `data` each way and checks it arrives intact.
fn exchange(client: &mut dyn Endpoint, server: &mut dyn Endpoint, data: &[u8]) {
    client.send(data);
    pump(client, server);
    assert_eq!(server.take_received(), data, "client to server");
    let reply: Vec<u8> = data.iter().rev().copied().collect();
    server.send(&reply);
    pump(client, server);
    assert_eq!(client.take_received(), reply, "server to client");
}

// ---------------------------------------------------------- configurations

fn versioned_client(chain: &Chain, v: ProtocolVersion) -> ClientConfig {
    let versions: &[&'static browntls::SupportedProtocolVersion] = match v {
        #[cfg(feature = "tls12")]
        ProtocolVersion::TLSv1_2 => &[&version::TLS12],
        _ => &[&version::TLS13],
    };
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn versioned_server(chain: &Chain, v: ProtocolVersion) -> ServerConfig {
    let versions: &[&'static browntls::SupportedProtocolVersion] = match v {
        #[cfg(feature = "tls12")]
        ProtocolVersion::TLSv1_2 => &[&version::TLS12],
        _ => &[&version::TLS13],
    };
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.session_storage = browntls::server::ServerSessionMemoryCache::new(16);
    config
}

#[cfg(feature = "tls12")]
const VERSIONS: [ProtocolVersion; 2] = [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
#[cfg(not(feature = "tls12"))]
const VERSIONS: [ProtocolVersion; 1] = [ProtocolVersion::TLSv1_3];

type UbClient = Unbuffered<UnbufferedClientConnection>;
type UbServer = Unbuffered<UnbufferedServerConnection>;

fn ub_client(config: &Arc<ClientConfig>, feed: Feed) -> UbClient {
    Unbuffered::new(
        UnbufferedClientConnection::new(config.clone(), server_name()).unwrap(),
        feed,
    )
}

fn ub_server(config: &Arc<ServerConfig>, feed: Feed) -> UbServer {
    Unbuffered::new(
        UnbufferedServerConnection::new(config.clone()).unwrap(),
        feed,
    )
}

fn b_client(config: &Arc<ClientConfig>) -> Buffered<ClientConnection> {
    Buffered::new(ClientConnection::new(config.clone(), server_name()).unwrap())
}

fn b_server(config: &Arc<ServerConfig>) -> Buffered<ServerConnection> {
    Buffered::new(ServerConnection::new(config.clone()).unwrap())
}

/// Larger than one record, so data spans several.
fn big_payload() -> Vec<u8> {
    (0..40_000u32).map(|i| (i % 251) as u8).collect()
}

// ------------------------------------------------------------------ cases

include!("unbuffered/handshake_and_data.rs");
include!("unbuffered/early_data.rs");
include!("unbuffered/key_update.rs");
include!("unbuffered/rustls_interop.rs");
include!("unbuffered/status_and_auth.rs");
include!("unbuffered/exporters.rs");
include!("unbuffered/acceptor.rs");
include!("unbuffered/kernel.rs");
include!("unbuffered/encrypt_failure.rs");
