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

#[test]
fn handshake_and_data_every_pairing() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));
        for feed in [Feed::Whole, Feed::ByteByByte] {
            let data: &[u8] = if feed == Feed::Whole {
                &big_payload()
            } else {
                b"hello over one-byte reads"
            };

            // unbuffered client, buffered server
            let mut c = ub_client(&cc, feed);
            let mut s = b_server(&sc);
            handshake(&mut c, &mut s);
            assert_eq!(c.conn.protocol_version(), Some(v));
            exchange(&mut c, &mut s, data);
            assert!(c.insufficient_seen > 0, "{v:?} {feed:?}");

            // buffered client, unbuffered server
            let mut c = b_client(&cc);
            let mut s = ub_server(&sc, feed);
            handshake(&mut c, &mut s);
            assert_eq!(s.conn.protocol_version(), Some(v));
            assert_eq!(s.conn.server_name(), Some("localhost"));
            exchange(&mut c, &mut s, data);

            // both unbuffered
            let mut c = ub_client(&cc, feed);
            let mut s = ub_server(&sc, feed);
            handshake(&mut c, &mut s);
            exchange(&mut c, &mut s, data);
            assert!(!c.states.contains(&"Err") && !s.states.contains(&"Err"));
        }
    }
}

#[test]
fn every_suite_both_unbuffered() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in prov::default_provider().cipher_suites {
        if format!("{:?}", suite.suite()).contains("_RSA_") {
            continue; // the certificate is ECDSA
        }
        let mut p = prov::default_provider();
        p.cipher_suites = vec![suite];
        let p = Arc::new(p);
        let cc = Arc::new(
            ClientConfig::builder_with_provider(p.clone())
                .with_protocol_versions(&[suite.version()])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
                .with_no_client_auth(),
        );
        let sc = Arc::new(
            ServerConfig::builder_with_provider(p)
                .with_protocol_versions(&[suite.version()])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain.cert_chain(), chain.private_key())
                .unwrap(),
        );
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = ub_server(&sc, Feed::Whole);
        pump(&mut c, &mut s);
        assert!(
            !c.failed() && !s.failed(),
            "{:?}: client {}, server {}",
            suite.suite(),
            c.describe(),
            s.describe()
        );
        assert_eq!(
            c.conn.negotiated_cipher_suite().unwrap().suite(),
            suite.suite()
        );
        exchange(&mut c, &mut s, &big_payload());
    }
}

#[test]
fn small_fragments_split_records() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let mut cfg = versioned_client(&chain, v);
        cfg.max_fragment_size = Some(64);
        let cc = Arc::new(cfg);
        let sc = Arc::new(versioned_server(&chain, v));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = ub_server(&sc, Feed::Whole);
        handshake(&mut c, &mut s);
        c.send(&[7u8; 1000]);
        let wire = c.take_output();
        // 1000 bytes in records of at most 59 bytes of plaintext.
        assert!(wire.len() > 1000 + 16 * 5, "{v:?}: {}", wire.len());
        s.give_input(&wire);
        assert_eq!(s.take_received(), vec![7u8; 1000]);
        assert!(
            s.states.iter().filter(|s| **s == "ReadTraffic").count() >= 17,
            "one ReadTraffic per record"
        );
    }
}

#[test]
fn insufficient_size_reports_exact_requirement() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let mut conn = UnbufferedClientConnection::new(cc, server_name()).unwrap();
    let status = conn.process_tls_records(&mut []);
    assert_eq!(status.discard, 0);
    let Ok(ConnectionState::EncodeTlsData(mut e)) = status.state else {
        panic!("expected the ClientHello");
    };
    let required = match e.encode(&mut [0u8; 10]) {
        Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
            required_size
        }
        other => panic!("{other:?}"),
    };
    let mut buf = vec![0u8; required - 1];
    assert!(e.encode(&mut buf).is_err(), "one byte short still fails");
    let mut buf = vec![0u8; required];
    assert_eq!(e.encode(&mut buf).unwrap(), required);
    assert_eq!(buf[0], 0x16, "a handshake record");
    assert_eq!(e.encode(&mut buf).unwrap(), 0, "nothing more queued");
    let status = conn.process_tls_records(&mut []);
    let Ok(ConnectionState::TransmitTlsData(t)) = status.state else {
        panic!("expected TransmitTlsData");
    };
    t.done();
    let status = conn.process_tls_records(&mut []);
    assert!(matches!(
        status.state,
        Ok(ConnectionState::BlockedHandshake)
    ));
}

#[test]
fn write_traffic_size_check_consumes_nothing() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        let status = c.conn.process_tls_records(&mut c.incoming);
        let Ok(ConnectionState::WriteTraffic(mut w)) = status.state else {
            panic!("expected WriteTraffic");
        };
        let data = b"exactly sized";
        let required = match w.encrypt(data, &mut [0u8; 8]) {
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                required_size
            }
            other => panic!("{other:?}"),
        };
        assert!(matches!(
            w.encrypt(data, &mut vec![0u8; required - 1]),
            Err(EncryptError::InsufficientSize(_))
        ));
        let mut buf = vec![0u8; required];
        assert_eq!(w.encrypt(data, &mut buf).unwrap(), required);
        assert_eq!(w.encrypt(&[], &mut buf).unwrap(), 0);
        // The failed attempts used no sequence numbers: the peer decrypts.
        s.give_input(&buf);
        assert!(!s.failed());
        assert_eq!(s.take_received(), data);
    }
}

#[test]
fn close_notify_both_ways() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));

        // Unbuffered client closes; buffered server sees it.
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        c.to_send = b"last words".to_vec();
        c.close_requested = true;
        pump(&mut c, &mut s);
        assert_eq!(s.take_received(), b"last words");
        let io = s.conn.process_new_packets().unwrap();
        assert!(io.peer_has_closed());
        // Writing after close_notify is refused.
        let status = c.conn.process_tls_records(&mut c.incoming);
        match status.state {
            Ok(ConnectionState::WriteTraffic(mut w)) => {
                assert_eq!(
                    w.encrypt(b"x", &mut [0u8; 100]),
                    Err(EncryptError::AlreadyClosed)
                );
                assert_eq!(w.queue_close_notify(&mut [0u8; 100]), Ok(0));
            }
            other => panic!("{other:?}"),
        }
        // The server answers; the client reports PeerClosed once, then Closed.
        s.conn.send_close_notify();
        pump(&mut c, &mut s);
        assert!(c.peer_closed && c.closed, "{:?}", c.states);
        assert_eq!(c.states.iter().filter(|s| **s == "PeerClosed").count(), 1);
        let status = c.conn.process_tls_records(&mut []);
        assert!(matches!(status.state, Ok(ConnectionState::Closed)));

        // Buffered client closes first; the unbuffered server may still
        // write after PeerClosed, then closes too.
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, Feed::ByteByByte);
        handshake(&mut c, &mut s);
        c.conn.send_close_notify();
        pump(&mut c, &mut s);
        assert!(s.peer_closed && !s.closed);
        s.to_send = b"half-closed reply".to_vec();
        s.close_requested = true;
        pump(&mut c, &mut s);
        assert!(s.closed, "{:?}", s.states);
        assert_eq!(c.take_received(), b"half-closed reply");
        assert!(c.conn.process_new_packets().unwrap().peer_has_closed());
    }
}

#[test]
fn bytes_after_close_notify_are_not_processed() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    let mut c = b_client(&cc);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    c.conn.send_close_notify();
    let mut wire = c.take_output();
    wire.extend_from_slice(&[0x17, 3, 3, 0, 1, 0xff]);
    s.give_input(&wire);
    assert!(s.peer_closed && s.error.is_none());
    assert_eq!(s.incoming, [0x17, 3, 3, 0, 1, 0xff], "left undiscarded");
}

#[test]
fn resumption_unbuffered_both_sides() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        for feed in [Feed::Whole, Feed::ByteByByte] {
            // Fresh session stores for each run.
            let cc = Arc::new(versioned_client(&chain, v));
            let sc = Arc::new(versioned_server(&chain, v));
            let mut c = ub_client(&cc, feed);
            let mut s = ub_server(&sc, feed);
            s.conn.set_resumption_data(b"app state");
            handshake(&mut c, &mut s);
            assert_eq!(c.conn.handshake_kind(), Some(HandshakeKind::Full));
            // TLS 1.3 tickets arrive after the handshake.
            exchange(&mut c, &mut s, b"first");
            if v == ProtocolVersion::TLSv1_3 {
                assert!(c.conn.tls13_tickets_received() > 0);
            }

            let mut c = ub_client(&cc, feed);
            let mut s = ub_server(&sc, feed);
            handshake(&mut c, &mut s);
            assert_eq!(c.conn.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(s.conn.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(s.conn.received_resumption_data(), Some(&b"app state"[..]));
            exchange(&mut c, &mut s, b"second");
        }
    }
}

fn early_data_configs(chain: &Chain, max: u32) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut cc = versioned_client(chain, ProtocolVersion::TLSv1_3);
    cc.enable_early_data = true;
    let mut sc = versioned_server(chain, ProtocolVersion::TLSv1_3);
    sc.max_early_data_size = max;
    (Arc::new(cc), Arc::new(sc))
}

fn prime(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>) {
    let mut c = ub_client(cc, Feed::Whole);
    let mut s = ub_server(sc, Feed::Whole);
    handshake(&mut c, &mut s);
    exchange(&mut c, &mut s, b"prime");
    assert!(c.conn.tls13_tickets_received() > 0);
}

#[test]
fn early_data_unbuffered_both_sides() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (cc, sc) = early_data_configs(&chain, 1024);
    for feed in [Feed::Whole, Feed::ByteByByte] {
        prime(&cc, &sc);
        let mut c = ub_client(&cc, feed);
        c.early_to_send = b"GET /idempotent".to_vec();
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        assert!(c.early_to_send.is_empty(), "early data was offered");
        assert!(c.conn.is_early_data_accepted());
        assert_eq!(s.received_early, b"GET /idempotent");
        assert!(s.states.contains(&"ReadEarlyData"));
        assert!(s.received.is_empty(), "0-RTT is not reported as 1-RTT data");
        exchange(&mut c, &mut s, b"1-RTT");
    }
}

#[test]
fn early_data_against_buffered_peers() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (cc, sc) = early_data_configs(&chain, 1024);

    // Unbuffered client, buffered server.
    prime(&cc, &sc);
    let mut c = ub_client(&cc, Feed::Whole);
    c.early_to_send = b"early to buffered".to_vec();
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);
    assert!(c.conn.is_early_data_accepted());
    let mut got = Vec::new();
    s.conn.early_data().unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"early to buffered");
    exchange(&mut c, &mut s, b"after");

    // Buffered client, unbuffered server.
    prime(&cc, &sc);
    let mut c = b_client(&cc);
    c.conn
        .early_data()
        .unwrap()
        .write_all(b"early to unbuffered")
        .unwrap();
    let mut s = ub_server(&sc, Feed::ByteByByte);
    handshake(&mut c, &mut s);
    assert!(c.conn.is_early_data_accepted());
    assert_eq!(s.received_early, b"early to unbuffered");
    exchange(&mut c, &mut s, b"after");
}

#[test]
fn early_data_limits_and_rejection() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (cc, sc) = early_data_configs(&chain, 16);
    prime(&cc, &sc);

    // The ticket's limit is enforced before anything is written.
    let mut conn = UnbufferedClientConnection::new(cc.clone(), server_name()).unwrap();
    let mut hello = vec![0u8; 4096];
    let n = match conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::EncodeTlsData(mut e)) => e.encode(&mut hello).unwrap(),
        other => panic!("{other:?}"),
    };
    hello.truncate(n);
    match conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::TransmitTlsData(mut t)) => {
            let mut early = t.may_encrypt_early_data().expect("ticket allows 0-RTT");
            assert_eq!(early.bytes_left(), 16);
            assert_eq!(
                early.encrypt(&[0u8; 17], &mut [0u8; 1024]),
                Err(EarlyDataError::ExceededAllowedEarlyData)
            );
            assert_eq!(early.bytes_left(), 16);
            assert!(early.encrypt(&[1u8; 16], &mut [0u8; 1024]).unwrap() > 16);
            assert_eq!(early.bytes_left(), 0);
            t.done();
        }
        other => panic!("{other:?}"),
    }

    // A server that rejects 0-RTT: the client learns it, data goes 1-RTT.
    // (The server skips rejected 0-RTT records up to `max_early_data_size`
    // bytes of ciphertext, so this needs a limit above one record's
    // overhead.)
    let (cc, sc) = early_data_configs(&chain, 1024);
    prime(&cc, &sc);
    let mut c = ub_client(&cc, Feed::Whole);
    c.early_to_send = b"0rtt".to_vec();
    let mut s = ub_server(&sc, Feed::Whole);
    s.conn.reject_early_data();
    handshake(&mut c, &mut s);
    assert!(c.early_to_send.is_empty());
    assert!(!c.conn.is_early_data_accepted());
    assert!(s.received_early.is_empty());
    exchange(&mut c, &mut s, b"retry over 1-RTT");

    // Without a ticket there is no early data state at all.
    let fresh = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let mut conn = UnbufferedClientConnection::new(fresh, server_name()).unwrap();
    let mut buf = vec![0u8; 4096];
    if let Ok(ConnectionState::EncodeTlsData(mut e)) = conn.process_tls_records(&mut []).state {
        e.encode(&mut buf).unwrap();
    }
    match conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::TransmitTlsData(mut t)) => {
            assert!(t.may_encrypt_early_data().is_none());
            assert!(t.may_encrypt_app_data().is_none());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn key_update_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));

    // The unbuffered side asks; the buffered peer answers.
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);
    for round in 0..3 {
        c.refresh_requested = true;
        c.run();
        exchange(&mut c, &mut s, format!("after refresh {round}").as_bytes());
    }

    // The buffered side asks; the unbuffered peer answers before its next
    // application data.
    for feed in [Feed::Whole, Feed::ByteByByte] {
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        for round in 0..3 {
            c.conn.refresh_traffic_keys().unwrap();
            exchange(&mut c, &mut s, format!("round {round}").as_bytes());
        }
    }

    // Both unbuffered, both refreshing.
    let mut c = ub_client(&cc, Feed::ByteByByte);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    c.refresh_requested = true;
    s.refresh_requested = true;
    c.run();
    s.run();
    exchange(&mut c, &mut s, b"both rotated");
}

#[test]
fn refresh_is_refused_in_tls12() {
    init_logging();
    if !VERSIONS.contains(&ProtocolVersion::TLSv1_2) {
        return;
    }
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, VERSIONS[VERSIONS.len() - 1]));
    let sc = Arc::new(versioned_server(&chain, VERSIONS[VERSIONS.len() - 1]));
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    match c.conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::WriteTraffic(w)) => assert!(w.refresh_traffic_keys().is_err()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn tampered_record_sends_alert_then_fails() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, Feed::Whole);
        handshake(&mut c, &mut s);
        c.send(b"tamper with me");
        let mut wire = c.take_output();
        let last = wire.len() - 1;
        wire[last] ^= 1;
        s.give_input(&wire);
        assert_eq!(s.error, Some(Error::DecryptError));
        // The alert was encoded before the error was reported.
        let n = s.states.len();
        assert_eq!(
            &s.states[n - 3..],
            ["EncodeTlsData", "TransmitTlsData", "Err"],
            "{v:?}"
        );
        let alert = s.take_output();
        c.give_input(&alert);
        assert_eq!(
            c.error,
            Some(Error::AlertReceived(
                browntls::AlertDescription::BadRecordMac
            ))
        );
        // The error is sticky.
        let status = s.conn.process_tls_records(&mut []);
        assert_eq!(status.state.err(), Some(Error::DecryptError));
    }
}

#[test]
fn handshake_failure_is_reported_with_alert() {
    init_logging();
    // The server presents a certificate the client does not pin.
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&other, v));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = ub_server(&sc, Feed::Whole);
        pump(&mut c, &mut s);
        assert!(
            matches!(c.error, Some(Error::InvalidCertificate(_))),
            "{:?}",
            c.error
        );
        assert!(
            matches!(s.error, Some(Error::AlertReceived(_))),
            "{:?}",
            s.error
        );
    }
}

#[test]
fn server_waits_for_client_hello() {
    let chain = server_chain(KeyType::EcdsaP256);
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    let mut conn = UnbufferedServerConnection::new(sc).unwrap();
    let status = conn.process_tls_records(&mut []);
    assert_eq!(status.discard, 0);
    assert!(matches!(
        status.state,
        Ok(ConnectionState::BlockedHandshake)
    ));
    // A partial record header is left alone.
    let mut partial = [0x16, 3, 1];
    let status = conn.process_tls_records(&mut partial);
    assert_eq!(status.discard, 0);
    assert!(matches!(
        status.state,
        Ok(ConnectionState::BlockedHandshake)
    ));
    // Garbage fails with an alert first.
    let mut garbage = [0x99u8, 3, 3, 0, 1, 0];
    let status = conn.process_tls_records(&mut garbage);
    assert!(matches!(
        status.state,
        Ok(ConnectionState::EncodeTlsData(_))
    ));
    let mut buf = [0u8; 64];
    if let Ok(ConnectionState::EncodeTlsData(mut e)) = conn.process_tls_records(&mut garbage).state
    {
        assert_eq!(e.encode(&mut buf).unwrap(), 7);
    }
    if let Ok(ConnectionState::TransmitTlsData(t)) = conn.process_tls_records(&mut []).state {
        t.done();
    }
    assert!(conn.process_tls_records(&mut []).state.is_err());
}

#[test]
fn export_keying_material_matches_buffered_peer() {
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        let a = c
            .conn
            .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"ctx"))
            .unwrap();
        let b = s
            .conn
            .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"ctx"))
            .unwrap();
        assert_eq!(a, b);
    }
}

/// TLS_AES_128_GCM_SHA256 with a confidentiality limit of `limit` records.
fn suite_with_limit(limit: u64) -> browntls::SupportedCipherSuite {
    let orig = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let suite: &'static browntls::Tls13CipherSuite =
        Box::leak(Box::new(browntls::Tls13CipherSuite {
            common: browntls::CipherSuiteCommon {
                suite: orig.common.suite,
                hash_provider: orig.common.hash_provider,
                confidentiality_limit: limit,
            },
            hkdf_provider: orig.hkdf_provider,
            aead_alg: orig.aead_alg,
        }));
    browntls::SupportedCipherSuite::Tls13(suite)
}

fn limited_configs(limit: u64) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let chain = server_chain(KeyType::Ed25519);
    let mut p = prov::default_provider();
    p.cipher_suites = vec![suite_with_limit(limit)];
    let p = Arc::new(p);
    let cc = ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let sc = ServerConfig::builder_with_provider(p)
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    (Arc::new(cc), Arc::new(sc))
}

#[test]
fn writes_past_the_confidentiality_limit_carry_their_key_updates() {
    init_logging();
    // RFC 9846 §5.5: the KeyUpdate goes into the caller's buffer with the
    // data, so a peer reading the bytes in order can follow the keys.
    let (cc, sc) = limited_configs(4);
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);
    let mut wire = Vec::new();
    let Ok(ConnectionState::WriteTraffic(mut w)) = c.conn.process_tls_records(&mut []).state else {
        panic!("expected WriteTraffic");
    };
    let mut buf = vec![0u8; 1024];
    for i in 0..20u8 {
        let n = w.encrypt(&[i], &mut buf).unwrap();
        wire.extend_from_slice(&buf[..n]);
    }
    // One write of more records than the limit allows in one key.
    let mut big = vec![0u8; 200_000];
    let n = w.encrypt(&[9u8; 70_000], &mut big).unwrap();
    wire.extend_from_slice(&big[..n]);
    s.give_input(&wire);
    assert!(!s.failed(), "{:?}", s.error);
    let mut expected: Vec<u8> = (0..20u8).collect();
    expected.extend_from_slice(&[9u8; 70_000]);
    assert_eq!(s.take_received(), expected);
    exchange(&mut c, &mut s, b"still in step");

    // Both unbuffered, through the driver's one-write-per-state loop.
    let mut c = ub_client(&cc, Feed::ByteByByte);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    for i in 0..12u8 {
        exchange(&mut c, &mut s, &[i; 3]);
    }
}

#[test]
fn half_rtt_data_at_the_limit_is_refused_not_misordered() {
    init_logging();
    // A server cannot send a KeyUpdate before the client's Finished: once
    // its half-RTT key is spent, writes fail and nothing is consumed.
    let (cc, sc) = limited_configs(4);
    let mut sc = (*sc).clone();
    sc.send_half_rtt_data = true;
    let sc = Arc::new(sc);
    let mut c = b_client(&cc);
    let mut s = ub_server(&sc, Feed::Whole);
    let hello = c.take_output();
    s.give_input(&hello);
    assert!(s.writable && s.conn.is_handshaking());
    let Ok(ConnectionState::WriteTraffic(mut w)) = s.conn.process_tls_records(&mut []).state else {
        panic!("expected WriteTraffic");
    };
    let mut wire = Vec::new();
    let mut taken = Vec::new();
    for i in 0..8u8 {
        // The size asked for is exactly one record: no KeyUpdate can be
        // sent before the handshake completes, so none is counted.
        let required = match w.encrypt(&[i], &mut []) {
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                required_size
            }
            // The key is spent; this is temporary, not fatal.
            Err(EncryptError::KeyUpdateAwaitsHandshake) => continue,
            other => panic!("{other:?}"),
        };
        let mut buf = vec![0u8; required];
        assert_eq!(w.encrypt(&[i], &mut buf), Ok(required));
        wire.extend_from_slice(&buf);
        taken.push(i);
    }
    assert!(!taken.is_empty() && taken.len() < 8, "{taken:?}");
    s.outgoing.extend_from_slice(&wire);
    handshake(&mut c, &mut s);
    assert_eq!(c.take_received(), taken);
    exchange(&mut c, &mut s, b"after the refresh");
}

/// A TLS 1.3 AEAD that understates the record length of a KeyUpdate (a
/// 5-byte plaintext) by one byte, standing in for a provider whose
/// `encrypted_payload_len` is wrong.
struct UnderstatesKeyUpdates(&'static dyn browntls::crypto::cipher::Tls13AeadAlgorithm);

struct UnderstatingEncrypter(Box<dyn browntls::crypto::cipher::MessageEncrypter>);

impl browntls::crypto::cipher::MessageEncrypter for UnderstatingEncrypter {
    fn encrypt(
        &mut self,
        msg: browntls::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<browntls::crypto::cipher::OutboundOpaqueMessage, Error> {
        self.0.encrypt(msg, seq)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        let real = self.0.encrypted_payload_len(payload_len);
        if payload_len == 5 { real - 1 } else { real }
    }
}

impl browntls::crypto::cipher::Tls13AeadAlgorithm for UnderstatesKeyUpdates {
    fn encrypter(
        &self,
        key: browntls::crypto::cipher::AeadKey,
        iv: browntls::crypto::cipher::Iv,
    ) -> Box<dyn browntls::crypto::cipher::MessageEncrypter> {
        Box::new(UnderstatingEncrypter(self.0.encrypter(key, iv)))
    }

    fn decrypter(
        &self,
        key: browntls::crypto::cipher::AeadKey,
        iv: browntls::crypto::cipher::Iv,
    ) -> Box<dyn browntls::crypto::cipher::MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: browntls::crypto::cipher::AeadKey,
        iv: browntls::crypto::cipher::Iv,
    ) -> Result<
        browntls::ConnectionTrafficSecrets,
        browntls::crypto::cipher::UnsupportedOperationError,
    > {
        self.0.extract_keys(key, iv)
    }
}

#[test]
fn trailing_key_update_that_does_not_fit_stays_queued() {
    init_logging();
    // The data records are sequenced and written; the KeyUpdate that
    // follows them must not be lost when it turns out longer than promised.
    let orig = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let suite: &'static browntls::Tls13CipherSuite =
        Box::leak(Box::new(browntls::Tls13CipherSuite {
            common: browntls::CipherSuiteCommon {
                suite: orig.common.suite,
                hash_provider: orig.common.hash_provider,
                confidentiality_limit: 4,
            },
            hkdf_provider: orig.hkdf_provider,
            aead_alg: Box::leak(Box::new(UnderstatesKeyUpdates(orig.aead_alg))),
        }));
    let chain = server_chain(KeyType::Ed25519);
    let mut p = prov::default_provider();
    p.cipher_suites = vec![browntls::SupportedCipherSuite::Tls13(suite)];
    let cc = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth(),
    );
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);

    let mut wire = Vec::new();
    let mut queued_after = None;
    let mut i = 0u8;
    while i < 6 {
        let Ok(ConnectionState::WriteTraffic(mut w)) = c.conn.process_tls_records(&mut []).state
        else {
            // The KeyUpdate left behind is offered first.
            let mut buf = vec![0u8; 256];
            match c.conn.process_tls_records(&mut []).state {
                Ok(ConnectionState::EncodeTlsData(mut e)) => {
                    let n = e.encode(&mut buf).unwrap();
                    wire.extend_from_slice(&buf[..n]);
                }
                other => panic!("{other:?}"),
            }
            match c.conn.process_tls_records(&mut []).state {
                Ok(ConnectionState::TransmitTlsData(t)) => t.done(),
                other => panic!("{other:?}"),
            }
            continue;
        };
        let required = match w.encrypt(&[i], &mut []) {
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                required_size
            }
            other => panic!("{other:?}"),
        };
        let mut buf = vec![0u8; required];
        let n = w.encrypt(&[i], &mut buf).unwrap();
        if n < required {
            queued_after.get_or_insert(i);
        }
        wire.extend_from_slice(&buf[..n]);
        i += 1;
    }
    assert!(queued_after.is_some(), "the KeyUpdate did not fit once");
    s.give_input(&wire);
    assert!(!s.failed(), "{:?}", s.error);
    assert_eq!(s.take_received(), (0..6u8).collect::<Vec<_>>());
    exchange(&mut c, &mut s, b"still in step");
}

#[test]
fn reject_early_data_after_accepting_it_does_nothing() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (cc, sc) = early_data_configs(&chain, 1024);
    prime(&cc, &sc);
    let mut c = b_client(&cc);
    c.conn.early_data().unwrap().write_all(b"one ").unwrap();
    let mut s = ub_server(&sc, Feed::Whole);
    let flight = c.take_output();
    s.give_input(&flight);
    assert_eq!(s.received_early, b"one ");
    // Too late: the server already accepted the client's 0-RTT data.
    s.conn.reject_early_data();
    c.conn.early_data().unwrap().write_all(b"two").unwrap();
    handshake(&mut c, &mut s);
    assert!(c.conn.is_early_data_accepted());
    assert_eq!(s.received_early, b"one two");
}

// ------------------------------------------------------------ rustls interop

mod interop {
    use super::*;
    use rustls_pki_types as rpki;

    /// A rustls 0.23 connection on the buffered API.
    struct Rustls<C> {
        conn: C,
        received: Vec<u8>,
        failed: bool,
    }

    impl<C, D> Endpoint for Rustls<C>
    where
        C: std::ops::DerefMut<Target = rustls::ConnectionCommon<D>>,
        D: rustls::SideData,
    {
        fn take_output(&mut self) -> Vec<u8> {
            let mut out = Vec::new();
            while self.conn.wants_write() {
                self.conn.write_tls(&mut out).unwrap();
            }
            out
        }

        fn give_input(&mut self, mut bytes: &[u8]) {
            while !bytes.is_empty() && !self.failed {
                self.conn.read_tls(&mut bytes).unwrap();
                if self.conn.process_new_packets().is_err() {
                    self.failed = true;
                }
                match self.conn.reader().read_to_end(&mut self.received) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("read: {e}"),
                }
            }
        }

        fn failed(&self) -> bool {
            self.failed
        }

        fn describe(&self) -> String {
            format!("rustls failed: {}", self.failed)
        }

        fn handshaking(&self) -> bool {
            self.conn.is_handshaking()
        }

        fn send(&mut self, data: &[u8]) {
            self.conn.writer().write_all(data).unwrap();
        }

        fn take_received(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.received)
        }
    }

    static R_TLS12: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
    static R_TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

    fn r_versions(v: ProtocolVersion) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match v {
            ProtocolVersion::TLSv1_2 => &R_TLS12,
            _ => &R_TLS13,
        }
    }

    fn r_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[test]
    fn unbuffered_client_to_rustls_server() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        for v in VERSIONS {
            let certs = chain
                .cert_chain()
                .iter()
                .map(|c| rpki::CertificateDer::from(c.as_ref().to_vec()))
                .collect();
            let key = rpki::PrivateKeyDer::Pkcs8(rpki::PrivatePkcs8KeyDer::from(
                chain.end_entity_key.clone(),
            ));
            let rc = Arc::new(
                rustls::ServerConfig::builder_with_provider(r_provider())
                    .with_protocol_versions(r_versions(v))
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap(),
            );
            let cc = Arc::new(versioned_client(&chain, v));
            for feed in [Feed::Whole, Feed::ByteByByte] {
                let mut c = ub_client(&cc, feed);
                let mut s = Rustls {
                    conn: rustls::ServerConnection::new(rc.clone()).unwrap(),
                    received: Vec::new(),
                    failed: false,
                };
                handshake(&mut c, &mut s);
                exchange(&mut c, &mut s, &big_payload());
                if v == ProtocolVersion::TLSv1_3 {
                    c.refresh_requested = true;
                    c.run();
                    exchange(&mut c, &mut s, b"after key update");
                }
                c.close_requested = true;
                pump(&mut c, &mut s);
                s.conn.send_close_notify();
                pump(&mut c, &mut s);
                assert!(c.closed, "{:?}", c.states);
            }
        }
    }

    #[test]
    fn rustls_client_to_unbuffered_server() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rpki::CertificateDer::from(chain.ca.as_ref().to_vec()))
            .unwrap();
        let roots = Arc::new(roots);
        for v in VERSIONS {
            let rc = Arc::new(
                rustls::ClientConfig::builder_with_provider(r_provider())
                    .with_protocol_versions(r_versions(v))
                    .unwrap()
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth(),
            );
            let sc = Arc::new(versioned_server(&chain, v));
            for feed in [Feed::Whole, Feed::ByteByByte] {
                let mut c = Rustls {
                    conn: rustls::ClientConnection::new(
                        rc.clone(),
                        rpki::ServerName::try_from("localhost").unwrap(),
                    )
                    .unwrap(),
                    received: Vec::new(),
                    failed: false,
                };
                let mut s = ub_server(&sc, feed);
                handshake(&mut c, &mut s);
                exchange(&mut c, &mut s, &big_payload());
                if v == ProtocolVersion::TLSv1_3 {
                    c.conn.refresh_traffic_keys().unwrap();
                    exchange(&mut c, &mut s, b"after key update");
                }
            }
        }
    }
}
