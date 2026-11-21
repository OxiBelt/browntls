// Shared cases, included by `tests/quic.rs` (RustCrypto provider) and
// `tests/quic_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.
//
// QUIC-TLS (RFC 9001): the Appendix A packet protection vectors, in-memory
// handshakes driven through `read_hs`/`write_hs` with every key change
// checked by protecting a packet on one side and opening it on the other,
// the RFC 9001 TLS rules, and interoperability with rustls's QUIC API.

use std::sync::Arc;

use browntls_core::quic as bq;
use browntls_core::{AlertDescription, Error, PeerMisbehaved, version};
use common::*;
use rustls::quic as rq;

// --------------------------------------------------------- handshake plumbing

/// Seals and opens packet payloads, for either library.
trait Prot {
    fn seal(&self, pn: u64, header: &[u8], payload: &[u8]) -> Vec<u8>;
    fn open(&self, pn: u64, header: &[u8], body: &[u8]) -> Option<Vec<u8>>;
}

/// Header protection of a short-header packet with a 4-byte packet number:
/// returns the protected first byte and packet number.
trait Hp {
    fn protect(&self, sample: &[u8]) -> (u8, [u8; 4]);
}

impl Prot for Box<dyn bq::PacketKey> {
    fn seal(&self, pn: u64, header: &[u8], payload: &[u8]) -> Vec<u8> {
        seal(&**self, pn, header, payload)
    }
    fn open(&self, pn: u64, header: &[u8], body: &[u8]) -> Option<Vec<u8>> {
        let mut body = body.to_vec();
        self.decrypt_in_place(pn, header, &mut body)
            .ok()
            .map(<[u8]>::to_vec)
    }
}

impl Prot for Box<dyn rq::PacketKey> {
    fn seal(&self, pn: u64, header: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut body = payload.to_vec();
        let tag = self.encrypt_in_place(pn, header, &mut body).unwrap();
        body.extend_from_slice(tag.as_ref());
        body
    }
    fn open(&self, pn: u64, header: &[u8], body: &[u8]) -> Option<Vec<u8>> {
        let mut body = body.to_vec();
        self.decrypt_in_place(pn, header, &mut body)
            .ok()
            .map(<[u8]>::to_vec)
    }
}

impl Hp for Box<dyn bq::HeaderProtectionKey> {
    fn protect(&self, sample: &[u8]) -> (u8, [u8; 4]) {
        let (mut first, mut pn) = (0x43, [1, 2, 3, 4]);
        self.encrypt_in_place(sample, &mut first, &mut pn).unwrap();
        (first, pn)
    }
}

impl Hp for Box<dyn rq::HeaderProtectionKey> {
    fn protect(&self, sample: &[u8]) -> (u8, [u8; 4]) {
        let (mut first, mut pn) = (0x43, [1, 2, 3, 4]);
        self.encrypt_in_place(sample, &mut first, &mut pn).unwrap();
        (first, pn)
    }
}

struct Dir {
    packet: Box<dyn Prot>,
    header: Box<dyn Hp>,
}

struct LevelKeys {
    local: Dir,
    remote: Dir,
}

impl From<bq::DirectionalKeys> for Dir {
    fn from(k: bq::DirectionalKeys) -> Self {
        Self {
            packet: Box::new(k.packet),
            header: Box::new(k.header),
        }
    }
}

impl From<rq::DirectionalKeys> for Dir {
    fn from(k: rq::DirectionalKeys) -> Self {
        Self {
            packet: Box::new(k.packet),
            header: Box::new(k.header),
        }
    }
}

impl From<bq::Keys> for LevelKeys {
    fn from(k: bq::Keys) -> Self {
        Self {
            local: k.local.into(),
            remote: k.remote.into(),
        }
    }
}

impl From<rq::Keys> for LevelKeys {
    fn from(k: rq::Keys) -> Self {
        Self {
            local: k.local.into(),
            remote: k.remote.into(),
        }
    }
}

/// The packet keys of the next key phase.
trait NextKeys {
    fn next(&mut self) -> (Box<dyn Prot>, Box<dyn Prot>);
}

impl NextKeys for bq::Secrets {
    fn next(&mut self) -> (Box<dyn Prot>, Box<dyn Prot>) {
        let k = self.next_packet_keys();
        (Box::new(k.local), Box::new(k.remote))
    }
}

impl NextKeys for rq::Secrets {
    fn next(&mut self) -> (Box<dyn Prot>, Box<dyn Prot>) {
        let k = self.next_packet_keys();
        (Box::new(k.local), Box::new(k.remote))
    }
}

enum Change {
    Handshake(LevelKeys),
    OneRtt(LevelKeys, Box<dyn NextKeys>),
}

/// The QUIC-TLS connection API, for either library.
trait Endpoint {
    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<Change>;
    fn read_hs(&mut self, data: &[u8]) -> Result<(), String>;
    fn handshaking(&self) -> bool;
    fn params(&self) -> Option<Vec<u8>>;
    fn alpn(&self) -> Option<Vec<u8>>;
    fn alert(&self) -> Option<u8>;
    fn zero_rtt(&self) -> Option<Dir>;
    fn early_accepted(&self) -> bool;
    fn resumed(&self) -> bool;
    fn exporter(&self) -> [u8; 32];
    fn tls_records_pending(&self) -> bool;
    fn peer_certified(&self) -> bool;
    fn cert_with_extern_psk(&self) -> bool {
        false
    }
}

impl Endpoint for bq::Connection {
    fn cert_with_extern_psk(&self) -> bool {
        self.negotiated_cert_with_extern_psk()
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<Change> {
        Some(match bq::Connection::write_hs(self, buf)? {
            bq::KeyChange::Handshake { keys } => Change::Handshake(keys.into()),
            bq::KeyChange::OneRtt { keys, next } => Change::OneRtt(keys.into(), Box::new(next)),
        })
    }
    fn read_hs(&mut self, data: &[u8]) -> Result<(), String> {
        bq::Connection::read_hs(self, data).map_err(|e| format!("{e:?}"))
    }
    fn handshaking(&self) -> bool {
        self.is_handshaking()
    }
    fn params(&self) -> Option<Vec<u8>> {
        self.quic_transport_parameters().map(<[u8]>::to_vec)
    }
    fn alpn(&self) -> Option<Vec<u8>> {
        self.alpn_protocol().map(<[u8]>::to_vec)
    }
    fn alert(&self) -> Option<u8> {
        bq::Connection::alert(self).map(u8::from)
    }
    fn zero_rtt(&self) -> Option<Dir> {
        self.zero_rtt_keys().map(Dir::from)
    }
    fn early_accepted(&self) -> bool {
        match self {
            Self::Client(c) => c.is_early_data_accepted(),
            Self::Server(s) => s.is_early_data_accepted(),
        }
    }
    fn resumed(&self) -> bool {
        self.handshake_kind() == Some(browntls_core::HandshakeKind::Resumed)
    }
    fn exporter(&self) -> [u8; 32] {
        self.export_keying_material([0; 32], b"EXPORTER-test", Some(b"ctx"))
            .unwrap()
    }
    fn tls_records_pending(&self) -> bool {
        self.wants_write()
    }
    fn peer_certified(&self) -> bool {
        self.peer_certificates().is_some()
    }
}

impl Endpoint for rq::Connection {
    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<Change> {
        Some(match rq::Connection::write_hs(self, buf)? {
            rq::KeyChange::Handshake { keys } => Change::Handshake(keys.into()),
            rq::KeyChange::OneRtt { keys, next } => Change::OneRtt(keys.into(), Box::new(next)),
        })
    }
    fn read_hs(&mut self, data: &[u8]) -> Result<(), String> {
        rq::Connection::read_hs(self, data).map_err(|e| format!("{e:?}"))
    }
    fn handshaking(&self) -> bool {
        self.is_handshaking()
    }
    fn params(&self) -> Option<Vec<u8>> {
        self.quic_transport_parameters().map(<[u8]>::to_vec)
    }
    fn alpn(&self) -> Option<Vec<u8>> {
        self.alpn_protocol().map(<[u8]>::to_vec)
    }
    fn alert(&self) -> Option<u8> {
        rq::Connection::alert(self).map(u8::from)
    }
    fn zero_rtt(&self) -> Option<Dir> {
        self.zero_rtt_keys().map(Dir::from)
    }
    fn early_accepted(&self) -> bool {
        match self {
            Self::Client(c) => c.is_early_data_accepted(),
            // rustls's QUIC server does not say; 0-RTT keys stand for it.
            Self::Server(_) => self.zero_rtt_keys().is_some(),
        }
    }
    fn resumed(&self) -> bool {
        self.handshake_kind() == Some(rustls::HandshakeKind::Resumed)
    }
    fn exporter(&self) -> [u8; 32] {
        self.export_keying_material([0; 32], b"EXPORTER-test", Some(b"ctx"))
            .unwrap()
    }
    fn tls_records_pending(&self) -> bool {
        self.wants_write()
    }
    fn peer_certified(&self) -> bool {
        self.peer_certificates().is_some()
    }
}

/// Encryption levels, as indices.
const INITIAL: usize = 0;
const HANDSHAKE: usize = 1;
const ONE_RTT: usize = 2;

/// One side of an in-memory QUIC handshake: the connection, the level it
/// sends at, the keys it was given, the bytes waiting to go out and which
/// levels its bytes went out at.
struct Peer {
    conn: Box<dyn Endpoint>,
    level: usize,
    keys: [Option<LevelKeys>; 3],
    next: Option<Box<dyn NextKeys>>,
    outbox: Vec<(usize, Vec<u8>)>,
    sent_at: Vec<usize>,
}

impl Peer {
    fn new(conn: impl Endpoint + 'static) -> Self {
        Self {
            conn: Box::new(conn),
            level: INITIAL,
            keys: [None, None, None],
            next: None,
            outbox: Vec::new(),
            sent_at: Vec::new(),
        }
    }

    /// Collects what the connection has to send and its new keys, as a QUIC
    /// stack does after every `read_hs`.
    fn poll(&mut self) {
        loop {
            let mut buf = Vec::new();
            let change = self.conn.write_hs(&mut buf);
            if !buf.is_empty() {
                self.outbox.push((self.level, buf));
            }
            match change {
                None => return,
                Some(Change::Handshake(keys)) => {
                    assert_eq!(self.level, INITIAL);
                    self.level = HANDSHAKE;
                    self.keys[HANDSHAKE] = Some(keys);
                }
                Some(Change::OneRtt(keys, next)) => {
                    assert_eq!(self.level, HANDSHAKE);
                    self.level = ONE_RTT;
                    self.keys[ONE_RTT] = Some(keys);
                    self.next = Some(next);
                }
            }
        }
    }
}

/// Delivers `from`'s pending handshake bytes to `to`, one level's bytes at a
/// time. Returns whether anything moved, or `to`'s error.
fn pump(from: &mut Peer, to: &mut Peer) -> Result<bool, String> {
    from.poll();
    let outbox = std::mem::take(&mut from.outbox);
    let moved = !outbox.is_empty();
    for (level, bytes) in outbox {
        from.sent_at.push(level);
        to.conn.read_hs(&bytes)?;
        to.poll();
    }
    Ok(moved)
}

#[derive(Debug, PartialEq)]
enum Failed {
    Client(String),
    Server(String),
}

/// Runs the handshake until neither side has anything to send.
fn handshake(client: &mut Peer, server: &mut Peer) -> Result<(), Failed> {
    for _ in 0..16 {
        let c = pump(client, server).map_err(Failed::Server)?;
        let s = pump(server, client).map_err(Failed::Client)?;
        if !c && !s && !client.conn.handshaking() && !server.conn.handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not finish");
}

/// `a`'s sending keys protect what `b`'s receiving keys open, and the other
/// way round.
fn assert_dirs_match(a: &Dir, b: &Dir, what: &str) {
    let header = b"\x43\x01\x02\x03\x04";
    let sealed = a.packet.seal(9, header, b"payload");
    assert_eq!(
        b.packet.open(9, header, &sealed).as_deref(),
        Some(&b"payload"[..]),
        "{what}: packet keys differ"
    );
    assert!(
        b.packet.open(10, header, &sealed).is_none(),
        "{what}: nonce ignored"
    );
    let sample = [0x5a; 16];
    assert_eq!(
        a.header.protect(&sample),
        b.header.protect(&sample),
        "{what}: header keys differ"
    );
}

/// Every level's keys and two key updates agree between the two sides.
fn assert_keys_match(client: &mut Peer, server: &mut Peer) {
    for (level, name) in [(HANDSHAKE, "handshake"), (ONE_RTT, "1-RTT")] {
        let c = client.keys[level].as_ref().expect("client keys");
        let s = server.keys[level].as_ref().expect("server keys");
        assert_dirs_match(&c.local, &s.remote, name);
        assert_dirs_match(&s.local, &c.remote, name);
        // The two directions use different keys.
        let sealed = c.local.packet.seal(1, b"h", b"x");
        assert!(c.remote.packet.open(1, b"h", &sealed).is_none());
    }
    let c_next = client.next.as_mut().unwrap();
    let s_next = server.next.as_mut().unwrap();
    for phase in 1..=2 {
        let (c_local, c_remote) = c_next.next();
        let (s_local, s_remote) = s_next.next();
        let sealed = c_local.seal(phase, b"h", b"update");
        assert_eq!(
            s_remote.open(phase, b"h", &sealed).as_deref(),
            Some(&b"update"[..])
        );
        let sealed = s_local.seal(phase, b"h", b"update");
        assert_eq!(
            c_remote.open(phase, b"h", &sealed).as_deref(),
            Some(&b"update"[..])
        );
        // A key update changes the keys.
        let old = &client.keys[ONE_RTT].as_ref().unwrap().remote.packet;
        assert!(old.open(phase, b"h", &sealed).is_none());
    }
}

const CLIENT_PARAMS: &[u8] = b"client transport parameters";
const SERVER_PARAMS: &[u8] = b"server transport parameters";
const ALPN: &[u8] = b"h3";

fn b_client_config_with(
    chain: &Chain,
    provider: browntls_core::crypto::CryptoProvider,
) -> browntls_core::ClientConfig {
    let mut config = browntls_core::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config
}

fn b_client_config(chain: &Chain) -> browntls_core::ClientConfig {
    b_client_config_with(chain, prov::default_provider())
}

fn b_server_config(chain: &Chain) -> browntls_core::ServerConfig {
    let mut config = server_config(chain);
    config.alpn_protocols = vec![ALPN.to_vec()];
    config
}

fn b_client(config: &Arc<browntls_core::ClientConfig>) -> Peer {
    Peer::new(bq::Connection::Client(
        bq::ClientConnection::new(
            config.clone(),
            bq::Version::V1,
            server_name(),
            CLIENT_PARAMS.to_vec(),
        )
        .unwrap(),
    ))
}

fn b_server(config: &Arc<browntls_core::ServerConfig>) -> Peer {
    Peer::new(bq::Connection::Server(
        bq::ServerConnection::new(config.clone(), bq::Version::V1, SERVER_PARAMS.to_vec()).unwrap(),
    ))
}

/// A full handshake's checks: parameters, ALPN, level sequence, keys.
fn assert_full_handshake(client: &mut Peer, server: &mut Peer) {
    assert_eq!(client.conn.params().as_deref(), Some(SERVER_PARAMS));
    assert_eq!(server.conn.params().as_deref(), Some(CLIENT_PARAMS));
    assert_eq!(client.conn.alpn().as_deref(), Some(ALPN));
    assert_eq!(server.conn.alpn().as_deref(), Some(ALPN));
    assert_eq!(client.conn.exporter(), server.conn.exporter());
    // ClientHello at Initial, client Finished at Handshake.
    assert_eq!(client.sent_at, [INITIAL, HANDSHAKE]);
    // ServerHello at Initial, EncryptedExtensions..Finished at Handshake,
    // then (perhaps) tickets at 1-RTT.
    assert_eq!(server.sent_at[..2], [INITIAL, HANDSHAKE]);
    assert!(server.sent_at[2..].iter().all(|l| *l == ONE_RTT));
    assert_keys_match(client, server);
}

include!("quic/vectors.rs");
include!("quic/handshakes.rs");
include!("quic/service_identity.rs");
include!("quic/rules.rs");
include!("quic/interop.rs");
include!("quic/grease.rs");
