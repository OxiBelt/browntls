//! QUIC-TLS (RFC 9001) with legacy RSA client authentication: the
//! handshake bytes travel as CRYPTO data, read with `read_hs` and written
//! with `write_hs` level by level, and the client's legacy
//! CertificateVerify goes at the Handshake level.

use std::sync::Arc;

use browntls_core::quic::{self as bq, KeyChange};
use browntls_core::{AlertDescription, ClientConfig, Error, HandshakeKind, ServerConfig};

use crate::common::server_name;
use crate::identity::{Setup, rsa_client};

const INITIAL: usize = 0;
const HANDSHAKE: usize = 1;
const ONE_RTT: usize = 2;

/// One side of an in-memory QUIC connection: the level it writes at and
/// the CRYPTO bytes it sent at each level.
struct Peer {
    conn: bq::Connection,
    level: usize,
    outbox: Vec<Vec<u8>>,
    sent: [usize; 3],
}

impl Peer {
    fn client(config: &Arc<ClientConfig>) -> Self {
        let conn = bq::ClientConnection::new(
            config.clone(),
            bq::Version::V1,
            server_name(),
            b"c".to_vec(),
        )
        .unwrap();
        Self::new(bq::Connection::Client(conn))
    }

    fn server(config: &Arc<ServerConfig>) -> Self {
        let conn =
            bq::ServerConnection::new(config.clone(), bq::Version::V1, b"s".to_vec()).unwrap();
        Self::new(bq::Connection::Server(conn))
    }

    fn new(conn: bq::Connection) -> Self {
        Self {
            conn,
            level: INITIAL,
            outbox: Vec::new(),
            sent: [0; 3],
        }
    }

    /// Takes what the connection writes, level by level.
    fn poll(&mut self) {
        loop {
            let mut buf = Vec::new();
            let change = self.conn.write_hs(&mut buf);
            if !buf.is_empty() {
                self.sent[self.level] += buf.len();
                self.outbox.push(buf);
            }
            match change {
                None => return,
                Some(KeyChange::Handshake { .. }) => self.level = HANDSHAKE,
                Some(KeyChange::OneRtt { .. }) => self.level = ONE_RTT,
            }
        }
    }
}

/// Delivers `from`'s CRYPTO bytes to `to`; whether anything moved.
fn pump(from: &mut Peer, to: &mut Peer) -> Result<bool, Error> {
    from.poll();
    let outbox = std::mem::take(&mut from.outbox);
    let moved = !outbox.is_empty();
    for bytes in outbox {
        to.conn.read_hs(&bytes)?;
        to.poll();
    }
    Ok(moved)
}

#[derive(Debug, PartialEq)]
enum Failed {
    Client(Error),
    Server(Error),
}

fn handshake(client: &mut Peer, server: &mut Peer) -> Result<(), Failed> {
    for _ in 0..16 {
        let c = pump(client, server).map_err(Failed::Server)?;
        let s = pump(server, client).map_err(Failed::Client)?;
        if !c && !s && !client.conn.is_handshaking() && !server.conn.is_handshaking() {
            return Ok(());
        }
    }
    panic!("QUIC handshake did not finish");
}

fn exporter(conn: &bq::Connection) -> [u8; 32] {
    conn.export_keying_material([0; 32], b"EXPORTER-test", None)
        .unwrap()
}

fn connect(setup: &Setup) -> (Peer, Peer) {
    let mut client = Peer::client(&setup.client);
    let mut server = Peer::server(&setup.server);
    handshake(&mut client, &mut server).unwrap();
    assert_eq!(exporter(&client.conn), exporter(&server.conn));
    (client, server)
}

/// The legacy key authenticates a QUIC client to an opted-in server: both
/// handshakes complete, the exporters agree, and the server verified
/// exactly one `rsa_pkcs1_sha512_legacy` signature over the client's chain.
#[test]
fn quic_mutual_authentication_with_the_legacy_key() {
    let setup = Setup::new(true);
    let (client, server) = connect(&setup);
    setup.assert_schemes();
    assert_eq!(client.conn.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.conn.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(
        server.conn.peer_certificates().unwrap(),
        rsa_client().cert_chain()
    );
    // The client's Handshake-level CRYPTO data holds its chain (compressed
    // when certificate compression is built) and its CertificateVerify,
    // whose signature alone is 256 bytes.
    assert!(
        client.sent[HANDSHAKE] > 4 + 2 + 2 + 256,
        "{:?}",
        client.sent
    );
}

/// Against a server without the opt-in, the client sends an empty
/// Certificate and the server fails with `NoCertificatesPresented`. Its
/// `certificate_required` alert becomes the QUIC CRYPTO_ERROR
/// 0x100 + 116 (RFC 9001 §4.8), which closes the connection.
#[test]
fn quic_default_server_refuses_the_legacy_key() {
    let setup = Setup::new(false);
    let mut client = Peer::client(&setup.client);
    let mut server = Peer::server(&setup.server);
    let failed = handshake(&mut client, &mut server).unwrap_err();
    assert_eq!(failed, Failed::Server(Error::NoCertificatesPresented));
    let alert = server.conn.alert().unwrap();
    assert_eq!(alert, AlertDescription::CertificateRequired);
    assert_eq!(bq::crypto_error_code(alert), 0x0174);
    assert!(setup.client_auth.seen().is_empty());
    assert!(server.conn.peer_certificates().is_none());
}

/// A resumed connection authenticates with the PSK of the ticket from the
/// legacy-authenticated one: no Certificate or CertificateVerify, so the
/// verifiers see no second signature, and the server still knows the
/// client's chain. 0-RTT keys come from that ticket.
#[test]
fn quic_resumption_after_legacy_client_authentication() {
    let setup = Setup::with(true, |client, server| {
        client.enable_early_data = true;
        server.max_early_data_size = u32::MAX;
    });
    let (_client, _server) = connect(&setup);
    setup.assert_schemes();

    let mut client = Peer::client(&setup.client);
    let mut server = Peer::server(&setup.server);
    client.poll();
    assert!(client.conn.zero_rtt_keys().is_some(), "0-RTT keys");
    handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.conn.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.conn.handshake_kind(), Some(HandshakeKind::Resumed));
    let bq::Connection::Server(s) = &server.conn else {
        unreachable!()
    };
    assert!(s.is_early_data_accepted());
    assert_eq!(exporter(&client.conn), exporter(&server.conn));
    // Still the one signature each from the full handshake.
    setup.assert_schemes();
    assert_eq!(
        server.conn.peer_certificates().unwrap(),
        rsa_client().cert_chain()
    );
    assert!(client.sent[HANDSHAKE] < 100, "{:?}", client.sent);
}
