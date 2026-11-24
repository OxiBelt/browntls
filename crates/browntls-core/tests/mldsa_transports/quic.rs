//! QUIC-TLS (RFC 9001) with ML-DSA authentication: the handshake bytes
//! travel as CRYPTO data, read with `read_hs` and written with `write_hs`
//! level by level, so the large Certificate and CertificateVerify messages
//! reach the peer as one stream of bytes per encryption level.

use std::sync::Arc;

use browntls_core::quic::{self as bq, KeyChange};
use browntls_core::{
    AlertDescription, ClientConfig, Error, HandshakeKind, PeerIncompatible, ServerConfig,
};

use crate::identity::{Setup, TLS13_ONLY, server_name};
use crate::ml_dsa::{SETS, Set};

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

#[test]
fn quic_server_and_mutual_authentication_with_every_parameter_set() {
    for set in SETS {
        for mutual in [false, true] {
            let setup = Setup::new(set, mutual);
            let (client, server) = connect(&setup);
            setup.assert_schemes(set);
            assert_eq!(server.conn.handshake_kind(), Some(HandshakeKind::Full));
            assert_eq!(client.conn.peer_certificates().unwrap().len(), 2);
            assert_eq!(
                server.conn.peer_certificates().map(<[_]>::len),
                mutual.then_some(2)
            );
            // The server's Handshake-level CRYPTO data holds its chain
            // and its signature, the client's its own when mutual.
            let signature = set.signature_len();
            assert!(server.sent[HANDSHAKE] > 2 * set.public_key_len() + 3 * signature);
            if mutual {
                assert!(client.sent[HANDSHAKE] > 2 * set.public_key_len() + 3 * signature);
            } else {
                assert!(client.sent[HANDSHAKE] < 100);
            }
            println!(
                "{set:?} mutual={mutual}: CRYPTO bytes server {:?}, client {:?}",
                server.sent, client.sent
            );
        }
    }
}

/// The client's first key share is for a group the server does not accept,
/// so the server answers with a HelloRetryRequest (in the Initial CRYPTO
/// data); the handshake then completes with ML-DSA server authentication.
#[test]
fn quic_hello_retry_request_with_ml_dsa_server_authentication() {
    let setup = Setup::new(Set::MlDsa65, false);
    let mut provider = (*crate::identity::opt_in()).clone();
    provider.kx_groups = vec![crate::prov::kx_group::SECP384R1];
    let server = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(TLS13_ONLY)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(setup.server_id.served(), setup.server_id.private_key())
        .unwrap();
    let mut client = Peer::client(&setup.client);
    let mut server = Peer::server(&Arc::new(server));
    handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        client.conn.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.conn.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(exporter(&client.conn), exporter(&server.conn));
    setup.assert_schemes(Set::MlDsa65);
    assert_eq!(client.conn.peer_certificates().unwrap().len(), 2);
}

/// RFC 9001 §4.8: a TLS alert becomes the QUIC CRYPTO_ERROR 0x100 + alert.
#[test]
fn quic_client_without_the_opt_in_gets_handshake_failure() {
    let setup = Setup::new(Set::MlDsa65, false);
    // The client offers the default schemes only: no ML-DSA.
    let provider = browntls_core::crypto::native::default_provider();
    let client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(TLS13_ONLY)
        .unwrap()
        .with_root_certificates(setup.server_id.chain.roots())
        .with_no_client_auth();
    let mut client = Peer::client(&Arc::new(client));
    let mut server = Peer::server(&setup.server);
    let failed = handshake(&mut client, &mut server).unwrap_err();
    assert_eq!(
        failed,
        Failed::Server(Error::PeerIncompatible(
            PeerIncompatible::NoSignatureSchemesInCommon
        ))
    );
    let alert = server.conn.alert().unwrap();
    assert_eq!(alert, AlertDescription::HandshakeFailure);
    assert_eq!(bq::crypto_error_code(alert), 0x0128);
    assert!(setup.server_auth.seen().is_empty());
}

/// A resumed connection authenticates with the PSK: no Certificate or
/// CertificateVerify, so the verifiers see no second signature; 0-RTT keys
/// come from the ticket of the ML-DSA-authenticated connection.
#[test]
fn quic_resumption_and_zero_rtt_after_ml_dsa_authentication() {
    let setup = Setup::with(Set::MlDsa87, true, |client, server| {
        client.enable_early_data = true;
        server.max_early_data_size = u32::MAX;
    });
    let (_client, _server) = connect(&setup);
    setup.assert_schemes(Set::MlDsa87);

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
    // Still the one signature each from the full handshake.
    setup.assert_schemes(Set::MlDsa87);
    assert!(server.sent[HANDSHAKE] < 1000, "{:?}", server.sent);
}
