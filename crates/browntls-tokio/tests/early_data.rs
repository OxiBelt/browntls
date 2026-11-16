//! TLS 1.3 0-RTT data through `TlsConnector::early_data`: accepted,
//! declined (and resent), and a read that completes the handshake.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Read as _;
use std::sync::Arc;
use std::time::Duration;

use browntls::server::{ServerSessionMemoryCache, StoresServerSessions};
use browntls::{HandshakeKind, ServerConfig};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

struct Setup {
    pki: Pki,
    cache: Arc<dyn StoresServerSessions>,
    connector: TlsConnector,
}

impl Setup {
    fn new() -> Self {
        let pki = Pki::new();
        let mut client_config = pki.client_config(&browntls::version::TLS13);
        client_config.enable_early_data = true;
        Self {
            connector: TlsConnector::from(Arc::new(client_config)).early_data(true),
            cache: ServerSessionMemoryCache::new(8),
            pki,
        }
    }

    fn acceptor(&self, max_early_data_size: u32) -> TlsAcceptor {
        let mut config: ServerConfig = self.pki.server_config(&browntls::version::TLS13);
        config.max_early_data_size = max_early_data_size;
        config.session_storage = self.cache.clone();
        TlsAcceptor::from(Arc::new(config))
    }

    /// A full handshake that leaves the client a ticket allowing 1 KiB of
    /// early data.
    async fn first_connection(&self) {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(
            self.connector.connect(localhost(), c),
            self.acceptor(1024).accept(s),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_eq!(
            client.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Full)
        );
        // Reading the server's data processes the tickets sent before it.
        server.write_all(b"t").await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(client.get_ref().1.tls13_tickets_received() > 0);
    }
}

#[tokio::test]
async fn accepted_early_data_and_a_read_that_completes_the_handshake() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        // Returns before the handshake: nothing has been sent yet.
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        assert!(client.get_ref().1.is_handshaking());
        client.write_all(b"early request").await.unwrap();
        // No flush: the read sends the ClientHello and early data, and
        // completes the handshake.
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        assert!(client.get_ref().1.is_early_data_accepted());
        assert_eq!(
            client.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Resumed)
        );
        client.write_all(b"after").await.unwrap();
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(1024).accept(s).await.unwrap();
        let mut early = Vec::new();
        server
            .get_mut()
            .1
            .early_data()
            .expect("early data accepted")
            .read_to_end(&mut early)
            .unwrap();
        assert_eq!(early, b"early request");
        server.write_all(b"reply").await.unwrap();
        server.flush().await.unwrap();
        // Ordinary reads see only the 1-RTT data.
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"after");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn declined_early_data_is_resent_as_ordinary_data() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        client.flush().await.unwrap();
        assert!(!client.get_ref().1.is_handshaking());
        assert!(!client.get_ref().1.is_early_data_accepted());
        client.shutdown().await.unwrap();
        // Kept open until the server is done writing its tickets.
        client
    };
    let server_side = async {
        // This server no longer takes early data.
        let mut server = setup.acceptor(0).accept(s).await.unwrap();
        assert!(server.get_mut().1.early_data().is_none());
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"early request");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn early_data_beyond_the_allowance_goes_out_after_the_handshake() {
    let setup = Setup::new();
    setup.first_connection().await;

    let data = pattern(3000);
    let (c, s) = duplex(64 * 1024);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        // 1 KiB as early data; the write that finds the allowance spent
        // completes the handshake and sends the rest as 1-RTT data.
        client.write_all(&data).await.unwrap();
        assert!(!client.get_ref().1.is_handshaking());
        assert!(client.get_ref().1.is_early_data_accepted());
        client.shutdown().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(1024).accept(s).await.unwrap();
        let mut got = Vec::new();
        server
            .get_mut()
            .1
            .early_data()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got.len(), 1024);
        server.read_to_end(&mut got).await.unwrap();
        assert!(got == data, "data differs");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

#[tokio::test]
async fn without_a_ticket_connect_waits_for_the_handshake() {
    let setup = Setup::new();
    let (c, s) = duplex(64 * 1024);
    let (client, server) = tokio::join!(
        setup.connector.connect(localhost(), c),
        setup.acceptor(1024).accept(s),
    );
    assert!(!client.unwrap().get_ref().1.is_handshaking());
    server.unwrap();
}
