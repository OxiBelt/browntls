//! Shared by the server early data tests: a client holding a ticket that
//! allows early data, servers that take it, and a client driven by hand.

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::server::{ServerSessionMemoryCache, StoresServerSessions};
use browntls_core::{ClientConfig, ClientConnection, HandshakeKind, ServerConfig};
use browntls_tokio::{TlsAcceptor, TlsConnector, server};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex};

use super::{Pki, localhost};

pub const LIMIT: Duration = Duration::from_secs(30);
pub const ALLOWANCE: u32 = 16 * 1024;

pub struct Setup {
    pub pki: Pki,
    pub cache: Arc<dyn StoresServerSessions>,
    pub client_config: Arc<ClientConfig>,
    pub connector: TlsConnector,
}

impl Setup {
    pub fn new() -> Self {
        let pki = Pki::new();
        let mut client_config = pki.client_config(&browntls_core::version::TLS13);
        client_config.enable_early_data = true;
        let client_config = Arc::new(client_config);
        Self {
            connector: TlsConnector::from(client_config.clone()).early_data(true),
            client_config,
            cache: ServerSessionMemoryCache::new(8),
            pki,
        }
    }

    pub fn server_config(&self, max_early_data_size: u32, half_rtt: bool) -> Arc<ServerConfig> {
        let mut config: ServerConfig = self.pki.server_config(&browntls_core::version::TLS13);
        config.max_early_data_size = max_early_data_size;
        config.send_half_rtt_data = half_rtt;
        config.session_storage = self.cache.clone();
        Arc::new(config)
    }

    /// An acceptor that returns before the handshake for early data.
    pub fn acceptor(&self, half_rtt: bool) -> TlsAcceptor {
        TlsAcceptor::from(self.server_config(ALLOWANCE, half_rtt)).early_data(true)
    }

    /// A full handshake that leaves the client a ticket allowing early data.
    pub async fn first_connection(&self) {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(
            self.connector.connect(localhost(), c),
            self.acceptor(false).accept(s),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_eq!(
            client.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Full)
        );
        // No early data: the option changes nothing.
        assert!(!server.get_ref().1.is_handshaking());
        assert!(server.early_data().is_none());
        // Reading the server's data processes the tickets sent before it.
        server.write_all(b"t").await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(client.get_ref().1.tls13_tickets_received() > 0);
    }

    /// A client driven by hand, so that a test decides when each of its
    /// flights is sent: it resumes, with `early` as early data.
    pub fn manual_client(&self, early: &[u8]) -> ClientConnection {
        let mut client = ClientConnection::new(self.client_config.clone(), localhost()).unwrap();
        client
            .early_data()
            .expect("the ticket allows early data")
            .write_all(early)
            .unwrap();
        client
    }
}

/// Writes everything `client` has queued to `io`.
pub async fn send(client: &mut ClientConnection, io: &mut DuplexStream) {
    let mut tls = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut tls).unwrap();
    }
    io.write_all(&tls).await.unwrap();
}

/// Waits for TLS bytes on `io` and has `client` process them.
pub async fn receive(client: &mut ClientConnection, io: &mut DuplexStream) {
    let mut tls = vec![0; 32 * 1024];
    let n = io.read(&mut tls).await.unwrap();
    assert!(n > 0, "the server closed the transport");
    let mut tls = &tls[..n];
    while !tls.is_empty() {
        client.read_tls(&mut tls).unwrap();
        client.process_new_packets().unwrap();
    }
}

pub async fn read_early<IO>(stream: &mut server::TlsStream<IO>, len: usize) -> Vec<u8>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut got = vec![0; len];
    stream
        .early_data()
        .expect("early data accepted")
        .read_exact(&mut got)
        .await
        .unwrap();
    got
}
