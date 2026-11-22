//! The shared key-log configuration reaches Tokio handshakes without storing
//! or displaying secret material in the test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[cfg(feature = "key-log")]
use std::sync::Arc;
#[cfg(feature = "key-log")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "key-log")]
use browntls_core::KeyLog;
#[cfg(feature = "key-log")]
use browntls_tokio::{TlsAcceptor, TlsConnector};
#[cfg(feature = "key-log")]
use common::*;

#[cfg(feature = "key-log")]
#[derive(Debug, Default)]
struct CountingKeyLog(AtomicUsize);

#[cfg(feature = "key-log")]
impl KeyLog for CountingKeyLog {
    fn log(&self, _: &str, _: &[u8], _: &[u8]) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
#[cfg(feature = "key-log")]
async fn key_log_configuration_reaches_tokio_handshake() {
    let pki = Pki::new();
    let client_log = Arc::new(CountingKeyLog::default());
    let server_log = Arc::new(CountingKeyLog::default());
    let mut client_config = pki.client_config(&browntls_core::version::TLS13);
    client_config.key_log = client_log.clone();
    let mut server_config = pki.server_config(&browntls_core::version::TLS13);
    server_config.key_log = server_log.clone();
    let connector = TlsConnector::from(Arc::new(client_config));
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let (client, server) = tokio::join!(
        connector.connect(localhost(), client_io),
        acceptor.accept(server_io)
    );
    assert!(client.is_ok());
    assert!(server.is_ok());
    assert!(client_log.0.load(Ordering::Relaxed) > 0);
    assert!(server_log.0.load(Ordering::Relaxed) > 0);
}

#[tokio::test]
#[cfg(feature = "key-log")]
async fn key_log_configuration_reaches_unbuffered_tokio_handshake() {
    use browntls_tokio::unbuffered;

    let pki = Pki::new();
    let client_log = Arc::new(CountingKeyLog::default());
    let server_log = Arc::new(CountingKeyLog::default());
    let mut client_config = pki.client_config(&browntls_core::version::TLS13);
    client_config.key_log = client_log.clone();
    let mut server_config = pki.server_config(&browntls_core::version::TLS13);
    server_config.key_log = server_log.clone();
    let connector = unbuffered::TlsConnector::from(Arc::new(client_config));
    let acceptor = unbuffered::TlsAcceptor::from(Arc::new(server_config));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let (client, server) = tokio::join!(
        connector.connect(localhost(), client_io),
        acceptor.accept(server_io)
    );
    assert!(client.is_ok());
    assert!(server.is_ok());
    assert!(client_log.0.load(Ordering::Relaxed) > 0);
    assert!(server_log.0.load(Ordering::Relaxed) > 0);
}
