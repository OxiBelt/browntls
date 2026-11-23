//! The shared key-log configuration reaches Tokio handshakes without storing
//! or displaying secret material in the test.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use browntls_core::KeyLog;
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;

#[derive(Debug, Default)]
struct CountingKeyLog(AtomicUsize);

impl KeyLog for CountingKeyLog {
    fn log(&self, _: &str, _: &[u8], _: &[u8]) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl CountingKeyLog {
    fn assert_handshake_count(&self) {
        let count = self.0.load(Ordering::Relaxed);
        let require_disabled =
            std::env::var("BROWNTLS_KEY_LOG_REQUIRE_DISABLED").is_ok_and(|value| value == "1");
        if require_disabled {
            assert_eq!(count, 0);
        } else if cfg!(feature = "key-log") {
            assert_eq!(count, 5);
        } else {
            // Another workspace member can enable the core dependency feature.
            assert!(matches!(count, 0 | 5));
        }
    }
}

#[tokio::test]
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
    client_log.assert_handshake_count();
    server_log.assert_handshake_count();
}

#[tokio::test]
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
    client_log.assert_handshake_count();
    server_log.assert_handshake_count();
}
