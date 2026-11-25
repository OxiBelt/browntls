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

/// The ECH records of RFC 9850 §2.3 reach the key log of a Tokio
/// handshake, buffered or not: one `ECH_SECRET` and one `ECH_CONFIG` on
/// each side. ECH needs HPKE, which only the native provider has.
#[cfg(feature = "native")]
mod ech {
    use std::sync::Mutex;

    use browntls_core::crypto::hpke::Hpke;
    use browntls_core::crypto::native::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    use browntls_core::ech::{EchConfig, EchMode, EchServerConfig, EchServerKey, EchStatus};
    use browntls_core::{ClientConfig, ServerConfig};

    use super::*;

    const SUITES: &[&dyn Hpke] = &[DH_KEM_X25519_HKDF_SHA256_AES_128];

    /// The ECH labels a connection logged, in order.
    #[derive(Debug, Default)]
    struct EchLabels(Mutex<Vec<String>>);

    impl KeyLog for EchLabels {
        fn log(&self, label: &str, _: &[u8], _: &[u8]) {
            if label.starts_with("ECH_") {
                self.0.lock().unwrap().push(label.to_owned());
            }
        }
    }

    impl EchLabels {
        fn assert_one_pair(&self) {
            let labels = self.0.lock().unwrap();
            let pair = ["ECH_SECRET", "ECH_CONFIG"];
            let require_disabled =
                std::env::var("BROWNTLS_KEY_LOG_REQUIRE_DISABLED").is_ok_and(|value| value == "1");
            if require_disabled {
                assert!(labels.is_empty());
            } else if cfg!(feature = "key-log") {
                assert_eq!(*labels, pair);
            } else {
                // Another workspace member can enable the core dependency
                // feature.
                assert!(labels.is_empty() || *labels == pair);
            }
        }
    }

    fn configs() -> (ClientConfig, ServerConfig, [Arc<EchLabels>; 2]) {
        let pki = Pki::new();
        let key = EchServerKey::generate(7, "public.example", 32, SUITES).unwrap();
        let ech = Arc::new(EchServerConfig::new(vec![key]).unwrap());
        let logs = [
            Arc::new(EchLabels::default()),
            Arc::new(EchLabels::default()),
        ];
        let mut client = pki.client_config(&browntls_core::version::TLS13);
        client.ech_mode = Some(EchMode::Enable(
            EchConfig::new(ech.ech_config_list(), SUITES).unwrap(),
        ));
        client.key_log = logs[0].clone();
        let mut server = pki.server_config(&browntls_core::version::TLS13);
        server.ech = Some(ech);
        server.key_log = logs[1].clone();
        (client, server, logs)
    }

    #[tokio::test]
    async fn ech_records_reach_the_key_log_of_a_tokio_handshake() {
        let (client_config, server_config, logs) = configs();
        let connector = TlsConnector::from(Arc::new(client_config));
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client, server) = tokio::join!(
            connector.connect(localhost(), client_io),
            acceptor.accept(server_io)
        );
        assert_eq!(
            client.unwrap().get_ref().1.ech_status(),
            EchStatus::Accepted
        );
        assert_eq!(
            server.unwrap().get_ref().1.ech_status(),
            EchStatus::Accepted
        );
        logs[0].assert_one_pair();
        logs[1].assert_one_pair();
    }

    #[tokio::test]
    async fn ech_records_reach_the_key_log_of_an_unbuffered_tokio_handshake() {
        use browntls_tokio::unbuffered;

        let (client_config, server_config, logs) = configs();
        let connector = unbuffered::TlsConnector::from(Arc::new(client_config));
        let acceptor = unbuffered::TlsAcceptor::from(Arc::new(server_config));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client, server) = tokio::join!(
            connector.connect(localhost(), client_io),
            acceptor.accept(server_io)
        );
        assert_eq!(
            client.unwrap().get_ref().1.ech_status(),
            EchStatus::Accepted
        );
        assert_eq!(
            server.unwrap().get_ref().1.ech_status(),
            EchStatus::Accepted
        );
        logs[0].assert_one_pair();
        logs[1].assert_one_pair();
    }
}
