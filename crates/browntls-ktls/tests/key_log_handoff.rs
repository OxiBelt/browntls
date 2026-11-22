//! Key logging stays on the userspace handshake side of synchronous and
//! asynchronous kernel handoff. The test sink counts events only.

#![cfg(all(
    target_os = "linux",
    feature = "key-log",
    any(feature = "native", feature = "rustcrypto")
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use browntls_core::{KeyLog, SupportedCipherSuite};
#[cfg(feature = "tokio")]
use browntls_ktls::AsyncKtlsStream;
use browntls_ktls::KtlsStream;
use common::*;

#[derive(Debug, Default)]
struct CountingKeyLog(AtomicUsize);

impl KeyLog for CountingKeyLog {
    fn log(&self, _: &str, _: &[u8], _: &[u8]) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn suitable_suite() -> SupportedCipherSuite {
    offloadable_suites()
        .into_iter()
        .find(|suite| suite.version().version == browntls_core::ProtocolVersion::TLSv1_3)
        .expect("provider has a TLS 1.3 suite accepted by kernel TLS")
}

#[test]
fn blocking_handoff_completes_key_logged_handshakes_in_userspace() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = suitable_suite();
    let client_log = Arc::new(CountingKeyLog::default());
    let server_log = Arc::new(CountingKeyLog::default());
    let mut client_config = pki.client_config(suite);
    client_config.key_log = client_log.clone();
    let mut server_config = pki.server_config(suite);
    server_config.key_log = server_log.clone();
    let (client_tcp, server_tcp) = tcp_pair();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let connection = browntls_core::ServerConnection::new(Arc::new(server_config)).unwrap();
            let _stream = KtlsStream::new(connection, server_tcp).unwrap();
        });
        let connection =
            browntls_core::ClientConnection::new(Arc::new(client_config), localhost()).unwrap();
        let _stream = KtlsStream::new(connection, client_tcp).unwrap();
        server.join().unwrap();
    });
    assert!(client_log.0.load(Ordering::Relaxed) > 0);
    assert!(server_log.0.load(Ordering::Relaxed) > 0);
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_handoff_completes_key_logged_handshakes_in_userspace() {
    if !kernel_tls() {
        return;
    }
    use browntls_tokio::{TlsAcceptor, TlsConnector};
    use tokio::net::TcpStream;

    let pki = Pki::new();
    let suite = suitable_suite();
    let client_log = Arc::new(CountingKeyLog::default());
    let server_log = Arc::new(CountingKeyLog::default());
    let mut client_config = pki.client_config(suite);
    client_config.key_log = client_log.clone();
    let mut server_config = pki.server_config(suite);
    server_config.key_log = server_log.clone();
    let (client_std, server_std) = tcp_pair();
    client_std.set_nonblocking(true).unwrap();
    server_std.set_nonblocking(true).unwrap();
    let client_tcp = TcpStream::from_std(client_std).unwrap();
    let server_tcp = TcpStream::from_std(server_std).unwrap();
    let client = TlsConnector::from(Arc::new(client_config)).connect(localhost(), client_tcp);
    let server = TlsAcceptor::from(Arc::new(server_config)).accept(server_tcp);
    let (client, server) = tokio::join!(client, server);
    let (client, server) = (client.unwrap(), server.unwrap());
    let (client, server) = tokio::join!(
        AsyncKtlsStream::from_client(client),
        AsyncKtlsStream::from_server(server)
    );
    let (_client, _server) = (client.unwrap(), server.unwrap());
    assert!(client_log.0.load(Ordering::Relaxed) > 0);
    assert!(server_log.0.load(Ordering::Relaxed) > 0);
}
