//! Key logging stays on the userspace handshake side of synchronous and
//! asynchronous kernel handoff. The test sink counts known labels only.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use browntls_core::{KeyLog, SupportedCipherSuite};
#[cfg(feature = "tokio")]
use browntls_ktls::AsyncKtlsStream;
use browntls_ktls::KtlsStream;
use common::*;

const LABELS: [&str; 5] = [
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];
const LIMIT: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
struct CountingKeyLog(Mutex<[usize; LABELS.len() + 1]>);

impl KeyLog for CountingKeyLog {
    fn log(&self, label: &str, _: &[u8], _: &[u8]) {
        let index = LABELS.iter().position(|known| *known == label);
        self.0.lock().unwrap()[index.unwrap_or(LABELS.len())] += 1;
    }
}

impl CountingKeyLog {
    fn assert_handshake_labels(&self) -> [usize; LABELS.len() + 1] {
        let counts = self.counts();
        let enabled = [1, 1, 1, 1, 1, 0];
        let disabled = [0; LABELS.len() + 1];
        let require_disabled =
            std::env::var("BROWNTLS_KEY_LOG_REQUIRE_DISABLED").is_ok_and(|value| value == "1");
        if require_disabled {
            assert_eq!(counts, disabled);
        } else if cfg!(feature = "key-log") {
            assert_eq!(counts, enabled);
        } else {
            // Another workspace member can enable the core dependency feature.
            assert!(counts == enabled || counts == disabled);
        }
        counts
    }

    fn counts(&self) -> [usize; LABELS.len() + 1] {
        *self.0.lock().unwrap()
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
    for socket in [&client_tcp, &server_tcp] {
        socket.set_read_timeout(Some(LIMIT)).unwrap();
        socket.set_write_timeout(Some(LIMIT)).unwrap();
    }
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let connection = browntls_core::ServerConnection::new(Arc::new(server_config)).unwrap();
            assert!(connection.is_handshaking());
            let mut stream = KtlsStream::new(connection, server_tcp).unwrap();
            let labels = server_log.assert_handshake_labels();
            let mut request = [0; 7];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"request");
            stream.write_all(b"reply").unwrap();
            stream.flush().unwrap();
            assert_eq!(server_log.counts(), labels);
        });
        let connection =
            browntls_core::ClientConnection::new(Arc::new(client_config), localhost()).unwrap();
        assert!(connection.is_handshaking());
        let mut stream = KtlsStream::new(connection, client_tcp).unwrap();
        let labels = client_log.assert_handshake_labels();
        stream.write_all(b"request").unwrap();
        stream.flush().unwrap();
        let mut reply = [0; 5];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
        assert_eq!(client_log.counts(), labels);
        server.join().unwrap();
    });
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_handoff_completes_key_logged_handshakes_in_userspace() {
    if !kernel_tls() {
        return;
    }
    use browntls_tokio::{TlsAcceptor, TlsConnector};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

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
    timeout(LIMIT, async {
        let (client, server) = tokio::join!(client, server);
        let client_labels = client_log.assert_handshake_labels();
        let server_labels = server_log.assert_handshake_labels();

        let (client, server) = tokio::join!(
            client.unwrap().into_kernel_handoff(),
            AsyncKtlsStream::from_server(server.unwrap()),
        );
        let (socket, conn, received) = client.unwrap().into_parts();
        let mut client = AsyncKtlsStream::new(conn, socket, received).unwrap();
        let mut server = server.unwrap();
        assert_eq!(client_log.counts(), client_labels);
        assert_eq!(server_log.counts(), server_labels);

        client.write_all(b"request").await.unwrap();
        client.flush().await.unwrap();
        let mut request = [0; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        server.write_all(b"reply").await.unwrap();
        server.flush().await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        assert_eq!(client_log.counts(), client_labels);
        assert_eq!(server_log.counts(), server_labels);
    })
    .await
    .expect("handshake, handoff, or application data timed out");
}
