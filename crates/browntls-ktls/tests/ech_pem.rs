//! Userspace ECH from PEM and the existing blocking and async handoffs.

#![cfg(all(target_os = "linux", feature = "native"))]
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use browntls_core::crypto::hpke::Hpke;
use browntls_core::crypto::native::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
use browntls_core::ech::pem::{EchPem, EchPemError, NATIVE_PKCS8_CODEC};
use browntls_core::ech::{EchServerConfig, EchServerKey, EchStatus};
use browntls_core::kernel::KernelHandoffBlocker;
use browntls_core::{
    CipherSuite, ClientConnection, Error, ServerConnection, Stream, SupportedCipherSuite,
};
use browntls_ktls::ech::{prepare_client, prepare_server};
use browntls_ktls::{HandoffError, KtlsStream};

use common::{Pki, kernel_tls, localhost, offloadable_suites, read_n, tcp_pair};

const SUITES: &[&dyn Hpke] = &[DH_KEM_X25519_HKDF_SHA256_AES_128];
const LIMIT: Duration = Duration::from_secs(10);

fn suite() -> SupportedCipherSuite {
    offloadable_suites()
        .into_iter()
        .find(|s| s.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256)
        .unwrap()
}

fn pem_fixture() -> (EchPem, EchPem) {
    let key = EchServerKey::generate(7, "public.example", 32, SUITES).unwrap();
    let ech = EchServerConfig::new(vec![key.clone()]).unwrap();
    let list = ech.ech_config_list();
    (
        EchPem::from_config_list(list).unwrap(),
        EchPem::from_server_key(&key, list, &NATIVE_PKCS8_CODEC).unwrap(),
    )
}

#[test]
fn preparation_preserves_typed_tls_errors() {
    let (public, private) = pem_fixture();
    let pki = Pki::new();
    let mut client = pki.client_config(suite());
    client.max_tls13_tickets_per_connection = 256;
    assert!(matches!(
        prepare_client(client, localhost(), &public, SUITES),
        Err(EchPemError::Tls(Error::BadTls13TicketLimit))
    ));

    let mut server = pki.server_config(suite());
    server.ech_backend = true;
    assert!(matches!(
        prepare_server(server, &[private], &[public], SUITES),
        Err(EchPemError::Tls(Error::General(message)))
            if message.contains("ech_backend")
    ));
}

fn userspace_pair(
    enable_secret_extraction: bool,
) -> ((ClientConnection, TcpStream), (ServerConnection, TcpStream)) {
    let (public, private) = pem_fixture();
    let pki = Pki::new();
    let mut client_config = pki.client_config(suite());
    let mut server_config = pki.server_config(suite());
    client_config.enable_secret_extraction = enable_secret_extraction;
    server_config.enable_secret_extraction = enable_secret_extraction;
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    server_config.send_tls13_tickets = 0;
    let mut client = prepare_client(client_config, localhost(), &public, SUITES).unwrap();
    let mut server = prepare_server(server_config, &[private], &[public], SUITES).unwrap();

    let (mut client_tcp, mut server_tcp) = tcp_pair();
    for tcp in [&client_tcp, &server_tcp] {
        tcp.set_read_timeout(Some(LIMIT)).unwrap();
        tcp.set_write_timeout(Some(LIMIT)).unwrap();
    }
    thread::scope(|scope| {
        let accepting = scope.spawn(|| {
            Stream::new(&mut server, &mut server_tcp)
                .complete_prior_io()
                .unwrap();
        });
        Stream::new(&mut client, &mut client_tcp)
            .complete_prior_io()
            .unwrap();
        accepting.join().unwrap();
    });

    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(server.ech_status(), EchStatus::Accepted);
    assert_eq!(server.server_name(), Some("localhost"));
    assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
    ((client, client_tcp), (server, server_tcp))
}

#[test]
fn prepared_connections_require_explicit_secret_extraction() {
    let ((client, client_tcp), (server, server_tcp)) = userspace_pair(false);
    let disabled = Some(KernelHandoffBlocker::SecretExtractionDisabled);
    assert_eq!(client.kernel_handoff_blocker(), disabled);
    assert_eq!(server.kernel_handoff_blocker(), disabled);
    assert!(matches!(
        KtlsStream::new(client, client_tcp),
        Err(HandoffError::Refused { .. })
    ));
    assert!(matches!(
        KtlsStream::new(server, server_tcp),
        Err(HandoffError::Refused { .. })
    ));
}

#[test]
fn prepared_connections_use_blocking_handoff() {
    let ((client, client_tcp), (server, server_tcp)) = userspace_pair(true);
    if !kernel_tls() {
        return;
    }
    let mut client = KtlsStream::new(client, client_tcp).unwrap();
    let mut server = KtlsStream::new(server, server_tcp).unwrap();
    client.write_all(b"hello").unwrap();
    assert_eq!(read_n(&mut server, 5).unwrap(), b"hello");
    server.write_all(b"world").unwrap();
    assert_eq!(read_n(&mut client, 5).unwrap(), b"world");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn prepared_connections_use_async_handoff() {
    use browntls_ktls::AsyncKtlsStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let ((client, client_tcp), (server, server_tcp)) =
        tokio::task::spawn_blocking(|| userspace_pair(true))
            .await
            .unwrap();
    if !kernel_tls() {
        return;
    }
    client_tcp.set_nonblocking(true).unwrap();
    server_tcp.set_nonblocking(true).unwrap();
    let mut client =
        AsyncKtlsStream::new(client, TcpStream::from_std(client_tcp).unwrap(), Vec::new()).unwrap();
    let mut server =
        AsyncKtlsStream::new(server, TcpStream::from_std(server_tcp).unwrap(), Vec::new()).unwrap();
    timeout(LIMIT, async {
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0; 5];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        server.write_all(b"world").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    })
    .await
    .unwrap();
}
