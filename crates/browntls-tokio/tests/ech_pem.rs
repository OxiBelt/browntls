//! ECH from PEM on the buffered and unbuffered Tokio streams.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use browntls_core::crypto::hpke::Hpke;
use browntls_core::crypto::native::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
use browntls_core::ech::pem::{EchPem, EchPemError, NATIVE_PKCS8_CODEC};
use browntls_core::ech::{EchServerConfig, EchServerKey, EchStatus};
use browntls_core::{ClientConfig, ServerConfig, version};
use browntls_tokio::{TlsAcceptor, TlsConnector, unbuffered};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::time::timeout;

use common::{Pki, localhost};

const SUITES: &[&dyn Hpke] = &[DH_KEM_X25519_HKDF_SHA256_AES_128];
const LIMIT: Duration = Duration::from_secs(10);

fn pem_fixture() -> (EchPem, EchPem) {
    let key = EchServerKey::generate(7, "public.example", 32, SUITES).unwrap();
    let ech = EchServerConfig::new(vec![key.clone()]).unwrap();
    let list = ech.ech_config_list();
    (
        EchPem::from_config_list(list).unwrap(),
        EchPem::from_server_key(&key, list, &NATIVE_PKCS8_CODEC).unwrap(),
    )
}

fn configs() -> (ClientConfig, ServerConfig) {
    let pki = Pki::new();
    let mut client = pki.client_config(&version::TLS13);
    let mut server = pki.server_config(&version::TLS13);
    client.alpn_protocols = vec![b"h2".to_vec()];
    server.alpn_protocols = vec![b"h2".to_vec()];
    (client, server)
}

#[test]
fn constructors_preserve_pem_errors() {
    let (client, server) = configs();
    let (public, _) = pem_fixture();
    assert!(matches!(
        TlsConnector::from_ech_pem(client.clone(), &public, &[]),
        Err(EchPemError::Tls(_))
    ));
    assert!(matches!(
        unbuffered::TlsConnector::from_ech_pem(client, &public, &[]),
        Err(EchPemError::Tls(_))
    ));
    let public_only = std::slice::from_ref(&public);
    assert!(matches!(
        TlsAcceptor::from_ech_pem(server.clone(), public_only, public_only, SUITES),
        Err(EchPemError::MissingPrivateKey)
    ));
    assert!(matches!(
        unbuffered::TlsAcceptor::from_ech_pem(server, public_only, public_only, SUITES),
        Err(EchPemError::MissingPrivateKey)
    ));
}

#[tokio::test]
async fn buffered_ech_from_pem() {
    let (client_config, server_config) = configs();
    let (public, private) = pem_fixture();
    let connector = TlsConnector::from_ech_pem(client_config, &public, SUITES).unwrap();
    let acceptor = TlsAcceptor::from_ech_pem(server_config, &[private], &[public], SUITES).unwrap();
    assert!(!connector.config().enable_secret_extraction);
    assert!(!acceptor.config().enable_secret_extraction);

    timeout(LIMIT, async {
        let (client_io, server_io) = duplex(16 * 1024);
        let (client, server) = tokio::try_join!(
            connector.connect(localhost(), client_io),
            acceptor.accept(server_io),
        )
        .unwrap();
        assert_eq!(client.get_ref().1.ech_status(), EchStatus::Accepted);
        assert_eq!(server.get_ref().1.ech_status(), EchStatus::Accepted);
        assert_eq!(server.get_ref().1.server_name(), Some("localhost"));
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        exchange(client, server).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unbuffered_ech_from_pem() {
    let (client_config, server_config) = configs();
    let (public, private) = pem_fixture();
    let connector = unbuffered::TlsConnector::from_ech_pem(client_config, &public, SUITES).unwrap();
    let acceptor =
        unbuffered::TlsAcceptor::from_ech_pem(server_config, &[private], &[public], SUITES)
            .unwrap();
    assert!(!connector.config().enable_secret_extraction);
    assert!(!acceptor.config().enable_secret_extraction);

    timeout(LIMIT, async {
        let (client_io, server_io) = duplex(16 * 1024);
        let (client, server) = tokio::try_join!(
            connector.connect(localhost(), client_io),
            acceptor.accept(server_io),
        )
        .unwrap();
        assert_eq!(client.get_ref().1.ech_status(), EchStatus::Accepted);
        assert_eq!(server.get_ref().1.ech_status(), EchStatus::Accepted);
        assert_eq!(server.get_ref().1.server_name(), Some("localhost"));
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        exchange(client, server).await;
    })
    .await
    .unwrap();
}

async fn exchange(
    mut client: impl AsyncRead + AsyncWrite + Unpin,
    mut server: impl AsyncRead + AsyncWrite + Unpin,
) {
    client.write_all(b"hello").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0; 5];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
    server.write_all(b"world").await.unwrap();
    server.flush().await.unwrap();
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");
}
