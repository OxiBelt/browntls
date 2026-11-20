//! A server with `ServerConfig::enable_grease` (RFC 8701 §4.1) behind the
//! asynchronous streams: its CertificateRequest and NewSessionTicket
//! messages carry GREASE values, and browntls and tokio-rustls clients still
//! authenticate with a certificate, exchange data and resume from the
//! tickets. The bytes on the wire are checked by the core tests; these cases
//! show the option works through `TlsAcceptor`, a post-handshake
//! CertificateRequest and the unbuffered driver.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::server::PostHandshakeAuthStatus;
use browntls_core::{HandshakeKind, ServerConfig, version};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use rustls::crypto::ring as ring_provider;
use rustls_pki_types as rpki;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

/// A TLS 1.3 server that verifies client certificates, with GREASE on.
fn grease_server(pki: &Pki) -> ServerConfig {
    let mut config = pki.server_config_with_client_auth(&version::TLS13);
    config.enable_grease = true;
    config
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.unwrap(), server.unwrap().0)
}

/// Sends `up` from the client and `down` from the server at the same time,
/// each side closing with `close_notify`, and checks what arrived. Reading
/// to the end makes the client process the tickets.
async fn exchange<C, S>(client: C, server: S, up: &[u8], down: &[u8])
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let (mut server_rd, mut server_wr) = tokio::io::split(server);
    let run = async {
        tokio::join!(
            async {
                client_wr.write_all(up).await.unwrap();
                client_wr.shutdown().await.unwrap();
            },
            async {
                server_wr.write_all(down).await.unwrap();
                server_wr.shutdown().await.unwrap();
            },
            async {
                let mut got = Vec::new();
                server_rd.read_to_end(&mut got).await.unwrap();
                got
            },
            async {
                let mut got = Vec::new();
                client_rd.read_to_end(&mut got).await.unwrap();
                got
            },
        )
    };
    let ((), (), server_got, client_got) = timeout(LIMIT, run).await.expect("timed out");
    assert!(server_got == up, "server received corrupt data");
    assert!(client_got == down, "client received corrupt data");
}

#[tokio::test]
async fn a_browntls_client_authenticates_and_resumes() {
    let pki = Pki::new();
    let acceptor = TlsAcceptor::from(Arc::new(grease_server(&pki)));
    let connector = TlsConnector::from(Arc::new(pki.client_config_with_cert(&version::TLS13)));

    for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
        })
        .await
        .expect("handshake timed out");
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.get_ref().1.handshake_kind(), Some(expected));
        assert_eq!(server.get_ref().1.handshake_kind(), Some(expected));
        let certs = server.get_ref().1.peer_certificates().unwrap();
        assert_eq!(certs[0], pki.client_chain[0], "{expected:?}");
        exchange(client, server, &pattern(64 * 1024), &pattern(32 * 1024)).await;
    }
}

fn rustls_client_with_cert(pki: &Pki) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rpki::CertificateDer::from(pki.ca.as_ref().to_vec()))
        .unwrap();
    let chain = pki
        .client_chain
        .iter()
        .map(|c| rpki::CertificateDer::from(c.as_ref().to_vec()))
        .collect();
    let key = rpki::PrivateKeyDer::Pkcs8(rpki::PrivatePkcs8KeyDer::from(pki.client_key.clone()));
    let config =
        rustls::ClientConfig::builder_with_provider(Arc::new(ring_provider::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn a_tokio_rustls_client_authenticates_and_resumes() {
    let pki = Pki::new();
    let acceptor = TlsAcceptor::from(Arc::new(grease_server(&pki)));
    let connector = rustls_client_with_cert(&pki);

    for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
        let (c, s) = tcp_pair().await;
        let name = rpki::ServerName::try_from("localhost").unwrap();
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(name, c), acceptor.accept(s))
        })
        .await
        .expect("handshake timed out");
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(server.get_ref().1.handshake_kind(), Some(expected));
        let rustls_kind = client.get_ref().1.handshake_kind();
        let rustls_expected = match expected {
            HandshakeKind::Resumed => rustls::HandshakeKind::Resumed,
            _ => rustls::HandshakeKind::Full,
        };
        assert_eq!(rustls_kind, Some(rustls_expected));
        let certs = server.get_ref().1.peer_certificates().unwrap();
        assert_eq!(certs[0], pki.client_chain[0], "{expected:?}");
        exchange(client, server, &pattern(32 * 1024), &pattern(64 * 1024)).await;
    }
}

#[tokio::test]
async fn post_handshake_client_authentication_with_grease() {
    let pki = Pki::new();
    let mut client_config = pki.client_config_with_cert(&version::TLS13);
    client_config.enable_post_handshake_auth = true;
    let mut server_config = grease_server(&pki);
    server_config.request_client_auth_after_handshake = true;

    let (c, s) = duplex(64 * 1024);
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), c),
        TlsAcceptor::from(Arc::new(server_config)).accept(s),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert!(server.get_ref().1.peer_certificates().is_none());

    let client_side = async {
        client.write_all(b"request\n").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0; 6];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply\n");
        assert_eq!(client.get_ref().1.post_handshake_auth_responses(), 1);
    };
    let server_side = async {
        let mut request = [0; 8];
        server.read_exact(&mut request).await.unwrap();
        // The CertificateRequest carries GREASE values.
        server.get_mut().1.request_client_auth().unwrap();
        server.flush().await.unwrap();
        while server.get_ref().1.post_handshake_auth_status()
            != Some(PostHandshakeAuthStatus::Authenticated)
        {
            let _ = timeout(Duration::from_millis(20), server.read(&mut [0; 1])).await;
        }
        let certs = server.get_ref().1.peer_certificates().unwrap();
        assert_eq!(certs[0], pki.client_chain[0]);
        server.write_all(b"reply\n").await.unwrap();
        server.flush().await.unwrap();
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("the client never answered the GREASE CertificateRequest");
}

#[tokio::test]
async fn an_unbuffered_server_with_grease_authenticates_a_client() {
    let pki = Pki::new();
    let acceptor = browntls_tokio::unbuffered::TlsAcceptor::from(Arc::new(grease_server(&pki)));
    let connector = TlsConnector::from(Arc::new(pki.client_config_with_cert(&version::TLS13)));

    for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
        })
        .await
        .expect("handshake timed out");
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.get_ref().1.handshake_kind(), Some(expected));
        let certs = server.get_ref().1.peer_certificates().unwrap();
        assert_eq!(certs[0], pki.client_chain[0], "{expected:?}");
        exchange(client, server, &pattern(64 * 1024), &pattern(64 * 1024)).await;
    }
}
