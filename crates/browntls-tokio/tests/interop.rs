//! Interoperability with tokio-rustls (rustls 0.23, ring provider) in both
//! directions, over TCP: handshakes, bulk data, and `close_notify`.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use rustls::crypto::ring as ring_provider;
use rustls_pki_types as rpki;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

fn rustls_versions(
    version: &'static browntls_core::SupportedProtocolVersion,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    static TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
    static TLS12: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
    match version.version {
        browntls_core::ProtocolVersion::TLSv1_3 => &TLS13,
        _ => &TLS12,
    }
}

fn rustls_server(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
) -> tokio_rustls::TlsAcceptor {
    let chain = pki
        .server_chain
        .iter()
        .map(|c| rpki::CertificateDer::from(c.as_ref().to_vec()))
        .collect();
    let key = rpki::PrivateKeyDer::Pkcs8(rpki::PrivatePkcs8KeyDer::from(pki.server_key.clone()));
    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(ring_provider::default_provider()))
            .with_protocol_versions(rustls_versions(version))
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn rustls_client(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rpki::CertificateDer::from(pki.ca.as_ref().to_vec()))
        .unwrap();
    let config =
        rustls::ClientConfig::builder_with_provider(Arc::new(ring_provider::default_provider()))
            .with_protocol_versions(rustls_versions(version))
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.unwrap(), server.unwrap().0)
}

/// Sends `up` from the client and `down` from the server at the same time,
/// each side closing with `close_notify`, and checks what arrived.
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
async fn browntls_tokio_client_to_tokio_rustls_server() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = tcp_pair().await;
        let (client, server) = tokio::join!(
            pki.connector(version).connect(localhost(), c),
            rustls_server(&pki, version).accept(s),
        );
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.get_ref().1.protocol_version(), Some(version.version));
        exchange(client, server, &pattern(256 * 1024), &pattern(100 * 1024)).await;
    }
}

#[tokio::test]
async fn tokio_rustls_client_to_browntls_tokio_server() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = tcp_pair().await;
        let name = rpki::ServerName::try_from("localhost").unwrap();
        let (client, server) = tokio::join!(
            rustls_client(&pki, version).connect(name, c),
            pki.acceptor(version).accept(s),
        );
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(server.get_ref().1.protocol_version(), Some(version.version));
        exchange(client, server, &pattern(100 * 1024), &pattern(256 * 1024)).await;
    }
}

#[tokio::test]
async fn tokio_rustls_sees_a_truncation_when_browntls_drops_the_transport() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let (c, s) = tcp_pair().await;
    let name = rpki::ServerName::try_from("localhost").unwrap();
    let (client, server) = tokio::join!(
        rustls_client(&pki, version).connect(name, c),
        pki.acceptor(version).accept(s),
    );
    let mut client = client.unwrap();
    drop(server.unwrap());
    let err = client.read(&mut [0; 8]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}
