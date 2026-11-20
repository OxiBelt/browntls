//! `unbuffered::LazyConfigAcceptor`: choosing the server configuration from
//! the ClientHello over the unbuffered acceptor, keeping what the transport
//! delivered behind it, and refusing what is not a ClientHello.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::server::{ServerSessionMemoryCache, UnbufferedAcceptor};
use browntls_core::{AlertDescription, Error, HandshakeKind};
use browntls_tokio::unbuffered::{LazyConfigAcceptor, StartHandshake, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn the_configuration_follows_the_client_hello() {
    let pki = Pki::new();
    for version in versions() {
        let mut h2 = pki.server_config(version);
        h2.alpn_protocols = vec![b"h2".to_vec()];
        let mut http11 = pki.server_config(version);
        http11.alpn_protocols = vec![b"http/1.1".to_vec()];
        let (h2, http11) = (Arc::new(h2), Arc::new(http11));

        for offer in [&b"h2"[..], b"http/1.1"] {
            let (c, s) = duplex(64 * 1024);
            let connector = TlsConnector::from(Arc::new(pki.client_config(version)));
            let server = async {
                let lazy = LazyConfigAcceptor::new(UnbufferedAcceptor::new(), s);
                assert!(format!("{lazy:?}").contains("has_io: true"));
                let start = lazy.await?;
                let hello = start.client_hello();
                assert_eq!(hello.server_name(), Some("localhost"));
                let wants_h2 = hello.alpn().is_some_and(|mut p| p.any(|p| p == b"h2"));
                let config = if wants_h2 { h2.clone() } else { http11.clone() };
                start.into_stream(config).await
            };
            let (client, server) = timeout(LIMIT, async {
                tokio::join!(
                    connector
                        .with_alpn(vec![offer.to_vec()])
                        .connect(localhost(), c),
                    server
                )
            })
            .await
            .unwrap();
            let (mut client, mut server) = (client.unwrap(), server.unwrap());
            assert_eq!(server.get_ref().1.alpn_protocol(), Some(offer));
            assert_eq!(client.get_ref().1.alpn_protocol(), Some(offer));
            assert_eq!(server.get_ref().1.server_name(), Some("localhost"));

            client.write_all(b"lazy").await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"lazy", "{version:?}");
        }
    }
}

#[tokio::test]
async fn a_plaintext_request_is_refused_with_an_alert_and_the_transport_kept() {
    let (mut c, s) = duplex(64 * 1024);
    c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut lazy = LazyConfigAcceptor::new(UnbufferedAcceptor::new(), s);
    let err = timeout(LIMIT, &mut lazy).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(tls_error(&err).is_some(), "{err:?}");

    // The client got a fatal alert record...
    let mut header = [0; 5];
    c.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 0x15, "an alert record");

    // ...and the server can still answer in plain text.
    // Polling again reports the failure, not a confusing acceptor error.
    let again = (&mut lazy).await.unwrap_err();
    assert!(again.to_string().contains("after it failed"), "{again}");
    let mut transport = lazy.take_io().expect("transport");
    transport
        .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        .await
        .unwrap();
    assert!(lazy.take_io().is_none());
    let err = (&mut lazy).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(err.to_string().contains("take_io"), "{err}");
}

#[tokio::test]
async fn eof_before_a_client_hello() {
    let (mut c, s) = duplex(1024);
    c.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
    c.shutdown().await.unwrap();
    let lazy = LazyConfigAcceptor::new(UnbufferedAcceptor::new(), s);
    let err = timeout(LIMIT, lazy).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn a_client_hello_split_into_single_bytes_is_assembled() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(64 * 1024);
        let connector = TlsConnector::from(Arc::new(pki.client_config(version)));
        let config = Arc::new(pki.server_config(version));
        let server = async {
            let start =
                LazyConfigAcceptor::new(UnbufferedAcceptor::new(), Choppy::new(s, 1)).await?;
            let (accepted, io, incoming_tls) = start.into_parts();
            // Nothing follows the ClientHello yet.
            assert!(incoming_tls.is_empty());
            StartHandshake::from_parts(accepted, io, incoming_tls)
                .into_stream_with(config, |conn| conn.set_resumption_data(b"lazy"))
                .await
        };
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), Choppy::new(c, 1)), server)
        })
        .await
        .unwrap();
        client.unwrap();
        server.unwrap();
    }
}

#[tokio::test]
async fn bytes_behind_the_client_hello_go_to_the_connection() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let cache = ServerSessionMemoryCache::new(8);
    let mut server_config = pki.server_config(version);
    server_config.max_early_data_size = 1024;
    server_config.session_storage = cache;
    let server_config = Arc::new(server_config);
    let mut client_config = pki.client_config(version);
    client_config.enable_early_data = true;
    // The buffered connector sends 0-RTT data right behind its ClientHello.
    let connector = browntls_tokio::TlsConnector::from(Arc::new(client_config)).early_data(true);

    for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
        let (c, s) = duplex(64 * 1024);
        let client_side = async {
            let mut client = connector.connect(localhost(), c).await.unwrap();
            client.write_all(b"right behind the hello").await.unwrap();
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(client.get_ref().1.handshake_kind(), Some(expected));
            client.shutdown().await.unwrap();
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
            client
        };
        let server_side = async {
            let start = LazyConfigAcceptor::new(UnbufferedAcceptor::new(), s)
                .await
                .unwrap();
            let (accepted, io, incoming_tls) = start.into_parts();
            let resumed = expected == HandshakeKind::Resumed;
            // The early data record arrived with the ClientHello and was
            // left for the connection.
            assert_eq!(!incoming_tls.is_empty(), resumed);
            let mut server = StartHandshake::from_parts(accepted, io, incoming_tls)
                .into_stream(server_config.clone())
                .await
                .unwrap();
            let mut got = server.take_early_data();
            server.write_all(b"reply").await.unwrap();
            server.shutdown().await.unwrap();
            server.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"right behind the hello");
        };
        let (client, ()) = timeout(LIMIT, async { tokio::join!(client_side, server_side) })
            .await
            .expect("timed out");
        assert_eq!(
            client.get_ref().1.is_early_data_accepted(),
            expected == HandshakeKind::Resumed
        );
    }
}

#[cfg(feature = "tls12")]
#[tokio::test]
async fn a_configuration_that_cannot_serve_the_hello_sends_an_alert() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let connector = TlsConnector::from(Arc::new(pki.client_config(&browntls_core::version::TLS13)));
    // A TLS 1.2-only configuration cannot serve a TLS 1.3-only client.
    let config = Arc::new(pki.server_config(&browntls_core::version::TLS12));
    let server = async {
        let start = LazyConfigAcceptor::new(UnbufferedAcceptor::new(), s).await?;
        let mut accept = start.into_stream(config);
        assert!(accept.get_ref().is_some() && accept.get_mut().is_some());
        accept.into_fallible().await.map_err(|(err, _io)| err)
    };
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), server)
    })
    .await
    .unwrap();

    let err = server.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let err = client.unwrap_err();
    assert!(
        matches!(
            tls_error(&err),
            Some(Error::AlertReceived(AlertDescription::ProtocolVersion))
        ),
        "{err:?}"
    );
}
