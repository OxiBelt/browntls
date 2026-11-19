//! `LazyConfigAcceptor`: choosing the server configuration from the
//! ClientHello, and refusing what is not a ClientHello.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::server::Acceptor;
use browntls_core::{AlertDescription, Error};
use browntls_tokio::{LazyConfigAcceptor, StartHandshake};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn the_configuration_follows_the_client_hello() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let mut h2 = pki.server_config(version);
    h2.alpn_protocols = vec![b"h2".to_vec()];
    let mut http11 = pki.server_config(version);
    http11.alpn_protocols = vec![b"http/1.1".to_vec()];
    let (h2, http11) = (Arc::new(h2), Arc::new(http11));

    for offer in [&b"h2"[..], b"http/1.1"] {
        let (c, s) = duplex(64 * 1024);
        let connector = pki.connector(version);
        let server = async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), s).await?;
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

        client.write_all(b"lazy").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"lazy");
    }
}

#[tokio::test]
async fn a_plaintext_request_is_refused_with_an_alert_and_the_transport_kept() {
    let (mut c, s) = duplex(64 * 1024);
    c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut lazy = LazyConfigAcceptor::new(Acceptor::default(), s);
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
    let err = timeout(LIMIT, LazyConfigAcceptor::new(Acceptor::default(), s))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn a_client_hello_split_into_single_bytes_is_assembled() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let (c, s) = duplex(64 * 1024);
    let connector = pki.connector(version);
    let config = Arc::new(pki.server_config(version));
    let server = async {
        let start = LazyConfigAcceptor::new(Acceptor::default(), Choppy::new(s, 1)).await?;
        let (accepted, io) = start.into_inner();
        StartHandshake::from_parts(accepted, io)
            .into_stream_with(config, |conn| conn.set_buffer_limit(Some(32 * 1024)))
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

#[cfg(feature = "tls12")]
#[tokio::test]
async fn a_configuration_that_cannot_serve_the_hello_sends_an_alert() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let connector = pki.connector(&browntls_core::version::TLS13);
    // A TLS 1.2-only configuration cannot serve a TLS 1.3-only client.
    let config = Arc::new(pki.server_config(&browntls_core::version::TLS12));
    let server = async {
        let start = LazyConfigAcceptor::new(Acceptor::default(), s).await?;
        start
            .into_stream(config)
            .into_fallible()
            .await
            .map_err(|(err, _io)| err)
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
