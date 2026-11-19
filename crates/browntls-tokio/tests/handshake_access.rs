//! The connection is reachable through the handshake futures while the
//! handshake runs, for callers that poll them by hand.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use browntls_core::server::Acceptor;
use browntls_tokio::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

/// Polls `future` once.
async fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(Pin::new(&mut *future).poll(cx))).await
}

#[tokio::test]
async fn the_connection_is_visible_while_the_handshake_runs() {
    let pki = Pki::new();
    for version in versions() {
        let mut server_config = pki.server_config(version);
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let (c, s) = duplex(64 * 1024);
        let mut connect = pki
            .connector(version)
            .with_alpn(vec![b"h2".to_vec()])
            .connect(localhost(), c);
        let mut accept = acceptor.accept(s);

        // Nothing was polled yet: both connections exist and know nothing.
        let client = connect.connection().expect("client connection");
        assert!(client.is_handshaking());
        assert_eq!(client.alpn_protocol(), None);
        let server = accept.connection().expect("server connection");
        assert!(server.is_handshaking());
        assert_eq!(server.server_name(), None);
        assert_eq!(server.negotiated_cipher_suite(), None);

        // The ClientHello goes out; the server reads it and answers.
        assert!(poll_once(&mut connect).await.is_pending());
        assert!(poll_once(&mut accept).await.is_pending());

        // The server has not seen the client's Finished, yet it knows what
        // the ClientHello asked for and what it chose.
        let server = accept.connection().expect("server connection");
        assert!(server.is_handshaking());
        assert_eq!(server.server_name(), Some("localhost"));
        assert_eq!(server.alpn_protocol(), Some(&b"h2"[..]));
        assert!(server.negotiated_cipher_suite().is_some());
        assert_eq!(
            server.protocol_version().map(u16::from),
            Some(u16::from(version.version))
        );

        // `&mut` access works while the handshake runs.
        accept
            .connection_mut()
            .expect("server connection")
            .set_buffer_limit(Some(12345));
        connect
            .connection_mut()
            .expect("client connection")
            .set_buffer_limit(Some(23456));

        let (client, server) = tokio::join!(&mut connect, &mut accept);
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        // The futures returned: they hold neither transport nor connection.
        assert!(connect.connection().is_none() && connect.connection_mut().is_none());
        assert!(accept.connection().is_none() && accept.connection_mut().is_none());
        assert!(connect.get_ref().is_none() && accept.get_ref().is_none());

        // The streams carry on with the connections the futures showed.
        assert_eq!(server.get_ref().1.server_name(), Some("localhost"));
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut ping = [0; 4];
        server.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"ping");
    }
}

#[tokio::test]
async fn fallible_futures_show_the_transport_and_the_connection() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
    let (c, s) = duplex(64 * 1024);
    let mut connect = pki
        .connector(version)
        .connect(localhost(), c)
        .into_fallible();
    let mut accept = pki.acceptor(version).accept(s).into_fallible();

    assert!(connect.get_ref().is_some() && connect.get_mut().is_some());
    assert!(accept.get_ref().is_some() && accept.get_mut().is_some());
    assert!(connect.connection().unwrap().is_handshaking());
    assert!(accept.connection().unwrap().is_handshaking());

    assert!(poll_once(&mut connect).await.is_pending());
    assert!(poll_once(&mut accept).await.is_pending());
    assert_eq!(
        accept.connection().unwrap().server_name(),
        Some("localhost")
    );
    assert!(accept.connection_mut().unwrap().is_handshaking());
    assert!(connect.connection_mut().unwrap().is_handshaking());

    let (client, server) = tokio::join!(&mut connect, &mut accept);
    assert!(client.is_ok() && server.is_ok());
    assert!(connect.get_ref().is_none() && connect.get_mut().is_none());
    assert!(accept.get_ref().is_none() && accept.get_mut().is_none());
    assert!(connect.connection().is_none() && connect.connection_mut().is_none());
    assert!(accept.connection().is_none() && accept.connection_mut().is_none());
}

#[tokio::test]
async fn a_future_without_a_connection_shows_only_the_transport() {
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;

    // A fragment size the connection refuses: none is created.
    let mut client_config = pki.client_config(version);
    client_config.max_fragment_size = Some(1);
    let mut server_config = pki.server_config(version);
    server_config.max_fragment_size = Some(1);
    let (c, s) = duplex(1024);
    let mut connect = TlsConnector::from(Arc::new(client_config)).connect(localhost(), c);
    let mut accept = TlsAcceptor::from(Arc::new(server_config)).accept(s);
    assert!(connect.get_ref().is_some() && connect.get_mut().is_some());
    assert!(accept.get_ref().is_some() && accept.get_mut().is_some());
    assert!(connect.connection().is_none() && connect.connection_mut().is_none());
    assert!(accept.connection().is_none() && accept.connection_mut().is_none());
    assert!((&mut connect).await.is_err());
    assert!((&mut accept).await.is_err());
    assert!(connect.get_ref().is_none() && accept.get_ref().is_none());

    let (c, s) = duplex(1024);
    let mut config = pki.client_config(version);
    config.max_fragment_size = Some(1);
    let mut connect = TlsConnector::from(Arc::new(config))
        .connect(localhost(), c)
        .into_fallible();
    let mut config = pki.server_config(version);
    config.max_fragment_size = Some(1);
    let mut accept = TlsAcceptor::from(Arc::new(config))
        .accept(s)
        .into_fallible();
    assert!(connect.get_ref().is_some() && connect.connection().is_none());
    assert!(accept.get_ref().is_some() && accept.connection().is_none());
    assert!(connect.connection_mut().is_none() && accept.connection_mut().is_none());
    assert!((&mut connect).await.is_err());
    assert!((&mut accept).await.is_err());
}

#[cfg(feature = "tls12")]
#[tokio::test]
async fn a_refused_client_hello_leaves_no_connection_to_show() {
    let pki = Pki::new();
    let (c, s) = duplex(64 * 1024);
    let mut connect = pki
        .connector(&browntls_core::version::TLS13)
        .connect(localhost(), c);
    assert!(poll_once(&mut connect).await.is_pending());

    // A TLS 1.2-only configuration cannot serve a TLS 1.3-only client: the
    // future only has an alert to send.
    let start = LazyConfigAcceptor::new(Acceptor::default(), s)
        .await
        .unwrap();
    let config = Arc::new(pki.server_config(&browntls_core::version::TLS12));
    let mut accept = start.into_stream(config);
    assert!(accept.get_ref().is_some() && accept.get_mut().is_some());
    assert!(accept.connection().is_none() && accept.connection_mut().is_none());
    assert!((&mut accept).await.is_err());
    assert!(connect.await.is_err());
}
