//! Messages beyond application data through the asynchronous streams:
//! client authentication during and after the handshake, HelloRetryRequest,
//! and a small send buffer.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use browntls::server::PostHandshakeAuthStatus;
use browntls::{HandshakeKind, NamedGroup};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

/// A client that sends a request and then only reads, over `client_io`,
/// against a server that asks for a certificate after the handshake and
/// answers only once it has one.
async fn post_handshake_authentication_with_a_reading_client<IO>(client_io: IO, s: DuplexStream)
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let mut client_config = pki.client_config_with_cert(version);
    client_config.enable_post_handshake_auth = true;
    let mut server_config = pki.server_config_with_client_auth(version);
    server_config.request_client_auth_after_handshake = true;

    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), client_io),
        TlsAcceptor::from(Arc::new(server_config)).accept(s),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert!(server.get_ref().1.peer_certificates().is_none());

    // The client sends its request and then only reads; the server asks for
    // a certificate and answers only once it has one.
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
        server.get_mut().1.request_client_auth().unwrap();
        server.flush().await.unwrap();
        // Reading processes the answer, which carries no plaintext.
        while server.get_ref().1.post_handshake_auth_status()
            != Some(PostHandshakeAuthStatus::Authenticated)
        {
            let _ = timeout(Duration::from_millis(20), server.read(&mut [0; 1])).await;
        }
        assert!(server.get_ref().1.peer_certificates().is_some());
        server.write_all(b"reply\n").await.unwrap();
        server.flush().await.unwrap();
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("the client never answered the CertificateRequest");
}

#[tokio::test]
async fn a_client_that_only_reads_answers_post_handshake_authentication() {
    let (c, s) = duplex(64 * 1024);
    post_handshake_authentication_with_a_reading_client(c, s).await;
}

#[tokio::test]
async fn a_reading_client_finishes_an_answer_the_transport_took_in_part() {
    // The answer (a certificate chain) leaves seven bytes per write, with a
    // `Pending` between writes: later reads must write the rest.
    let (c, s) = duplex(64 * 1024);
    post_handshake_authentication_with_a_reading_client(Choppy::new(c, 7), s).await;
}

#[tokio::test]
async fn client_authentication_during_the_handshake() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(
            TlsConnector::from(Arc::new(pki.client_config_with_cert(version)))
                .connect(localhost(), c),
            TlsAcceptor::from(Arc::new(pki.server_config_with_client_auth(version))).accept(s),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        let certs = server.get_ref().1.peer_certificates().unwrap();
        assert_eq!(certs[0], pki.client_chain[0], "{version:?}");

        client.write_all(b"authenticated").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"authenticated");
    }
}

#[tokio::test]
async fn a_hello_retry_request_over_a_choppy_transport() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let mut provider = (*provider()).clone();
    provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::secp256r1);
    assert!(!provider.kx_groups.is_empty());
    let server_config = browntls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.server_chain.clone(), pki.server_key())
        .unwrap();

    let (c, s) = duplex(4096);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            pki.connector(version)
                .connect(localhost(), Choppy::new(c, 5)),
            TlsAcceptor::from(Arc::new(server_config)).accept(Choppy::new(s, 3)),
        )
    })
    .await
    .unwrap();
    let (client, server) = (client.unwrap(), server.unwrap());
    assert_eq!(
        client.get_ref().1.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        NamedGroup::secp256r1
    );
}

#[tokio::test]
async fn a_small_send_buffer_still_moves_everything() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(8192);
        let connector = pki.connector(version);
        let acceptor = pki.acceptor(version);
        let (client, server) = tokio::join!(
            connector.connect_with(localhost(), Choppy::new(c, 64), |conn| {
                conn.set_buffer_limit(Some(512))
            }),
            acceptor.accept(s),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        let data = pattern(200 * 1024);
        let run = async {
            tokio::join!(
                async {
                    client.write_all(&data).await.unwrap();
                    client.shutdown().await.unwrap();
                },
                async {
                    let mut got = Vec::new();
                    server.read_to_end(&mut got).await.unwrap();
                    got
                },
            )
        };
        let ((), got) = timeout(LIMIT, run).await.expect("timed out");
        assert!(got == data, "{version:?}: corrupt data");
    }
}

#[tokio::test]
async fn a_task_polling_both_directions_does_not_spin_while_answering() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let mut client_config = pki.client_config_with_cert(version);
    client_config.enable_post_handshake_auth = true;
    let mut server_config = pki.server_config_with_client_auth(version);
    server_config.request_client_auth_after_handshake = true;
    // A small transport: the certificate answer only goes out in part.
    let (c, s) = duplex(300);
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), c),
        TlsAcceptor::from(Arc::new(server_config)).accept(s),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    server.get_mut().1.request_client_auth().unwrap();
    let mut buf = [0u8; 16];
    let (flushed, _) = tokio::join!(
        server.flush(),
        timeout(Duration::from_millis(100), client.read(&mut buf))
    );
    flushed.unwrap();

    // Park a write, then poll writes and reads from one task while the
    // server reads nothing.
    let big = vec![0u8; 256 * 1024];
    poll_fn(|cx| match Pin::new(&mut client).poll_write(cx, &big) {
        Poll::Pending => Poll::Ready(()),
        _ => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
    let polls = AtomicUsize::new(0);
    let both = poll_fn(|cx| {
        polls.fetch_add(1, Ordering::Relaxed);
        let _ = Pin::new(&mut client).poll_write(cx, &big);
        let _ = Pin::new(&mut client).poll_read(cx, &mut ReadBuf::new(&mut buf));
        Poll::<()>::Pending
    });
    let _ = timeout(Duration::from_millis(300), both).await;
    let polls = polls.load(Ordering::Relaxed);
    assert!(polls < 100, "the task spun: {polls} polls in 300 ms");
    drop(server);
}
