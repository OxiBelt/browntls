//! `into_kernel_handoff` of a server stream that asked for a client
//! certificate after the handshake and checks client certificates for
//! revocation: the handoff waits for the client's answer (the kernel cannot
//! check it), taking the application data that comes before it.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::ServerConfig;
use browntls_core::kernel::KernelHandoffBlocker;
use browntls_core::revocation::{RevocationDigests, RevocationPolicy};
use browntls_core::server::{PostHandshakeAuthStatus, WebPkiClientVerifier};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(10);

/// Asks for client certificates after the handshake only, and checks them
/// for revocation (best effort: the test has no evidence to give).
fn server_config(pki: &Pki) -> ServerConfig {
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(pki.roots()), provider())
        .with_revocation_policy(RevocationPolicy::new(RevocationDigests::native()).best_effort())
        .allow_unauthenticated()
        .build()
        .unwrap();
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&browntls_core::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(pki.server_chain.clone(), pki.server_key())
        .unwrap();
    config.request_client_auth_after_handshake = true;
    config.enable_secret_extraction = true;
    config
}

type Client = browntls_tokio::client::TlsStream<DuplexStream>;
type Server = browntls_tokio::server::TlsStream<DuplexStream>;

/// A connected pair whose server has queued a post-handshake
/// CertificateRequest.
async fn requested(pki: &Pki) -> (Client, Server) {
    let mut client_config = pki.client_config_with_cert(&browntls_core::version::TLS13);
    client_config.enable_post_handshake_auth = true;
    let (c, s) = tokio::io::duplex(64 * 1024);
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), c),
        TlsAcceptor::from(Arc::new(server_config(pki))).accept(s),
    );
    let (client, mut server) = (client.unwrap(), server.unwrap());
    server.get_mut().1.request_client_auth().unwrap();
    (client, server)
}

/// Reads until the client has answered the CertificateRequest.
async fn answer(client: &mut Client) {
    while client.get_ref().1.post_handshake_auth_responses() == 0 {
        let _ = timeout(Duration::from_millis(20), client.read(&mut [0; 1])).await;
    }
}

#[tokio::test]
async fn the_handoff_waits_for_the_answer_to_a_post_handshake_certificate_request() {
    let pki = Pki::new();
    let (mut client, server) = requested(&pki).await;
    assert_eq!(
        server.get_ref().1.kernel_handoff_blocker(),
        Some(KernelHandoffBlocker::RevocationPending),
    );

    // The client writes before it reads the request, so its data comes
    // ahead of its answer; reading then answers the request.
    let client_side = async {
        client.write_all(b"before the answer").await.unwrap();
        client.flush().await.unwrap();
        answer(&mut client).await;
        client
    };
    let (client, handoff) = timeout(LIMIT, async {
        tokio::join!(client_side, server.into_kernel_handoff())
    })
    .await
    .expect("the handoff never completed");
    let handoff = handoff.unwrap();
    let conn = handoff.get_ref().1;
    assert_eq!(
        conn.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated),
    );
    assert!(conn.peer_certificates().is_some());
    assert_eq!(conn.kernel_handoff_blocker(), None);

    let (_io, conn, received) = handoff.into_parts();
    assert_eq!(received, b"before the answer");
    conn.dangerous_into_kernel_connection().unwrap();
    drop(client);
}

/// A client may send data for as long as it likes before it answers: past
/// what the handoff holds, it fails and the stream comes back usable.
#[tokio::test]
async fn data_without_end_before_the_answer_fails_the_handoff() {
    let pki = Pki::new();
    let (mut client, server) = requested(&pki).await;
    let sent = pattern(200 * 1024);
    // Spawned: it finishes only once the server reads the rest.
    let writer = tokio::spawn({
        let sent = sent.clone();
        async move {
            client.write_all(&sent).await.unwrap();
            client.flush().await.unwrap();
            client
        }
    });
    let err = timeout(LIMIT, server.into_kernel_handoff())
        .await
        .expect("the handoff never ended")
        .unwrap_err();
    assert_eq!(
        err.error.kind(),
        std::io::ErrorKind::Unsupported,
        "{:?}",
        err.error
    );
    let taken = err.received.len();
    assert!((64 * 1024..sent.len()).contains(&taken), "{taken}");
    assert_eq!(err.received, sent[..taken]);

    // The stream goes on in userspace with the rest, in order.
    let mut server = err.stream;
    let mut rest = vec![0; sent.len() - taken];
    timeout(LIMIT, server.read_exact(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rest, sent[taken..]);
    drop(timeout(LIMIT, writer).await.unwrap().unwrap());
}

#[tokio::test]
async fn a_client_that_closes_before_answering_fails_the_handoff() {
    let pki = Pki::new();
    let (client, server) = requested(&pki).await;
    drop(client);
    let err = timeout(LIMIT, server.into_kernel_handoff())
        .await
        .expect("the handoff never ended")
        .unwrap_err();
    assert_ne!(
        err.error.kind(),
        std::io::ErrorKind::Unsupported,
        "{:?}",
        err.error
    );
}

#[tokio::test]
async fn a_server_that_shut_down_does_not_wait_for_the_answer() {
    let pki = Pki::new();
    let (_client, mut server) = requested(&pki).await;
    server.shutdown().await.unwrap();
    let err = timeout(LIMIT, server.into_kernel_handoff())
        .await
        .expect("the handoff waited for an answer after close_notify")
        .unwrap_err();
    assert_eq!(
        err.error.kind(),
        std::io::ErrorKind::Unsupported,
        "{:?}",
        err.error
    );
}
