//! RFC 7924 `cached_info` through the connectors and acceptors of both
//! stream families: two connections share one client store, and the second
//! gets the server's Certificate and CertificateRequest as fingerprints.

#![cfg(all(any(feature = "native", feature = "rustcrypto"), feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use browntls_core::cached_info::{
    CachedInformationType, ClientCachedInfoMemoryCache, ClientCachedInfoStore,
    ServerCachedInfoPolicy,
};
use browntls_core::client::Resumption;
use browntls_core::version::TLS12;
use browntls_core::{ClientConfig, CommonState, ServerConfig};
use common::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};

const TYPES: [CachedInformationType; 2] =
    [CachedInformationType::Cert, CachedInformationType::CertReq];

/// TLS 1.2 with client authentication and both types on; the client never
/// resumes, so every handshake sends (or replaces) the Certificate.
fn configs(
    pki: &Pki,
) -> (
    Arc<ClientCachedInfoMemoryCache>,
    Arc<ClientConfig>,
    Arc<ServerConfig>,
) {
    let store = Arc::new(ClientCachedInfoMemoryCache::new(4, 2));
    let mut client = pki.client_config_with_cert(&TLS12);
    client.resumption = Resumption::disabled();
    client.cached_info = Some(store.clone());
    let mut server = pki.server_config_with_client_auth(&TLS12);
    let mut policy = ServerCachedInfoPolicy::default();
    (policy.cert, policy.cert_req) = (true, true);
    server.cached_info = policy;
    (store, Arc::new(client), Arc::new(server))
}

/// Checks connection `round` (0 or 1) once both handshakes completed.
fn check(
    pki: &Pki,
    store: &ClientCachedInfoMemoryCache,
    round: usize,
    c: &CommonState,
    s: &CommonState,
) {
    let replaced = c.cached_info_replaced();
    for typ in TYPES {
        assert_eq!(replaced.contains(typ), round == 1, "round {round}");
        // The first connection filled the store, once per type.
        assert_eq!(store.lookup(&localhost(), typ).len(), 1);
    }
    assert_eq!(s.cached_info_replaced(), replaced);
    assert_eq!(c.peer_certificates().unwrap(), pki.server_chain);
    assert_eq!(s.peer_certificates().unwrap(), pki.client_chain);
}

async fn ping<C, S>(client: &mut C, server: &mut S)
where
    C: AsyncWrite + Unpin,
    S: AsyncRead + Unpin,
{
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn buffered_streams_restore_certificate_and_request() {
    use browntls_tokio::{TlsAcceptor, TlsConnector};

    let pki = Pki::new();
    let (store, client, server) = configs(&pki);
    let (connector, acceptor) = (TlsConnector::from(client), TlsAcceptor::from(server));
    for round in 0..2 {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(connector.connect(localhost(), c), acceptor.accept(s));
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        check(&pki, &store, round, client.get_ref().1, server.get_ref().1);
        ping(&mut client, &mut server).await;
    }
}

#[tokio::test]
async fn unbuffered_streams_restore_certificate_and_request() {
    use browntls_tokio::unbuffered::{TlsAcceptor, TlsConnector};

    let pki = Pki::new();
    let (store, client, server) = configs(&pki);
    let (connector, acceptor) = (TlsConnector::from(client), TlsAcceptor::from(server));
    for round in 0..2 {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = tokio::join!(connector.connect(localhost(), c), acceptor.accept(s));
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        check(&pki, &store, round, client.get_ref().1, server.get_ref().1);
        ping(&mut client, &mut server).await;
    }
}
