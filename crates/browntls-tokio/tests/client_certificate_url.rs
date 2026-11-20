//! Client certificates named by URL (RFC 6066 §5): the server handshakes
//! of this crate answer the connection's query through the application's
//! fetcher. The fetches are simulated; nothing here opens a connection to
//! a URL.

#![cfg(all(any(feature = "native", feature = "rustcrypto"), feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use browntls_core::certificate_url::{
    CertificateUrl, CertificateUrlError, ClientCertificateUrlPolicy, ClientCertificateUrlQuery,
    UrlAndHash,
};
use browntls_core::server::{Acceptor, UnbufferedAcceptor};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::{AlertDescription, ClientConfig, Error, ServerConfig, version};
use browntls_tokio::certificate_url::FetchClientCertificateUrl;
use browntls_tokio::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);
const EE_URL: &str = "http://certs.example/client.der";

#[cfg(feature = "native")]
const SHA1: fn(&[u8]) -> [u8; 20] = browntls_core::crypto::native::sha1;
#[cfg(not(feature = "native"))]
const SHA1: fn(&[u8]) -> [u8; 20] = browntls_core::crypto::rustcrypto::sha1;

/// A client that holds no certificate and names its end-entity
/// certificate by URL, and a server that fetches certificates by URL.
fn configs(pki: &Pki) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let key = provider()
        .key_provider
        .load_private_key(pki.client_key())
        .unwrap();
    let mut key = CertifiedKey::new(Vec::new(), key);
    let entry = UrlAndHash::for_object(EE_URL, &pki.client_chain[0], SHA1).unwrap();
    key.set_certificate_url(Some(CertificateUrl::individual_certs(vec![entry]).unwrap()));
    let mut client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_root_certificates(pki.roots())
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    client.enable_client_certificate_url = true;
    let mut server = pki.server_config_with_client_auth(&version::TLS12);
    server.client_certificate_url = Some(ClientCertificateUrlPolicy::new(SHA1));
    (Arc::new(client), Arc::new(server))
}

/// A fetcher serving `object` for every URL after yielding to the
/// scheduler a few times, so that the handshake has to be woken; counts
/// its fetches.
fn fetcher(object: Vec<u8>, calls: Arc<AtomicUsize>) -> Arc<dyn FetchClientCertificateUrl> {
    Arc::new(move |query: ClientCertificateUrlQuery| {
        calls.fetch_add(1, Ordering::SeqCst);
        let object = object.clone();
        async move {
            for _ in 0..3 {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert_eq!(query.entries()[0].url(), EE_URL);
            Ok(vec![object; query.entries().len()])
        }
    })
}

#[tokio::test]
async fn the_acceptor_fetches_through_a_waking_fetcher() {
    let pki = Pki::new();
    let (client, server) = configs(&pki);
    let calls = Arc::new(AtomicUsize::new(0));
    let acceptor = TlsAcceptor::from(server)
        .client_certificate_url_fetcher(fetcher(pki.client_chain[0].to_vec(), calls.clone()));
    let (c, s) = duplex(64 * 1024);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            TlsConnector::from(client).connect(localhost(), c),
            acceptor.accept(s)
        )
    })
    .await
    .unwrap();
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        server.get_ref().1.peer_certificates().unwrap(),
        &pki.client_chain[..1]
    );
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut got = [0; 4];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
}

/// Runs a handshake whose server is `accept`; returns the errors of both
/// sides.
async fn failing(
    client: Arc<ClientConfig>,
    accept: impl FnOnce(tokio::io::DuplexStream) -> Pin<Box<dyn Future<Output = io::Result<()>>>>,
) -> (io::Error, io::Error) {
    let (c, s) = duplex(64 * 1024);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            async {
                let mut stream = TlsConnector::from(client).connect(localhost(), c).await?;
                // A TLS 1.2 client finishes before the server answers.
                let mut byte = [0; 1];
                stream.read_exact(&mut byte).await.map(|_| ())
            },
            accept(s)
        )
    })
    .await
    .unwrap();
    (client.unwrap_err(), server.unwrap_err())
}

fn assert_tls_errors(errors: (io::Error, io::Error), server: CertificateUrlError) {
    let (client_err, server_err) = errors;
    assert_eq!(tls_error(&server_err), Some(&Error::CertificateUrl(server)));
    assert_eq!(
        tls_error(&client_err),
        Some(&Error::AlertReceived(AlertDescription::from(server)))
    );
}

#[tokio::test]
async fn without_a_fetcher_the_chain_is_unobtainable() {
    let pki = Pki::new();
    let (client, server) = configs(&pki);
    let acceptor = TlsAcceptor::from(server);
    let errors = failing(client, move |s| {
        Box::pin(async move { acceptor.accept(s).await.map(|_| ()) })
    })
    .await;
    assert_tls_errors(errors, CertificateUrlError::Unobtainable);
}

#[tokio::test]
async fn a_fetcher_that_fails_makes_the_chain_unobtainable() {
    let pki = Pki::new();
    let (client, server) = configs(&pki);
    let refuse = Arc::new(|_: ClientCertificateUrlQuery| async {
        Err::<Vec<Vec<u8>>, _>(io::Error::from(io::ErrorKind::PermissionDenied))
    });
    let acceptor = TlsAcceptor::from(server).client_certificate_url_fetcher(refuse);
    let errors = failing(client, move |s| {
        Box::pin(async move { acceptor.accept(s).await.map(|_| ()) })
    })
    .await;
    assert_tls_errors(errors, CertificateUrlError::Unobtainable);
}

#[tokio::test]
async fn a_wrong_object_is_a_hash_mismatch() {
    let pki = Pki::new();
    let (client, server) = configs(&pki);
    let calls = Arc::new(AtomicUsize::new(0));
    let acceptor = TlsAcceptor::from(server)
        .client_certificate_url_fetcher(fetcher(pki.ca.to_vec(), calls.clone()));
    let errors = failing(client, move |s| {
        Box::pin(async move { acceptor.accept(s).await.map(|_| ()) })
    })
    .await;
    assert_tls_errors(errors, CertificateUrlError::HashMismatch);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_lazy_acceptor_passes_the_fetcher_on() {
    let pki = Pki::new();
    let (client, server) = configs(&pki);
    let calls = Arc::new(AtomicUsize::new(0));
    let (c, s) = duplex(64 * 1024);
    let fetch = fetcher(pki.client_chain[0].to_vec(), calls.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(TlsConnector::from(client).connect(localhost(), c), async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), s)
                .client_certificate_url_fetcher(fetch)
                .await?;
            start.into_stream(server).await
        })
    })
    .await
    .unwrap();
    client.unwrap();
    let server = server.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        server.get_ref().1.peer_certificates().unwrap(),
        &pki.client_chain[..1]
    );

    // Attached to the StartHandshake instead.
    let (client, server) = configs(&pki);
    let (c, s) = duplex(64 * 1024);
    let fetch = fetcher(pki.client_chain[0].to_vec(), calls.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(TlsConnector::from(client).connect(localhost(), c), async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), s).await?;
            start
                .client_certificate_url_fetcher(fetch)
                .into_stream(server)
                .await
        })
    })
    .await
    .unwrap();
    client.unwrap();
    server.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_unbuffered_acceptors_fetch() {
    let pki = Pki::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let (client, server) = configs(&pki);
    let acceptor = browntls_tokio::unbuffered::TlsAcceptor::from(server)
        .client_certificate_url_fetcher(fetcher(pki.client_chain[0].to_vec(), calls.clone()));
    let (c, s) = duplex(64 * 1024);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            TlsConnector::from(client).connect(localhost(), c),
            acceptor.accept(s)
        )
    })
    .await
    .unwrap();
    client.unwrap();
    let server = server.unwrap();
    assert_eq!(
        server.get_ref().1.peer_certificates().unwrap(),
        &pki.client_chain[..1]
    );

    let (client, server) = configs(&pki);
    let (c, s) = duplex(64 * 1024);
    let fetch = fetcher(pki.client_chain[0].to_vec(), calls.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(TlsConnector::from(client).connect(localhost(), c), async {
            let start =
                browntls_tokio::unbuffered::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), s)
                    .client_certificate_url_fetcher(fetch)
                    .await?;
            start.into_stream(server).await
        })
    })
    .await
    .unwrap();
    client.unwrap();
    server.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // Without a fetcher.
    let (client, server) = configs(&pki);
    let acceptor = browntls_tokio::unbuffered::TlsAcceptor::from(server);
    let errors = failing(client, move |s| {
        Box::pin(async move { acceptor.accept(s).await.map(|_| ()) })
    })
    .await;
    assert_tls_errors(errors, CertificateUrlError::Unobtainable);
}

/// Sets its flag when dropped.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A fetch that never completes.
struct Never(#[allow(dead_code)] DropFlag);

impl Future for Never {
    type Output = io::Result<Vec<Vec<u8>>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

/// Dropping the accept future drops the fetch it waits for.
#[tokio::test]
async fn dropping_the_handshake_drops_the_fetch() {
    let pki = Pki::new();
    let (client, server) = configs(&pki);
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let (started2, dropped2) = (started.clone(), dropped.clone());
    let acceptor = TlsAcceptor::from(server).client_certificate_url_fetcher(Arc::new(
        move |_: ClientCertificateUrlQuery| {
            started2.store(true, Ordering::SeqCst);
            Never(DropFlag(dropped2.clone()))
        },
    ));
    let (c, s) = duplex(64 * 1024);
    let client_task = tokio::spawn(async move {
        let _ = TlsConnector::from(client).connect(localhost(), c).await;
    });
    let mut accept = Box::pin(acceptor.accept(s));
    let waited = timeout(Duration::from_millis(500), &mut accept).await;
    assert!(waited.is_err(), "the handshake must wait for the fetch");
    assert!(started.load(Ordering::SeqCst));
    assert!(!dropped.load(Ordering::SeqCst));
    drop(accept);
    assert!(dropped.load(Ordering::SeqCst));
    client_task.abort();
}
