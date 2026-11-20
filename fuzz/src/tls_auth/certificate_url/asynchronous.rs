//! TLS 1.2 handshakes through the six `browntls-tokio` acceptors with a
//! client certificate URL fetcher, over an in-memory transport under a
//! paused clock.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use browntls_core::certificate_url::{ClientCertificateUrlQuery, ClientCertificateUrlResponse};
use browntls_core::pki_types::{CertificateDer, ServerName};
use browntls_core::server::{Acceptor, UnbufferedAcceptor};
use browntls_core::{CommonState, Error};
use browntls_tokio::certificate_url::FetchClientCertificateUrl;
use browntls_tokio::{LazyConfigAcceptor, TlsAcceptor, TlsConnector, unbuffered};
use tokio::io::duplex;
use tokio::time::timeout;

use super::{Plan, check};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

type Peer = Option<Vec<CertificateDer<'static>>>;

fn peer(state: &CommonState) -> Peer {
    state.peer_certificates().map(<[_]>::to_vec)
}

/// The library error inside a stream's error.
fn tls_error(err: &io::Error) -> Error {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<Error>())
        .cloned()
        .unwrap_or_else(|| Error::General(err.to_string()))
}

pub(super) fn run(plan: &Plan, acceptor: usize) {
    if !plan.valid() {
        // Connection creation refuses the policy (checked by the other
        // drivers).
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("runtime");
    runtime.block_on(handshake(plan, acceptor));
}

async fn handshake(plan: &Plan, acceptor: usize) {
    let objects = match plan.response() {
        ClientCertificateUrlResponse::Fetched(objects) => Some(objects),
        _ => None,
    };
    let urls = plan.urls.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let fetcher: Arc<dyn FetchClientCertificateUrl> = {
        let calls = calls.clone();
        Arc::new(move |query: ClientCertificateUrlQuery| {
            calls.fetch_add(1, Ordering::Relaxed);
            let urls = urls.as_ref().expect("a query needs URLs");
            assert_eq!(query.entries(), urls.entries());
            let objects = objects.clone();
            async move { objects.ok_or_else(|| io::Error::other("unobtainable")) }
        })
    };
    let config = plan.server_config();
    let (left, right) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let f = fetcher;
        match acceptor {
            0 => TlsAcceptor::from(config)
                .client_certificate_url_fetcher(f)
                .accept(right)
                .await
                .map(|tls| peer(tls.get_ref().1)),
            1 | 2 => {
                let lazy = LazyConfigAcceptor::new(Acceptor::default(), right);
                let start = if acceptor == 1 {
                    lazy.client_certificate_url_fetcher(f).await?
                } else {
                    lazy.await?.client_certificate_url_fetcher(f)
                };
                let tls = start.into_stream(config).await?;
                Ok(peer(tls.get_ref().1))
            }
            3 => unbuffered::TlsAcceptor::from(config)
                .client_certificate_url_fetcher(f)
                .accept(right)
                .await
                .map(|tls| peer(tls.get_ref().1)),
            _ => {
                let lazy = unbuffered::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), right);
                let start = if acceptor == 4 {
                    lazy.client_certificate_url_fetcher(f).await?
                } else {
                    lazy.await?.client_certificate_url_fetcher(f)
                };
                let tls = start.into_stream(config).await?;
                Ok(peer(tls.get_ref().1))
            }
        }
    });
    let name = ServerName::try_from("localhost").expect("name");
    let (client, server) = timeout(HANDSHAKE_TIMEOUT, async {
        let client = TlsConnector::from(plan.client_config())
            .connect(name, left)
            .await;
        // The client stream stays open until the server is done.
        let server: io::Result<Peer> = server.await.expect("server task");
        (client.map(drop), server)
    })
    .await
    .expect("bounded in-memory handshake");
    let surfaced = calls.load(Ordering::Relaxed);
    let (server, peer) = match server {
        Ok(peer) => (Ok(()), peer),
        Err(err) => (Err(tls_error(&err)), None),
    };
    check(
        plan,
        surfaced,
        client.map_err(|err| tls_error(&err)),
        server,
        peer.as_deref(),
    );
}
