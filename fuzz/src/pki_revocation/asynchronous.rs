//! In-memory TLS and issuer-response callbacks under a paused Tokio clock.

use std::future::{pending, poll_fn};
use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use browntls_core::revocation::{RevocationQuery, RevocationResponse, RevocationStatus};
use browntls_core::server::{Acceptor, UnbufferedAcceptor};
use browntls_tokio::revocation::{FetchLimits, RevocationFetcher, staple::StapleRefresh};
use browntls_tokio::unbuffered;
use browntls_tokio::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};
use tokio::io::duplex;
use tokio::time::timeout;

use super::drivers::{configs, localhost, staple_resolver};
use super::fixtures::{Fixture, NEXT_UPDATE, NOW, RESPONDER};

const DEADLINE: Duration = Duration::from_millis(20);
const MAX_RESPONSE: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) fn run(fixture: &'static Fixture, input: &[u8]) {
    let Some((&mode, bytes)) = input.split_first() else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(async {
        match mode % 6 {
            4 => refresh(fixture, bytes).await,
            5 => fetch_limits(fixture).await,
            mode => handshake(fixture, mode, bytes).await,
        }
    });
}

async fn handshake(fixture: &'static Fixture, mode: u8, bytes: &[u8]) {
    let (client, server) = configs(fixture, &browntls_core::version::TLS13, true, false);
    let canned = bytes.is_empty();
    let response = if canned {
        fixture.response.as_slice()
    } else {
        bytes
    };
    let response: Arc<[u8]> = Arc::from(response);
    let calls = Arc::new(AtomicUsize::new(0));
    let fetcher = {
        let calls = calls.clone();
        RevocationFetcher::builder(move |query: RevocationQuery, limits: FetchLimits| {
            assert!(
                query
                    .responder_urls()
                    .iter()
                    .map(String::as_str)
                    .eq([RESPONDER])
            );
            assert_eq!(limits.max_response_len, MAX_RESPONSE);
            calls.fetch_add(1, Ordering::Relaxed);
            let response = response.clone();
            async move { Ok(response.to_vec()) }
        })
        .deadline(DEADLINE)
        .max_response_len(MAX_RESPONSE)
        .cache_capacity(2, MAX_RESPONSE * 2)
        .cache_ttl(Duration::from_secs(2))
        .unavailable_ttl(Duration::ZERO)
        .max_concurrent_fetches(1)
        .build()
    };
    assert_eq!(fetcher.limits().deadline, DEADLINE);
    let fetcher = Arc::new(fetcher);
    for _ in 0..2 {
        let (left, right) = duplex(16 * 1024);
        let server_fetcher = fetcher.clone();
        let server = server.clone();
        let lazy = mode & 1 != 0;
        let (client_status, server_status) = timeout(HANDSHAKE_TIMEOUT, async {
            if mode < 2 {
                let peer = tokio::spawn(async move {
                    let tls = if lazy {
                        LazyConfigAcceptor::new(Acceptor::default(), right)
                            .revocation_fetcher(server_fetcher.clone())
                            .await?
                            .revocation_fetcher(server_fetcher)
                            .into_stream(server)
                            .await?
                    } else {
                        TlsAcceptor::from(server)
                            .revocation_fetcher(server_fetcher)
                            .accept(right)
                            .await?
                    };
                    Ok::<_, io::Error>(tls.get_ref().1.peer_revocation_status())
                });
                let client = TlsConnector::from(client.clone())
                    .revocation_fetcher(fetcher.clone())
                    .connect(localhost(), left)
                    .await
                    .map(|tls| tls.get_ref().1.peer_revocation_status());
                (client, peer.await.unwrap())
            } else {
                let peer = tokio::spawn(async move {
                    let tls = if lazy {
                        unbuffered::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), right)
                            .revocation_fetcher(server_fetcher.clone())
                            .await?
                            .revocation_fetcher(server_fetcher)
                            .into_stream(server)
                            .await?
                    } else {
                        unbuffered::TlsAcceptor::from(server)
                            .revocation_fetcher(server_fetcher)
                            .accept(right)
                            .await?
                    };
                    Ok::<_, io::Error>(tls.get_ref().1.peer_revocation_status())
                });
                let client = unbuffered::TlsConnector::from(client.clone())
                    .revocation_fetcher(fetcher.clone())
                    .connect(localhost(), left)
                    .await
                    .map(|tls| tls.get_ref().1.peer_revocation_status());
                (client, peer.await.unwrap())
            }
        })
        .await
        .expect("bounded in-memory handshake");

        if canned {
            assert_eq!(client_status.unwrap(), Some(RevocationStatus::Good));
            assert_eq!(server_status.unwrap(), Some(RevocationStatus::Good));
        }
    }
    if canned {
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "both peers use the same cached CertID"
        );
    }
}

async fn fetch_limits(fixture: &Fixture) {
    let resolver = staple_resolver(fixture);
    let query = resolver.refresh_query().unwrap().unwrap();
    let query = query.query();
    let success =
        RevocationFetcher::new(|_: RevocationQuery, _: FetchLimits| async { Ok(vec![1]) });
    assert!(matches!(success.resolve(query).await, RevocationResponse::Der(body) if body == [1]));

    let slow = RevocationFetcher::builder(|_: RevocationQuery, _: FetchLimits| pending())
        .deadline(DEADLINE)
        .build();
    assert!(matches!(
        slow.resolve(query).await,
        RevocationResponse::Unavailable
    ));

    let oversized =
        RevocationFetcher::builder(|_: RevocationQuery, _: FetchLimits| async { Ok(vec![1, 2]) })
            .max_response_len(1)
            .build();
    assert!(matches!(
        oversized.resolve(query).await,
        RevocationResponse::Unavailable
    ));
}

async fn refresh(fixture: &Fixture, bytes: &[u8]) {
    let resolver = Arc::new(staple_resolver(fixture));
    let canned = bytes.is_empty();
    let response: Arc<[u8]> = Arc::from(if canned {
        fixture.response.as_slice()
    } else {
        bytes
    });
    let mut refresh = StapleRefresh::new(
        resolver.clone(),
        move |_: RevocationQuery, _: FetchLimits| {
            let response = response.clone();
            async move { Ok(response.to_vec()) }
        },
    )
    .interval(Duration::from_secs(30))
    .retry(DEADLINE, Duration::from_secs(1))
    .deadline(DEADLINE)
    .max_response_len(MAX_RESPONSE);
    let result = refresh.refresh_once().await;
    if canned {
        let round = result.unwrap();
        assert_eq!(round.installed, 1);
        assert_eq!(
            round.shortest_lifetime,
            Some(Duration::from_secs(NEXT_UPDATE - NOW))
        );
    }

    let rounds = Arc::new(AtomicUsize::new(0));
    let count = rounds.clone();
    let mut refresh = pin!(
        refresh
            .observe(move |_| {
                count.fetch_add(1, Ordering::Relaxed);
            })
            .run()
    );
    poll_fn(|cx| {
        assert!(refresh.as_mut().poll(cx).is_pending());
        assert_eq!(rounds.load(Ordering::Relaxed), 1);
        Poll::Ready(())
    })
    .await;
    // Dropping the future cancels the refresh loop during its first sleep.
}
