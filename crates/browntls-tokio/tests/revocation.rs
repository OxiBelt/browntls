//! Certificate status queries: the fetcher's deadline, single fetch per
//! request, cancellation and bounded cache, and the streams that answer
//! their connection's queries with it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use browntls::revocation::{RevocationCheck, RevocationQuery, RevocationResponse};
use browntls_tokio::revocation::{FetchLimits, RevocationFetcher, RevocationFetcherBuilder};
use tokio::time::Instant;

/// A query for the request `tag` stands for.
fn query(tag: u8) -> RevocationQuery {
    let check = RevocationCheck::pending(
        [tag; 32],
        vec!["http://ocsp.invalid/".into()],
        vec![0x30, 0x01, tag],
        |_| Ok(RevocationCheck::Complete(None)),
    );
    match check {
        RevocationCheck::Pending(pending) => pending.query().clone(),
        _ => panic!("a pending check"),
    }
}

/// The request a query stands for.
fn tag(query: &RevocationQuery) -> u8 {
    query.request_der()[2]
}

fn der(response: RevocationResponse) -> Option<Vec<u8>> {
    match response {
        RevocationResponse::Der(der) => Some(der),
        _ => None,
    }
}

/// What the application's fetch was asked to do.
#[derive(Default)]
struct Probe {
    /// Fetches begun.
    started: AtomicUsize,
    /// Fetches dropped before they returned.
    dropped: AtomicUsize,
}

impl Probe {
    fn started(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

struct Running {
    probe: Arc<Probe>,
    returned: bool,
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.returned {
            self.probe.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A fetcher whose fetch takes `delay` and returns what `answer` says.
fn probed(
    probe: &Arc<Probe>,
    delay: Duration,
    answer: impl Fn(&RevocationQuery) -> io::Result<Vec<u8>> + Send + Sync + 'static,
) -> RevocationFetcherBuilder {
    let probe = probe.clone();
    RevocationFetcher::builder(move |query: RevocationQuery, _limits: FetchLimits| {
        probe.started.fetch_add(1, Ordering::SeqCst);
        let running = Running {
            probe: probe.clone(),
            returned: false,
        };
        let result = answer(&query);
        async move {
            // The whole guard lives in the future, to see it dropped.
            let mut running = running;
            tokio::time::sleep(delay).await;
            running.returned = true;
            result
        }
    })
}

/// A response that says which request it answers.
fn echo(query: &RevocationQuery) -> io::Result<Vec<u8>> {
    Ok(vec![0xA0, tag(query)])
}

const DELAY: Duration = Duration::from_millis(200);

/// Polls `future` once.
async fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *future).poll(cx))).await
}

#[tokio::test(start_paused = true)]
async fn lookups_of_one_request_share_one_fetch() {
    let probe = Arc::new(Probe::default());
    let fetcher = Arc::new(probed(&probe, DELAY, echo).build());
    let (one, other) = (query(1), query(1));

    // In one task, which polls both.
    let (first, second) = tokio::join!(fetcher.resolve(&one), fetcher.resolve(&other));
    assert_eq!(der(first), Some(vec![0xA0, 1]));
    assert_eq!(der(second), Some(vec![0xA0, 1]));
    assert_eq!(probe.started(), 1);

    // In tasks of their own: only one of them drives the fetch, and the
    // others are woken with its result. Another request has its own fetch.
    let tasks: Vec<_> = [2, 2, 2, 3]
        .into_iter()
        .map(|tag| {
            let fetcher = fetcher.clone();
            tokio::spawn(async move { der(fetcher.resolve(&query(tag)).await) })
        })
        .collect();
    let mut answers = Vec::new();
    for task in tasks {
        answers.push(task.await.unwrap().unwrap()[1]);
    }
    assert_eq!(answers, [2, 2, 2, 3]);
    assert_eq!(probe.started(), 3);
    assert_eq!(probe.dropped(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_response_is_remembered_for_the_cache_ttl_only() {
    let probe = Arc::new(Probe::default());
    let fetcher = probed(&probe, DELAY, echo)
        .cache_ttl(Duration::from_secs(30))
        .build();
    let query = query(1);

    assert!(der(fetcher.resolve(&query).await).is_some());
    let before = Instant::now();
    assert_eq!(der(fetcher.resolve(&query).await), Some(vec![0xA0, 1]));
    assert_eq!(probe.started(), 1);
    assert_eq!(before.elapsed(), Duration::ZERO, "served without a fetch");

    tokio::time::advance(Duration::from_secs(31)).await;
    assert!(der(fetcher.resolve(&query).await).is_some());
    assert_eq!(probe.started(), 2);

    // A time to live of zero remembers nothing.
    let probe = Arc::new(Probe::default());
    let fetcher = fetcher_without_cache(&probe);
    for _ in 0..3 {
        assert!(der(fetcher.resolve(&query).await).is_some());
    }
    assert_eq!(probe.started(), 3);
}

fn fetcher_without_cache(probe: &Arc<Probe>) -> RevocationFetcher {
    probed(probe, DELAY, echo).cache_ttl(Duration::ZERO).build()
}

#[tokio::test(start_paused = true)]
async fn the_cache_is_bounded_in_entries_and_in_bytes() {
    let probe = Arc::new(Probe::default());
    let fetcher = probed(&probe, DELAY, echo)
        .cache_capacity(2, 1 << 20)
        .build();
    for tag in [1, 2, 3] {
        assert!(der(fetcher.resolve(&query(tag)).await).is_some());
    }
    assert_eq!(probe.started(), 3);
    // The two newest are remembered, the oldest was dropped for them.
    for tag in [2, 3] {
        assert!(der(fetcher.resolve(&query(tag)).await).is_some());
    }
    assert_eq!(probe.started(), 3);
    assert!(der(fetcher.resolve(&query(1)).await).is_some());
    assert_eq!(probe.started(), 4);
    // That one took the place of the oldest left.
    assert!(der(fetcher.resolve(&query(3)).await).is_some());
    assert_eq!(probe.started(), 4);
    assert!(der(fetcher.resolve(&query(2)).await).is_some());
    assert_eq!(probe.started(), 5);

    // Responses that do not fit the byte bound are not remembered, and
    // neither is anything with no entries allowed.
    for (entries, bytes) in [(16, 64), (0, 1 << 20)] {
        let probe = Arc::new(Probe::default());
        let fetcher = probed(&probe, DELAY, |_| Ok(vec![0xA0; 512]))
            .cache_capacity(entries, bytes)
            .build();
        for _ in 0..2 {
            assert_eq!(der(fetcher.resolve(&query(1)).await), Some(vec![0xA0; 512]));
        }
        assert_eq!(probe.started(), 2);
    }

    // The byte bound evicts as the entry bound does.
    let probe = Arc::new(Probe::default());
    let fetcher = probed(&probe, DELAY, |_| Ok(vec![0xA0; 512]))
        .cache_capacity(16, 1500)
        .build();
    for tag in [1, 2, 3, 3, 2, 1] {
        assert!(der(fetcher.resolve(&query(tag)).await).is_some());
    }
    assert_eq!(
        probe.started(),
        4,
        "two responses fit, the third evicted the first"
    );
}

#[tokio::test(start_paused = true)]
async fn a_fetch_past_its_deadline_is_dropped_and_answers_unavailable() {
    let probe = Arc::new(Probe::default());
    let fetcher = probed(&probe, Duration::from_secs(60), echo)
        .deadline(Duration::from_secs(2))
        .unavailable_ttl(Duration::from_secs(10))
        .build();
    assert_eq!(fetcher.limits().deadline, Duration::from_secs(2));
    let query = query(1);

    let before = Instant::now();
    assert!(der(fetcher.resolve(&query).await).is_none());
    assert_eq!(before.elapsed(), Duration::from_secs(2));
    assert_eq!((probe.started(), probe.dropped()), (1, 1));

    // The failure is remembered for a while: no connection waits for the
    // deadline again, and the responder is left alone.
    let before = Instant::now();
    assert!(der(fetcher.resolve(&query).await).is_none());
    assert_eq!(before.elapsed(), Duration::ZERO);
    assert_eq!(probe.started(), 1);

    tokio::time::advance(Duration::from_secs(11)).await;
    assert!(der(fetcher.resolve(&query).await).is_none());
    assert_eq!(probe.started(), 2);

    // A lookup that joins a running fetch waits for what is left of it.
    let late = self::query(2);
    let mut first = Box::pin(fetcher.resolve(&late));
    assert!(poll_once(&mut first).await.is_pending());
    tokio::time::advance(Duration::from_millis(1500)).await;
    let before = Instant::now();
    assert!(der(fetcher.resolve(&late).await).is_none());
    assert_eq!(before.elapsed(), Duration::from_millis(500));
    assert!(der(first.await).is_none());
    assert_eq!(probe.started(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_failed_fetch_is_not_remembered_when_told_so() {
    let probe = Arc::new(Probe::default());
    let fail = Arc::new(AtomicBool::new(true));
    let failing = fail.clone();
    let fetcher = probed(&probe, DELAY, move |query| {
        if failing.load(Ordering::SeqCst) {
            Err(io::ErrorKind::ConnectionRefused.into())
        } else {
            echo(query)
        }
    })
    .unavailable_ttl(Duration::ZERO)
    .build();
    let query = query(1);

    assert!(der(fetcher.resolve(&query).await).is_none());
    assert!(der(fetcher.resolve(&query).await).is_none());
    assert_eq!(probe.started(), 2);
    fail.store(false, Ordering::SeqCst);
    assert_eq!(der(fetcher.resolve(&query).await), Some(vec![0xA0, 1]));
    assert_eq!(probe.started(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_fetch_nobody_waits_for_is_dropped() {
    let probe = Arc::new(Probe::default());
    let fetcher = probed(&probe, DELAY, echo).build();
    let query = query(1);

    // A lookup that is never polled starts nothing.
    drop(fetcher.resolve(&query));
    assert_eq!(probe.started(), 0);

    let mut first = Box::pin(fetcher.resolve(&query));
    let mut second = Box::pin(fetcher.resolve(&query));
    assert!(poll_once(&mut first).await.is_pending());
    assert!(poll_once(&mut second).await.is_pending());
    assert_eq!(probe.started(), 1);

    // The fetch goes on for as long as one lookup waits for it.
    drop(first);
    assert_eq!(probe.dropped(), 0);
    drop(second);
    assert_eq!(probe.dropped(), 1);

    // Nothing of it was remembered: the next lookup fetches.
    assert_eq!(der(fetcher.resolve(&query).await), Some(vec![0xA0, 1]));
    assert_eq!((probe.started(), probe.dropped()), (2, 1));

    // The lookup left over drives the fetch that the dropped one began.
    let other = self::query(2);
    let mut first = Box::pin(fetcher.resolve(&other));
    let second = fetcher.resolve(&other);
    assert!(poll_once(&mut first).await.is_pending());
    drop(first);
    assert_eq!(der(second.await), Some(vec![0xA0, 2]));
    assert_eq!((probe.started(), probe.dropped()), (3, 1));
}

#[tokio::test(start_paused = true)]
async fn responses_out_of_bounds_answer_unavailable() {
    for (response, accepted) in [(0, false), (1, true), (64, true), (65, false)] {
        let probe = Arc::new(Probe::default());
        let fetcher = probed(&probe, DELAY, move |_| Ok(vec![0xA0; response]))
            .max_response_len(64)
            .build();
        assert_eq!(fetcher.limits().max_response_len, 64);
        let answer = der(fetcher.resolve(&query(1)).await);
        assert_eq!(answer.is_some(), accepted, "{response} bytes");
    }
}

#[tokio::test(start_paused = true)]
async fn fetches_beyond_the_concurrency_bound_answer_unavailable_at_once() {
    let probe = Arc::new(Probe::default());
    let fetcher = probed(&probe, DELAY, echo)
        .max_concurrent_fetches(1)
        .build();

    let mut running = Box::pin(fetcher.resolve(&query(1)));
    assert!(poll_once(&mut running).await.is_pending());

    let before = Instant::now();
    assert!(der(fetcher.resolve(&query(2)).await).is_none());
    assert_eq!(before.elapsed(), Duration::ZERO);
    // Joining the fetch that runs needs no other.
    let joined = fetcher.resolve(&query(1));
    assert_eq!(der(running.await), Some(vec![0xA0, 1]));
    assert_eq!(der(joined.await), Some(vec![0xA0, 1]));
    assert_eq!(probe.started(), 1);

    // The refusal was not remembered.
    assert_eq!(der(fetcher.resolve(&query(2)).await), Some(vec![0xA0, 2]));
    assert_eq!(probe.started(), 2);
}

/// The streams, over connections whose verifier asks for a certificate
/// status response.
#[cfg(any(feature = "native", feature = "rustcrypto"))]
mod common;

#[cfg(any(feature = "native", feature = "rustcrypto"))]
mod streams {
    use browntls::client::WebPkiServerVerifier;
    use browntls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use browntls::pki_types::{CertificateDer, ServerName, UnixTime};
    use browntls::revocation::{PeerEvidence, RevocationStatus};
    use browntls::{
        CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
        SupportedProtocolVersion,
    };
    use browntls_tokio::TlsConnector;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::timeout;

    use super::common::{Pki, localhost, provider, tls_error, versions};
    use super::*;

    const LIMIT: Duration = Duration::from_secs(30);

    /// The response the verifier below takes for "good".
    const GOOD: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x00];

    /// Verifies the chain, then asks for a status response and accepts
    /// [`GOOD`] only.
    #[derive(Debug)]
    struct AsksForStatus {
        inner: Arc<WebPkiServerVerifier>,
    }

    impl ServerCertVerifier for AsksForStatus {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        }

        fn verify_server_cert_with_evidence(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            _evidence: PeerEvidence<'_>,
            now: UnixTime,
        ) -> Result<RevocationCheck, Error> {
            self.verify_server_cert(end_entity, intermediates, server_name, &[], now)?;
            Ok(RevocationCheck::pending(
                [7; 32],
                vec!["http://ocsp.invalid/".into()],
                vec![0x30, 0x01, 0x07],
                |response| match response {
                    RevocationResponse::Der(der) if der == GOOD => {
                        Ok(RevocationCheck::Complete(Some(RevocationStatus::Good)))
                    }
                    RevocationResponse::Der(_) => Err(Error::InvalidCertificate(
                        CertificateError::InvalidOcspResponse,
                    )),
                    _ => Err(Error::InvalidCertificate(
                        CertificateError::UnknownRevocationStatus,
                    )),
                },
            ))
        }

        fn revocation_enabled(&self) -> bool {
            true
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    fn client_config(pki: &Pki, version: &'static SupportedProtocolVersion) -> Arc<ClientConfig> {
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(pki.roots()), provider())
            .build()
            .unwrap();
        let config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AsksForStatus { inner }))
            .with_no_client_auth();
        Arc::new(config)
    }

    /// A server that echoes one message per connection, for as many
    /// connections as the test makes; returns the client's transports.
    fn serve(
        pki: &Pki,
        version: &'static SupportedProtocolVersion,
        connections: usize,
    ) -> Vec<tokio::io::DuplexStream> {
        let acceptor = pki.acceptor(version);
        (0..connections)
            .map(|_| {
                let (client, server) = duplex(1 << 16);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // A client that refuses the certificate ends this early.
                    let Ok(mut tls) = acceptor.accept(server).await else {
                        return;
                    };
                    let mut message = [0; 4];
                    if tls.read_exact(&mut message).await.is_ok() {
                        let _ = tls.write_all(&message).await;
                        let _ = tls.flush().await;
                    }
                });
                client
            })
            .collect()
    }

    async fn echoes<S: AsyncReadExt + AsyncWriteExt + Unpin>(tls: &mut S) {
        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();
        let mut message = [0; 4];
        tls.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"ping");
    }

    fn certificate_error(err: &io::Error) -> Option<&CertificateError> {
        match tls_error(err) {
            Some(Error::InvalidCertificate(reason)) => Some(reason),
            _ => None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_fetches_the_status_its_verifier_asks_for() {
        for version in versions() {
            let pki = Pki::new();
            let probe = Arc::new(Probe::default());
            let fetcher = Arc::new(probed(&probe, DELAY, |_| Ok(GOOD.to_vec())).build());
            let connector =
                TlsConnector::from(client_config(&pki, version)).revocation_fetcher(fetcher);

            for io in serve(&pki, version, 2) {
                let mut tls = timeout(LIMIT, connector.connect(localhost(), io))
                    .await
                    .unwrap()
                    .unwrap();
                let (_, conn) = tls.get_ref();
                assert_eq!(conn.peer_revocation_status(), Some(RevocationStatus::Good));
                assert!(conn.pending_revocation().is_none());
                echoes(&mut tls).await;
            }
            // The second connection was given the remembered response, and
            // verified it as the first did.
            assert_eq!(probe.started(), 1, "{version:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unbuffered_handshake_fetches_the_status_too() {
        for version in versions() {
            let pki = Pki::new();
            let probe = Arc::new(Probe::default());
            let fetcher = Arc::new(probed(&probe, DELAY, |_| Ok(GOOD.to_vec())).build());
            let connector =
                browntls_tokio::unbuffered::TlsConnector::from(client_config(&pki, version))
                    .revocation_fetcher(fetcher);

            for io in serve(&pki, version, 2) {
                let mut tls = timeout(LIMIT, connector.connect(localhost(), io))
                    .await
                    .unwrap()
                    .unwrap();
                let (_, conn) = tls.get_ref();
                assert_eq!(conn.peer_revocation_status(), Some(RevocationStatus::Good));
                echoes(&mut tls).await;
            }
            assert_eq!(probe.started(), 1, "{version:?}");

            // Without a fetcher the verifier is told that there is no
            // response, and refuses.
            let connector =
                browntls_tokio::unbuffered::TlsConnector::from(client_config(&pki, version));
            let io = serve(&pki, version, 1).remove(0);
            let err = timeout(LIMIT, connector.connect(localhost(), io))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(
                certificate_error(&err),
                Some(&CertificateError::UnknownRevocationStatus),
                "{version:?}: {err}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_query_nothing_answers_is_unavailable_to_the_verifier() {
        for version in versions() {
            let pki = Pki::new();
            // No fetcher at all: answered at once.
            let connector = TlsConnector::from(client_config(&pki, version));
            let io = serve(&pki, version, 1).remove(0);
            let before = Instant::now();
            let err = timeout(LIMIT, connector.connect(localhost(), io))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(
                certificate_error(&err),
                Some(&CertificateError::UnknownRevocationStatus),
                "{version:?}: {err}"
            );
            assert_eq!(before.elapsed(), Duration::ZERO);

            // A responder that does not answer: at the deadline.
            let probe = Arc::new(Probe::default());
            let fetcher = probed(&probe, Duration::from_secs(3600), |_| Ok(GOOD.to_vec()))
                .deadline(Duration::from_secs(3))
                .build();
            let connector = connector.revocation_fetcher(Arc::new(fetcher));
            let io = serve(&pki, version, 1).remove(0);
            let before = Instant::now();
            let err = timeout(LIMIT, connector.connect(localhost(), io))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(
                certificate_error(&err),
                Some(&CertificateError::UnknownRevocationStatus),
                "{version:?}: {err}"
            );
            assert_eq!(before.elapsed(), Duration::from_secs(3));
            assert_eq!((probe.started(), probe.dropped()), (1, 1));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_response_the_verifier_refuses_is_not_given_to_the_next_connection() {
        for version in versions() {
            let pki = Pki::new();
            let probe = Arc::new(Probe::default());
            let good = Arc::new(AtomicBool::new(false));
            let answer = good.clone();
            let fetcher = probed(&probe, DELAY, move |_| {
                Ok(match answer.load(Ordering::SeqCst) {
                    true => GOOD.to_vec(),
                    false => vec![0x30, 0x00],
                })
            })
            .build();
            let connector = TlsConnector::from(client_config(&pki, version))
                .revocation_fetcher(Arc::new(fetcher));
            let mut ios = serve(&pki, version, 2).into_iter();

            let err = timeout(LIMIT, connector.connect(localhost(), ios.next().unwrap()))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(
                certificate_error(&err),
                Some(&CertificateError::InvalidOcspResponse),
                "{version:?}: {err}"
            );

            // The responder has a proper response now; the refused one is
            // not what the next connection gets.
            good.store(true, Ordering::SeqCst);
            let mut tls = timeout(LIMIT, connector.connect(localhost(), ios.next().unwrap()))
                .await
                .unwrap()
                .unwrap();
            echoes(&mut tls).await;
            assert_eq!(probe.started(), 2, "{version:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_handshake_drops_its_fetch() {
        let version = &browntls::version::TLS13;
        let pki = Pki::new();
        let probe = Arc::new(Probe::default());
        let fetcher = probed(&probe, Duration::from_secs(3600), |_| Ok(GOOD.to_vec()))
            .deadline(Duration::from_secs(3600))
            .build();
        let connector =
            TlsConnector::from(client_config(&pki, version)).revocation_fetcher(Arc::new(fetcher));
        let io = serve(&pki, version, 1).remove(0);

        // The handshake gets as far as the query and waits there.
        let mut connect = Box::pin(connector.connect(localhost(), io));
        let waited = timeout(Duration::from_secs(60), &mut connect).await;
        assert!(waited.is_err(), "the handshake waits for the response");
        assert_eq!((probe.started(), probe.dropped()), (1, 0));
        let conn = connect.connection().unwrap();
        assert!(conn.pending_revocation().is_some());
        assert!(conn.is_handshaking());

        drop(connect);
        assert_eq!(probe.dropped(), 1);
    }
}
