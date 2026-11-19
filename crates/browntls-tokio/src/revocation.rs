//! Fetching certificate status (OCSP) responses for connections that
//! wait for one.
//!
//! A verifier that needs a status response the peer did not staple pauses
//! the connection with a [`RevocationQuery`]
//! ([`CommonState::pending_revocation`]). The streams and handshake futures
//! of this crate answer it by themselves when a [`RevocationFetcher`] is
//! attached to the connector or acceptor they came from: during the
//! handshake, and whenever a later read meets a certificate (TLS 1.3
//! post-handshake authentication). A connection with no fetcher attached is
//! answered [`RevocationResponse::Unavailable`] at once, and the verifier's
//! policy decides what that means.
//!
//! # What the application provides
//!
//! This crate has no HTTP client. The application implements
//! [`FetchRevocation`] (a closure does) and makes the request itself:
//!
//! ```
//! use std::io;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use browntls_tokio::browntls::ClientConfig;
//! use browntls_tokio::browntls::revocation::RevocationQuery;
//! use browntls_tokio::revocation::{FetchLimits, RevocationFetcher};
//! use browntls_tokio::TlsConnector;
//!
//! async fn post_ocsp(url: String, body: Vec<u8>, limits: FetchLimits) -> io::Result<Vec<u8>> {
//!     // The application's HTTP client: POST `body` as
//!     // `application/ocsp-request`, read at most
//!     // `limits.max_response_len` bytes of the answer.
//! #   let _ = (url, body, limits);
//! #   Err(io::ErrorKind::Unsupported.into())
//! }
//!
//! fn connector(config: Arc<ClientConfig>) -> TlsConnector {
//!     let fetcher = RevocationFetcher::builder(|query: RevocationQuery, limits: FetchLimits| {
//!         // Only responders this application decided to trust for the
//!         // issuer are contacted.
//!         let url = query
//!             .responder_urls()
//!             .iter()
//!             .find(|url| url.starts_with("http://ocsp.example/"))
//!             .cloned();
//!         let body = query.request_der().to_vec();
//!         async move {
//!             match url {
//!                 Some(url) => post_ocsp(url, body, limits).await,
//!                 None => Err(io::ErrorKind::PermissionDenied.into()),
//!             }
//!         }
//!     })
//!     .deadline(Duration::from_secs(3))
//!     .build();
//!     TlsConnector::from(config).revocation_fetcher(Arc::new(fetcher))
//! }
//! ```
//!
//! **The responder URLs come from the peer's certificate.** Requesting
//! whatever they name lets a peer make this host send requests to
//! addresses of its choosing (internal services included). Decide which
//! responder may be asked for which issuer
//! ([`RevocationQuery::issuer_key_hash`]), check the address that is
//! dialed, follow no redirects, and bound the size of the answer.
//!
//! The answer is not trusted either: the fetcher hands the bytes to the
//! connection, and the verifier that asked authenticates them (signature,
//! freshness, and that they speak of the certificate in question). Nothing
//! here parses a response or decides whether a certificate is good.
//!
//! # What the fetcher adds
//!
//! - **A deadline.** A fetch that has not answered within
//!   [`deadline`](RevocationFetcherBuilder::deadline) is dropped and the
//!   query answered `Unavailable`. It is measured with [`tokio::time`], so
//!   the runtime that polls the connection needs its time driver enabled.
//! - **One fetch per request.** Connections that ask for the same request
//!   while a fetch for it runs share that fetch. No task is spawned: the
//!   connections drive it from their own polls.
//! - **Cancellation.** A fetch is dropped as soon as no connection waits
//!   for it (each was dropped, or timed out by its owner).
//! - **A bounded cache** of responses, so that a burst of connections to
//!   one peer asks its responder once. Each connection still verifies the
//!   response it is given. See [`cache_ttl`](RevocationFetcherBuilder::cache_ttl)
//!   for what remembering a response costs.
//! - **Bounds** on the size of a response and on how many fetches run at
//!   once; beyond them a query is answered `Unavailable`.
//!
//! While a connection waits for a response it reads nothing from its
//! transport, so it does not notice a peer that goes away meanwhile; the
//! deadline bounds that wait.
//!
//! [`staple`] has the server's side: keeping its own stapled response
//! fresh.
//!
//! [`CommonState::pending_revocation`]: browntls_core::CommonState::pending_revocation

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use browntls_core::revocation::{RevocationQuery, RevocationResponse};

mod flight;
pub mod staple;

use flight::{Begin, Engine, Key, Limits, Lookup, Outcome, Starter};

/// The bounds a fetch runs under, for the application's HTTP client to
/// apply as well.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct FetchLimits {
    /// How long the fetch may take before it is dropped.
    pub deadline: Duration,
    /// The longest response that is accepted. Stop reading the body there:
    /// a longer one is discarded.
    pub max_response_len: usize,
}

/// The future of one fetch: the responder's raw DER body, or why there is
/// none.
pub type FetchFuture = Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>;

/// The application's transport for certificate status requests; see the
/// [module documentation](self).
///
/// Implemented by closures `Fn(RevocationQuery, FetchLimits) -> impl
/// Future<Output = io::Result<Vec<u8>>>`.
pub trait FetchRevocation: Send + Sync {
    /// Sends [`RevocationQuery::request_der`] to a responder the
    /// application authorizes for [`RevocationQuery::issuer_key_hash`] and
    /// returns the body of its answer.
    ///
    /// Any error answers the query
    /// [`Unavailable`](RevocationResponse::Unavailable), and so does a
    /// refusal to contact the responders the certificate names. The future
    /// is dropped at the deadline and when no connection waits for it any
    /// more.
    fn fetch(&self, query: RevocationQuery, limits: FetchLimits) -> FetchFuture;
}

impl<F, Fut> FetchRevocation for F
where
    F: Fn(RevocationQuery, FetchLimits) -> Fut + Send + Sync,
    Fut: Future<Output = io::Result<Vec<u8>>> + Send + 'static,
{
    fn fetch(&self, query: RevocationQuery, limits: FetchLimits) -> FetchFuture {
        Box::pin(self(query, limits))
    }
}

/// Answers the certificate status queries of the connections it is
/// attached to; see the [module documentation](self).
///
/// Share one, in an [`Arc`], between the connectors and acceptors whose
/// connections may ask for the same certificates: the cache and the
/// running fetches are its own.
pub struct RevocationFetcher {
    fetch: Arc<dyn FetchRevocation>,
    engine: Arc<Engine>,
    limits: FetchLimits,
}

impl RevocationFetcher {
    /// A fetcher over `fetch` with the default bounds.
    pub fn new(fetch: impl FetchRevocation + 'static) -> Self {
        Self::builder(fetch).build()
    }

    /// Starts a fetcher over `fetch` whose bounds can be chosen.
    pub fn builder(fetch: impl FetchRevocation + 'static) -> RevocationFetcherBuilder {
        RevocationFetcherBuilder {
            fetch: Arc::new(fetch),
            limits: FetchLimits {
                deadline: Duration::from_secs(5),
                max_response_len: 64 * 1024,
            },
            cache: Limits {
                max_entries: 1024,
                max_bytes: 4 * 1024 * 1024,
                ttl: Duration::from_secs(60),
                unavailable_ttl: Duration::from_secs(10),
                max_flights: 256,
            },
        }
    }

    /// The bounds fetches run under.
    pub fn limits(&self) -> FetchLimits {
        self.limits
    }

    /// Answers `query` as the streams of this crate do, for a connection
    /// that is driven by hand: pass the result to its
    /// `resolve_peer_revocation` with [`RevocationQuery::id`].
    ///
    /// Dropping the future gives the lookup up; the fetch goes on only
    /// while another connection waits for the same request.
    pub fn resolve(&self, query: &RevocationQuery) -> Resolve {
        Resolve(self.begin(query))
    }

    /// Starts answering `query`.
    pub(crate) fn begin(&self, query: &RevocationQuery) -> PendingResponse {
        let key = Key::new(query.issuer_key_hash(), query.request_der());
        let begin = self.engine.begin(key.clone(), || self.starter(query));
        PendingResponse {
            key,
            state: match begin {
                Begin::Known(outcome) => State::Ready(outcome),
                Begin::Wait(lookup) => State::Waiting(lookup),
                Begin::Busy => State::Ready(None),
            },
        }
    }

    /// What runs when the first lookup of a new fetch is polled: the
    /// application's fetch under the deadline, its result within bounds.
    fn starter(&self, query: &RevocationQuery) -> Starter {
        let fetch = self.fetch.clone();
        let limits = self.limits;
        let query = query.clone();
        Box::new(move || {
            Box::pin(async move {
                let fetched = tokio::time::timeout(limits.deadline, fetch.fetch(query, limits));
                match fetched.await {
                    Ok(Ok(der)) if !der.is_empty() && der.len() <= limits.max_response_len => {
                        Some(Arc::from(der))
                    }
                    _ => None,
                }
            })
        })
    }

    /// The connection refused the response it was given: it is not given
    /// to another.
    pub(crate) fn refused(&self, delivered: &Delivered) {
        self.engine.forget(&delivered.key, &delivered.response);
    }
}

impl fmt::Debug for RevocationFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationFetcher")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Chooses the bounds of a [`RevocationFetcher`].
pub struct RevocationFetcherBuilder {
    fetch: Arc<dyn FetchRevocation>,
    limits: FetchLimits,
    cache: Limits,
}

impl RevocationFetcherBuilder {
    /// How long one fetch may take (5 seconds by default). Connections
    /// that join a running fetch wait for what is left of it.
    pub fn deadline(mut self, deadline: Duration) -> Self {
        self.limits.deadline = deadline;
        self
    }

    /// The longest response accepted (64 KiB by default); a longer one
    /// answers the query `Unavailable`.
    pub fn max_response_len(mut self, len: usize) -> Self {
        self.limits.max_response_len = len;
        self
    }

    /// How many answers the cache holds (1024 by default) and how many
    /// bytes they may take with their requests (4 MiB by default). The
    /// oldest answers go first. Zero entries turns the cache off.
    pub fn cache_capacity(mut self, max_entries: usize, max_bytes: usize) -> Self {
        self.cache.max_entries = max_entries;
        self.cache.max_bytes = max_bytes;
        self
    }

    /// How long a response is given to later connections that ask for the
    /// same request (60 seconds by default); zero for never.
    ///
    /// Every connection verifies the response it is given, so the cache
    /// cannot make a certificate pass that its responder's answer would
    /// not. What it can do is hand out a response that expired while it
    /// was remembered: the connection that gets it refuses it and fails as
    /// its verifier's policy says, and the response is forgotten. Nothing
    /// here reads a response's validity period, so keep this well below
    /// the time responders leave before a response expires.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache.ttl = ttl;
        self
    }

    /// How long a failed fetch answers the same request `Unavailable`
    /// without another fetch (10 seconds by default); zero for never.
    ///
    /// With a responder that is down, every connection would otherwise
    /// wait for the deadline. For as long as a failure is remembered,
    /// though, a responder that came back is not asked.
    pub fn unavailable_ttl(mut self, ttl: Duration) -> Self {
        self.cache.unavailable_ttl = ttl;
        self
    }

    /// How many fetches may run at the same time (256 by default). A query
    /// that would need one more is answered `Unavailable`, and that is not
    /// remembered.
    pub fn max_concurrent_fetches(mut self, fetches: usize) -> Self {
        self.cache.max_flights = fetches;
        self
    }

    /// The fetcher.
    pub fn build(self) -> RevocationFetcher {
        RevocationFetcher {
            fetch: self.fetch,
            engine: Arc::new(Engine::new(self.cache)),
            limits: self.limits,
        }
    }
}

impl fmt::Debug for RevocationFetcherBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationFetcherBuilder")
            .field("limits", &self.limits)
            .field("cache", &self.cache)
            .finish_non_exhaustive()
    }
}

enum State {
    Ready(Outcome),
    Waiting(Lookup),
}

/// The answer to one query, on its way.
pub(crate) struct PendingResponse {
    key: Key,
    state: State,
}

impl PendingResponse {
    /// The answer and, when it is a response, what tells the fetcher which
    /// one it was should the connection refuse it.
    pub(crate) fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(RevocationResponse, Option<Delivered>)> {
        let outcome = match &mut self.state {
            State::Ready(outcome) => outcome.take(),
            State::Waiting(lookup) => ready!(lookup.poll(cx)),
        };
        // Polled again, there is nothing to give.
        self.state = State::Ready(None);
        Poll::Ready(match outcome {
            Some(der) => {
                let response = RevocationResponse::Der(der.to_vec());
                let delivered = Delivered {
                    key: self.key.clone(),
                    response: der,
                };
                (response, Some(delivered))
            }
            None => (RevocationResponse::Unavailable, None),
        })
    }
}

/// A response that was given to a connection.
pub(crate) struct Delivered {
    key: Key,
    response: Arc<[u8]>,
}

/// The future of [`RevocationFetcher::resolve`].
#[must_use = "futures do nothing unless polled"]
pub struct Resolve(PendingResponse);

impl Future for Resolve {
    type Output = RevocationResponse;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll(cx).map(|(response, _)| response)
    }
}

impl fmt::Debug for Resolve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolve").finish_non_exhaustive()
    }
}
