//! Fetching client certificates named by URL (RFC 6066 §5) for the server
//! handshakes of this crate.
//!
//! A TLS 1.2 server whose [`ServerConfig::client_certificate_url`] is set
//! may receive a CertificateURL message: the client names its certificate
//! chain with URLs and SHA-1 hashes instead of sending it. The connection
//! then pauses with a [`ClientCertificateUrlQuery`]
//! ([`CommonState::pending_client_certificate_url`]). The handshakes of
//! this crate answer it through the [`FetchClientCertificateUrl`] attached
//! to the acceptor (`client_certificate_url_fetcher` on [`TlsAcceptor`],
//! [`LazyConfigAcceptor`], [`StartHandshake`] and their counterparts in
//! [`unbuffered`](crate::unbuffered)). Without one, the query is answered
//! [`Unobtainable`](ClientCertificateUrlResponse::Unobtainable) at once and
//! the handshake fails with `certificate_unobtainable`.
//!
//! # The fetcher decides what is fetched
//!
//! Neither this crate nor `browntls-core` opens a connection to a URL. The
//! URLs come from an unauthenticated client: a server that fetches
//! whatever they name can be made to send requests to addresses of the
//! client's choosing, internal services included (server-side request
//! forgery, RFC 6066 §11.3). The server's policy has already refused URLs
//! outside its schemes and limits; the fetcher must still:
//!
//! - **authorize every destination**: scheme, host and port, and the
//!   address actually dialled after name resolution (refuse loopback,
//!   private and link-local ranges unless they are meant). Check the URL as
//!   parsed by the HTTP client's own parser, or the dialled address, never
//!   by matching strings: the policy lets IP literals such as
//!   `http://[::1]/` through, and such addresses have many spellings;
//! - **never follow redirects** (RFC 6066 §5: the server MUST NOT);
//! - **bound time and size**: the handshake waits for the fetch, and the
//!   objects may take at most
//!   [`ClientCertificateUrlPolicy::max_fetched_len`] bytes together;
//! - **beware of loops**: an `https` URL may lead back into this same
//!   server, whose handshake then waits for itself;
//! - **limit fetches across connections** (RFC 6066 §11.3): every
//!   unauthenticated client can make the server fetch, so cap the fetches
//!   in flight and their rate, and answer from a cache by URL and hash
//!   where possible.
//!
//! Put a timeout around the whole accept (for example
//! `tokio::time::timeout`): while a fetch runs the connection reads nothing
//! from its transport, so a slow fetch holds the connection open.
//!
//! The answer is not trusted either: the connection checks every object
//! against the hash the client sent (`bad_certificate_hash_value`
//! otherwise) and verifies the chain as one sent in a Certificate message.
//! A fetcher may answer from a cache by URL and hash (RFC 6066 §5 allows
//! a cached copy whose hash matches).
//!
//! ```
//! use std::io;
//! use std::sync::Arc;
//!
//! use browntls_tokio::browntls::certificate_url::ClientCertificateUrlQuery;
//! use browntls_tokio::browntls::ServerConfig;
//! use browntls_tokio::TlsAcceptor;
//!
//! async fn get(url: &str, max_len: usize) -> io::Result<Vec<u8>> {
//!     // The application's HTTP client: a GET that follows no redirect,
//!     // to an address the application checked, under a deadline, reading
//!     // at most `max_len` bytes.
//! #   let _ = (url, max_len);
//! #   Err(io::ErrorKind::Unsupported.into())
//! }
//!
//! fn acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
//!     TlsAcceptor::from(config).client_certificate_url_fetcher(Arc::new(
//!         |query: ClientCertificateUrlQuery| async move {
//!             let mut objects = Vec::new();
//!             for entry in query.entries() {
//!                 // Only this application's certificate host is asked.
//!                 if !entry.url().starts_with("http://certs.example/") {
//!                     return Err(io::ErrorKind::PermissionDenied.into());
//!                 }
//!                 objects.push(get(entry.url(), 64 * 1024).await?);
//!             }
//!             Ok(objects)
//!         },
//!     ))
//! }
//! ```
//!
//! The fetch runs in the poll of the handshake future, with no task of its
//! own: dropping the future drops the fetch. While it runs, the connection
//! reads nothing from its transport.
//!
//! [`ServerConfig::client_certificate_url`]: browntls_core::ServerConfig::client_certificate_url
//! [`CommonState::pending_client_certificate_url`]: browntls_core::CommonState::pending_client_certificate_url
//! [`ClientCertificateUrlPolicy::max_fetched_len`]: browntls_core::certificate_url::ClientCertificateUrlPolicy::max_fetched_len
//! [`TlsAcceptor`]: crate::TlsAcceptor
//! [`LazyConfigAcceptor`]: crate::LazyConfigAcceptor
//! [`StartHandshake`]: crate::StartHandshake

use std::future::Future;
use std::io;
use std::pin::Pin;

pub use browntls_core::certificate_url::{ClientCertificateUrlQuery, ClientCertificateUrlResponse};

/// The future of one fetch: the objects, one per URL in the query's
/// order, or why there are none.
pub type FetchFuture = Pin<Box<dyn Future<Output = io::Result<Vec<Vec<u8>>>> + Send>>;

/// The application's fetcher of client certificates named by URL; see the
/// [module documentation](self).
///
/// Implemented by closures `Fn(ClientCertificateUrlQuery) -> impl
/// Future<Output = io::Result<Vec<Vec<u8>>>>`.
pub trait FetchClientCertificateUrl: Send + Sync {
    /// Fetches the object each URL of `query` names, from destinations the
    /// application authorizes, following no redirect.
    ///
    /// Any error, a refusal included, answers the query
    /// [`Unobtainable`](ClientCertificateUrlResponse::Unobtainable). The
    /// future is dropped with the handshake that waits for it.
    fn fetch(&self, query: ClientCertificateUrlQuery) -> FetchFuture;
}

impl<F, Fut> FetchClientCertificateUrl for F
where
    F: Fn(ClientCertificateUrlQuery) -> Fut + Send + Sync,
    Fut: Future<Output = io::Result<Vec<Vec<u8>>>> + Send + 'static,
{
    fn fetch(&self, query: ClientCertificateUrlQuery) -> FetchFuture {
        Box::pin(self(query))
    }
}
