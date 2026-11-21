//! Starting unbuffered streams: [`TlsConnector`], [`TlsAcceptor`] and the
//! futures that drive their handshakes.

use std::fmt;
use std::future::Future;
use std::io;
use std::mem;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls_core::client::UnbufferedClientConnection;
use browntls_core::pki_types::ServerName;
use browntls_core::server::UnbufferedServerConnection;
use browntls_core::unbuffered::UnbufferedConnectionCommon;
use browntls_core::{ClientConfig, ClientServerIdentity, ServerConfig, SideData};
use tokio::io::{AsyncRead, AsyncWrite};

use super::buffers::{Incoming, Outgoing};
use super::lazy::poll_send_alert;
use super::{ClientTlsStream, ServerTlsStream, TlsStream};
use crate::common::RevocationSource;

/// A handshake in progress, or how it ended.
pub(super) enum MidHandshake<IO, C> {
    Handshaking(TlsStream<IO, C>),
    /// Continuing a handshake failed before any I/O, with an alert to send
    /// before reporting `error`.
    SendAlert {
        io: IO,
        alert: Outgoing,
        error: io::Error,
    },
    /// Setting up the connection failed before any I/O.
    Error {
        io: IO,
        error: io::Error,
    },
    /// The future already returned.
    End,
}

impl<IO, C> MidHandshake<IO, C> {
    fn io(&self) -> Option<&IO> {
        match self {
            Self::Handshaking(stream) => Some(&stream.io),
            Self::SendAlert { io, .. } | Self::Error { io, .. } => Some(io),
            Self::End => None,
        }
    }

    fn io_mut(&mut self) -> Option<&mut IO> {
        match self {
            Self::Handshaking(stream) => Some(&mut stream.io),
            Self::SendAlert { io, .. } | Self::Error { io, .. } => Some(io),
            Self::End => None,
        }
    }
}

impl<IO, C, D> Future for MidHandshake<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = UnbufferedConnectionCommon<D>> + Unpin,
    D: SideData,
{
    type Output = Result<TlsStream<IO, C>, (io::Error, IO)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut stream = match mem::replace(this, Self::End) {
            Self::Handshaking(stream) => stream,
            Self::SendAlert {
                mut io,
                mut alert,
                error,
            } => {
                if poll_send_alert(&mut io, &mut alert, cx).is_pending() {
                    *this = Self::SendAlert { io, alert, error };
                    return Poll::Pending;
                }
                return Poll::Ready(Err((error, io)));
            }
            Self::Error { io, error } => return Poll::Ready(Err((error, io))),
            // Like any future, this one must not be polled after it returned
            // `Ready`; by then the transport has been handed back.
            #[allow(clippy::panic)]
            Self::End => panic!("TLS handshake future polled after completion"),
        };
        match stream.poll_handshake(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(stream)),
            Poll::Ready(Err(error)) => Poll::Ready(Err((error, stream.io))),
            Poll::Pending => {
                *this = Self::Handshaking(stream);
                Poll::Pending
            }
        }
    }
}

/// Starts client handshakes with a shared [`ClientConfig`], over the
/// unbuffered connection API; see the [module documentation](super).
///
/// Cheap to clone; create one per configuration and reuse it.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
    revocation: RevocationSource,
}

impl TlsConnector {
    /// Answers the certificate status (OCSP) queries of this connector's
    /// connections with `fetcher`: during the handshake, and in the
    /// operations after it. Without one, such a query is answered as
    /// unavailable at once. See [`crate::revocation`].
    #[cfg(feature = "ocsp")]
    pub fn revocation_fetcher(
        mut self,
        fetcher: Arc<crate::revocation::RevocationFetcher>,
    ) -> Self {
        self.revocation.set_fetcher(fetcher);
        self
    }

    /// Connects over `stream` to the server named `domain`.
    ///
    /// `domain` is checked against the server's certificate and sent as SNI
    /// when it is a DNS name. The returned future resolves once the
    /// handshake completes. No 0-RTT data is sent, whatever the
    /// configuration enables.
    pub fn connect<IO>(&self, domain: ServerName<'static>, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_impl(domain, stream, None, |_| ())
    }

    /// Like [`connect`](Self::connect), letting `f` adjust the
    /// [`UnbufferedClientConnection`] before the first flight is sent.
    pub fn connect_with<IO, F>(&self, domain: ServerName<'static>, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut UnbufferedClientConnection),
    {
        self.connect_impl(domain, stream, None, f)
    }

    /// Connects using RFC 9525 service identity matching. `identity` supplies
    /// the routing name sent as SNI and the reference identifiers checked
    /// against the server certificate.
    pub fn connect_with_identity<IO>(
        &self,
        identity: ClientServerIdentity,
        stream: IO,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_identity_impl(identity, stream, None, |_| ())
    }

    /// Like [`connect_with_identity`](Self::connect_with_identity), adjusting
    /// the connection before its first flight is sent.
    pub fn connect_with_identity_and_callback<IO, F>(
        &self,
        identity: ClientServerIdentity,
        stream: IO,
        f: F,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut UnbufferedClientConnection),
    {
        self.connect_identity_impl(identity, stream, None, f)
    }

    /// Overrides the configuration's ALPN protocols for one connection.
    pub fn with_alpn(&self, alpn_protocols: Vec<Vec<u8>>) -> TlsConnectorWithAlpn<'_> {
        TlsConnectorWithAlpn {
            inner: self,
            alpn_protocols,
        }
    }

    /// The configuration new connections use.
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.inner
    }

    fn connect_impl<IO, F>(
        &self,
        domain: ServerName<'static>,
        stream: IO,
        alpn_protocols: Option<Vec<Vec<u8>>>,
        f: F,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut UnbufferedClientConnection),
    {
        let alpn = alpn_protocols.unwrap_or_else(|| self.inner.alpn_protocols.clone());
        self.finish_connect(
            stream,
            UnbufferedClientConnection::new_with_alpn(self.inner.clone(), domain, alpn),
            f,
        )
    }

    fn connect_identity_impl<IO, F>(
        &self,
        identity: ClientServerIdentity,
        stream: IO,
        alpn_protocols: Option<Vec<Vec<u8>>>,
        f: F,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut UnbufferedClientConnection),
    {
        let alpn = alpn_protocols.unwrap_or_else(|| self.inner.alpn_protocols.clone());
        self.finish_connect(
            stream,
            UnbufferedClientConnection::new_with_identity_and_alpn(
                self.inner.clone(),
                identity,
                alpn,
            ),
            f,
        )
    }

    fn finish_connect<IO, F>(
        &self,
        stream: IO,
        result: Result<UnbufferedClientConnection, browntls_core::Error>,
        f: F,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut UnbufferedClientConnection),
    {
        match result {
            Ok(mut conn) => {
                f(&mut conn);
                Connect(MidHandshake::Handshaking(TlsStream::new(
                    stream,
                    conn,
                    Incoming::new(),
                    self.revocation.for_stream(),
                )))
            }
            Err(error) => Connect(MidHandshake::Error {
                io: stream,
                error: io::Error::other(error),
            }),
        }
    }
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> Self {
        Self {
            inner,
            revocation: RevocationSource::default(),
        }
    }
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector")
            .field("revocation", &self.revocation)
            .finish_non_exhaustive()
    }
}

/// A [`TlsConnector`] with per-connection ALPN protocols; see
/// [`TlsConnector::with_alpn`].
pub struct TlsConnectorWithAlpn<'c> {
    inner: &'c TlsConnector,
    alpn_protocols: Vec<Vec<u8>>,
}

impl TlsConnectorWithAlpn<'_> {
    /// [`TlsConnector::connect`] with these ALPN protocols.
    pub fn connect<IO>(self, domain: ServerName<'static>, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.inner
            .connect_impl(domain, stream, Some(self.alpn_protocols), |_| ())
    }

    /// [`TlsConnector::connect_with`] with these ALPN protocols.
    pub fn connect_with<IO, F>(self, domain: ServerName<'static>, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut UnbufferedClientConnection),
    {
        self.inner
            .connect_impl(domain, stream, Some(self.alpn_protocols), f)
    }

    /// [`TlsConnector::connect_with_identity`] with these ALPN protocols.
    pub fn connect_with_identity<IO>(
        self,
        identity: ClientServerIdentity,
        stream: IO,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.inner
            .connect_identity_impl(identity, stream, Some(self.alpn_protocols), |_| ())
    }

    /// [`TlsConnector::connect_with_identity_and_callback`] with these ALPN
    /// protocols.
    pub fn connect_with_identity_and_callback<IO, F>(
        self,
        identity: ClientServerIdentity,
        stream: IO,
        f: F,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut UnbufferedClientConnection),
    {
        self.inner
            .connect_identity_impl(identity, stream, Some(self.alpn_protocols), f)
    }
}

impl fmt::Debug for TlsConnectorWithAlpn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnectorWithAlpn")
            .field("alpn_protocols", &self.alpn_protocols)
            .finish_non_exhaustive()
    }
}

/// Accepts server handshakes with a shared [`ServerConfig`], over the
/// unbuffered connection API; see the [module documentation](super).
///
/// Cheap to clone; create one per configuration and reuse it.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
    revocation: RevocationSource,
}

impl TlsAcceptor {
    /// Answers the certificate status (OCSP) queries of this acceptor's
    /// connections (about client certificates) with `fetcher`: during the
    /// handshake, and in the operations after it (post-handshake
    /// authentication). Without one, such a query is answered as
    /// unavailable at once. See [`crate::revocation`].
    #[cfg(feature = "ocsp")]
    pub fn revocation_fetcher(
        mut self,
        fetcher: Arc<crate::revocation::RevocationFetcher>,
    ) -> Self {
        self.revocation.set_fetcher(fetcher);
        self
    }

    /// Fetches, with `fetcher`, the client certificates that TLS 1.2
    /// clients of this acceptor name by URL (RFC 6066 §5, with
    /// [`ServerConfig::client_certificate_url`](browntls_core::ServerConfig::client_certificate_url)
    /// set). Without one, such a handshake fails with
    /// `certificate_unobtainable`.
    ///
    /// Neither this crate nor `browntls-core` opens a connection to a URL:
    /// `fetcher` must authorize every destination the client names. See
    /// [`crate::certificate_url`].
    pub fn client_certificate_url_fetcher(
        mut self,
        fetcher: Arc<dyn crate::certificate_url::FetchClientCertificateUrl>,
    ) -> Self {
        self.revocation.set_certificate_url_fetcher(fetcher);
        self
    }

    /// Accepts a TLS connection over `stream`. The returned future resolves
    /// once the handshake completes.
    ///
    /// Bound the handshake's duration (with [`tokio::time::timeout`], say):
    /// a client that stops sending holds the future, and the transport, for
    /// as long as the transport stays open.
    ///
    /// [`tokio::time::timeout`]: https://docs.rs/tokio/1/tokio/time/fn.timeout.html
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.accept_with(stream, |_| ())
    }

    /// Like [`accept`](Self::accept), letting `f` adjust the
    /// [`UnbufferedServerConnection`] before the handshake starts.
    pub fn accept_with<IO, F>(&self, stream: IO, f: F) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut UnbufferedServerConnection),
    {
        match UnbufferedServerConnection::new(self.inner.clone()) {
            Ok(mut conn) => {
                f(&mut conn);
                Accept(MidHandshake::Handshaking(TlsStream::new(
                    stream,
                    conn,
                    Incoming::new(),
                    self.revocation.for_stream(),
                )))
            }
            Err(error) => Accept(MidHandshake::Error {
                io: stream,
                error: io::Error::other(error),
            }),
        }
    }

    /// The configuration new connections use.
    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.inner
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> Self {
        Self {
            inner,
            revocation: RevocationSource::default(),
        }
    }
}

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor")
            .field("revocation", &self.revocation)
            .finish_non_exhaustive()
    }
}

/// A client handshake in progress; resolves to the [`ClientTlsStream`].
///
/// Errors are `io::Error`s. A TLS failure has kind `InvalidData`, wraps the
/// [`browntls_core::Error`] (which `get_ref` and `downcast_ref` recover), and
/// is reported once the alert describing it was written or the transport
/// refused it. Creating the connection can fail too, before any I/O: that
/// error has kind `Other` and wraps the [`browntls_core::Error`] the same way.
#[must_use = "futures do nothing unless polled"]
pub struct Connect<IO>(pub(super) MidHandshake<IO, UnbufferedClientConnection>);

impl<IO> Connect<IO> {
    /// Turns this into a future that also hands the transport back on
    /// error.
    pub fn into_fallible(self) -> FallibleConnect<IO> {
        FallibleConnect(self.0)
    }

    /// The transport, unless the future already returned.
    pub fn get_ref(&self) -> Option<&IO> {
        self.0.io()
    }

    /// The transport, unless the future already returned.
    pub fn get_mut(&mut self) -> Option<&mut IO> {
        self.0.io_mut()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<ClientTlsStream<IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

impl<IO> fmt::Debug for Connect<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connect").finish_non_exhaustive()
    }
}

/// Like [`Connect`], but an error comes with the transport.
#[must_use = "futures do nothing unless polled"]
pub struct FallibleConnect<IO>(MidHandshake<IO, UnbufferedClientConnection>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleConnect<IO> {
    type Output = Result<ClientTlsStream<IO>, (io::Error, IO)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<IO> fmt::Debug for FallibleConnect<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FallibleConnect").finish_non_exhaustive()
    }
}

/// A server handshake in progress; resolves to the [`ServerTlsStream`].
///
/// Errors are `io::Error`s. A TLS failure has kind `InvalidData`, wraps the
/// [`browntls_core::Error`] (which `get_ref` and `downcast_ref` recover), and
/// is reported once the alert describing it was written or the transport
/// refused it. Creating the connection can fail too, before any I/O: that
/// error has kind `Other` and wraps the [`browntls_core::Error`] the same way.
#[must_use = "futures do nothing unless polled"]
pub struct Accept<IO>(pub(super) MidHandshake<IO, UnbufferedServerConnection>);

impl<IO> Accept<IO> {
    /// Turns this into a future that also hands the transport back on
    /// error.
    pub fn into_fallible(self) -> FallibleAccept<IO> {
        FallibleAccept(self.0)
    }

    /// The transport, unless the future already returned.
    pub fn get_ref(&self) -> Option<&IO> {
        self.0.io()
    }

    /// The transport, unless the future already returned.
    pub fn get_mut(&mut self) -> Option<&mut IO> {
        self.0.io_mut()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<ServerTlsStream<IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

impl<IO> fmt::Debug for Accept<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accept").finish_non_exhaustive()
    }
}

/// Like [`Accept`], but an error comes with the transport.
#[must_use = "futures do nothing unless polled"]
pub struct FallibleAccept<IO>(MidHandshake<IO, UnbufferedServerConnection>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleAccept<IO> {
    type Output = Result<ServerTlsStream<IO>, (io::Error, IO)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<IO> fmt::Debug for FallibleAccept<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FallibleAccept").finish_non_exhaustive()
    }
}
