//! Choosing the [`ServerConfig`] after reading the ClientHello, over the
//! unbuffered acceptor.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls_core::ServerConfig;
use browntls_core::server::{
    ClientHello, UnbufferedAcceptStatus, UnbufferedAccepted, UnbufferedAcceptedAlert,
    UnbufferedAcceptor, UnbufferedServerConnection,
};
use browntls_core::unbuffered::{EncodeError, InsufficientSizeError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::TlsStream;
use super::buffers::{Incoming, Outgoing};
use super::handshake::{Accept, MidHandshake};
use crate::common::RevocationSource;

/// How often the buffer is grown for one record of an alert.
const MAX_GROW_ATTEMPTS: usize = 4;

/// Copies the records of a refusal into a buffer for the transport.
pub(super) fn encode_alert(mut alert: UnbufferedAcceptedAlert) -> Outgoing {
    let mut outgoing = Outgoing::new();
    let mut attempts = 0;
    while !alert.is_empty() && attempts < MAX_GROW_ATTEMPTS {
        match alert.encode(outgoing.spare_mut()) {
            Ok(n) => {
                outgoing.commit(n);
                attempts = 0;
            }
            Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                outgoing.reserve(required_size);
                attempts += 1;
            }
            Err(_) => break,
        }
    }
    outgoing
}

/// Writes `alert` to `io` and flushes it. `Ready` once it is out, or once
/// the transport failed or took nothing: the caller then reports the error
/// that caused the alert, not the transport's.
pub(super) fn poll_send_alert<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    alert: &mut Outgoing,
    cx: &mut Context<'_>,
) -> Poll<()> {
    while !alert.is_empty() {
        match ready!(Pin::new(&mut *io).poll_write(cx, alert.unsent())) {
            Ok(n) if n > 0 => alert.advance(n),
            _ => return Poll::Ready(()),
        }
    }
    Pin::new(io).poll_flush(cx).map(|_| ())
}

/// Reads a ClientHello so the server can pick a [`ServerConfig`] for it
/// (by SNI, ALPN or cipher suites, say), then continues the handshake with
/// [`StartHandshake::into_stream`]: the counterpart of
/// [`LazyConfigAcceptor`](crate::LazyConfigAcceptor) over
/// [`UnbufferedAcceptor`], which returns an unbuffered stream.
///
/// ```no_run
/// use std::sync::Arc;
///
/// use browntls_tokio::browntls::ServerConfig;
/// use browntls_tokio::browntls::server::UnbufferedAcceptor;
/// use browntls_tokio::unbuffered::LazyConfigAcceptor;
/// use tokio::net::TcpStream;
///
/// # async fn run(tcp: TcpStream, configs: impl Fn(Option<&str>) -> Arc<ServerConfig>)
/// # -> std::io::Result<()> {
/// let start = LazyConfigAcceptor::new(UnbufferedAcceptor::new(), tcp).await?;
/// let config = configs(start.client_hello().server_name());
/// let tls = start.into_stream(config).await?;
/// # Ok(())
/// # }
/// ```
///
/// The bytes the transport delivered behind the ClientHello stay in the
/// receive buffer, which the stream takes over. A ClientHello the acceptor
/// refuses is answered with its alert before the future fails. Like any
/// handshake, bound the wait with a timeout.
#[must_use = "futures do nothing unless polled"]
pub struct LazyConfigAcceptor<IO> {
    acceptor: UnbufferedAcceptor,
    io: Option<IO>,
    incoming: Incoming,
    /// A refusal whose alert is being written.
    alert: Option<(browntls_core::Error, Outgoing)>,
    /// The future already failed (and keeps the transport for `take_io`).
    failed: bool,
    /// Handed on to the [`StartHandshake`].
    revocation: RevocationSource,
}

impl<IO> LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Reads a ClientHello from `io` with `acceptor`.
    pub fn new(acceptor: UnbufferedAcceptor, io: IO) -> Self {
        Self {
            acceptor,
            io: Some(io),
            incoming: Incoming::new(),
            alert: None,
            failed: false,
            revocation: RevocationSource::default(),
        }
    }

    /// Answers the certificate status (OCSP) queries of the connection
    /// with `fetcher`: the [`StartHandshake`] this future returns keeps
    /// it. See
    /// [`TlsAcceptor::revocation_fetcher`](super::TlsAcceptor::revocation_fetcher).
    #[cfg(feature = "ocsp")]
    pub fn revocation_fetcher(
        mut self,
        fetcher: Arc<crate::revocation::RevocationFetcher>,
    ) -> Self {
        self.revocation.set_fetcher(fetcher);
        self
    }

    /// Fetches, with `fetcher`, the client certificates a TLS 1.2 client
    /// names by URL (RFC 6066 §5); see
    /// [`TlsAcceptor::client_certificate_url_fetcher`](super::TlsAcceptor::client_certificate_url_fetcher).
    /// `fetcher` must authorize every destination the client names.
    pub fn client_certificate_url_fetcher(
        mut self,
        fetcher: Arc<dyn crate::certificate_url::FetchClientCertificateUrl>,
    ) -> Self {
        self.revocation.set_certificate_url_fetcher(fetcher);
        self
    }

    /// Takes the transport back, abandoning the handshake. `None` once the
    /// future returned it in a [`StartHandshake`], or if taken before.
    ///
    /// What was read of a ClientHello is dropped: the transport is only fit
    /// to be closed, or to report an error in another protocol (an HTTP
    /// redirect for a plain-text request, say).
    pub fn take_io(&mut self) -> Option<IO> {
        self.io.take()
    }
}

impl<IO> Future for LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<StartHandshake<IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let Some(io) = this.io.as_mut() else {
                return Poll::Ready(Err(io::Error::other(
                    "LazyConfigAcceptor polled after completion or after take_io",
                )));
            };
            if this.failed {
                return Poll::Ready(Err(io::Error::other(
                    "LazyConfigAcceptor polled after it failed",
                )));
            }
            if let Some((error, mut alert)) = this.alert.take() {
                if poll_send_alert(io, &mut alert, cx).is_pending() {
                    this.alert = Some((error, alert));
                    return Poll::Pending;
                }
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
            }

            let UnbufferedAcceptStatus { discard, state } =
                this.acceptor.accept(this.incoming.unprocessed_mut());
            this.incoming.processed(discard, None);
            match state {
                Ok(Some(accepted)) => {
                    if let Some(io) = this.io.take() {
                        return Poll::Ready(Ok(StartHandshake {
                            accepted,
                            io,
                            incoming: std::mem::replace(&mut this.incoming, Incoming::new()),
                            revocation: this.revocation.clone(),
                        }));
                    }
                }
                Ok(None) => {
                    let mut buf = match this.incoming.spare_mut() {
                        Ok(spare) => ReadBuf::new(spare),
                        Err(err) => {
                            this.failed = true;
                            return Poll::Ready(Err(err));
                        }
                    };
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
                    let n = buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed connection before sending a ClientHello",
                        )));
                    }
                    this.incoming.received(n);
                }
                Err((error, alert)) => this.alert = Some((error, encode_alert(alert))),
            }
        }
    }
}

impl<IO> fmt::Debug for LazyConfigAcceptor<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyConfigAcceptor")
            .field("acceptor", &self.acceptor)
            .field("has_io", &self.io.is_some())
            .field("refused", &self.alert.as_ref().map(|(error, _)| error))
            .field("revocation", &self.revocation)
            .finish()
    }
}

/// A ClientHello read by [`LazyConfigAcceptor`], with its transport and the
/// bytes received behind it.
#[derive(Debug)]
pub struct StartHandshake<IO> {
    accepted: UnbufferedAccepted,
    io: IO,
    incoming: Incoming,
    revocation: RevocationSource,
}

impl<IO> StartHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Pairs a ClientHello accepted elsewhere with its transport.
    ///
    /// `incoming_tls` holds the bytes received behind the ClientHello and
    /// not processed yet: what was left of the buffer given to
    /// [`UnbufferedAcceptor::accept`] once the bytes it discarded were
    /// removed.
    pub fn from_parts(accepted: UnbufferedAccepted, io: IO, incoming_tls: Vec<u8>) -> Self {
        Self {
            accepted,
            io,
            incoming: Incoming::with_received(incoming_tls),
            revocation: RevocationSource::default(),
        }
    }

    /// Answers the certificate status (OCSP) queries of the connection
    /// with `fetcher`; see
    /// [`TlsAcceptor::revocation_fetcher`](super::TlsAcceptor::revocation_fetcher).
    #[cfg(feature = "ocsp")]
    pub fn revocation_fetcher(
        mut self,
        fetcher: Arc<crate::revocation::RevocationFetcher>,
    ) -> Self {
        self.revocation.set_fetcher(fetcher);
        self
    }

    /// Fetches, with `fetcher`, the client certificates a TLS 1.2 client
    /// names by URL (RFC 6066 §5); see
    /// [`TlsAcceptor::client_certificate_url_fetcher`](super::TlsAcceptor::client_certificate_url_fetcher).
    /// `fetcher` must authorize every destination the client names.
    pub fn client_certificate_url_fetcher(
        mut self,
        fetcher: Arc<dyn crate::certificate_url::FetchClientCertificateUrl>,
    ) -> Self {
        self.revocation.set_certificate_url_fetcher(fetcher);
        self
    }

    /// The ClientHello.
    pub fn client_hello(&self) -> ClientHello<'_> {
        self.accepted.client_hello()
    }

    /// Continues the handshake with `config`.
    pub fn into_stream(self, config: Arc<ServerConfig>) -> Accept<IO> {
        self.into_stream_with(config, |_| ())
    }

    /// Like [`into_stream`](Self::into_stream), letting `f` adjust the
    /// [`UnbufferedServerConnection`] first.
    ///
    /// If `config` cannot serve the ClientHello, the returned future sends
    /// the alert and then fails.
    pub fn into_stream_with<F>(self, config: Arc<ServerConfig>, f: F) -> Accept<IO>
    where
        F: FnOnce(&mut UnbufferedServerConnection),
    {
        match self.accepted.into_connection(config) {
            Ok(mut conn) => {
                f(&mut conn);
                Accept(MidHandshake::Handshaking(TlsStream::new(
                    self.io,
                    conn,
                    self.incoming,
                    self.revocation.for_stream(),
                )))
            }
            Err((error, alert)) => Accept(MidHandshake::SendAlert {
                io: self.io,
                alert: encode_alert(alert),
                error: io::Error::new(io::ErrorKind::InvalidData, error),
            }),
        }
    }

    /// The accepted ClientHello, the transport, and the bytes received
    /// behind the ClientHello and not processed yet (see
    /// [`Self::from_parts`]).
    pub fn into_parts(self) -> (UnbufferedAccepted, IO, Vec<u8>) {
        let (_, incoming_tls) = self.incoming.into_parts();
        (self.accepted, self.io, incoming_tls)
    }
}
