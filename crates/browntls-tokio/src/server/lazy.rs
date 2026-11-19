//! Choosing the [`ServerConfig`] after reading the ClientHello.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls::server::{Accepted, AcceptedAlert, Acceptor, ClientHello};
use browntls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{Accept, EarlyPhase, TlsStream};
use crate::common::{
    MidHandshake, RevocationSource, StreamState, SyncReadAdapter, coop, poll_send_alert,
};

/// Reads a ClientHello so the server can pick a [`ServerConfig`] for it
/// (by SNI, ALPN or cipher suites, say), then continues the handshake with
/// [`StartHandshake::into_stream`].
///
/// ```no_run
/// use std::sync::Arc;
///
/// use browntls_tokio::browntls::ServerConfig;
/// use browntls_tokio::browntls::server::Acceptor;
/// use browntls_tokio::LazyConfigAcceptor;
/// use tokio::net::TcpStream;
///
/// # async fn run(tcp: TcpStream, configs: impl Fn(Option<&str>) -> Arc<ServerConfig>)
/// # -> std::io::Result<()> {
/// let start = LazyConfigAcceptor::new(Acceptor::default(), tcp).await?;
/// let config = configs(start.client_hello().server_name());
/// let tls = start.into_stream(config).await?;
/// # Ok(())
/// # }
/// ```
///
/// A ClientHello the acceptor refuses is answered with its alert before
/// the future fails. Like any handshake, bound the wait with a timeout.
#[must_use = "futures do nothing unless polled"]
pub struct LazyConfigAcceptor<IO> {
    acceptor: Acceptor,
    io: Option<IO>,
    /// A refusal whose alert is being written.
    alert: Option<(browntls::Error, AcceptedAlert)>,
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
    pub fn new(acceptor: Acceptor, io: IO) -> Self {
        Self {
            acceptor,
            io: Some(io),
            alert: None,
            failed: false,
            revocation: RevocationSource::default(),
        }
    }

    /// Answers the certificate status (OCSP) queries of the connection
    /// with `fetcher`: the [`StartHandshake`] this future returns keeps
    /// it. See [`TlsAcceptor::revocation_fetcher`](super::TlsAcceptor::revocation_fetcher).
    #[cfg(feature = "ocsp")]
    pub fn revocation_fetcher(
        mut self,
        fetcher: Arc<crate::revocation::RevocationFetcher>,
    ) -> Self {
        self.revocation = RevocationSource::new(fetcher);
        self
    }

    /// Takes the transport back, abandoning the handshake. `None` once the
    /// future returned it in a [`StartHandshake`], or if taken before.
    ///
    /// The transport may then hold a partly read ClientHello: it is only
    /// fit to be closed, or to report an error in another protocol (an HTTP
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
        coop::budgeted(cx, |cx| this.poll_client_hello(cx))
    }
}

impl<IO> LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_client_hello(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<StartHandshake<IO>>> {
        let this = self;
        // Every read after the first in one poll takes a unit of the task's
        // cooperative budget, as in `Stream::read_io`: the client decides
        // in how many pieces its ClientHello arrives.
        let mut read_before = false;
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

            let unit = match read_before {
                true => Some(ready!(coop::poll_proceed(cx))),
                false => None,
            };
            let mut reader = SyncReadAdapter { io, cx };
            let result = match this.acceptor.read_tls(&mut reader) {
                // The transport is not ready: `unit` returns to the budget.
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                result => result,
            };
            read_before = true;
            if let Some(unit) = unit {
                unit.spent();
            }
            match result {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed connection before sending a ClientHello",
                    )));
                }
                Ok(_) => {}
                Err(err) => return Poll::Ready(Err(err)),
            }

            match this.acceptor.accept() {
                Ok(Some(accepted)) => {
                    if let Some(io) = this.io.take() {
                        let mut start = StartHandshake::from_parts(accepted, io);
                        start.revocation = this.revocation.clone();
                        return Poll::Ready(Ok(start));
                    }
                }
                Ok(None) => {}
                Err((error, alert)) => this.alert = Some((error, alert)),
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

/// A ClientHello read by [`LazyConfigAcceptor`], with its transport.
#[derive(Debug)]
pub struct StartHandshake<IO> {
    accepted: Accepted,
    io: IO,
    early_data: bool,
    revocation: RevocationSource,
}

impl<IO> StartHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Pairs a ClientHello accepted elsewhere with its transport.
    pub fn from_parts(accepted: Accepted, io: IO) -> Self {
        Self {
            accepted,
            io,
            early_data: false,
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
        self.revocation = RevocationSource::new(fetcher);
        self
    }

    /// Whether the future [`into_stream`](Self::into_stream) returns may
    /// resolve before the handshake completes, to read the client's 0-RTT
    /// data: [`TlsAcceptor::early_data`](super::TlsAcceptor::early_data)
    /// for a handshake continued here, with the same warning about replay.
    /// Off by default.
    pub fn early_data(mut self, enabled: bool) -> Self {
        self.early_data = enabled;
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
    /// [`ServerConnection`] first.
    ///
    /// If `config` cannot serve the ClientHello, or what the client sent
    /// after it is refused, the returned future sends the alert and then
    /// fails.
    pub fn into_stream_with<F>(self, config: Arc<ServerConfig>, f: F) -> Accept<IO>
    where
        F: FnOnce(&mut ServerConnection),
    {
        let half_rtt = config.send_half_rtt_data;
        let mut session = match self.accepted.into_connection(config) {
            Ok(session) => session,
            Err((error, alert)) => {
                return Accept(MidHandshake::SendAlert {
                    io: self.io,
                    alert,
                    error: io::Error::new(io::ErrorKind::InvalidData, error),
                });
            }
        };
        f(&mut session);
        // What the acceptor read past the ClientHello (early data, say) is
        // processed now: the handshake would not look at it before it read
        // more from the transport.
        if let Err(error) = session.process_new_packets() {
            return Accept(MidHandshake::SendAlert {
                io: self.io,
                alert: AcceptedAlert::from(session),
                error: io::Error::new(io::ErrorKind::InvalidData, error),
            });
        }
        Accept(MidHandshake::Handshaking(TlsStream {
            io: self.io,
            session,
            st: StreamState::new(self.revocation.for_stream()),
            early: self.early_data.then(|| EarlyPhase::new(half_rtt)),
        }))
    }

    /// The accepted ClientHello and the transport.
    pub fn into_inner(self) -> (Accepted, IO) {
        (self.accepted, self.io)
    }
}
