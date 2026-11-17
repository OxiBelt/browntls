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

use super::{Accept, TlsStream};
use crate::common::{MidHandshake, StreamState, SyncReadAdapter, poll_send_alert};

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
        }
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

            let mut reader = SyncReadAdapter { io, cx };
            match this.acceptor.read_tls(&mut reader) {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed connection before sending a ClientHello",
                    )));
                }
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(err) => return Poll::Ready(Err(err)),
            }

            match this.acceptor.accept() {
                Ok(Some(accepted)) => {
                    if let Some(io) = this.io.take() {
                        return Poll::Ready(Ok(StartHandshake { accepted, io }));
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
            .finish()
    }
}

/// A ClientHello read by [`LazyConfigAcceptor`], with its transport.
#[derive(Debug)]
pub struct StartHandshake<IO> {
    accepted: Accepted,
    io: IO,
}

impl<IO> StartHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Pairs a ClientHello accepted elsewhere with its transport.
    pub fn from_parts(accepted: Accepted, io: IO) -> Self {
        Self { accepted, io }
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
    /// If `config` cannot serve the ClientHello, the returned future sends
    /// the alert and then fails.
    pub fn into_stream_with<F>(self, config: Arc<ServerConfig>, f: F) -> Accept<IO>
    where
        F: FnOnce(&mut ServerConnection),
    {
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
        Accept(MidHandshake::Handshaking(TlsStream {
            io: self.io,
            session,
            st: StreamState::new(),
        }))
    }

    /// The accepted ClientHello and the transport.
    pub fn into_inner(self) -> (Accepted, IO) {
        (self.accepted, self.io)
    }
}
