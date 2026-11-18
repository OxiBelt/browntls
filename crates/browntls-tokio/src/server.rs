//! The server side: [`TlsAcceptor`] and the server [`TlsStream`].

use std::fmt;
use std::future::Future;
use std::io::{self, BufRead as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{self, IoSession, MidHandshake, StreamState, coop};

mod lazy;
pub use lazy::{LazyConfigAcceptor, StartHandshake};

/// Accepts server handshakes with a shared [`ServerConfig`].
///
/// Cheap to clone; create one per configuration and reuse it.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl TlsAcceptor {
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
    /// [`ServerConnection`] before the handshake starts.
    pub fn accept_with<IO, F>(&self, stream: IO, f: F) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ServerConnection),
    {
        let mut session = match ServerConnection::new(self.inner.clone()) {
            Ok(session) => session,
            Err(error) => {
                return Accept(MidHandshake::Error {
                    io: stream,
                    error: io::Error::other(error),
                });
            }
        };
        f(&mut session);

        Accept(MidHandshake::Handshaking(TlsStream {
            io: stream,
            session,
            st: StreamState::new(),
        }))
    }

    /// The configuration new connections use.
    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.inner
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

/// A server handshake in progress; resolves to the accepted [`TlsStream`].
///
/// Errors are `io::Error`s. A TLS failure has kind `InvalidData` and wraps
/// the [`browntls::Error`], which `get_ref` and `downcast_ref` recover.
#[must_use = "futures do nothing unless polled"]
pub struct Accept<IO>(MidHandshake<TlsStream<IO>>);

impl<IO> Accept<IO> {
    /// Turns this into a future that also hands the transport back on error.
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

    /// The connection while the handshake runs, for a caller that polls
    /// this future itself and looks at the handshake between polls: once
    /// the ClientHello was processed, the server name, the ALPN protocol
    /// and the cipher suite are known, before the client's Finished
    /// arrives. Until the handshake completes, what it shows is not
    /// authenticated: the ClientHello may have been altered on the way.
    ///
    /// `None` once the future returned, and when there is no connection:
    /// it could not be created, or the configuration could not serve the
    /// ClientHello ([`StartHandshake::into_stream`]); the future then
    /// fails.
    pub fn connection(&self) -> Option<&ServerConnection> {
        self.0.session()
    }

    /// Like [`connection`](Self::connection), for calls that need `&mut`.
    ///
    /// The future drives the connection's I/O: reading or writing TLS
    /// records or plaintext through this reference disturbs the handshake.
    pub fn connection_mut(&mut self) -> Option<&mut ServerConnection> {
        self.0.session_mut()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<TlsStream<IO>>;

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
pub struct FallibleAccept<IO>(MidHandshake<TlsStream<IO>>);

impl<IO> FallibleAccept<IO> {
    /// The transport, unless the future already returned.
    pub fn get_ref(&self) -> Option<&IO> {
        self.0.io()
    }

    /// The transport, unless the future already returned.
    pub fn get_mut(&mut self) -> Option<&mut IO> {
        self.0.io_mut()
    }

    /// The connection while the handshake runs; see
    /// [`Accept::connection`].
    pub fn connection(&self) -> Option<&ServerConnection> {
        self.0.session()
    }

    /// The connection while the handshake runs; see
    /// [`Accept::connection_mut`].
    pub fn connection_mut(&mut self) -> Option<&mut ServerConnection> {
        self.0.session_mut()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleAccept<IO> {
    type Output = Result<TlsStream<IO>, (io::Error, IO)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<IO> fmt::Debug for FallibleAccept<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FallibleAccept").finish_non_exhaustive()
    }
}

/// A server TLS connection over a transport `IO`.
///
/// Reads and writes plaintext; [`AsyncWriteExt::shutdown`] sends
/// `close_notify` and shuts the transport's write side. Records the
/// transport did not take at once stay queued until a later write or
/// [`AsyncWriteExt::flush`].
///
/// [`AsyncWriteExt::shutdown`]: https://docs.rs/tokio/1/tokio/io/trait.AsyncWriteExt.html#method.shutdown
/// [`AsyncWriteExt::flush`]: https://docs.rs/tokio/1/tokio/io/trait.AsyncWriteExt.html#method.flush
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) session: ServerConnection,
    pub(crate) st: StreamState,
}

impl<IO> TlsStream<IO> {
    /// The transport and the connection.
    pub fn get_ref(&self) -> (&IO, &ServerConnection) {
        (&self.io, &self.session)
    }

    /// The transport and the connection. Reading from or writing to the
    /// transport directly corrupts the TLS stream.
    pub fn get_mut(&mut self) -> (&mut IO, &mut ServerConnection) {
        (&mut self.io, &mut self.session)
    }

    /// The transport and the connection, ending the stream.
    pub fn into_inner(self) -> (IO, ServerConnection) {
        (self.io, self.session)
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ServerConnection;

    fn skip_handshake(&self) -> bool {
        false
    }

    fn refs(&self) -> (&IO, &ServerConnection) {
        (&self.io, &self.session)
    }

    fn parts(&mut self) -> (&mut StreamState, &mut IO, &mut ServerConnection) {
        (&mut self.st, &mut self.io, &mut self.session)
    }

    fn into_io(self) -> IO {
        self.io
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.st.begin_poll();
        coop::budgeted(cx, |cx| {
            common::poll_read(&mut this.io, &mut this.session, &mut this.st, cx, buf)
        })
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncBufRead for TlsStream<IO> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        this.st.begin_poll();
        ready!(coop::poll_budget(cx));
        let poll = common::poll_fill_buf(&mut this.io, &mut this.session, &mut this.st, cx);
        coop::spend_if_ready(cx, poll)
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.session.reader().consume(amt);
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.st.begin_poll();
        coop::budgeted(cx, |cx| {
            common::poll_write(&mut this.io, &mut this.session, &mut this.st, cx, buf)
        })
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.st.begin_poll();
        coop::budgeted(cx, |cx| {
            common::poll_write_vectored(&mut this.io, &mut this.session, &mut this.st, cx, bufs)
        })
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.st.begin_poll();
        coop::budgeted(cx, |cx| {
            common::poll_flush(&mut this.io, &mut this.session, &mut this.st, cx)
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.st.begin_poll();
        coop::budgeted(cx, |cx| {
            common::poll_shutdown(&mut this.io, &mut this.session, &mut this.st, cx)
        })
    }
}
