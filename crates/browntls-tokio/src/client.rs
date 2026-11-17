//! The client side: [`TlsConnector`] and the client [`TlsStream`].

use std::fmt;
use std::future::Future;
use std::io::{self, BufRead as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls::pki_types::ServerName;
use browntls::{ClientConfig, ClientConnection};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{self, IoSession, MidHandshake, StreamState};

/// Starts client handshakes with a shared [`ClientConfig`].
///
/// Cheap to clone; create one per configuration and reuse it.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
}

impl TlsConnector {
    /// Connects over `stream` to the server named `domain`.
    ///
    /// `domain` is checked against the server's certificate and sent as SNI
    /// when it is a DNS name. The returned future resolves once the
    /// handshake completes.
    pub fn connect<IO>(&self, domain: ServerName<'static>, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_impl(domain, stream, None, |_| ())
    }

    /// Like [`connect`](Self::connect), letting `f` adjust the
    /// [`ClientConnection`] before the first flight is sent.
    pub fn connect_with<IO, F>(&self, domain: ServerName<'static>, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ClientConnection),
    {
        self.connect_impl(domain, stream, None, f)
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
        F: FnOnce(&mut ClientConnection),
    {
        let alpn = alpn_protocols.unwrap_or_else(|| self.inner.alpn_protocols.clone());
        let mut session = match ClientConnection::new_with_alpn(self.inner.clone(), domain, alpn) {
            Ok(session) => session,
            Err(error) => {
                return Connect(MidHandshake::Error {
                    io: stream,
                    error: io::Error::other(error),
                });
            }
        };
        f(&mut session);

        Connect(MidHandshake::Handshaking(TlsStream {
            io: stream,
            session,
            st: StreamState::new(),
        }))
    }
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
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
        F: FnOnce(&mut ClientConnection),
    {
        self.inner
            .connect_impl(domain, stream, Some(self.alpn_protocols), f)
    }
}

impl fmt::Debug for TlsConnectorWithAlpn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnectorWithAlpn")
            .field("alpn_protocols", &self.alpn_protocols)
            .finish_non_exhaustive()
    }
}

/// A client handshake in progress; resolves to the connected [`TlsStream`].
///
/// Errors are `io::Error`s. A TLS failure has kind `InvalidData` and wraps
/// the [`browntls::Error`], which `get_ref` and `downcast_ref` recover.
#[must_use = "futures do nothing unless polled"]
pub struct Connect<IO>(MidHandshake<TlsStream<IO>>);

impl<IO> Connect<IO> {
    /// Turns this into a future that also hands the transport back on error.
    pub fn into_fallible(self) -> FallibleConnect<IO> {
        FallibleConnect(self.0)
    }

    /// The transport, unless the future already returned.
    pub fn get_ref(&self) -> Option<&IO> {
        match &self.0 {
            MidHandshake::Handshaking(stream) => Some(&stream.io),
            MidHandshake::Error { io, .. } | MidHandshake::SendAlert { io, .. } => Some(io),
            MidHandshake::End => None,
        }
    }

    /// The transport, unless the future already returned.
    pub fn get_mut(&mut self) -> Option<&mut IO> {
        match &mut self.0 {
            MidHandshake::Handshaking(stream) => Some(&mut stream.io),
            MidHandshake::Error { io, .. } | MidHandshake::SendAlert { io, .. } => Some(io),
            MidHandshake::End => None,
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<TlsStream<IO>>;

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
pub struct FallibleConnect<IO>(MidHandshake<TlsStream<IO>>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleConnect<IO> {
    type Output = Result<TlsStream<IO>, (io::Error, IO)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<IO> fmt::Debug for FallibleConnect<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FallibleConnect").finish_non_exhaustive()
    }
}

/// A client TLS connection over a transport `IO`.
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
    pub(crate) session: ClientConnection,
    pub(crate) st: StreamState,
}

impl<IO> TlsStream<IO> {
    /// The transport and the connection.
    pub fn get_ref(&self) -> (&IO, &ClientConnection) {
        (&self.io, &self.session)
    }

    /// The transport and the connection. Reading from or writing to the
    /// transport directly corrupts the TLS stream.
    pub fn get_mut(&mut self) -> (&mut IO, &mut ClientConnection) {
        (&mut self.io, &mut self.session)
    }

    /// The transport and the connection, ending the stream.
    pub fn into_inner(self) -> (IO, ClientConnection) {
        (self.io, self.session)
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ClientConnection;

    fn skip_handshake(&self) -> bool {
        false
    }

    fn parts(&mut self) -> (&mut StreamState, &mut IO, &mut ClientConnection) {
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
        common::poll_read(&mut this.io, &mut this.session, &mut this.st, cx, buf)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncBufRead for TlsStream<IO> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        common::poll_fill_buf(&mut this.io, &mut this.session, &mut this.st, cx)
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
        common::poll_write(&mut this.io, &mut this.session, &mut this.st, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        common::poll_write_vectored(&mut this.io, &mut this.session, &mut this.st, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        common::poll_flush(&mut this.io, &mut this.session, &mut this.st, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        common::poll_shutdown(&mut this.io, &mut this.session, &mut this.st, cx)
    }
}
