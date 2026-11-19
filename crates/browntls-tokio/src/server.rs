//! The server side: [`TlsAcceptor`] and the server [`TlsStream`].

use std::fmt;
use std::future::Future;
use std::io::{self, BufRead as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{self, IoSession, MidHandshake, RevocationSource, StreamState, coop};
use crate::kernel::IntoKernelHandoff;
use crate::split::{self, ReadHalf, WriteHalf};

mod early;
mod lazy;
pub use early::EarlyDataReader;
use early::EarlyPhase;
pub use lazy::{LazyConfigAcceptor, StartHandshake};

/// Accepts server handshakes with a shared [`ServerConfig`].
///
/// Cheap to clone; create one per configuration and reuse it.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
    early_data: bool,
    revocation: RevocationSource,
}

impl TlsAcceptor {
    /// Answers the certificate status (OCSP) queries of this acceptor's
    /// connections (about client certificates) with `fetcher`: during the
    /// handshake, and in reads after it (post-handshake authentication).
    /// Without one, such a query is answered as unavailable at once. See
    /// [`crate::revocation`].
    #[cfg(feature = "ocsp")]
    pub fn revocation_fetcher(
        mut self,
        fetcher: Arc<crate::revocation::RevocationFetcher>,
    ) -> Self {
        self.revocation = RevocationSource::new(fetcher);
        self
    }

    /// Whether [`accept`](Self::accept) may return before the handshake
    /// completes, so the server can read the client's 0-RTT ("early") data
    /// without waiting for the client's Finished. Off by default.
    ///
    /// It does when the connection accepted early data, which `browntls`
    /// does in two cases: for a TLS 1.3 session resumed from the server's
    /// [session storage](ServerConfig::session_storage) (never from a
    /// stateless ticket) with a non-zero
    /// [`ServerConfig::max_early_data_size`], and for an external PSK
    /// configured to allow early data. `accept` then resolves once the
    /// server's flight is written, and on the returned stream:
    ///
    /// - [`TlsStream::early_data`] reads the early data as it arrives;
    /// - an ordinary read, a flush or a shutdown completes the handshake
    ///   first, and ordinary reads never return early data;
    /// - a write waits for the handshake too, unless
    ///   [`ServerConfig::send_half_rtt_data`] is set: it is then sent at
    ///   once, ahead of the client's Finished (0.5-RTT data).
    ///
    /// A handshake that fails in this phase fails every later operation
    /// with its error. Every other connection is accepted as without this
    /// option, after its handshake.
    ///
    /// A timeout around `accept` no longer bounds the handshake of such a
    /// stream: the rest of it runs inside the operations above, which a
    /// client that stops sending holds for as long as the transport stays
    /// open. Bound them too.
    ///
    /// # Replay
    ///
    /// Early data is **replayable**: until the handshake completes
    /// ([`is_handshaking`](browntls::CommonState::is_handshaking) on the
    /// connection is `false`), nothing shows that the client is taking part
    /// in this connection now, rather than an attacker sending again a
    /// ClientHello and early data it recorded. The same holds for what the
    /// connection reports from the resumed session in this phase (the
    /// client's certificates, the resumption data).
    ///
    /// What `browntls` does against replay is limited to resumed sessions:
    /// the session is taken out of the session storage, which makes each
    /// ticket good for one attempt (RFC 9846 §8.1) as long as every server
    /// that honours the ticket shares that storage and its `take` is
    /// atomic. Early data under an external PSK has no protection at all,
    /// and the library records no ClientHellos and keeps no other
    /// anti-replay store. Without this option, `accept` hands the early
    /// data over only after the client's Finished, which a replay cannot
    /// produce. With it, act before the handshake completes only on
    /// requests that are safe to repeat (RFC 9846 §2.3 and §8; for HTTP,
    /// RFC 8470), and remember that a 0.5-RTT answer goes to a client that
    /// has not proved it holds the session's keys now. Early data also
    /// lacks forward secrecy with respect to the resumption secret or the
    /// external PSK.
    pub fn early_data(mut self, enabled: bool) -> Self {
        self.early_data = enabled;
        self
    }

    /// Accepts a TLS connection over `stream`. The returned future resolves
    /// once the handshake completes, or sooner for a connection with early
    /// data when [`early_data`](Self::early_data) is on.
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
            st: StreamState::new(self.revocation.for_stream()),
            early: self
                .early_data
                .then(|| EarlyPhase::new(self.inner.send_half_rtt_data)),
        }))
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
            early_data: false,
            revocation: RevocationSource::default(),
        }
    }
}

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor")
            .field("early_data", &self.early_data)
            .field("revocation", &self.revocation)
            .finish_non_exhaustive()
    }
}

/// A server handshake in progress; resolves to the accepted [`TlsStream`].
/// With [`TlsAcceptor::early_data`] or [`StartHandshake::early_data`] on,
/// it resolves before the handshake completes for a connection that has
/// early data to read.
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
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.map(TlsStream::accepted).map_err(|(err, _)| err))
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
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.map(TlsStream::accepted))
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
    /// Set while the stream was handed out before its handshake completed,
    /// to read early data.
    pub(crate) early: Option<EarlyPhase>,
}

impl<IO> TlsStream<IO> {
    /// A reader for the client's 0-RTT ("early") data, or `None` when this
    /// connection accepted none.
    ///
    /// On a stream returned before its handshake completed (see
    /// [`TlsAcceptor::early_data`]) the reader waits for early data that is
    /// still to arrive, and reaches end of file when the handshake is
    /// complete. Otherwise all of it is already buffered. Ordinary reads
    /// never return early data, and what is not read here stays readable
    /// after the handshake.
    ///
    /// A client sends the end of its early data only after the server's
    /// flight reached it: read a request by its own framing rather than to
    /// the end to answer without that round trip. The reader borrows the
    /// whole stream, so read the early data before splitting the stream
    /// into halves.
    ///
    /// Early data is **replayable**; see [`TlsAcceptor::early_data`].
    pub fn early_data(&mut self) -> Option<EarlyDataReader<'_, IO>> {
        self.session.early_data()?;
        Some(EarlyDataReader { stream: self })
    }

    /// The stream as the accept futures return it: one whose handshake
    /// completed is not in the early phase.
    fn accepted(mut self) -> Self {
        if !self.session.is_handshaking() {
            self.early = None;
        }
        self
    }

    /// The transport and the connection.
    pub fn get_ref(&self) -> (&IO, &ServerConnection) {
        (&self.io, &self.session)
    }

    /// The transport and the connection. Reading from or writing to the
    /// transport directly corrupts the TLS stream, and so does driving the
    /// connection's own I/O while the stream's handshake is in progress
    /// (see [`TlsAcceptor::early_data`]).
    pub fn get_mut(&mut self) -> (&mut IO, &mut ServerConnection) {
        (&mut self.io, &mut self.session)
    }

    /// The transport and the connection, ending the stream.
    ///
    /// A read error the stream kept for the next read is dropped with it.
    /// The connection keeps its own queues (records not yet written,
    /// plaintext not yet read). To move the connection to kernel TLS, use
    /// [`into_kernel_handoff`](Self::into_kernel_handoff), which settles
    /// all of that first.
    pub fn into_inner(self) -> (IO, ServerConnection) {
        (self.io, self.session)
    }

    /// Splits the stream into a read half and a write half that two tasks
    /// can use at the same time.
    ///
    /// The halves share the stream and take turns with it, one poll at a
    /// time. Neither ever blocks its thread for the other: a half that
    /// finds the other's poll in progress returns `Pending` and is woken
    /// when that poll ends. [`ReadHalf::reunite`] puts them back together.
    pub fn into_split(self) -> (ReadHalf<Self>, WriteHalf<Self>) {
        split::split(self)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Readies the stream for kernel TLS offload (see [`crate::kernel`]):
    /// writes and flushes every queued record, reads exactly up to the next
    /// record boundary, and sets the received plaintext (accepted 0-RTT
    /// data first) aside.
    ///
    /// 0-RTT data the server accepted and has not read with `early_data()`
    /// comes first in that plaintext, and can be replayed by an attacker:
    /// [`KernelHandoff::early_data_len`](crate::kernel::KernelHandoff::early_data_len)
    /// tells where it ends. The transport must not read ahead (see
    /// [`crate::kernel`]).
    ///
    /// A stream returned before its handshake completed (see
    /// [`TlsAcceptor::early_data`]) has the handshake completed first, as
    /// by a flush: what was written as 0.5-RTT data goes out, the future
    /// waits for the client's Finished, and a handshake that fails fails
    /// it, and every later operation of the stream that comes back, with
    /// its error. A connection that cannot be offloaded at all is refused
    /// only after that wait, too.
    ///
    /// The configuration must have `enable_secret_extraction` set. On
    /// failure the stream comes back in the
    /// [`KernelHandoffError`](crate::kernel::KernelHandoffError), with the
    /// data already taken out of it.
    pub fn into_kernel_handoff(self) -> IntoKernelHandoff<Self> {
        IntoKernelHandoff::new(self)
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ServerConnection;

    fn skip_handshake(&self) -> bool {
        false
    }

    fn returns_early(&self) -> bool {
        self.early.is_some()
    }

    fn early_phase_reached(session: &mut ServerConnection) -> bool {
        session.early_data().is_some()
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

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Ends the early phase, if any, before ordinary I/O: completes the
    /// handshake.
    pub(crate) fn poll_finish_early(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        early::poll_finish(
            &mut self.early,
            &mut self.io,
            &mut self.session,
            &mut self.st,
            cx,
        )
    }

    /// Ends the early phase for a read, which may take over the writer's
    /// registration while doing so. A read left waiting is woken when
    /// another operation moves the handshake on.
    fn poll_finish_early_for_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.early.is_none() {
            return Poll::Ready(Ok(()));
        }
        // The handshake writes too, and may take a parked writer's
        // registration: register both tasks, as answering reads do.
        let joint = common::joint_waker(cx.waker(), self.st.write_waker.as_ref());
        let poll = self.poll_finish_early(&mut Context::from_waker(&joint));
        if poll.is_pending()
            && let Some(early) = &mut self.early
        {
            early.park_reader(cx);
        }
        if poll.is_ready()
            && let Some(waker) = self.st.write_waker.take()
        {
            waker.wake();
        }
        poll
    }

    /// Ends the early phase for a write-side operation, which may take over
    /// the transport registration of a read waiting in the phase while it
    /// drives the handshake. It registers both tasks, so that the read is
    /// woken even if this operation is dropped before it ends the phase.
    fn poll_finish_early_for_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(early) = &self.early else {
            return Poll::Ready(Ok(()));
        };
        let joint = common::joint_waker(cx.waker(), early.read_waker());
        let poll = self.poll_finish_early(&mut Context::from_waker(&joint));
        self.st.track(cx, poll)
    }

    /// Runs the write `f` so that, in the early phase, a read waiting in the
    /// phase is registered with it: a write that goes out as 0.5-RTT data
    /// does not end the phase, and may take over the transport registration
    /// of a read that waits to flush what the handshake queued.
    fn write_with_early_reader<T>(
        &mut self,
        cx: &mut Context<'_>,
        f: impl FnOnce(&mut Self, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let Some(early) = &self.early else {
            return f(self, cx);
        };
        let joint = common::joint_waker(cx.waker(), early.read_waker());
        let poll = f(self, &mut Context::from_waker(&joint));
        // The writer is parked under its own waker, not the joint one.
        self.st.track(cx, poll)
    }

    /// The early-phase part of a write: `Ready(Ok(()))` once the connection
    /// may take the bytes. With 0.5-RTT data that is at once; otherwise the
    /// handshake completes first, as the connection would only hold them.
    fn poll_write_early(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &self.early {
            Some(early) if early.half_rtt() => Poll::Ready(early.check()),
            _ => self.poll_finish_early_for_write(cx),
        }
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
            ready!(this.poll_finish_early_for_read(cx))?;
            common::poll_read(&mut this.io, &mut this.session, &mut this.st, cx, buf)
        })
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncBufRead for TlsStream<IO> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        this.st.begin_poll();
        ready!(coop::poll_budget(cx));
        let poll = match this.poll_finish_early_for_read(cx) {
            Poll::Ready(Ok(())) => {
                common::poll_fill_buf(&mut this.io, &mut this.session, &mut this.st, cx)
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        };
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
            if !buf.is_empty() {
                ready!(this.poll_write_early(cx))?;
            }
            this.write_with_early_reader(cx, |this, cx| {
                common::poll_write(&mut this.io, &mut this.session, &mut this.st, cx, buf)
            })
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
            if !bufs.iter().all(|buf| buf.is_empty()) {
                ready!(this.poll_write_early(cx))?;
            }
            this.write_with_early_reader(cx, |this, cx| {
                common::poll_write_vectored(&mut this.io, &mut this.session, &mut this.st, cx, bufs)
            })
        })
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.st.begin_poll();
        coop::budgeted(cx, |cx| {
            if this.early.is_some() {
                // What was written as 0.5-RTT data reaches the peer before
                // the wait for the client's Finished: the handshake writes
                // what is queued and, told so here, flushes the transport
                // before it reads.
                this.st.need_flush = true;
                ready!(this.poll_finish_early_for_write(cx))?;
            }
            common::poll_flush(&mut this.io, &mut this.session, &mut this.st, cx)
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.st.begin_poll();
        coop::budgeted(cx, |cx| {
            ready!(this.poll_finish_early_for_write(cx))?;
            common::poll_shutdown(&mut this.io, &mut this.session, &mut this.st, cx)
        })
    }
}
