//! The client side: [`TlsConnector`] and the client [`TlsStream`].

use std::fmt;
use std::future::Future;
use std::io::{self, BufRead as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use browntls_core::crypto::hpke::Hpke;
use browntls_core::ech::pem::{EchPem, EchPemError};
use browntls_core::ech::{EchConfig, EchMode};
use browntls_core::pki_types::ServerName;
use browntls_core::{ClientConfig, ClientConnection, ClientServerIdentity};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::client_early::EarlyResult;
use crate::common::{self, IoSession, MidHandshake, RevocationSource, StreamState, coop};
use crate::kernel::IntoKernelHandoff;
use crate::split::{self, ReadHalf, WriteHalf};

mod early;
pub use crate::client_early::{EarlyDataNotResent, EarlyDataOutcome, RejectedEarlyDataPolicy};
use early::EarlyData;

/// Starts client handshakes with a shared [`ClientConfig`].
///
/// Cheap to clone; create one per configuration and reuse it.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
    early_data: bool,
    rejected_early_data: RejectedEarlyDataPolicy,
    revocation: RevocationSource,
}

impl TlsConnector {
    /// Replaces the ECH mode in `config` with the first usable configuration
    /// from `pem`, using the caller's HPKE `suites`.
    ///
    /// All other client settings are preserved. Real ECH requires TLS 1.3.
    pub fn from_ech_pem(
        mut config: ClientConfig,
        pem: &EchPem,
        suites: &[&'static dyn Hpke],
    ) -> Result<Self, EchPemError> {
        config.ech_mode = Some(EchMode::Enable(EchConfig::from_pem(pem, suites)?));
        Ok(Self::from(Arc::new(config)))
    }

    /// Answers the certificate status (OCSP) queries of this connector's
    /// connections with `fetcher`: during the handshake, and in reads
    /// after it. Without one, such a query is answered as unavailable at
    /// once. See [`crate::revocation`].
    #[cfg(feature = "ocsp")]
    pub fn revocation_fetcher(
        mut self,
        fetcher: Arc<crate::revocation::RevocationFetcher>,
    ) -> Self {
        self.revocation.set_fetcher(fetcher);
        self
    }

    /// Whether [`connect`](Self::connect) may return before the handshake,
    /// to send 0-RTT ("early") data. Off by default.
    ///
    /// It does when the configuration enables early data
    /// ([`ClientConfig::enable_early_data`]) and the selected PSK permits
    /// it. The first read, flush, shutdown or write beyond the allowance
    /// finishes the handshake. The resend policy defaults to reporting
    /// rejected bytes for the application to handle.
    ///
    /// Early data is replayable. Send only requests that are safe to repeat.
    pub fn early_data(mut self, enabled: bool) -> Self {
        self.early_data = enabled;
        self
    }

    /// Sets how the adapter handles early data the server declines.
    /// This does not enable early writes.
    pub fn rejected_early_data_policy(mut self, policy: RejectedEarlyDataPolicy) -> Self {
        self.rejected_early_data = policy;
        self
    }

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
        F: FnOnce(&mut ClientConnection),
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
        F: FnOnce(&mut ClientConnection),
    {
        let alpn = alpn_protocols.unwrap_or_else(|| self.inner.alpn_protocols.clone());
        self.finish_connect(
            stream,
            ClientConnection::new_with_alpn(self.inner.clone(), domain, alpn),
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
        F: FnOnce(&mut ClientConnection),
    {
        let alpn = alpn_protocols.unwrap_or_else(|| self.inner.alpn_protocols.clone());
        self.finish_connect(
            stream,
            ClientConnection::new_with_identity_and_alpn(self.inner.clone(), identity, alpn),
            f,
        )
    }

    fn finish_connect<IO, F>(
        &self,
        stream: IO,
        result: Result<ClientConnection, browntls_core::Error>,
        f: F,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ClientConnection),
    {
        let mut session = match result {
            Ok(session) => session,
            Err(error) => {
                return Connect(MidHandshake::Error {
                    io: stream,
                    error: io::Error::other(error),
                });
            }
        };
        f(&mut session);

        let early = (self.early_data && session.early_data().is_some())
            .then(|| EarlyData::new(self.rejected_early_data));
        let early_result = if early.is_some() {
            EarlyResult::pending()
        } else {
            EarlyResult::default()
        };
        Connect(MidHandshake::Handshaking(TlsStream {
            io: stream,
            session,
            st: StreamState::new(self.revocation.for_stream()),
            early,
            early_result,
        }))
    }
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> Self {
        Self {
            inner,
            early_data: false,
            rejected_early_data: RejectedEarlyDataPolicy::default(),
            revocation: RevocationSource::default(),
        }
    }
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector")
            .field("early_data", &self.early_data)
            .field("rejected_early_data", &self.rejected_early_data)
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

    /// [`TlsConnector::connect_with`] with these ALPN protocols.
    pub fn connect_with<IO, F>(self, domain: ServerName<'static>, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ClientConnection),
    {
        self.inner
            .connect_impl(domain, stream, Some(self.alpn_protocols), f)
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
        F: FnOnce(&mut ClientConnection),
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

/// A client handshake in progress; resolves to the connected [`TlsStream`].
///
/// Errors are `io::Error`s. A TLS failure has kind `InvalidData` and wraps
/// the [`browntls_core::Error`], which `get_ref` and `downcast_ref` recover.
/// Creating the connection can fail too, before any I/O: that error has
/// kind `Other` and wraps the [`browntls_core::Error`] the same way.
#[must_use = "futures do nothing unless polled"]
pub struct Connect<IO>(MidHandshake<TlsStream<IO>>);

impl<IO> Connect<IO> {
    /// Turns this into a future that also hands the transport back on error.
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

    /// The connection while the handshake runs, for a caller that polls
    /// this future itself and looks at the handshake between polls (which
    /// messages arrived, what was negotiated so far). Until the handshake
    /// completes, what it shows is not authenticated.
    ///
    /// `None` once the future returned, and when the connection could not
    /// be created, which the future's first poll reports.
    pub fn connection(&self) -> Option<&ClientConnection> {
        self.0.session()
    }

    /// Like [`connection`](Self::connection), for calls that need `&mut`.
    ///
    /// The future drives the connection's I/O: reading or writing TLS
    /// records or plaintext through this reference disturbs the handshake.
    pub fn connection_mut(&mut self) -> Option<&mut ClientConnection> {
        self.0.session_mut()
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

impl<IO> FallibleConnect<IO> {
    /// The transport, unless the future already returned.
    pub fn get_ref(&self) -> Option<&IO> {
        self.0.io()
    }

    /// The transport, unless the future already returned.
    pub fn get_mut(&mut self) -> Option<&mut IO> {
        self.0.io_mut()
    }

    /// The connection while the handshake runs; see
    /// [`Connect::connection`].
    pub fn connection(&self) -> Option<&ClientConnection> {
        self.0.session()
    }

    /// The connection while the handshake runs; see
    /// [`Connect::connection_mut`].
    pub fn connection_mut(&mut self) -> Option<&mut ClientConnection> {
        self.0.session_mut()
    }
}

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
    /// Set while the handshake is unfinished and early data may be sent.
    pub(crate) early: Option<EarlyData>,
    early_result: EarlyResult,
}

impl<IO> TlsStream<IO> {
    /// Returns the local early-data outcome without consuming it.
    pub fn early_data_outcome(&self) -> EarlyDataOutcome {
        self.early_result.outcome
    }

    /// Acknowledges unresent early data, returning its byte count once.
    ///
    /// Subsequent writes may proceed. The caller decides what to send.
    pub fn acknowledge_rejected_early_data(&mut self) -> Option<usize> {
        self.early_result.acknowledge()
    }

    /// The transport and the connection.
    pub fn get_ref(&self) -> (&IO, &ClientConnection) {
        (&self.io, &self.session)
    }

    /// The transport and the connection. Reading from or writing to the
    /// transport directly corrupts the TLS stream. Use the stream's writer
    /// for early data so that the adapter accounts for those bytes.
    pub fn get_mut(&mut self) -> (&mut IO, &mut ClientConnection) {
        (&mut self.io, &mut self.session)
    }

    /// The transport and the connection, ending the stream.
    ///
    /// Whatever the stream still held is dropped with it: an unfinished
    /// 0-RTT phase and the early data it would send again, a read error
    /// kept for the next read. The connection keeps its own queues (records
    /// not yet written, plaintext not yet read). To move the connection to
    /// kernel TLS, use [`into_kernel_handoff`](Self::into_kernel_handoff),
    /// which settles all of that first.
    pub fn into_inner(self) -> (IO, ClientConnection) {
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

impl<IO> ReadHalf<TlsStream<IO>> {
    /// Returns the shared stream's local early-data outcome.
    pub async fn early_data_outcome(&mut self) -> io::Result<EarlyDataOutcome> {
        self.inspect(TlsStream::early_data_outcome).await
    }
}

impl<IO> WriteHalf<TlsStream<IO>> {
    /// Returns the shared stream's local early-data outcome.
    pub async fn early_data_outcome(&mut self) -> io::Result<EarlyDataOutcome> {
        self.inspect(|stream| stream.early_data_outcome()).await
    }

    /// Acknowledges unresent early data on the shared stream.
    pub async fn acknowledge_rejected_early_data(&mut self) -> io::Result<Option<usize>> {
        self.inspect(TlsStream::acknowledge_rejected_early_data)
            .await
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> WriteHalf<TlsStream<IO>> {
    /// Completes the shared stream's early phase and returns its outcome.
    pub async fn finish_early_data(&mut self) -> io::Result<EarlyDataOutcome> {
        self.drive(TlsStream::poll_early_data_outcome).await
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Completes the early phase and returns its outcome. A rejected
    /// outcome leaves the stream usable after acknowledgement.
    pub async fn finish_early_data(&mut self) -> io::Result<EarlyDataOutcome> {
        std::future::poll_fn(|cx| self.poll_early_data_outcome(cx)).await
    }

    pub(crate) fn poll_early_data_outcome(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<EarlyDataOutcome>> {
        self.st.begin_poll();
        coop::budgeted(cx, |cx| {
            ready!(self.poll_drive_early_for_write(cx))?;
            Poll::Ready(Ok(self.early_data_outcome()))
        })
    }

    /// Readies the stream for kernel TLS offload (see [`crate::kernel`]):
    /// completes the handshake of a stream returned early for 0-RTT data
    /// (sending declined early data again where that is allowed), writes
    /// and flushes every queued record, reads exactly up to the next record
    /// boundary, and sets the received plaintext aside. The transport must
    /// not read ahead (see [`crate::kernel`]).
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
    type Session = ClientConnection;

    fn skip_handshake(&self) -> bool {
        self.early.is_some()
    }

    fn refs(&self) -> (&IO, &ClientConnection) {
        (&self.io, &self.session)
    }

    fn parts(&mut self) -> (&mut StreamState, &mut IO, &mut ClientConnection) {
        (&mut self.st, &mut self.io, &mut self.session)
    }

    fn into_io(self) -> IO {
        self.io
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Ends the early-data phase, if any, before ordinary I/O: completes the
    /// handshake and resends declined early data.
    pub(crate) fn poll_finish_early(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        early::poll_finish(
            &mut self.early,
            &mut self.early_result,
            &mut self.io,
            &mut self.session,
            &mut self.st,
            cx,
        )
    }

    /// A write of nothing: moves nothing, and fails as a write would after
    /// the early phase (a kept handshake failure or an unacknowledged
    /// rejection) or after `shutdown`.
    fn empty_write(&self) -> io::Result<usize> {
        self.early_result.check_write()?;
        common::empty_write(&self.st)
    }

    pub(crate) fn poll_finish_early_for_write(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_drive_early_for_write(cx))?;
        Poll::Ready(self.early_result.check_write())
    }

    fn poll_drive_early_for_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let joint = self
            .early
            .as_ref()
            .and_then(EarlyData::read_waker)
            .filter(|reader| !reader.will_wake(cx.waker()))
            .map(|reader| common::joint_waker(cx.waker(), Some(reader)));
        let poll = match &joint {
            Some(waker) => self.poll_finish_early(&mut Context::from_waker(waker)),
            None => self.poll_finish_early(cx),
        };
        self.st.track(cx, poll)
    }

    /// The early-data part of a write: `Ready(Ok(n))` with `n > 0` when
    /// early data took the bytes, `Ready(Ok(0))` when the write should go
    /// the ordinary way.
    fn poll_write_early(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let Some(early) = &mut self.early else {
            return Poll::Ready(self.early_result.check_write().map(|()| 0));
        };
        match early::write(early, &mut self.session, bufs) {
            Ok(0) => {}
            other => return Poll::Ready(other),
        }
        self.poll_finish_early_for_write(cx).map_ok(|()| 0)
    }

    /// Ends the early-data phase for a read, which may have taken over the
    /// writer's registration while doing so. A read left waiting is woken
    /// when another operation ends the phase.
    fn poll_finish_early_for_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.early.is_none() {
            return Poll::Ready(self.early_result.failure());
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
        if buf.is_empty() {
            return Poll::Ready(this.empty_write());
        }
        coop::budgeted(cx, |cx| {
            match ready!(this.poll_write_early(cx, &[io::IoSlice::new(buf)]))? {
                0 => common::poll_write(&mut this.io, &mut this.session, &mut this.st, cx, buf),
                n => Poll::Ready(Ok(n)),
            }
        })
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.st.begin_poll();
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(this.empty_write());
        }
        coop::budgeted(cx, |cx| match ready!(this.poll_write_early(cx, bufs))? {
            0 => {
                common::poll_write_vectored(&mut this.io, &mut this.session, &mut this.st, cx, bufs)
            }
            n => Poll::Ready(Ok(n)),
        })
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.st.begin_poll();
        coop::budgeted(cx, |cx| {
            ready!(this.poll_finish_early_for_write(cx))?;
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
