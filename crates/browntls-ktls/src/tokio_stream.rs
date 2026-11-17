//! [`AsyncKtlsStream`]: a Tokio TCP socket whose records the kernel
//! protects, and the handover of `browntls-tokio` streams.
//!
//! The socket's readiness comes from Tokio; the kernel TLS system calls
//! are the ones [`KtlsStream`](crate::KtlsStream) makes, through the same
//! [`Engine`], each inside `TcpStream::try_io` so that a call that finds
//! the socket not ready clears Tokio's readiness and the task is woken
//! when it changes.

use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use browntls::SideData;
use browntls::client::ClientConnectionData;
use browntls::kernel::{KernelConnection, KernelHandoffBlocker};
use browntls::server::ServerConnectionData;
use browntls_tokio::{client, server};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;

use crate::engine::Engine;
use crate::stream::{HandoffError, Offload, check_record_size, install, refused, unsupported};
use crate::sys;

/// Why a `browntls-tokio` stream was not handed to the kernel
/// ([`AsyncKtlsStream::from_client`], [`AsyncKtlsStream::from_server`]).
pub enum StreamHandoffError<S> {
    /// Nothing was given to the kernel, and nothing is lost: the stream
    /// comes back with the application data the handover had already taken
    /// out of it.
    ///
    /// The stream goes on in userspace when `error` has kind
    /// [`io::ErrorKind::Unsupported`] (the connection cannot be offloaded,
    /// or the peer's `record_size_limit` needs a newer kernel), when it is
    /// the kernel's refusal of the `tls` upper layer protocol (no `tls`
    /// module: `ENOENT`; a peer that has already closed TCP: `ENOTCONN`,
    /// since the kernel attaches it to an established connection only), or
    /// when it wraps
    /// [`EarlyDataNotResent`](browntls_tokio::client::EarlyDataNotResent).
    /// After any other error the stream has failed like one whose read or
    /// write returned that error.
    ///
    /// The socket may carry the kernel's `tls` upper layer protocol without
    /// keys, which leaves its bytes untouched.
    Refused {
        /// The stream.
        stream: S,
        /// Application data taken from the stream, to be read before
        /// anything the stream yields.
        received: Vec<u8>,
        /// What stood in the way.
        error: io::Error,
    },
    /// The kernel took part of the connection's state and then failed: the
    /// connection is lost and the socket was closed.
    Failed(io::Error),
}

impl<S> StreamHandoffError<S> {
    /// The error, dropping the stream.
    pub fn into_io_error(self) -> io::Error {
        match self {
            Self::Refused { error, .. } | Self::Failed(error) => error,
        }
    }
}

/// `Debug` shows the length of the received data only: it is application
/// plaintext.
impl<S> fmt::Debug for StreamHandoffError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused {
                error, received, ..
            } => f
                .debug_struct("Refused")
                .field("error", error)
                .field("received", &received.len())
                .finish_non_exhaustive(),
            Self::Failed(error) => f.debug_tuple("Failed").field(error).finish(),
        }
    }
}

impl<S> fmt::Display for StreamHandoffError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { error, .. } => write!(f, "kernel TLS handover refused: {error}"),
            Self::Failed(error) => write!(f, "kernel TLS handover failed: {error}"),
        }
    }
}

impl<S> std::error::Error for StreamHandoffError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused { error, .. } | Self::Failed(error) => Some(error),
        }
    }
}

/// A Tokio TCP socket whose records Linux kernel TLS protects: the
/// asynchronous [`KtlsStream`](crate::KtlsStream).
///
/// Reads return the application data the kernel decrypted; records of
/// other types are handled on the way (a TLS 1.3 KeyUpdate is answered and
/// the new keys installed, tickets are stored, `close_notify` is end of
/// file). Writes give the bytes to the kernel and count the records it
/// makes of them against the cipher suite's confidentiality limit,
/// refreshing the TLS 1.3 keys when it is reached.
/// [`shutdown`](AsyncWrite::poll_shutdown) sends `close_notify` and shuts
/// the socket's write side; writes then fail with `BrokenPipe`.
///
/// A read that owes the peer something (a KeyUpdate answer, a
/// post-handshake authentication response) sends it as far as the socket
/// has room and, while some is left, is also woken when the socket has
/// room again; a write or flush sends it too. A TCP connection that ends
/// without `close_notify` fails the read with `UnexpectedEof`. Errors from
/// the connection are [`io::ErrorKind::InvalidData`] with the
/// [`browntls::Error`] inside; the stream has then failed for good, and
/// `flush` or `shutdown` sends its alert.
///
/// [`tokio::io::split`] gives halves for two tasks. The limitation of
/// [`KtlsStream`](crate::KtlsStream) with KeyUpdate records that are not
/// one whole KeyUpdate applies here too.
///
/// ```no_run
/// # async fn run(
/// #     config: std::sync::Arc<browntls::ClientConfig>,
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// // `config` has `enable_secret_extraction` set.
/// let tcp = tokio::net::TcpStream::connect("example.com:443").await?;
/// let tls = browntls_tokio::TlsConnector::from(config)
///     .connect("example.com".try_into()?, tcp)
///     .await?;
/// let mut tls = browntls_ktls::AsyncKtlsStream::from_client(tls)
///     .await
///     .map_err(|e| e.into_io_error())?;
/// tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
/// let mut response = Vec::new();
/// tls.read_to_end(&mut response).await?;
/// # Ok(())
/// # }
/// ```
///
/// [`tokio::io::split`]: https://docs.rs/tokio/1/tokio/io/fn.split.html
pub struct AsyncKtlsStream<Data> {
    socket: TcpStream,
    engine: Engine<Data>,
    /// The waker of the last write, flush or shutdown that returned
    /// `Pending`. A read that sends what the connection owes takes over
    /// the socket's write-readiness registration, so it registers this
    /// waker along with its own.
    write_waker: Option<Waker>,
    /// The waker of a read that waits for room to send what the connection
    /// owes. A write, flush or shutdown takes the registration back, so it
    /// registers this waker along with its own.
    read_waker: Option<Waker>,
    /// `shutdown` has queued `close_notify`.
    closing: bool,
}

/// Nothing in the stream is pinned: the socket and the connection state
/// are moved freely between polls.
impl<Data> Unpin for AsyncKtlsStream<Data> {}

impl<Data: SideData> AsyncKtlsStream<Data> {
    /// Hands `conn` to the kernel on `socket`.
    ///
    /// `conn` must have nothing in flight: its handshake complete, no
    /// record queued or partly received, no plaintext unread
    /// (`kernel_handoff_blocker` reports nothing), as
    /// `into_kernel_handoff` of a `browntls-tokio` stream leaves it.
    /// `received` is the application data taken out of it, which the
    /// stream returns before anything the kernel delivers. Otherwise, and
    /// when the kernel lacks TLS support, everything comes back in
    /// [`HandoffError::Refused`].
    ///
    /// [`from_client`](AsyncKtlsStream::from_client) and
    /// [`from_server`](AsyncKtlsStream::from_server) do all of this for a
    /// `browntls-tokio` stream.
    pub fn new<C>(
        conn: C,
        socket: TcpStream,
        received: Vec<u8>,
    ) -> Result<Self, HandoffError<C, TcpStream>>
    where
        C: Offload<Data = Data>,
    {
        let ready = match conn.kernel_handoff_blocker() {
            Some(blocker) => Err(unsupported(blocker)),
            None => sys::set_ulp_tls(socket.as_fd())
                .and_then(|()| check_record_size(&conn, socket.as_fd())),
        };
        if let Err(error) = ready {
            return Err(refused(conn, socket, received, error));
        }
        match install(conn, socket.as_fd(), received) {
            Ok(engine) => Ok(Self::with_engine(socket, engine)),
            Err(error) => Err(HandoffError::Failed(error)),
        }
    }

    fn with_engine(socket: TcpStream, engine: Engine<Data>) -> Self {
        Self {
            socket,
            engine,
            write_waker: None,
            read_waker: None,
            closing: false,
        }
    }

    /// The connection's state after the handover.
    pub fn kernel_connection(&self) -> &KernelConnection<Data> {
        self.engine.conn()
    }

    /// The socket.
    ///
    /// Bytes sent on it directly (for example with `sendfile`) become
    /// application data records the stream did not count: report them with
    /// [`Self::records_sent`]. Reading from it directly loses the records
    /// that are not application data.
    pub fn get_ref(&self) -> &TcpStream {
        &self.socket
    }

    /// Reports `records` application data records sent on the socket
    /// directly, then carries out what the connection asks for (a key
    /// refresh at the confidentiality limit) as far as the socket has
    /// room; the rest is sent by the next write or flush. Overcount when
    /// unsure: one `send` of `n` bytes without `MSG_MORE` makes at most
    /// `n.div_ceil(16384)` records.
    pub fn records_sent(&mut self, records: u64) -> io::Result<()> {
        self.engine.records_sent(self.socket.as_fd(), records)
    }

    /// Rotates the TLS 1.3 transmit keys and asks the peer to rotate
    /// theirs. A KeyUpdate the socket has no room for is sent, and the new
    /// keys installed, by the next write or flush.
    pub fn refresh_traffic_keys(&mut self) -> io::Result<()> {
        self.engine.refresh_traffic_keys(self.socket.as_fd())
    }

    /// For a read: sends what the connection owes as far as the socket has
    /// room. When it has none, the reader is registered for writability,
    /// together with a parked writer, whose registration this replaces.
    fn poll_send_owed(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        while self.engine.has_outputs() {
            let joint = joint_waker(cx.waker(), self.write_waker.as_ref());
            match self
                .socket
                .poll_write_ready(&mut Context::from_waker(&joint))
            {
                Poll::Pending => {
                    park(&mut self.read_waker, cx);
                    return Ok(());
                }
                Poll::Ready(Err(err)) => return Err(err),
                Poll::Ready(Ok(())) => {}
            }
            let Self { socket, engine, .. } = &mut *self;
            match socket.try_io(Interest::WRITABLE, || engine.flush_outputs(socket.as_fd())) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => {
                    // The connection failed: a parked writer must see it.
                    if let Some(waker) = self.write_waker.take() {
                        waker.wake();
                    }
                    return Err(err);
                }
            }
        }
        self.read_waker = None;
        Ok(())
    }

    /// For a write, flush or shutdown: runs `op`, which fails with
    /// `WouldBlock` only when the socket has no room, once the socket is
    /// writable. A read waiting for room is registered along with the
    /// caller, whose registration replaces the read's.
    fn poll_writable<R>(
        &mut self,
        cx: &mut Context<'_>,
        mut op: impl FnMut(&mut Engine<Data>, BorrowedFd<'_>) -> io::Result<R>,
    ) -> Poll<io::Result<R>> {
        loop {
            let joint = joint_waker(cx.waker(), self.read_waker.as_ref());
            match self
                .socket
                .poll_write_ready(&mut Context::from_waker(&joint))
            {
                Poll::Pending => {
                    park(&mut self.write_waker, cx);
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
            let Self { socket, engine, .. } = &mut *self;
            match socket.try_io(Interest::WRITABLE, || op(engine, socket.as_fd())) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                result => {
                    self.write_waker = None;
                    if !self.engine.has_outputs() {
                        // Nothing is left for a waiting read to send.
                        self.read_waker = None;
                    }
                    return Poll::Ready(result);
                }
            }
        }
    }
}

/// The handover of a `browntls-tokio` stream, for either side.
macro_rules! from_stream {
    ($name:ident, $stream:ty, $data:ty, $side:literal) => {
        impl AsyncKtlsStream<$data> {
            #[doc = concat!("Hands a `browntls-tokio` ", $side, " stream over a Tokio TCP socket to the kernel.")]
            ///
            /// The stream's configuration must have
            /// `enable_secret_extraction` set. A stream that cannot be
            /// offloaded, a kernel without TLS support and a peer that
            /// has already closed TCP are found out before anything is
            /// taken from the stream. Then the stream
            /// is readied with `into_kernel_handoff` (its handshake and
            /// 0-RTT phase completed, queued records written, the input
            /// read up to a record boundary) and the keys are installed.
            /// The application data received before that is returned by
            /// the first reads.
            ///
            /// Until the keys are installed every failure returns the
            /// stream ([`StreamHandoffError::Refused`]). Dropping the
            /// future drops the stream with it; to keep it across a
            /// timeout, call `into_kernel_handoff` and
            /// [`AsyncKtlsStream::new`] instead.
            // The error hands the stream back, once per connection.
            #[allow(clippy::result_large_err)]
            pub async fn $name(stream: $stream) -> Result<Self, StreamHandoffError<$stream>> {
                let (socket, conn) = stream.get_ref();
                let ready = match conn.kernel_handoff_blocker() {
                    Some(blocker) if permanent(blocker, conn.is_handshaking()) => {
                        Err(unsupported(blocker))
                    }
                    // Checks kernel support before anything is consumed:
                    // with the upper layer protocol attached but no keys,
                    // the socket passes its bytes through unchanged.
                    _ => sys::set_ulp_tls(socket.as_fd()),
                };
                if let Err(error) = ready {
                    return Err(StreamHandoffError::Refused {
                        stream,
                        received: Vec::new(),
                        error,
                    });
                }
                let handoff = match stream.into_kernel_handoff().await {
                    Ok(handoff) => handoff,
                    Err(err) => {
                        return Err(StreamHandoffError::Refused {
                            stream: err.stream,
                            received: err.received,
                            error: err.error,
                        });
                    }
                };
                let (socket, conn) = handoff.get_ref();
                if let Err(error) = check_record_size(conn, socket.as_fd()) {
                    let (stream, received) = handoff.into_stream();
                    return Err(StreamHandoffError::Refused {
                        stream,
                        received,
                        error,
                    });
                }
                let (socket, conn, received) = handoff.into_parts();
                match install(conn, socket.as_fd(), received) {
                    Ok(engine) => Ok(Self::with_engine(socket, engine)),
                    Err(error) => Err(StreamHandoffError::Failed(error)),
                }
            }
        }
    };
}

from_stream!(
    from_client,
    client::TlsStream<TcpStream>,
    ClientConnectionData,
    "client"
);
from_stream!(
    from_server,
    server::TlsStream<TcpStream>,
    ServerConnectionData,
    "server"
);

/// Whether driving a stream on cannot clear `blocker`.
fn permanent(blocker: KernelHandoffBlocker, handshaking: bool) -> bool {
    match blocker {
        KernelHandoffBlocker::HandshakeIncomplete => !handshaking,
        KernelHandoffBlocker::SecretExtractionDisabled
        | KernelHandoffBlocker::Quic
        | KernelHandoffBlocker::UnsupportedCipherSuite
        | KernelHandoffBlocker::Closed
        | KernelHandoffBlocker::FragmentTooSmall => true,
        _ => false,
    }
}

impl<Data: SideData> AsyncRead for AsyncKtlsStream<Data> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            // Plaintext from before the handover, the peer's closure and a
            // failure are reported without asking the kernel.
            let direct = this.engine.reads_without_socket();
            if !direct {
                this.poll_send_owed(cx)?;
                match this.socket.poll_read_ready(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let Self { socket, engine, .. } = &mut *this;
            let fd = socket.as_fd();
            let result = if direct {
                engine.read(fd, buf.initialize_unfilled())
            } else {
                // Fails with `WouldBlock` only when the kernel has no
                // record to give.
                socket.try_io(Interest::READABLE, || {
                    engine.read(fd, buf.initialize_unfilled())
                })
            };
            match result {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }
}

impl<Data: SideData> AsyncWrite for AsyncKtlsStream<Data> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Err(err) = this.engine.check() {
            return Poll::Ready(Err(err));
        }
        this.poll_writable(cx, |engine, fd| engine.write(fd, buf))
    }

    /// Sends what waits, including a fatal alert after a failure. The
    /// kernel sends application data as it is written.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.engine.has_outputs() {
            return Poll::Ready(this.engine.check());
        }
        this.poll_writable(cx, |engine, fd| engine.flush(fd))
    }

    /// Sends `close_notify` (an alert instead, after a failure), then
    /// shuts the socket's write side. Reads go on until the peer's
    /// `close_notify`.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closing {
            this.closing = true;
            // A failed connection has queued or sent its alert instead.
            let _ = this.engine.queue_close_notify();
        }
        if this.engine.has_outputs() {
            match this.poll_writable(cx, |engine, fd| engine.flush_outputs(fd)) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut this.socket).poll_shutdown(cx) {
            // A socket that is already gone has nothing left to shut.
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::NotConnected => {
                Poll::Ready(Ok(()))
            }
            poll => poll,
        }
    }
}

impl<Data> AsFd for AsyncKtlsStream<Data> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl<Data> AsRawFd for AsyncKtlsStream<Data> {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl<Data> fmt::Debug for AsyncKtlsStream<Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncKtlsStream")
            .field("engine", &self.engine)
            .field("closing", &self.closing)
            .finish_non_exhaustive()
    }
}

/// Records the waker of a poll about to wait.
fn park(slot: &mut Option<Waker>, cx: &Context<'_>) {
    match slot {
        Some(waker) if waker.will_wake(cx.waker()) => {}
        slot => *slot = Some(cx.waker().clone()),
    }
}

/// Wakes two tasks: the one registering for the socket's writability, and
/// the one whose registration that replaces.
struct JointWaker {
    own: Waker,
    other: Waker,
}

impl Wake for JointWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.own.wake_by_ref();
        self.other.wake_by_ref();
    }
}

/// `own`, or a waker for both `own` and `other` when another task is
/// parked.
fn joint_waker(own: &Waker, other: Option<&Waker>) -> Waker {
    match other {
        Some(other) if !other.will_wake(own) => Waker::from(Arc::new(JointWaker {
            own: own.clone(),
            other: other.clone(),
        })),
        _ => own.clone(),
    }
}
