//! Readying a stream for kernel TLS offload.
//!
//! A connection can be handed to the kernel (Linux kernel TLS, see
//! [`browntls::kernel`]) only when nothing of it is in flight in
//! userspace: no record waiting to be written, no received record half
//! read, no plaintext the application has not seen. A stream holds all
//! three, and some of its own (a 0-RTT phase to finish, a read error kept
//! for the next read), so [`TlsStream::into_inner`] followed by
//! `dangerous_extract_secrets` either fails or, with the checks done by
//! hand, loses data.
//!
//! [`TlsStream::into_kernel_handoff`] drives the stream to that point
//! instead: it finishes a client's 0-RTT phase, writes and flushes every
//! queued record, reads exactly up to the next record boundary (the kernel
//! must start at one), answers what the records read on the way call for,
//! and takes the plaintext received so far out of the connection. The
//! [`KernelHandoff`] it resolves to holds the transport, the connection
//! (for `dangerous_into_kernel_connection`) and that plaintext, which the
//! application reads before anything the kernel delivers.
//!
//! The transport must not read ahead of what it is asked for (a buffered
//! reader would): the bytes after the record boundary are the kernel's, and
//! what a transport holds back never reaches it. Bytes it buffers for
//! writing are flushed.
//!
//! 0-RTT data a server accepted and has not read (it can be replayed, and
//! reads of the stream never return it) comes first in that plaintext;
//! [`KernelHandoff::early_data_len`] tells where it ends.
//!
//! The module makes no system call and works over any transport; an
//! asynchronous kernel TLS stream can be built on top of it.
//!
//! [`TlsStream::into_inner`]: crate::client::TlsStream::into_inner
//! [`TlsStream::into_kernel_handoff`]: crate::client::TlsStream::into_kernel_handoff

use std::fmt;
use std::future::Future;
use std::io::{self, BufRead as _, Read as _};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use browntls::kernel::KernelHandoffBlocker;
use browntls::{ClientConnection, ConnectionCommon, IoState, ServerConnection, SideData};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::{self, Stream, StreamState, SyncReadAdapter};
use crate::{client, server};

/// A stream ready to be handed to the kernel: nothing of its connection is
/// in flight, and the plaintext it had received is set aside.
///
/// [`into_parts`](KernelHandoff::into_parts) gives the transport, the
/// connection and that plaintext. The connection's
/// `dangerous_into_kernel_connection` then succeeds, as long as nothing is
/// read from or written to either in between. When the kernel turns the
/// connection down after all, [`into_stream`](Self::into_stream) goes on in
/// userspace.
pub struct KernelHandoff<S> {
    stream: S,
    received: Vec<u8>,
    early_data_len: usize,
}

impl<S> KernelHandoff<S> {
    /// The application data received before the handover and not read yet
    /// (0-RTT data a server accepted first): it comes before anything read
    /// afterwards.
    pub fn received(&self) -> &[u8] {
        &self.received
    }

    /// How many bytes at the start of [`received`](Self::received) are
    /// 0-RTT data a server accepted and had not read (`early_data()` of
    /// the connection). An attacker can replay that data, so a server must
    /// not act on it as on the rest. Zero for a client.
    pub fn early_data_len(&self) -> usize {
        self.early_data_len
    }

    /// Goes on in userspace: the stream, and the data to read before
    /// anything the stream yields. Its first
    /// [`early_data_len`](Self::early_data_len) bytes are 0-RTT data;
    /// take that length first, this drops it.
    pub fn into_stream(self) -> (S, Vec<u8>) {
        (self.stream, self.received)
    }
}

impl<IO> KernelHandoff<client::TlsStream<IO>> {
    /// The transport and the connection.
    pub fn get_ref(&self) -> (&IO, &ClientConnection) {
        self.stream.get_ref()
    }

    /// The transport, the connection to hand to the kernel, and the data to
    /// read before anything the kernel delivers.
    pub fn into_parts(self) -> (IO, ClientConnection, Vec<u8>) {
        let (io, conn) = self.stream.into_inner();
        (io, conn, self.received)
    }
}

impl<IO> KernelHandoff<server::TlsStream<IO>> {
    /// The transport and the connection.
    pub fn get_ref(&self) -> (&IO, &ServerConnection) {
        self.stream.get_ref()
    }

    /// The transport, the connection to hand to the kernel, and the data to
    /// read before anything the kernel delivers. Its first
    /// [`early_data_len`](Self::early_data_len) bytes are 0-RTT data;
    /// take that length first, this drops it.
    pub fn into_parts(self) -> (IO, ServerConnection, Vec<u8>) {
        let (io, conn) = self.stream.into_inner();
        (io, conn, self.received)
    }
}

/// `Debug` shows the length of the received data only: it is application
/// plaintext.
impl<S> fmt::Debug for KernelHandoff<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelHandoff")
            .field("received", &self.received.len())
            .field("early_data_len", &self.early_data_len)
            .finish_non_exhaustive()
    }
}

/// Why a stream was not made ready for the kernel.
///
/// Nothing is lost: the stream comes back with the application data the
/// attempt had already taken out of it.
#[non_exhaustive]
pub struct KernelHandoffError<S> {
    /// The stream. It is still usable when `error` has kind
    /// [`io::ErrorKind::Unsupported`] (the connection cannot be offloaded:
    /// a [`KernelHandoffBlocker`] that driving the stream does not clear)
    /// or wraps [`EarlyDataNotResent`](crate::client::EarlyDataNotResent),
    /// and it can still write and shut down when the error says that data
    /// follows the peer's `close_notify`
    /// ([`io::ErrorKind::InvalidData`] without a [`browntls::Error`]
    /// inside); after any other error it has failed like a stream whose
    /// read or write returned that error (a connection that had failed
    /// before reports its error again).
    pub stream: S,
    /// Application data taken from the stream before the error, to be read
    /// before anything the stream yields.
    pub received: Vec<u8>,
    /// How many bytes at the start of `received` are 0-RTT data a server
    /// accepted and had not read; see [`KernelHandoff::early_data_len`].
    pub early_data_len: usize,
    /// What stood in the way.
    pub error: io::Error,
}

impl<S> KernelHandoffError<S> {
    /// The error, dropping the stream and the received data.
    pub fn into_io_error(self) -> io::Error {
        self.error
    }
}

/// `Debug` shows the length of the received data only: it is application
/// plaintext.
impl<S> fmt::Debug for KernelHandoffError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelHandoffError")
            .field("error", &self.error)
            .field("received", &self.received.len())
            .field("early_data_len", &self.early_data_len)
            .finish_non_exhaustive()
    }
}

impl<S> fmt::Display for KernelHandoffError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream not ready for kernel TLS: {}", self.error)
    }
}

impl<S> std::error::Error for KernelHandoffError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The future of `into_kernel_handoff`; resolves to the [`KernelHandoff`].
///
/// The future owns the stream. To give up without losing it (after a
/// timeout, say), poll the future by reference and call
/// [`into_stream`](Self::into_stream).
#[must_use = "futures do nothing unless polled"]
pub struct IntoKernelHandoff<S> {
    /// `None` once the future returned.
    stream: Option<S>,
    taken: sealed::Taken,
}

impl<S> IntoKernelHandoff<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
            taken: sealed::Taken::default(),
        }
    }

    /// How many bytes at the start of the data taken so far are 0-RTT data
    /// a server accepted; see [`KernelHandoff::early_data_len`].
    pub fn early_data_len(&self) -> usize {
        self.taken.early_len
    }

    /// Gives up: the stream and the application data already taken out of
    /// it, to be read before anything the stream yields. Its first
    /// [`early_data_len`](Self::early_data_len) bytes are 0-RTT data; take
    /// that length first, this drops it. `None` once the future returned.
    pub fn into_stream(self) -> Option<(S, Vec<u8>)> {
        Some((self.stream?, self.taken.data))
    }
}

impl<S> fmt::Debug for IntoKernelHandoff<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntoKernelHandoff")
            .field("received", &self.taken.data.len())
            .field("early_data_len", &self.taken.early_len)
            .finish_non_exhaustive()
    }
}

mod sealed {
    use super::*;

    /// The plaintext taken out of a connection: accepted 0-RTT data (the
    /// first `early_len` bytes), then the rest.
    #[derive(Default)]
    pub struct Taken {
        pub(super) data: Vec<u8>,
        pub(super) early_len: usize,
    }

    /// Lengths only: the data is application plaintext.
    impl fmt::Debug for Taken {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Taken")
                .field("data", &self.data.len())
                .field("early_len", &self.early_len)
                .finish()
        }
    }

    /// A stream [`IntoKernelHandoff`] can drive.
    pub trait Prepare {
        /// Moves the stream towards a state with nothing in flight, putting
        /// the plaintext it takes out of the connection into `taken`.
        fn poll_prepare(&mut self, cx: &mut Context<'_>, taken: &mut Taken)
        -> Poll<io::Result<()>>;
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> sealed::Prepare for client::TlsStream<IO> {
    fn poll_prepare(
        &mut self,
        cx: &mut Context<'_>,
        taken: &mut sealed::Taken,
    ) -> Poll<io::Result<()>> {
        self.st.begin_poll();
        // The 0-RTT phase first: only the stream knows what to send again
        // when the server declined the early data.
        ready!(self.poll_finish_early(cx))?;
        poll_prepare(
            &mut self.io,
            &mut self.session,
            &mut self.st,
            cx,
            taken,
            |_, _| Ok(()),
        )
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> sealed::Prepare for server::TlsStream<IO> {
    fn poll_prepare(
        &mut self,
        cx: &mut Context<'_>,
        taken: &mut sealed::Taken,
    ) -> Poll<io::Result<()>> {
        self.st.begin_poll();
        poll_prepare(
            &mut self.io,
            &mut self.session,
            &mut self.st,
            cx,
            taken,
            |session, early_data| match session.early_data() {
                Some(mut early) => early.read_to_end(early_data).map(|_| ()),
                None => Ok(()),
            },
        )
    }
}

impl<S: sealed::Prepare + Unpin> Future for IntoKernelHandoff<S> {
    type Output = Result<KernelHandoff<S>, KernelHandoffError<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Like any future, this one must not be polled after it returned
        // `Ready`; by then the stream has been handed back.
        #[allow(clippy::panic)]
        let Some(mut stream) = this.stream.take() else {
            panic!("kernel handoff future polled after completion")
        };
        let result = match stream.poll_prepare(cx, &mut this.taken) {
            Poll::Ready(result) => result,
            Poll::Pending => {
                this.stream = Some(stream);
                return Poll::Pending;
            }
        };
        let sealed::Taken {
            data: received,
            early_len: early_data_len,
        } = std::mem::take(&mut this.taken);
        Poll::Ready(match result {
            Ok(()) => Ok(KernelHandoff {
                stream,
                received,
                early_data_len,
            }),
            Err(error) => Err(KernelHandoffError {
                stream,
                received,
                early_data_len,
                error,
            }),
        })
    }
}

/// One poll towards a connection with nothing in flight: `Ready(Ok(()))`
/// once [`ConnectionCommon::kernel_handoff_blocker`] reports nothing and
/// the transport is flushed.
///
/// Every round of the loop either clears the blocker it met, moves bytes,
/// or returns.
fn poll_prepare<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    st: &mut StreamState,
    cx: &mut Context<'_>,
    taken: &mut sealed::Taken,
    take_early_data: fn(&mut C, &mut Vec<u8>) -> io::Result<()>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if let Some(err) = st.deferred_error.take() {
        return Poll::Ready(Err(err));
    }
    loop {
        let Some(blocker) = session.kernel_handoff_blocker() else {
            // Nothing is queued any more; bytes a buffering transport still
            // holds must be out before the kernel writes behind them.
            ready!(Pin::new(&mut *io).poll_flush(cx))?;
            st.need_flush = false;
            return Poll::Ready(Ok(()));
        };
        match blocker {
            KernelHandoffBlocker::HandshakeIncomplete if session.is_handshaking() => {
                // A stream returned before its handshake completed. Plaintext
                // left unread (a server's 0-RTT data) would stall it.
                take_plaintext(session, taken, take_early_data)?;
                // The reads of this poll so far count for the task's
                // budget as in any operation of the stream.
                let mut stream = Stream::new(io, session)
                    .set_eof(!st.state.readable())
                    .set_need_flush(st.need_flush)
                    .set_read_before(st.read_before);
                let poll = stream.handshake(cx);
                st.need_flush = stream.need_flush;
                st.read_before = stream.read_before;
                ready!(poll)?;
            }
            KernelHandoffBlocker::UnreadPlaintext => {
                take_plaintext(session, taken, take_early_data)?;
            }
            KernelHandoffBlocker::UnsentRecords => {
                ready!(common::poll_flush(io, session, st, cx))?;
            }
            KernelHandoffBlocker::UnprocessedInput => {
                ready!(poll_to_record_boundary(io, session, cx))?;
            }
            KernelHandoffBlocker::KeyUpdatePending => {
                // Processing (nothing new) sends the KeyUpdate that is due.
                let _ = process(io, session, cx)?;
                if session.kernel_handoff_blocker() == Some(blocker) {
                    return Poll::Ready(Err(unsupported(blocker)));
                }
            }
            other => {
                // A connection that has failed says so (it reports an
                // incomplete handshake); any other blocker here is one
                // that driving the stream does not clear.
                let _ = process(io, session, cx)?;
                return Poll::Ready(Err(unsupported(other)));
            }
        }
    }
}

/// Moves the plaintext the connection holds for the application into
/// `taken`: accepted 0-RTT data in front, as it was sent first.
fn take_plaintext<C, SD>(
    session: &mut C,
    taken: &mut sealed::Taken,
    take_early_data: fn(&mut C, &mut Vec<u8>) -> io::Result<()>,
) -> io::Result<()>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    let mut early = Vec::new();
    let result = take_early_data(session, &mut early);
    // Kept even when taking it failed part of the way, and kept together
    // in front whatever was taken before.
    let at = taken.early_len;
    taken.early_len += early.len();
    taken.data.splice(at..at, early);
    result?;
    let received = &mut taken.data;
    let mut reader = session.reader();
    // An error here (`WouldBlock`, a truncated transport) says only that
    // nothing more is buffered; whoever reads next meets it again.
    while let Ok(chunk) = reader.fill_buf() {
        if chunk.is_empty() {
            break;
        }
        let len = chunk.len();
        received.extend_from_slice(chunk);
        reader.consume(len);
    }
    Ok(())
}

/// Processes the buffered records and, while a record is still incomplete,
/// reads towards its end and no byte beyond it (what follows is the
/// kernel's).
fn poll_to_record_boundary<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    let state = process(io, session, cx)?;
    if session.kernel_handoff_blocker() != Some(KernelHandoffBlocker::UnprocessedInput) {
        return Poll::Ready(Ok(()));
    }
    if state.peer_has_closed() {
        // The connection stops at the peer's close_notify: what follows
        // it, whole or in part, would stay unprocessed for good.
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "data follows the peer's close_notify",
        )));
    }
    let missing = session.bytes_to_record_boundary();
    if missing == 0 {
        // Whole records that processing left in place.
        return Poll::Ready(Err(unsupported(KernelHandoffBlocker::UnprocessedInput)));
    }
    let mut limited = SyncReadAdapter { io, cx }.take(missing as u64);
    match session.read_tls(&mut limited) {
        Ok(0) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed the connection inside a record",
        ))),
        // The next round processes what was read.
        Ok(_) => Poll::Ready(Ok(())),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(err) => Poll::Ready(Err(err)),
    }
}

/// Processes the buffered records. On failure the alert goes out if the
/// transport takes it now, as after a failed read.
fn process<IO, C, SD>(io: &mut IO, session: &mut C, cx: &mut Context<'_>) -> io::Result<IoState>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    match session.process_new_packets() {
        Ok(state) => Ok(state),
        Err(err) => {
            let _ = Stream::new(io, session).write_io(cx);
            Err(io::Error::new(io::ErrorKind::InvalidData, err))
        }
    }
}

fn unsupported(blocker: KernelHandoffBlocker) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, blocker.to_string())
}
