//! TLS 1.3 0-RTT ("early") data on the server: a stream handed out before
//! its handshake completes, and the reader for the early data.

use std::fmt;
use std::io::{self, Read as _};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use browntls::ServerConnection;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::TlsStream;
use crate::common::{HandshakeFailure, Stream, StreamState, coop, joint_waker};

/// A stream returned while its handshake is in progress, because the
/// client's early data was accepted.
#[derive(Debug)]
pub(crate) struct EarlyPhase {
    /// The connection sends application data before the client's Finished
    /// ([`ServerConfig::send_half_rtt_data`](browntls::ServerConfig)), so
    /// writes need not wait for the handshake.
    half_rtt: bool,
    /// The handshake failed: every later operation reports it.
    failure: Option<HandshakeFailure>,
    /// A read waiting for the handshake; woken when another operation moves
    /// it on, since that operation may have taken over the read's
    /// registration in the transport.
    read_waker: Option<Waker>,
}

impl EarlyPhase {
    pub(crate) fn new(half_rtt: bool) -> Self {
        Self {
            half_rtt,
            failure: None,
            read_waker: None,
        }
    }

    /// Whether writes go out now, as 0.5-RTT data, rather than after the
    /// handshake.
    pub(crate) fn half_rtt(&self) -> bool {
        self.half_rtt
    }

    /// The handshake failure, if it failed.
    pub(crate) fn check(&self) -> io::Result<()> {
        match &self.failure {
            Some(failure) => Err(failure.error()),
            None => Ok(()),
        }
    }

    /// Records the waker of a read that waits for the handshake.
    pub(crate) fn park_reader(&mut self, cx: &Context<'_>) {
        match &mut self.read_waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            slot => *slot = Some(cx.waker().clone()),
        }
    }

    /// The read waiting for the handshake, if any.
    pub(crate) fn read_waker(&self) -> Option<&Waker> {
        self.read_waker.as_ref()
    }

    fn wake_reader(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    fn fail(&mut self, err: &io::Error) {
        self.failure = Some(HandshakeFailure::new(err));
        self.wake_reader();
    }
}

/// Completes the handshake, flushes what it queued (the tickets) and ends
/// the early phase (`*slot` becomes `None`). A handshake failure is kept and
/// reported by every later call.
pub(crate) fn poll_finish<IO>(
    slot: &mut Option<EarlyPhase>,
    io: &mut IO,
    session: &mut ServerConnection,
    st: &mut StreamState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let Some(early) = slot else {
        return Poll::Ready(Ok(()));
    };
    early.check()?;
    let mut stream = Stream::new(io, session)
        .set_eof(!st.state.readable())
        .set_need_flush(st.need_flush)
        .set_read_before(st.read_before);
    while stream.session.is_handshaking() {
        let poll = stream.handshake(cx);
        st.need_flush = stream.need_flush;
        st.read_before = stream.read_before;
        match poll {
            // More early data may have arrived for a waiting reader.
            Poll::Ready(Ok(_)) => early.wake_reader(),
            Poll::Ready(Err(err)) => {
                early.fail(&err);
                return Poll::Ready(Err(err));
            }
            Poll::Pending => return Poll::Pending,
        }
    }
    ready!(Pin::new(&mut stream).poll_flush(cx))?;
    st.need_flush = false;
    early.wake_reader();
    *slot = None;
    Poll::Ready(Ok(()))
}

/// Copies buffered early data into `buf`; returns how much.
fn copy_buffered(session: &mut ServerConnection, buf: &mut ReadBuf<'_>) -> io::Result<usize> {
    let Some(mut early_data) = session.early_data() else {
        return Ok(0);
    };
    let n = early_data.read(buf.initialize_unfilled())?;
    buf.advance(n);
    Ok(n)
}

/// A read of early data: what is buffered, else what the handshake brings
/// in. Leaves `buf` as it was at the end of the early data, which is when
/// the handshake is complete. Early data that arrived before the handshake
/// failed is returned before the failure.
fn poll_read<IO>(
    slot: &mut Option<EarlyPhase>,
    io: &mut IO,
    session: &mut ServerConnection,
    st: &mut StreamState,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if buf.remaining() == 0 {
        return Poll::Ready(Ok(()));
    }
    loop {
        if copy_buffered(session, buf)? > 0 {
            return Poll::Ready(Ok(()));
        }
        let Some(early) = slot.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        early.check()?;
        if !session.is_handshaking() {
            return Poll::Ready(Ok(()));
        }

        // The handshake writes too, and may take a parked writer's
        // registration in the transport: register both tasks, as answering
        // reads do.
        let joint = joint_waker(cx.waker(), st.write_waker.as_ref());
        let mut stream = Stream::new(&mut *io, &mut *session)
            .set_eof(!st.state.readable())
            .set_need_flush(st.need_flush)
            .set_read_before(st.read_before);
        let poll = stream.handshake(&mut Context::from_waker(&joint));
        st.need_flush = stream.need_flush;
        st.read_before = stream.read_before;
        match poll {
            Poll::Pending => {
                // Another operation may take the registration over: it
                // wakes this read when it moves the handshake on.
                early.park_reader(cx);
                return Poll::Pending;
            }
            Poll::Ready(result) => {
                if let Err(err) = &result {
                    early.fail(err);
                }
                if let Some(waker) = st.write_waker.take() {
                    waker.wake();
                }
            }
        }
    }
}

/// Reads the 0-RTT ("early") data a client sent with its ClientHello; see
/// [`TlsStream::early_data`].
///
/// A read returns early data as it arrives, driving the handshake while it
/// waits. End of file comes once the handshake is complete and all early
/// data was read, so reading to the end also waits for the handshake. A
/// handshake that fails ends the reads with its error, after the early data
/// received before it.
///
/// Everything read here is **replayable** until the handshake completes;
/// see [`TlsAcceptor::early_data`](super::TlsAcceptor::early_data).
#[must_use = "readers do nothing unless read"]
pub struct EarlyDataReader<'a, IO> {
    pub(super) stream: &'a mut TlsStream<IO>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for EarlyDataReader<'_, IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = &mut *self.get_mut().stream;
        stream.st.begin_poll();
        coop::budgeted(cx, |cx| {
            poll_read(
                &mut stream.early,
                &mut stream.io,
                &mut stream.session,
                &mut stream.st,
                cx,
                buf,
            )
        })
    }
}

impl<IO> fmt::Debug for EarlyDataReader<'_, IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EarlyDataReader").finish_non_exhaustive()
    }
}
