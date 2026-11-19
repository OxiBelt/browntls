//! The polling core shared by the client and server streams: moving TLS
//! records between a `browntls` connection and an `AsyncRead + AsyncWrite`
//! transport without blocking.
//!
//! Adapted from tokio-rustls (`src/common/mod.rs`, Copyright (c) 2017
//! quininer kel, MIT OR Apache-2.0), used here under Apache-2.0. Changes:
//! browntls types, writes that cannot spin on a connection that takes no
//! plaintext, a handshake exit when no progress is possible, reads that
//! send the answers the peer waits for, reads that wait for those answers
//! to be written before they take more input, and the answers to the
//! connection's certificate status queries.

use std::io::{self, BufRead as _, IoSlice, Read, Write};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use browntls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod coalesce;
pub(crate) mod coop;
mod handshake;
mod revocation;
pub(crate) use handshake::{HandshakeFailure, IoSession, MidHandshake};
pub(crate) use revocation::{PeerRevocation, RevocationSource};

/// Which directions of a stream are still open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsState {
    /// Both directions are open.
    Stream,
    /// The peer closed its direction (a `close_notify`, or end of file).
    ReadShutdown,
    /// We sent `close_notify`; nothing more may be written.
    WriteShutdown,
    /// Both of the above.
    FullyShutdown,
}

impl TlsState {
    pub(crate) fn shutdown_read(&mut self) {
        *self = match *self {
            Self::WriteShutdown | Self::FullyShutdown => Self::FullyShutdown,
            _ => Self::ReadShutdown,
        };
    }

    pub(crate) fn shutdown_write(&mut self) {
        *self = match *self {
            Self::ReadShutdown | Self::FullyShutdown => Self::FullyShutdown,
            _ => Self::WriteShutdown,
        };
    }

    pub(crate) fn readable(self) -> bool {
        !matches!(self, Self::ReadShutdown | Self::FullyShutdown)
    }

    pub(crate) fn writeable(self) -> bool {
        !matches!(self, Self::WriteShutdown | Self::FullyShutdown)
    }
}

/// The per-stream state the polling functions share.
#[derive(Debug)]
pub(crate) struct StreamState {
    pub(crate) state: TlsState,
    /// TLS bytes reached the transport during the handshake and were not
    /// flushed yet.
    pub(crate) need_flush: bool,
    /// A read error met after a read already returned bytes.
    pub(crate) deferred_error: Option<io::Error>,
    /// The waker of the last write, flush or shutdown that returned
    /// `Pending`. A read that writes to the transport (to answer the peer)
    /// may take over the transport's write-readiness registration, so it
    /// wakes this waker afterwards to let the writer register again.
    pub(crate) write_waker: Option<Waker>,
    /// The waker of a read waiting for queued TLS bytes to be written
    /// before it takes more input (`Stream::write_before_reading`). A write,
    /// flush or shutdown may take over the transport's write-readiness
    /// registration and write those bytes itself, so it wakes this waker
    /// when it moved bytes or failed.
    pub(crate) read_waker: Option<Waker>,
    /// A read queued TLS bytes the peer may be waiting for, and they are
    /// not all written yet: later reads keep writing them.
    pub(crate) answering: bool,
    /// The poll now running already read from the transport: its later
    /// reads take from the task's cooperative budget, whichever [`Stream`]
    /// of the poll makes them (`begin_poll` clears it).
    pub(crate) read_before: bool,
    /// The answers to the connection's certificate status queries.
    pub(crate) revocation: PeerRevocation,
}

impl StreamState {
    pub(crate) fn new(revocation: PeerRevocation) -> Self {
        Self {
            state: TlsState::Stream,
            need_flush: false,
            deferred_error: None,
            write_waker: None,
            read_waker: None,
            answering: false,
            read_before: false,
            revocation,
        }
    }

    /// Starts a poll of the stream that may read from the transport: its
    /// first read is free of the cooperative budget again.
    pub(crate) fn begin_poll(&mut self) {
        self.read_before = false;
    }

    /// Records the waker of a read about to wait for queued TLS bytes to be
    /// written.
    fn park_reader(&mut self, cx: &Context<'_>) {
        match &mut self.read_waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            slot => *slot = Some(cx.waker().clone()),
        }
    }

    /// After a write-side poll: wakes a read waiting for queued bytes when
    /// the poll moved bytes or failed, then records `cx` if it is `Pending`.
    fn settle<T>(
        &mut self,
        cx: &Context<'_>,
        wrote: bool,
        poll: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if (wrote || matches!(poll, Poll::Ready(Err(_))))
            && let Some(waker) = self.read_waker.take()
        {
            waker.wake();
        }
        self.track(cx, poll)
    }

    /// Records the waker of a write-side poll about to return `Pending`.
    fn park_writer(&mut self, cx: &Context<'_>) {
        match &mut self.write_waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            slot => *slot = Some(cx.waker().clone()),
        }
    }

    /// Records `cx` when `poll` is `Pending`, and passes it on.
    pub(crate) fn track<T>(&mut self, cx: &Context<'_>, poll: Poll<T>) -> Poll<T> {
        if poll.is_pending() {
            self.park_writer(cx);
        }
        poll
    }
}

/// Wakes two tasks: a read that writes to the transport, and the writer
/// whose registration that write may replace.
struct JointWaker {
    reader: Waker,
    writer: Waker,
}

impl Wake for JointWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.reader.wake_by_ref();
        self.writer.wake_by_ref();
    }
}

/// `reader`, or a waker for both `reader` and `writer` when a writer is
/// parked.
pub(crate) fn joint_waker(reader: &Waker, writer: Option<&Waker>) -> Waker {
    match writer {
        Some(writer) if !writer.will_wake(reader) => Waker::from(Arc::new(JointWaker {
            reader: reader.clone(),
            writer: writer.clone(),
        })),
        _ => reader.clone(),
    }
}

/// The error for a write after `close_notify` was sent: RFC 9846 §6.1 lets
/// nothing follow it.
pub(crate) fn write_after_shutdown() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "TLS stream was shut down for writing (close_notify sent)",
    )
}

/// A connection paired with its transport for the duration of one poll.
pub(crate) struct Stream<'a, IO, C> {
    pub(crate) io: &'a mut IO,
    pub(crate) session: &'a mut C,
    /// The transport reached end of file (or reading was shut down).
    pub(crate) eof: bool,
    /// TLS bytes were written to the transport and not flushed yet.
    pub(crate) need_flush: bool,
    /// Some TLS bytes reached the transport during this poll.
    pub(crate) wrote: bool,
    /// This poll already read from the transport: its later reads take
    /// from the task's cooperative budget. A poll that uses several
    /// `Stream`s carries it from one to the next in
    /// [`StreamState::read_before`].
    pub(crate) read_before: bool,
}

impl<'a, IO, C, SD> Stream<'a, IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    pub(crate) fn new(io: &'a mut IO, session: &'a mut C) -> Self {
        Self {
            io,
            session,
            eof: false,
            need_flush: false,
            wrote: false,
            read_before: false,
        }
    }

    pub(crate) fn set_eof(mut self, eof: bool) -> Self {
        self.eof = eof;
        self
    }

    pub(crate) fn set_need_flush(mut self, need_flush: bool) -> Self {
        self.need_flush = need_flush;
        self
    }

    pub(crate) fn set_read_before(mut self, read_before: bool) -> Self {
        self.read_before = read_before;
        self
    }

    pub(crate) fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }

    /// Reads TLS bytes from the transport and processes them. `Ready(Ok(0))`
    /// is end of file.
    ///
    /// Every read after the first in one poll takes a unit of the task's
    /// cooperative budget, and is `Pending` (the task being rescheduled)
    /// once the budget is spent: the peer decides how long a read loop goes
    /// on (records without plaintext, a handshake in small pieces), and the
    /// transport need not take part in the budget itself.
    pub(crate) fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let unit = match self.read_before {
            true => Some(ready!(coop::poll_proceed(cx))),
            false => None,
        };
        let mut reader = SyncReadAdapter { io: self.io, cx };
        let n = match self.session.read_tls(&mut reader) {
            // The transport is not ready: `unit` returns to the budget.
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            result => {
                self.read_before = true;
                if let Some(unit) = unit {
                    unit.spent();
                }
                match result {
                    Ok(n) => n,
                    Err(err) => return Poll::Ready(Err(err)),
                }
            }
        };

        if let Err(err) = self.session.process_new_packets() {
            // Deliver the alert describing the failure if the transport takes
            // it now; the failure itself is what the caller sees.
            let _ = self.write_io(cx);
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
        }
        Poll::Ready(Ok(n))
    }

    /// Writes queued TLS bytes to the transport.
    pub(crate) fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = SyncWriteAdapter { io: self.io, cx };
        match self.session.write_tls(&mut writer) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => {
                if matches!(result, Ok(n) if n > 0) {
                    self.wrote = true;
                }
                Poll::Ready(result)
            }
        }
    }

    /// Answers the certificate status queries the connection waits on
    /// (one after another, when a chain needs several): `Ready(Ok(()))`
    /// once it waits on none, `Pending` while an answer is fetched, the
    /// fetch then waking `cx`.
    ///
    /// The connection goes on with the input it had buffered as it takes
    /// an answer. When it fails over one, its alert is written if the
    /// transport takes it now, as after a failed read.
    pub(crate) fn poll_revocation(
        &mut self,
        cx: &mut Context<'_>,
        revocation: &mut PeerRevocation,
    ) -> Poll<io::Result<()>> {
        while let Some(query) = self.session.pending_revocation() {
            let id = query.id();
            let response = ready!(revocation.poll_response(cx, query));
            let result = self.session.resolve_peer_revocation(id, response);
            revocation.settled(result.is_ok());
            if let Err(err) = result {
                let _ = self.write_io(cx);
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Makes as much handshake progress as the transport allows. Returns the
    /// TLS bytes `(read, written)`; `Pending` only when nothing moved.
    ///
    /// A certificate status query the connection waits on is answered
    /// through `revocation`, once our own flight is out. Nothing is read
    /// while its answer is fetched.
    pub(crate) fn handshake(
        &mut self,
        cx: &mut Context<'_>,
        revocation: &mut PeerRevocation,
    ) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;
            let mut revocation_pending = false;

            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "transport accepted no TLS bytes",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        wrlen += n;
                        self.need_flush = true;
                    }
                    Poll::Pending => {
                        write_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            if self.need_flush {
                match Pin::new(&mut *self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => self.need_flush = false,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => write_would_block = true,
                }
            }

            loop {
                match self.poll_revocation(cx, revocation) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        revocation_pending = true;
                        break;
                    }
                }
                if self.eof || !self.session.wants_read() {
                    break;
                }
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(n)) => rdlen += n,
                    Poll::Pending => {
                        read_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            if !self.session.is_handshaking() {
                return Poll::Ready(Ok((rdlen, wrlen)));
            }
            if self.eof {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed connection during handshake",
                )));
            }
            if write_would_block || read_would_block || revocation_pending {
                return if rdlen != 0 || wrlen != 0 {
                    Poll::Ready(Ok((rdlen, wrlen)))
                } else {
                    Poll::Pending
                };
            }
            // Neither direction blocked, yet the handshake goes on. Unless
            // the connection still wants to move bytes, it never will (the
            // peer sent close_notify mid-handshake, say): looping would spin.
            if !self.session.wants_read() && !self.session.wants_write() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS handshake cannot make progress",
                )));
            }
        }
    }

    /// Reads records until plaintext is available or the peer closed, and
    /// returns the first buffered chunk (empty after `close_notify`).
    ///
    /// Messages the records call for (an alert, a KeyUpdate answer, a
    /// post-handshake authentication response) are written at once, as far
    /// as the transport takes them without waiting: a peer may wait for
    /// them before it sends what this read waits for. Records already
    /// queued by writes are left to the writer, unless a read failed (the
    /// alert must go out). Touching the write side wakes the parked
    /// writer, whose registration it may have replaced. When the connection
    /// stops reading until its queued records are written, the read writes
    /// them itself and waits for writability rather than taking more input.
    ///
    /// A certificate the records bring (post-handshake authentication) may
    /// leave the connection waiting on a certificate status query: the read
    /// answers it through `st` and takes no more input meanwhile.
    pub(crate) fn poll_fill_buf(
        mut self,
        cx: &mut Context<'_>,
        st: &mut StreamState,
    ) -> Poll<io::Result<&'a [u8]>>
    where
        SD: 'a,
    {
        let had_queued_tls = self.session.wants_write();
        let mut io_pending = false;
        let mut error = None;

        loop {
            match self.poll_revocation(cx, &mut st.revocation) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => {
                    error = Some(err);
                    break;
                }
                Poll::Pending => {
                    // The fetch wakes this read, as the transport would.
                    io_pending = true;
                    break;
                }
            }
            if self.eof || !self.session.wants_read() {
                break;
            }
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(err)) => {
                    error = Some(err);
                    break;
                }
            }
        }
        // Nothing below reads from the transport.
        st.read_before = self.read_before;

        // An answer partly written by an earlier read is still ours to
        // finish, even though bytes were queued when this read began.
        let answer = self.session.wants_write() && (st.answering || !had_queued_tls);
        if answer || error.is_some() {
            st.answering = answer;
            // The read's write may take over the transport's write-readiness
            // registration from a parked writer, so it registers a waker for
            // both tasks: writability then wakes the writer too, and the
            // reader need not poll again for that. Waking the writer at
            // every `Pending` instead would spin a task that polls both
            // directions. A write that moved bytes changed the writer's
            // queue, and a failed read is final: both wake it at once.
            let joint = joint_waker(cx.waker(), st.write_waker.as_ref());
            let wrote = self.answer_peer(&mut Context::from_waker(&joint));
            if (wrote || error.is_some())
                && let Some(waker) = st.write_waker.take()
            {
                waker.wake();
            }
        }
        if !self.session.wants_write() {
            st.answering = false;
        }
        if let Some(err) = error {
            return Poll::Ready(Err(err));
        }

        let no_plaintext = matches!(
            self.session.reader().into_first_chunk(),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock
        );
        if no_plaintext && !io_pending && !self.eof && self.session.wants_write() {
            return self.write_before_reading(cx, st);
        }

        match self.session.reader().into_first_chunk() {
            Ok(chunk) => Poll::Ready(Ok(chunk)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    // The read loop stopped because the backlog of control
                    // records the connection owes was full (when the poll
                    // began, or once this poll's reads filled it), and the
                    // answer above then wrote all of it. No transport
                    // waker is registered (the last read returned, or none
                    // was made) and nothing is left to write: poll again
                    // rather than hang. The next poll reads, so the wake
                    // does not repeat, and the task returns to the
                    // scheduler in between.
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    /// A read that cannot go on until queued TLS bytes are written: the
    /// connection stops reading while the control records it owes the peer
    /// (KeyUpdate answers, post-handshake authentication responses) pile up
    /// unwritten, so that a peer that sends requests and reads nothing
    /// cannot grow them without bound. Writes everything queued, the
    /// writer's records ahead of the answers included, and polls again once
    /// it is out; otherwise waits for writability. Like the answers above,
    /// the write registers a waker for a parked writer too, and wakes it at
    /// once when bytes moved or the transport failed. A read left waiting is
    /// recorded in `st`: a write that takes the registration over wakes it.
    fn write_before_reading(
        &mut self,
        cx: &mut Context<'_>,
        st: &mut StreamState,
    ) -> Poll<io::Result<&'a [u8]>> {
        let joint = joint_waker(cx.waker(), st.write_waker.as_ref());
        let mut jcx = Context::from_waker(&joint);
        let mut wrote = false;
        let outcome = loop {
            if !self.session.wants_write() {
                let _ = Pin::new(&mut *self.io).poll_flush(&mut jcx);
                break Ok(true);
            }
            match self.write_io(&mut jcx) {
                Poll::Ready(Ok(0)) => {
                    break Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "transport accepted no TLS bytes",
                    ));
                }
                Poll::Ready(Ok(_)) => wrote = true,
                Poll::Pending => break Ok(false),
                Poll::Ready(Err(err)) => break Err(err),
            }
        };
        if (wrote || outcome.is_err())
            && let Some(waker) = st.write_waker.take()
        {
            waker.wake();
        }
        match outcome {
            Err(err) => Poll::Ready(Err(err)),
            Ok(true) => {
                // Reading may resume: poll again.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(false) => {
                // A writer may take the registration over and write the
                // bytes itself: it wakes this read when it does.
                st.park_reader(cx);
                Poll::Pending
            }
        }
    }

    /// Writes and flushes queued TLS bytes as far as the transport takes them
    /// now; returns whether any were written. Errors are left for the next
    /// write to report.
    fn answer_peer(&mut self, cx: &mut Context<'_>) -> bool {
        let mut wrote = false;
        while self.session.wants_write() {
            match self.write_io(cx) {
                Poll::Ready(Ok(n)) if n > 0 => wrote = true,
                _ => break,
            }
        }
        let _ = Pin::new(&mut *self.io).poll_flush(cx);
        wrote
    }
}

impl<IO, C, SD> AsyncWrite for Stream<'_, IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut pos = 0;
        loop {
            let taken = this.session.writer().write(&buf[pos..])?;
            pos += taken;
            match this.drain(cx) {
                Drain::Error(err) => return Poll::Ready(Err(err)),
                Drain::Blocked if pos == 0 => return Poll::Pending,
                Drain::Blocked => return Poll::Ready(Ok(pos)),
                Drain::Done { wrote } => {
                    if pos == buf.len() {
                        return Poll::Ready(Ok(pos));
                    }
                    if taken == 0 && !wrote {
                        // The connection took nothing and has nothing queued:
                        // another round would not change that.
                        return Poll::Ready(no_progress(pos));
                    }
                }
            }
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }
        loop {
            let taken = this.session.writer().write_vectored(bufs)?;
            match this.drain(cx) {
                Drain::Error(err) => return Poll::Ready(Err(err)),
                Drain::Blocked if taken == 0 => return Poll::Pending,
                Drain::Blocked => return Poll::Ready(Ok(taken)),
                Drain::Done { .. } if taken != 0 => return Poll::Ready(Ok(taken)),
                Drain::Done { wrote: false } => return Poll::Ready(no_progress(0)),
                Drain::Done { wrote: true } => {}
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.session.writer().flush()?;
        while this.session.wants_write() {
            if ready!(this.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Pin::new(&mut *this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.session.wants_write() {
            if ready!(this.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Poll::Ready(match ready!(Pin::new(&mut *this.io).poll_shutdown(cx)) {
            // A transport that is already gone has nothing left to shut.
            Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(()),
            result => result,
        })
    }
}

/// The outcome of writing queued TLS bytes out.
enum Drain {
    /// Everything queued was written; `wrote` says whether anything was.
    Done {
        wrote: bool,
    },
    /// The transport is not ready; its waker is registered.
    Blocked,
    Error(io::Error),
}

impl<IO, C, SD> Stream<'_, IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    fn drain(&mut self, cx: &mut Context<'_>) -> Drain {
        let mut wrote = false;
        while self.session.wants_write() {
            match self.write_io(cx) {
                Poll::Ready(Ok(0)) => {
                    return Drain::Error(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "transport accepted no TLS bytes",
                    ));
                }
                Poll::Ready(Ok(_)) => wrote = true,
                Poll::Pending => return Drain::Blocked,
                Poll::Ready(Err(err)) => return Drain::Error(err),
            }
        }
        Drain::Done { wrote }
    }
}

/// What a write returns when the connection accepted no more plaintext and
/// had nothing to send: the bytes taken so far, or `WriteZero`.
fn no_progress(pos: usize) -> io::Result<usize> {
    if pos > 0 {
        Ok(pos)
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "TLS connection accepted no plaintext",
        ))
    }
}

/// `AsyncBufRead::poll_fill_buf` for a stream in `st`.
pub(crate) fn poll_fill_buf<'a, IO, C, SD>(
    io: &'a mut IO,
    session: &'a mut C,
    st: &mut StreamState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<&'a [u8]>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData + 'a,
{
    if !st.state.readable() {
        return Poll::Ready(Ok(&[]));
    }
    let stream = Stream::new(io, session).set_read_before(st.read_before);
    match stream.poll_fill_buf(cx, st) {
        Poll::Ready(Ok(chunk)) => {
            if chunk.is_empty() {
                st.state.shutdown_read();
            }
            Poll::Ready(Ok(chunk))
        }
        other => other,
    }
}

/// `AsyncRead::poll_read`: copies plaintext into `buf`, then keeps filling
/// while more is ready without waiting. An error met after some bytes were
/// copied is kept and returned by the next read.
pub(crate) fn poll_read<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    st: &mut StreamState,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if let Some(err) = st.deferred_error.take() {
        return Poll::Ready(Err(err));
    }
    let mut copied = false;
    while buf.remaining() > 0 {
        match poll_fill_buf(io, session, st, cx) {
            Poll::Ready(Ok(chunk)) => {
                if chunk.is_empty() {
                    break;
                }
                let len = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..len]);
                session.reader().consume(len);
                copied = true;
            }
            Poll::Ready(Err(err)) if copied => {
                st.deferred_error = Some(err);
                break;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending if copied => break,
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

/// `AsyncWrite::poll_write` for a stream in `st`.
pub(crate) fn poll_write<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    st: &mut StreamState,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if !st.state.writeable() {
        return Poll::Ready(Err(write_after_shutdown()));
    }
    let mut stream = Stream::new(io, session);
    let poll = stream.as_mut_pin().poll_write(cx, buf);
    let wrote = stream.wrote;
    st.settle(cx, wrote, poll)
}

/// `AsyncWrite::poll_write_vectored` for a stream in `st`.
pub(crate) fn poll_write_vectored<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    st: &mut StreamState,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
) -> Poll<io::Result<usize>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if !st.state.writeable() {
        return Poll::Ready(Err(write_after_shutdown()));
    }
    let mut stream = Stream::new(io, session);
    let poll = stream.as_mut_pin().poll_write_vectored(cx, bufs);
    let wrote = stream.wrote;
    st.settle(cx, wrote, poll)
}

/// `AsyncWrite::poll_flush`: writes every queued TLS byte and flushes the
/// transport.
pub(crate) fn poll_flush<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    st: &mut StreamState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    let mut stream = Stream::new(io, session);
    let poll = stream.as_mut_pin().poll_flush(cx);
    let wrote = stream.wrote;
    st.settle(cx, wrote, poll)
}

/// `AsyncWrite::poll_shutdown`: queues `close_notify` (once), writes it and
/// anything queued before it, then shuts the transport's write side.
pub(crate) fn poll_shutdown<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    st: &mut StreamState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if st.state.writeable() {
        session.send_close_notify();
        st.state.shutdown_write();
    }
    let mut stream = Stream::new(io, session);
    let poll = stream.as_mut_pin().poll_shutdown(cx);
    let wrote = stream.wrote;
    st.settle(cx, wrote, poll)
}

/// Writes `alert` to `io` and flushes it. `Ready` once it is out, or once
/// the transport failed or took nothing: the caller then reports the error
/// that caused the alert, not the transport's.
pub(crate) fn poll_send_alert<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    alert: &mut browntls::server::AcceptedAlert,
    cx: &mut Context<'_>,
) -> Poll<()> {
    loop {
        match alert.write(&mut SyncWriteAdapter { io, cx }) {
            Ok(0) => break,
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(_) => return Poll::Ready(()),
        }
    }
    Pin::new(io).poll_flush(cx).map(|_| ())
}

/// Gives `browntls`'s blocking `read_tls` an [`AsyncRead`], turning
/// `Pending` into `WouldBlock`.
pub(crate) struct SyncReadAdapter<'a, 'b, T> {
    pub(crate) io: &'a mut T,
    pub(crate) cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Gives `browntls`'s blocking `write_tls` an [`AsyncWrite`], turning
/// `Pending` into `WouldBlock`. The records `write_tls` offers go to a
/// transport with a vectored write as they are, and to any other gathered
/// into one write (see [`coalesce`]).
pub(crate) struct SyncWriteAdapter<'a, 'b, T> {
    pub(crate) io: &'a mut T,
    pub(crate) cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> SyncWriteAdapter<'_, '_, T> {
    fn poll_with<U>(
        &mut self,
        f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<U>>,
    ) -> io::Result<U> {
        match f(Pin::new(&mut *self.io), self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.poll_with(|io, cx| io.poll_write(cx, buf))
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.poll_with(|io, cx| {
            if io.is_write_vectored() {
                io.poll_write_vectored(cx, bufs)
            } else {
                coalesce::poll_write_coalesced(io, cx, bufs)
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.poll_with(|io, cx| io.poll_flush(cx))
    }
}

#[cfg(test)]
mod tests;
