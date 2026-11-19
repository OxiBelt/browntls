//! The polling core of the unbuffered streams: running a `browntls`
//! unbuffered connection against an `AsyncRead + AsyncWrite` transport.
//!
//! Every call of `process_tls_records` is made here. Reads pass the received
//! bytes, so records are decrypted where the transport put them; writes,
//! flushes and shutdowns pass no input, so they never decrypt a record the
//! reader has not asked for (at most, the connection goes on with a
//! handshake message it had already taken in whole). Whatever the connection queues (handshake
//! messages, alerts, KeyUpdates) is encoded into the one outgoing buffer at
//! once, in the order the connection sequenced it, ahead of or behind the
//! application data records encrypted into the same buffer.
//!
//! A connection that waits on a certificate status query
//! (`ConnectionState::PendingRevocation`) is answered by the operation
//! that met it, through the stream's fetcher, and takes no input meanwhile.

use std::io::{self, IoSlice};
use std::ops::{DerefMut, Range};
use std::pin::Pin;
use std::task::{Context, Poll};

use browntls::SideData;
use browntls::unbuffered::{
    ConnectionState, EncodeError, EncodeTlsData, EncryptError, InsufficientSizeError,
    UnbufferedConnectionCommon, UnbufferedStatus, WriteTraffic,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::TlsStream;
use super::buffers::Outgoing;
use crate::common::{joint_waker, write_after_shutdown};

/// The most plaintext one write encrypts: four records of the largest size
/// (more, smaller ones under a lower fragment size or record size limit). A
/// write takes more only once the transport took the records of the one
/// before.
const MAX_WRITE: usize = 4 * 16_384;

/// The most plaintext a vectored write gathers from several slices into one
/// record.
const MAX_GATHER: usize = 16_384;

/// How many bytes of records that reads owe the peer (KeyUpdate answers,
/// post-handshake authentication responses) may wait for the transport
/// before reads stop taking input, so that a peer that sends requests and
/// reads nothing cannot grow the outgoing buffer without bound.
const CONTROL_BACKLOG_LIMIT: usize = 16 * 1024;

/// How often a buffer is grown for one record before the connection's size
/// estimate is taken to be wrong.
const MAX_GROW_ATTEMPTS: usize = 4;

/// What one `process_tls_records` call with the received bytes came to.
enum Step {
    /// The state machine moved on; nothing to do.
    Progress,
    /// Queued records were encoded and wait in the outgoing buffer.
    Transmit,
    /// An application data record was decrypted; its plaintext is in
    /// `Incoming::plaintext` unless the record was empty.
    Plaintext,
    /// No complete record is buffered: more TLS bytes are needed.
    NeedInput,
    /// The peer sent `close_notify`, or the connection is closed.
    PeerClosed,
    /// The connection waits on a certificate status query.
    Revocation,
}

/// What a call without input came to; see `TlsStream::write_step`.
enum Queued {
    /// The connection offered to write, and `write` was called.
    Written,
    /// The connection is closed.
    Closed,
    /// The connection waits on a certificate status query, and offers
    /// nothing until it is answered.
    Revocation,
}

/// An `InvalidData` error wrapping the TLS failure.
pub(super) fn tls_error(err: browntls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

fn internal(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn write_zero() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "transport accepted no TLS bytes")
}

/// Copies the connection's queued records into `outgoing`; returns the
/// bytes added.
fn encode<D>(encoder: &mut EncodeTlsData<'_, D>, outgoing: &mut Outgoing) -> io::Result<usize> {
    for _ in 0..MAX_GROW_ATTEMPTS {
        match encoder.encode(outgoing.spare_mut()) {
            Ok(n) => {
                outgoing.commit(n);
                return Ok(n);
            }
            Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                outgoing.reserve(required_size);
            }
            Err(_) => break,
        }
    }
    Err(internal("TLS records could not be encoded"))
}

/// Runs `operation` (an encryption into the room behind the unsent bytes)
/// until the room is large enough; returns the bytes added.
fn encrypt_with(
    outgoing: &mut Outgoing,
    mut operation: impl FnMut(&mut [u8]) -> Result<usize, EncryptError>,
) -> io::Result<usize> {
    for _ in 0..MAX_GROW_ATTEMPTS {
        match operation(outgoing.spare_mut()) {
            Ok(n) => {
                outgoing.commit(n);
                return Ok(n);
            }
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                outgoing.reserve(required_size);
            }
            Err(EncryptError::AlreadyClosed) => return Err(write_after_shutdown()),
            Err(EncryptError::Failed) => return Err(tls_error(browntls::Error::EncryptError)),
            // The write key is spent and cannot be refreshed: the caller
            // closes the connection.
            Err(err) => return Err(io::Error::other(err)),
        }
    }
    Err(internal("TLS records could not be encrypted"))
}

impl<IO, C, D> TlsStream<IO, C>
where
    C: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    /// Lets the connection process the received bytes up to the next thing
    /// to act on.
    fn read_step(&mut self) -> io::Result<Step> {
        let input = self.incoming.unprocessed_mut();
        let base = input.as_ptr().addr();
        let UnbufferedStatus { discard, state } = self.conn.process_tls_records(input);
        let state = match state {
            Ok(state) => state,
            Err(err) => {
                // What was decrypted in place is not fed in again.
                self.incoming.processed(discard, None);
                return Err(tls_error(err));
            }
        };
        let mut plain: Option<Range<usize>> = None;
        let mut failure = None;
        let step = match state {
            ConnectionState::ReadTraffic(record) => {
                let payload = record.payload();
                if !payload.is_empty() {
                    // The plaintext is a part of `input`: where, is its
                    // distance from the start of `input`.
                    let offset = payload.as_ptr().addr().wrapping_sub(base);
                    plain = Some(offset..offset.saturating_add(payload.len()));
                }
                Step::Plaintext
            }
            ConnectionState::ReadEarlyData(record) => {
                self.early_data.extend_from_slice(record.payload());
                Step::Progress
            }
            ConnectionState::EncodeTlsData(mut encoder) => {
                match encode(&mut encoder, &mut self.outgoing) {
                    Ok(n) => {
                        self.control_bytes = self.control_bytes.saturating_add(n);
                        // Reads see these records out, whoever marks them
                        // transmitted.
                        self.answering = true;
                    }
                    Err(err) => failure = Some(err),
                }
                Step::Progress
            }
            ConnectionState::TransmitTlsData(transmit) => {
                // The records are in the outgoing buffer, which is what
                // goes to the transport next.
                transmit.done();
                Step::Transmit
            }
            ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => Step::NeedInput,
            ConnectionState::PeerClosed | ConnectionState::Closed => Step::PeerClosed,
            ConnectionState::PendingRevocation => Step::Revocation,
            _ => {
                failure = Some(internal("unexpected TLS connection state"));
                Step::Progress
            }
        };
        self.incoming.processed(discard, plain);
        match failure {
            Some(err) => Err(err),
            None => Ok(step),
        }
    }

    /// Lets the connection encode what it has queued, without input, until
    /// it offers to write; `write` then encrypts into the outgoing buffer.
    /// `write` is not called when the connection is closed, or waits on a
    /// certificate status query.
    fn write_step<R>(
        &mut self,
        write: impl FnOnce(&mut WriteTraffic<'_, D>, &mut Outgoing) -> io::Result<R>,
    ) -> io::Result<Queued> {
        loop {
            let status = self.conn.process_tls_records(&mut []);
            match status.state.map_err(tls_error)? {
                ConnectionState::EncodeTlsData(mut encoder) => {
                    let n = encode(&mut encoder, &mut self.outgoing)?;
                    self.control_bytes = self.control_bytes.saturating_add(n);
                }
                ConnectionState::TransmitTlsData(transmit) => transmit.done(),
                ConnectionState::WriteTraffic(mut writer) => {
                    write(&mut writer, &mut self.outgoing)?;
                    return Ok(Queued::Written);
                }
                ConnectionState::PeerClosed => self.peer_closed(),
                ConnectionState::Closed => {
                    self.peer_closed();
                    return Ok(Queued::Closed);
                }
                ConnectionState::PendingRevocation => return Ok(Queued::Revocation),
                ConnectionState::BlockedHandshake => {
                    return Err(internal("TLS handshake is not complete"));
                }
                _ => return Err(internal("unexpected TLS connection state")),
            }
        }
    }

    /// The peer's `close_notify` was seen: reads are at their end.
    fn peer_closed(&mut self) {
        self.state.shutdown_read();
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    /// Encodes whatever the connection has queued (a KeyUpdate or a
    /// CertificateRequest asked for through `get_mut`, say). What a
    /// connection that waits on a certificate status query has queued is
    /// encoded too; what it queues once answered is not there yet.
    fn encode_queued(&mut self) -> io::Result<()> {
        self.write_step(|_, _| Ok(())).map(|_| ())
    }

    /// Encrypts `data` behind everything encoded so far. `Ok(false)`,
    /// with nothing encrypted, when the connection waits on a certificate
    /// status query.
    fn encrypt(&mut self, data: &[u8]) -> io::Result<bool> {
        let written = self.write_step(|writer, outgoing| {
            encrypt_with(outgoing, |room| writer.encrypt(data, room))
        })?;
        match written {
            Queued::Written => {
                // Records the reads owed the peer are ahead of this data
                // now; what reads encode from here on is counted afresh.
                self.control_bytes = 0;
                Ok(true)
            }
            Queued::Closed => Err(write_after_shutdown()),
            Queued::Revocation => Ok(false),
        }
    }

    /// Queues `close_notify` behind everything encoded so far. Nothing is
    /// queued on a connection that has failed or is closed. `false`, with
    /// nothing queued, when the connection waits on a certificate status
    /// query.
    fn close_notify(&mut self) -> bool {
        let queued = self.write_step(|writer, outgoing| {
            encrypt_with(outgoing, |room| writer.queue_close_notify(room))
        });
        !matches!(queued, Ok(Queued::Revocation))
    }

    /// The unwritten bytes of records that reads encoded for the peer.
    fn control_backlog(&self) -> usize {
        self.control_bytes.min(self.outgoing.len())
    }
}

impl<IO, C, D> TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    /// Writes the outgoing buffer to the transport until `backlog` allows
    /// stopping.
    fn poll_write_while(
        &mut self,
        cx: &mut Context<'_>,
        backlog: impl Fn(&Self) -> bool,
    ) -> Poll<io::Result<()>> {
        while backlog(self) {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, self.outgoing.unsent()))?;
            if n == 0 {
                return Poll::Ready(Err(write_zero()));
            }
            self.outgoing.advance(n);
            self.moved = true;
            self.need_flush = true;
        }
        if self.outgoing.is_empty() {
            self.control_bytes = 0;
        }
        Poll::Ready(Ok(()))
    }

    /// Writes the whole outgoing buffer to the transport.
    fn poll_write_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_while(cx, |this| !this.outgoing.is_empty())
    }

    /// Flushes the transport if TLS bytes were written since the last flush.
    fn poll_flush_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.need_flush {
            ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.need_flush = false;
        }
        Poll::Ready(Ok(()))
    }

    /// Reads TLS bytes from the transport; `Ready(Ok(0))` is end of file.
    fn poll_read_in(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut buf = ReadBuf::new(self.incoming.spare_mut()?);
        ready!(Pin::new(&mut self.io).poll_read(cx, &mut buf))?;
        let n = buf.filled().len();
        self.incoming.received(n);
        Poll::Ready(Ok(n))
    }

    /// Fetches the answer to the certificate status query the connection
    /// waits on and hands it over; `Pending` while it is fetched, the
    /// fetch then waking `cx`.
    ///
    /// What came of the answer (the next query, the rest of the flight, or
    /// the failure with its alert) is what the connection reports next.
    fn poll_revocation(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(query) = self.conn.pending_revocation() else {
            // Returning as if answered would poll the connection for ever.
            return Poll::Ready(Err(internal(
                "TLS connection awaits a certificate status it did not ask for",
            )));
        };
        let id = query.id();
        let response = ready!(self.revocation.poll_response(cx, query));
        let accepted = self.conn.resolve_peer_revocation(id, response).is_ok();
        self.revocation.settled(accepted);
        Poll::Ready(Ok(()))
    }

    /// [`Self::poll_revocation`] for a write-side poll, which cannot send
    /// before the connection has its answer and may be the only operation
    /// in progress. A read that waited for the answer goes on.
    fn poll_revocation_for_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_revocation(cx))?;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }

    /// Drives the handshake to completion. A TLS failure is reported once
    /// its alert is written, or the transport refused it.
    pub(super) fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.handshake_failure.is_some() {
                // Whether the alert got out or not, the failure is the news.
                if ready!(self.poll_write_out(cx)).is_ok() {
                    let _ = ready!(self.poll_flush_io(cx));
                }
                let err = self.handshake_failure.take();
                return Poll::Ready(Err(err.unwrap_or_else(|| internal("TLS handshake failed"))));
            }
            if !self.conn.is_handshaking() {
                // Our last flight may still be queued; the peer needs it
                // before anything else. No received byte is processed here:
                // what follows the peer's last flight is the stream's.
                self.encode_queued()?;
                ready!(self.poll_write_out(cx))?;
                ready!(self.poll_flush_io(cx))?;
                return Poll::Ready(Ok(()));
            }
            match self.read_step() {
                Err(err) => self.handshake_failure = Some(err),
                Ok(Step::Progress | Step::Transmit) => {}
                Ok(Step::Plaintext) => {
                    // Application data only follows the handshake: the next
                    // round ends it, and the stream reads the record.
                    if self.conn.is_handshaking() {
                        return Poll::Ready(Err(internal(
                            "application data before the TLS handshake completed",
                        )));
                    }
                }
                Ok(Step::NeedInput) => {
                    if !self.conn.is_handshaking() {
                        // The peer's last flight was the last message: the
                        // connection asks for input as any open one does.
                        continue;
                    }
                    // Our flight goes out while the peer's bytes come in:
                    // a peer that writes more before it reads (early data)
                    // must not wait for a transport that waits for it. What
                    // a handshake makes the connection queue is bounded.
                    if self.poll_write_out(cx)?.is_ready() {
                        let _ = self.poll_flush_io(cx)?;
                    }
                    if ready!(self.poll_read_in(cx))? == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed connection during handshake",
                        )));
                    }
                }
                Ok(Step::Revocation) => {
                    // Our flight goes out while the answer is fetched.
                    if self.poll_write_out(cx)?.is_ready() {
                        let _ = self.poll_flush_io(cx)?;
                    }
                    ready!(self.poll_revocation(cx))?;
                }
                Ok(Step::PeerClosed) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS handshake cannot make progress",
                    )));
                }
            }
        }
    }

    /// Makes plaintext available in `Incoming::plaintext`; `Ready(Ok(()))`
    /// without any is the end of the stream (the peer's `close_notify`).
    ///
    /// Records the connection queues while it processes input (an alert, a
    /// KeyUpdate answer, a post-handshake authentication response) are
    /// written at once, as far as the transport takes them without waiting:
    /// a peer may wait for them before it sends what this read waits for.
    /// Touching the write side wakes the parked writer, whose registration
    /// in the transport it may have replaced. While more than
    /// [`CONTROL_BACKLOG_LIMIT`] bytes of such records are unwritten, the
    /// read takes no more input and waits for the transport to take them.
    pub(super) fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.answering {
            // An answer an earlier read could not write out entirely.
            self.answer_peer(cx);
        }
        loop {
            if !self.incoming.plaintext().is_empty() || !self.state.readable() {
                return Poll::Ready(Ok(()));
            }
            if self.control_backlog() > CONTROL_BACKLOG_LIMIT {
                ready!(self.poll_write_before_reading(cx))?;
                continue;
            }
            match self.read_step() {
                Err(err) => {
                    // Deliver the alert describing the failure if the
                    // transport takes it now; the failure is what the
                    // caller sees. A failed read is final for the writer
                    // too: wake it.
                    self.answer_peer(cx);
                    if let Some(waker) = self.write_waker.take() {
                        waker.wake();
                    }
                    return Poll::Ready(Err(err));
                }
                Ok(Step::Progress | Step::Plaintext) => {}
                Ok(Step::Transmit) => self.answer_peer(cx),
                Ok(Step::NeedInput) => {
                    if ready!(self.poll_read_in(cx))? == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed connection without sending TLS close_notify",
                        )));
                    }
                }
                Ok(Step::Revocation) => {
                    // A write-side poll may take the wait over (it needs
                    // the answer too): each registers both tasks.
                    let joint = joint_waker(cx.waker(), self.write_waker.as_ref());
                    let poll = self.poll_revocation(&mut Context::from_waker(&joint));
                    self.park_reader(cx, poll.is_pending() || self.answering);
                    ready!(poll)?;
                    // The writer may have waited for the answer as well.
                    if let Some(waker) = self.write_waker.take() {
                        waker.wake();
                    }
                }
                Ok(Step::PeerClosed) => self.state.shutdown_read(),
            }
        }
    }

    /// Writes and flushes the outgoing buffer as far as the transport takes
    /// it now. Errors are left for the next write to report.
    ///
    /// The write may take over the transport's write-readiness registration
    /// from a parked writer, so it registers a waker for both tasks:
    /// writability then wakes the writer too. A write that moved bytes
    /// changed what the writer waits for: it is woken at once. While the
    /// transport has not taken and flushed everything, later reads go on
    /// with it, and the read's waker is kept for write-side polls, which
    /// may take the registration over in turn.
    fn answer_peer(&mut self, cx: &mut Context<'_>) {
        let joint = joint_waker(cx.waker(), self.write_waker.as_ref());
        let mut joint_cx = Context::from_waker(&joint);
        self.moved = false;
        let poll = self.poll_write_out(&mut joint_cx);
        if matches!(poll, Poll::Ready(Ok(()))) {
            let _ = self.poll_flush_io(&mut joint_cx);
        }
        self.answering = !self.outgoing.is_empty() || self.need_flush;
        if (self.moved || matches!(poll, Poll::Ready(Err(_))))
            && let Some(waker) = self.write_waker.take()
        {
            waker.wake();
        }
        self.park_reader(cx, self.answering);
    }

    /// Keeps the waker of a read that waits for the transport to take or
    /// flush records (`waiting`), or forgets it.
    fn park_reader(&mut self, cx: &Context<'_>, waiting: bool) {
        if !waiting {
            self.read_waker = None;
            return;
        }
        match &mut self.read_waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            slot => *slot = Some(cx.waker().clone()),
        }
    }

    /// A read that takes no more input until records it owes the peer are
    /// written: writes the outgoing buffer (the writer's records ahead of
    /// them included) until the backlog is within its limit, or waits for
    /// writability. Like [`Self::answer_peer`], the write registers a waker
    /// for a parked writer too and wakes it when bytes moved or the
    /// transport failed. A read left waiting is recorded: a write, flush or
    /// shutdown that takes the registration over wakes it.
    fn poll_write_before_reading(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let joint = joint_waker(cx.waker(), self.write_waker.as_ref());
        let mut joint_cx = Context::from_waker(&joint);
        self.moved = false;
        let poll = self.poll_write_while(&mut joint_cx, |this| {
            this.control_backlog() > CONTROL_BACKLOG_LIMIT
        });
        if matches!(poll, Poll::Ready(Ok(()))) && self.poll_flush_io(&mut joint_cx).is_pending() {
            // Later reads go on with the flush.
            self.answering = true;
        }
        if (self.moved || matches!(poll, Poll::Ready(Err(_))))
            && let Some(waker) = self.write_waker.take()
        {
            waker.wake();
        }
        self.park_reader(cx, poll.is_pending() || self.answering);
        poll
    }

    /// Runs a write-side poll (`operation`). A read may be waiting for the
    /// transport to take records it owes the peer, and this poll may take
    /// over the transport's write-readiness registration: the transport is
    /// then given a waker for both tasks, so that the read goes on even if
    /// this write is never polled again (a write future dropped at a
    /// timeout).
    fn write_side<T>(
        &mut self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&mut Self, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        self.moved = false;
        let joint = self
            .read_waker
            .as_ref()
            .filter(|reader| !reader.will_wake(cx.waker()))
            .map(|reader| joint_waker(cx.waker(), Some(reader)));
        let poll = match &joint {
            Some(joint) => operation(self, &mut Context::from_waker(joint)),
            None => operation(self, cx),
        };
        self.settle(cx, poll)
    }

    /// After a write-side poll: wakes a read waiting for the outgoing
    /// buffer to drain when the poll moved bytes or failed, and records the
    /// writer's waker when the poll is `Pending`.
    fn settle<T>(&mut self, cx: &Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if (std::mem::take(&mut self.moved) || matches!(poll, Poll::Ready(Err(_))))
            && let Some(waker) = self.read_waker.take()
        {
            waker.wake();
        }
        if poll.is_pending() {
            match &mut self.write_waker {
                Some(waker) if waker.will_wake(cx.waker()) => {}
                slot => *slot = Some(cx.waker().clone()),
            }
        }
        poll
    }

    /// `AsyncWrite::poll_write`: once the transport took the records of
    /// earlier writes, encrypts up to [`MAX_WRITE`] bytes of `buf` and
    /// writes as much of the result as the transport takes without waiting.
    pub(super) fn poll_write_plain(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_side(cx, |this, cx| this.write_plain(cx, buf))
    }

    fn write_plain(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if !self.state.writeable() {
            return Poll::Ready(Err(write_after_shutdown()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.poll_write_out(cx))?;
        let taken = buf.len().min(MAX_WRITE);
        while !self.encrypt(&buf[..taken])? {
            ready!(self.poll_revocation_for_write(cx))?;
        }
        match self.poll_write_out(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            _ => Poll::Ready(Ok(taken)),
        }
    }

    /// `AsyncWrite::poll_write_vectored`: like a write of the first
    /// non-empty slice, except that several small slices are gathered into
    /// one record (up to [`MAX_GATHER`] bytes) rather than sent as one
    /// record each.
    pub(super) fn poll_write_slices(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.write_side(cx, |this, cx| this.write_slices(cx, bufs))
    }

    fn write_slices(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut slices = bufs.iter().filter(|buf| !buf.is_empty());
        let Some(first) = slices.next() else {
            return Poll::Ready(Ok(0));
        };
        if first.len() >= MAX_GATHER || slices.next().is_none() {
            return self.write_plain(cx, first);
        }
        if !self.state.writeable() {
            return Poll::Ready(Err(write_after_shutdown()));
        }
        let taken = loop {
            ready!(self.poll_write_out(cx))?;
            let mut gathered = std::mem::take(&mut self.gather);
            gathered.clear();
            for buf in bufs {
                let room = MAX_GATHER - gathered.len();
                gathered.extend_from_slice(&buf[..buf.len().min(room)]);
                if gathered.len() == MAX_GATHER {
                    break;
                }
            }
            let taken = gathered.len();
            let result = self.encrypt(&gathered);
            // The scratch buffer held application plaintext: keep the
            // allocation, not the bytes.
            gathered.fill(0);
            gathered.clear();
            self.gather = gathered;
            if result? {
                break taken;
            }
            // Gathered again once the connection has its answer.
            ready!(self.poll_revocation_for_write(cx))?;
        };
        match self.poll_write_out(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            _ => Poll::Ready(Ok(taken)),
        }
    }

    /// `AsyncWrite::poll_flush`: encodes what the connection has queued,
    /// writes every encoded byte and flushes the transport.
    pub(super) fn poll_flush_all(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_side(cx, Self::flush_all)
    }

    fn flush_all(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A connection that failed has its alert encoded already: write
        // that out before reporting the failure.
        let queued = self.encode_queued();
        ready!(self.poll_write_out(cx))?;
        queued?;
        self.need_flush = true;
        self.poll_flush_io(cx)
    }

    /// `AsyncWrite::poll_shutdown`: queues `close_notify` (once), writes it
    /// and everything encoded before it, then shuts the transport's write
    /// side.
    pub(super) fn poll_shutdown_all(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_side(cx, Self::shutdown_all)
    }

    fn shutdown_all(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.writeable() {
            while !self.close_notify() {
                // `close_notify` cannot be queued before the connection
                // has the answer it waits on.
                ready!(self.poll_revocation_for_write(cx))?;
            }
            self.state.shutdown_write();
        }
        ready!(self.poll_write_out(cx))?;
        Poll::Ready(match ready!(Pin::new(&mut self.io).poll_shutdown(cx)) {
            // A transport that is already gone has nothing left to shut.
            Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(()),
            result => result,
        })
    }
}
