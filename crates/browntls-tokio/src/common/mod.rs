//! The polling core shared by the client and server streams: moving TLS
//! records between a `browntls` connection and an `AsyncRead + AsyncWrite`
//! transport without blocking.

use std::io::{self, BufRead as _, IoSlice, Read, Write};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use browntls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod handshake;
pub(crate) use handshake::{IoSession, MidHandshake};

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

    pub(crate) fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }

    /// Reads TLS bytes from the transport and processes them. `Ready(Ok(0))`
    /// is end of file.
    pub(crate) fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = SyncReadAdapter { io: self.io, cx };
        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
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
            result => Poll::Ready(result),
        }
    }

    /// Makes as much handshake progress as the transport allows. Returns the
    /// TLS bytes `(read, written)`; `Pending` only when nothing moved.
    pub(crate) fn handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;

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

            while !self.eof && self.session.wants_read() {
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
            if write_would_block || read_would_block {
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
    pub(crate) fn poll_fill_buf(mut self, cx: &mut Context<'_>) -> Poll<io::Result<&'a [u8]>>
    where
        SD: 'a,
    {
        let mut io_pending = false;

        while !self.eof && self.session.wants_read() {
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        match self.session.reader().into_first_chunk() {
            Ok(chunk) => Poll::Ready(Ok(chunk)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    // The connection stopped wanting to read without
                    // plaintext or closure, so no transport waker is
                    // registered: poll again rather than hang. Tokio's
                    // cooperative budget bounds a pathological loop.
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
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

/// `AsyncBufRead::poll_fill_buf` for a stream in `state`.
pub(crate) fn poll_fill_buf<'a, IO, C, SD>(
    io: &'a mut IO,
    session: &'a mut C,
    state: &mut TlsState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<&'a [u8]>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData + 'a,
{
    if !state.readable() {
        return Poll::Ready(Ok(&[]));
    }
    match Stream::new(io, session).poll_fill_buf(cx) {
        Poll::Ready(Ok(chunk)) => {
            if chunk.is_empty() {
                state.shutdown_read();
            }
            Poll::Ready(Ok(chunk))
        }
        other => other,
    }
}

/// `AsyncRead::poll_read`: copies plaintext into `buf`, then keeps filling
/// while more is ready without waiting. An error met after some bytes were
/// copied is kept in `deferred` and returned by the next read.
pub(crate) fn poll_read<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    state: &mut TlsState,
    deferred: &mut Option<io::Error>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if let Some(err) = deferred.take() {
        return Poll::Ready(Err(err));
    }
    let mut copied = false;
    while buf.remaining() > 0 {
        match poll_fill_buf(io, session, state, cx) {
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
                *deferred = Some(err);
                break;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending if copied => break,
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

/// `AsyncWrite::poll_write` for a stream in `state`.
pub(crate) fn poll_write<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    state: TlsState,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if !state.writeable() {
        return Poll::Ready(Err(write_after_shutdown()));
    }
    Stream::new(io, session).as_mut_pin().poll_write(cx, buf)
}

/// `AsyncWrite::poll_write_vectored` for a stream in `state`.
pub(crate) fn poll_write_vectored<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    state: TlsState,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
) -> Poll<io::Result<usize>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if !state.writeable() {
        return Poll::Ready(Err(write_after_shutdown()));
    }
    Stream::new(io, session)
        .as_mut_pin()
        .poll_write_vectored(cx, bufs)
}

/// `AsyncWrite::poll_flush`: writes every queued TLS byte and flushes the
/// transport.
pub(crate) fn poll_flush<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    Stream::new(io, session).as_mut_pin().poll_flush(cx)
}

/// `AsyncWrite::poll_shutdown`: queues `close_notify` (once), writes it and
/// anything queued before it, then shuts the transport's write side.
pub(crate) fn poll_shutdown<IO, C, SD>(
    io: &mut IO,
    session: &mut C,
    state: &mut TlsState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    if state.writeable() {
        session.send_close_notify();
        state.shutdown_write();
    }
    Stream::new(io, session).as_mut_pin().poll_shutdown(cx)
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
/// `Pending` into `WouldBlock`.
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
        self.poll_with(|io, cx| io.poll_write_vectored(cx, bufs))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.poll_with(|io, cx| io.poll_flush(cx))
    }
}

#[cfg(test)]
mod tests;
