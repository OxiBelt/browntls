//! Read and write halves of a TLS stream, for two tasks.
//!
//! TLS ties both directions to one connection state (a read may have to
//! answer the peer, a failure in one direction ends the other), so the
//! halves share the stream and take turns: each poll of a half has the
//! stream to itself for as long as it runs.
//!
//! [`tokio::io::split`] does that with a blocking lock: a poll of one half
//! parks its worker thread while the other half's poll runs, which for a TLS
//! stream includes protecting or opening records. These halves never wait
//! for the other half's poll. A half that finds the stream in use returns
//! `Pending` and is woken when the other half's poll ends. (The one lock a
//! half does wait for guards the two wakers, for a few instructions.) They
//! also need no Tokio feature, and [`reunite`](ReadHalf::reunite) gives the
//! stream back.
//!
//! What follows from taking turns this way:
//!
//! - Any operation of a half, a zero-length write included, may return
//!   `Pending` while the other half's poll runs.
//! - Turns are not queued. A half that waits is woken whenever a poll of
//!   the other half ends, and may find that half in its next poll already:
//!   it then waits again. A half that is always ready can take the stream
//!   again and again until its task yields, which the `coop` feature makes
//!   it do.
//! - If a poll of one half panics, the stream's state is unknown, and every
//!   later operation of either half fails with an [`io::Error`] of kind
//!   `Other` (the halves of `tokio::io::split` panic instead). `reunite`
//!   still returns the stream, as the panicking poll left it: do not use
//!   it for TLS again.
//!
//! [`tokio::io::split`]: https://docs.rs/tokio/1/tokio/io/fn.split.html

use std::error::Error;
use std::fmt;
use std::io::{self, IoSlice};
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Splits `stream` into its two halves.
pub(crate) fn split<S>(stream: S) -> (ReadHalf<S>, WriteHalf<S>) {
    let shared = Arc::new(Shared {
        stream: Mutex::new(stream),
        waiting: Mutex::new([None, None]),
    });
    (
        ReadHalf {
            shared: shared.clone(),
        },
        WriteHalf { shared },
    )
}

/// The read half of a TLS stream `S`, from `into_split` (for example
/// [`client::TlsStream::into_split`](crate::client::TlsStream::into_split)).
///
/// It reads plaintext with [`AsyncRead`]. A read still writes what the
/// peer's messages call for (see the crate documentation), and the peer's
/// `close_notify` is end of file. Dropping this half leaves the write half
/// working; the stream is dropped with the second half. After a panic in a
/// poll of either half, every operation fails (see
/// [`reunite`](Self::reunite)).
///
/// The half is not an [`AsyncBufRead`](tokio::io::AsyncBufRead): the
/// stream's buffer cannot be lent out between two polls while the other
/// half uses the stream. Wrap it in a `BufReader`, or
/// [`reunite`](Self::reunite) the halves.
pub struct ReadHalf<S> {
    shared: Arc<Shared<S>>,
}

/// The write half of a TLS stream `S`, from `into_split` (for example
/// [`client::TlsStream::into_split`](crate::client::TlsStream::into_split)).
///
/// It writes plaintext with [`AsyncWrite`]; `shutdown` sends `close_notify`
/// and shuts the transport's write side, after which the read half still
/// reads until the peer closes. Dropping this half sends nothing: call
/// `shutdown` first to close the TLS session properly.
///
/// Any operation, a zero-length write included, may return `Pending` while
/// a poll of the read half runs. After a panic in a poll of either half,
/// every operation fails (see [`reunite`](Self::reunite)).
pub struct WriteHalf<S> {
    shared: Arc<Shared<S>>,
}

/// What two halves share.
struct Shared<S> {
    /// The stream, locked for the length of one poll and only ever with
    /// `try_lock`: a half that finds it locked does not wait for it here.
    stream: Mutex<S>,
    /// The waker of each half that found the stream locked, by [`Side`].
    waiting: Mutex<[Option<Waker>; 2]>,
}

#[derive(Clone, Copy)]
enum Side {
    Read = 0,
    Write = 1,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Self::Read => Self::Write,
            Self::Write => Self::Read,
        }
    }
}

impl<S> Shared<S> {
    /// The stream, for the rest of this poll. `Pending` while the other
    /// half's poll has it; that poll's end wakes `cx`.
    fn poll_lock(&self, side: Side, cx: &mut Context<'_>) -> Poll<io::Result<Turn<'_, S>>> {
        if let Some(turn) = self.try_lock(side) {
            return Poll::Ready(turn);
        }
        // The other half is in a poll on another thread. Leave it a waker,
        // then look again: its poll may have ended before the waker was
        // there for it to find. It unlocks before it looks for a waker, and
        // both steps here and there lock `waiting`, so either it finds the
        // waker or the second look here finds the stream unlocked (or
        // locked by a later poll, whose end finds the waker).
        //
        // This holds only if `try_lock` fails for no other reason than a
        // held lock: a failure on a free stream would leave this half
        // waiting with nobody to wake it. `Mutex::try_lock` documents no
        // other reason, and std's locks have none (a strong compare and
        // exchange on futex targets).
        #[cfg(test)]
        tests::reached(tests::Point::BeforeWaiting);
        drop(self.set_waiting(side, Some(cx.waker().clone())));
        #[cfg(test)]
        tests::reached(tests::Point::BeforeSecondLook);
        match self.try_lock(side) {
            Some(turn) => {
                // The waker is not needed after all.
                drop(self.set_waiting(side, None));
                Poll::Ready(turn)
            }
            None => Poll::Pending,
        }
    }

    /// The stream if no poll has it; an error if a poll panicked with it.
    fn try_lock(&self, side: Side) -> Option<io::Result<Turn<'_, S>>> {
        match self.stream.try_lock() {
            Ok(stream) => Some(Ok(Turn {
                stream,
                _end: EndOfTurn { shared: self, side },
            })),
            Err(TryLockError::WouldBlock) => None,
            // A poisoned result still holds the stream lock. End its turn
            // normally so a half waiting on that lock gets its wakeup, but
            // never use the stream: its TLS state may be unknown.
            Err(TryLockError::Poisoned(poisoned)) => {
                let turn = Turn {
                    stream: poisoned.into_inner(),
                    _end: EndOfTurn { shared: self, side },
                };
                #[cfg(test)]
                tests::reached(tests::Point::PoisonedAcquired);
                drop(turn);
                Some(Err(io::Error::other(
                    "a poll of the other half of this TLS stream panicked",
                )))
            }
        }
    }

    /// Returns the waker that was there, for the caller to drop once
    /// `waiting` is unlocked again: dropping a waker runs its owner's code.
    #[must_use]
    fn set_waiting(&self, side: Side, waker: Option<Waker>) -> Option<Waker> {
        let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut waiting[side as usize], waker)
    }

    fn take_waiting(&self, side: Side) -> Option<Waker> {
        let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        waiting[side as usize].take()
    }
}

/// One half's turn with the stream, for the length of a poll.
struct Turn<'a, S> {
    stream: MutexGuard<'a, S>,
    /// Declared after `stream`, so dropped after it: the stream is unlocked
    /// before the other half is woken, also when the poll panics.
    _end: EndOfTurn<'a, S>,
}

/// Wakes the other half, if it waits for a turn, when dropped.
struct EndOfTurn<'a, S> {
    shared: &'a Shared<S>,
    side: Side,
}

impl<S> Drop for EndOfTurn<'_, S> {
    fn drop(&mut self) {
        // After a panicking poll this runs while unwinding, where a waker
        // that panicked in turn would abort the process, as with any wake
        // from a destructor. A runtime's wakers do not panic.
        if let Some(waker) = self.shared.take_waiting(self.side.other()) {
            waker.wake();
        }
    }
}

/// Runs one poll of `S` for `side`.
fn poll_with<S: Unpin, T>(
    shared: &Shared<S>,
    side: Side,
    cx: &mut Context<'_>,
    poll: impl FnOnce(Pin<&mut S>, &mut Context<'_>) -> Poll<io::Result<T>>,
) -> Poll<io::Result<T>> {
    let mut turn = ready!(shared.poll_lock(side, cx))?;
    poll(Pin::new(turn.stream.deref_mut()), cx)
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadHalf<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        poll_with(&self.shared, Side::Read, cx, |stream, cx| {
            stream.poll_read(cx, buf)
        })
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteHalf<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        poll_with(&self.shared, Side::Write, cx, |stream, cx| {
            stream.poll_write(cx, buf)
        })
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        poll_with(&self.shared, Side::Write, cx, |stream, cx| {
            stream.poll_write_vectored(cx, bufs)
        })
    }

    /// `true`: the halves are only made of this crate's TLS streams, which
    /// take every buffer of a vectored write.
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_with(&self.shared, Side::Write, cx, |stream, cx| {
            stream.poll_flush(cx)
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_with(&self.shared, Side::Write, cx, |stream, cx| {
            stream.poll_shutdown(cx)
        })
    }
}

impl<S> ReadHalf<S> {
    /// Whether `write` is the other half of the same stream.
    pub fn is_pair_of(&self, write: &WriteHalf<S>) -> bool {
        Arc::ptr_eq(&self.shared, &write.shared)
    }

    /// Puts the two halves of a stream back together.
    ///
    /// Fails, returning both, if they are halves of different streams.
    ///
    /// If a poll of either half panicked, the halves fail every operation,
    /// but this still returns the stream, in whatever state that poll left
    /// it: its TLS state is unknown, so use it only to get at the transport
    /// (`into_inner` of the client or server stream).
    pub fn reunite(self, write: WriteHalf<S>) -> Result<S, ReuniteError<S>> {
        reunite(self, write)
    }
}

impl<S> WriteHalf<S> {
    /// Whether `read` is the other half of the same stream.
    pub fn is_pair_of(&self, read: &ReadHalf<S>) -> bool {
        read.is_pair_of(self)
    }

    /// Puts the two halves of a stream back together.
    ///
    /// Fails, returning both, if they are halves of different streams.
    ///
    /// If a poll of either half panicked, the halves fail every operation,
    /// but this still returns the stream, in whatever state that poll left
    /// it: its TLS state is unknown, so use it only to get at the transport
    /// (`into_inner` of the client or server stream).
    pub fn reunite(self, read: ReadHalf<S>) -> Result<S, ReuniteError<S>> {
        reunite(read, self)
    }
}

fn reunite<S>(read: ReadHalf<S>, write: WriteHalf<S>) -> Result<S, ReuniteError<S>> {
    if !read.is_pair_of(&write) {
        return Err(ReuniteError(read, write));
    }
    drop(write);
    match Arc::try_unwrap(read.shared) {
        // A stream a poll panicked with is returned as that poll left it.
        Ok(shared) => Ok(shared
            .stream
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)),
        // Not reached: the two halves held the only references.
        Err(shared) => Err(ReuniteError(
            ReadHalf {
                shared: shared.clone(),
            },
            WriteHalf { shared },
        )),
    }
}

impl<S> fmt::Debug for ReadHalf<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadHalf").finish_non_exhaustive()
    }
}

impl<S> fmt::Debug for WriteHalf<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteHalf").finish_non_exhaustive()
    }
}

/// The two halves given to `reunite` belong to different streams; both are
/// returned.
pub struct ReuniteError<S>(pub ReadHalf<S>, pub WriteHalf<S>);

impl<S> fmt::Debug for ReuniteError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReuniteError").finish_non_exhaustive()
    }
}

impl<S> fmt::Display for ReuniteError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the halves are not the two halves of one TLS stream")
    }
}

impl<S> Error for ReuniteError<S> {}

#[cfg(test)]
mod tests;
