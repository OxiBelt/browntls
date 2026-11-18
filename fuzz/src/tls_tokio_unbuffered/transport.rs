//! The in-memory transport of `tls_tokio_unbuffered`: two lanes of bytes,
//! one per direction, whose chunking, `Pending` points, capacity and
//! failures the input sets.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The bytes a lane holds when the input does not say.
const DEFAULT_CAPACITY: usize = 64 * 1024;

/// A lane failure the input asked for. Like a socket's, it is permanent:
/// a stream whose write failed keeps the records it could not write, and
/// would deliver them, after reporting the failure, if the transport came
/// back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    /// Writes report that the transport took nothing (`Ok(0)`).
    WriteZero,
    /// Writes and flushes fail.
    WriteError,
    /// Reads fail.
    ReadError,
}

/// One direction of the transport: bytes written by one side for the other.
#[derive(Default)]
pub(super) struct Lane {
    pub(super) bytes: VecDeque<u8>,
    /// The writer shut its side down, or the input ended the lane: end of
    /// file for the reader once the lane is empty, an error for the writer.
    /// A closed lane never gains bytes.
    pub(super) closed: bool,
    /// The reader was told of the end of file: it is told again at once,
    /// as a socket does.
    ended: bool,
    /// The failures in force, indexed by [`Fault`].
    faults: [bool; 3],
    /// Largest number of bytes per read or write call (at least 1).
    chunk: usize,
    /// How many bytes the lane holds before writes wait.
    capacity: usize,
    /// Bit `i % 8` set: the `i`th read (mask 0), and the `i`th write and
    /// the `i`th flush (mask 1), return `Pending`.
    masks: [u8; 2],
    /// Calls so far: reads, writes, flushes.
    calls: [u32; 3],
}

impl Lane {
    /// Applies four settings bytes: chunk size, read mask, write mask,
    /// capacity.
    pub(super) fn configure(&mut self, settings: [u8; 4]) {
        let [chunk, read_mask, write_mask, capacity] = settings.map(usize::from);
        self.chunk = match chunk {
            0..32 => chunk.max(1),
            _ => (chunk - 31) * 128,
        };
        self.masks = [read_mask as u8, write_mask as u8];
        self.capacity = match capacity {
            0 => DEFAULT_CAPACITY,
            _ => capacity * 256,
        };
    }

    /// Makes the lane fail from now on.
    pub(super) fn fail(&mut self, fault: Fault) {
        self.faults[fault as usize] = true;
    }

    fn has(&self, fault: Fault) -> bool {
        self.faults[fault as usize]
    }

    fn pending(&mut self, call: usize) -> bool {
        let calls = &mut self.calls[call];
        let bit = *calls % 8;
        *calls = calls.wrapping_add(1);
        self.masks[call.min(1)] & (1 << bit) != 0
    }

    /// Appends bytes behind the transport's back (injected bytes, or what a
    /// stream taken apart had left to write). Returns whether they went in.
    pub(super) fn push(&mut self, bytes: &[u8]) -> bool {
        if self.closed || self.has(Fault::WriteZero) || self.has(Fault::WriteError) {
            return false;
        }
        self.bytes.extend(bytes);
        true
    }
}

/// Both lanes; lane `side` carries what that side writes.
#[derive(Default)]
pub(super) struct Wire {
    pub(super) lanes: [Lane; 2],
    /// Set while the harness lets everything in flight arrive: the `Pending`
    /// masks are ignored, so that a poll only waits for bytes or for room.
    pub(super) settling: bool,
    /// Bytes that entered or left a lane, in total.
    pub(super) moved: u64,
}

impl Wire {
    pub(super) fn new(settings: [u8; 8]) -> Rc<RefCell<Self>> {
        let mut wire = Self::default();
        let (client, server) = settings.split_at(4);
        for (lane, settings) in wire.lanes.iter_mut().zip([client, server]) {
            lane.configure([settings[0], settings[1], settings[2], settings[3]]);
        }
        Rc::new(RefCell::new(wire))
    }

    /// Takes everything in flight toward `side`.
    pub(super) fn take_all(&mut self, side: usize, into: &mut Vec<u8>) {
        let lane = &mut self.lanes[1 - side];
        self.moved += lane.bytes.len() as u64;
        into.extend(lane.bytes.drain(..));
    }
}

fn broken() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}

fn reset() -> io::Error {
    io::ErrorKind::ConnectionReset.into()
}

/// One end of the transport.
pub(super) struct End {
    pub(super) wire: Rc<RefCell<Wire>>,
    pub(super) side: usize,
}

impl fmt::Debug for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "End({})", self.side)
    }
}

impl AsyncRead for End {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut wire = self.wire.borrow_mut();
        let settling = wire.settling;
        let lane = &mut wire.lanes[1 - self.side];
        if lane.has(Fault::ReadError) {
            return Poll::Ready(Err(reset()));
        }
        if lane.pending(0) && !settling && !lane.ended {
            return Poll::Pending;
        }
        if lane.bytes.is_empty() {
            lane.ended = lane.closed;
            return if lane.closed {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }
        let n = buf.remaining().min(lane.chunk).min(lane.bytes.len());
        let (front, back) = lane.bytes.as_slices();
        let from_front = n.min(front.len());
        buf.put_slice(&front[..from_front]);
        buf.put_slice(&back[..n - from_front]);
        lane.bytes.drain(..n);
        wire.moved += n as u64;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for End {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut wire = self.wire.borrow_mut();
        let settling = wire.settling;
        let lane = &mut wire.lanes[self.side];
        if lane.closed {
            return Poll::Ready(Err(broken()));
        }
        if lane.has(Fault::WriteError) {
            return Poll::Ready(Err(reset()));
        }
        if lane.has(Fault::WriteZero) {
            return Poll::Ready(Ok(0));
        }
        if lane.pending(1) && !settling || lane.bytes.len() >= lane.capacity {
            return Poll::Pending;
        }
        let n = buf
            .len()
            .min(lane.chunk)
            .min(lane.capacity - lane.bytes.len());
        lane.bytes.extend(&buf[..n]);
        wire.moved += n as u64;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut wire = self.wire.borrow_mut();
        let settling = wire.settling;
        let lane = &mut wire.lanes[self.side];
        if lane.has(Fault::WriteError) {
            return Poll::Ready(Err(reset()));
        }
        if lane.pending(2) && !settling {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wire.borrow_mut().lanes[self.side].closed = true;
        Poll::Ready(Ok(()))
    }
}
