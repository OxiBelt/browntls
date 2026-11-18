//! One transport write for several TLS records, for transports without a
//! vectored write.
//!
//! `write_tls` offers the queued records as separate slices. A transport
//! that reports no efficient vectored write ([`AsyncWrite::is_write_vectored`])
//! usually has Tokio's default `poll_write_vectored`, which writes only the
//! first slice, so every record would cost a write of its own: a handshake
//! flight of six records, six writes. [`poll_write_coalesced`] copies whole
//! records into a buffer on the stack and writes them together instead. The
//! report decides: a `poll_write_vectored` the transport does not report is
//! not called.

use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncWrite, ReadBuf};

/// The most bytes gathered into one write. A slice that does not fit with
/// those before it starts the next write, and a first slice that fits with
/// no other is written from where it is: full-size records are never
/// copied.
pub(crate) const COALESCE_LEN: usize = 8 * 1024;

/// Writes the first slices of `bufs` to `io` with one `poll_write`: as many
/// whole non-empty slices as fit in [`COALESCE_LEN`] bytes together, or the
/// first non-empty slice alone when no second one fits with it. Returns the
/// bytes `io` took, counted from the start of `bufs` as a vectored write
/// counts them; nothing is kept between calls.
pub(crate) fn poll_write_coalesced<T: AsyncWrite + ?Sized>(
    io: Pin<&mut T>,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
) -> Poll<io::Result<usize>> {
    let mut bufs = bufs.iter().filter(|buf| !buf.is_empty());
    let Some(first) = bufs.next() else {
        return io.poll_write(cx, &[]);
    };
    let second = bufs
        .next()
        .filter(|second| first.len().saturating_add(second.len()) <= COALESCE_LEN);
    let Some(second) = second else {
        return io.poll_write(cx, first);
    };

    let mut storage = [MaybeUninit::<u8>::uninit(); COALESCE_LEN];
    let mut gathered = ReadBuf::uninit(&mut storage);
    gathered.put_slice(first);
    gathered.put_slice(second);
    for buf in bufs {
        if buf.len() > gathered.remaining() {
            break;
        }
        gathered.put_slice(buf);
    }
    io.poll_write(cx, gathered.filled())
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use super::*;

    /// Records each write; takes at most `accept` bytes of it, or none
    /// (`Pending`) while `blocked`.
    struct Sink {
        writes: Vec<Vec<u8>>,
        accept: usize,
        blocked: bool,
    }

    impl Sink {
        fn new() -> Self {
            Self {
                writes: Vec::new(),
                accept: usize::MAX,
                blocked: false,
            }
        }

        fn write(&mut self, slices: &[&[u8]]) -> Poll<io::Result<usize>> {
            let bufs: Vec<IoSlice<'_>> = slices.iter().map(|s| IoSlice::new(s)).collect();
            let mut cx = Context::from_waker(Waker::noop());
            poll_write_coalesced(Pin::new(self), &mut cx, &bufs)
        }
    }

    impl AsyncWrite for Sink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.blocked {
                return Poll::Pending;
            }
            let take = buf.len().min(self.accept);
            self.writes.push(buf[..take].to_vec());
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn taken(poll: Poll<io::Result<usize>>) -> usize {
        match poll {
            Poll::Ready(Ok(n)) => n,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn small_slices_share_one_write_in_order() {
        let mut sink = Sink::new();
        assert_eq!(taken(sink.write(&[b"one", b"", b"two", b"three"])), 11);
        assert_eq!(sink.writes, [b"onetwothree".to_vec()]);
    }

    #[test]
    fn a_slice_that_does_not_fit_starts_the_next_write() {
        let small = [1u8; 100];
        let filler = [2u8; COALESCE_LEN - 200];
        let big = [3u8; 101];
        let mut sink = Sink::new();
        // Exactly full with the third slice.
        assert_eq!(
            taken(sink.write(&[&small, &filler, &small, &small])),
            COALESCE_LEN
        );
        assert_eq!(sink.writes[0].len(), COALESCE_LEN);
        assert_eq!(sink.writes[0][COALESCE_LEN - 100..], small);
        // One byte too many: the third slice is left out, and so is the
        // smaller one behind it (slices are never reordered).
        assert_eq!(
            taken(sink.write(&[&small, &filler, &big, &small])),
            COALESCE_LEN - 100
        );
        assert_eq!(sink.writes[1], [&small[..], &filler[..]].concat());
    }

    #[test]
    fn a_slice_no_other_fits_with_is_written_alone() {
        let full = [7u8; COALESCE_LEN];
        let large = [8u8; 3 * COALESCE_LEN];
        let mut sink = Sink::new();
        assert_eq!(taken(sink.write(&[&large, b"x"])), large.len());
        assert_eq!(taken(sink.write(&[&full, b"x"])), full.len());
        assert_eq!(taken(sink.write(&[b"x", &full])), 1);
        assert_eq!(taken(sink.write(&[b"", b"only"])), 4);
        assert_eq!(
            sink.writes,
            [
                large.to_vec(),
                full.to_vec(),
                b"x".to_vec(),
                b"only".to_vec()
            ]
        );
    }

    #[test]
    fn the_count_is_what_the_transport_took() {
        let mut sink = Sink::new();
        sink.accept = 4;
        assert_eq!(taken(sink.write(&[b"abc", b"def"])), 4);
        assert_eq!(sink.writes, [b"abcd".to_vec()]);

        // Empty slices take no part in the count.
        assert_eq!(taken(sink.write(&[b"", b"abc", b"", b"def"])), 4);
        assert_eq!(sink.writes[1], b"abcd");

        sink.blocked = true;
        assert!(sink.write(&[b"abc", b"def"]).is_pending());
        assert!(sink.write(&[b"abc"]).is_pending());
        assert_eq!(sink.writes.len(), 2);
    }

    #[test]
    fn no_data_is_an_empty_write() {
        let mut sink = Sink::new();
        assert_eq!(taken(sink.write(&[])), 0);
        assert_eq!(taken(sink.write(&[b"", b""])), 0);
        assert_eq!(sink.writes, [Vec::<u8>::new(), Vec::new()]);
    }
}
