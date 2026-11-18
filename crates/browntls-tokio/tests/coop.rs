//! Cooperative scheduling: with the `coop` feature a task cannot keep a
//! worker to itself through a TLS stream, even over a transport that is
//! always ready and takes no part in Tokio's task budget. Without the
//! feature the same operations run on for as long as they are ready.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use browntls::server::Acceptor;
use browntls_tokio::{LazyConfigAcceptor, client, server};
use common::{Pki, localhost, pattern};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// The operations Tokio lets a task complete before it must yield.
const BUDGET: usize = 128;

/// One direction of an in-memory connection.
#[derive(Default)]
struct Channel {
    bytes: VecDeque<u8>,
    closed: bool,
    reader: Option<Waker>,
}

/// One end of an in-memory connection that, unlike `tokio::io::duplex`,
/// takes no part in the task budget: writes always complete, and reads
/// complete whenever bytes are queued.
struct RawPipe {
    incoming: Arc<Mutex<Channel>>,
    outgoing: Arc<Mutex<Channel>>,
    /// The most bytes one read returns.
    max_read: usize,
    /// How many reads returned bytes.
    reads: Arc<AtomicUsize>,
}

/// A connected pair; the first end's reads return at most `max_read` bytes.
fn raw_pair(max_read: usize) -> (RawPipe, RawPipe) {
    let a_to_b = Arc::new(Mutex::new(Channel::default()));
    let b_to_a = Arc::new(Mutex::new(Channel::default()));
    (
        RawPipe {
            incoming: b_to_a.clone(),
            outgoing: a_to_b.clone(),
            max_read,
            reads: Arc::default(),
        },
        RawPipe {
            incoming: a_to_b,
            outgoing: b_to_a,
            max_read: usize::MAX,
            reads: Arc::default(),
        },
    )
}

impl AsyncRead for RawPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut channel = self.incoming.lock().unwrap();
        if channel.bytes.is_empty() {
            if channel.closed {
                return Poll::Ready(Ok(()));
            }
            channel.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let len = buf.remaining().min(self.max_read).min(channel.bytes.len());
        for byte in channel.bytes.drain(..len) {
            buf.put_slice(&[byte]);
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RawPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut channel = self.outgoing.lock().unwrap();
        channel.bytes.extend(buf);
        if let Some(waker) = channel.reader.take() {
            waker.wake();
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut channel = self.outgoing.lock().unwrap();
        channel.closed = true;
        if let Some(waker) = channel.reader.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

/// A connected client and server over a [`RawPipe`] pair; the client's
/// transport reads return at most `max_read` bytes.
async fn tls_pair(max_read: usize) -> (client::TlsStream<RawPipe>, server::TlsStream<RawPipe>) {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let (client_io, server_io) = raw_pair(max_read);
    let accept = tokio::spawn(pki.acceptor(version).accept(server_io));
    let client = pki
        .connector(version)
        .connect(localhost(), client_io)
        .await
        .unwrap();
    (client, accept.await.unwrap().unwrap())
}

/// Checks how the polls of a task went: `counts` holds, for each poll, how
/// many steps it completed, and there were more steps to do than `limit`.
/// With the `coop` feature the fullest poll stops at `limit` exactly (no
/// later, and no earlier: nothing takes more than its unit); without the
/// feature some poll goes past it, since nothing stops it.
fn assert_budgeted(counts: &[usize], limit: usize) {
    let most = counts.iter().copied().max().unwrap();
    if cfg!(feature = "coop") {
        assert_eq!(most, limit, "the fullest poll: {counts:?}");
    } else {
        assert!(most > limit, "no poll went past {limit}: {counts:?}");
    }
}

/// Reads `len` bytes one at a time, in a task of its own. Returns the bytes
/// and how many reads completed in each poll of the task.
async fn read_bytewise<F>(
    mut stream: client::TlsStream<RawPipe>,
    len: usize,
    wrap: impl FnOnce(Pin<Box<dyn Future<Output = (Vec<u8>, Vec<usize>)> + Send>>) -> F,
) -> (Vec<u8>, Vec<usize>)
where
    F: Future<Output = (Vec<u8>, Vec<usize>)> + Send + 'static,
{
    let reading = async move {
        let mut bytes = Vec::new();
        let mut counts = Vec::new();
        poll_fn(|cx| {
            let mut count = 0;
            let poll = loop {
                let mut byte = [0u8];
                let mut buf = ReadBuf::new(&mut byte);
                match Pin::new(&mut stream).poll_read(cx, &mut buf) {
                    Poll::Ready(result) => {
                        result.unwrap();
                        bytes.push(byte[0]);
                        count += 1;
                        if bytes.len() == len {
                            break Poll::Ready(());
                        }
                    }
                    Poll::Pending => break Poll::Pending,
                }
            };
            counts.push(count);
            poll
        })
        .await;
        (bytes, counts)
    };
    tokio::spawn(wrap(Box::pin(reading))).await.unwrap()
}

#[tokio::test]
async fn reads_of_buffered_plaintext_spend_the_budget() {
    const LEN: usize = 4096;
    let (client, mut server) = tls_pair(usize::MAX).await;
    // One record: the first read buffers all of it, and the rest of the
    // reads never touch the transport.
    server.write_all(&pattern(LEN)).await.unwrap();
    server.flush().await.unwrap();

    let (bytes, counts) = read_bytewise(client, LEN, |reading| reading).await;
    assert_eq!(bytes, pattern(LEN));
    assert_budgeted(&counts, BUDGET);
}

#[cfg(feature = "coop")]
#[tokio::test]
async fn an_unconstrained_task_reads_on() {
    const LEN: usize = 4096;
    let (client, mut server) = tls_pair(usize::MAX).await;
    server.write_all(&pattern(LEN)).await.unwrap();
    server.flush().await.unwrap();

    let (bytes, counts) = read_bytewise(client, LEN, tokio::task::coop::unconstrained).await;
    assert_eq!(bytes, pattern(LEN));
    assert_eq!(counts, [LEN]);
}

#[tokio::test]
async fn writes_spend_the_budget() {
    const WRITES: usize = 1000;
    let (mut client, _server) = tls_pair(usize::MAX).await;

    let counts = tokio::spawn(async move {
        let mut counts = Vec::new();
        let mut written = 0;
        poll_fn(|cx| {
            let mut count = 0;
            let poll = loop {
                match Pin::new(&mut client).poll_write(cx, b"x") {
                    Poll::Ready(result) => {
                        assert_eq!(result.unwrap(), 1);
                        written += 1;
                        count += 1;
                        if written == WRITES {
                            break Poll::Ready(());
                        }
                    }
                    Poll::Pending => break Poll::Pending,
                }
            };
            counts.push(count);
            poll
        })
        .await;
        counts
    })
    .await
    .unwrap();
    assert_eq!(counts.iter().sum::<usize>(), WRITES);
    assert_budgeted(&counts, BUDGET);
}

/// Polls `future` to completion in a task of its own. Returns its output
/// and how many transport reads (counted by `reads`) each poll made.
async fn count_reads_per_poll<F>(future: F, reads: Arc<AtomicUsize>) -> (F::Output, Vec<usize>)
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    tokio::spawn(async move {
        let mut future = Box::pin(future);
        let mut counts = Vec::new();
        let output = poll_fn(|cx| {
            let before = reads.load(Ordering::Relaxed);
            let poll = future.as_mut().poll(cx);
            counts.push(reads.load(Ordering::Relaxed) - before);
            poll
        })
        .await;
        (output, counts)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn buffered_reads_and_flushes_spend_the_budget_on_the_server() {
    const LEN: usize = 4096;
    const FLUSHES: usize = 1000;
    let (mut client, mut server) = tls_pair(usize::MAX).await;
    client.write_all(&pattern(LEN)).await.unwrap();
    client.flush().await.unwrap();

    let (bytes, reads, flushes) = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let mut reads = Vec::new();
        poll_fn(|cx| {
            let mut count = 0;
            let poll = loop {
                match Pin::new(&mut server).poll_fill_buf(cx) {
                    Poll::Ready(chunk) => {
                        bytes.push(chunk.unwrap()[0]);
                        Pin::new(&mut server).consume(1);
                        count += 1;
                        if bytes.len() == LEN {
                            break Poll::Ready(());
                        }
                    }
                    Poll::Pending => break Poll::Pending,
                }
            };
            reads.push(count);
            poll
        })
        .await;

        let mut flushes = Vec::new();
        let mut flushed = 0;
        poll_fn(|cx| {
            let mut count = 0;
            let poll = loop {
                match Pin::new(&mut server).poll_flush(cx) {
                    Poll::Ready(result) => {
                        result.unwrap();
                        flushed += 1;
                        count += 1;
                        if flushed == FLUSHES {
                            break Poll::Ready(());
                        }
                    }
                    Poll::Pending => break Poll::Pending,
                }
            };
            flushes.push(count);
            poll
        })
        .await;
        (bytes, reads, flushes)
    })
    .await
    .unwrap();
    assert_eq!(bytes, pattern(LEN));
    assert_budgeted(&reads, BUDGET);
    assert_budgeted(&flushes, BUDGET);
}

/// Takes every unit left in the budget of the task being polled. Returns
/// how many there were.
fn drain_budget(cx: &mut Context<'_>) -> usize {
    let mut units = 0;
    while let Poll::Ready(unit) = tokio::task::coop::poll_proceed(cx) {
        unit.made_progress();
        units += 1;
    }
    units
}

#[tokio::test]
async fn a_read_left_waiting_by_the_transport_takes_nothing_from_the_budget() {
    let (mut client, server) = tls_pair(usize::MAX).await;
    // A record the client receives in two parts.
    let (server_io, mut connection) = server.into_inner();
    io::Write::write_all(&mut connection.writer(), b"hello").unwrap();
    let mut record = Vec::new();
    connection.write_tls(&mut record).unwrap();
    let rest = record.split_off(10);
    let deliver = |bytes: &[u8]| {
        let mut channel = server_io.outgoing.lock().unwrap();
        channel.bytes.extend(bytes);
        if let Some(waker) = channel.reader.take() {
            waker.wake();
        }
    };
    deliver(&record);

    let reads = client.get_ref().0.reads.clone();
    let before = reads.load(Ordering::Relaxed);
    let (mut client, left) = tokio::spawn(async move {
        let left = poll_fn(|cx| {
            // The first transport read is free and returns the first part.
            // The second takes a unit, finds the transport not ready and
            // gives the unit back.
            let mut byte = [0u8];
            let mut buf = ReadBuf::new(&mut byte);
            assert!(Pin::new(&mut client).poll_read(cx, &mut buf).is_pending());
            Poll::Ready(drain_budget(cx))
        })
        .await;
        (client, left)
    })
    .await
    .unwrap();
    assert_eq!(reads.load(Ordering::Relaxed) - before, 1);
    assert_eq!(left, BUDGET);

    deliver(&rest);
    let mut hello = [0; 5];
    client.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
}

#[cfg(feature = "coop")]
#[tokio::test]
async fn an_operation_started_without_budget_changes_nothing() {
    let (mut client, mut server) = tls_pair(usize::MAX).await;
    server.write_all(b"pong").await.unwrap();
    server.flush().await.unwrap();

    let reads = client.get_ref().0.reads.clone();
    let rescheduled = tokio::spawn(async move {
        let mut polls = 0;
        poll_fn(|cx| {
            polls += 1;
            if polls > 1 {
                // The spent budget rescheduled the task.
                return Poll::Ready(());
            }
            assert_eq!(drain_budget(cx), BUDGET);
            let before = reads.load(Ordering::Relaxed);
            let mut byte = [0u8];
            let mut buf = ReadBuf::new(&mut byte);
            assert!(Pin::new(&mut client).poll_read(cx, &mut buf).is_pending());
            assert!(buf.filled().is_empty());
            assert!(Pin::new(&mut client).poll_fill_buf(cx).is_pending());
            assert!(Pin::new(&mut client).poll_write(cx, b"lost?").is_pending());
            assert!(Pin::new(&mut client).poll_flush(cx).is_pending());
            assert!(Pin::new(&mut client).poll_shutdown(cx).is_pending());
            // Nothing reached the transport or the connection.
            assert_eq!(reads.load(Ordering::Relaxed), before);
            Poll::Pending
        })
        .await;
        client
    });
    let mut client = tokio::time::timeout(Duration::from_secs(60), rescheduled)
        .await
        .expect("the spent budget did not reschedule the task")
        .unwrap();

    // Neither the refused write nor the refused shutdown left a trace.
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut ping = [0; 4];
    server.read_exact(&mut ping).await.unwrap();
    assert_eq!(&ping, b"ping");
    let mut pong = [0; 4];
    client.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_halves_on_four_workers_move_data_both_ways() {
    const LEN: usize = 1 << 20;
    // The client's transport reads return a few bytes each, so its reads
    // run out of budget time and again while its writes go on.
    for max_read in [5, 4096, usize::MAX] {
        let (client, server) = tls_pair(max_read).await;
        let (mut client_rd, mut client_wr) = tokio::io::split(client);
        let (mut server_rd, mut server_wr) = tokio::io::split(server);
        let to_server = pattern(LEN);
        let to_client: Vec<u8> = pattern(LEN).into_iter().rev().collect();

        let data = to_server.clone();
        let client_writer = tokio::spawn(async move {
            for chunk in data.chunks(1021) {
                client_wr.write_all(chunk).await.unwrap();
            }
            client_wr.shutdown().await.unwrap();
        });
        let data = to_client.clone();
        let server_writer = tokio::spawn(async move {
            for chunk in data.chunks(70_001) {
                server_wr.write_all(chunk).await.unwrap();
                server_wr.flush().await.unwrap();
            }
            server_wr.shutdown().await.unwrap();
        });
        let client_reader = tokio::spawn(async move {
            let mut received = Vec::new();
            client_rd.read_to_end(&mut received).await.unwrap();
            received
        });
        let server_reader = tokio::spawn(async move {
            let mut received = Vec::new();
            server_rd.read_to_end(&mut received).await.unwrap();
            received
        });

        let (client_wrote, server_wrote, at_client, at_server) =
            tokio::time::timeout(Duration::from_secs(60), async {
                tokio::join!(client_writer, server_writer, client_reader, server_reader)
            })
            .await
            .expect("the halves stopped moving data");
        client_wrote.unwrap();
        server_wrote.unwrap();
        assert!(
            at_client.unwrap() == to_client,
            "the client read other bytes"
        );
        assert!(
            at_server.unwrap() == to_server,
            "the server read other bytes"
        );
    }
}

// In the five tests below the transport hands the reader a little at a
// time and is always ready, so one poll would read on until the operation
// completed. A poll's first read is free and each later one takes a unit.

/// Reads `len` bytes from `stream`, offering each read all of the buffer
/// that is left and reading on within one poll for as long as reads
/// complete.
async fn read_filling<S: AsyncRead + Unpin>(mut stream: S, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    let mut filled = 0;
    poll_fn(|cx| {
        while filled < len {
            let mut buf = ReadBuf::new(&mut bytes[filled..]);
            match Pin::new(&mut stream).poll_read(cx, &mut buf) {
                Poll::Ready(result) => {
                    result.unwrap();
                    assert!(!buf.filled().is_empty(), "end of file");
                    filled += buf.filled().len();
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(())
    })
    .await;
    bytes
}

/// How the polls of a task went that read many more one-byte records than
/// the budget allows in one poll: see [`assert_budgeted`]; and the first
/// read is free in every poll, not only in the first.
fn assert_budgeted_in_every_poll(counts: &[usize]) {
    assert_budgeted(counts, 1 + BUDGET);
    if cfg!(feature = "coop") {
        let (_last, full) = counts.split_last().unwrap();
        assert!(full.iter().all(|&count| count == 1 + BUDGET), "{counts:?}");
    }
}

/// A TLS 1.3 record of one byte of application data.
const SMALL_RECORD: usize = 5 + 1 + 1 + 16;

#[tokio::test]
async fn a_server_read_of_many_small_records_spends_the_budget() {
    const LEN: usize = 4096;
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let (server_io, client_io) = raw_pair(SMALL_RECORD);
    let reads = server_io.reads.clone();
    let accept = tokio::spawn(pki.acceptor(version).accept(server_io));
    let mut client = pki
        .connector(version)
        .connect(localhost(), client_io)
        .await
        .unwrap();
    let server = accept.await.unwrap().unwrap();
    for byte in pattern(LEN) {
        client.write_all(&[byte]).await.unwrap();
        client.flush().await.unwrap();
    }

    let (bytes, counts) = count_reads_per_poll(read_filling(server, LEN), reads).await;
    assert_eq!(bytes, pattern(LEN));
    assert_budgeted_in_every_poll(&counts);
}

#[tokio::test]
async fn a_read_of_many_small_records_spends_the_budget() {
    const LEN: usize = 4096;
    let (client, mut server) = tls_pair(SMALL_RECORD).await;
    for byte in pattern(LEN) {
        server.write_all(&[byte]).await.unwrap();
        server.flush().await.unwrap();
    }

    // Each transport read returns one record, which has plaintext for the
    // caller: reading on is what fills the caller's large buffer.
    let reads = client.get_ref().0.reads.clone();
    let (bytes, counts) = count_reads_per_poll(read_filling(client, LEN), reads).await;
    assert_eq!(bytes, pattern(LEN));
    assert_budgeted_in_every_poll(&counts);
}

#[tokio::test]
async fn a_read_that_needs_many_transport_reads_spends_the_budget() {
    const LEN: usize = 4096;
    let (client, mut server) = tls_pair(1).await;
    server.write_all(&pattern(LEN)).await.unwrap();
    server.flush().await.unwrap();

    let reads = client.get_ref().0.reads.clone();
    let (bytes, counts) = count_reads_per_poll(read_filling(client, LEN), reads).await;
    assert_eq!(bytes, pattern(LEN));
    assert_budgeted(&counts, 1 + BUDGET);
}

#[tokio::test]
async fn a_handshake_in_small_pieces_spends_the_budget() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let (client_io, server_io) = raw_pair(1);
    let reads = client_io.reads.clone();
    let accept = tokio::spawn(pki.acceptor(version).accept(server_io));

    // The server writes its whole flight at once, so the client can read
    // it, a byte at a time, in one poll.
    let connect = pki.connector(version).connect(localhost(), client_io);
    let (result, counts) = count_reads_per_poll(connect, reads).await;
    let mut client = result.unwrap();
    let mut server = accept.await.unwrap().unwrap();
    assert_budgeted(&counts, 1 + BUDGET);

    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut ping = [0; 4];
    server.read_exact(&mut ping).await.unwrap();
    assert_eq!(&ping, b"ping");
}

#[tokio::test]
async fn a_client_hello_in_small_pieces_spends_the_budget() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let (server_io, client_io) = raw_pair(1);
    let reads = server_io.reads.clone();

    // The client's first poll writes its whole ClientHello into the pipe.
    let mut connect = Box::pin(pki.connector(version).connect(localhost(), client_io));
    assert!(poll_fn(|cx| Poll::Ready(connect.as_mut().poll(cx).is_pending())).await);

    let lazy = LazyConfigAcceptor::new(Acceptor::default(), server_io);
    let (start, counts) = count_reads_per_poll(lazy, reads).await;
    let start = start.unwrap();
    assert_eq!(start.client_hello().server_name(), Some("localhost"));
    assert_budgeted(&counts, 1 + BUDGET);

    let config = Arc::new(pki.server_config(version));
    let (client, server) = tokio::join!(connect, start.into_stream(config));
    client.unwrap();
    server.unwrap();
}
