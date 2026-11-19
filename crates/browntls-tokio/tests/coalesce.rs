//! How TLS records reach the transport: a transport without a vectored write
//! gets small records gathered into one write, large records as they are,
//! and a transport with one gets the records as slices.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use common::*;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

/// What a TLS 1.3 record adds to its plaintext: the header, the content
/// type and the AEAD tag.
const OVERHEAD: usize = 5 + 1 + 16;

/// What a [`Recorder`] saw, and whether it lets writes through.
#[derive(Default)]
struct Log {
    /// The bytes of each `poll_write` the transport took.
    writes: Mutex<Vec<Vec<u8>>>,
    /// The slice lengths of each `poll_write_vectored`.
    vectored: Mutex<Vec<Vec<usize>>>,
    closed: AtomicBool,
    waiting: Mutex<Option<Waker>>,
}

impl Log {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
        if let Some(waker) = self.waiting.lock().unwrap().take() {
            waker.wake();
        }
    }

    /// Whether writes must wait; records the waker if so.
    fn blocks(&self, cx: &Context<'_>) -> bool {
        let closed = self.closed.load(Ordering::SeqCst);
        if closed {
            *self.waiting.lock().unwrap() = Some(cx.waker().clone());
        }
        closed
    }

    /// The lengths of the writes so far, forgetting them.
    fn take_write_lengths(&self) -> Vec<usize> {
        let writes = std::mem::take(&mut *self.writes.lock().unwrap());
        writes.iter().map(Vec::len).collect()
    }
}

/// A transport that records its writes and makes them wait while its log is
/// closed, as a socket with a full send buffer does. It has a vectored
/// write only if `vectored` says so.
struct Recorder {
    inner: DuplexStream,
    log: Arc<Log>,
    vectored: bool,
}

impl AsyncRead for Recorder {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Recorder {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.log.blocks(cx) {
            return Poll::Pending;
        }
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.log.writes.lock().unwrap().push(buf[..n].to_vec());
        }
        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        assert!(self.vectored, "a vectored write to a transport without one");
        if self.log.blocks(cx) {
            return Poll::Pending;
        }
        let mut total = 0;
        for buf in bufs {
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => total += n,
                other => panic!("the test transport is never full: {other:?}"),
            }
        }
        let lengths = bufs.iter().map(|buf| buf.len()).collect();
        self.log.vectored.lock().unwrap().push(lengths);
        Poll::Ready(Ok(total))
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// How many whole records `bytes` holds.
fn record_count(bytes: &[u8]) -> usize {
    let mut count = 0;
    let mut rest = bytes;
    while !rest.is_empty() {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        rest = &rest[5 + len..];
        count += 1;
    }
    count
}

/// A connected client over a [`Recorder`] and its peer.
async fn recorded_client(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
    vectored: bool,
) -> (
    browntls_tokio::client::TlsStream<Recorder>,
    browntls_tokio::server::TlsStream<DuplexStream>,
    Arc<Log>,
) {
    let (c, s) = duplex(1 << 20);
    let log = Arc::new(Log::default());
    let c = Recorder {
        inner: c,
        log: log.clone(),
        vectored,
    };
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            pki.connector(version).connect(localhost(), c),
            pki.acceptor(version).accept(s)
        )
    })
    .await
    .expect("handshake timed out");
    (client.unwrap(), server.unwrap(), log)
}

#[tokio::test]
async fn a_handshake_flight_reaches_a_plain_transport_in_one_write() {
    let pki = Pki::new();
    for version in versions() {
        let (c, s) = duplex(1 << 20);
        let log = Arc::new(Log::default());
        let s = Recorder {
            inner: s,
            log: log.clone(),
            vectored: false,
        };
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                pki.connector(version).connect(localhost(), c),
                pki.acceptor(version).accept(s)
            )
        })
        .await
        .expect("handshake timed out");
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        // The server's first flight is several records (ServerHello up to
        // Finished, or up to ServerHelloDone): one write carries them all,
        // and what the server sends after it (session tickets, or
        // ChangeCipherSpec and Finished) shares a write too.
        let writes = std::mem::take(&mut *log.writes.lock().unwrap());
        let records: Vec<usize> = writes.iter().map(|write| record_count(write)).collect();
        assert!(
            records.first().is_some_and(|&first| first >= 3),
            "{version:?}: {records:?} records per write"
        );
        assert!(
            records.iter().all(|&count| count >= 2),
            "{version:?}: {records:?} records per write"
        );

        server.write_all(b"after").await.unwrap();
        server.flush().await.unwrap();
        let mut buf = [0u8; 5];
        timeout(LIMIT, client.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"after");
    }
}

#[tokio::test]
async fn queued_records_share_a_write_on_a_plain_transport() {
    let pki = Pki::new();
    let (mut client, mut server, log) =
        recorded_client(&pki, &browntls_core::version::TLS13, false).await;
    log.take_write_lengths();

    // While the transport takes nothing, each write queues a record.
    log.close();
    let mut expected = Vec::new();
    for i in 0..5u8 {
        client.write_all(&[i; 100]).await.unwrap();
        expected.extend_from_slice(&[i; 100]);
    }
    assert!(log.take_write_lengths().is_empty());

    // Once it does, one write carries the five records.
    log.open();
    timeout(LIMIT, client.flush()).await.unwrap().unwrap();
    assert_eq!(log.take_write_lengths(), [5 * (100 + OVERHEAD)]);

    let mut received = vec![0u8; expected.len()];
    timeout(LIMIT, server.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn large_records_reach_a_plain_transport_as_they_are() {
    let pki = Pki::new();
    let (mut client, mut server, log) =
        recorded_client(&pki, &browntls_core::version::TLS13, false).await;
    log.take_write_lengths();

    // Full-size records are written one by one, without a copy: gathering
    // them would cost more than the writes it saves.
    let bulk = pattern(40_000);
    client.write_all(&bulk).await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(
        log.take_write_lengths(),
        [
            16_384 + OVERHEAD,
            16_384 + OVERHEAD,
            40_000 - 2 * 16_384 + OVERHEAD
        ]
    );

    // A record that does not fit with those gathered so far starts the next
    // write, and the order of the records never changes.
    log.close();
    let parts: [&[u8]; 5] = [&[1; 100], &[2; 100], &[3; 100], &[4; 9_000], &[5; 100]];
    for part in parts {
        client.write_all(part).await.unwrap();
    }
    log.open();
    timeout(LIMIT, client.flush()).await.unwrap().unwrap();
    assert_eq!(
        log.take_write_lengths(),
        [3 * (100 + OVERHEAD), 9_000 + OVERHEAD, 100 + OVERHEAD]
    );

    let expected = [bulk.as_slice(), &parts.concat()].concat();
    let mut received = vec![0u8; expected.len()];
    timeout(LIMIT, server.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn a_vectored_transport_gets_the_records_as_slices() {
    let pki = Pki::new();
    let (mut client, mut server, log) =
        recorded_client(&pki, &browntls_core::version::TLS13, true).await;
    log.vectored.lock().unwrap().clear();

    log.close();
    for i in 0..5u8 {
        client.write_all(&[i; 100]).await.unwrap();
    }
    log.open();
    timeout(LIMIT, client.flush()).await.unwrap().unwrap();
    assert_eq!(*log.vectored.lock().unwrap(), [vec![100 + OVERHEAD; 5]]);
    assert!(
        log.writes.lock().unwrap().is_empty(),
        "nothing was gathered"
    );

    let mut received = vec![0u8; 500];
    timeout(LIMIT, server.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received[400..], [4; 100]);
}
