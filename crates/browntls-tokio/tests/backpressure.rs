//! Reads stop taking input while the answers they owe the peer cannot be
//! written, without spinning, and resume once the transport takes them.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::poll_fn;
use std::io::{self, Write as _};
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

/// Whether a [`Gate`] lets writes through, and the writer waiting for it.
#[derive(Default)]
struct GateState {
    closed: AtomicBool,
    waiting: Mutex<Option<Waker>>,
}

impl GateState {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
        if let Some(waker) = self.waiting.lock().unwrap().take() {
            waker.wake();
        }
    }
}

/// A transport whose writes wait (`Pending`) while its gate is closed, as a
/// socket does when the peer reads nothing and the send buffer is full.
struct Gate {
    inner: DuplexStream,
    state: Arc<GateState>,
}

impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.state.closed.load(Ordering::SeqCst) {
            *self.state.waiting.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn reads_wait_for_owed_answers_to_be_written() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let (c, s) = duplex(1 << 20);
    let gate = Arc::new(GateState::default());
    let s = Gate {
        inner: s,
        state: gate.clone(),
    };

    // The server's send buffer limit, and so the backlog of control records
    // it lets pile up unwritten, is smaller than one KeyUpdate answer.
    let (client, server) = tokio::join!(
        pki.connector(version).connect(localhost(), c),
        pki.acceptor(version)
            .accept_with(s, |conn| conn.set_buffer_limit(Some(16))),
    );
    let (mut client_io, mut client) = client.unwrap().into_inner();
    let mut server = server.unwrap();

    // The server's transport stops taking bytes; the peer asks for a
    // KeyUpdate and then sends more data than one read takes in.
    gate.close();
    let data = pattern(256 * 1024);
    client.refresh_traffic_keys().unwrap();
    let mut records = Vec::new();
    for chunk in data.chunks(4096) {
        client.writer().write_all(chunk).unwrap();
        while client.wants_write() {
            client.write_tls(&mut records).unwrap();
        }
    }
    client_io.write_all(&records).await.unwrap();

    // The server reads what it had taken in before its answer was queued,
    // then waits: it neither takes more input nor spins.
    let mut received = vec![0u8; data.len()];
    let mut got = 0;
    let mut polls = 0usize;
    let reading = poll_fn(|cx| {
        polls += 1;
        loop {
            let mut buf = ReadBuf::new(&mut received[got..]);
            match Pin::new(&mut server).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) if buf.filled().is_empty() => return Poll::Ready(()),
                Poll::Ready(Ok(())) => {
                    got += buf.filled().len();
                    if got == data.len() {
                        return Poll::Ready(());
                    }
                }
                Poll::Ready(Err(err)) => panic!("read failed: {err}"),
                Poll::Pending => return Poll::Pending,
            }
        }
    });
    let blocked = timeout(Duration::from_millis(300), reading).await;
    assert!(blocked.is_err(), "the server read everything ({got} bytes)");
    assert!(got < data.len());
    assert!(polls < 100, "{polls} polls while the transport was blocked");

    // Once the transport takes bytes again, the answer goes out and the
    // server reads the rest.
    gate.open();
    timeout(LIMIT, server.read_exact(&mut received[got..]))
        .await
        .expect("the server never resumed reading")
        .unwrap();
    assert_eq!(received, data);

    // The peer accepts the server's answer.
    let mut answer = vec![0u8; 4096];
    let n = timeout(LIMIT, client_io.read(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(n, 0);
    client.read_tls(&mut &answer[..n]).unwrap();
    client.process_new_packets().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_reader_waiting_for_answers_wakes_when_the_writer_sends_them() {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let (c, s) = duplex(1 << 20);
    let gate = Arc::new(GateState::default());
    let s = Gate {
        inner: s,
        state: gate.clone(),
    };
    let (client, server) = tokio::join!(
        pki.connector(version).connect(localhost(), c),
        pki.acceptor(version)
            .accept_with(s, |conn| conn.set_buffer_limit(Some(16))),
    );
    let (mut client_io, mut client) = client.unwrap().into_inner();
    let server = server.unwrap();

    gate.close();
    let data = pattern(256 * 1024);
    client.refresh_traffic_keys().unwrap();
    let mut records = Vec::new();
    for chunk in data.chunks(4096) {
        client.writer().write_all(chunk).unwrap();
        while client.wants_write() {
            client.write_tls(&mut records).unwrap();
        }
    }
    client_io.write_all(&records).await.unwrap();

    // The reader waits for its answer to be written.
    let (mut rd, mut wr) = tokio::io::split(server);
    let len = data.len();
    let reader = tokio::spawn(async move {
        let mut received = vec![0u8; len];
        rd.read_exact(&mut received).await.map(|_| received)
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A writer then waits on the blocked transport, taking over its
    // write-readiness registration; once the transport takes bytes again,
    // the writer sends the answer and must wake the reader.
    let writer = tokio::spawn(async move {
        wr.write_all(b"hello").await.unwrap();
        wr.flush().await.unwrap();
        wr
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.open();
    let _wr = timeout(LIMIT, writer).await.expect("writer hung").unwrap();
    let drain = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok(n) = client_io.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });
    let received = timeout(LIMIT, reader)
        .await
        .expect("the reader never woke after the writer sent its answer")
        .unwrap()
        .unwrap();
    drain.abort();
    assert_eq!(received, data);
}
