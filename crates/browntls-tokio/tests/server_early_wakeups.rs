//! Wakeups in the server's early phase (`TlsAcceptor::early_data`): split
//! halves that wait for the handshake in two tasks, and operations dropped
//! after they took over the other task's registration in the transport, in
//! either direction.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read as _, Write as _};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Wake, Waker};
use std::time::Duration;

use common::server_early::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};
use tokio::time::timeout;

/// A waker that records that it was used.
#[derive(Default)]
struct Woken(AtomicBool);

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_halves_waiting_for_the_handshake_are_both_woken() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(b"early request");
    send(&mut client, &mut c).await;
    let server = setup.acceptor(false).accept(s).await.unwrap();
    assert!(server.get_ref().1.is_handshaking());

    let (mut rd, mut wr) = tokio::io::split(server);
    // Both halves wait for the handshake, one after the other, so that the
    // second takes over the transport registration of the first.
    let reader = tokio::spawn(async move {
        let mut got = [0; 5];
        rd.read_exact(&mut got).await.map(|_| got)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let writer = tokio::spawn(async move {
        wr.write_all(b"reply").await?;
        wr.flush().await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    receive(&mut client, &mut c).await;
    client.writer().write_all(b"after").unwrap();
    send(&mut client, &mut c).await;

    let got = timeout(Duration::from_secs(10), reader)
        .await
        .expect("the reader was never woken")
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"after");
    timeout(Duration::from_secs(10), writer)
        .await
        .expect("the writer was never woken")
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_write_leaves_a_waiting_read_its_wakeup() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(b"early request");
    send(&mut client, &mut c).await;
    let server = setup.acceptor(false).accept(s).await.unwrap();
    assert!(server.get_ref().1.is_handshaking());

    let (mut rd, mut wr) = tokio::io::split(server);
    let reader = tokio::spawn(async move {
        let mut got = [0; 5];
        rd.read_exact(&mut got).await.map(|_| got)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The write drives the handshake, taking over the read's registration
    // in the transport, and is then dropped; its task lives on, so a
    // wakeup sent only to it would be lost.
    let writer = tokio::spawn(async move {
        let cancelled = timeout(Duration::from_millis(100), wr.write_all(b"reply")).await;
        assert!(cancelled.is_err(), "the write did not wait");
        tokio::time::sleep(Duration::from_secs(20)).await;
        wr
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    receive(&mut client, &mut c).await;
    client.writer().write_all(b"after").unwrap();
    send(&mut client, &mut c).await;

    let got = timeout(Duration::from_secs(10), reader)
        .await
        .expect("the reader was never woken")
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"after");
    writer.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_half_rtt_write_leaves_a_waiting_read_its_wakeup() {
    let setup = Setup::new();
    setup.first_connection().await;

    // A transport that fills up, so that operations wait to write.
    let (mut c, s) = duplex(4096);
    let mut client = setup.manual_client(b"early request");
    send(&mut client, &mut c).await;
    let mut server = setup.acceptor(true).accept(s).await.unwrap();
    assert!(server.get_ref().1.is_handshaking());

    // The handshake completes through the early data reader, which leaves
    // the phase on: the tickets are still to be flushed.
    receive(&mut client, &mut c).await;
    send(&mut client, &mut c).await;
    let mut early = Vec::new();
    server
        .early_data()
        .unwrap()
        .read_to_end(&mut early)
        .await
        .unwrap();
    assert_eq!(early, b"early request");
    // Writes fill the transport and the connection's send buffer.
    let fill = vec![0x5a; 512 * 1024];
    assert!(
        timeout(Duration::from_millis(200), server.write_all(&fill))
            .await
            .is_err(),
        "the transport never filled"
    );

    let (mut rd, mut wr) = tokio::io::split(server);
    // The read ends the phase first, and waits for the transport to take
    // what is queued.
    let reader = tokio::spawn(async move {
        let mut got = [0; 5];
        rd.read_exact(&mut got).await.map(|_| got)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The write takes over that registration and is dropped; its task
    // lives on, so a wakeup sent only to it would be lost.
    let writer = tokio::spawn(async move {
        let cancelled = timeout(Duration::from_millis(100), wr.write_all(b"more")).await;
        assert!(cancelled.is_err(), "the write did not wait");
        tokio::time::sleep(Duration::from_secs(20)).await;
        wr
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The client reads until the server has nothing more for it.
    let mut tls = vec![0; 32 * 1024];
    let mut sink = vec![0; 32 * 1024];
    while let Ok(n) = timeout(Duration::from_millis(500), c.read(&mut tls)).await {
        let mut tls = &tls[..n.unwrap()];
        while !tls.is_empty() {
            client.read_tls(&mut tls).unwrap();
            client.process_new_packets().unwrap();
            while matches!(client.reader().read(&mut sink), Ok(n) if n > 0) {}
        }
    }
    client.writer().write_all(b"after").unwrap();
    send(&mut client, &mut c).await;

    let got = timeout(Duration::from_secs(10), reader)
        .await
        .expect("the reader was never woken")
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"after");
    writer.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_read_leaves_a_waiting_write_its_wakeup() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(b"early request");
    send(&mut client, &mut c).await;
    let server = setup.acceptor(false).accept(s).await.unwrap();
    assert!(server.get_ref().1.is_handshaking());

    let (mut rd, mut wr) = tokio::io::split(server);
    // Without 0.5-RTT data the write waits for the handshake.
    let writer = tokio::spawn(async move { wr.write_all(b"reply").await.map(|()| wr) });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The read drives the handshake, taking over the write's registration
    // in the transport, and is then dropped; its task lives on, so a
    // wakeup sent only to it would be lost.
    let reader = tokio::spawn(async move {
        let mut got = [0; 5];
        let cancelled = timeout(Duration::from_millis(100), rd.read_exact(&mut got)).await;
        assert!(cancelled.is_err(), "the read did not wait");
        tokio::time::sleep(Duration::from_secs(20)).await;
        rd
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    receive(&mut client, &mut c).await;
    send(&mut client, &mut c).await;

    timeout(Duration::from_secs(10), writer)
        .await
        .expect("the writer was never woken")
        .unwrap()
        .unwrap();
    reader.abort();
}

#[tokio::test]
async fn a_dropped_early_data_read_leaves_a_waiting_write_its_wakeup() {
    let setup = Setup::new();
    setup.first_connection().await;

    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(b"early request");
    send(&mut client, &mut c).await;
    let mut server = setup.acceptor(false).accept(s).await.unwrap();
    assert_eq!(read_early(&mut server, 13).await, b"early request");

    // The early data reader borrows the whole stream, so the two
    // operations are polled by hand, each under the waker of its own task.
    let woken = Arc::new(Woken::default());
    let writer = Waker::from(woken.clone());
    let write = Pin::new(&mut server).poll_write(&mut Context::from_waker(&writer), b"reply");
    assert!(write.is_pending(), "the write did not wait");

    // The read drives the handshake, taking over the write's registration
    // in the transport, and is not polled again.
    let mut byte = [0];
    let mut buf = ReadBuf::new(&mut byte);
    let mut reader = server.early_data().unwrap();
    let read = Pin::new(&mut reader).poll_read(&mut Context::from_waker(Waker::noop()), &mut buf);
    assert!(read.is_pending(), "the read did not wait");
    assert!(!woken.0.load(Ordering::SeqCst));

    receive(&mut client, &mut c).await;
    send(&mut client, &mut c).await;
    assert!(woken.0.load(Ordering::SeqCst), "the writer was never woken");

    // The write goes on from there.
    server.write_all(b"reply").await.unwrap();
    assert!(!server.get_ref().1.is_handshaking());
}
