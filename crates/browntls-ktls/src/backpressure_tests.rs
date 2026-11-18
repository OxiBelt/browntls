//! A peer that keeps asking for KeyUpdates while it reads nothing: the
//! answers wait for room on a full socket, and reading must stop once
//! they cost more than their budget, then go on once the peer reads.
//!
//! The peer is raw kernel TLS driven from here (with the crate's socket
//! calls), since a browntls connection would not ask again before its
//! earlier request was answered.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use browntls::kernel::KernelOutput;
use browntls::{
    ClientConnection, ProtocolVersion, ServerConfig, ServerConnection, SupportedCipherSuite,
};

use crate::{CryptoInfo, KtlsStream, sys};
use common::{Pki, kernel_tls, localhost, offloadable_suites, tcp_pair};

/// The most KeyUpdate requests the peer sends, each followed by one byte
/// of data (which renews the server's budget of requests). The kernel
/// still takes small control records for a while after it refuses data
/// (some hundreds to a few thousand answers here), so the peer asks well
/// beyond that, or until its own socket has no room.
const CYCLES: usize = 4000;

/// How long reading must make no progress to count as stopped.
const STOPPED: Duration = Duration::from_millis(500);

/// How many writes in a row must find no room for the socket to count as
/// full.
const FULL_AFTER: usize = 50;

const LIMIT: Duration = Duration::from_secs(60);

/// The most outputs that may wait once reading stops: KeyUpdate answers
/// (a record and its transmit keys) up to just past the budget. Fewer
/// wait when the socket took some answers before it filled up.
fn most_waiting() -> usize {
    let answer = 2 * size_of::<KernelOutput>() + 5;
    2 * (crate::outputs::BUDGET / answer + 1)
}

/// Checks the server when its reading stopped after `before` of the
/// `sent` cycles, with `waiting` outputs held back.
fn check_stopped(before: usize, sent: usize, waiting: usize) {
    assert!(
        before < sent,
        "read all {sent} cycles without stopping ({waiting} outputs wait)"
    );
    assert!(
        (1..=most_waiting()).contains(&waiting),
        "{waiting} outputs wait after {before} cycles (at most {})",
        most_waiting()
    );
}

fn tls13_suite() -> Option<SupportedCipherSuite> {
    offloadable_suites()
        .into_iter()
        .find(|suite| suite.version().version == ProtocolVersion::TLSv1_3)
}

fn server_config(pki: &Pki, suite: SupportedCipherSuite) -> ServerConfig {
    let mut config = pki.server_config(suite);
    // Nothing for the raw peer to take in before its handover.
    config.send_tls13_tickets = 0;
    config
}

/// What the test tells the peer, and the peer tells the test.
struct Peer {
    /// How many cycles the peer sent, once it has.
    flooded: mpsc::Receiver<usize>,
    drain: mpsc::Sender<()>,
    handle: thread::JoinHandle<()>,
}

/// Completes a handshake on `tcp`, hands the client's transmit keys to the
/// kernel, then, once `start` fires, sends up to [`CYCLES`] KeyUpdate
/// requests each followed by one byte (fewer if its socket fills up first),
/// and reads nothing until told to drain (then discards what arrives until
/// `drain` is dropped).
fn peer(
    pki: &Pki,
    suite: SupportedCipherSuite,
    mut tcp: TcpStream,
    start: mpsc::Receiver<()>,
) -> Peer {
    let config = Arc::new(pki.client_config(suite));
    let (flooded_tx, flooded) = mpsc::channel();
    let (drain, drain_rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        let mut conn = ClientConnection::new(config, localhost()).unwrap();
        while conn.is_handshaking() || conn.wants_write() {
            conn.complete_io(&mut tcp).unwrap();
        }
        let (secrets, mut kernel) = conn.dangerous_into_kernel_connection().unwrap();
        let fd = tcp.as_fd();
        sys::set_ulp_tls(fd).unwrap();
        let (seq, tx) = &secrets.tx;
        let info = CryptoInfo::new(ProtocolVersion::TLSv1_3, tx, *seq).unwrap();
        sys::set_crypto_info(fd, false, info.as_bytes()).unwrap();
        start.recv().unwrap();
        tcp.set_nonblocking(true).unwrap();
        let mut sent = 0;
        'flood: for _ in 0..CYCLES {
            // The connection rotates its transmit key; the record says
            // `update_requested` whatever it would have sent. No room
            // ends the flood: nothing more is sent after it.
            kernel.refresh_traffic_keys().unwrap();
            while let Some(output) = kernel.pop_output() {
                match output {
                    KernelOutput::Record { payload, .. } => {
                        assert_eq!(payload.first(), Some(&24), "a KeyUpdate");
                        match sys::send_record(fd, 22, &[24, 0, 0, 1, 1]) {
                            Ok(()) => {}
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break 'flood,
                            Err(err) => panic!("peer send: {err}"),
                        }
                    }
                    KernelOutput::TxKeys(secrets) => {
                        let info = CryptoInfo::new(ProtocolVersion::TLSv1_3, &secrets, 0).unwrap();
                        sys::set_crypto_info(fd, false, info.as_bytes()).unwrap();
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            match sys::send(fd, b"x") {
                Ok(1) => sent += 1,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                other => panic!("peer send: {other:?}"),
            }
        }
        flooded_tx.send(sent).unwrap();
        // Reading starts only when told; the raw bytes are discarded.
        drain_rx.recv().unwrap();
        tcp.set_nonblocking(false).unwrap();
        tcp.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut sink = vec![0; 1 << 16];
        loop {
            match tcp.read(&mut sink) {
                Ok(0) => break,
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if matches!(drain_rx.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
                        break;
                    }
                }
                Err(err) => panic!("peer read: {err}"),
            }
        }
    });
    Peer {
        flooded,
        drain,
        handle,
    }
}

/// One read on the non-blocking `tls`: `None` when it would block.
fn read_once<S: AsFd, D: browntls::SideData>(tls: &mut KtlsStream<S, D>) -> Option<usize> {
    let mut buf = [0; 4096];
    match tls.read(&mut buf) {
        Ok(0) => panic!("unexpected end"),
        Ok(n) => Some(n),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
        Err(err) => panic!("read: {err}"),
    }
}

#[test]
fn ktls_stream_stops_reading_while_answers_wait() {
    if !kernel_tls() {
        return;
    }
    let Some(suite) = tls13_suite() else {
        return;
    };
    let pki = Pki::new();
    let (client_tcp, server_tcp) = tcp_pair();
    let (start, start_rx) = mpsc::channel();
    let peer = peer(&pki, suite, client_tcp, start_rx);

    let conn = ServerConnection::new(Arc::new(server_config(&pki, suite))).unwrap();
    let mut tls = KtlsStream::new(conn, server_tcp).unwrap();
    tls.get_ref().set_nonblocking(true).unwrap();
    // The peer reads nothing: fill the socket until large, then small,
    // writes keep failing.
    let chunk = vec![7; 1 << 16];
    let mut filled = 0;
    for len in [chunk.len(), 64] {
        let mut refused = 0;
        while refused < FULL_AFTER {
            match tls.write(&chunk[..len]) {
                Ok(n) => {
                    filled += n;
                    refused = 0;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    refused += 1;
                    thread::sleep(Duration::from_millis(2));
                }
                Err(err) => panic!("{err}"),
            }
        }
    }
    eprintln!("socket full after {filled} bytes");
    start.send(()).unwrap();
    let sent = peer.flooded.recv_timeout(LIMIT).unwrap();

    // Read until nothing more comes for a while.
    let mut before = 0;
    let mut since = Instant::now();
    while since.elapsed() < STOPPED {
        match read_once(&mut tls) {
            Some(n) => {
                before += n;
                since = Instant::now();
            }
            None => thread::sleep(Duration::from_millis(5)),
        }
    }
    check_stopped(before, sent, tls.waiting_len());

    // Once the peer reads, the answers go out and reading goes on.
    peer.drain.send(()).unwrap();
    let deadline = Instant::now() + LIMIT;
    let mut total = before;
    while total < sent {
        assert!(Instant::now() < deadline, "reading did not resume: {total}");
        match read_once(&mut tls) {
            Some(n) => total += n,
            None => thread::sleep(Duration::from_millis(1)),
        }
    }
    assert_eq!(total, sent);
    drop(peer.drain);
    drop(tls);
    peer.handle.join().unwrap();
}

#[cfg(feature = "tokio")]
#[test]
fn async_ktls_stream_stops_reading_while_answers_wait() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    if !kernel_tls() {
        return;
    }
    let Some(suite) = tls13_suite() else {
        return;
    };
    let pki = Pki::new();
    let (client_tcp, server_tcp) = tcp_pair();
    let (start, start_rx) = mpsc::channel();
    let peer = peer(&pki, suite, client_tcp, start_rx);
    let config = Arc::new(server_config(&pki, suite));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        server_tcp.set_nonblocking(true).unwrap();
        let tcp = tokio::net::TcpStream::from_std(server_tcp).unwrap();
        let stream = timeout(LIMIT, browntls_tokio::TlsAcceptor::from(config).accept(tcp))
            .await
            .unwrap()
            .unwrap();
        let mut tls = timeout(LIMIT, crate::AsyncKtlsStream::from_server(stream))
            .await
            .unwrap()
            .unwrap();
        // The peer reads nothing: write until large, then small, writes
        // stay pending.
        let chunk = vec![7; 1 << 16];
        let mut filled = 0;
        for len in [chunk.len(), 64] {
            let mut pending = 0;
            while pending < FULL_AFTER / 5 {
                match timeout(Duration::from_millis(10), tls.write(&chunk[..len])).await {
                    Ok(written) => {
                        filled += written.unwrap();
                        pending = 0;
                    }
                    Err(_) => pending += 1,
                }
            }
        }
        eprintln!("socket full after {filled} bytes");
        start.send(()).unwrap();
        let (peer, sent) = tokio::task::spawn_blocking(move || {
            let sent = peer.flooded.recv_timeout(LIMIT).unwrap();
            (peer, sent)
        })
        .await
        .unwrap();
        let mut buf = [0; 4096];
        let mut before = 0;
        loop {
            match timeout(STOPPED, tls.read(&mut buf)).await {
                Ok(Ok(0)) => panic!("unexpected end"),
                Ok(Ok(n)) => before += n,
                Ok(Err(err)) => panic!("read: {err}"),
                Err(_) => break,
            }
        }
        check_stopped(before, sent, tls.waiting_len());

        // Once the peer reads, the answers go out and reading goes on:
        // the read is woken by room to send, and the records the kernel
        // already holds are read without new arrivals.
        peer.drain.send(()).unwrap();
        let mut total = before;
        while total < sent {
            match timeout(LIMIT, tls.read(&mut buf)).await {
                Ok(Ok(0)) => panic!("unexpected end"),
                Ok(Ok(n)) => total += n,
                Ok(Err(err)) => panic!("read: {err}"),
                Err(_) => panic!("reading did not resume: {total}"),
            }
        }
        assert_eq!(total, sent);
        drop(peer.drain);
        drop(tls);
        peer.handle.join().unwrap();
    });
}
