//! Unbuffered streams under write backpressure: reads stop taking input
//! while the answers they owe the peer cannot be written, without spinning,
//! and resume once the transport takes them; a write waits for the records
//! of the one before.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/gate.rs"]
mod gate;

use std::fmt::Debug;
use std::future::poll_fn;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use browntls_tokio::unbuffered::{ServerTlsStream, TlsAcceptor};
use common::*;
use gate::{Gate, GateState};
use rustls::ClientConnection;
use rustls_pki_types as rpki;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);
/// The stream's limit on unwritten records that reads owe the peer.
const CONTROL_BACKLOG_LIMIT: usize = 16 * 1024;

/// Counts how often it is woken.
#[derive(Default)]
struct CountingWaker(AtomicUsize);

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// How many TLS bytes the stream holds unwritten, from its `Debug` output.
fn unsent(stream: &impl Debug) -> usize {
    let debug = format!("{stream:?}");
    let rest = debug.split("unsent: ").nth(1).expect("an outgoing buffer");
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap()
}

/// An unbuffered server behind a gated transport, and the connection and
/// transport of its client, to write records by hand. The client is rustls,
/// whose every `refresh_traffic_keys` asks for the peer's KeyUpdate
/// (browntls asks again only once the peer answered).
async fn gated_server() -> (
    ServerTlsStream<Gate>,
    Arc<GateState>,
    DuplexStream,
    ClientConnection,
) {
    let pki = Pki::new();
    let version = &browntls::version::TLS13;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rpki::CertificateDer::from(pki.ca.as_ref().to_vec()))
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();

    let (c, s) = duplex(1 << 20);
    let gate = Arc::new(GateState::default());
    let s = Gate::new(s, gate.clone());
    let name = rpki::ServerName::try_from("localhost").unwrap();
    let (client, server) = tokio::join!(
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, c),
        TlsAcceptor::from(Arc::new(pki.server_config(version))).accept(s),
    );
    let (client_io, client) = client.unwrap().into_inner();
    (server.unwrap(), gate, client_io, client)
}

/// One KeyUpdate that asks for the peer's, then `data` in a record.
fn key_update_and(client: &mut ClientConnection, data: &[u8]) -> Vec<u8> {
    let mut records = Vec::new();
    client.refresh_traffic_keys().unwrap();
    client.writer().write_all(data).unwrap();
    while client.wants_write() {
        client.write_tls(&mut records).unwrap();
    }
    records
}

/// Polls `server` for plaintext with `waker` until it has none to give;
/// returns whether the stream ended.
fn read_available<IO>(server: &mut IO, waker: &Waker, into: &mut Vec<u8>) -> bool
where
    IO: AsyncRead + Unpin,
{
    let mut cx = Context::from_waker(waker);
    let mut chunk = [0u8; 4096];
    loop {
        let mut buf = ReadBuf::new(&mut chunk);
        match Pin::new(&mut *server).poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(())) if buf.filled().is_empty() => return true,
            Poll::Ready(Ok(())) => into.extend_from_slice(buf.filled()),
            Poll::Ready(Err(err)) => panic!("read failed: {err}"),
            Poll::Pending => return false,
        }
    }
}

#[tokio::test]
async fn reads_stop_while_owed_answers_pile_up_unwritten() {
    let (mut server, gate, mut client_io, mut client) = gated_server().await;

    // The server's transport stops taking bytes. The peer asks for a
    // KeyUpdate before every record, and the server reads each record as
    // it arrives, so it owes one answer per record.
    gate.close();
    let handshake = gate.written();
    let counter = Arc::new(CountingWaker::default());
    let waker = Waker::from(counter.clone());
    let mut sent = Vec::new();
    let mut received = Vec::new();
    let mut stalled_at = None;
    for round in 0..2000u32 {
        let data = round.to_be_bytes();
        client_io
            .write_all(&key_update_and(&mut client, &data))
            .await
            .unwrap();
        sent.extend_from_slice(&data);
        let before = received.len();
        assert!(!read_available(&mut server, &waker, &mut received));
        if received.len() == before && stalled_at.is_none() {
            stalled_at = Some(round);
        }
    }

    // Past its limit of unwritten answers the server took no more input,
    // however much the peer sent.
    let stalled_at = stalled_at.expect("the server answered 2000 requests into its buffer");
    assert!(stalled_at > 100, "stalled after {stalled_at} answers");
    assert!(received.len() < sent.len());
    assert_eq!(received, sent[..received.len()]);
    let backlog = unsent(&server);
    assert!(backlog > CONTROL_BACKLOG_LIMIT, "{backlog} bytes");
    assert!(backlog < CONTROL_BACKLOG_LIMIT + 1024, "{backlog} bytes");
    assert_eq!(gate.written(), handshake);

    // A read left waiting does not wake itself: it waits for the transport.
    let woken = counter.0.load(Ordering::SeqCst);
    assert!(!read_available(&mut server, &waker, &mut received));
    assert_eq!(counter.0.load(Ordering::SeqCst), woken, "the read spun");

    // Once the transport takes bytes again, the answers go out and the
    // server reads the rest.
    gate.open();
    assert!(
        counter.0.load(Ordering::SeqCst) > woken,
        "the read was not woken"
    );
    let mut rest = vec![0u8; sent.len() - received.len()];
    timeout(LIMIT, server.read_exact(&mut rest))
        .await
        .expect("the server never resumed reading")
        .unwrap();
    received.extend_from_slice(&rest);
    assert_eq!(received, sent);
    assert!(gate.written() - handshake > CONTROL_BACKLOG_LIMIT);

    // The peer accepts an answer (rustls refuses a long run of KeyUpdates
    // without data in between, so it is given the first only).
    let mut answers = vec![0u8; 256 * 1024];
    let n = timeout(LIMIT, client_io.read(&mut answers))
        .await
        .unwrap()
        .unwrap();
    let first = 5 + usize::from(u16::from_be_bytes([answers[3], answers[4]]));
    assert!(n >= first);
    client.read_tls(&mut &answers[..first]).unwrap();
    client.process_new_packets().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_reader_waiting_for_answers_wakes_when_the_writer_sends_them() {
    let (mut server, gate, mut client_io, mut client) = gated_server().await;

    gate.close();
    let waker = Waker::noop();
    let mut sent = Vec::new();
    let mut received = Vec::new();
    for round in 0..2000u32 {
        let data = round.to_be_bytes();
        client_io
            .write_all(&key_update_and(&mut client, &data))
            .await
            .unwrap();
        sent.extend_from_slice(&data);
        assert!(!read_available(&mut server, waker, &mut received));
    }
    assert!(received.len() < sent.len());

    // The reader waits for its answers to be written.
    let (mut rd, mut wr) = tokio::io::split(server);
    let missing = sent.len() - received.len();
    let reader = tokio::spawn(async move {
        let mut rest = vec![0u8; missing];
        rd.read_exact(&mut rest).await.map(|_| rest)
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A writer then waits on the blocked transport, taking over its
    // write-readiness registration; once the transport takes bytes again,
    // the writer sends the answers and must wake the reader.
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
    let rest = timeout(LIMIT, reader)
        .await
        .expect("the reader never woke after the writer sent its answers")
        .unwrap()
        .unwrap();
    drain.abort();
    received.extend_from_slice(&rest);
    assert_eq!(received, sent);
}

#[tokio::test]
async fn data_the_writer_queued_does_not_stop_reads() {
    let (mut server, gate, mut client_io, mut client) = gated_server().await;

    // The server's own data waits for the transport: that is no reason to
    // stop reading (both peers writing at once must not deadlock).
    gate.close();
    let big = pattern(60_000);
    let n = poll_fn(|cx| Pin::new(&mut server).poll_write(cx, &big))
        .await
        .unwrap();
    assert_eq!(n, big.len());
    assert!(unsent(&server) > CONTROL_BACKLOG_LIMIT);

    let mut sent = Vec::new();
    let mut received = Vec::new();
    for round in 0..200u32 {
        let data = round.to_be_bytes();
        client_io
            .write_all(&key_update_and(&mut client, &data))
            .await
            .unwrap();
        sent.extend_from_slice(&data);
        assert!(!read_available(&mut server, Waker::noop(), &mut received));
    }
    assert_eq!(received, sent);
    gate.open();
    server.flush().await.unwrap();
    assert_eq!(unsent(&server), 0);
}

#[tokio::test]
async fn a_write_waits_for_the_records_of_the_one_before() {
    let (mut server, gate, mut client_io, mut client) = gated_server().await;

    gate.close();
    let first = pattern(1000);
    let n = poll_fn(|cx| Pin::new(&mut server).poll_write(cx, &first))
        .await
        .unwrap();
    assert_eq!(n, first.len());
    let held = unsent(&server);

    // The stream holds one write at most.
    let counter = Arc::new(CountingWaker::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    let second = pattern(2000);
    assert!(
        Pin::new(&mut server)
            .poll_write(&mut cx, &second)
            .is_pending()
    );
    assert!(Pin::new(&mut server).poll_flush(&mut cx).is_pending());
    assert_eq!(unsent(&server), held);
    assert_eq!(counter.0.load(Ordering::SeqCst), 0, "the write spun");

    gate.open();
    assert!(
        counter.0.load(Ordering::SeqCst) > 0,
        "the write was not woken"
    );
    server.write_all(&second).await.unwrap();
    server.shutdown().await.unwrap();

    let mut records = Vec::new();
    client_io.read_to_end(&mut records).await.unwrap();
    client.read_tls(&mut &records[..]).unwrap();
    client.process_new_packets().unwrap();
    let mut got = Vec::new();
    std::io::Read::read_to_end(&mut client.reader(), &mut got).unwrap();
    assert_eq!(got, [first, second].concat());
}
