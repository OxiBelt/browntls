//! Unbuffered streams: the records a read owes the peer reach it when the
//! transport is slow to flush or a writer got in the way, and a handshake
//! keeps reading while its own flight waits for the transport.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/gate.rs"]
mod gate;

use std::fmt::Debug;
use std::io;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker, ready};
use std::time::Duration;

use browntls_core::server::PostHandshakeAuthStatus;
use browntls_tokio::unbuffered::{ClientTlsStream, ServerTlsStream, TlsAcceptor, TlsConnector};
use common::*;
use gate::{Gate, GateState};
use rustls_pki_types as rpki;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::time::timeout;

/// Counts how often it is woken.
#[derive(Default)]
struct CountingWaker(AtomicUsize);

impl CountingWaker {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Whether a [`LateFlush`] flushes, and the task waiting for it to.
#[derive(Debug, Default)]
struct FlushState {
    blocked: AtomicBool,
    waiting: Mutex<Option<Waker>>,
}

impl FlushState {
    fn block(&self) {
        self.blocked.store(true, Ordering::SeqCst);
    }

    fn unblock(&self) {
        self.blocked.store(false, Ordering::SeqCst);
        if let Some(waker) = self.waiting.lock().unwrap().take() {
            waker.wake();
        }
    }
}

/// A transport that takes every write into a buffer of its own and passes
/// it on only when flushed, as a `BufWriter` or a TLS stream does.
#[derive(Debug)]
struct LateFlush {
    inner: DuplexStream,
    held: Vec<u8>,
    state: Arc<FlushState>,
}

impl AsyncRead for LateFlush {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for LateFlush {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.held.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.blocked.load(Ordering::SeqCst) {
            *self.state.waiting.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let this = &mut *self;
        while !this.held.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.held))?;
            this.held.drain(..n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A client over `client_io` and a server that has just asked it for a
/// certificate (TLS 1.3 post-handshake authentication): the client's next
/// read owes the server an answer.
async fn asked_for_a_certificate<IO>(
    pki: &Pki,
    client_io: IO,
    s: DuplexStream,
) -> (ClientTlsStream<IO>, ServerTlsStream<DuplexStream>)
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let version = &browntls_core::version::TLS13;
    let mut client_config = pki.client_config_with_cert(version);
    client_config.enable_post_handshake_auth = true;
    let mut server_config = pki.server_config_with_client_auth(version);
    server_config.request_client_auth_after_handshake = true;
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), client_io),
        TlsAcceptor::from(Arc::new(server_config)).accept(s),
    );
    let (client, mut server) = (client.unwrap(), server.unwrap());
    server.get_mut().1.request_client_auth().unwrap();
    server.flush().await.unwrap();
    (client, server)
}

/// Polls `stream` for one byte with `waker`; the stream has none to give.
fn read_is_pending<S: AsyncRead + Unpin>(stream: &mut S, waker: &Waker) {
    let mut byte = [0u8; 1];
    let mut buf = ReadBuf::new(&mut byte);
    let poll = Pin::new(stream).poll_read(&mut Context::from_waker(waker), &mut buf);
    assert!(poll.is_pending());
}

#[tokio::test]
async fn an_answer_the_transport_did_not_flush_is_flushed_by_a_later_read() {
    let (c, s) = duplex(64 * 1024);
    let flush = Arc::new(FlushState::default());
    let c = LateFlush {
        inner: c,
        held: Vec::new(),
        state: flush.clone(),
    };
    let (mut client, _server) = asked_for_a_certificate(&Pki::new(), c, s).await;

    // The read writes its answer, and the transport does not flush it.
    flush.block();
    let reader = Arc::new(CountingWaker::default());
    let waker = Waker::from(reader.clone());
    read_is_pending(&mut client, &waker);
    assert!(!client.get_ref().0.held.is_empty(), "no answer was written");

    // The transport can flush again: that wakes the read, which flushes.
    flush.unblock();
    assert_eq!(reader.count(), 1, "the read was not woken");
    read_is_pending(&mut client, &waker);
    assert!(
        client.get_ref().0.held.is_empty(),
        "the answer was left unflushed"
    );
}

#[tokio::test]
async fn a_read_owing_an_answer_is_woken_after_a_dropped_write_took_its_place() {
    let (c, s) = duplex(64 * 1024);
    let gate = Arc::new(GateState::default());
    let (mut client, _server) =
        asked_for_a_certificate(&Pki::new(), Gate::new(c, gate.clone()), s).await;

    // The read encodes its answer; the transport does not take it.
    gate.close();
    let reader = Arc::new(CountingWaker::default());
    let read_waker = Waker::from(reader.clone());
    read_is_pending(&mut client, &read_waker);

    // A flush on another task waits for the transport too, in the read's
    // place, and is given up (a timeout, a `select!`).
    let writer = Arc::new(CountingWaker::default());
    let write_waker = Waker::from(writer.clone());
    let poll = Pin::new(&mut client).poll_flush(&mut Context::from_waker(&write_waker));
    assert!(poll.is_pending());

    // The transport takes bytes again: the read hears of it, and sends.
    let written = gate.written();
    gate.open();
    assert!(reader.count() > 0, "the read was not woken");
    read_is_pending(&mut client, &read_waker);
    assert!(gate.written() > written, "the answer was not sent");
}

/// How many TLS bytes the stream holds unwritten, from its `Debug` output.
fn unsent(stream: &impl Debug) -> usize {
    let debug = format!("{stream:?}");
    let rest = debug.split("unsent: ").nth(1).expect("an outgoing buffer");
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap()
}

#[tokio::test]
async fn a_large_answer_is_sent_after_a_dropped_flush_marked_it_transmitted() {
    // A client certificate of some 40 kB that compression does not shrink:
    // the answer is several records, more than reads leave unwritten
    // before they take more input.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let names = (0..1300)
        .map(|_| {
            let label: String = (0..24)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let index = usize::try_from(state >> 33).unwrap() % 36;
                    char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[index])
                })
                .collect();
            format!("{label}.x.test")
        })
        .collect();
    let pki = Pki::with_client_names(names);
    // The transport takes the answer in parts.
    let (c, s) = duplex(4096);
    let gate = Arc::new(GateState::default());
    let (mut client, mut server) =
        asked_for_a_certificate(&pki, Gate::new(c, gate.clone()), s).await;

    // The read encodes the start of its answer and waits for the transport
    // before it has seen the rest out of the connection.
    gate.close();
    let reader = Arc::new(CountingWaker::default());
    let read_waker = Waker::from(reader.clone());
    read_is_pending(&mut client, &read_waker);
    assert!(unsent(&client) > 16 * 1024);

    // A flush on another task encodes the rest, marks it transmitted, and
    // is given up.
    let write_waker = Waker::from(Arc::new(CountingWaker::default()));
    let poll = Pin::new(&mut client).poll_flush(&mut Context::from_waker(&write_waker));
    assert!(poll.is_pending());
    gate.open();
    assert!(reader.count() > 0, "the read was not woken");
    read_is_pending(&mut client, &read_waker);

    // The server reads; the client's read is polled when it is woken, and
    // sends the whole answer.
    let mut seen = reader.count();
    for _ in 0..400 {
        let status = server.get_ref().1.post_handshake_auth_status();
        if status == Some(PostHandshakeAuthStatus::Authenticated) {
            break;
        }
        let _ = timeout(Duration::from_millis(5), server.read(&mut [0; 1])).await;
        if reader.count() != seen {
            seen = reader.count();
            read_is_pending(&mut client, &read_waker);
        }
    }
    assert_eq!(unsent(&client), 0, "a part of the answer was never sent");
    assert_eq!(
        server.get_ref().1.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
}

#[tokio::test]
async fn a_handshake_reads_while_its_flight_waits_for_the_transport() {
    const PIPE: usize = 4096;
    let pki = Pki::new();
    let version = &browntls_core::version::TLS13;
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
    let name = rpki::ServerName::try_from("localhost").unwrap();
    let mut hello = Vec::new();
    rustls::ClientConnection::new(Arc::new(config), name)
        .unwrap()
        .write_tls(&mut hello)
        .unwrap();
    assert!(hello.len() < PIPE);

    // The server reads the ClientHello; its transport does not take the
    // answer.
    let (mut c, s) = duplex(PIPE);
    let gate = Arc::new(GateState::default());
    gate.close();
    let acceptor = TlsAcceptor::from(Arc::new(pki.server_config(version)));
    let mut accept = pin!(acceptor.accept(Gate::new(s, gate.clone())));
    let mut cx = Context::from_waker(Waker::noop());
    c.write_all(&hello).await.unwrap();
    assert!(accept.as_mut().poll(&mut cx).is_pending());
    assert_eq!(gate.written(), 0);

    // The peer goes on writing (the start of a record that fills its
    // pipe): the handshake takes that in, though its own flight waits.
    let mut more = vec![23, 3, 3, 0x40, 0x00];
    more.resize(PIPE, 0xaa);
    c.write_all(&more).await.unwrap();
    assert!(accept.as_mut().poll(&mut cx).is_pending());
    let poll = Pin::new(&mut c).poll_write(&mut cx, &[0xaa]);
    assert!(
        matches!(poll, Poll::Ready(Ok(1))),
        "the handshake left the peer's bytes in the pipe"
    );
    assert_eq!(gate.written(), 0);
}
