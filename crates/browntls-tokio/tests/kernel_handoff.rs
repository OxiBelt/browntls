//! `into_kernel_handoff`: a stream is handed to a simulated kernel (the
//! stand-in the `browntls-core` kernel tests use, keyed with the extracted
//! secrets) without losing a byte in either direction, whatever was in
//! flight: unread plaintext, part of a record, records not yet written, a
//! KeyUpdate to answer, an unfinished 0-RTT phase.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[allow(dead_code)]
#[path = "../../browntls-core/tests/cases/kernel/sim.rs"]
mod sim;

use std::future::poll_fn;
use std::io::{self, Write as _};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use browntls_core::kernel::KernelHandoffBlocker;
use browntls_core::server::{ServerSessionMemoryCache, StoresServerSessions};
use browntls_core::{ClientConfig, ServerConfig, SideData, SupportedProtocolVersion};
use browntls_tokio::client::EarlyDataNotResent;
use browntls_tokio::kernel::KernelHandoffError;
use browntls_tokio::{TlsAcceptor, TlsConnector, client, server};
use common::*;
use sim::Offloaded;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

/// What a TLS 1.3 record adds to its plaintext on the wire: the header,
/// the inner content type and the AEAD tag.
const TLS13_OVERHEAD: usize = 5 + 1 + 16;

/// What a [`Gated`] transport lets through.
struct GateState {
    /// Bytes the reader may still take; `None` is no limit.
    read_budget: Option<usize>,
    /// Reads fail with `ConnectionReset` once the budget is spent.
    reset_when_spent: bool,
    /// Reads report end of file, whatever is still on the way.
    cut: bool,
    /// Whether writes go through.
    write_open: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

/// The test's handle on a [`Gated`] transport.
#[derive(Clone)]
struct Gate(Arc<Mutex<GateState>>);

impl Gate {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(GateState {
            read_budget: None,
            reset_when_spent: false,
            cut: false,
            write_open: true,
            read_waker: None,
            write_waker: None,
        })))
    }

    /// Lets the reader take `budget` more bytes (`None`: everything).
    fn allow_read(&self, budget: Option<usize>) {
        let mut state = self.0.lock().unwrap();
        state.read_budget = budget;
        if let Some(waker) = state.read_waker.take() {
            waker.wake();
        }
    }

    /// Makes reads fail once the byte budget is spent, instead of waiting.
    fn reset_when_spent(&self) {
        self.0.lock().unwrap().reset_when_spent = true;
    }

    /// Ends the reader's side of the transport here.
    fn cut(&self) {
        let mut state = self.0.lock().unwrap();
        state.cut = true;
        if let Some(waker) = state.read_waker.take() {
            waker.wake();
        }
    }

    fn set_write_open(&self, open: bool) {
        let mut state = self.0.lock().unwrap();
        state.write_open = open;
        if let Some(waker) = state.write_waker.take() {
            waker.wake();
        }
    }
}

/// A transport whose reads stop after a byte budget and whose writes can be
/// held back, to leave a connection with a part of a record or with
/// records it could not write.
struct Gated {
    inner: DuplexStream,
    gate: Gate,
}

impl AsyncRead for Gated {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let gate = self.gate.clone();
        let mut state = gate.0.lock().unwrap();
        if state.cut {
            return Poll::Ready(Ok(()));
        }
        let take = match state.read_budget {
            Some(0) if state.reset_when_spent => {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            Some(0) => {
                state.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Some(budget) => buf.remaining().min(budget),
            None => buf.remaining(),
        };
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(take));
        let result = Pin::new(&mut self.inner).poll_read(cx, &mut limited);
        let n = limited.filled().len();
        buf.advance(n);
        if let Some(budget) = &mut state.read_budget {
            *budget -= n;
        }
        result
    }
}

impl AsyncWrite for Gated {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        {
            let mut state = self.gate.0.lock().unwrap();
            if !state.write_open {
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
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

/// A connected pair: the client over a gated transport, both
/// configurations with secret extraction on unless `tweak` says otherwise.
struct Ends {
    client: client::TlsStream<Gated>,
    server: server::TlsStream<DuplexStream>,
    gate: Gate,
}

async fn connect(
    version: &'static SupportedProtocolVersion,
    tweak: impl FnOnce(&mut ClientConfig, &mut ServerConfig),
) -> Ends {
    let pki = Pki::new();
    let mut client_config = pki.client_config(version);
    let mut server_config = pki.server_config(version);
    client_config.enable_secret_extraction = true;
    server_config.enable_secret_extraction = true;
    tweak(&mut client_config, &mut server_config);

    let (c, s) = duplex(1 << 20);
    let gate = Gate::new();
    let c = Gated {
        inner: c,
        gate: gate.clone(),
    };
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), c),
        TlsAcceptor::from(Arc::new(server_config)).accept(s),
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    // The client reads what the server sent after the handshake (TLS 1.3
    // tickets), so that both ends start with nothing on the way.
    server.write_all(b"!").await.unwrap();
    server.flush().await.unwrap();
    let mut mark = [0u8; 1];
    client.read_exact(&mut mark).await.unwrap();
    Ends {
        client,
        server,
        gate,
    }
}

/// Whatever the transport has ready now, without waiting.
async fn read_available<R: AsyncRead + Unpin>(io: &mut R) -> Vec<u8> {
    let mut out = Vec::new();
    poll_fn(|cx| {
        loop {
            let mut chunk = [0u8; 4096];
            let mut buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut *io).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) if !buf.filled().is_empty() => {
                    out.extend_from_slice(buf.filled());
                }
                _ => return Poll::Ready(()),
            }
        }
    })
    .await;
    out
}

/// Polls a read once and expects it to wait.
async fn read_stalls<R: AsyncRead + Unpin>(io: &mut R) {
    let mut chunk = [0u8; 64];
    poll_fn(|cx| {
        let mut buf = ReadBuf::new(&mut chunk);
        assert!(
            Pin::new(&mut *io).poll_read(cx, &mut buf).is_pending(),
            "the read did not wait"
        );
        Poll::Ready(())
    })
    .await;
}

/// The simulated kernel's side of a handed-over connection: `io` carries
/// its ciphertext.
struct Kernel<IO, Data> {
    io: IO,
    sim: Offloaded<Data>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin, Data: SideData> Kernel<IO, Data> {
    /// Decrypts everything the peer has sent so far, starting where the
    /// connection stopped reading; a record the secrets do not open, or
    /// one cut short, fails the test.
    async fn receive(&mut self) -> Vec<u8> {
        let wire = read_available(&mut self.io).await;
        self.sim.receive(&wire).unwrap();
        self.send_wire().await;
        std::mem::take(&mut self.sim.app_in)
    }

    async fn send(&mut self, data: &[u8]) {
        self.sim.send(data);
        self.send_wire().await;
    }

    async fn send_wire(&mut self) {
        let wire = self.sim.take_wire();
        self.io.write_all(&wire).await.unwrap();
    }
}

async fn client_kernel(
    stream: client::TlsStream<Gated>,
) -> (
    Kernel<Gated, browntls_core::client::ClientConnectionData>,
    Vec<u8>,
) {
    let handoff = stream.into_kernel_handoff().await.unwrap();
    assert_eq!(handoff.get_ref().1.kernel_handoff_blocker(), None);
    let (io, conn, received) = handoff.into_parts();
    let (secrets, conn) = conn.dangerous_into_kernel_connection().unwrap();
    let sim = Offloaded::new(conn, secrets);
    (Kernel { io, sim }, received)
}

/// The client holds seven bytes of a record when it is handed over: the
/// handoff reads the rest of that record and nothing beyond, the record's
/// plaintext comes back as `received`, and the kernel opens the records
/// that follow with the extracted sequence number.
#[tokio::test]
async fn a_partial_record_is_completed_and_what_follows_is_left_to_the_kernel() {
    for version in versions() {
        let Ends {
            mut client,
            mut server,
            gate,
        } = connect(version, |_, _| ()).await;
        let (a, b, c) = (pattern(3000), pattern(2000), pattern(40_000));
        gate.allow_read(Some(7));
        for part in [&a, &b, &c] {
            server.write_all(part).await.unwrap();
            server.flush().await.unwrap();
        }
        read_stalls(&mut client).await;
        assert!(client.get_ref().1.bytes_to_record_boundary() > 0);
        gate.allow_read(None);

        let (mut kernel, received) = timeout(LIMIT, client_kernel(client)).await.unwrap();
        assert_eq!(received, a, "{version:?}");
        let rest = kernel.receive().await;
        assert_eq!(rest, [b, c].concat(), "{version:?}");

        // The other direction: the server opens the kernel's records.
        let up = pattern(50_000);
        kernel.send(&up).await;
        let mut got = vec![0; up.len()];
        timeout(LIMIT, server.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, up, "{version:?}");
    }
}

/// The client read ahead: several records are buffered and only ten bytes
/// were read by the application. Every other byte comes back, in order,
/// from `received` and then from the kernel.
#[tokio::test]
async fn plaintext_read_ahead_is_returned_in_order() {
    for version in versions() {
        let Ends {
            mut client,
            mut server,
            ..
        } = connect(version, |_, _| ()).await;
        let down = pattern(100_000);
        for part in down.chunks(7000) {
            server.write_all(part).await.unwrap();
        }
        server.flush().await.unwrap();
        let mut first = [0u8; 10];
        client.read_exact(&mut first).await.unwrap();

        let (mut kernel, mut got) = timeout(LIMIT, client_kernel(client)).await.unwrap();
        assert!(!got.is_empty(), "{version:?}");
        got.extend(kernel.receive().await);
        assert_eq!([&first[..], &got].concat(), down, "{version:?}");
    }
}

/// A stream put back together from its halves hands over like any other:
/// what the read half read ahead comes back in order, behind what it gave
/// out, and what the write half wrote has reached the peer.
#[tokio::test]
async fn a_reunited_stream_is_handed_over() {
    for version in versions() {
        let Ends {
            client, mut server, ..
        } = connect(version, |_, _| ()).await;
        let down = pattern(50_000);
        server.write_all(&down).await.unwrap();
        server.flush().await.unwrap();

        let (mut read, mut write) = client.into_split();
        let mut first = [0u8; 10];
        read.read_exact(&mut first).await.unwrap();
        let up = b"from the write half";
        write.write_all(up).await.unwrap();
        let client = read.reunite(write).unwrap();

        let (mut kernel, mut got) = timeout(LIMIT, client_kernel(client)).await.unwrap();
        assert!(!got.is_empty(), "{version:?}");
        got.extend(kernel.receive().await);
        assert_eq!([&first[..], &got].concat(), down, "{version:?}");
        let mut sent = [0u8; 19];
        timeout(LIMIT, server.read_exact(&mut sent))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&sent, up, "{version:?}");
    }
}

/// Records the transport would not take are written before the handover,
/// ahead of what the kernel sends.
#[tokio::test]
async fn queued_records_are_written_first() {
    for version in versions() {
        let Ends {
            mut client,
            mut server,
            gate,
        } = connect(version, |_, _| ()).await;
        let (first, second) = (pattern(30_000), pattern(9000));
        gate.set_write_open(false);
        // The connection takes the plaintext; the records stay queued.
        let taken = client.write(&first).await.unwrap();
        assert!(taken > 0 && client.get_ref().1.wants_write());
        let handoff = client.into_kernel_handoff();
        tokio::pin!(handoff);
        assert!(
            timeout(Duration::from_millis(50), &mut handoff)
                .await
                .is_err(),
            "handed over with records unwritten"
        );
        gate.set_write_open(true);
        let handoff = timeout(LIMIT, handoff).await.unwrap().unwrap();
        let (io, conn, received) = handoff.into_parts();
        assert!(received.is_empty());
        let (secrets, conn) = conn.dangerous_into_kernel_connection().unwrap();
        let mut kernel = Kernel {
            io,
            sim: Offloaded::new(conn, secrets),
        };
        kernel.send(&second).await;

        let mut got = vec![0; taken + second.len()];
        timeout(LIMIT, server.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, [&first[..taken], &second].concat(), "{version:?}");
    }
}

/// The peer's KeyUpdate is half received at the handover: the handoff
/// reads the rest, answers it, and the kernel starts with the new keys in
/// both directions.
#[tokio::test]
async fn a_key_update_in_flight_is_answered_before_the_handover() {
    let Ends {
        mut client,
        mut server,
        gate,
    } = connect(&browntls_core::version::TLS13, |_, _| ()).await;
    let down = pattern(5000);
    gate.allow_read(Some(9));
    server.get_mut().1.refresh_traffic_keys().unwrap();
    server.write_all(&down).await.unwrap();
    server.flush().await.unwrap();
    read_stalls(&mut client).await;
    gate.allow_read(None);

    let (mut kernel, received) = timeout(LIMIT, client_kernel(client)).await.unwrap();
    assert!(received.is_empty());
    assert_eq!(kernel.receive().await, down);
    // The answer went out in userspace, before the handover.
    assert!(kernel.sim.control_sent.is_empty());
    assert_eq!((kernel.sim.tx_rekeys, kernel.sim.rx_rekeys), (0, 0));

    let up = pattern(20_000);
    kernel.send(&up).await;
    let mut got = vec![0; up.len()];
    timeout(LIMIT, server.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, up);
}

/// A server stream is handed over the same way.
#[tokio::test]
async fn a_server_stream_is_handed_over() {
    for version in versions() {
        let Ends {
            mut client, server, ..
        } = connect(version, |_, _| ()).await;
        let up = pattern(20_000);
        client.write_all(&up[..6000]).await.unwrap();
        client.flush().await.unwrap();

        let handoff = timeout(LIMIT, server.into_kernel_handoff())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(handoff.get_ref().1.kernel_handoff_blocker(), None);
        let (io, conn, received) = handoff.into_parts();
        let (secrets, conn) = conn.dangerous_into_kernel_connection().unwrap();
        let mut kernel = Kernel {
            io,
            sim: Offloaded::new(conn, secrets),
        };
        client.write_all(&up[6000..]).await.unwrap();
        client.flush().await.unwrap();
        let got = [received, kernel.receive().await].concat();
        assert_eq!(got, up, "{version:?}");

        let down = pattern(20_000);
        kernel.send(&down).await;
        let mut got = vec![0; down.len()];
        timeout(LIMIT, client.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, down, "{version:?}");
    }
}

/// Without secret extraction the stream comes back untouched and goes on
/// in userspace.
#[tokio::test]
async fn a_stream_that_cannot_be_offloaded_comes_back_whole() {
    for version in versions() {
        let Ends {
            client, mut server, ..
        } = connect(version, |client, _| {
            client.enable_secret_extraction = false;
        })
        .await;
        let down = pattern(3000);
        server.write_all(&down).await.unwrap();
        server.flush().await.unwrap();

        let KernelHandoffError {
            stream: mut client,
            received,
            error,
            ..
        } = client.into_kernel_handoff().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
        assert!(received.is_empty());
        let mut got = vec![0; down.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, down, "{version:?}");
        client.write_all(b"still here").await.unwrap();
        client.flush().await.unwrap();
        let mut echo = [0u8; 10];
        server.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"still here");
    }
}

/// A ready stream can still go on in userspace (the kernel turned it
/// down): the data set aside, then the stream.
#[tokio::test]
async fn a_ready_stream_can_go_on_in_userspace() {
    for version in versions() {
        let Ends {
            mut client,
            mut server,
            ..
        } = connect(version, |_, _| ()).await;
        let down = pattern(60_000);
        server.write_all(&down[..30_000]).await.unwrap();
        server.flush().await.unwrap();
        let mut first = [0u8; 100];
        client.read_exact(&mut first).await.unwrap();

        let handoff = client.into_kernel_handoff().await.unwrap();
        assert!(!handoff.received().is_empty());
        let (mut client, received) = handoff.into_stream();
        server.write_all(&down[30_000..]).await.unwrap();
        server.flush().await.unwrap();
        let mut rest = vec![0; down.len() - first.len() - received.len()];
        client.read_exact(&mut rest).await.unwrap();
        assert_eq!([&first[..], &received, &rest].concat(), down, "{version:?}");

        client.write_all(b"and back").await.unwrap();
        client.flush().await.unwrap();
        let mut echo = [0u8; 8];
        server.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"and back");
    }
}

/// Giving up on the future keeps the stream and what was taken from it.
#[tokio::test]
async fn an_abandoned_handoff_gives_the_stream_back() {
    let Ends {
        mut client,
        mut server,
        gate,
    } = connect(&browntls_core::version::TLS13, |_, _| ()).await;
    let down = pattern(9000);
    // The first record whole and eleven bytes of the second, so that the
    // handoff waits for the rest.
    gate.allow_read(Some(TLS13_OVERHEAD + 4000 + 11));
    for part in [&down[..4000], &down[4000..]] {
        server.write_all(part).await.unwrap();
        server.flush().await.unwrap();
    }
    let mut first = [0u8; 1];
    client.read_exact(&mut first).await.unwrap();
    assert!(client.get_ref().1.bytes_to_record_boundary() > 0);

    let mut handoff = client.into_kernel_handoff();
    assert!(
        timeout(Duration::from_millis(50), &mut handoff)
            .await
            .is_err()
    );
    let (mut client, received) = handoff.into_stream().unwrap();
    assert_eq!(received, &down[1..4000]);
    gate.allow_read(None);
    let mut rest = vec![0; 5000];
    client.read_exact(&mut rest).await.unwrap();
    assert_eq!(rest, &down[4000..]);
}

/// A truncated record fails the handoff as it fails a read, and the data
/// received before it is not lost.
#[tokio::test]
async fn a_transport_that_ends_inside_a_record_fails_the_handoff() {
    let Ends {
        mut client,
        mut server,
        gate,
    } = connect(&browntls_core::version::TLS13, |_, _| ()).await;
    let down = pattern(8000);
    gate.allow_read(Some(TLS13_OVERHEAD + 4000 + 11));
    for part in [&down[..4000], &down[4000..]] {
        server.write_all(part).await.unwrap();
        server.flush().await.unwrap();
    }
    let mut first = [0u8; 1];
    client.read_exact(&mut first).await.unwrap();
    assert!(client.get_ref().1.bytes_to_record_boundary() > 0);
    // The rest of the record never arrives.
    gate.cut();

    let err = timeout(LIMIT, client.into_kernel_handoff())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(err.received, &down[1..4000]);
}

/// The connection stops at the peer's `close_notify`. Bytes that follow
/// it, a whole record or the start of one, would stay unprocessed for
/// good: the handoff fails at once instead of waiting for the rest.
#[tokio::test]
async fn data_after_close_notify_fails_the_handoff() {
    for version in versions() {
        for trailing in [&[0x17u8][..], &[0x17, 3, 3, 0, 1, 0]] {
            let Ends {
                mut client,
                mut server,
                ..
            } = connect(version, |_, _| ()).await;
            server.get_mut().1.send_close_notify();
            server.flush().await.unwrap();
            server.get_mut().0.write_all(trailing).await.unwrap();
            // Reads the close_notify and, with it, what follows.
            assert_eq!(client.read(&mut [0u8; 8]).await.unwrap(), 0);
            assert_eq!(
                client.get_ref().1.kernel_handoff_blocker(),
                Some(KernelHandoffBlocker::UnprocessedInput)
            );

            let err = timeout(Duration::from_secs(5), client.into_kernel_handoff())
                .await
                .expect("the handoff waited for the rest of a record")
                .unwrap_err();
            assert_eq!(err.error.kind(), io::ErrorKind::InvalidData, "{err}");
            assert!(err.received.is_empty());
            assert_eq!(err.early_data_len, 0);
            // Only reading is over: the stream still writes and closes.
            let mut client = err.stream;
            client.write_all(b"still here").await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"still here");
        }
    }
}

/// An error a read kept for the next read (it had data to return first) is
/// reported by the handoff, not dropped.
#[tokio::test]
async fn a_kept_read_error_fails_the_handoff() {
    let Ends {
        mut client,
        mut server,
        gate,
    } = connect(&browntls_core::version::TLS13, |_, _| ()).await;
    // The transport delivers one record and then fails: the read below
    // returns the record's plaintext and keeps the error.
    gate.allow_read(Some(TLS13_OVERHEAD + 2));
    gate.reset_when_spent();
    server.write_all(b"ok").await.unwrap();
    server.flush().await.unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(client.read(&mut buf).await.unwrap(), 2);
    assert_eq!(&buf[..2], b"ok");

    let err = timeout(LIMIT, client.into_kernel_handoff())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.error.kind(), io::ErrorKind::ConnectionReset, "{err}");
    assert!(err.received.is_empty());
}

/// A connection that has failed reports its error again, not a blocker
/// that would pass for a connection merely unfit for the kernel.
#[tokio::test]
async fn a_failed_connection_fails_the_handoff() {
    let Ends {
        mut client,
        mut server,
        ..
    } = connect(&browntls_core::version::TLS13, |_, _| ()).await;
    // A record that does not open.
    let (transport, _) = server.get_mut();
    transport.write_all(&[0x17, 3, 3, 0, 1, 0]).await.unwrap();
    let err = client.read(&mut [0u8; 8]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let err = timeout(LIMIT, client.into_kernel_handoff())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.error.kind(), io::ErrorKind::InvalidData, "{err}");
}

struct EarlySetup {
    pki: Pki,
    cache: Arc<dyn StoresServerSessions>,
    connector: TlsConnector,
}

impl EarlySetup {
    /// A client offering `alpn` that may send 0-RTT data; the server
    /// selects the first protocol it supports.
    fn new(alpn: &[&[u8]]) -> Self {
        let pki = Pki::new();
        let mut config = pki.client_config(&browntls_core::version::TLS13);
        config.enable_early_data = true;
        config.enable_secret_extraction = true;
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Self {
            connector: TlsConnector::from(Arc::new(config)).early_data(true),
            cache: ServerSessionMemoryCache::new(8),
            pki,
        }
    }

    fn acceptor(&self, max_early_data_size: u32) -> TlsAcceptor {
        let mut config = self.pki.server_config(&browntls_core::version::TLS13);
        config.max_early_data_size = max_early_data_size;
        config.session_storage = self.cache.clone();
        config.enable_secret_extraction = true;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    /// A full handshake that leaves the client a ticket allowing 1 KiB of
    /// early data.
    async fn first_connection(&self) {
        let (c, s) = duplex(1 << 16);
        let (client, server) = tokio::join!(
            self.connector.connect(localhost(), c),
            self.acceptor(1024).accept(s),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        server.write_all(b"t").await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(client.get_ref().1.tls13_tickets_received() > 0);
    }
}

/// A client stream still in its 0-RTT phase: the handoff completes the
/// handshake and sends the declined early data again, ahead of what the
/// kernel sends. `into_inner` would have dropped it.
#[tokio::test]
async fn declined_early_data_is_resent_before_the_handover() {
    let setup = EarlySetup::new(&[b"h2"]);
    setup.first_connection().await;

    let (c, s) = duplex(1 << 16);
    let client_side = async {
        let mut client = setup
            .connector
            .clone()
            .rejected_early_data_policy(browntls_tokio::RejectedEarlyDataPolicy::ResendIfSameAlpn {
                max_bytes: std::num::NonZeroUsize::new(512).unwrap(),
            })
            .connect(localhost(), c)
            .await
            .unwrap();
        assert!(client.get_ref().1.is_handshaking());
        client.write_all(b"early request").await.unwrap();
        let handoff = client.into_kernel_handoff().await.unwrap();
        assert_eq!(
            handoff.early_data_outcome(),
            browntls_tokio::EarlyDataOutcome::Rejected {
                early_bytes: 13,
                resent_bytes: 13,
                unresent_bytes: 0,
            }
        );
        let (io, conn, received) = handoff.into_parts();
        assert!(received.is_empty());
        assert!(!conn.is_early_data_accepted());
        let (secrets, conn) = conn.dangerous_into_kernel_connection().unwrap();
        let mut kernel = Kernel {
            io,
            sim: Offloaded::new(conn, secrets),
        };
        kernel.send(b" and more").await;
        kernel
    };
    let server_side = async {
        let mut server = setup.acceptor(0).accept(s).await.unwrap();
        let mut got = [0u8; 22];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"early request and more");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

/// Early data that may not be sent again is reported, the stream stays
/// usable, and a second attempt hands it over.
#[tokio::test]
async fn early_data_that_is_not_resent_is_reported_by_the_handoff() {
    let setup = EarlySetup::new(&[b"h2", b"http/1.1"]);
    setup.first_connection().await;

    let (c, s) = duplex(1 << 16);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        let KernelHandoffError {
            stream: mut client,
            received,
            error,
            ..
        } = client.into_kernel_handoff().await.unwrap_err();
        let not_resent = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<EarlyDataNotResent>())
            .expect("EarlyDataNotResent");
        assert_eq!(not_resent.len, 13);
        assert!(received.is_empty());
        assert_eq!(client.acknowledge_rejected_early_data(), Some(13));
        client.write_all(b"chosen again").await.unwrap();
        let handoff = client.into_kernel_handoff().await.unwrap();
        let (io, conn, _) = handoff.into_parts();
        let (secrets, conn) = conn.dangerous_into_kernel_connection().unwrap();
        let mut kernel = Kernel {
            io,
            sim: Offloaded::new(conn, secrets),
        };
        kernel.send(b", then the kernel").await;
        kernel
    };
    let server_side = async {
        let mut server = setup.acceptor(0).accept(s).await.unwrap();
        let mut got = [0u8; 29];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"chosen again, then the kernel");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

/// 0-RTT data a server accepted and did not read comes first in
/// `received`, and `early_data_len` tells where it ends.
#[tokio::test]
async fn accepted_early_data_is_returned_first() {
    let setup = EarlySetup::new(&[]);
    setup.first_connection().await;

    let (c, s) = duplex(1 << 16);
    let client_side = async {
        let mut client = setup.connector.connect(localhost(), c).await.unwrap();
        client.write_all(b"early request").await.unwrap();
        client.flush().await.unwrap();
        assert!(client.get_ref().1.is_early_data_accepted());
        client.write_all(b" and the rest").await.unwrap();
        client.flush().await.unwrap();
        client
    };
    let server_side = async {
        let mut server = setup.acceptor(1024).accept(s).await.unwrap();
        // Reads the first ordinary record ahead of the handover.
        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        let handoff = server.into_kernel_handoff().await.unwrap();
        // The 0-RTT data can be told from the rest: it can be replayed.
        let early = handoff.early_data_len();
        let (_, _, received) = handoff.into_parts();
        assert_eq!(first, *b" ");
        assert_eq!(&received[..early], b"early request");
        assert_eq!(&received[early..], b"and the rest");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("timed out");
}

/// The length of the 0-RTT data is also given when the handoff fails
/// (bytes behind the client's `close_notify`) and when its future is given
/// up (a record the transport does not take).
#[tokio::test]
async fn early_data_is_counted_when_the_handoff_does_not_complete() {
    for give_up in [false, true] {
        let setup = EarlySetup::new(&[]);
        setup.first_connection().await;
        let (c, s) = duplex(1 << 16);
        let gate = Gate::new();
        let s = Gated {
            inner: s,
            gate: gate.clone(),
        };
        let all_sent = AtomicBool::new(false);
        let client_side = async {
            let mut client = setup.connector.connect(localhost(), c).await.unwrap();
            client.write_all(b"early request").await.unwrap();
            client.flush().await.unwrap();
            assert!(client.get_ref().1.is_early_data_accepted());
            client.write_all(b" and the rest").await.unwrap();
            client.flush().await.unwrap();
            if !give_up {
                client.get_mut().1.send_close_notify();
                client.flush().await.unwrap();
                client.get_mut().0.write_all(&[0x17, 3]).await.unwrap();
            }
            all_sent.store(true, Ordering::SeqCst);
            client
        };
        let server_side = async {
            let mut server = setup.acceptor(1024).accept(s).await.unwrap();
            while !all_sent.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            // Reads the first ordinary record ahead of the handover.
            let mut first = [0u8; 1];
            server.read_exact(&mut first).await.unwrap();
            let (early, received) = if give_up {
                gate.set_write_open(false);
                server.get_mut().1.writer().write_all(b"queued").unwrap();
                let mut handoff = server.into_kernel_handoff();
                let waited = timeout(Duration::from_millis(50), &mut handoff).await;
                assert!(waited.is_err(), "handed over with a record unsent");
                assert!(format!("{handoff:?}").contains("early_data_len: 13"));
                let early = handoff.early_data_len();
                (early, handoff.into_stream().unwrap().1)
            } else {
                let err = server.into_kernel_handoff().await.unwrap_err();
                assert_eq!(err.error.kind(), io::ErrorKind::InvalidData, "{err}");
                assert!(format!("{err:?}").contains("early_data_len: 13"));
                (err.early_data_len, err.received)
            };
            assert_eq!(&received[..early], b"early request");
            assert_eq!(&received[early..], b"and the rest");
        };
        timeout(LIMIT, async { tokio::join!(client_side, server_side) })
            .await
            .expect("timed out");
    }
}

/// The debug output of the handoff types shows no application data.
#[tokio::test]
async fn debug_output_omits_the_received_data() {
    let Ends {
        mut client,
        mut server,
        ..
    } = connect(&browntls_core::version::TLS13, |_, _| ()).await;
    server.write_all(b"\x01secret-plaintext").await.unwrap();
    server.flush().await.unwrap();
    let mut first = [0u8; 1];
    client.read_exact(&mut first).await.unwrap();
    let pending = client.into_kernel_handoff();
    assert!(!format!("{pending:?}").contains("115, 101, 99"));
    let handoff = pending.await.unwrap();
    assert_eq!(handoff.received(), b"secret-plaintext");
    let debug = format!("{handoff:?}");
    assert!(!debug.contains("115, 101, 99") && !debug.contains("secret-plaintext"));
}
