//! `AsyncKtlsStream` against the running kernel over loopback TCP: both
//! ends offloaded, one end offloaded against a userspace `browntls-tokio`
//! peer, data in flight at the handover, key updates answered by a read
//! while the socket is full, split halves, a bulk transfer through small
//! socket buffers shut down at once, what the kernel holds back from TCP,
//! closure and refusals.
//!
//! The tests that need kernel TLS are skipped without the `tls` module
//! unless `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(
    target_os = "linux",
    feature = "tokio",
    any(feature = "native", feature = "rustcrypto")
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use browntls::client::ClientConnectionData;
use browntls::server::{ServerConnectionData, ServerSessionMemoryCache};
use browntls::{ClientConfig, ProtocolVersion, ServerConfig, SupportedCipherSuite};
use browntls_ktls::{AsyncKtlsStream, HandoffError, StreamHandoffError};
use browntls_tokio::{TlsAcceptor, TlsConnector, client, server};
use common::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

const LEN: usize = 200_000;
const LIMIT: Duration = Duration::from_secs(60);

fn tls13(suite: SupportedCipherSuite) -> bool {
    suite.version().version == ProtocolVersion::TLSv1_3
}

fn to_tokio(tcp: std::net::TcpStream) -> TcpStream {
    tcp.set_nonblocking(true).unwrap();
    TcpStream::from_std(tcp).unwrap()
}

/// A connected loopback pair of Tokio sockets: (client, server).
fn tokio_pair() -> (TcpStream, TcpStream) {
    let (client, server) = tcp_pair();
    (to_tokio(client), to_tokio(server))
}

/// A handshake between `browntls-tokio` streams over loopback TCP.
async fn userspace_pair(
    client_config: ClientConfig,
    server_config: ServerConfig,
) -> (client::TlsStream<TcpStream>, server::TlsStream<TcpStream>) {
    let (client_tcp, server_tcp) = tokio_pair();
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client_config)).connect(localhost(), client_tcp),
        TlsAcceptor::from(Arc::new(server_config)).accept(server_tcp),
    );
    (client.unwrap(), server.unwrap())
}

async fn pair(
    pki: &Pki,
    suite: SupportedCipherSuite,
) -> (client::TlsStream<TcpStream>, server::TlsStream<TcpStream>) {
    userspace_pair(pki.client_config(suite), pki.server_config(suite)).await
}

async fn read_n_async<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Vec<u8> {
    let mut buf = vec![0; n];
    timeout(LIMIT, r.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    buf
}

async fn read_to_end_async<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    timeout(LIMIT, r.read_to_end(&mut buf))
        .await
        .expect("read timed out")?;
    Ok(buf)
}

async fn write_all_async<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) {
    timeout(LIMIT, w.write_all(data))
        .await
        .expect("write timed out")
        .unwrap();
}

async fn client_kernel(
    stream: client::TlsStream<TcpStream>,
) -> AsyncKtlsStream<ClientConnectionData> {
    timeout(LIMIT, AsyncKtlsStream::from_client(stream))
        .await
        .expect("handover timed out")
        .unwrap()
}

async fn server_kernel(
    stream: server::TlsStream<TcpStream>,
) -> AsyncKtlsStream<ServerConnectionData> {
    timeout(LIMIT, AsyncKtlsStream::from_server(stream))
        .await
        .expect("handover timed out")
        .unwrap()
}

/// Waits until the kernel has given TCP every record of `tls`, which it
/// does as the peer reads.
async fn all_sent<Data: browntls::SideData>(tls: &AsyncKtlsStream<Data>) {
    timeout(LIMIT, async {
        while tls.unsent().unwrap() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the kernel kept records back");
}

/// A loopback pair with a 4096-byte send buffer at the client and a
/// 4096-byte receive buffer at the server, so that a record of full size
/// never fits into what TCP takes at once: (client, server).
async fn narrow_pair() -> (TcpStream, TcpStream) {
    let listener = TcpSocket::new_v4().unwrap();
    listener.set_recv_buffer_size(4096).unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = listener.listen(1).unwrap();
    let connecting = TcpSocket::new_v4().unwrap();
    connecting.set_send_buffer_size(4096).unwrap();
    let (client, server) = tokio::join!(
        connecting.connect(listener.local_addr().unwrap()),
        listener.accept(),
    );
    (client.unwrap(), server.unwrap().0)
}

/// Both ends in the kernel, for every suite: data both ways, a key refresh
/// from each end (TLS 1.3), `close_notify` both ways.
#[tokio::test]
async fn both_ends_offloaded_for_every_suite() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client, server) = pair(&pki, suite).await;
        let (up, down) = (pattern(LEN, 1), pattern(LEN, 2));
        let server_side = async {
            let mut tls = server_kernel(server).await;
            assert_eq!(read_n_async(&mut tls, LEN).await, up, "{suite:?}");
            if tls13(suite) {
                tls.refresh_traffic_keys().unwrap();
            }
            write_all_async(&mut tls, &down).await;
            // The client's close_notify, after its KeyUpdate answer.
            assert!(read_to_end_async(&mut tls).await.unwrap().is_empty());
            assert!(tls.kernel_connection().peer_has_closed());
            timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
        };
        let client_side = async {
            let mut tls = client_kernel(client).await;
            write_all_async(&mut tls, &up[..LEN / 2]).await;
            if tls13(suite) {
                tls.refresh_traffic_keys().unwrap();
            }
            write_all_async(&mut tls, &up[LEN / 2..]).await;
            assert_eq!(read_n_async(&mut tls, LEN).await, down, "{suite:?}");
            // The server has read everything: the kernel's counters and
            // the stream's come to agree, to the byte.
            all_sent(&tls).await;
            timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
            // Nothing may be written after close_notify.
            let err = timeout(LIMIT, tls.write(b"late"))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{suite:?}");
            assert!(read_to_end_async(&mut tls).await.unwrap().is_empty());
        };
        tokio::join!(server_side, client_side);
    }
}

/// The handover happens with data in flight in both directions: the
/// server had written more than the client read, and the client's own
/// records were not flushed. Nothing is lost or reordered, with a
/// userspace peer that checks every record.
#[tokio::test]
async fn data_in_flight_at_the_handover_is_kept_in_order() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (mut client, mut server) = pair(&pki, suite).await;
        let (up, down) = (pattern(LEN, 3), pattern(LEN, 4));
        let server_side = async {
            // Everything at once: the client reads ahead of its
            // application, and the kernel takes over mid-stream.
            write_all_async(&mut server, &down).await;
            timeout(LIMIT, server.flush()).await.unwrap().unwrap();
            assert_eq!(read_n_async(&mut server, LEN).await, up, "{suite:?}");
            if tls13(suite) {
                server.get_mut().1.refresh_traffic_keys().unwrap();
            }
            write_all_async(&mut server, b"bye").await;
            timeout(LIMIT, server.shutdown()).await.unwrap().unwrap();
            assert!(read_to_end_async(&mut server).await.unwrap().is_empty());
        };
        let client_side = async {
            // Ten bytes read by the application; much more is buffered.
            let first = read_n_async(&mut client, 10).await;
            // Written and not flushed.
            write_all_async(&mut client, &up[..1000]).await;
            let mut tls = client_kernel(client).await;
            write_all_async(&mut tls, &up[1000..]).await;
            let rest = read_n_async(&mut tls, LEN - 10).await;
            assert_eq!([first, rest].concat(), down, "{suite:?}");
            assert_eq!(read_to_end_async(&mut tls).await.unwrap(), b"bye");
            if tls13(suite) {
                assert!(tls.kernel_connection().tls13_tickets_received() > 0);
            }
            timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
        };
        tokio::join!(server_side, client_side);
    }
}

/// A kernel server against a userspace client that updates its keys and
/// asks for the server's: the reads answer, and data goes on both ways.
#[tokio::test]
async fn kernel_server_with_userspace_client() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (mut client, server) = pair(&pki, suite).await;
        let (up, down) = (pattern(LEN, 5), pattern(LEN, 6));
        let server_side = async {
            let mut tls = server_kernel(server).await;
            assert_eq!(read_n_async(&mut tls, LEN).await, up, "{suite:?}");
            write_all_async(&mut tls, &down).await;
            assert!(read_to_end_async(&mut tls).await.unwrap().is_empty());
            timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
        };
        let client_side = async {
            write_all_async(&mut client, &up[..LEN / 2]).await;
            if tls13(suite) {
                client.get_mut().1.refresh_traffic_keys().unwrap();
            }
            write_all_async(&mut client, &up[LEN / 2..]).await;
            timeout(LIMIT, client.flush()).await.unwrap().unwrap();
            assert_eq!(read_n_async(&mut client, LEN).await, down, "{suite:?}");
            timeout(LIMIT, client.shutdown()).await.unwrap().unwrap();
            assert!(read_to_end_async(&mut client).await.unwrap().is_empty());
        };
        tokio::join!(server_side, client_side);
    }
}

/// Writes until the socket takes no more, and still takes no more after
/// whatever carries the bytes on (a relay) has had time to drain it;
/// returns how much it took.
async fn fill<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> usize {
    let mut sent = 0;
    loop {
        let before = sent;
        // Large writes, then small ones, until not even a small record fits.
        for chunk in [usize::MAX, 64] {
            poll_fn(|cx| {
                while sent < data.len() {
                    let end = data.len().min(sent.saturating_add(chunk));
                    match Pin::new(&mut *w).poll_write(cx, &data[sent..end]) {
                        Poll::Ready(Ok(n)) => sent += n,
                        Poll::Ready(Err(err)) => panic!("{err}"),
                        Poll::Pending => break,
                    }
                }
                Poll::Ready(())
            })
            .await;
        }
        assert!(sent < data.len(), "the socket never filled");
        if sent == before {
            return sent;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Whether `wire` holds a TLS 1.3 record as long as a protected KeyUpdate
/// (5 bytes, the content type and a 16-byte tag).
fn has_key_update_record(wire: &[u8]) -> bool {
    let mut rest = wire;
    while rest.len() >= 5 {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        if rest[0] == 23 && len == 5 + 1 + 16 {
            return true;
        }
        let Some(next) = rest.get(5 + len..) else {
            break;
        };
        rest = next;
    }
    false
}

/// The peer asks for a key update while the kernel socket is full. The
/// read installs the new receive keys at once and keeps reading; the
/// answer waits for room, and the read itself sends it when the peer makes
/// room, without any write or flush. Split halves, so the read task is
/// alone with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_answers_a_key_update_once_the_socket_has_room() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let Some(suite) = offloadable_suites().into_iter().find(|s| tls13(*s)) else {
        return;
    };
    let (client_tcp, server_tcp, wire, relay) = relay();
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(pki.client_config(suite)))
            .connect(localhost(), to_tokio(client_tcp)),
        TlsAcceptor::from(Arc::new(pki.server_config(suite))).accept(to_tokio(server_tcp)),
    );
    let (client, mut server) = (client.unwrap(), server.unwrap());
    let tls = client_kernel(client).await;
    let (mut reader, mut writer) = tokio::io::split(tls);

    // The kernel end fills its socket: the server reads nothing yet.
    let up = pattern(64 << 20, 7);
    let sent = fill(&mut writer, &up).await;
    assert!(!has_key_update_record(
        &wire.lock().unwrap().client_to_server
    ));

    // The server rotates its keys, asks for ours, and sends data under the
    // new keys, which the read must still open.
    let down = pattern(50_000, 8);
    server.get_mut().1.refresh_traffic_keys().unwrap();
    write_all_async(&mut server, &down).await;
    timeout(LIMIT, server.flush()).await.unwrap().unwrap();
    let read_task = tokio::spawn(async move {
        let got = read_n_async(&mut reader, 50_000).await;
        // Goes on reading: nothing more comes until the server closes,
        // and meanwhile the answer must leave from here.
        let rest = read_to_end_async(&mut reader).await.unwrap();
        (got, rest, reader)
    });

    // The server makes room; the answer follows what was queued before it.
    assert_eq!(read_n_async(&mut server, sent).await, &up[..sent]);
    let answered = async {
        while !has_key_update_record(&wire.lock().unwrap().client_to_server) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    timeout(LIMIT, answered)
        .await
        .expect("the read never sent the KeyUpdate answer");

    // Data after the answer travels under the new transmit keys.
    write_all_async(&mut writer, &up[sent..sent + 100_000]).await;
    assert_eq!(
        read_n_async(&mut server, 100_000).await,
        &up[sent..sent + 100_000]
    );
    timeout(LIMIT, server.shutdown()).await.unwrap().unwrap();
    let (got, rest, reader) = read_task.await.unwrap();
    assert_eq!(got, down);
    assert!(rest.is_empty());
    let mut tls = reader.unsplit(writer);
    timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
    assert!(read_to_end_async(&mut server).await.unwrap().is_empty());
    drop((tls, server));
    relay.join();
}

/// Split halves on two tasks, both ends in the kernel, with key refreshes
/// from both ends while data flows both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_halves_carry_data_both_ways_across_key_updates() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let Some(suite) = offloadable_suites().into_iter().find(|s| tls13(*s)) else {
        return;
    };
    const TOTAL: usize = 4 << 20;
    let (client, server) = pair(&pki, suite).await;
    let (client, server) = (client_kernel(client).await, server_kernel(server).await);

    async fn run<Data>(mut tls: AsyncKtlsStream<Data>, send_seed: u8, recv_seed: u8)
    where
        Data: browntls::SideData + Send + 'static,
    {
        // A key refresh ahead of the data, then split for two tasks.
        tls.refresh_traffic_keys().unwrap();
        let (mut reader, mut writer) = tokio::io::split(tls);
        let write_task = tokio::spawn(async move {
            let data = pattern(TOTAL, send_seed);
            for chunk in data.chunks(300_000) {
                write_all_async(&mut writer, chunk).await;
            }
            writer
        });
        let got = read_n_async(&mut reader, TOTAL).await;
        assert_eq!(got, pattern(TOTAL, recv_seed));
        let writer = write_task.await.unwrap();
        let mut tls = reader.unsplit(writer);
        tls.refresh_traffic_keys().unwrap();
        timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
        assert!(read_to_end_async(&mut tls).await.unwrap().is_empty());
    }
    let (a, b) = tokio::join!(
        tokio::spawn(run(client, 9, 10)),
        tokio::spawn(run(server, 10, 9)),
    );
    a.unwrap();
    b.unwrap();
}

/// A resumed client returned before its handshake to send 0-RTT data: the
/// handover completes the handshake first, and the early data reaches the
/// server once, whether it was accepted or declined and sent again.
#[tokio::test]
async fn a_client_in_its_early_data_phase_is_handed_over() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let Some(suite) = offloadable_suites().into_iter().find(|s| tls13(*s)) else {
        return;
    };
    for accept_early in [true, false] {
        let mut client_config = pki.client_config(suite);
        client_config.enable_early_data = true;
        let connector = TlsConnector::from(Arc::new(client_config)).early_data(true);
        let cache = ServerSessionMemoryCache::new(8);
        let acceptor = |max_early_data_size| {
            let mut config = pki.server_config(suite);
            config.max_early_data_size = max_early_data_size;
            config.session_storage = cache.clone();
            TlsAcceptor::from(Arc::new(config))
        };

        // A first connection leaves the client a ticket.
        let (client_tcp, server_tcp) = tokio_pair();
        let (client, server) = tokio::join!(
            connector.connect(localhost(), client_tcp),
            acceptor(1024).accept(server_tcp),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        write_all_async(&mut server, b"t").await;
        timeout(LIMIT, server.shutdown()).await.unwrap().unwrap();
        assert_eq!(read_to_end_async(&mut client).await.unwrap(), b"t");
        assert!(client.get_ref().1.tls13_tickets_received() > 0);

        let (client_tcp, server_tcp) = tokio_pair();
        let server_side = async {
            let limit = if accept_early { 1024 } else { 0 };
            let mut server = acceptor(limit).accept(server_tcp).await.unwrap();
            let mut tls = if accept_early {
                // Accepted 0-RTT data comes first out of the kernel stream,
                // which tells how much of it there is.
                assert!(server.get_mut().1.early_data().is_some());
                let tls = server_kernel(server).await;
                assert_eq!(tls.early_data_len(), b"early request".len());
                tls
            } else {
                assert!(server.get_mut().1.early_data().is_none());
                let tls = server_kernel(server).await;
                assert_eq!(tls.early_data_len(), 0);
                tls
            };
            assert_eq!(
                read_n_async(&mut tls, 22).await,
                b"early request and more",
                "accepted: {accept_early}"
            );
            write_all_async(&mut tls, b"reply").await;
            timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
            assert!(read_to_end_async(&mut tls).await.unwrap().is_empty());
        };
        let client_side = async {
            let mut client = connector.connect(localhost(), client_tcp).await.unwrap();
            assert!(client.get_ref().1.is_handshaking());
            write_all_async(&mut client, b"early request").await;
            let mut tls = client_kernel(client).await;
            write_all_async(&mut tls, b" and more").await;
            assert_eq!(read_to_end_async(&mut tls).await.unwrap(), b"reply");
            timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
        };
        tokio::join!(server_side, client_side);
    }
}

/// A peer that closes TCP without `close_notify` is reported as
/// truncation, by every later read too.
#[tokio::test]
async fn truncation_is_reported() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (client, mut server) = pair(&pki, suite).await;
    write_all_async(&mut server, b"partial").await;
    timeout(LIMIT, server.flush()).await.unwrap().unwrap();
    // Handed over first: the kernel refuses the upper layer protocol once
    // the peer's FIN has arrived.
    let mut tls = client_kernel(client).await;
    let (tcp, _) = server.into_inner();
    drop(tcp);

    let mut got = Vec::new();
    let err = timeout(LIMIT, tls.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(got, b"partial");
    let err = tls.read(&mut [0u8; 8]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

/// A megabyte written through small socket buffers and shut down at once
/// arrives whole, `close_notify` included. The kernel reports each write
/// done while it still holds most of a record TCP had no room for;
/// `shutdown` waits until the kernel's counters show every record with
/// TCP before it sends the FIN.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_megabyte_shut_down_at_once_arrives_whole() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    for round in 0..8u8 {
        let (client_tcp, server_tcp) = narrow_pair().await;
        let (client, server) = tokio::join!(
            TlsConnector::from(Arc::new(pki.client_config(suite))).connect(localhost(), client_tcp),
            TlsAcceptor::from(Arc::new(pki.server_config(suite))).accept(server_tcp),
        );
        let (client, mut server) = (client.unwrap(), server.unwrap());
        let mut tls = client_kernel(client).await;

        let up = pattern(1 << 20, round);
        let expected = up.clone();
        let reader = tokio::spawn(async move {
            // A slow reader: the kernel end is ahead of it throughout.
            let mut got = Vec::with_capacity(expected.len());
            let mut chunk = vec![0u8; 8192];
            loop {
                let n = timeout(LIMIT, server.read(&mut chunk))
                    .await
                    .expect("read timed out")
                    .expect("the stream was cut short");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..n]);
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
            assert!(got == expected, "round {round}: {} bytes", got.len());
            timeout(LIMIT, server.shutdown()).await.unwrap().unwrap();
        });
        write_all_async(&mut tls, &up).await;
        timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
        assert!(
            read_to_end_async(&mut tls).await.unwrap().is_empty(),
            "round {round}"
        );
        reader.await.unwrap();
    }
}

/// What the kernel accepted and TCP had no room for is counted, and
/// `shutdown` does not send the FIN ahead of it: with a peer that does not
/// read, a write of four records is reported done while most of it is
/// still with the kernel, and the shutdown stays pending. Once the peer
/// reads, it gets every byte and `close_notify`, and the shutdown ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_waits_for_what_the_kernel_holds() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client_tcp, server_tcp) = narrow_pair().await;
        let (client, server) = tokio::join!(
            TlsConnector::from(Arc::new(pki.client_config(suite))).connect(localhost(), client_tcp),
            TlsAcceptor::from(Arc::new(pki.server_config(suite))).accept(server_tcp),
        );
        let (client, mut server) = (client.unwrap(), server.unwrap());
        let mut tls = client_kernel(client).await;
        assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");

        let up = pattern(4 * 16384, 9);
        let taken = timeout(LIMIT, tls.write(&up)).await.unwrap().unwrap();
        assert!(taken >= 16384, "{suite:?}: {taken}");
        let held = tls.unsent().unwrap();
        // More than the socket's buffers can have taken is left, and no
        // more than the records of what was written come to.
        assert!(held > 0, "{suite:?}");
        let most = taken + 29 * taken.div_ceil(16384);
        assert!(held <= most as u64, "{suite:?}: {held} of {most}");

        // Dropping the future gives up the wait, not the shutdown.
        for _ in 0..2 {
            assert!(
                timeout(Duration::from_millis(100), tls.shutdown())
                    .await
                    .is_err(),
                "{suite:?}: shut down with {} bytes unsent",
                tls.unsent().unwrap_or(u64::MAX)
            );
        }
        assert!(tls.unsent().unwrap() > 0, "{suite:?}");

        let reader = tokio::spawn(async move {
            let got = read_to_end_async(&mut server)
                .await
                .expect("the stream was cut short");
            timeout(LIMIT, server.shutdown()).await.unwrap().unwrap();
            got
        });
        timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
        assert!(
            read_to_end_async(&mut tls).await.unwrap().is_empty(),
            "{suite:?}"
        );
        assert!(reader.await.unwrap() == up[..taken], "{suite:?}");
    }
}

/// A peer that has closed TCP is not handed over: the kernel attaches the
/// `tls` upper layer protocol to an established connection only. The
/// stream comes back untouched and yields in userspace what the peer sent.
#[tokio::test]
async fn a_peer_that_closed_tcp_is_left_to_userspace() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (client, mut server) = pair(&pki, suite).await;
    write_all_async(&mut server, b"last words").await;
    timeout(LIMIT, server.shutdown()).await.unwrap().unwrap();
    drop(server);
    // The FIN has arrived once the socket reports its read side closed.
    timeout(LIMIT, async {
        let (tcp, _) = client.get_ref();
        while !tcp
            .ready(Interest::READABLE)
            .await
            .unwrap()
            .is_read_closed()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the peer's FIN did not arrive");

    let Err(StreamHandoffError::Refused {
        stream: mut client,
        received,
        error,
        ..
    }) = AsyncKtlsStream::from_client(client).await
    else {
        panic!("handed over after the peer closed TCP");
    };
    assert_eq!(error.kind(), io::ErrorKind::NotConnected, "{error}");
    assert!(received.is_empty());
    assert_eq!(read_to_end_async(&mut client).await.unwrap(), b"last words");
}

/// `into_kernel_handoff` and `AsyncKtlsStream::new` by hand, which keeps
/// the stream across a timeout; a connection that still has something in
/// flight is refused whole.
#[tokio::test]
async fn a_readied_connection_is_handed_over_from_its_parts() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (mut client, mut server) = pair(&pki, suite).await;
    write_all_async(&mut server, b"before the handover").await;
    timeout(LIMIT, server.flush()).await.unwrap().unwrap();
    assert_eq!(read_n_async(&mut client, 6).await, b"before");

    // Unread plaintext: not ready, and everything comes back.
    let (tcp, conn) = client.into_inner();
    let Err(HandoffError::Refused {
        conn,
        socket,
        received,
        error,
    }) = AsyncKtlsStream::new(conn, tcp, Vec::new())
    else {
        panic!("handed over with plaintext unread");
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
    assert!(received.is_empty());

    // Readied by hand: what was unread is returned first.
    let mut conn = conn;
    let mut unread = Vec::new();
    io::Read::read_to_end(&mut conn.reader(), &mut unread).unwrap_err();
    assert_eq!(unread, b" the handover");
    let mut tls = AsyncKtlsStream::new(conn, socket, unread).unwrap();
    write_all_async(&mut server, b", and after").await;
    timeout(LIMIT, server.shutdown()).await.unwrap().unwrap();
    assert_eq!(
        read_to_end_async(&mut tls).await.unwrap(),
        b" the handover, and after"
    );
    write_all_async(&mut tls, b"reply").await;
    timeout(LIMIT, tls.shutdown()).await.unwrap().unwrap();
    assert_eq!(read_to_end_async(&mut server).await.unwrap(), b"reply");
}

/// Without secret extraction nothing is handed over, the socket is left
/// alone, and the stream carries on in userspace. Needs no kernel TLS.
#[tokio::test]
async fn a_refused_handover_returns_the_stream() {
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let mut server_config = pki.server_config(suite);
    server_config.enable_secret_extraction = false;
    let (mut client, mut server) = userspace_pair(pki.client_config(suite), server_config).await;
    write_all_async(&mut client, b"hello").await;
    timeout(LIMIT, client.flush()).await.unwrap().unwrap();
    assert_eq!(read_n_async(&mut server, 2).await, b"he");

    let Err(StreamHandoffError::Refused {
        stream: mut server,
        received,
        early_data_len,
        error,
    }) = AsyncKtlsStream::from_server(server).await
    else {
        panic!("handed over without secret extraction");
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
    assert!(received.is_empty());
    assert_eq!(early_data_len, 0);
    assert_eq!(read_n_async(&mut server, 3).await, b"llo");
    write_all_async(&mut server, b"world").await;
    timeout(LIMIT, server.flush()).await.unwrap().unwrap();
    assert_eq!(read_n_async(&mut client, 5).await, b"world");
}

/// Without the `tls` module the stream comes back untouched (the refusal
/// is the kernel's), and goes on in userspace. Runs only where kernel TLS
/// is missing.
#[tokio::test]
async fn a_kernel_without_tls_returns_the_stream() {
    let has_tls = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp")
        .is_ok_and(|ulps| ulps.split_whitespace().any(|ulp| ulp == "tls"));
    if has_tls {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (mut client, mut server) = pair(&pki, suite).await;
    write_all_async(&mut server, b"hello").await;
    timeout(LIMIT, server.flush()).await.unwrap().unwrap();
    assert_eq!(read_n_async(&mut client, 2).await, b"he");

    let Err(StreamHandoffError::Refused {
        stream: mut client,
        received,
        ..
    }) = AsyncKtlsStream::from_client(client).await
    else {
        panic!("handed over without kernel TLS");
    };
    // Refused before anything was taken out of the stream.
    assert!(received.is_empty());
    assert_eq!(read_n_async(&mut client, 3).await, b"llo");
}
