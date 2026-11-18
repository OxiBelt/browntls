//! The kernel's zero-copy options, and `sendfile`, on `AsyncKtlsStream`,
//! against the running kernel over loopback TCP: the options read back, a
//! file sent between writes and key updates, and a file sent through small
//! socket buffers and shut down at once.
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

use std::io;
use std::sync::Arc;
use std::time::Duration;

use browntls::client::ClientConnectionData;
use browntls::server::ServerConnectionData;
use browntls::{ProtocolVersion, SideData, SupportedCipherSuite};
use browntls_ktls::AsyncKtlsStream;
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// Both ends in the kernel after a `browntls-tokio` handshake over the
/// connected pair `(client, server)`.
async fn kernel_pair_over(
    pki: &Pki,
    suite: SupportedCipherSuite,
    (client_tcp, server_tcp): (TcpStream, TcpStream),
) -> (
    AsyncKtlsStream<ClientConnectionData>,
    AsyncKtlsStream<ServerConnectionData>,
) {
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(pki.client_config(suite))).connect(localhost(), client_tcp),
        TlsAcceptor::from(Arc::new(pki.server_config(suite))).accept(server_tcp),
    );
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            AsyncKtlsStream::from_client(client.unwrap()),
            AsyncKtlsStream::from_server(server.unwrap()),
        )
    })
    .await
    .expect("handover timed out");
    (client.unwrap(), server.unwrap())
}

/// Both ends in the kernel over loopback TCP: (client, server).
async fn kernel_pair(
    pki: &Pki,
    suite: SupportedCipherSuite,
) -> (
    AsyncKtlsStream<ClientConnectionData>,
    AsyncKtlsStream<ServerConnectionData>,
) {
    let (client_tcp, server_tcp) = tcp_pair();
    kernel_pair_over(pki, suite, (to_tokio(client_tcp), to_tokio(server_tcp))).await
}

/// A loopback pair with a send buffer of `size` bytes at the client and a
/// receive buffer of `size` bytes at the server (the kernel doubles them,
/// and has a least size), so that a record of full size never fits into
/// what TCP takes at once: (client, server).
async fn narrow_pair(size: u32) -> (TcpStream, TcpStream) {
    let listener = TcpSocket::new_v4().unwrap();
    listener.set_recv_buffer_size(size).unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = listener.listen(1).unwrap();
    let connecting = TcpSocket::new_v4().unwrap();
    connecting.set_send_buffer_size(size).unwrap();
    let (client, server) = tokio::join!(
        connecting.connect(listener.local_addr().unwrap()),
        listener.accept(),
    );
    (client.unwrap(), server.unwrap().0)
}

/// Sends `file[from..to]`.
async fn sendfile_all<Data: SideData>(
    tls: &mut AsyncKtlsStream<Data>,
    file: &std::fs::File,
    from: usize,
    to: usize,
) {
    let mut offset = from;
    while offset < to {
        let sent = tls
            .sendfile(file, offset as u64, to - offset)
            .await
            .unwrap();
        assert!(sent != 0 && sent <= to - offset, "{sent} at {offset}");
        offset += sent;
    }
}

/// The options are read back as set, TLS 1.2 and a kernel before Linux
/// 7.2 refuse the promise about padding, and data, a key refresh and the
/// closure pass with what could be set.
#[tokio::test]
async fn the_options_are_read_back_and_the_stream_goes_on() {
    if !kernel_tls() {
        return;
    }
    let promised = no_pad_kernel();
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (mut client, mut server) = kernel_pair(&pki, suite).await;
        let (up, down) = (pattern(LEN, 21), pattern(LEN, 22));

        assert!(!client.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
        client.set_tx_zerocopy_sendfile(true).unwrap();
        assert!(client.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
        if tls13(suite) && promised {
            for expect in [true, false, true] {
                client.set_rx_expect_no_pad(expect).unwrap();
                assert_eq!(client.rx_expect_no_pad().unwrap(), expect, "{suite:?}");
            }
        } else {
            let err = client.set_rx_expect_no_pad(true).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{suite:?}");
            if tls13(suite) {
                assert!(!client.rx_expect_no_pad().unwrap(), "{suite:?}");
            } else {
                let err = client.rx_expect_no_pad().unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{suite:?}");
            }
        }

        let server_side = async {
            let mut got = vec![0; LEN];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, up, "{suite:?}");
            server.write_all(&down[..LEN / 2]).await.unwrap();
            if tls13(suite) {
                server.refresh_traffic_keys().unwrap();
            }
            server.write_all(&down[LEN / 2..]).await.unwrap();
            let mut rest = Vec::new();
            server.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            server.shutdown().await.unwrap();
        };
        let client_side = async {
            client.write_all(&up).await.unwrap();
            let mut got = vec![0; LEN];
            client.read_exact(&mut got).await.unwrap();
            assert_eq!(got, down, "{suite:?}");
            assert!(client.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
            if tls13(suite) {
                // New receive keys came with the server's KeyUpdate.
                assert_eq!(client.rx_expect_no_pad().unwrap(), promised, "{suite:?}");
            }
            client.shutdown().await.unwrap();
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        };
        timeout(LIMIT, async { tokio::join!(server_side, client_side) })
            .await
            .expect("the exchange timed out");
    }
}

/// A file sent between writes, with a key refresh in the middle, for every
/// suite: the peer reads every byte in order, and `shutdown` finds every
/// record with TCP.
#[tokio::test]
async fn a_file_is_sent_for_every_suite() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (mut client, mut server) = kernel_pair(&pki, suite).await;
        let contents = pattern(LEN + 7, 23);
        let file = temp_file(&contents);
        let mut expected = b"before".to_vec();
        expected.extend_from_slice(&contents[1..]);
        expected.extend_from_slice(b"after");

        let server_side = async {
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            assert!(got == expected, "{suite:?}: {} bytes", got.len());
            server.shutdown().await.unwrap();
        };
        let client_side = async {
            assert_eq!(client.sendfile(&file, 0, 0).await.unwrap(), 0);
            client.write_all(b"before").await.unwrap();
            sendfile_all(&mut client, &file, 1, LEN / 2).await;
            if tls13(suite) {
                client.refresh_traffic_keys().unwrap();
            }
            // More than the file has left, then its end.
            let mut offset = LEN / 2;
            while offset < contents.len() {
                let sent = client
                    .sendfile(&file, offset as u64, 4 * LEN)
                    .await
                    .unwrap();
                assert!(sent != 0 && sent <= contents.len() - offset, "{suite:?}");
                offset += sent;
            }
            let end = contents.len() as u64;
            assert_eq!(client.sendfile(&file, end, 100).await.unwrap(), 0);
            client.write_all(b"after").await.unwrap();
            client.shutdown().await.unwrap();
            let err = client.sendfile(&file, 0, 100).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{suite:?}");
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        };
        timeout(LIMIT, async { tokio::join!(server_side, client_side) })
            .await
            .expect("the exchange timed out");
    }
}

/// A file larger than the socket buffers by far, sent through sockets that
/// never take a whole record at once and shut down at once: `sendfile`
/// waits for room as a write does, and nothing is cut short.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_is_sent_through_small_socket_buffers() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suites = offloadable_suites();
    let chosen = [
        suites.iter().copied().find(|s| tls13(*s)),
        suites.iter().copied().find(|s| !tls13(*s)),
    ];
    for suite in chosen.into_iter().flatten() {
        let (mut client, mut server) = kernel_pair_over(&pki, suite, narrow_pair(4096).await).await;
        let contents = pattern((2 << 20) + 5, 24);
        let file = temp_file(&contents);
        let expected = contents.clone();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            assert!(got == expected, "{} bytes", got.len());
            server.shutdown().await.unwrap();
        });
        timeout(LIMIT, async {
            sendfile_all(&mut client, &file, 0, contents.len()).await;
            client.shutdown().await.unwrap();
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        })
        .await
        .expect("the transfer timed out");
        timeout(LIMIT, reader)
            .await
            .expect("the reader timed out")
            .unwrap();
    }
}

/// A count that reaches past the end of the file does not make the call
/// wait for the peer. Left to find the end of the file itself, the kernel
/// would send the last record without regard for the non-blocking socket
/// and keep the thread until TCP has room for all of it; the stream asks
/// for no more than the file holds. The peer reads nothing until the call
/// is back: its kernel holds one record that came before, which is all it
/// takes in unread, and the narrowest sockets the kernel allows have no
/// room for the record the file makes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_count_past_the_end_of_the_file_does_not_wait_for_the_peer() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suites = offloadable_suites();
    let chosen = [
        suites.iter().copied().find(|s| tls13(*s)),
        suites.iter().copied().find(|s| !tls13(*s)),
    ];
    for suite in chosen.into_iter().flatten() {
        let (mut client, mut server) = kernel_pair_over(&pki, suite, narrow_pair(1).await).await;
        let before = pattern(16384, 26);
        let contents = pattern(16_000, 25);
        let file = temp_file(&contents);
        // One record for the peer's kernel to hold, all of it out of TCP's
        // hands at this end.
        timeout(LIMIT, async {
            client.write_all(&before).await.unwrap();
            while client.unsent().unwrap() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        })
        .await
        .expect("the first record was not sent");
        // Spawned: the future is `Send`, and a call that waits in the
        // kernel after all keeps one thread only.
        let mut sender = tokio::spawn(async move {
            let sent = client.sendfile(&file, 0, 1 << 20).await;
            let unsent = client.unsent().unwrap();
            (client, sent, unsent)
        });
        let in_time = timeout(Duration::from_secs(5), &mut sender).await;
        // The peer reads now, which also frees a call that did wait.
        let mut got = vec![0; before.len() + contents.len()];
        timeout(LIMIT, server.read_exact(&mut got))
            .await
            .expect("the file did not arrive")
            .unwrap();
        assert!(got[..before.len()] == before, "{suite:?}");
        assert!(got[before.len()..] == contents, "{suite:?}");
        let (mut client, sent, unsent) = match in_time {
            Ok(joined) => joined.unwrap(),
            Err(_) => {
                let _ = timeout(LIMIT, sender).await;
                panic!("{suite:?}: `sendfile` waited for the peer to read");
            }
        };
        assert_eq!(sent.unwrap(), contents.len(), "{suite:?}");
        // The call came back with part of the record still in the kernel's
        // hands: it had not waited for room.
        eprintln!(
            "{:?}: the kernel held {unsent} bytes of the file's record",
            suite.suite()
        );
        assert_ne!(unsent, 0, "{suite:?}: TCP had room for the whole record");
        let both = async {
            tokio::join!(
                async {
                    client.shutdown().await.unwrap();
                    let mut rest = Vec::new();
                    client.read_to_end(&mut rest).await.unwrap();
                },
                async {
                    let mut rest = Vec::new();
                    server.read_to_end(&mut rest).await.unwrap();
                    assert!(rest.is_empty(), "{suite:?}");
                    server.shutdown().await.unwrap();
                },
            )
        };
        timeout(LIMIT, both).await.expect("the closure timed out");
    }
}
