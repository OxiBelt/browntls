//! `into_kernel_handoff` of a server stream returned before its handshake
//! completed (`TlsAcceptor::early_data`): the handoff completes the
//! handshake first (0.5-RTT data sent before the wait), sets the unread
//! 0-RTT data aside in front, and a handshake that fails is reported by
//! the handoff and by every later operation of the stream that comes back.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Write as _};
use std::sync::Arc;
use std::time::Duration;

use browntls_core::ClientConnection;
use browntls_tokio::{TlsAcceptor, server};
use common::server_early::*;
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter, DuplexStream, duplex};
use tokio::time::timeout;

/// How long a handoff that has to wait is watched before it is taken to be
/// waiting.
const WAITING: Duration = Duration::from_millis(50);

const EARLY: &[u8] = b"early request";
const REST: &[u8] = b"and the rest";

/// An acceptor that returns before the handshake for early data, with a
/// connection that may be handed to the kernel.
fn acceptor(setup: &Setup, half_rtt: bool) -> TlsAcceptor {
    let mut config = setup.pki.server_config(&browntls_core::version::TLS13);
    config.max_early_data_size = ALLOWANCE;
    config.send_half_rtt_data = half_rtt;
    config.session_storage = setup.cache.clone();
    config.enable_secret_extraction = true;
    TlsAcceptor::from(Arc::new(config)).early_data(true)
}

/// A resumed connection whose client, driven by hand, has sent its
/// ClientHello and [`EARLY`] and nothing more: the client, its transport,
/// and the server's stream, returned in the middle of its handshake.
async fn returned_early(
    setup: &Setup,
    half_rtt: bool,
) -> (
    ClientConnection,
    DuplexStream,
    server::TlsStream<DuplexStream>,
) {
    setup.first_connection().await;
    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(EARLY);
    send(&mut client, &mut c).await;
    let server = timeout(LIMIT, acceptor(setup, half_rtt).accept(s))
        .await
        .expect("timed out")
        .unwrap();
    assert!(server.get_ref().1.is_handshaking());
    (client, c, server)
}

/// The client takes the server's flight and sends the end of its early
/// data, its Finished and [`REST`].
async fn finish(client: &mut ClientConnection, c: &mut DuplexStream) {
    receive(client, c).await;
    assert!(!client.is_handshaking());
    assert!(client.is_early_data_accepted());
    client.writer().write_all(REST).unwrap();
    send(client, c).await;
}

/// Has `client` take what the server sends until it has read `len` bytes
/// of plaintext.
async fn read_until(client: &mut ClientConnection, c: &mut DuplexStream, len: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < len {
        receive(client, c).await;
        let _ = io::Read::read_to_end(&mut client.reader(), &mut got);
    }
    got
}

/// Reads from `server` until `got` holds [`REST`].
async fn read_rest(server: &mut server::TlsStream<DuplexStream>, mut got: Vec<u8>) {
    while got.len() < REST.len() {
        let mut buf = [0; 64];
        let n = timeout(LIMIT, server.read(&mut buf))
            .await
            .expect("timed out")
            .unwrap();
        assert!(n > 0, "end of file before the data");
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, REST);
}

/// The handoff of a stream in the middle of its handshake waits for the
/// client's Finished, completes the handshake, and then holds the 0-RTT
/// data nobody read in front of what followed it. The connection is ready
/// for the kernel, and a stream turned back is past its early phase.
#[tokio::test]
async fn a_stream_returned_early_completes_its_handshake_in_the_handoff() {
    for (half_rtt, take_apart) in [(false, false), (false, true), (true, false), (true, true)] {
        let setup = Setup::new();
        let (mut client, mut c, mut server) = returned_early(&setup, half_rtt).await;
        if half_rtt {
            // 0.5-RTT data, written while the client's Finished is out.
            server.write_all(b"reply").await.unwrap();
        }

        let mut handoff = server.into_kernel_handoff();
        let waited = timeout(WAITING, &mut handoff).await;
        assert!(waited.is_err(), "handed over in the middle of a handshake");

        finish(&mut client, &mut c).await;
        let handoff = timeout(LIMIT, handoff).await.expect("timed out").unwrap();
        let conn = handoff.get_ref().1;
        assert!(!conn.is_handshaking());
        assert_eq!(conn.kernel_handoff_blocker(), None);
        let early = handoff.early_data_len();
        assert_eq!(&handoff.received()[..early], EARLY, "{half_rtt}");

        if take_apart {
            let (_io, conn, received) = handoff.into_parts();
            assert!(REST.starts_with(&received[early..]));
            assert!(conn.dangerous_into_kernel_connection().is_ok());
            continue;
        }
        let (mut server, received) = handoff.into_stream();
        // What the handshake's last read brought in is set aside; the
        // rest of the client's data is the stream's to read.
        read_rest(&mut server, received[early..].to_vec()).await;
        // No early phase is left: the early data ended with the handshake,
        // and the stream writes and shuts down.
        let mut none = Vec::new();
        let mut reader = server.early_data().unwrap();
        timeout(LIMIT, reader.read_to_end(&mut none))
            .await
            .expect("timed out")
            .unwrap();
        assert!(none.is_empty());
        server.write_all(b"after").await.unwrap();
        server.shutdown().await.unwrap();
        let expected: &[u8] = if half_rtt { b"replyafter" } else { b"after" };
        let got = timeout(LIMIT, read_until(&mut client, &mut c, expected.len()))
            .await
            .expect("timed out");
        assert_eq!(got, expected);
    }
}

/// 0.5-RTT data a write-buffering transport still holds goes out before
/// the handoff waits for the client's Finished, as in a flush of the
/// stream: the client has its answer while the handoff is still waiting.
#[tokio::test]
async fn half_rtt_data_is_flushed_before_the_handoff_waits() {
    let setup = Setup::new();
    setup.first_connection().await;
    let (mut c, s) = duplex(64 * 1024);
    let mut client = setup.manual_client(EARLY);
    send(&mut client, &mut c).await;
    let mut server = timeout(LIMIT, acceptor(&setup, true).accept(BufWriter::new(s)))
        .await
        .expect("timed out")
        .unwrap();
    assert!(server.get_ref().1.is_handshaking());
    // Encrypted at once, and left in the transport's buffer.
    server.write_all(b"reply").await.unwrap();

    let mut handoff = server.into_kernel_handoff();
    let waited = timeout(WAITING, &mut handoff).await;
    assert!(waited.is_err(), "handed over in the middle of a handshake");
    let reply = timeout(LIMIT, read_until(&mut client, &mut c, 5))
        .await
        .expect("the 0.5-RTT data is held back until the client's Finished");
    assert_eq!(reply, b"reply");

    client.writer().write_all(REST).unwrap();
    send(&mut client, &mut c).await;
    let handoff = timeout(LIMIT, handoff).await.expect("timed out").unwrap();
    let early = handoff.early_data_len();
    assert_eq!(&handoff.received()[..early], EARLY);
    assert_eq!(handoff.get_ref().1.kernel_handoff_blocker(), None);
}

/// A handoff given up in the middle of the handshake returns the stream
/// as it was: still in its early phase, the 0-RTT data still to be read
/// through its reader, the handshake still to complete.
#[tokio::test]
async fn a_handoff_given_up_leaves_the_early_phase_in_place() {
    let setup = Setup::new();
    let (mut client, mut c, server) = returned_early(&setup, false).await;

    let mut handoff = server.into_kernel_handoff();
    let waited = timeout(WAITING, &mut handoff).await;
    assert!(waited.is_err(), "handed over in the middle of a handshake");
    let early = handoff.early_data_len();
    let (mut server, received) = handoff.into_stream().unwrap();
    assert!(server.get_ref().1.is_handshaking());

    // Nothing was taken out of the stream: the 0-RTT data is still its
    // reader's.
    assert_eq!((early, received.len()), (0, 0));
    let all = timeout(LIMIT, read_early(&mut server, EARLY.len()))
        .await
        .expect("timed out");
    assert_eq!(all, EARLY);

    finish(&mut client, &mut c).await;
    read_rest(&mut server, Vec::new()).await;
    assert!(!server.get_ref().1.is_handshaking());
}

/// A handshake that failed before the handoff is reported by it at once,
/// with the stream's error, and the stream that comes back goes on
/// reporting it.
#[tokio::test]
async fn a_handshake_that_failed_before_the_handoff_fails_it() {
    for half_rtt in [false, true] {
        let setup = Setup::new();
        let (_client, mut c, mut server) = returned_early(&setup, half_rtt).await;
        // Bytes that are no TLS record follow the early data. The transport
        // stays open: only the TLS state ends the operations.
        c.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await
            .unwrap();
        let first = timeout(LIMIT, server.flush()).await.unwrap().unwrap_err();
        assert!(tls_error(&first).is_some(), "{first:?}");

        let err = timeout(LIMIT, server.into_kernel_handoff())
            .await
            .expect("the handoff waits on a handshake that failed")
            .unwrap_err();
        assert_eq!(err.error.kind(), first.kind(), "{err}");
        assert_eq!(tls_error(&err.error), tls_error(&first), "{err}");
        assert_eq!((err.early_data_len, err.received.len()), (0, 0));

        let mut server = err.stream;
        let again = timeout(LIMIT, server.flush()).await.unwrap().unwrap_err();
        assert_eq!(tls_error(&again), tls_error(&first), "{again:?}");
        drop(c);
    }
}

/// A handshake that fails while the handoff drives it fails the handoff,
/// the 0-RTT data that had arrived is not lost, and every later operation
/// of the stream that comes back reports the failure instead of waiting
/// for the peer.
#[tokio::test]
async fn a_handshake_that_fails_in_the_handoff_fails_the_stream() {
    for eof in [false, true] {
        let setup = Setup::new();
        let (_client, mut c, server) = returned_early(&setup, false).await;

        let mut handoff = server.into_kernel_handoff();
        let waited = timeout(WAITING, &mut handoff).await;
        assert!(waited.is_err(), "handed over in the middle of a handshake");
        let open = if eof {
            drop(c);
            None
        } else {
            c.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await
                .unwrap();
            Some(c)
        };
        let expect = |err: &io::Error| {
            if eof {
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err:?}");
            } else {
                assert!(tls_error(err).is_some(), "{err:?}");
            }
        };

        let err = timeout(LIMIT, handoff)
            .await
            .expect("timed out")
            .unwrap_err();
        expect(&err.error);
        assert_eq!((err.early_data_len, err.received.len()), (0, 0));
        let mut server = err.stream;

        // The early data that arrived is still the reader's.
        let mut early = Vec::new();
        let failed = timeout(LIMIT, server.early_data().unwrap().read_to_end(&mut early))
            .await
            .expect("timed out")
            .unwrap_err();
        expect(&failed);
        assert_eq!(early, EARLY);

        for _ in 0..2 {
            let failed = timeout(LIMIT, server.read(&mut [0; 4]))
                .await
                .expect("a read waits after the handshake failed")
                .unwrap_err();
            expect(&failed);
            let failed = timeout(LIMIT, server.write(b"more"))
                .await
                .expect("a write waits after the handshake failed")
                .unwrap_err();
            expect(&failed);
            let failed = timeout(LIMIT, server.flush())
                .await
                .expect("a flush waits after the handshake failed")
                .unwrap_err();
            expect(&failed);
        }
        drop(open);
    }
}
