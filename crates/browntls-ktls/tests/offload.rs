//! Handovers to the running kernel over loopback TCP: both ends offloaded,
//! one end offloaded against a userspace peer (with the ciphertext
//! recorded), key updates, tickets, record size limits, closure.
//!
//! The tests that need kernel TLS are skipped without the `tls` module
//! unless `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use browntls_core::client::ClientConnectionData;
use browntls_core::kernel::KernelHandoffBlocker;
use browntls_core::server::ServerConnectionData;
use browntls_core::{
    ClientConnection, ProtocolVersion, ServerConnection, StreamOwned, SupportedCipherSuite,
};
use browntls_ktls::{HandoffError, KtlsStream};
use common::*;

const LEN: usize = 200_000;

fn client_stream(
    pki: &Pki,
    suite: SupportedCipherSuite,
    tcp: TcpStream,
) -> KtlsStream<TcpStream, ClientConnectionData> {
    let conn = ClientConnection::new(Arc::new(pki.client_config(suite)), localhost()).unwrap();
    KtlsStream::new(conn, tcp).unwrap()
}

fn server_stream(
    pki: &Pki,
    suite: SupportedCipherSuite,
    tcp: TcpStream,
) -> KtlsStream<TcpStream, ServerConnectionData> {
    let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
    KtlsStream::new(conn, tcp).unwrap()
}

fn tls13(suite: SupportedCipherSuite) -> bool {
    suite.version().version == ProtocolVersion::TLSv1_3
}

#[test]
fn both_ends_offloaded_for_every_suite() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client_tcp, server_tcp) = tcp_pair();
        let up = pattern(LEN, 1);
        let down = pattern(LEN, 2);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut tls = server_stream(&pki, suite, server_tcp);
                assert_eq!(read_n(&mut tls, LEN).unwrap(), up, "{suite:?}");
                if tls13(suite) {
                    tls.refresh_traffic_keys().unwrap();
                }
                tls.write_all(&down).unwrap();
                assert_eq!(read_n(&mut tls, 16).unwrap(), b"after the answer");
                assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
                // The client's close_notify, after its KeyUpdate answer.
                let mut rest = Vec::new();
                tls.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty());
                assert!(tls.kernel_connection().peer_has_closed());
                tls.send_close_notify().unwrap();
                assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            // A blocking socket: the kernel holds nothing back after a
            // call, and its counters agree with the stream's to the byte,
            // across records of every kind and new keys.
            assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            tls.write_all(&up[..LEN / 2]).unwrap();
            assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            if tls13(suite) {
                tls.refresh_traffic_keys().unwrap();
                assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            }
            tls.write_all(&up[LEN / 2..]).unwrap();
            assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            // Reading answers the server's KeyUpdate with one under the
            // old keys, then installs new ones.
            assert_eq!(read_n(&mut tls, LEN).unwrap(), down, "{suite:?}");
            assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            tls.write_all(b"after the answer").unwrap();
            assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            tls.send_close_notify().unwrap();
            assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            server.join().unwrap();
        });
    }
}

/// A kernel client against a userspace server that sends tickets, updates
/// its keys, and closes: the userspace end checks every record, and the
/// recorded TLS 1.2 explicit nonces never repeat.
#[test]
fn kernel_client_with_userspace_server() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client_tcp, server_tcp, wire, relay) = relay();
        let up = pattern(LEN, 3);
        let down = pattern(LEN, 4);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                assert_eq!(read_n(&mut tls, LEN).unwrap(), up, "{suite:?}");
                tls.write_all(&down[..LEN / 2]).unwrap();
                if tls13(suite) {
                    tls.conn.refresh_traffic_keys().unwrap();
                }
                tls.write_all(&down[LEN / 2..]).unwrap();
                tls.conn.send_close_notify();
                tls.flush().unwrap();
                let mut rest = Vec::new();
                tls.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty());
                tls.sock.shutdown(Shutdown::Both).unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            tls.write_all(&up).unwrap();
            let mut got = Vec::new();
            tls.read_to_end(&mut got).unwrap();
            assert_eq!(got, down, "{suite:?}");
            if tls13(suite) {
                assert!(tls.kernel_connection().tls13_tickets_received() > 0);
            }
            tls.send_close_notify().unwrap();
            drop(tls);
            server.join().unwrap();
        });
        relay.join();
        check_explicit_nonces(suite, &wire.lock().unwrap());
    }
}

/// A kernel server against a userspace client whose first data travels
/// with its Finished (read before the handover and returned first), and
/// which updates its keys mid-stream.
#[test]
fn kernel_server_with_userspace_client() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client_tcp, server_tcp, wire, relay) = relay();
        let up = pattern(LEN, 5);
        let down = pattern(LEN, 6);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut tls = server_stream(&pki, suite, server_tcp);
                assert_eq!(read_n(&mut tls, LEN).unwrap(), up, "{suite:?}");
                tls.write_all(&down).unwrap();
                let mut rest = Vec::new();
                tls.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty());
                tls.send_close_notify().unwrap();
            });
            let conn =
                ClientConnection::new(Arc::new(pki.client_config(suite)), localhost()).unwrap();
            let mut tls = StreamOwned::new(conn, client_tcp);
            // Queued during the handshake, sent right after Finished.
            tls.conn.writer().write_all(&up[..1000]).unwrap();
            tls.write_all(&up[1000..LEN / 2]).unwrap();
            if tls13(suite) {
                tls.conn.refresh_traffic_keys().unwrap();
            }
            tls.write_all(&up[LEN / 2..]).unwrap();
            assert_eq!(read_n(&mut tls, LEN).unwrap(), down, "{suite:?}");
            tls.conn.send_close_notify();
            tls.flush().unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            server.join().unwrap();
            tls.sock.shutdown(Shutdown::Both).unwrap();
        });
        relay.join();
        check_explicit_nonces(suite, &wire.lock().unwrap());
    }
}

fn check_explicit_nonces(suite: SupportedCipherSuite, wire: &Wire) {
    let name = format!("{:?}", suite.suite());
    if tls13(suite) || !name.contains("GCM") {
        return;
    }
    for (direction, bytes) in [
        ("client", &wire.client_to_server),
        ("server", &wire.server_to_client),
    ] {
        let nonces = tls12_explicit_nonces(bytes);
        assert!(nonces.len() > LEN / 16384, "{name} {direction}");
        let unique: HashSet<_> = nonces.iter().collect();
        assert_eq!(
            unique.len(),
            nonces.len(),
            "{name}: {direction} reused a nonce"
        );
    }
}

/// The kernel honours a peer's smaller `record_size_limit` (Linux 6.19:
/// `TLS_TX_MAX_PAYLOAD_LEN`); the userspace server refuses larger records.
#[test]
fn a_smaller_record_size_limit_reaches_the_kernel() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client_tcp, server_tcp) = tcp_pair();
        let up = pattern(50_000, 7);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut config = pki.server_config(suite);
                config.record_size_limit = Some(1000);
                let conn = ServerConnection::new(Arc::new(config)).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                assert_eq!(read_n(&mut tls, up.len()).unwrap(), up, "{suite:?}");
                tls.conn.send_close_notify();
                tls.flush().unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            // TLS 1.3 counts the inner content type byte in the limit.
            let expected = if tls13(suite) { 999 } else { 1000 };
            assert_eq!(
                tls.kernel_connection().max_tx_payload_len(),
                Some(expected),
                "{suite:?}"
            );
            tls.write_all(&up).unwrap();
            // Counted by the records the kernel made, far more than the
            // protocol's largest would have been.
            assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            // Bytes sent past the stream end its count.
            tls.records_sent(0).unwrap();
            assert_eq!(
                tls.unsent().unwrap_err().kind(),
                io::ErrorKind::Unsupported,
                "{suite:?}"
            );
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            server.join().unwrap();
        });
    }
}

/// A peer that closes TCP without `close_notify` is reported as truncation.
#[test]
fn truncation_is_reported() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (client_tcp, server_tcp) = tcp_pair();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
            let mut tls = StreamOwned::new(conn, server_tcp);
            tls.write_all(b"partial").unwrap();
            tls.sock.shutdown(Shutdown::Both).unwrap();
        });
        let mut tls = client_stream(&pki, suite, client_tcp);
        let mut got = Vec::new();
        let err = tls.read_to_end(&mut got).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(got, b"partial");
        server.join().unwrap();
    });
}

/// The connection stops at the peer's `close_notify`: a byte of another
/// record behind it would stay unprocessed for good, so the handover is
/// refused at once instead of waiting for the rest of that record.
#[test]
fn data_after_close_notify_is_refused() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (mut client_tcp, server_tcp) = tcp_pair();
    let (done, wait) = mpsc::channel::<()>();
    let pki = &pki;
    thread::scope(|scope| {
        // Dropped if the test fails, which lets the server go.
        let done = done;
        let server = scope.spawn(move || {
            let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
            let mut tls = StreamOwned::new(conn, server_tcp);
            tls.write_all(b"!").unwrap();
            tls.conn.send_close_notify();
            tls.flush().unwrap();
            // The first byte of another record; the socket stays open.
            tls.sock.write_all(&[0x17]).unwrap();
            let _ = wait.recv();
        });
        let mut conn =
            ClientConnection::new(Arc::new(pki.client_config(suite)), localhost()).unwrap();
        while conn.is_handshaking() || conn.wants_write() {
            conn.complete_io(&mut client_tcp).unwrap();
        }
        // Reads the close_notify and the byte behind it in userspace.
        let mut data = Vec::new();
        loop {
            let state = conn.process_new_packets().unwrap();
            let _ = conn.reader().read_to_end(&mut data);
            if state.peer_has_closed()
                && conn.kernel_handoff_blocker() == Some(KernelHandoffBlocker::UnprocessedInput)
            {
                break;
            }
            assert!(conn.read_tls(&mut client_tcp).unwrap() > 0);
        }
        assert_eq!(data, b"!");

        // A handover that waited for the rest of the record would time out.
        client_tcp
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let Err(HandoffError::Refused { error, .. }) = KtlsStream::new(conn, client_tcp) else {
            panic!("handed over with data after close_notify");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        done.send(()).unwrap();
        server.join().unwrap();
    });
}

/// Without secret extraction nothing is handed over, the socket is left
/// alone, and the connection carries on in userspace. Needs no kernel TLS.
#[test]
fn a_refused_handover_returns_the_connection() {
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (client_tcp, server_tcp) = tcp_pair();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut config = pki.server_config(suite);
            config.enable_secret_extraction = false;
            let conn = ServerConnection::new(Arc::new(config)).unwrap();
            let Err(HandoffError::Refused {
                conn,
                socket,
                received,
                error,
            }) = KtlsStream::new(conn, server_tcp)
            else {
                panic!("handed over without secret extraction");
            };
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(received.is_empty());
            let mut tls = StreamOwned::new(conn, socket);
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).unwrap();
            tls.write_all(&buf).unwrap();
            tls.flush().unwrap();
        });
        let conn = ClientConnection::new(Arc::new(pki.client_config(suite)), localhost()).unwrap();
        let mut tls = StreamOwned::new(conn, client_tcp);
        tls.write_all(b"hello").unwrap();
        assert_eq!(read_n(&mut tls, 5).unwrap(), b"hello");
        server.join().unwrap();
    });
}

/// A non-blocking socket refuses with `WouldBlock` mid-handshake; trying
/// again with what came back (the `tls` ULP already attached) completes
/// the handover.
///
/// The server starts its handshake only after the first refusal: a server
/// that answered at once could, with the client's thread kept off its
/// processor in between, have its whole flight waiting for the client's
/// first read, and nothing would be refused.
#[test]
fn a_refused_handover_can_be_retried() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (client_tcp, server_tcp) = tcp_pair();
    let (refused_tx, refused_rx) = mpsc::channel::<()>();
    let pki = &pki;
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            refused_rx.recv().unwrap();
            let mut tls = server_stream(pki, suite, server_tcp);
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).unwrap();
            tls.write_all(&buf).unwrap();
            tls.send_close_notify().unwrap();
        });
        client_tcp.set_nonblocking(true).unwrap();
        let mut conn =
            ClientConnection::new(Arc::new(pki.client_config(suite)), localhost()).unwrap();
        let mut socket = client_tcp;
        let mut retries = 0;
        let mut tls = loop {
            match KtlsStream::new(conn, socket) {
                Ok(tls) => break tls,
                Err(HandoffError::Refused {
                    conn: c,
                    socket: s,
                    received,
                    error,
                }) => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
                    assert!(received.is_empty());
                    (conn, socket) = (c, s);
                    if retries == 0 {
                        refused_tx.send(()).unwrap();
                    }
                    retries += 1;
                    assert!(retries < 10_000, "no progress");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("{err}"),
            }
        };
        assert!(retries > 0, "the handshake never blocked");
        tls.get_ref().set_nonblocking(false).unwrap();
        tls.write_all(b"hello").unwrap();
        assert_eq!(read_n(&mut tls, 5).unwrap(), b"hello");
        server.join().unwrap();
    });
}

/// On a full non-blocking socket a KeyUpdate waits (with the new transmit
/// keys behind it) and nothing overtakes it: later data goes out under the
/// new keys only after `flush` sent it.
#[test]
fn a_key_update_waits_for_room_on_a_non_blocking_socket() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let Some(suite) = offloadable_suites().into_iter().find(|s| tls13(*s)) else {
        return;
    };
    let (client_tcp, server_tcp) = tcp_pair();
    let (done_tx, done_rx) = mpsc::channel::<usize>();
    let pki = &pki;
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let mut tls = server_stream(pki, suite, server_tcp);
            // Starts reading only once the client's socket is full.
            let total = done_rx.recv().unwrap();
            let got = read_n(&mut tls, total).unwrap();
            assert_eq!(got, pattern(total, 8));
            // Answers the client's KeyUpdate on the way, then replies.
            tls.write_all(b"done").unwrap();
            tls.send_close_notify().unwrap();
        });
        let mut tls = client_stream(pki, suite, client_tcp);
        tls.get_ref().set_nonblocking(true).unwrap();
        let data = pattern(16 << 20, 8);
        let mut sent = 0;
        // Large writes, then small ones, until not even a small record fits.
        for chunk in [usize::MAX, 64] {
            while sent < data.len() {
                let end = data.len().min(sent.saturating_add(chunk));
                match tls.write(&data[sent..end]) {
                    Ok(n) => sent += n,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => panic!("{err}"),
                }
            }
        }
        assert!(sent < data.len(), "the socket never filled");
        // No room: the KeyUpdate waits.
        tls.refresh_traffic_keys().unwrap();
        assert_eq!(
            tls.write(b"x").unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "data must not overtake the waiting KeyUpdate"
        );
        let more = 100_000;
        done_tx.send(sent + more).unwrap();
        loop {
            match tls.flush() {
                Ok(()) => break,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("{err}"),
            }
        }
        tls.get_ref().set_nonblocking(false).unwrap();
        tls.write_all(&data[sent..sent + more]).unwrap();
        assert_eq!(read_n(&mut tls, 4).unwrap(), b"done");
        server.join().unwrap();
    });
}
