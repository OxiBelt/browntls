//! `KtlsStream::sendfile` against the running kernel over loopback TCP: a
//! file sent between writes and key updates to a userspace peer that
//! checks every record, in the small records a peer asked for, its ends
//! (the end of the file, a closed connection, a descriptor `sendfile`
//! cannot read), and through a full non-blocking socket.
//!
//! The tests that need kernel TLS are skipped without the `tls` module
//! unless `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use browntls::client::ClientConnectionData;
use browntls::server::ServerConnectionData;
use browntls::{
    ClientConnection, ProtocolVersion, ServerConnection, SideData, StreamOwned,
    SupportedCipherSuite,
};
use browntls_ktls::KtlsStream;
use common::*;

/// Not a multiple of the record or the page size.
const LEN: usize = 300_007;
const LIMIT: Duration = Duration::from_secs(60);

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

/// Sends `file[from..to]` on a blocking socket, after each call of which
/// the kernel holds nothing back.
fn sendfile_all<S: AsFd, Data: SideData>(
    tls: &mut KtlsStream<S, Data>,
    file: &std::fs::File,
    from: usize,
    to: usize,
) {
    let mut offset = from;
    while offset < to {
        let sent = tls.sendfile(file, offset as u64, to - offset).unwrap();
        assert_ne!(sent, 0, "the file ended at {offset}");
        assert!(sent <= to - offset);
        assert_eq!(tls.unsent().unwrap(), 0, "after {sent} bytes from {offset}");
        offset += sent;
    }
}

/// A kernel client sends a file to a userspace server, between writes and
/// with a key refresh in the middle: every byte arrives in order, in
/// records the userspace end accepts, and the kernel's counters agree
/// with the stream's to the byte after every call.
#[test]
fn a_file_is_sent_for_every_suite() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client_tcp, server_tcp) = tcp_pair();
        let contents = pattern(LEN, 31);
        let file = temp_file(&contents);
        let mut expected = b"before".to_vec();
        expected.extend_from_slice(&contents[1..]);
        expected.extend_from_slice(b"after");
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                let mut got = Vec::new();
                tls.read_to_end(&mut got).unwrap();
                assert!(got == expected, "{suite:?}: {} bytes", got.len());
                tls.conn.send_close_notify();
                tls.flush().unwrap();
                tls.sock.shutdown(Shutdown::Both).unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            assert_eq!(tls.sendfile(&file, 0, 0).unwrap(), 0, "{suite:?}");
            tls.write_all(b"before").unwrap();
            // From an offset that is not page aligned.
            sendfile_all(&mut tls, &file, 1, LEN / 2);
            if tls13(suite) {
                tls.refresh_traffic_keys().unwrap();
            }
            // More than the file has left: the rest of it is sent, then
            // nothing.
            let mut offset = LEN / 2;
            while offset < LEN {
                let sent = tls.sendfile(&file, offset as u64, 4 * LEN).unwrap();
                assert!(sent != 0 && sent <= LEN - offset, "{suite:?}: {sent}");
                assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
                offset += sent;
            }
            assert_eq!(tls.sendfile(&file, LEN as u64, 100).unwrap(), 0);
            assert_eq!(tls.sendfile(&file, 2 * LEN as u64, 100).unwrap(), 0);
            tls.write_all(b"after").unwrap();
            assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
            tls.send_close_notify().unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            server.join().unwrap();
        });
    }
}

/// The records a file makes on the wire, seen by a relay: at least as many
/// as its bytes need, and possibly more, since the kernel may close a
/// record wherever it stops reading the file for a moment. (That is why
/// the stream counts them by the kernel's own number; how many there are
/// is logged, not required.)
#[test]
fn the_records_of_a_file_are_seen_on_the_wire() {
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
        let (client_tcp, server_tcp, wire, relay) = relay();
        let contents = pattern(2_000_003, 34);
        let file = temp_file(&contents);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                let mut got = Vec::new();
                tls.read_to_end(&mut got).unwrap();
                assert!(got == contents[1..], "{suite:?}: {} bytes", got.len());
                tls.conn.send_close_notify();
                tls.flush().unwrap();
                tls.sock.shutdown(Shutdown::Both).unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            sendfile_all(&mut tls, &file, 1, contents.len());
            tls.send_close_notify().unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            drop(tls);
            server.join().unwrap();
        });
        relay.join();
        // Records of more than a kilobyte are the file's (the handshake
        // and the alert are shorter), but for a last one that may be small.
        let wire = wire.lock().unwrap();
        let mut rest = &wire.client_to_server[..];
        let (mut records, mut short) = (0, 0);
        while rest.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            if rest[0] == 23 && len > 1024 {
                records += 1;
                short += usize::from(len < 16384);
            }
            rest = rest.get(5 + len..).unwrap_or_default();
        }
        let needed = (contents.len() - 1).div_ceil(16384);
        eprintln!(
            "{:?}: {} bytes of a file went out in {records} records ({short} not full); \
             the bytes alone need {needed}",
            suite.suite(),
            contents.len() - 1,
        );
        assert!(records + 1 >= needed, "{suite:?}: {records} records");
    }
}

/// A file goes out in the small records a peer asked for (Linux 6.18):
/// the userspace server refuses larger ones.
#[test]
fn a_file_is_sent_in_the_records_the_peer_asked_for() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client_tcp, server_tcp) = tcp_pair();
        let contents = pattern(100_003, 32);
        let file = temp_file(&contents);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut config = pki.server_config(suite);
                config.record_size_limit = Some(1000);
                let conn = ServerConnection::new(Arc::new(config)).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                let got = read_n(&mut tls, contents.len()).unwrap();
                assert!(got == contents, "{suite:?}");
                tls.conn.send_close_notify();
                tls.flush().unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            let max = if tls13(suite) { 999 } else { 1000 };
            let mut offset = 0;
            while offset < contents.len() {
                let rest = contents.len() - offset;
                let sent = tls.sendfile(&file, offset as u64, rest).unwrap();
                // One call stays within 64 records.
                assert!(sent != 0 && sent <= 64 * max, "{suite:?}: {sent}");
                assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
                offset += sent;
            }
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            server.join().unwrap();
        });
    }
}

/// What `sendfile` cannot read is an error that leaves the stream as it
/// was, and nothing is sent once the stream has said goodbye.
#[test]
fn errors_leave_the_stream_usable_and_a_closed_stream_sends_nothing() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let suite = offloadable_suites()[0];
    let (client_tcp, server_tcp) = tcp_pair();
    let file = temp_file(b"contents");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut tls = server_stream(&pki, suite, server_tcp);
            let mut got = Vec::new();
            tls.read_to_end(&mut got).unwrap();
            assert_eq!(got, b"contents and more");
            tls.send_close_notify().unwrap();
        });
        let mut tls = client_stream(&pki, suite, client_tcp);
        // A socket is nothing `sendfile` reads from.
        let (not_a_file, _peer) = tcp_pair();
        let err = tls.sendfile(&not_a_file, 0, 100).unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::WouldBlock, "{err}");
        // An offset the kernel's signed type cannot hold.
        let err = tls.sendfile(&file, u64::MAX, 100).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(tls.unsent().unwrap(), 0);

        assert_eq!(tls.sendfile(&file, 0, 100).unwrap(), 8);
        tls.write_all(b" and more").unwrap();
        tls.send_close_notify().unwrap();
        let err = tls.sendfile(&file, 0, 100).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let mut rest = Vec::new();
        tls.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        server.join().unwrap();
    });
}

/// A non-blocking socket whose peer does not read takes part of a file
/// and then reports no room. Whatever the kernel holds of it then (records
/// TCP had no room for, bytes in a record not yet closed) arrives once the
/// rest is sent, and the count of it comes down to zero.
#[test]
fn a_full_socket_takes_part_of_a_file() {
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
        let (client_tcp, server_tcp) = tcp_pair();
        let contents = pattern(48 << 20, 33);
        let file = temp_file(&contents);
        let (sent_first, tell_first) = std::sync::mpsc::channel::<usize>();
        thread::scope(|scope| {
            let (pki, contents) = (&pki, &contents);
            let server = scope.spawn(move || {
                let mut tls = server_stream(pki, suite, server_tcp);
                // What the client got rid of before it found no room: read
                // until nothing comes for a while.
                let first = tell_first.recv().unwrap();
                tls.get_ref()
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let mut got = Vec::new();
                let mut buf = vec![0; 1 << 16];
                loop {
                    match tls.read(&mut buf) {
                        Ok(0) => panic!("closed early"),
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) => panic!("{err}"),
                    }
                    if got.len() >= first {
                        break;
                    }
                }
                eprintln!(
                    "{:?}: {} of the first {first} bytes arrived before more was sent",
                    suite.suite(),
                    got.len()
                );
                tls.get_ref().set_read_timeout(Some(LIMIT)).unwrap();
                tls.read_to_end(&mut got).unwrap();
                assert!(got == contents[1..], "{suite:?}: {} bytes", got.len());
                tls.send_close_notify().unwrap();
            });
            let mut tls = client_stream(pki, suite, client_tcp);
            tls.get_ref().set_nonblocking(true).unwrap();
            let mut offset = 1;
            let err = loop {
                match tls.sendfile(&file, offset as u64, contents.len() - offset) {
                    Ok(sent) => {
                        assert_ne!(sent, 0);
                        offset += sent;
                        assert!(offset < contents.len(), "the socket took the whole file");
                    }
                    Err(err) => break err,
                }
            };
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock, "{suite:?}");
            eprintln!(
                "{:?}: no room after {} bytes, the kernel holds {} bytes of records",
                suite.suite(),
                offset - 1,
                tls.unsent().unwrap()
            );
            sent_first.send(offset - 1).unwrap();
            // The reader has gone on when it reads the rest.
            let start = Instant::now();
            while offset < contents.len() {
                match tls.sendfile(&file, offset as u64, contents.len() - offset) {
                    Ok(sent) => {
                        assert_ne!(sent, 0);
                        offset += sent;
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        assert!(start.elapsed() < LIMIT, "no room for {LIMIT:?}");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(err) => panic!("{err}"),
                }
            }
            // The whole count went through at the end, so every record is
            // closed and the kernel sends what it holds as TCP takes it.
            while tls.unsent().unwrap() != 0 {
                assert!(start.elapsed() < LIMIT, "the kernel kept records back");
                thread::sleep(Duration::from_millis(1));
            }
            loop {
                match tls.send_close_notify().and_then(|()| tls.flush()) {
                    Ok(()) => break,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(err) => panic!("{err}"),
                }
            }
            while tls.unsent().unwrap() != 0 {
                assert!(start.elapsed() < LIMIT, "the kernel kept the alert back");
                thread::sleep(Duration::from_millis(1));
            }
            tls.get_ref().set_nonblocking(false).unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            server.join().unwrap();
        });
    }
}
