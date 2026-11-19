//! `KtlsStream::sendfile` against the running kernel over loopback TCP: a
//! file sent between writes and key updates to a userspace peer that
//! checks every record, in the small records a peer asked for, its ends
//! (the end of the file, a closed connection, a descriptor that is no
//! regular file), counted against the confidentiality limit, and through a
//! full non-blocking socket.
//!
//! The tests that need kernel TLS are skipped without the `tls` module
//! unless `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsFd;
use std::sync::{Arc, mpsc};
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

/// The records a file makes on the wire, seen by a relay: on a blocking
/// socket every call sends all it was asked for in full records and
/// closes the last one, so the records are those the bytes of each call
/// need, with the default record size and with the small one a peer asked
/// for.
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
    let cases = chosen
        .into_iter()
        .flatten()
        .flat_map(|suite| [(suite, None), (suite, Some(1000))]);
    for (suite, limit) in cases {
        // The most plaintext in a record: TLS 1.3 counts the content type
        // byte in the peer's limit.
        let max = match limit {
            Some(limit) => usize::from(limit) - usize::from(tls13(suite)),
            None => 16384,
        };
        let (client_tcp, server_tcp, wire, relay) = relay();
        let contents = pattern(2_000_003, 34);
        let file = temp_file(&contents);
        let mut needed = 0;
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut config = pki.server_config(suite);
                config.record_size_limit = limit;
                let conn = ServerConnection::new(Arc::new(config)).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                let mut got = Vec::new();
                tls.read_to_end(&mut got).unwrap();
                assert!(got == contents[1..], "{suite:?}: {} bytes", got.len());
                tls.conn.send_close_notify();
                tls.flush().unwrap();
                tls.sock.shutdown(Shutdown::Both).unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            let mut offset = 1;
            while offset < contents.len() {
                let rest = contents.len() - offset;
                let sent = tls.sendfile(&file, offset as u64, rest).unwrap();
                assert!(sent != 0 && sent <= rest, "{suite:?}: {sent}");
                assert_eq!(tls.unsent().unwrap(), 0, "{suite:?}");
                needed += sent.div_ceil(max);
                offset += sent;
            }
            tls.send_close_notify().unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            drop(tls);
            server.join().unwrap();
        });
        relay.join();
        // Application data records of more than 200 bytes are the file's
        // (the handshake's and the alert are shorter), but for a last one
        // that may be small.
        let wire = wire.lock().unwrap();
        let mut rest = &wire.client_to_server[..];
        let (mut records, mut short) = (0, 0);
        while rest.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            if rest[0] == 23 && len > 200 {
                records += 1;
                short += usize::from(len < max);
            }
            rest = rest.get(5 + len..).unwrap_or_default();
        }
        eprintln!(
            "{:?}, record limit {limit:?}: {} bytes of a file went out in {records} records \
             ({short} not full)",
            suite.suite(),
            contents.len() - 1,
        );
        assert!(
            records == needed || records + 1 == needed,
            "{suite:?}, record limit {limit:?}: {records} records where the calls need {needed}"
        );
    }
}

/// The records of a file count against the cipher suite's confidentiality
/// limit: with keys that last for 100 records, a file of 450 makes the
/// stream send a KeyUpdate on the way, again and again, and the userspace
/// peer reads the whole file under the keys that follow.
#[test]
fn the_records_of_a_file_count_against_the_confidentiality_limit() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let Some(suite) = offloadable_suites().into_iter().find(|s| tls13(*s)) else {
        return;
    };
    let (client_tcp, server_tcp, wire, relay) = relay();
    let contents = pattern(450 * 16384, 35);
    let file = temp_file(&contents);
    let mut calls = 0;
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
            let mut tls = StreamOwned::new(conn, server_tcp);
            let mut got = Vec::new();
            tls.read_to_end(&mut got).unwrap();
            assert!(got == contents, "{} bytes", got.len());
            tls.conn.send_close_notify();
            tls.flush().unwrap();
            tls.sock.shutdown(Shutdown::Both).unwrap();
        });
        let config = pki.client_config(limited_suite(suite, 100));
        let conn = ClientConnection::new(Arc::new(config), localhost()).unwrap();
        let mut tls = KtlsStream::new(conn, client_tcp).unwrap();
        let mut offset = 0;
        while offset < contents.len() {
            let rest = contents.len() - offset;
            offset += tls.sendfile(&file, offset as u64, rest).unwrap();
            calls += 1;
        }
        tls.send_close_notify().unwrap();
        let mut rest = Vec::new();
        tls.read_to_end(&mut rest).unwrap();
        drop(tls);
        server.join().unwrap();
    });
    relay.join();
    // A KeyUpdate is a record of 22 bytes: five of the message, the
    // content type and the tag. Nothing else the client sends is.
    let wire = wire.lock().unwrap();
    let mut rest = &wire.client_to_server[..];
    let mut key_updates = 0;
    while rest.len() >= 5 {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        key_updates += usize::from(rest[0] == 23 && len == 22);
        rest = rest.get(5 + len..).unwrap_or_default();
    }
    eprintln!("450 records in {calls} calls: {key_updates} KeyUpdates");
    // One call sends 64 records and counts 65: every second call passes
    // the limit.
    assert!(calls >= 7, "{calls} calls");
    assert!(
        (3..=calls).contains(&key_updates),
        "{key_updates} KeyUpdates in {calls} calls"
    );
}

/// A file goes out in the small records a peer asked for (Linux 6.19):
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

/// What is no regular file is refused before the kernel is asked, an
/// error leaves the stream as it was, and nothing is sent once the stream
/// has said goodbye.
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
        // Only a regular file has a length to stay within.
        let (socket, _peer) = tcp_pair();
        let err = tls.sendfile(&socket, 0, 100).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        let directory = std::fs::File::open(std::env::temp_dir()).unwrap();
        let err = tls.sendfile(&directory, 0, 100).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        // Behind the end of the file there is nothing, however far.
        assert_eq!(tls.sendfile(&file, 9, 100).unwrap(), 0);
        assert_eq!(tls.sendfile(&file, u64::MAX, 100).unwrap(), 0);
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
/// rest is sent, and the count of it comes down to zero. With the small
/// records a peer asked for, the pieces the kernel takes the file in do
/// not end where records do. How much of the first part arrives before
/// more is sent is logged, not required.
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
    let cases = chosen
        .into_iter()
        .flatten()
        .flat_map(|suite| [(suite, None), (suite, Some(1000))]);
    for (suite, limit) in cases {
        let (client_tcp, server_tcp) = tcp_pair();
        let contents = pattern(16 << 20, 33);
        let file = temp_file(&contents);
        let (sent_first, first_sent) = mpsc::channel::<usize>();
        let (arrived_first, first_arrived) = mpsc::channel::<usize>();
        thread::scope(|scope| {
            let (pki, contents) = (&pki, &contents);
            let server = scope.spawn(move || {
                let mut config = pki.server_config(suite);
                config.record_size_limit = limit;
                let conn = ServerConnection::new(Arc::new(config)).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                while tls.conn.is_handshaking() || tls.conn.wants_write() {
                    tls.conn.complete_io(&mut tls.sock).unwrap();
                }
                // What the client got rid of before it found no room: read
                // it, and no more, until nothing comes for a while.
                let first = first_sent.recv().unwrap();
                let pause = Some(Duration::from_millis(500));
                tls.sock.set_read_timeout(pause).unwrap();
                let mut got = vec![0; first];
                let mut arrived = 0;
                while arrived < first {
                    match tls.read(&mut got[arrived..]) {
                        Ok(0) => panic!("closed early"),
                        Ok(n) => arrived += n,
                        Err(err)
                            if matches!(
                                err.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            break;
                        }
                        Err(err) => panic!("{err}"),
                    }
                }
                got.truncate(arrived);
                arrived_first.send(arrived).unwrap();
                tls.sock.set_read_timeout(Some(LIMIT)).unwrap();
                tls.read_to_end(&mut got).unwrap();
                assert!(got == contents[1..], "{suite:?}: {} bytes", got.len());
                tls.conn.send_close_notify();
                tls.flush().unwrap();
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
            let first = offset - 1;
            let held = tls.unsent().unwrap();
            sent_first.send(first).unwrap();
            let arrived = first_arrived.recv().unwrap();
            eprintln!(
                "{:?}, record limit {limit:?}: no room after {first} bytes, of which the \
                 kernel held {held} bytes of records; {arrived} arrived before more was \
                 sent, {} bytes of records still held",
                suite.suite(),
                tls.unsent().unwrap()
            );
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
