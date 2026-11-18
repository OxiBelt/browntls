//! The kernel's zero-copy options on streams handed to the running kernel
//! over loopback TCP: the options are read back as set; unpadded records
//! are promised only to a kernel that can be trusted with the promise
//! (Linux 7.2), and there the stream reads right across control records,
//! new keys and a peer that pads after all.
//!
//! The tests that need kernel TLS are skipped without the `tls` module
//! unless `BROWNTLS_KTLS_REQUIRED=1`; those that need the promise say so
//! and pass on an older kernel.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, mpsc};
use std::thread;

use browntls::client::ClientConnectionData;
use browntls::server::ServerConnectionData;
use browntls::{
    ClientConnection, ProtocolVersion, ServerConnection, StreamOwned, SupportedCipherSuite,
};
use browntls_ktls::KtlsStream;
use common::*;

const LEN: usize = 200_000;

/// What a read's buffer holds before the read.
const MARK: u8 = 0xa5;

/// The most a record adds to a read's buffer.
const RECORD: usize = 16384 + 256;

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

/// One read into `buf`, which must come back holding the bytes read and
/// nothing else of the connection: zeroes for a record's length behind
/// them (where the kernel may have decrypted a record it then did not
/// report), and behind that zeroes (behind a control record the read
/// handled on its way) or what it held before.
fn read_marked(tls: &mut impl Read, buf: &mut [u8]) -> usize {
    buf.fill(MARK);
    let n = tls.read(buf).unwrap();
    let wiped = buf.len().min(n + RECORD);
    assert!(
        buf[n..wiped].iter().all(|byte| *byte == 0),
        "bytes behind the {n} read"
    );
    assert!(
        buf[wiped..].iter().all(|byte| *byte == 0 || *byte == MARK),
        "bytes far behind the {n} read"
    );
    n
}

/// Reads to the peer's `close_notify` with buffers larger and smaller
/// than a record.
fn read_all_marked(tls: &mut impl Read) -> Vec<u8> {
    let mut got = Vec::new();
    let mut large = vec![0; 64 * 1024];
    let mut small = [0; 1000];
    for turn in 0.. {
        let buf = if turn % 4 == 3 {
            &mut small[..]
        } else {
            &mut large[..]
        };
        match read_marked(tls, buf) {
            0 => break,
            n => got.extend_from_slice(&buf[..n]),
        }
    }
    got
}

/// Both options are off after the handover and read back as set. TLS 1.2
/// has no padding to make a promise about, and a kernel before Linux 7.2
/// is not given the promise.
#[test]
fn the_options_are_read_back_as_set() {
    if !kernel_tls() {
        return;
    }
    let promised = no_pad_kernel();
    let pki = Pki::new();
    for suite in offloadable_suites() {
        let (client_tcp, server_tcp) = tcp_pair();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut tls = server_stream(&pki, suite, server_tcp);
                assert_eq!(read_n(&mut tls, 5).unwrap(), b"hello", "{suite:?}");
                tls.write_all(b"world").unwrap();
                let mut rest = Vec::new();
                tls.read_to_end(&mut rest).unwrap();
                tls.send_close_notify().unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);

            assert!(!tls.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
            tls.set_tx_zerocopy_sendfile(true).unwrap();
            assert!(tls.tx_zerocopy_sendfile().unwrap(), "{suite:?}");

            if !tls13(suite) {
                for err in [
                    tls.set_rx_expect_no_pad(true).unwrap_err(),
                    tls.set_rx_expect_no_pad(false).unwrap_err(),
                    tls.rx_expect_no_pad().unwrap_err(),
                ] {
                    assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{suite:?}");
                }
            } else if promised {
                assert!(!tls.rx_expect_no_pad().unwrap(), "{suite:?}");
                tls.set_rx_expect_no_pad(true).unwrap();
                assert!(tls.rx_expect_no_pad().unwrap(), "{suite:?}");
            } else {
                assert!(!tls.rx_expect_no_pad().unwrap(), "{suite:?}");
                let err = tls.set_rx_expect_no_pad(true).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{suite:?}");
                assert!(!tls.rx_expect_no_pad().unwrap(), "{suite:?}");
                // Taking back a promise that was not made is no error.
                tls.set_rx_expect_no_pad(false).unwrap();
            }

            // With the options set the stream works as before.
            tls.write_all(b"hello").unwrap();
            assert_eq!(read_n(&mut tls, 5).unwrap(), b"world", "{suite:?}");

            tls.set_tx_zerocopy_sendfile(false).unwrap();
            assert!(!tls.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
            if tls13(suite) && promised {
                tls.set_rx_expect_no_pad(false).unwrap();
                assert!(!tls.rx_expect_no_pad().unwrap(), "{suite:?}");
            }
            tls.send_close_notify().unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            server.join().unwrap();
        });
    }
}

/// A kernel client that expects unpadded records, against a userspace
/// server that pads none: tickets and a KeyUpdate (records that are not
/// application data, which the kernel decrypts a second time) arrive
/// between the data, the promise stands after the new receive keys, and
/// no read leaves a control record's plaintext in its buffer.
#[test]
fn unpadded_records_are_expected_across_control_records_and_new_keys() {
    if !kernel_tls() || !no_pad_kernel() {
        return;
    }
    let pki = Pki::new();
    let retries = tls_stat("TlsDecryptRetry");
    for suite in offloadable_suites().into_iter().filter(|s| tls13(*s)) {
        let (client_tcp, server_tcp) = tcp_pair();
        let up = pattern(LEN, 11);
        let down = pattern(LEN, 12);
        let (sent, all_sent) = mpsc::channel();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                assert_eq!(read_n(&mut tls, LEN).unwrap(), up, "{suite:?}");
                tls.write_all(&down[..LEN / 2]).unwrap();
                tls.conn.refresh_traffic_keys().unwrap();
                tls.write_all(&down[LEN / 2..]).unwrap();
                tls.conn.send_close_notify();
                tls.flush().unwrap();
                sent.send(()).unwrap();
                let mut rest = Vec::new();
                tls.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty());
                tls.sock.shutdown(Shutdown::Both).unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            tls.set_rx_expect_no_pad(true).unwrap();
            tls.write_all(&up).unwrap();
            // Everything is there to be read: a read finds control records
            // behind the data it returns.
            all_sent.recv().unwrap();
            assert_eq!(read_all_marked(&mut tls), down, "{suite:?}");
            assert!(tls.kernel_connection().tls13_tickets_received() > 0);
            // The server's KeyUpdate brought new receive keys.
            assert!(tls.rx_expect_no_pad().unwrap(), "{suite:?}");
            tls.send_close_notify().unwrap();
            drop(tls);
            server.join().unwrap();
        });
    }
    // The kernel did decrypt into the readers' buffers: it took back at
    // least the KeyUpdates.
    assert!(tls_stat("TlsDecryptRetry") > retries);
}

/// A peer that pads its records after all (handshake, data and KeyUpdate
/// alike) costs the kernel a second decryption and nothing else: the
/// application reads what was sent, in order, and neither padding nor a
/// control record stays in a read's buffer.
#[test]
fn a_peer_that_pads_after_all_is_read_right() {
    if !kernel_tls() || !no_pad_kernel() {
        return;
    }
    let pki = Pki::new();
    let violations = tls_stat("TlsRxNoPadViolation");
    for suite in offloadable_suites().into_iter().filter(|s| tls13(*s)) {
        let (client_tcp, server_tcp) = tcp_pair();
        let up = pattern(LEN, 15);
        let down = pattern(LEN, 16);
        let (sent, all_sent) = mpsc::channel();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let config = pki.server_config(padding_suite(suite));
                let conn = ServerConnection::new(Arc::new(config)).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                assert_eq!(read_n(&mut tls, LEN).unwrap(), up, "{suite:?}");
                // Records of many lengths, most of them padded, with new
                // keys on the way.
                let mut rest = &down[..];
                let mut piece = 1;
                while !rest.is_empty() {
                    let (now, later) = rest.split_at(piece.min(rest.len()));
                    tls.write_all(now).unwrap();
                    if rest.len() > LEN / 2 && later.len() <= LEN / 2 {
                        tls.conn.refresh_traffic_keys().unwrap();
                    }
                    rest = later;
                    piece = piece * 3 % 9001 + 1;
                }
                tls.conn.send_close_notify();
                tls.flush().unwrap();
                sent.send(()).unwrap();
                let mut rest = Vec::new();
                tls.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty());
                tls.sock.shutdown(Shutdown::Both).unwrap();
            });
            // The padded handshake is read in userspace.
            let mut tls = client_stream(&pki, suite, client_tcp);
            tls.set_rx_expect_no_pad(true).unwrap();
            tls.write_all(&up).unwrap();
            // Everything is there to be read, so that a read takes several
            // records, padded ones among them.
            all_sent.recv().unwrap();
            assert_eq!(read_all_marked(&mut tls), down, "{suite:?}");
            assert!(tls.rx_expect_no_pad().unwrap(), "{suite:?}");
            tls.send_close_notify().unwrap();
            drop(tls);
            server.join().unwrap();
        });
    }
    // The kernel saw padded application data.
    assert!(tls_stat("TlsRxNoPadViolation") > violations);
}

/// Both ends in the kernel, both expecting unpadded records, each
/// refreshing its keys: the kernel pads nothing it sends.
#[test]
fn both_kernel_ends_expect_unpadded_records() {
    if !kernel_tls() || !no_pad_kernel() {
        return;
    }
    let pki = Pki::new();
    for suite in offloadable_suites().into_iter().filter(|s| tls13(*s)) {
        let (client_tcp, server_tcp) = tcp_pair();
        let up = pattern(LEN, 13);
        let down = pattern(LEN, 14);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut tls = server_stream(&pki, suite, server_tcp);
                tls.set_rx_expect_no_pad(true).unwrap();
                assert_eq!(read_n(&mut tls, LEN).unwrap(), up, "{suite:?}");
                tls.refresh_traffic_keys().unwrap();
                tls.write_all(&down).unwrap();
                let mut rest = Vec::new();
                tls.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty());
                assert!(tls.rx_expect_no_pad().unwrap(), "{suite:?}");
                tls.send_close_notify().unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            tls.set_rx_expect_no_pad(true).unwrap();
            tls.write_all(&up[..LEN / 2]).unwrap();
            tls.refresh_traffic_keys().unwrap();
            tls.write_all(&up[LEN / 2..]).unwrap();
            assert_eq!(read_n(&mut tls, LEN).unwrap(), down, "{suite:?}");
            assert!(tls.rx_expect_no_pad().unwrap(), "{suite:?}");
            tls.send_close_notify().unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            server.join().unwrap();
        });
    }
}

/// The padding peer of these tests does pad, and browntls reads its
/// records in userspace: what the kernel tests rely on, shown without the
/// kernel.
#[test]
fn the_padding_peer_pads_and_is_understood() {
    let pki = Pki::new();
    for suite in offloadable_suites().into_iter().filter(|s| tls13(*s)) {
        let (client_tcp, server_tcp, wire, relay) = relay();
        let down = pattern(20_000, 17);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let config = pki.server_config(padding_suite(suite));
                let conn = ServerConnection::new(Arc::new(config)).unwrap();
                let mut tls = StreamOwned::new(conn, server_tcp);
                assert_eq!(read_n(&mut tls, 5).unwrap(), b"hello", "{suite:?}");
                for piece in down.chunks(1000) {
                    tls.write_all(piece).unwrap();
                }
                tls.conn.send_close_notify();
                tls.flush().unwrap();
                tls.sock.shutdown(Shutdown::Write).unwrap();
            });
            let config = pki.client_config(suite);
            let conn = ClientConnection::new(Arc::new(config), localhost()).unwrap();
            let mut tls = StreamOwned::new(conn, client_tcp);
            tls.write_all(b"hello").unwrap();
            let mut got = Vec::new();
            tls.read_to_end(&mut got).unwrap();
            assert_eq!(got, down, "{suite:?}");
            tls.sock.shutdown(Shutdown::Write).unwrap();
            server.join().unwrap();
        });
        relay.join();
        // Twenty records of a thousand bytes without padding come to
        // 20 x (5 + 1000 + 1 + 16) bytes; the server sent more.
        let wire = wire.lock().unwrap();
        let mut rest = &wire.server_to_client[..];
        let (mut data_records, mut padded) = (0, 0);
        while rest.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            if rest[0] == 23 && len >= 1017 {
                data_records += 1;
                padded += usize::from(len > 1017);
                assert!(len <= 1017 + MAX_PADDING, "{suite:?}");
            }
            rest = &rest[5 + len..];
        }
        assert_eq!(data_records, 20, "{suite:?}");
        assert!(padded >= 10, "{suite:?}: {padded} padded records");
    }
}
