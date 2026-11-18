//! The kernel's zero-copy options on streams handed to the running kernel
//! over loopback TCP: the options are read back as set, a TLS 1.3 stream
//! that expects unpadded records keeps reading across control records and
//! new keys, and TLS 1.2 refuses the promise it has no use for.
//!
//! The tests that need kernel TLS are skipped without the `tls` module
//! unless `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::thread;

use browntls::client::ClientConnectionData;
use browntls::server::ServerConnectionData;
use browntls::{
    ClientConnection, ProtocolVersion, ServerConnection, StreamOwned, SupportedCipherSuite,
};
use browntls_ktls::KtlsStream;
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

/// The kernel's count of records it decrypted a second time, if it keeps
/// one: for the log only, since other connections count there too.
fn decrypt_retries() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/net/tls_stat").ok()?;
    stat.lines()
        .find_map(|line| line.strip_prefix("TlsDecryptRetry"))
        .and_then(|count| count.trim().parse().ok())
}

/// Both options are off after the handover, read back as set, and can be
/// taken back. TLS 1.2 has no padding to make a promise about.
#[test]
fn the_options_are_read_back_as_set() {
    if !kernel_tls() {
        return;
    }
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

            if tls13(suite) {
                assert!(!tls.rx_expect_no_pad().unwrap(), "{suite:?}");
                tls.set_rx_expect_no_pad(true).unwrap();
                assert!(tls.rx_expect_no_pad().unwrap(), "{suite:?}");
            } else {
                for err in [
                    tls.set_rx_expect_no_pad(true).unwrap_err(),
                    tls.set_rx_expect_no_pad(false).unwrap_err(),
                    tls.rx_expect_no_pad().unwrap_err(),
                ] {
                    assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{suite:?}");
                }
            }

            // With both set the stream works as before.
            tls.write_all(b"hello").unwrap();
            assert_eq!(read_n(&mut tls, 5).unwrap(), b"world", "{suite:?}");

            tls.set_tx_zerocopy_sendfile(false).unwrap();
            assert!(!tls.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
            if tls13(suite) {
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
/// server: tickets and a KeyUpdate (records that are not application data,
/// which the kernel decrypts a second time) arrive between data read into
/// buffers larger and smaller than a record, and the promise stands after
/// the new receive keys.
#[test]
fn unpadded_records_are_expected_across_control_records_and_new_keys() {
    if !kernel_tls() {
        return;
    }
    let pki = Pki::new();
    let before = decrypt_retries();
    for suite in offloadable_suites().into_iter().filter(|s| tls13(*s)) {
        let (client_tcp, server_tcp) = tcp_pair();
        let up = pattern(LEN, 11);
        let down = pattern(LEN, 12);
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
                let mut rest = Vec::new();
                tls.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty());
                tls.sock.shutdown(Shutdown::Both).unwrap();
            });
            let mut tls = client_stream(&pki, suite, client_tcp);
            tls.set_rx_expect_no_pad(true).unwrap();
            tls.write_all(&up).unwrap();

            // Room for whole records first, then less than one.
            let mut got = Vec::new();
            let mut large = vec![0; 64 * 1024];
            while got.len() < LEN / 4 {
                let n = tls.read(&mut large).unwrap();
                assert_ne!(n, 0, "{suite:?}");
                got.extend_from_slice(&large[..n]);
            }
            let mut small = [0; 1000];
            loop {
                let n = tls.read(&mut small).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&small[..n]);
            }
            assert_eq!(got, down, "{suite:?}");
            assert!(tls.kernel_connection().tls13_tickets_received() > 0);
            // The server's KeyUpdate brought new receive keys.
            assert!(tls.rx_expect_no_pad().unwrap(), "{suite:?}");
            tls.send_close_notify().unwrap();
            drop(tls);
            server.join().unwrap();
        });
    }
    if let (Some(before), Some(after)) = (before, decrypt_retries()) {
        eprintln!(
            "TlsDecryptRetry rose by {} (all connections)",
            after - before
        );
    }
}

/// Both ends in the kernel, both expecting unpadded records, each
/// refreshing its keys: the kernel pads nothing it sends.
#[test]
fn both_kernel_ends_expect_unpadded_records() {
    if !kernel_tls() {
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
