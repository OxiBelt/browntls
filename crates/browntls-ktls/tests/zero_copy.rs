//! The kernel's zero-copy option for `sendfile` on streams handed to the
//! running kernel over loopback TCP: it is off after the handover, read
//! back as set, and the stream works as before with it.
//!
//! The tests that need kernel TLS are skipped without the `tls` module
//! unless `BROWNTLS_KTLS_REQUIRED=1`.

#![cfg(all(target_os = "linux", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

use browntls::client::ClientConnectionData;
use browntls::server::ServerConnectionData;
use browntls::{ClientConnection, ServerConnection, SupportedCipherSuite};
use browntls_ktls::KtlsStream;
use common::*;

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

/// The option is off after the handover, read back as set, and can be
/// taken back; data passes with it set (the kernel encrypts in software
/// here, where the option changes nothing).
#[test]
fn the_option_is_read_back_as_set() {
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

            tls.write_all(b"hello").unwrap();
            assert_eq!(read_n(&mut tls, 5).unwrap(), b"world", "{suite:?}");

            tls.set_tx_zerocopy_sendfile(false).unwrap();
            assert!(!tls.tx_zerocopy_sendfile().unwrap(), "{suite:?}");
            tls.send_close_notify().unwrap();
            let mut rest = Vec::new();
            tls.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
            server.join().unwrap();
        });
    }
}
