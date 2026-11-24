//! `browntls::ktls` is `browntls-ktls`: a client named through `browntls`
//! alone hands its connection to the running kernel over loopback TCP.
//!
//! Without the kernel's `tls` module the handover must return the
//! connection and the socket unharmed, and the test goes on in userspace,
//! unless `BROWNTLS_KTLS_REQUIRED=1` makes the missing module a failure.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use browntls::ktls::{HandoffError, KtlsStream};
use browntls::{ClientConnection, ServerConnection, StreamOwned};
use common::*;

/// Whether the kernel has the `tls` upper layer protocol loaded.
fn kernel_tls() -> bool {
    let loaded = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp")
        .is_ok_and(|ulps| ulps.split_whitespace().any(|ulp| ulp == "tls"));
    if !loaded {
        assert!(
            std::env::var_os("BROWNTLS_KTLS_REQUIRED").is_none_or(|v| v != "1"),
            "BROWNTLS_KTLS_REQUIRED=1 but the kernel has no `tls` ULP (sudo modprobe tls)"
        );
    }
    loaded
}

#[test]
fn client_hands_its_connection_to_the_kernel() {
    let pki = Pki::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Built before either side blocks on the socket.
    let server_config = pki.server_config();
    let mut client_config = pki.client_config();
    #[cfg(feature = "zstd")]
    let (server_config, probe) = zstd_server(server_config, &mut client_config);
    let server_config = Arc::new(server_config);
    client_config.enable_secret_extraction = true;
    let identity = browntls::ClientServerIdentity::new(
        browntls::pki_types::ServerName::try_from("localhost").unwrap(),
        browntls::ServiceIdentity::new(vec![browntls::ReferenceIdentifier::Dns(
            browntls::pki_types::DnsName::try_from("localhost")
                .unwrap()
                .to_owned(),
        )])
        .unwrap(),
    );
    let conn = ClientConnection::new_with_identity(Arc::new(client_config), identity).unwrap();
    // The listener's backlog takes the connection before `accept` runs.
    let tcp = TcpStream::connect(addr).unwrap();

    thread::scope(|scope| {
        // A userspace server: only the client side is under test.
        scope.spawn(|| {
            let (tcp, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(server_config).unwrap();
            let mut tls = StreamOwned::new(conn, tcp);
            let mut request = [0u8; 5];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"hello");
            tls.write_all(b"world").unwrap();
            tls.conn.send_close_notify();
            tls.flush().unwrap();
        });

        let mut reply = Vec::new();
        match KtlsStream::new(conn, tcp) {
            // An accepted handover is itself the proof of kernel TLS (the
            // probe below cannot see it from every network namespace).
            Ok(mut tls) => {
                assert_eq!(
                    tls.kernel_connection().matched_service_identity(),
                    Some(&browntls::ReferenceIdentifier::Dns(
                        browntls::pki_types::DnsName::try_from("localhost")
                            .unwrap()
                            .to_owned()
                    ))
                );
                tls.write_all(b"hello").unwrap();
                tls.read_to_end(&mut reply).unwrap();
            }
            Err(HandoffError::Refused {
                conn,
                socket,
                received,
                error,
            }) => {
                assert!(!kernel_tls(), "refused with the `tls` module: {error}");
                eprintln!("no kernel TLS ({error}): going on in userspace");
                assert!(received.is_empty());
                let mut tls = StreamOwned::new(conn, socket);
                tls.write_all(b"hello").unwrap();
                tls.read_to_end(&mut reply).unwrap();
            }
            Err(HandoffError::Failed(error)) => panic!("handover failed: {error}"),
        }
        assert_eq!(reply, b"world");
        #[cfg(feature = "zstd")]
        assert_eq!(probe.count(), 1);
    });
}

#[test]
fn facade_blocking_adapter_hands_off_each_hybrid_group() {
    if !kernel_tls() {
        return;
    }
    for (expected, provider) in hybrid_providers() {
        let pki = Pki::new();
        let provider = Arc::new(provider);
        let mut client_config = pki.client_config_with_provider(provider.clone());
        client_config.enable_secret_extraction = true;
        let client_config = Arc::new(client_config);
        let server_config = Arc::new(pki.server_config_with_provider(provider));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let tcp = TcpStream::connect(address).unwrap();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (socket, _) = listener.accept().unwrap();
                let connection = ServerConnection::new(server_config).unwrap();
                let mut stream = StreamOwned::new(connection, socket);
                let mut request = [0; 6];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"hybrid");
                assert_eq!(
                    stream.conn.negotiated_key_exchange_group().unwrap().name(),
                    expected,
                    "{expected:?} facade kTLS peer"
                );
                stream.write_all(b"passed").unwrap();
                stream.conn.send_close_notify();
                stream.flush().unwrap();
            });
            let connection = ClientConnection::new(client_config, localhost()).unwrap();
            let mut tls = KtlsStream::new(connection, tcp).unwrap();
            tls.write_all(b"hybrid").unwrap();
            let mut reply = [0; 6];
            tls.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"passed");
            server.join().unwrap();
        });
    }
}

/// `native` reaches `browntls-ktls`: its load-aware routing exists.
#[test]
fn routing_module_follows_the_native_feature() {
    let _: fn() -> std::io::Result<()> = browntls::ktls::routing::activate;
}
