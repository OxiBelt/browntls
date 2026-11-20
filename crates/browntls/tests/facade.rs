//! The crate root is `browntls-core`: a handshake and application data
//! between a client and a server that name every item through `browntls`,
//! and the items each feature of this crate must make nameable.
//!
//! A feature of this crate that failed to turn on the feature of the same
//! name in `browntls-core` would leave the items below undefined, so this
//! file would not compile. `tests/scripts/check_facade_features.py` checks
//! the manifests themselves.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use browntls::{ClientConnection, HandshakeKind, ServerConnection, StreamOwned};
use common::*;

#[test]
fn handshake_and_data_through_the_root() {
    let pki = Pki::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Built before either side blocks on the socket.
    let server_config = Arc::new(pki.server_config());
    let conn = ClientConnection::new(Arc::new(pki.client_config()), localhost()).unwrap();
    // The listener's backlog takes the connection before `accept` runs.
    let tcp = TcpStream::connect(addr).unwrap();

    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (tcp, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(server_config).unwrap();
            let mut tls = StreamOwned::new(conn, tcp);
            let mut request = [0u8; 5];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"hello");
            tls.write_all(b"world").unwrap();
            tls.conn.send_close_notify();
            tls.flush().unwrap();
            tls.conn.protocol_version()
        });

        let mut tls = StreamOwned::new(conn, tcp);
        tls.write_all(b"hello").unwrap();
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"world");
        assert_eq!(tls.conn.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(
            tls.conn.protocol_version(),
            Some(browntls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(server.join().unwrap(), tls.conn.protocol_version());
    });
}

/// `native`: the built-in provider, which the configurations above were
/// built with.
#[test]
fn native_provider_is_nameable() {
    let provider = browntls::crypto::native::default_provider();
    assert!(!provider.cipher_suites.is_empty());
    // `prefer-post-quantum` decides which group leads the default list.
    let first = provider.kx_groups[0].name();
    #[cfg(feature = "prefer-post-quantum")]
    assert_eq!(first, browntls::NamedGroup::X25519MLKEM768);
    #[cfg(not(feature = "prefer-post-quantum"))]
    assert_eq!(first, browntls::NamedGroup::X25519);
}

#[cfg(feature = "rustcrypto")]
#[test]
fn rustcrypto_provider_is_nameable() {
    let provider = browntls::crypto::rustcrypto::default_provider();
    assert!(!provider.cipher_suites.is_empty());
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_is_nameable() {
    assert_eq!(
        browntls::version::TLS12.version,
        browntls::ProtocolVersion::TLSv1_2
    );
    assert!(browntls::ALL_VERSIONS.contains(&&browntls::version::TLS12));
}

#[cfg(not(feature = "tls12"))]
#[test]
fn tls12_is_absent() {
    assert_eq!(browntls::ALL_VERSIONS, &[&browntls::version::TLS13]);
}

/// `zlib`, `brotli`, `zstd`: each enabled algorithm joins the default
/// certificate compressors.
#[test]
fn certificate_compressors_follow_the_features() {
    use browntls::CertificateCompressionAlgorithm as Alg;

    let enabled: Vec<Alg> = browntls::compress::default_cert_compressors()
        .iter()
        .map(|c| c.algorithm())
        .collect();
    assert_eq!(enabled.contains(&Alg::Zlib), cfg!(feature = "zlib"));
    assert_eq!(enabled.contains(&Alg::Brotli), cfg!(feature = "brotli"));
    assert_eq!(enabled.contains(&Alg::Zstd), cfg!(feature = "zstd"));
}
