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
fn rfc9525_identity_types_are_reexported_at_the_root() {
    fn takes_client_identity(_: browntls::ClientServerIdentity) {}
    fn takes_service_identity(_: browntls::ServiceIdentity) {}
    fn takes_reference(_: Option<&browntls::ReferenceIdentifier>) {}
    fn takes_uri_id(_: Option<browntls::UriId>) {}
    fn takes_srv_id(_: Option<browntls::SrvId>) {}

    let _ = takes_client_identity;
    let _ = takes_service_identity;
    let _ = takes_reference;
    let _ = takes_uri_id;
    let _ = takes_srv_id;
}

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

#[test]
fn rfc9973_through_the_facade() {
    let pki = Pki::new();
    let key = Arc::new(
        browntls::psk::ExternalPsk::new(
            b"facade-rfc9973".to_vec(),
            vec![42; 32],
            browntls::crypto::hash::HashAlgorithm::SHA256,
        )
        .unwrap(),
    );
    let mut client = pki.client_config();
    client.cert_with_extern_psk = true;
    client.external_psks = vec![key.clone()];
    let mut server = pki.server_config();
    server.require_cert_with_extern_psk = true;
    server.external_psks = Some(Arc::new(vec![key]));
    let mut client = ClientConnection::new(Arc::new(client), localhost()).unwrap();
    let mut acceptor = browntls::server::Acceptor::default();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    acceptor.read_tls(&mut hello.as_slice()).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    assert!(accepted.client_hello().offers_cert_with_extern_psk());
    let mut server = accepted.into_connection(Arc::new(server)).unwrap();

    let mut flight = Vec::new();
    for _ in 0..8 {
        server.write_tls(&mut flight).unwrap();
        client.read_tls(&mut flight.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        flight.clear();
        client.write_tls(&mut flight).unwrap();
        server.read_tls(&mut flight.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        flight.clear();
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(client.negotiated_cert_with_extern_psk());
    assert!(server.negotiated_cert_with_extern_psk());
}

/// `ServerConfig::enable_grease` (RFC 8701 §4.1) is reachable through the
/// root: with it on, the server's CertificateRequest and NewSessionTicket
/// messages carry GREASE values, and a client still authenticates with a
/// certificate and resumes from the tickets.
#[test]
fn server_grease_with_client_authentication_through_the_root() {
    let pki = Pki::new();
    let mut server_config = pki.server_config_with_client_auth();
    server_config.enable_grease = true;
    let server_config = Arc::new(server_config);
    let client_config = Arc::new(pki.client_config_with_cert());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
        let conn = ClientConnection::new(client_config.clone(), localhost()).unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (tcp, _) = listener.accept().unwrap();
                let conn = ServerConnection::new(server_config.clone()).unwrap();
                let mut tls = StreamOwned::new(conn, tcp);
                let mut request = [0u8; 5];
                tls.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"hello");
                let certs = tls.conn.peer_certificates().unwrap().to_vec();
                tls.write_all(b"world").unwrap();
                tls.conn.send_close_notify();
                tls.flush().unwrap();
                certs
            });

            let mut tls = StreamOwned::new(conn, tcp);
            tls.write_all(b"hello").unwrap();
            // Reading to the end takes in the tickets.
            let mut reply = Vec::new();
            tls.read_to_end(&mut reply).unwrap();
            assert_eq!(reply, b"world");
            assert_eq!(tls.conn.handshake_kind(), Some(expected));
            assert_eq!(
                tls.conn.protocol_version(),
                Some(browntls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(server.join().unwrap()[0], pki.client_chain[0]);
        });
    }
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

/// Client certificate URLs (RFC 6066 §5) are configured through the root:
/// the PkiPath helpers, the client's URLs and the server's policy.
#[test]
fn certificate_url_is_nameable() {
    use browntls::certificate_url::{
        CertificateUrl, ClientCertificateUrlPolicy, UrlAndHash, decode_pki_path, encode_pki_path,
    };

    let chain = [browntls::pki_types::CertificateDer::from(vec![0x30, 0x00])];
    let path = encode_pki_path(&chain).unwrap();
    assert_eq!(path, [0x30, 0x02, 0x30, 0x00]);
    assert_eq!(decode_pki_path(&path).unwrap(), chain);
    let entry = UrlAndHash::for_object(
        "http://certs.example/p",
        &path,
        browntls::crypto::native::sha1,
    )
    .unwrap();
    let urls = CertificateUrl::pkipath(entry).unwrap();

    let mut client = Pki::new().client_config();
    client.enable_client_certificate_url = true;
    let mut server = Pki::new().server_config();
    server.client_certificate_url = Some(ClientCertificateUrlPolicy::new(
        browntls::crypto::native::sha1,
    ));
    assert_eq!(urls.entries().len(), 1);
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

/// Certificate Transparency 2.0 (RFC 9162): the TLS side at the root, the
/// PKI side under `pki_types`.
#[test]
fn transparency_is_nameable() {
    let requirements = browntls::transparency::CtV2Requirements::new(
        browntls::revocation::RevocationDigests::native(),
        Vec::new(),
    );
    assert_eq!(requirements.min_verified_scts, 1);
    // §6.3: a `TransItemList` is not empty.
    assert!(browntls::pki_types::transparency::TransItemList::parse(&[0, 0]).is_err());
    let mut config = Pki::new().client_config();
    config.request_transparency_info = true;
}

/// `trusted_ca_keys` (RFC 6066 §6), named through `browntls` only: a TLS 1.2
/// server whose resolver follows the client's list acknowledges it.
#[cfg(feature = "tls12")]
#[test]
fn trusted_ca_keys_through_the_root() {
    use browntls::server::{ResolvesServerCert, ResolvesServerCertUsingTrustedCaKeys};
    use browntls::{ServerConfig, TrustedAuthority};

    let pki = Pki::new();
    let sha1 = browntls::crypto::native::sha1;
    let mut resolver = ResolvesServerCertUsingTrustedCaKeys::new(Arc::new(
        browntls::sign::SingleCertAndKey::from(pki.certified_key()),
    ));
    resolver
        .add_for_root(pki.ca(), sha1, pki.certified_key())
        .unwrap();
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(resolver);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&browntls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let mut client_config = pki.client_config();
    client_config.trusted_ca_keys = Some(vec![TrustedAuthority::x509_name(pki.ca()).unwrap()]);

    let mut client = ClientConnection::new(Arc::new(client_config), localhost()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut &buf[..]).unwrap();
        server.process_new_packets().unwrap();
        buf.clear();
        server.write_tls(&mut buf).unwrap();
        client.read_tls(&mut &buf[..]).unwrap();
        client.process_new_packets().unwrap();
    }
    assert!(client.trusted_ca_keys_acknowledged());
    assert_eq!(
        client.protocol_version(),
        Some(browntls::ProtocolVersion::TLSv1_2)
    );
}
