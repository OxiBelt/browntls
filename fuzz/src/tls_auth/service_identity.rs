//! Exercise the public identity constructors with the generated PKI fixture.

use std::net::UdpSocket;
use std::sync::Arc;

use browntls_core::client::UnbufferedClientConnection;
use browntls_core::pki_types::{DnsName, ServerName};
use browntls_core::server::ParsedCertificate;
use browntls_core::{
    ClientConfig, ClientConnection, ClientServerIdentity, ReferenceIdentifier, RootCertStore,
    ServiceIdentity, dtls, quic,
};

fn config() -> Arc<ClientConfig> {
    crate::init();
    let fixture = crate::tls_config::fixtures::get();
    let mut roots = RootCertStore::empty();
    roots.add(fixture.ca.clone()).expect("fixture CA");
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"example".to_vec()];
    Arc::new(config)
}

fn identity() -> ClientServerIdentity {
    let name = ServerName::try_from("localhost").expect("routing name");
    ClientServerIdentity::new(name, references())
}

fn references() -> ServiceIdentity {
    ServiceIdentity::new(vec![ReferenceIdentifier::Dns(
        DnsName::try_from_ascii("localhost").expect("DNS name"),
    )])
    .expect("reference list")
}

#[test]
fn public_identity_constructors() {
    let config = config();
    let alpn = config.alpn_protocols.clone();
    let initial = ClientConnection::new_with_identity(config.clone(), identity()).expect("TLS");
    assert!(initial.matched_service_identity().is_none());
    ClientConnection::new_with_identity_and_alpn(config.clone(), identity(), alpn.clone())
        .expect("TLS with ALPN");
    UnbufferedClientConnection::new_with_identity(config.clone(), identity())
        .expect("unbuffered TLS");
    UnbufferedClientConnection::new_with_identity_and_alpn(
        config.clone(),
        identity(),
        alpn.clone(),
    )
    .expect("unbuffered TLS with ALPN");
    quic::ClientConnection::new_with_identity(
        config.clone(),
        quic::Version::V1,
        identity(),
        vec![],
    )
    .expect("QUIC");
    quic::ClientConnection::new_with_identity_and_alpn(
        config.clone(),
        quic::Version::V1,
        identity(),
        vec![],
        alpn,
    )
    .expect("QUIC with ALPN");
    dtls::ClientConnection::new_with_identity(config.clone(), identity()).expect("DTLS");
    dtls::ClientConnection::new_with_identity_and_settings(
        config.clone(),
        identity(),
        dtls::Settings::default(),
    )
    .expect("DTLS with settings");

    let socket = || UdpSocket::bind("127.0.0.1:0").expect("UDP socket");
    assert!(dtls::UdpClient::connect_with_identity(config.clone(), identity(), socket()).is_err());
    assert!(
        dtls::UdpClient::connect_with_identity_and_settings(
            config,
            identity(),
            socket(),
            dtls::Settings::default(),
        )
        .is_err()
    );

    let fixture = crate::tls_config::fixtures::get();
    let cert = ParsedCertificate::try_from(&fixture.keys[0].chain[0]).expect("fixture leaf");
    let references = references();
    assert_eq!(
        browntls_core::client::verify_server_identity(&cert, &references).expect("identity"),
        &references.references()[0]
    );
}
