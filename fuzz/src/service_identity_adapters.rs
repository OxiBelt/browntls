//! Exercise the public Tokio identity entry points with the fuzz fixture.

use std::sync::Arc;

use browntls_core::pki_types::{DnsName, ServerName};
use browntls_core::{
    ClientConfig, ClientServerIdentity, ReferenceIdentifier, RootCertStore, ServiceIdentity,
};
use browntls_tokio::{TlsConnector, dtls, unbuffered};
use tokio::io::duplex;
use tokio::net::UdpSocket;

fn identity() -> ClientServerIdentity {
    let route = ServerName::try_from("localhost").expect("routing name");
    let name = DnsName::try_from_ascii("localhost").expect("reference name");
    let references = ServiceIdentity::new(vec![ReferenceIdentifier::Dns(name)]).expect("policy");
    ClientServerIdentity::new(route, references)
}

#[test]
fn public_adapter_identity_entry_points() {
    crate::init();
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(config.clone());
    let unbuffered = unbuffered::TlsConnector::from(config.clone());
    let stream = || duplex(8).0;
    let alpn = || vec![b"example".to_vec()];

    drop(connector.connect_with_identity(identity(), stream()));
    drop(connector.connect_with_identity_and_callback(identity(), stream(), |_| {}));
    drop(
        connector
            .with_alpn(alpn())
            .connect_with_identity(identity(), stream()),
    );
    drop(
        connector
            .with_alpn(alpn())
            .connect_with_identity_and_callback(identity(), stream(), |_| {}),
    );
    drop(unbuffered.connect_with_identity(identity(), stream()));
    drop(unbuffered.connect_with_identity_and_callback(identity(), stream(), |_| {}));
    drop(
        unbuffered
            .with_alpn(alpn())
            .connect_with_identity(identity(), stream()),
    );
    drop(
        unbuffered
            .with_alpn(alpn())
            .connect_with_identity_and_callback(identity(), stream(), |_| {}),
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("peer");
        let address = peer.local_addr().expect("peer address");
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("socket");
        socket.connect(address).await.expect("connected socket");
        assert!(dtls::UdpClient::new_with_identity(config.clone(), identity(), socket).is_ok());
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("socket");
        socket.connect(address).await.expect("connected socket");
        assert!(
            dtls::UdpClient::new_with_identity_and_settings(
                config,
                identity(),
                socket,
                browntls_core::dtls::Settings::default(),
            )
            .is_ok()
        );
    });
}
