//! `browntls::tokio` is `browntls-tokio`: a handshake and application data
//! between a connector and an acceptor named through `browntls` alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use browntls::tokio::{TlsAcceptor, TlsConnector};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn handshake_and_data_through_the_tokio_module() {
    let pki = Pki::new();
    let acceptor = TlsAcceptor::from(Arc::new(pki.server_config()));
    let connector = TlsConnector::from(Arc::new(pki.client_config()));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = async {
        let mut tls = acceptor.accept(server_io).await.unwrap();
        let mut request = [0u8; 5];
        tls.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"hello");
        tls.write_all(b"world").await.unwrap();
        tls.shutdown().await.unwrap();
    };
    let client = async {
        let mut tls = connector.connect(localhost(), client_io).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"world");
        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.protocol_version(),
            Some(browntls::ProtocolVersion::TLSv1_3)
        );
    };
    tokio::join!(server, client);
}

/// An acceptor whose configuration turns on `enable_grease` (RFC 8701
/// §4.1) authenticates a client certificate through `browntls::tokio`.
#[tokio::test]
async fn server_grease_with_client_authentication_through_the_tokio_module() {
    let pki = Pki::new();
    let mut server_config = pki.server_config_with_client_auth();
    server_config.enable_grease = true;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let connector = TlsConnector::from(Arc::new(pki.client_config_with_cert()));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = async {
        let mut tls = acceptor.accept(server_io).await.unwrap();
        let certs = tls.get_ref().1.peer_certificates().unwrap();
        assert_eq!(certs[0], pki.client_chain[0]);
        let mut request = [0u8; 5];
        tls.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"hello");
        tls.write_all(b"world").await.unwrap();
        tls.shutdown().await.unwrap();
    };
    let client = async {
        let mut tls = connector.connect(localhost(), client_io).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"world");
    };
    tokio::join!(server, client);
}

/// A client authenticates with a delegated credential (RFC 9345 §4.1.2)
/// through `browntls::tokio`, issued with the native provider, and the
/// server reads it from the accepted stream.
#[tokio::test]
async fn client_delegated_credential_through_the_tokio_module() {
    use browntls::crypto::native::delegated_credential::generate;
    use browntls::delegated_credential::valid_time_until;
    use browntls::pki_types::UnixTime;
    use browntls::sign::{CertifiedKey, SingleCertAndKey};
    use browntls::{ClientConfig, Side, SignatureScheme};

    let pki = Pki::with_delegation();
    let end_entity = &pki.client_chain[0];
    let cert_key = provider()
        .key_provider
        .load_private_key(pki.client_key())
        .unwrap();
    let a_day_from_now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        UnixTime::now().as_secs() + 24 * 3600,
    ));
    let issued = generate(
        Side::Client,
        end_entity,
        &*cert_key,
        &[SignatureScheme::ECDSA_NISTP256_SHA256],
        SignatureScheme::ED25519,
        valid_time_until(end_entity, a_day_from_now).unwrap(),
    )
    .unwrap();
    let certified = CertifiedKey::new(pki.client_chain.clone(), cert_key)
        .with_client_delegated_credential(issued.credential.clone(), issued.signing_key)
        .unwrap();
    let client = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(pki.roots())
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));

    let mut server = pki.server_config_with_client_auth();
    server.enable_delegated_credentials = true;

    let acceptor = TlsAcceptor::from(Arc::new(server));
    let connector = TlsConnector::from(Arc::new(client));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = async {
        let mut tls = acceptor.accept(server_io).await.unwrap();
        let (_, conn) = tls.get_ref();
        assert_eq!(conn.client_delegated_credential(), Some(&issued.credential));
        let mut request = [0u8; 5];
        tls.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"hello");
        tls.write_all(b"world").await.unwrap();
        tls.shutdown().await.unwrap();
    };
    let client = async {
        let mut tls = connector.connect(localhost(), client_io).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"world");
    };
    tokio::join!(server, client);
}

/// The module's own re-export of the protocol crate names the same items
/// as this crate's root: a configuration built through one path is the
/// type the other path expects.
#[test]
fn both_paths_name_the_same_types() {
    fn takes_module_path(_: &browntls::tokio::browntls::ClientConfig) {}
    fn takes_root_path(_: &browntls::ClientConfig) {}

    let config = Pki::new().client_config();
    takes_module_path(&config);
    takes_root_path(&config);
}

/// The client certificate URL fetcher (RFC 6066 §5) attaches to an
/// acceptor named through `browntls::tokio`, with the policy and query
/// types named through `browntls`.
#[test]
fn client_certificate_url_fetcher_is_attachable() {
    use browntls::certificate_url::{ClientCertificateUrlPolicy, ClientCertificateUrlQuery};
    use browntls::tokio::certificate_url::FetchClientCertificateUrl;

    let mut config = Pki::new().server_config();
    config.client_certificate_url = Some(ClientCertificateUrlPolicy::new(
        browntls::crypto::native::sha1,
    ));
    let fetcher: Arc<dyn FetchClientCertificateUrl> =
        Arc::new(|_: ClientCertificateUrlQuery| async {
            Err::<Vec<Vec<u8>>, _>(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        });
    let _acceptor = TlsAcceptor::from(Arc::new(config)).client_certificate_url_fetcher(fetcher);
}

/// `ocsp` reaches `browntls-tokio`: its `revocation` module exists.
#[cfg(feature = "ocsp")]
#[test]
fn revocation_module_follows_the_ocsp_feature() {
    fn assert_debug<T: std::fmt::Debug>() {}
    assert_debug::<browntls::tokio::revocation::FetchLimits>();
}

/// `tokio` together with `ktls` turns on `browntls-ktls`'s Tokio stream.
#[cfg(all(feature = "ktls", target_os = "linux"))]
#[test]
fn async_kernel_stream_is_nameable() {
    fn assert_stream<T: tokio::io::AsyncRead + tokio::io::AsyncWrite>() {}
    assert_stream::<browntls::ktls::AsyncKtlsStream<browntls::client::ClientConnectionData>>();
}
