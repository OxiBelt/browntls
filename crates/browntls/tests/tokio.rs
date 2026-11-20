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
