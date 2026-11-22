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

#[cfg(feature = "zstd")]
#[tokio::test]
async fn zstd_policy_reaches_buffered_and_unbuffered_lazy_acceptors() {
    use browntls::server::{Acceptor, UnbufferedAcceptor};
    use browntls::tokio::{LazyConfigAcceptor, unbuffered};

    let pki = Pki::new();
    let mut client = pki.client_config();
    let (server, probe) = zstd_server(pki.server_config(), &mut client);
    let client = Arc::new(client);
    let server = Arc::new(server);
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let connector = TlsConnector::from(client.clone());
    let (client_result, server_result) =
        tokio::join!(connector.connect(localhost(), client_io), async {
            LazyConfigAcceptor::new(Acceptor::default(), server_io)
                .await?
                .into_stream(server.clone())
                .await
        },);
    client_result.unwrap();
    server_result.unwrap();
    assert_eq!(probe.count(), 1);

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let connector = unbuffered::TlsConnector::from(client);
    let (client_result, server_result) =
        tokio::join!(connector.connect(localhost(), client_io), async {
            unbuffered::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), server_io)
                .await?
                .into_stream(server)
                .await
        },);
    client_result.unwrap();
    server_result.unwrap();
    assert_eq!(probe.count(), 2);
}

#[tokio::test]
async fn hybrid_groups_negotiate_through_the_tokio_facade_adapter() {
    for (expected, provider) in hybrid_providers() {
        let pki = Pki::new();
        let provider = Arc::new(provider);
        let acceptor =
            TlsAcceptor::from(Arc::new(pki.server_config_with_provider(provider.clone())));
        let connector = TlsConnector::from(Arc::new(pki.client_config_with_provider(provider)));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = async {
            let mut tls = acceptor.accept(server_io).await.unwrap();
            let mut request = [0; 6];
            tls.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hybrid");
            assert_eq!(
                tls.get_ref()
                    .1
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                expected,
                "{expected:?} server"
            );
            tls.write_all(b"passed").await.unwrap();
            tls.shutdown().await.unwrap();
        };
        let client = async {
            let mut tls = connector.connect(localhost(), client_io).await.unwrap();
            tls.write_all(b"hybrid").await.unwrap();
            let mut reply = [0; 6];
            tls.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"passed");
            assert_eq!(
                tls.get_ref()
                    .1
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                expected,
                "{expected:?} client"
            );
        };
        tokio::join!(server, client);
    }
}

#[cfg(all(feature = "ktls", target_os = "linux"))]
#[tokio::test]
async fn hybrid_groups_handoff_through_the_facade_async_ktls_adapter() {
    use browntls::ktls::AsyncKtlsStream;
    use tokio::net::{TcpListener, TcpStream};

    let available = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp")
        .is_ok_and(|ulps| ulps.split_whitespace().any(|ulp| ulp == "tls"));
    if !available {
        assert!(std::env::var_os("BROWNTLS_KTLS_REQUIRED").is_none_or(|v| v != "1"));
        return;
    }

    for (expected, provider) in hybrid_providers() {
        let pki = Pki::new();
        let provider = Arc::new(provider);
        let mut client_config = pki.client_config_with_provider(provider.clone());
        client_config.enable_secret_extraction = true;
        let server_config = pki.server_config_with_provider(provider);
        #[cfg(feature = "zstd")]
        let (server_config, probe) = zstd_server(server_config, &mut client_config);
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let connector = TlsConnector::from(Arc::new(client_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            let mut request = [0; 6];
            tls.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hybrid");
            tls.write_all(b"passed").await.unwrap();
            tls.shutdown().await.unwrap();
        };
        let client = async {
            let socket = TcpStream::connect(address).await.unwrap();
            let tls = connector.connect(localhost(), socket).await.unwrap();
            assert_eq!(
                tls.get_ref()
                    .1
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                expected,
                "{expected:?} facade async peer before handoff"
            );
            let mut offloaded = AsyncKtlsStream::from_client(tls).await.unwrap();
            #[cfg(feature = "zstd")]
            assert_eq!(probe.count(), 1);
            offloaded.write_all(b"hybrid").await.unwrap();
            let mut reply = [0; 6];
            offloaded.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"passed");
        };
        tokio::join!(server, client);
    }
}

fn localhost_identity(reference: &str) -> browntls::ClientServerIdentity {
    use browntls::pki_types::{DnsName, ServerName};
    use browntls::{ReferenceIdentifier, ServiceIdentity};

    browntls::ClientServerIdentity::new(
        ServerName::try_from("localhost").unwrap(),
        ServiceIdentity::new(vec![ReferenceIdentifier::Dns(
            DnsName::try_from(reference).unwrap().to_owned(),
        )])
        .unwrap(),
    )
}

#[tokio::test]
async fn rfc9525_identity_matches_and_is_reported_through_facade_tokio() {
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
        tls.flush().await.unwrap();
    };
    let client = async {
        let mut tls = connector
            .connect_with_identity(localhost_identity("localhost"), client_io)
            .await
            .unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = [0u8; 5];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world");
        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.matched_service_identity(),
            Some(&browntls::ReferenceIdentifier::Dns(
                browntls::pki_types::DnsName::try_from("localhost")
                    .unwrap()
                    .to_owned()
            ))
        );
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn rfc9525_identity_mismatch_fails_through_facade_tokio() {
    let pki = Pki::new();
    let acceptor = TlsAcceptor::from(Arc::new(pki.server_config()));
    let connector = TlsConnector::from(Arc::new(pki.client_config()));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = async {
        if let Ok(mut tls) = acceptor.accept(server_io).await {
            let _ = tokio::io::copy(&mut tls, &mut tokio::io::sink()).await;
        }
    };
    let client = async {
        let error = connector
            .connect_with_identity_and_callback(
                localhost_identity("other.example"),
                client_io,
                |_| {},
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
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
        .with_client_delegated_credential(
            issued.credential.clone(),
            issued.signing_key,
            &provider(),
        )
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
