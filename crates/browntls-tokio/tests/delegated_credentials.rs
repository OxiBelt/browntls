//! TLS 1.3 client authentication with a delegated credential (RFC 9345
//! §4.1.2) through the asynchronous streams: the buffered connector and
//! acceptor, the lazy acceptor, the unbuffered driver, post-handshake
//! authentication and resumption, with the credentials a server rejects.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::delegated_credential::{Credential, DelegatedCredential, valid_time_until};
use browntls_core::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
};
use browntls_core::server::danger::ClientCertVerifier;
use browntls_core::server::{Acceptor, PostHandshakeAuthStatus, WebPkiClientVerifier};
use browntls_core::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use browntls_core::time_provider::TimeProvider;
use browntls_core::{
    AlertDescription, ClientConfig, Error, HandshakeKind, PeerMisbehaved, ServerConfig, Side,
    SignatureScheme, SupportedProtocolVersion,
};
use browntls_tokio::{LazyConfigAcceptor, TlsAcceptor, TlsConnector, client, server};
use common::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

const DAY: i64 = 24 * 3600;

const TLS13: &SupportedProtocolVersion = &browntls_core::version::TLS13;

/// A fixed clock.
#[derive(Debug)]
struct FixedTime(UnixTime);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
}

/// Now, moved by `by` seconds.
fn shifted(by: i64) -> UnixTime {
    let secs = UnixTime::now().as_secs().checked_add_signed(by).unwrap();
    UnixTime::since_unix_epoch(Duration::from_secs(secs))
}

/// A credential and its ECDSA P-256 key, issued by `chain`'s end entity
/// (whose key is `cert_key`) for `side`, expiring at `expiry`.
fn issue(
    side: Side,
    chain: &[CertificateDer<'static>],
    cert_key: PrivateKeyDer<'static>,
    expiry: UnixTime,
) -> (DelegatedCredential, Arc<dyn SigningKey>) {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let dc_key = provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pair.serialize_der(),
        )))
        .unwrap();
    let public_key =
        SubjectPublicKeyInfoDer::from(rcgen::PublicKeyData::subject_public_key_info(&pair));
    let cert_key = provider().key_provider.load_private_key(cert_key).unwrap();
    let dc = DelegatedCredential::issue(
        side,
        &chain[0],
        &*cert_key,
        &[SignatureScheme::ECDSA_NISTP256_SHA256],
        Credential {
            valid_time: valid_time_until(&chain[0], expiry).unwrap(),
            dc_cert_verify_algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
            public_key,
        },
    )
    .unwrap();
    (dc, dc_key)
}

/// A client credential, valid for a day.
fn client_credential(pki: &Pki) -> (DelegatedCredential, Arc<dyn SigningKey>) {
    issue(
        Side::Client,
        &pki.client_chain,
        pki.client_key(),
        shifted(DAY),
    )
}

/// A client configuration for `version` that trusts the CA and presents
/// the client certificate, with `credential` attached to it.
fn client_config(
    pki: &Pki,
    version: &'static SupportedProtocolVersion,
    credential: Option<(DelegatedCredential, Arc<dyn SigningKey>)>,
) -> ClientConfig {
    let mut key =
        CertifiedKey::from_der(pki.client_chain.clone(), pki.client_key(), &provider()).unwrap();
    if let Some((dc, dc_key)) = credential {
        key = key.with_client_delegated_credential(dc, dc_key).unwrap();
    }
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(pki.roots())
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)))
}

fn client_verifier(pki: &Pki) -> Arc<dyn ClientCertVerifier> {
    WebPkiClientVerifier::builder_with_provider(Arc::new(pki.roots()), provider())
        .build()
        .unwrap()
}

/// A server configuration for `version` that requires a client
/// certificate from the CA and accepts client delegated credentials.
fn dc_server_config(pki: &Pki, version: &'static SupportedProtocolVersion) -> ServerConfig {
    let mut config = pki.server_config_with_client_auth(version);
    config.enable_delegated_credentials = true;
    config
}

/// Connects `client` and `server` over an in-memory transport.
async fn connect(
    client: ClientConfig,
    server: ServerConfig,
) -> (
    io::Result<client::TlsStream<DuplexStream>>,
    io::Result<server::TlsStream<DuplexStream>>,
) {
    let (c, s) = duplex(64 * 1024);
    timeout(LIMIT, async {
        tokio::join!(
            TlsConnector::from(Arc::new(client)).connect(localhost(), c),
            TlsAcceptor::from(Arc::new(server)).accept(s),
        )
    })
    .await
    .expect("handshake timed out")
}

/// Sends a request from `client` and an answer from `server`.
async fn exchange<C, S>(client: &mut C, server: &mut S)
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let work = async {
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    };
    timeout(LIMIT, work).await.expect("data exchange timed out");
}

/// Whether `err` carries `expected`, the misbehaviour the server found.
fn is_misbehaviour(err: &io::Error, expected: PeerMisbehaved) -> bool {
    matches!(tls_error(err), Some(Error::PeerMisbehaved(found)) if *found == expected)
}

/// The client of a handshake the server refused with `illegal_parameter`:
/// either its handshake fails with that alert or, when it finished its
/// side first, its next read does.
async fn assert_client_got_illegal_parameter(client: io::Result<client::TlsStream<DuplexStream>>) {
    let err = match client {
        Err(err) => err,
        Ok(mut stream) => timeout(LIMIT, stream.read(&mut [0; 1]))
            .await
            .expect("read timed out")
            .expect_err("the server refused the handshake"),
    };
    assert!(
        matches!(
            tls_error(&err),
            Some(Error::AlertReceived(AlertDescription::IllegalParameter))
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn client_authenticates_with_a_delegated_credential() {
    let pki = Pki::with_delegation();
    let (dc, key) = client_credential(&pki);
    let (client, server) = connect(
        client_config(&pki, TLS13, Some((dc.clone(), key))),
        dc_server_config(&pki, TLS13),
    )
    .await;
    let (mut client, mut server) = (client.unwrap(), server.unwrap());

    let conn = server.get_ref().1;
    assert_eq!(conn.client_delegated_credential(), Some(&dc));
    assert_eq!(conn.peer_certificates().unwrap()[0], pki.client_chain[0]);
    // The server authenticated with its certificate key.
    assert!(client.get_ref().1.delegated_credential().is_none());
    exchange(&mut client, &mut server).await;
}

#[tokio::test]
async fn both_sides_authenticate_with_delegated_credentials() {
    let pki = Pki::with_delegation();
    let (client_dc, client_key) = client_credential(&pki);
    let (server_dc, server_key) = issue(
        Side::Server,
        &pki.server_chain,
        pki.server_key(),
        shifted(DAY),
    );

    let mut client = client_config(&pki, TLS13, Some((client_dc.clone(), client_key)));
    client.enable_delegated_credentials = true;
    let server_key =
        CertifiedKey::from_der(pki.server_chain.clone(), pki.server_key(), &provider())
            .unwrap()
            .with_delegated_credential(server_dc.clone(), server_key)
            .unwrap();
    let mut server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[TLS13])
        .unwrap()
        .with_client_cert_verifier(client_verifier(&pki))
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(server_key)));
    server.enable_delegated_credentials = true;

    let (client, server) = connect(client, server).await;
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert_eq!(
        server.get_ref().1.client_delegated_credential(),
        Some(&client_dc)
    );
    assert_eq!(client.get_ref().1.delegated_credential(), Some(&server_dc));
    exchange(&mut client, &mut server).await;
}

#[tokio::test]
async fn a_server_without_the_flag_sees_the_certificate_key() {
    let pki = Pki::with_delegation();
    let (client, server) = connect(
        client_config(&pki, TLS13, Some(client_credential(&pki))),
        pki.server_config_with_client_auth(TLS13),
    )
    .await;
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    let conn = server.get_ref().1;
    assert!(conn.client_delegated_credential().is_none());
    assert_eq!(conn.peer_certificates().unwrap()[0], pki.client_chain[0]);
    exchange(&mut client, &mut server).await;
}

#[tokio::test]
async fn a_client_without_a_credential_uses_its_certificate_key() {
    let pki = Pki::with_delegation();
    for version in versions() {
        let (client, server) = connect(
            client_config(&pki, version, None),
            dc_server_config(&pki, version),
        )
        .await;
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        let conn = server.get_ref().1;
        assert!(conn.client_delegated_credential().is_none(), "{version:?}");
        assert_eq!(conn.peer_certificates().unwrap()[0], pki.client_chain[0]);
        exchange(&mut client, &mut server).await;
    }
}

/// TLS 1.2 has no delegated credentials: the credential is not used.
#[cfg(feature = "tls12")]
#[tokio::test]
async fn tls12_ignores_the_credential() {
    let pki = Pki::with_delegation();
    let version = &browntls_core::version::TLS12;
    let (client, server) = connect(
        client_config(&pki, version, Some(client_credential(&pki))),
        dc_server_config(&pki, version),
    )
    .await;
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    let conn = server.get_ref().1;
    assert!(conn.client_delegated_credential().is_none());
    assert_eq!(conn.peer_certificates().unwrap()[0], pki.client_chain[0]);
    exchange(&mut client, &mut server).await;
}

#[tokio::test]
async fn a_server_credential_presented_by_the_client_is_refused() {
    let pki = Pki::with_delegation();
    // Signed for the server's side: the signature over the client's
    // context does not verify.
    let wrong_side = issue(
        Side::Server,
        &pki.client_chain,
        pki.client_key(),
        shifted(DAY),
    );
    let (client, server) = connect(
        client_config(&pki, TLS13, Some(wrong_side)),
        dc_server_config(&pki, TLS13),
    )
    .await;
    let err = server.unwrap_err();
    assert!(
        is_misbehaviour(&err, PeerMisbehaved::DelegatedCredentialBadSignature),
        "{err:?}"
    );
    assert_client_got_illegal_parameter(client).await;
}

#[tokio::test]
async fn an_expired_credential_is_refused() {
    let pki = Pki::with_delegation();
    // Valid for a day by the client's clock; the server's clock is two
    // days ahead.
    let mut server = dc_server_config(&pki, TLS13);
    server.time_provider = Arc::new(FixedTime(shifted(2 * DAY)));
    let (client, server) = connect(
        client_config(&pki, TLS13, Some(client_credential(&pki))),
        server,
    )
    .await;
    let err = server.unwrap_err();
    assert!(
        is_misbehaviour(&err, PeerMisbehaved::DelegatedCredentialExpired),
        "{err:?}"
    );
    assert_client_got_illegal_parameter(client).await;
}

#[tokio::test]
async fn the_lazy_acceptor_enables_credentials_after_the_client_hello() {
    let pki = Pki::with_delegation();
    let (dc, key) = client_credential(&pki);
    let connector = TlsConnector::from(Arc::new(client_config(
        &pki,
        TLS13,
        Some((dc.clone(), key)),
    )));
    let config = Arc::new(dc_server_config(&pki, TLS13));
    let (c, s) = duplex(64 * 1024);
    let server = async {
        let start = LazyConfigAcceptor::new(Acceptor::default(), s).await?;
        assert_eq!(start.client_hello().server_name(), Some("localhost"));
        start.into_stream(config).await
    };
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), server)
    })
    .await
    .unwrap();
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert_eq!(server.get_ref().1.client_delegated_credential(), Some(&dc));
    exchange(&mut client, &mut server).await;
}

#[tokio::test]
async fn the_unbuffered_driver_reports_the_credential() {
    use browntls_tokio::unbuffered;

    let pki = Pki::with_delegation();
    let (dc, key) = client_credential(&pki);
    let connector = unbuffered::TlsConnector::from(Arc::new(client_config(
        &pki,
        TLS13,
        Some((dc.clone(), key)),
    )));
    let acceptor = unbuffered::TlsAcceptor::from(Arc::new(dc_server_config(&pki, TLS13)));
    let (c, s) = duplex(64 * 1024);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .unwrap();
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    let conn = server.get_ref().1;
    assert_eq!(conn.client_delegated_credential(), Some(&dc));
    assert_eq!(conn.peer_certificates().unwrap()[0], pki.client_chain[0]);
    exchange(&mut client, &mut server).await;
}

#[tokio::test]
async fn post_handshake_authentication_with_a_credential() {
    let pki = Pki::with_delegation();
    let (dc, key) = client_credential(&pki);
    let mut client = client_config(&pki, TLS13, Some((dc.clone(), key)));
    client.enable_post_handshake_auth = true;
    let mut server = dc_server_config(&pki, TLS13);
    server.request_client_auth_after_handshake = true;
    let (client, server) = connect(client, server).await;
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert!(server.get_ref().1.peer_certificates().is_none());
    assert!(server.get_ref().1.client_delegated_credential().is_none());

    // The client answers the CertificateRequest while it reads the reply,
    // and its next message follows the answer, which the server has
    // processed once it reads that message.
    let client_side = async {
        client.write_all(b"request\n").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0; 6];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply\n");
        client.write_all(b"done").await.unwrap();
        client.flush().await.unwrap();
    };
    let server_side = async {
        let mut request = [0; 8];
        server.read_exact(&mut request).await.unwrap();
        server.get_mut().1.request_client_auth().unwrap();
        server.write_all(b"reply\n").await.unwrap();
        server.flush().await.unwrap();
        let mut done = [0; 4];
        server.read_exact(&mut done).await.unwrap();
        assert_eq!(&done, b"done");
    };
    timeout(LIMIT, async { tokio::join!(client_side, server_side) })
        .await
        .expect("the client never answered the CertificateRequest");

    let conn = server.get_ref().1;
    assert_eq!(
        conn.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
    assert_eq!(conn.client_delegated_credential(), Some(&dc));
    assert_eq!(conn.peer_certificates().unwrap()[0], pki.client_chain[0]);
    assert_eq!(client.get_ref().1.post_handshake_auth_responses(), 1);
}

#[tokio::test]
async fn resumption_after_a_credential_keeps_the_certificates() {
    let pki = Pki::with_delegation();
    let (dc, key) = client_credential(&pki);
    let connector = TlsConnector::from(Arc::new(client_config(
        &pki,
        TLS13,
        Some((dc.clone(), key)),
    )));
    let acceptor = TlsAcceptor::from(Arc::new(dc_server_config(&pki, TLS13)));

    for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
        let (c, s) = duplex(64 * 1024);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
        })
        .await
        .unwrap();
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        let conn = server.get_ref().1;
        assert_eq!(conn.handshake_kind(), Some(expected));
        assert_eq!(conn.peer_certificates().unwrap()[0], pki.client_chain[0]);
        let credential = conn.client_delegated_credential();
        match expected {
            HandshakeKind::Full => assert_eq!(credential, Some(&dc)),
            _ => assert!(credential.is_none(), "{credential:?}"),
        }

        // Reading to the end takes the tickets the server sent.
        let work = async {
            server.write_all(b"bye").await.unwrap();
            server.shutdown().await.unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"bye");
        };
        timeout(LIMIT, work).await.expect("timed out");
    }
}
