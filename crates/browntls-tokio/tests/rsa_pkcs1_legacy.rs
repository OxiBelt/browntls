//! The legacy RSASSA-PKCS1-v1_5 schemes of RFC 9963 in TLS 1.3 client
//! authentication through both Tokio drivers: the streams of the crate
//! root (`TlsConnector`, `TlsAcceptor`) and those of
//! `browntls_tokio::unbuffered`, over an in-memory duplex. The client's
//! RSA key is `crypto::native::sign::any_rsa_pkcs1_legacy_type`, the
//! server's client verifier has the native provider's opt-in
//! (`SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY`) or not, and every
//! handshake checks the scheme of the client's `CertificateVerify`.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_core as tls;

#[path = "rsa_pkcs1_legacy/pki.rs"]
mod pki;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::server::PostHandshakeAuthStatus;
use browntls_core::server::danger::ClientCertVerifier;
use browntls_core::{
    AlertDescription, ClientConfig, Error, HandshakeKind, ProtocolVersion, ServerConfig,
    SignatureScheme,
};
use pki::{Recorder, localhost, pki};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);

/// The configurations of one case and the verifiers that record the
/// `CertificateVerify` schemes.
struct Configs {
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    server_auth: Arc<Recorder<browntls_core::client::WebPkiServerVerifier>>,
    client_auth: Arc<Recorder<dyn ClientCertVerifier>>,
}

impl Configs {
    /// A client with the legacy key and a server with mandatory client
    /// authentication, opted in if `opted_in`; `tweak` adjusts both.
    fn new(opted_in: bool, tweak: impl FnOnce(&mut ClientConfig, &mut ServerConfig)) -> Self {
        let server_auth = pki().server_verifier();
        let client_auth = pki().client_verifier(opted_in);
        let mut client = pki().client_config(&server_auth);
        let mut server = pki().server_config(&client_auth);
        tweak(&mut client, &mut server);
        Self {
            client: Arc::new(client),
            server: Arc::new(server),
            server_auth,
            client_auth,
        }
    }

    /// The client verified one ECDSA P-256 server signature and the server
    /// one `rsa_pkcs1_sha512_legacy` client signature.
    fn assert_schemes(&self) {
        assert_eq!(
            self.server_auth.seen(),
            [SignatureScheme::ECDSA_NISTP256_SHA256]
        );
        assert_eq!(
            self.client_auth.seen(),
            [SignatureScheme::RSA_PKCS1_SHA512_LEGACY]
        );
    }
}

/// Writes `data` on `a`, reads it on `b`, and the other way round.
async fn echo<A, B>(a: &mut A, b: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
    let exchange = async {
        let (write, read) = tokio::join!(
            async {
                a.write_all(&data).await?;
                a.flush().await
            },
            async {
                let mut got = vec![0; data.len()];
                b.read_exact(&mut got).await.map(|_| got)
            }
        );
        write.unwrap();
        assert!(read.unwrap() == data, "data differs");
        b.write_all(b"reply").await.unwrap();
        b.flush().await.unwrap();
        let mut reply = [0; 5];
        a.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    };
    timeout(LIMIT, exchange)
        .await
        .expect("data exchange timed out");
}

/// The legacy key authenticates the client through the buffered streams
/// to an opted-in server: the server verifies one
/// `rsa_pkcs1_sha512_legacy` signature and sees the client's chain, and
/// data is echoed both ways.
#[tokio::test]
async fn legacy_client_authentication_through_the_buffered_streams() {
    let configs = Configs::new(true, |_, _| {});
    let (c, s) = duplex(4096);
    let connector = browntls_tokio::TlsConnector::from(configs.client.clone());
    let acceptor = browntls_tokio::TlsAcceptor::from(configs.server.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .expect("handshake timed out");
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    configs.assert_schemes();
    let (_, conn) = client.get_ref();
    assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(conn.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    let (_, conn) = server.get_ref();
    assert_eq!(conn.peer_certificates().unwrap(), pki().client_chain);
    echo(&mut client, &mut server).await;
}

/// The same through the streams of `browntls_tokio::unbuffered`.
#[tokio::test]
async fn legacy_client_authentication_through_the_unbuffered_streams() {
    let configs = Configs::new(true, |_, _| {});
    let (c, s) = duplex(4096);
    let connector = browntls_tokio::unbuffered::TlsConnector::from(configs.client.clone());
    let acceptor = browntls_tokio::unbuffered::TlsAcceptor::from(configs.server.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .expect("handshake timed out");
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    configs.assert_schemes();
    let (_, conn) = client.get_ref();
    assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full));
    let (_, conn) = server.get_ref();
    assert_eq!(conn.peer_certificates().unwrap(), pki().client_chain);
    echo(&mut client, &mut server).await;
}

/// The `browntls_core::Error` inside an `io::Error`, if any.
fn tls_error(err: &io::Error) -> Option<&Error> {
    err.get_ref()?.downcast_ref()
}

/// Against a server without the opt-in the legacy key does not sign and
/// the client sends an empty Certificate: the server's accept fails with
/// `InvalidData` carrying `NoCertificatesPresented`, and the client, whose
/// side of the handshake may already be complete, fails with
/// `certificate_required` in its handshake or its next read.
#[tokio::test]
async fn default_server_refuses_the_legacy_key_through_the_buffered_streams() {
    let configs = Configs::new(false, |_, _| {});
    let (c, s) = duplex(4096);
    let connector = browntls_tokio::TlsConnector::from(configs.client.clone());
    let acceptor = browntls_tokio::TlsAcceptor::from(configs.server.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .expect("handshake timed out");
    let err = server.expect_err("the server refused the client");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(tls_error(&err), Some(&Error::NoCertificatesPresented));
    let err = match client {
        Err(err) => err,
        Ok(mut stream) => timeout(LIMIT, stream.read(&mut [0; 1]))
            .await
            .expect("read timed out")
            .expect_err("the server refused the handshake"),
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        tls_error(&err),
        Some(&Error::AlertReceived(AlertDescription::CertificateRequired))
    );
    assert!(configs.client_auth.seen().is_empty());
}

/// Post-handshake client authentication (RFC 9846 §4.6.2) through the
/// buffered streams: the opted-in server asks for the client's certificate
/// after the handshake, the client answers while it reads, and the server
/// verifies one `rsa_pkcs1_sha512_legacy` signature over the client's
/// chain.
#[tokio::test]
async fn legacy_post_handshake_authentication_through_the_buffered_streams() {
    let configs = Configs::new(true, |client, server| {
        client.enable_post_handshake_auth = true;
        server.request_client_auth_after_handshake = true;
    });
    let (c, s) = duplex(4096);
    let connector = browntls_tokio::TlsConnector::from(configs.client.clone());
    let acceptor = browntls_tokio::TlsAcceptor::from(configs.server.clone());
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(connector.connect(localhost(), c), acceptor.accept(s))
    })
    .await
    .expect("handshake timed out");
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert!(server.get_ref().1.peer_certificates().is_none());
    assert!(configs.client_auth.seen().is_empty());

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
    assert_eq!(conn.peer_certificates().unwrap(), pki().client_chain);
    assert_eq!(client.get_ref().1.post_handshake_auth_responses(), 1);
    configs.assert_schemes();
}
