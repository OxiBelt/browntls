//! The RFC 9963 legacy RSA client authentication opt-in of the native
//! provider is reachable through the facade: the verification table
//! `crypto::native::SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY`, the key
//! loader `crypto::native::sign::any_rsa_pkcs1_legacy_type` and its key
//! type `crypto::native::sign::RsaPkcs1LegacySigningKey`, and the
//! signature check `crypto::verify_tls13_client_signature`. Every TLS item
//! is named through `browntls`; the identities come from
//! `browntls-tokio/tests/rsa_pkcs1_legacy/pki.rs`.

#![cfg(all(feature = "std", feature = "native"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls as tls;

#[path = "../../browntls-tokio/tests/rsa_pkcs1_legacy/pki.rs"]
mod pki;

use std::sync::Arc;

use browntls::crypto::native::sign::{RsaPkcs1LegacySigningKey, any_rsa_pkcs1_legacy_type};
use browntls::crypto::native::{SUPPORTED_SIG_ALGS, SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY};
use browntls::crypto::{verify_tls13_client_signature, verify_tls13_signature};
use browntls::server::WebPkiClientVerifier;
use browntls::server::danger::ClientCertVerifier;
use browntls::sign::{CertifiedKey, SigningKey};
use browntls::version::TLS13;
use browntls::{
    ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct, Error, HandshakeKind,
    PeerMisbehaved, ServerConfig, ServerConnection, SideData, SignatureAlgorithm,
    SignatureScheme as S,
};
use pki::{OPT_IN_ORDER, localhost, pki};

/// The opt-in provider, built from the items as the facade names them.
fn provider() -> Arc<browntls::crypto::CryptoProvider> {
    let mut provider = browntls::crypto::native::default_provider();
    provider.signature_verification_algorithms = SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY;
    Arc::new(provider)
}

/// Moves `from`'s records to `to` and processes them, keeping in `wire`
/// what `to` does not take yet.
fn deliver<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    wire: &mut Vec<u8>,
    to: &mut ConnectionCommon<B>,
) -> bool {
    while from.wants_write() {
        from.write_tls(wire).unwrap();
    }
    let before = wire.len();
    while !wire.is_empty() && to.wants_read() {
        if let Ok(n) = to.read_tls(&mut &wire[..]) {
            wire.drain(..n);
        }
        to.process_new_packets().unwrap();
    }
    wire.len() != before
}

/// `any_rsa_pkcs1_legacy_type` loads an RSA key as a
/// `RsaPkcs1LegacySigningKey` that signs with a legacy scheme when offered
/// one (the largest hash offered, wherever the list puts it) and with
/// `rsa_pkcs1_*` when offered TLS 1.2 schemes, never with RSASSA-PSS. Its
/// legacy signature passes
/// `verify_tls13_client_signature` with the opt-in table only, and never
/// `verify_tls13_signature` (a server's CertificateVerify).
#[test]
fn the_opt_in_items_load_and_verify_a_legacy_signature() {
    let key: Arc<dyn SigningKey> = any_rsa_pkcs1_legacy_type(&pki().client_key()).unwrap();
    assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);
    assert!(
        format!("{key:?}").starts_with(
            std::any::type_name::<RsaPkcs1LegacySigningKey>()
                .rsplit("::")
                .next()
                .unwrap()
        )
    );
    assert!(key.choose_scheme(&[S::RSA_PSS_SHA256]).is_none());
    let tls12 = key.choose_scheme(&[S::RSA_PKCS1_SHA256]).unwrap();
    assert_eq!(tls12.scheme(), S::RSA_PKCS1_SHA256);
    let reversed = [S::RSA_PKCS1_SHA256_LEGACY, S::RSA_PKCS1_SHA384_LEGACY];
    let chosen = key.choose_scheme(&reversed).unwrap();
    assert_eq!(chosen.scheme(), S::RSA_PKCS1_SHA384_LEGACY);
    let signer = key.choose_scheme(&OPT_IN_ORDER).unwrap();
    assert_eq!(signer.scheme(), S::RSA_PKCS1_SHA512_LEGACY);

    let message = b"TLS 1.3, client CertificateVerify";
    let dss = DigitallySignedStruct::new(signer.scheme(), signer.sign(message).unwrap());
    let cert = &pki().client_chain[0];
    let advertised = SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY.supported_schemes();
    assert!(OPT_IN_ORDER.iter().all(|s| advertised.contains(s)));
    verify_tls13_client_signature(
        message,
        cert,
        &dss,
        &SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY,
    )
    .unwrap();
    let unadvertised = Err(Error::PeerMisbehaved(
        PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
    ));
    assert_eq!(
        verify_tls13_client_signature(message, cert, &dss, &SUPPORTED_SIG_ALGS).map(|_| ()),
        unadvertised
    );
    assert_eq!(
        verify_tls13_signature(
            message,
            cert,
            &dss,
            &SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY
        )
        .map(|_| ()),
        unadvertised
    );
}

/// A TLS 1.3 handshake with the items: a server whose client verifier is
/// built with the opt-in provider verifies one `rsa_pkcs1_sha512_legacy`
/// signature from a client whose key `any_rsa_pkcs1_legacy_type` loaded.
#[test]
fn the_opt_in_items_authenticate_a_tls13_client() {
    let server_auth = pki().server_verifier();
    let inner: Arc<dyn ClientCertVerifier> =
        WebPkiClientVerifier::builder_with_provider(pki().roots(), provider())
            .build()
            .unwrap();
    let client_auth = pki::Recorder::new(inner);
    let key = any_rsa_pkcs1_legacy_type(&pki().client_key()).unwrap();
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_auth.clone())
        .with_client_auth_certified_key(CertifiedKey::new(pki().client_chain.clone(), key));
    let server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_client_cert_verifier(client_auth.clone())
        .with_single_cert(pki().server_chain.clone(), pki().server_key())
        .unwrap();
    let mut client = ClientConnection::new(Arc::new(client), localhost()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server)).unwrap();
    let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
    for _ in 0..16 {
        let c = deliver(&mut client, &mut to_server, &mut server);
        let s = deliver(&mut server, &mut to_client, &mut client);
        if !c && !s {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server_auth.seen(), [S::ECDSA_NISTP256_SHA256]);
    assert_eq!(client_auth.seen(), [S::RSA_PKCS1_SHA512_LEGACY]);
    assert_eq!(server.peer_certificates().unwrap(), pki().client_chain);
}

/// The opt-in through `browntls::tokio`, the streams of `browntls-tokio`:
/// legacy client authentication and data both ways.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn legacy_client_authentication_through_the_tokio_module() {
    use browntls::tokio::{TlsAcceptor, TlsConnector};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let server_auth = pki().server_verifier();
    let client_auth = pki().client_verifier(true);
    let connector = TlsConnector::from(Arc::new(pki().client_config(&server_auth)));
    let acceptor = TlsAcceptor::from(Arc::new(pki().server_config(&client_auth)));
    let (client_io, server_io) = tokio::io::duplex(4096);
    let (client, server) = tokio::join!(
        connector.connect(localhost(), client_io),
        acceptor.accept(server_io)
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut got = [0; 4];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    server.write_all(b"ok").await.unwrap();
    server.flush().await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ok");
    assert_eq!(server_auth.seen(), [S::ECDSA_NISTP256_SHA256]);
    assert_eq!(client_auth.seen(), [S::RSA_PKCS1_SHA512_LEGACY]);
    assert_eq!(
        server.get_ref().1.peer_certificates().unwrap(),
        pki().client_chain
    );
}
