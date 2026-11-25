//! The ML-DSA TLS 1.3 opt-in of the native provider
//! (`draft-ietf-tls-mldsa-06`) is reachable through the facade: the two
//! provider fields, `crypto::native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13`
//! and `crypto::native::KEY_PROVIDER_WITH_ML_DSA`, and the key loader
//! `crypto::native::sign::any_ml_dsa_type`, which also signs the test
//! certificates (`browntls-tokio/tests/mldsa/pki.rs`). Every item is named
//! through `browntls`.

#![cfg(all(feature = "std", feature = "native"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls as tls;

#[path = "../../browntls-tokio/tests/mldsa/pki.rs"]
mod pki;

use std::sync::Arc;

use browntls::crypto::native::sign::any_ml_dsa_type;
use browntls::crypto::native::{
    KEY_PROVIDER_WITH_ML_DSA, SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13, default_provider,
};
use browntls::pki_types::PrivatePkcs8KeyDer;
use browntls::sign::SigningKey;
use browntls::version::TLS13;
use browntls::{
    ClientConfig, ClientConnection, ConnectionCommon, HandshakeKind, ServerConfig,
    ServerConnection, SideData, SignatureAlgorithm,
};
use pki::{Identity, Purpose, SETS, Set, localhost};

/// The opt-in provider, built from the items as the facade names them.
fn provider() -> Arc<browntls::crypto::CryptoProvider> {
    let mut provider = default_provider();
    provider.signature_verification_algorithms = SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13;
    provider.key_provider = KEY_PROVIDER_WITH_ML_DSA;
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

#[test]
fn the_opt_in_items_load_keys_and_authenticate_a_handshake() {
    // `any_ml_dsa_type` loads an RFC 9881 PKCS #8 key that signs with its
    // own TLS 1.3 scheme only and has no TLS 1.2 signature algorithm.
    let key: Arc<dyn SigningKey> =
        any_ml_dsa_type(&pki::pkcs8_seed(Set::MlDsa65, &[7; 32])).unwrap();
    assert_eq!(key.algorithm(), SignatureAlgorithm::Unknown(0xff));
    assert!(key.choose_scheme(&[Set::MlDsa44.scheme()]).is_none());
    assert!(key.choose_scheme(&[Set::MlDsa65.scheme()]).is_some());
    assert!(any_ml_dsa_type(&PrivatePkcs8KeyDer::from(vec![0x30, 0x00])).is_err());
    let advertised = SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.supported_schemes();
    assert!(SETS.iter().all(|set| advertised.contains(&set.scheme())));

    for set in SETS {
        let server_id = Identity::new(set, Purpose::Server);
        let client_id = Identity::new(set, Purpose::Client);
        let server_auth = server_id.server_verifier();
        let client_auth = client_id.client_verifier();
        let client = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_auth.clone())
            .with_client_auth_cert(client_id.chain(), client_id.private_key())
            .unwrap();
        // `with_single_cert` loads the key through `KEY_PROVIDER_WITH_ML_DSA`.
        let server = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_client_cert_verifier(client_auth.clone())
            .with_single_cert(server_id.chain(), server_id.private_key())
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
        assert_eq!(server_auth.seen(), [set.scheme()], "{set:?}");
        assert_eq!(client_auth.seen(), [set.scheme()], "{set:?}");
        assert_eq!(server.peer_certificates().unwrap(), client_id.chain());
    }
}

/// The opt-in through `browntls::tokio`, the streams of `browntls-tokio`.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn ml_dsa_server_authentication_through_the_tokio_module() {
    use browntls::tokio::{TlsAcceptor, TlsConnector};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let server_id = Identity::new(Set::MlDsa87, Purpose::Server);
    let server_auth = server_id.server_verifier();
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_auth.clone())
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(server_id.chain(), server_id.private_key())
        .unwrap();
    let connector = TlsConnector::from(Arc::new(client));
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let (client_io, server_io) = tokio::io::duplex(4096);
    let (client, server) = tokio::join!(
        connector.connect(localhost(), client_io),
        acceptor.accept(server_io)
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    server.write_all(b"ok").await.unwrap();
    server.flush().await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ok");
    assert_eq!(server_auth.seen(), [Set::MlDsa87.scheme()]);
}
