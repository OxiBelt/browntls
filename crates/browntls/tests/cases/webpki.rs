// Shared cases, included by `tests/webpki.rs` (RustCrypto provider) and
// `tests/webpki_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.

use std::sync::Arc;

use browntls::client::WebPkiServerVerifier;
use browntls::server::{ResolvesServerCertUsingSni, WebPkiClientVerifier};
use browntls::sign::CertifiedKey;
use browntls::{
    ClientConfig, ClientConnection, HandshakeKind, RootCertStore, ServerConfig, ServerConnection,
};
use common::*;

fn roots_for(chain: &Chain) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).expect("CA certificate parses");
    Arc::new(roots)
}

#[test]
fn root_store_starts_empty() {
    let roots = RootCertStore::empty();
    assert!(roots.is_empty());
    assert_eq!(roots.len(), 0);
    assert!(roots.subjects().is_empty());
}

#[test]
fn webpki_server_verifier_accepts_chain_from_trusted_root() {
    init_logging();
    for &key_type in KeyType::SIGNING {
        let chain = server_chain(key_type);
        let client_config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots_for(&chain))
            .with_no_client_auth();
        let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
        do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{key_type:?}: {e}"));
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    }
}

#[test]
fn webpki_server_verifier_rejects_unknown_root_and_wrong_name() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);

    // unknown issuer
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots_for(&other))
        .with_no_client_auth();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert!(
        matches!(client_res, Err(browntls::Error::InvalidCertificate(_))),
        "{client_res:?}"
    );

    // right issuer, wrong name
    let verifier = WebPkiServerVerifier::builder_with_provider(roots_for(&chain), provider())
        .build()
        .unwrap();
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        browntls::pki_types::ServerName::try_from("not-the-server.example").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res,
        Err(browntls::CertificateError::NotValidForName.into())
    );
}

#[test]
fn webpki_client_verifier_accepts_and_requires_client_certificates() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let verifier =
        WebPkiClientVerifier::builder_with_provider(roots_for(&client_chain), provider())
            .build()
            .unwrap();
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap(),
    );

    let client_config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots_for(&server_chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );

    // a client without a certificate is refused
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots_for(&server_chain))
        .with_no_client_auth();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(server_res, Err(browntls::Error::NoCertificatesPresented));
}

#[test]
fn sni_resolver_serves_the_matching_certificate() {
    init_logging();
    let localhost = server_chain(KeyType::EcdsaP256);
    let other = gen_chain(
        KeyType::Ed25519,
        &["other.example"],
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    );
    let mut resolver = ResolvesServerCertUsingSni::new();
    resolver
        .add(
            "localhost",
            CertifiedKey::from_der(localhost.cert_chain(), localhost.private_key(), &provider())
                .unwrap(),
        )
        .unwrap();
    resolver
        .add(
            "other.example",
            CertifiedKey::from_der(other.cert_chain(), other.private_key(), &provider()).unwrap(),
        )
        .unwrap();
    // the certificate must be valid for the name it is registered under
    assert!(
        resolver
            .add(
                "mismatch.example",
                CertifiedKey::from_der(other.cert_chain(), other.private_key(), &provider())
                    .unwrap(),
            )
            .is_err()
    );
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver)),
    );

    let mut client =
        ClientConnection::new(Arc::new(client_config(&localhost)), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.peer_certificates().unwrap(), localhost.cert_chain());

    let mut client = ClientConnection::new(
        Arc::new(client_config(&other)),
        browntls::pki_types::ServerName::try_from("other.example").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.peer_certificates().unwrap(), other.cert_chain());
}
