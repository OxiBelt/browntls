// Shared cases, included by `tests/rpk.rs` (RustCrypto provider) and
// `tests/rpk_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.

use std::sync::Arc;

use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, PeerIncompatible, ProtocolVersion,
    ServerConfig, ServerConnection, version,
};
use common::*;

#[cfg(feature = "tls12")]
static TLS12_ONLY: [&browntls_core::SupportedProtocolVersion; 1] = [&version::TLS12];
static TLS13_ONLY: [&browntls_core::SupportedProtocolVersion; 1] = [&version::TLS13];

/// The versions every case runs with.
#[cfg(feature = "tls12")]
const VERSIONS: [ProtocolVersion; 2] = [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
#[cfg(not(feature = "tls12"))]
const VERSIONS: [ProtocolVersion; 1] = [ProtocolVersion::TLSv1_3];

fn versions(v: ProtocolVersion) -> &'static [&'static browntls_core::SupportedProtocolVersion] {
    match v {
        #[cfg(feature = "tls12")]
        ProtocolVersion::TLSv1_2 => &TLS12_ONLY,
        _ => &TLS13_ONLY,
    }
}

/// A server presenting a raw public key, optionally demanding one back.
fn rpk_server(chain: &Chain, v: ProtocolVersion, client: Option<&Chain>) -> ServerConfig {
    let builder = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(v))
        .unwrap();
    let builder = match client {
        Some(client_chain) => {
            builder.with_client_cert_verifier(PinnedClientVerifier::raw_public_key(client_chain))
        }
        None => builder.with_no_client_auth(),
    };
    builder.with_cert_resolver(RawKeyResolver::new(chain))
}

/// A client expecting a raw public key, optionally presenting one.
fn rpk_client(chain: &Chain, v: ProtocolVersion, client: Option<&Chain>) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(v))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::raw_public_key(chain));
    match client {
        Some(client_chain) => builder.with_client_cert_resolver(RawKeyResolver::new(client_chain)),
        None => builder.with_no_client_auth(),
    }
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

#[test]
fn rfc9973_still_verifies_both_raw_public_keys() {
    use browntls_core::crypto::hash::HashAlgorithm;
    use browntls_core::psk::ExternalPsk;

    let server_chain = server_chain(KeyType::EcdsaP256);
    let untrusted_server = gen_chain(
        KeyType::EcdsaP256,
        &["localhost"],
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client_chain = client_chain(KeyType::EcdsaP256);
    let version = ProtocolVersion::TLSv1_3;
    let key = Arc::new(
        ExternalPsk::new(b"rpk-rfc9973".to_vec(), vec![42; 32], HashAlgorithm::SHA256).unwrap(),
    );
    for (expected_server, trusted) in [(&server_chain, true), (&untrusted_server, false)] {
        let mut client_config = rpk_client(expected_server, version, Some(&client_chain));
        client_config.external_psks = vec![key.clone()];
        client_config.cert_with_extern_psk = true;
        let mut server_config = rpk_server(&server_chain, version, Some(&client_chain));
        server_config.external_psks = Some(Arc::new(vec![key.clone()]));
        server_config.require_cert_with_extern_psk = true;
        let (mut client, mut server) = connect(client_config, server_config);
        if trusted {
            do_handshake(&mut client, &mut server).unwrap();
            assert!(client.negotiated_cert_with_extern_psk());
            assert!(server.negotiated_cert_with_extern_psk());
            assert!(client.peer_certificates().is_some());
            assert!(server.peer_certificates().is_some());
        } else {
            assert!(
                do_handshake_until_error(&mut client, &mut server)
                    .0
                    .is_err()
            );
            assert!(!client.negotiated_cert_with_extern_psk());
            assert!(!server.negotiated_cert_with_extern_psk());
        }
    }
}

#[test]
fn server_raw_public_key_every_key_type_and_version() {
    init_logging();
    for v in VERSIONS {
        for &key_type in KeyType::SIGNING {
            let chain = server_chain(key_type);
            let (mut client, mut server) =
                connect(rpk_client(&chain, v, None), rpk_server(&chain, v, None));
            do_handshake(&mut client, &mut server)
                .unwrap_or_else(|e| panic!("{v:?} {key_type:?}: {e}"));
            assert_eq!(client.protocol_version(), Some(v));
            // The "certificate" the client saw is the bare
            // SubjectPublicKeyInfo.
            assert_eq!(
                client.peer_certificates().unwrap(),
                [browntls_core::pki_types::CertificateDer::from(
                    chain.end_entity_spki.clone()
                )]
            );
            assert_eq!(send_and_receive(&mut client, &mut server, b"raw"), b"raw");
            assert_eq!(send_and_receive(&mut server, &mut client, b"keys"), b"keys");
        }
    }
}

#[test]
fn mutual_raw_public_keys() {
    init_logging();
    for v in VERSIONS {
        let chain = server_chain(KeyType::EcdsaP256);
        let client_chain = client_chain(KeyType::Ed25519);
        let (mut client, mut server) = connect(
            rpk_client(&chain, v, Some(&client_chain)),
            rpk_server(&chain, v, Some(&client_chain)),
        );
        do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{v:?}: {e}"));
        assert_eq!(
            server.peer_certificates().unwrap(),
            [browntls_core::pki_types::CertificateDer::from(
                client_chain.end_entity_spki.clone()
            )]
        );
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"mutual"),
            b"mutual"
        );
    }
}

#[test]
fn server_requiring_raw_keys_refuses_x509_only_client() {
    init_logging();
    for v in VERSIONS {
        let chain = server_chain(KeyType::EcdsaP256);
        let x509_client = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions(v))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        let (mut client, mut server) = connect(x509_client, rpk_server(&chain, v, None));
        let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            server_res,
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into()),
            "{v:?}"
        );
        assert_eq!(
            client_res,
            Err(Error::AlertReceived(AlertDescription::HandshakeFailure)),
            "{v:?}"
        );
    }
}

#[test]
fn client_requiring_raw_keys_refuses_x509_server() {
    init_logging();
    for v in VERSIONS {
        let chain = server_chain(KeyType::EcdsaP256);
        let (mut client, mut server) = connect(rpk_client(&chain, v, None), server_config(&chain));
        let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
        // The client offered only RawPublicKey; a server that can only present
        // X.509 has nothing acceptable and refuses (as rustls does).
        assert_eq!(
            server_res,
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into()),
            "{v:?}"
        );
        assert_eq!(
            client_res,
            Err(Error::AlertReceived(AlertDescription::HandshakeFailure)),
            "{v:?}"
        );
    }
}

#[test]
fn wrong_raw_public_key_is_rejected() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        rpk_client(&other, ProtocolVersion::TLSv1_3, None),
        rpk_server(&chain, ProtocolVersion::TLSv1_3, None),
    );
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res,
        Err(browntls_core::CertificateError::UnknownIssuer.into())
    );
}

#[test]
fn client_hello_view_reports_offered_certificate_types() {
    init_logging();
    #[derive(Debug)]
    struct Inspecting(
        Arc<browntls_core::sign::CertifiedKey>,
        std::sync::Mutex<Option<bool>>,
    );
    impl browntls_core::server::ResolvesServerCert for Inspecting {
        fn resolve(
            &self,
            client_hello: browntls_core::server::ClientHello<'_>,
        ) -> Option<Arc<browntls_core::sign::CertifiedKey>> {
            *self.1.lock().unwrap() = Some(
                client_hello
                    .server_cert_types()
                    .is_some_and(|t| t.contains(&browntls_core::CertificateType::RawPublicKey)),
            );
            Some(self.0.clone())
        }
        fn only_raw_public_keys(&self) -> bool {
            true
        }
    }
    let chain = server_chain(KeyType::Ed25519);
    let resolver = Arc::new(Inspecting(
        RawKeyResolver::new(&chain).0.clone(),
        std::sync::Mutex::new(None),
    ));
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    let (mut client, mut server) = connect(
        rpk_client(&chain, ProtocolVersion::TLSv1_3, None),
        server_config,
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(*resolver.1.lock().unwrap(), Some(true));
}
