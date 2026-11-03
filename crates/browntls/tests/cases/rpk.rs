// Shared cases, included by `tests/rpk.rs` (RustCrypto provider) and
// `tests/rpk_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.

use std::sync::Arc;

use browntls::{
    AlertDescription, ClientConfig, ClientConnection, Error, PeerIncompatible, ProtocolVersion,
    ServerConfig, ServerConnection, version,
};
use common::*;

static TLS12_ONLY: [&browntls::SupportedProtocolVersion; 1] = [&version::TLS12];
static TLS13_ONLY: [&browntls::SupportedProtocolVersion; 1] = [&version::TLS13];

fn versions(v: ProtocolVersion) -> &'static [&'static browntls::SupportedProtocolVersion] {
    match v {
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
fn server_raw_public_key_every_key_type_and_version() {
    init_logging();
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        for &key_type in KeyType::SIGNING {
            let chain = server_chain(key_type);
            let (mut client, mut server) =
                connect(rpk_client(&chain, v, None), rpk_server(&chain, v, None));
            do_handshake(&mut client, &mut server)
                .unwrap_or_else(|e| panic!("{v:?} {key_type:?}: {e}"));
            assert_eq!(client.protocol_version(), Some(v));
            // The "certificate" the client saw is the bare SubjectPublicKeyInfo.
            assert_eq!(
                client.peer_certificates().unwrap(),
                [browntls::pki_types::CertificateDer::from(
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
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        let chain = server_chain(KeyType::EcdsaP256);
        let client_chain = client_chain(KeyType::Ed25519);
        let (mut client, mut server) = connect(
            rpk_client(&chain, v, Some(&client_chain)),
            rpk_server(&chain, v, Some(&client_chain)),
        );
        do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{v:?}: {e}"));
        assert_eq!(
            server.peer_certificates().unwrap(),
            [browntls::pki_types::CertificateDer::from(
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
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
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
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
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
        Err(browntls::CertificateError::UnknownIssuer.into())
    );
}

#[test]
fn client_hello_view_reports_offered_certificate_types() {
    init_logging();
    #[derive(Debug)]
    struct Inspecting(
        Arc<browntls::sign::CertifiedKey>,
        std::sync::Mutex<Option<bool>>,
    );
    impl browntls::server::ResolvesServerCert for Inspecting {
        fn resolve(
            &self,
            client_hello: browntls::server::ClientHello<'_>,
        ) -> Option<Arc<browntls::sign::CertifiedKey>> {
            *self.1.lock().unwrap() = Some(
                client_hello
                    .server_cert_types()
                    .is_some_and(|t| t.contains(&browntls::CertificateType::RawPublicKey)),
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
