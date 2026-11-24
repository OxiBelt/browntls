use std::sync::Arc;

use browntls_core::pki_types::{DnsName, ServerName};
use browntls_core::{
    CertificateError, ClientConfig, ClientConnection, ClientServerIdentity, Error, HandshakeKind,
    ReferenceIdentifier, RootCertStore, ServerConfig, ServerConnection, ServiceIdentity,
    SupportedProtocolVersion, UriId, WildcardPolicy, version,
};
use common::*;
use rcgen::{ExtendedKeyUsagePurpose, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};

fn service_chain() -> Chain {
    let ca = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    issue_chain_with(
        KeyType::EcdsaP256,
        ca,
        &leaf,
        leaf.serialize_der(),
        &["edge.example"],
        ExtendedKeyUsagePurpose::ServerAuth,
        |params| {
            params.subject_alt_names.push(SanType::URI(
                "example://identity.example/presented?value=elsewhere"
                    .try_into()
                    .unwrap(),
            ));
        },
    )
}

fn configs(
    chain: &Chain,
    version: &'static SupportedProtocolVersion,
) -> (ClientConfig, ServerConfig) {
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    (client, server)
}

fn uri(scheme: &str) -> ReferenceIdentifier {
    ReferenceIdentifier::Uri(
        UriId::new(scheme, DnsName::try_from("identity.example").unwrap()).unwrap(),
    )
}

fn edge_dns() -> ReferenceIdentifier {
    ReferenceIdentifier::Dns(DnsName::try_from("edge.example").unwrap())
}

fn routed(policy: ServiceIdentity) -> ClientServerIdentity {
    ClientServerIdentity::new(ServerName::try_from("edge.example").unwrap(), policy)
}

fn handshake(
    client: &mut ClientConnection,
    server: &Arc<ServerConfig>,
) -> Result<ServerConnection, Error> {
    let mut server = ServerConnection::new(server.clone()).unwrap();
    do_handshake(client, &mut server)?;
    transfer(&mut server, client);
    client.process_new_packets()?;
    Ok(server)
}

const VERSIONS: &[&SupportedProtocolVersion] = &[
    &version::TLS13,
    #[cfg(feature = "tls12")]
    &version::TLS12,
];

#[test]
fn typed_identity_is_independent_of_sni_and_preserves_caller_priority() {
    let chain = service_chain();
    for version in VERSIONS {
        let (client, server) = configs(&chain, version);
        let client = Arc::new(client);
        let server = Arc::new(server);
        let preferred = uri("EXAMPLE");
        let policy = ServiceIdentity::new(vec![preferred.clone(), edge_dns()]).unwrap();
        let mut connection =
            ClientConnection::new_with_identity(client.clone(), routed(policy)).unwrap();
        assert!(connection.matched_service_identity().is_none());

        let peer = handshake(&mut connection, &server).unwrap();
        assert_eq!(peer.server_name(), Some("edge.example"));
        assert_eq!(connection.matched_service_identity(), Some(&preferred));

        let wrong = ServiceIdentity::new(vec![uri("wrong")]).unwrap();
        let mut connection =
            ClientConnection::new_with_identity(client.clone(), routed(wrong)).unwrap();
        assert!(matches!(
            handshake(&mut connection, &server),
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            ))
        ));
        assert!(connection.matched_service_identity().is_none());

        let mut legacy =
            ClientConnection::new(client, ServerName::try_from("edge.example").unwrap()).unwrap();
        handshake(&mut legacy, &server).unwrap();
        assert_eq!(legacy.matched_service_identity(), Some(&edge_dns()));
    }
}

#[test]
fn resumption_and_early_data_use_the_original_bound_policy() {
    let chain = service_chain();
    for version in VERSIONS {
        let (mut client, mut server) = configs(&chain, version);
        client.enable_early_data = true;
        server.max_early_data_size = 1024;
        let client = Arc::new(client);
        let server = Arc::new(server);
        let preferred = uri("example");
        let policy = ServiceIdentity::new(vec![preferred.clone(), edge_dns()]).unwrap();

        let mut first =
            ClientConnection::new_with_identity(client.clone(), routed(policy.clone())).unwrap();
        handshake(&mut first, &server).unwrap();
        assert_eq!(first.handshake_kind(), Some(HandshakeKind::Full));

        let mut resumed =
            ClientConnection::new_with_identity(client.clone(), routed(policy.clone())).unwrap();
        assert_eq!(resumed.early_data().is_some(), *version == &version::TLS13);
        assert!(resumed.matched_service_identity().is_none());
        handshake(&mut resumed, &server).unwrap();
        assert_eq!(resumed.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(resumed.matched_service_identity(), Some(&preferred));

        let reordered = ServiceIdentity::new(vec![edge_dns(), preferred.clone()]).unwrap();
        let mut next =
            ClientConnection::new_with_identity(client.clone(), routed(reordered)).unwrap();
        assert!(next.early_data().is_none());
        handshake(&mut next, &server).unwrap();
        assert_eq!(next.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(next.matched_service_identity(), Some(&edge_dns()));

        let restricted = ServiceIdentity::new(vec![edge_dns(), preferred])
            .unwrap()
            .with_wildcard_policy(WildcardPolicy::Deny);
        let mut next =
            ClientConnection::new_with_identity(client.clone(), routed(restricted)).unwrap();
        assert!(next.early_data().is_none());
        handshake(&mut next, &server).unwrap();
        assert_eq!(next.handshake_kind(), Some(HandshakeKind::Full));

        let wrong = ServiceIdentity::new(vec![uri("wrong")]).unwrap();
        let mut wrong = ClientConnection::new_with_identity(client, routed(wrong)).unwrap();
        assert!(wrong.early_data().is_none());
        assert!(handshake(&mut wrong, &server).is_err());
    }
}

#[test]
fn legacy_custom_verifier_cannot_accept_an_explicit_identity() {
    let chain = service_chain();
    let (_, server) = configs(&chain, &version::TLS13);
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let policy = ServiceIdentity::new(vec![uri("example")]).unwrap();
    let mut connection =
        ClientConnection::new_with_identity(Arc::new(client), routed(policy)).unwrap();
    assert!(matches!(
        handshake(&mut connection, &Arc::new(server)),
        Err(Error::General(message)) if message.contains("explicit service identities")
    ));
    assert!(connection.matched_service_identity().is_none());
}

#[test]
fn exported_authenticator_uses_the_connection_reference_set() {
    use browntls_core::exported_authenticator::AuthenticatorRequestExtensions;
    use browntls_core::sign::CertifiedKey;

    let chain = service_chain();
    for version in VERSIONS {
        let (config, server) = configs(&chain, version);
        let preferred = uri("example");
        let policy = ServiceIdentity::new(vec![preferred.clone()]).unwrap();
        let identity = ClientServerIdentity::new(
            ServerName::try_from("only-a-routing-name.example").unwrap(),
            policy,
        );
        let mut client = ClientConnection::new_with_identity(Arc::new(config), identity).unwrap();
        let mut server = handshake(&mut client, &Arc::new(server)).unwrap();
        let key =
            CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap();
        let request = client
            .request_authenticator(b"typed service", &AuthenticatorRequestExtensions::default())
            .unwrap();
        let authenticator = server.authenticator(Some(&request), Some(&key)).unwrap();
        assert_eq!(
            client
                .validate_authenticator(Some(&request), &authenticator)
                .unwrap(),
            Some(chain.cert_chain())
        );
        assert_eq!(client.matched_service_identity(), Some(&preferred));
    }
}

#[test]
fn external_psk_selection_requires_a_certificate_for_explicit_identity() {
    use browntls_core::crypto::hash::HashAlgorithm;
    use browntls_core::psk::ExternalPsk;

    let chain = service_chain();
    let (mut client, mut server) = configs(&chain, &version::TLS13);
    let key = Arc::new(
        ExternalPsk::new(
            b"configured-key".to_vec(),
            vec![42; 32],
            HashAlgorithm::SHA256,
        )
        .unwrap(),
    );
    client.external_psks = vec![key.clone()];
    client.cert_with_extern_psk = true;
    server.external_psks = Some(Arc::new(vec![key]));
    let policy = ServiceIdentity::new(vec![uri("example")]).unwrap();
    let client = Arc::new(client);

    let mut rejected =
        ClientConnection::new_with_identity(client.clone(), routed(policy.clone())).unwrap();
    assert_eq!(
        handshake(&mut rejected, &Arc::new(server.clone())).unwrap_err(),
        Error::NoCertificatesPresented
    );
    assert!(rejected.matched_service_identity().is_none());

    server.cert_with_extern_psk = true;
    let mut accepted = ClientConnection::new_with_identity(client, routed(policy)).unwrap();
    handshake(&mut accepted, &Arc::new(server)).unwrap();
    assert_eq!(accepted.matched_service_identity(), Some(&uri("example")));
}
