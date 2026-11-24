use browntls_core::pki_types::{DnsName, ServerName};
use browntls_core::{
    ClientServerIdentity, ReferenceIdentifier, RootCertStore, ServiceIdentity, UriId,
};
use rcgen::{ExtendedKeyUsagePurpose, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};

fn unbuffered_identity_chain() -> Chain {
    let ca = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    issue_chain_with(
        KeyType::EcdsaP256,
        ca,
        &leaf,
        leaf.serialize_der(),
        &[],
        ExtendedKeyUsagePurpose::ServerAuth,
        |params| {
            params.subject_alt_names.push(SanType::URI(
                "example://identity.example/presented".try_into().unwrap(),
            ));
        },
    )
}

fn unbuffered_identity_config(chain: &Chain) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn unbuffered_uri(scheme: &str) -> ReferenceIdentifier {
    ReferenceIdentifier::Uri(
        UriId::new(scheme, DnsName::try_from("identity.example").unwrap()).unwrap(),
    )
}

#[test]
fn unbuffered_client_authenticates_typed_uri_identity_separately_from_routing_name() {
    let chain = unbuffered_identity_chain();
    let (client_config, server_config) = unbuffered_identity_config(&chain);
    let expected = unbuffered_uri("EXAMPLE");
    let identity = ClientServerIdentity::new(
        ServerName::try_from("route.example").unwrap(),
        ServiceIdentity::new(vec![expected.clone()]).unwrap(),
    );
    let mut client = Unbuffered::new(
        UnbufferedClientConnection::new_with_identity(client_config.clone(), identity).unwrap(),
        Feed::ByteByByte,
    );
    let mut server = ub_server(&server_config, Feed::ByteByByte);
    assert!(client.conn.matched_service_identity().is_none());
    handshake(&mut client, &mut server);
    assert_eq!(server.conn.server_name(), Some("route.example"));
    assert_eq!(client.conn.matched_service_identity(), Some(&expected));

    let identity = ClientServerIdentity::new(
        ServerName::try_from("route.example").unwrap(),
        ServiceIdentity::new(vec![unbuffered_uri("other")]).unwrap(),
    );
    let mut client = Unbuffered::new(
        UnbufferedClientConnection::new_with_identity(client_config, identity).unwrap(),
        Feed::Whole,
    );
    let mut server = ub_server(&server_config, Feed::Whole);
    pump(&mut client, &mut server);
    assert!(matches!(client.error, Some(Error::InvalidCertificate(_))));
    assert!(client.conn.matched_service_identity().is_none());
}
