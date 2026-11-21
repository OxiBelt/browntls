use browntls_core::pki_types::{DnsName, ServerName};
use browntls_core::{
    ClientServerIdentity, ReferenceIdentifier, RootCertStore, ServiceIdentity, UriId,
};
use rcgen::{ExtendedKeyUsagePurpose, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};

fn quic_identity_chain() -> Chain {
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

fn quic_uri(scheme: &str) -> ReferenceIdentifier {
    ReferenceIdentifier::Uri(
        UriId::new(scheme, DnsName::try_from("identity.example").unwrap()).unwrap(),
    )
}

fn identity_transfer(from: &mut bq::Connection, to: &mut bq::Connection) -> Result<bool, String> {
    let mut moved = false;
    loop {
        let mut bytes = Vec::new();
        let change = Endpoint::write_hs(from, &mut bytes);
        if !bytes.is_empty() {
            moved = true;
            Endpoint::read_hs(to, &bytes)?;
        }
        if change.is_none() {
            return Ok(moved);
        }
    }
}

fn identity_handshake(
    client: &mut bq::Connection,
    server: &mut bq::Connection,
) -> Result<(), String> {
    for _ in 0..16 {
        let client_moved = identity_transfer(client, server)?;
        let server_moved = identity_transfer(server, client)?;
        if !client_moved && !server_moved && !client.handshaking() && !server.handshaking() {
            return Ok(());
        }
    }
    Err("QUIC service-identity handshake did not finish".into())
}

#[test]
fn quic_client_authenticates_typed_uri_identity_separately_from_routing_name() {
    let chain = quic_identity_chain();
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    let mut client_config = browntls_core::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![ALPN.to_vec()];
    let client_config = Arc::new(client_config);
    let mut server_config = b_server_config(&chain);
    server_config.alpn_protocols = vec![ALPN.to_vec()];
    let server_config = Arc::new(server_config);

    let expected = quic_uri("EXAMPLE");
    let identity = ClientServerIdentity::new(
        ServerName::try_from("route.example").unwrap(),
        ServiceIdentity::new(vec![expected.clone()]).unwrap(),
    );
    let mut client = bq::Connection::Client(
        bq::ClientConnection::new_with_identity(
            client_config.clone(),
            bq::Version::V1,
            identity,
            CLIENT_PARAMS.to_vec(),
        )
        .unwrap(),
    );
    let mut server = bq::Connection::Server(
        bq::ServerConnection::new(
            server_config.clone(),
            bq::Version::V1,
            SERVER_PARAMS.to_vec(),
        )
        .unwrap(),
    );
    assert!(client.matched_service_identity().is_none());
    identity_handshake(&mut client, &mut server).unwrap();
    let bq::Connection::Client(client) = client else {
        unreachable!();
    };
    assert_eq!(client.matched_service_identity(), Some(&expected));

    let identity = ClientServerIdentity::new(
        ServerName::try_from("route.example").unwrap(),
        ServiceIdentity::new(vec![quic_uri("other")]).unwrap(),
    );
    let mut client = bq::Connection::Client(
        bq::ClientConnection::new_with_identity(
            client_config,
            bq::Version::V1,
            identity,
            CLIENT_PARAMS.to_vec(),
        )
        .unwrap(),
    );
    let mut server = bq::Connection::Server(
        bq::ServerConnection::new(server_config, bq::Version::V1, SERVER_PARAMS.to_vec()).unwrap(),
    );
    assert!(identity_handshake(&mut client, &mut server).is_err());
    let bq::Connection::Client(client) = client else {
        unreachable!();
    };
    assert!(client.matched_service_identity().is_none());
}
