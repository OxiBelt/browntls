#[cfg(feature = "tls12")]
#[test]
fn dtls12_client_authenticates_typed_uri_identity_with_explicit_settings() {
    use browntls_core::pki_types::{DnsName, ServerName};
    use browntls_core::{
        ClientServerIdentity, ReferenceIdentifier, RootCertStore, ServiceIdentity, UriId, version,
    };
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, SanType};

    fn uri(scheme: &str) -> ReferenceIdentifier {
        ReferenceIdentifier::Uri(
            UriId::new(scheme, DnsName::try_from("identity.example").unwrap()).unwrap(),
        )
    }

    let ca = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let chain = issue_chain_with(
        KeyType::EcdsaP256,
        ca,
        &leaf,
        leaf.serialize_der(),
        &[],
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        |params| {
            params.subject_alt_names.push(SanType::URI(
                "example://identity.example/presented".try_into().unwrap(),
            ));
        },
    );
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_config = Arc::new(dtls_server_config(&chain));
    let settings = dtls::Settings::default().with_versions(dtls::Versions::V1_2);
    let expected = uri("EXAMPLE");
    let identity = ClientServerIdentity::new(
        ServerName::try_from("route.example").unwrap(),
        ServiceIdentity::new(vec![expected.clone()]).unwrap(),
    );
    let mut pair = Pair {
        client: dtls::ClientConnection::new_with_identity_and_settings(
            client_config.clone(),
            identity,
            settings,
        )
        .unwrap(),
        server: dtls::ServerConnection::new_with_settings(
            server_config.clone(),
            PEER,
            dtls::Settings::default().with_versions(dtls::Versions::V1_2),
        )
        .unwrap(),
    };
    assert!(pair.client.matched_service_identity().is_none());
    pair.handshake(&mut Sim::perfect()).unwrap();
    assert_eq!(
        pair.client.protocol_version(),
        Some(ProtocolVersion::DTLSv1_2)
    );
    assert_eq!(pair.server.server_name(), Some("route.example"));
    assert_eq!(pair.client.matched_service_identity(), Some(&expected));

    let identity = ClientServerIdentity::new(
        ServerName::try_from("route.example").unwrap(),
        ServiceIdentity::new(vec![uri("other")]).unwrap(),
    );
    let mut pair = Pair {
        client: dtls::ClientConnection::new_with_identity_and_settings(
            client_config,
            identity,
            dtls::Settings::default().with_versions(dtls::Versions::V1_2),
        )
        .unwrap(),
        server: dtls::ServerConnection::new_with_settings(
            server_config,
            PEER,
            dtls::Settings::default().with_versions(dtls::Versions::V1_2),
        )
        .unwrap(),
    };
    assert!(pair.handshake(&mut Sim::perfect()).is_err());
    assert!(pair.client.matched_service_identity().is_none());
}
