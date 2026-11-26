// Cases included by `cases/tls13_only_policy.rs`, which holds the imports
// and the shared helpers: the TLS 1.3-only preset of the builders and the
// `supports_version` accessor of the configurations.

fn preset_client(chain: &Chain) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_tls13_only()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn preset_server(chain: &Chain) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_tls13_only()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

#[test]
fn the_preset_is_the_tls13_only_list() {
    let chain = server_chain(KeyType::Ed25519);

    // The same offer as the explicit list makes.
    let preset = take_flight(&mut client_conn(preset_client(&chain)));
    let listed = client_hello(&chain, Policy::Tls13Only);
    assert_eq!(supported_versions(&preset).unwrap(), [2, 0x03, 0x04]);
    assert_eq!(
        client_hello_cipher_suites(&preset),
        client_hello_cipher_suites(&listed)
    );
    assert_eq!(
        hello_extension_types(&preset, true),
        hello_extension_types(&listed, true)
    );

    // The same answer to a peer of the same policy and of the default one.
    for (client, server) in [
        (preset_client(&chain), preset_server(&chain)),
        (
            preset_client(&chain),
            policy_server(&chain, Policy::Default),
        ),
        (
            policy_client(&chain, Policy::Default),
            preset_server(&chain),
        ),
    ] {
        let (mut client, mut server) = (client_conn(client), server_conn(server));
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    }
}

#[cfg(feature = "tls12")]
#[test]
fn the_preset_refuses_a_tls12_peer_on_either_side() {
    let chain = server_chain(KeyType::Ed25519);

    let hello = client_hello(&chain, Policy::Tls12Only);
    assert_eq!(
        serve(preset_server(&chain), &hello),
        (
            Err(Error::PeerIncompatible(
                PeerIncompatible::Tls12NotOfferedOrEnabled
            )),
            Some(AlertDescription::ProtocolVersion)
        )
    );

    let hello = take_flight(&mut client_conn(preset_client(&chain)));
    assert_eq!(
        serve(policy_server(&chain, Policy::Tls12Only), &hello),
        (
            Err(Error::PeerIncompatible(
                PeerIncompatible::Tls12NotOfferedOrEnabled
            )),
            Some(AlertDescription::ProtocolVersion)
        )
    );
}

#[cfg(feature = "tls12")]
#[test]
fn the_preset_needs_a_tls13_suite() {
    let mut tls12_suites = prov::default_provider();
    tls12_suites
        .cipher_suites
        .retain(|suite| suite.version() == &version::TLS12);
    let tls12_suites = Arc::new(tls12_suites);
    let refused = Error::General("no usable cipher suites configured".into());
    assert_eq!(
        ClientConfig::builder_with_provider(tls12_suites.clone())
            .with_tls13_only()
            .map(|_| ())
            .unwrap_err(),
        refused
    );
    assert_eq!(
        ServerConfig::builder_with_provider(tls12_suites)
            .with_tls13_only()
            .map(|_| ())
            .unwrap_err(),
        refused
    );
}

#[test]
fn a_configuration_reports_the_versions_of_its_list() {
    let chain = server_chain(KeyType::Ed25519);
    let (tls13, tls12) = (ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2);
    let cases = [
        (Policy::Tls13Only, true, false),
        (Policy::Default, true, cfg!(feature = "tls12")),
        #[cfg(feature = "tls12")]
        (Policy::Tls12Only, false, true),
    ];
    for (policy, has_tls13, has_tls12) in cases {
        let client = policy_client(&chain, policy);
        let server = policy_server(&chain, policy);
        assert_eq!(client.supports_version(tls13), has_tls13, "{policy:?}");
        assert_eq!(client.supports_version(tls12), has_tls12, "{policy:?}");
        assert_eq!(server.supports_version(tls13), has_tls13, "{policy:?}");
        assert_eq!(server.supports_version(tls12), has_tls12, "{policy:?}");
        // Nothing else is ever in a list: no older TLS, and no DTLS
        // version, which a `dtls` endpoint has a policy of its own for.
        for other in [
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_0,
            ProtocolVersion::SSLv3,
            ProtocolVersion::DTLSv1_2,
            ProtocolVersion::DTLSv1_3,
        ] {
            assert!(!client.supports_version(other), "{policy:?} {other:?}");
            assert!(!server.supports_version(other), "{policy:?} {other:?}");
        }
    }
    assert!(preset_client(&chain).supports_version(tls13));
    assert!(!preset_client(&chain).supports_version(tls12));
    assert!(preset_server(&chain).supports_version(tls13));
    assert!(!preset_server(&chain).supports_version(tls12));
}

/// The accessor reports the list, not what the provider can negotiate:
/// the default list keeps TLS 1.2 for a provider without a TLS 1.2 suite.
#[cfg(feature = "tls12")]
#[test]
fn the_accessor_reports_a_listed_version_without_suites() {
    let chain = server_chain(KeyType::Ed25519);
    let mut tls13_suites = prov::default_provider();
    tls13_suites
        .cipher_suites
        .retain(|suite| suite.version() == &version::TLS13);
    let config = ClientConfig::builder_with_provider(Arc::new(tls13_suites))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    assert!(config.supports_version(ProtocolVersion::TLSv1_2));
    // The hello still names TLS 1.2 in `supported_versions`, with no suite
    // a TLS 1.2 server could select: the list, and not the suites, is what
    // an application checks and what it has to state.
    let hello = take_flight(&mut client_conn(config));
    assert_eq!(supported_versions(&hello).unwrap(), [4, 3, 4, 3, 3]);
    assert!(
        client_hello_cipher_suites(&hello)
            .iter()
            .all(|suite| suite >> 8 == 0x13 || *suite == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    );
}
