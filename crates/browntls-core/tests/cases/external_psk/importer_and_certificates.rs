// Cases included by `cases/external_psk.rs`, which holds the imports and the
// shared helpers: the PSK importer (RFC 9258), certificate authentication
// with an external PSK (RFC 8773) and `require_external_psk`.

// ------------------------------------------------------- RFC 9258 importer

fn imported(identity: &[u8], hash: HashAlgorithm, context: &[u8]) -> ExternalPsk {
    psk(identity, hash).imported(context.to_vec()).unwrap()
}

#[test]
fn imported_psk_handshake() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for epsk_hash in [HashAlgorithm::SHA256, HashAlgorithm::SHA384] {
        let (mut client, mut server) = connect(
            client_with(&chain, vec![imported(b"epsk", epsk_hash, b"app ctx")]),
            psk_only_server(vec![imported(b"epsk", epsk_hash, b"app ctx")]),
        );
        do_handshake(&mut client, &mut server).unwrap();
        // The client imports for each hash of its suites, SHA-384 first
        // (AES-256-GCM leads its list); the server takes the first.
        assert_eq!(suite_of(&server), CipherSuite::TLS13_AES_256_GCM_SHA384);
        assert_eq!(client.external_psk_identity(), Some(&b"epsk"[..]));
        assert_eq!(server.external_psk_identity(), Some(&b"epsk"[..]));
        assert!(client.peer_certificates().is_none());
        exchange_data(&mut client, &mut server);
    }
}

#[test]
fn imported_psk_for_each_suite_hash() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in [
        prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
        prov::cipher_suite::TLS13_AES_256_GCM_SHA384,
        prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        // The client imports for SHA-384 and SHA-256; the server, which
        // has one suite, takes the identity imported for its hash. (The
        // importer runs HKDF with the EPSK's hash, so that hash must be a
        // suite's of the provider.)
        let hash = suite.tls13().unwrap().common.hash_provider.algorithm();
        let (mut client, mut server) = connect(
            client_with(&chain, vec![imported(b"epsk", hash, b"")]),
            psk_only_server_with_provider(
                vec![imported(b"epsk", hash, b"")],
                tls13_provider(Some(&[suite]), None),
            ),
        );
        do_handshake(&mut client, &mut server)
            .unwrap_or_else(|e| panic!("{:?}: {e}", suite.suite()));
        assert_eq!(suite_of(&server), suite.suite());
        exchange_data(&mut client, &mut server);
    }
}

#[test]
fn imported_psk_context_must_match() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(
            &chain,
            vec![imported(b"epsk", HashAlgorithm::SHA256, b"one")],
        ),
        psk_only_server(vec![imported(b"epsk", HashAlgorithm::SHA256, b"two")]),
    );
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::NoUsablePskForServerWithoutCertificate)
    );
}

#[test]
fn imported_and_direct_uses_do_not_mix() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // Direct offer, importer-only server key.
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"epsk", HashAlgorithm::SHA256)]),
        psk_only_server(vec![imported(b"epsk", HashAlgorithm::SHA256, b"")]),
    );
    assert!(
        do_handshake_until_error(&mut client, &mut server)
            .1
            .is_err()
    );
    // Imported offer, direct-only server key.
    let (mut client, mut server) = connect(
        client_with(&chain, vec![imported(b"epsk", HashAlgorithm::SHA256, b"")]),
        psk_only_server(vec![psk(b"epsk", HashAlgorithm::SHA256)]),
    );
    assert!(
        do_handshake_until_error(&mut client, &mut server)
            .1
            .is_err()
    );
}

/// A resolver that records the identities it is asked for.
#[derive(Debug, Default)]
struct RecordingResolver {
    keys: Vec<Arc<ExternalPsk>>,
    asked: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl ResolvesExternalPsk for RecordingResolver {
    fn resolve(&self, identity: &[u8]) -> Option<Arc<ExternalPsk>> {
        self.asked.lock().unwrap().push(identity.to_vec());
        self.keys.iter().find(|k| k.identity() == identity).cloned()
    }
}

#[test]
fn imported_identities_on_the_wire() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let resolver = Arc::new(RecordingResolver {
        keys: vec![Arc::new(imported(b"epsk", HashAlgorithm::SHA256, b"ctx"))],
        ..Default::default()
    });
    let mut server_config = psk_only_server(Vec::new());
    server_config.external_psks = Some(resolver.clone());
    let (mut client, mut server) = connect(
        client_with(
            &chain,
            vec![imported(b"epsk", HashAlgorithm::SHA256, b"ctx")],
        ),
        server_config,
    );
    do_handshake(&mut client, &mut server).unwrap();
    let asked = resolver.asked.lock().unwrap().clone();
    // Each offered identity is first looked up as is; the imported ones then
    // by their external identity.
    let expect = |kdf| ImportedIdentity {
        external_identity: b"epsk".to_vec(),
        context: b"ctx".to_vec(),
        target_protocol: browntls_core::ProtocolVersion::TLSv1_3,
        target_kdf: kdf,
    };
    assert_eq!(
        asked,
        vec![
            expect(ImportedIdentity::HKDF_SHA384).encode(),
            b"epsk".to_vec(),
            expect(ImportedIdentity::HKDF_SHA256).encode(),
            b"epsk".to_vec(),
        ]
    );
}

// --------------------------------------------------------------- RFC 8773

#[test]
fn certificate_authentication_with_an_external_psk() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    client_config.cert_with_extern_psk = true;
    client_config.require_cert_with_extern_psk = true;
    let mut server_config = cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    server_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(server.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    exchange_data(&mut client, &mut server);
}

#[test]
fn certificate_authentication_with_an_external_psk_and_client_auth() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    client_config.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))];
    client_config.cert_with_extern_psk = true;
    let mut server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    server_config.external_psks = Some(Arc::new(vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))]));
    server_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
    exchange_data(&mut client, &mut server);
}

#[test]
fn certificate_authentication_with_an_external_psk_is_opt_in() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // The server does not enable it: a plain PSK handshake, which a client
    // that only asks accepts...
    let mut client_config = client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    client_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(
        client_config.clone(),
        cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert!(client.peer_certificates().is_none());

    // ...and a client that requires it refuses.
    client_config.require_cert_with_extern_psk = true;
    let (mut client, mut server) = connect(
        client_config,
        cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
    );
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::CertWithExternPskRequired)
    );

    // A server without a certificate cannot do it, and does a PSK handshake.
    let mut client_config = client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    client_config.cert_with_extern_psk = true;
    let mut server_config = psk_only_server(vec![psk(b"k", HashAlgorithm::SHA256)]);
    server_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.peer_certificates().is_none());
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
}

// ------------------------------------------------------ require_external_psk

#[test]
fn client_requiring_an_external_psk_refuses_a_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // The server does not know the client's key and authenticates with its
    // certificate, which the client would accept...
    let mut client_config = client_with(&chain, vec![psk(b"a", HashAlgorithm::SHA256)]);
    let (mut client, mut server) = connect(
        client_config.clone(),
        cert_and_psk_server(&chain, vec![psk(b"b", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), None);
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());

    // ...unless it requires an external PSK.
    client_config.require_external_psk = true;
    let (mut client, mut server) = connect(
        client_config.clone(),
        cert_and_psk_server(&chain, vec![psk(b"b", HashAlgorithm::SHA256)]),
    );
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::ExternalPskRequired)
    );
    assert_eq!(
        server_res.unwrap_err(),
        Error::AlertReceived(AlertDescription::HandshakeFailure)
    );

    // With a server that knows the key, it is used.
    let (mut client, mut server) = connect(
        client_config,
        cert_and_psk_server(&chain, vec![psk(b"a", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), Some(&b"a"[..]));
}

#[test]
fn server_requiring_an_external_psk_refuses_certificate_clients() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut server_config = cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    server_config.require_external_psk = true;
    let server_config = Arc::new(server_config);

    // A client without the key would get the certificate otherwise.
    let mut client = ClientConnection::new(
        Arc::new(client_with(
            &chain,
            vec![psk(b"other", HashAlgorithm::SHA256)],
        )),
        server_name(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::ExternalPskRequired)
    );
    assert_eq!(
        client_res.unwrap_err(),
        Error::AlertReceived(AlertDescription::HandshakeFailure)
    );

    let mut client = ClientConnection::new(
        Arc::new(client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)])),
        server_name(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.external_psk_identity(), Some(&b"k"[..]));
}

#[cfg(feature = "tls12")]
#[test]
fn requiring_an_external_psk_refuses_tls12() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // Client side: a TLS 1.2 server.
    let mut client_config = client_config(&chain);
    client_config.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))];
    client_config.require_external_psk = true;
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::ExternalPskRequired)
    );

    // Server side: a TLS 1.2 client.
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut server_config = cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    server_config.require_external_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::ExternalPskRequired)
    );
}
