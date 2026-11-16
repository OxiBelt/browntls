// Cases included by `cases/external_psk.rs`, which holds the imports and the
// shared helpers: tickets and resumption next to external PSKs, and 0-RTT
// data with an external PSK.

// ----------------------------------------------- tickets next to external PSKs

#[test]
fn ticket_and_external_psk_offered_together() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = Arc::new(client_with(
        &chain,
        vec![psk(b"client-1", HashAlgorithm::SHA256)],
    ));
    let server_config = Arc::new(psk_only_server(vec![psk(
        b"client-1",
        HashAlgorithm::SHA256,
    )]));

    // First connection: external PSK, then a ticket.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);

    // Second connection: the ticket comes first and is taken.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    // The ticket came from an external-PSK session and carries its identity.
    assert_eq!(client.external_psk_identity(), Some(&b"client-1"[..]));
    assert_eq!(server.external_psk_identity(), Some(&b"client-1"[..]));
    exchange_data(&mut client, &mut server);

    // Third: a server that does not know the ticket takes the external PSK,
    // the second identity offered.
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(psk_only_server(vec![psk(
        b"client-1",
        HashAlgorithm::SHA256,
    )])))
    .unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"client-1"[..]));
    assert_eq!(server.external_psk_identity(), Some(&b"client-1"[..]));
    exchange_data(&mut client, &mut server);
}

// ------------------------------------------------------------------ 0-RTT

fn early_psk() -> ExternalPsk {
    psk(b"early", HashAlgorithm::SHA256)
        .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)
        .with_early_data(1024)
}

#[test]
fn early_data_with_an_external_psk_when_allowed() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_with(&chain, vec![early_psk()]);
    client_config.enable_early_data = true;
    let (mut client, mut server) = connect(client_config, psk_only_server(vec![early_psk()]));
    {
        let mut early = client.early_data().expect("PSK allows early data");
        assert_eq!(early.bytes_left(), 1024);
        early.write_all(b"GET /idempotent").unwrap();
    }
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.is_early_data_accepted());
    let mut got = Vec::new();
    server
        .early_data()
        .expect("server accepted early data")
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, b"GET /idempotent");
    exchange_data(&mut client, &mut server);
}

#[test]
fn early_data_with_an_external_psk_is_off_by_default() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);

    // Client side: no early data unless the PSK allows it.
    let mut client_config = client_with(
        &chain,
        vec![
            psk(b"early", HashAlgorithm::SHA256)
                .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256),
        ],
    );
    client_config.enable_early_data = true;
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    assert!(client.early_data().is_none());

    // Without a provisioned suite, neither.
    let mut client_config = client_with(
        &chain,
        vec![psk(b"early", HashAlgorithm::SHA256).with_early_data(1024)],
    );
    client_config.enable_early_data = true;
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    assert!(client.early_data().is_none());

    // Server side: a server whose PSK does not allow it rejects the data
    // and the handshake still completes.
    let mut client_config = client_with(&chain, vec![early_psk()]);
    client_config.enable_early_data = true;
    let (mut client, mut server) = connect(
        client_config,
        psk_only_server(vec![
            psk(b"early", HashAlgorithm::SHA256)
                .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256),
        ]),
    );
    client
        .early_data()
        .unwrap()
        .write_all(b"GET /idempotent")
        .unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
    assert_eq!(server.external_psk_identity(), Some(&b"early"[..]));
    exchange_data(&mut client, &mut server);
}

// ------------------------------------------------------------- resumption

/// The resumption key schedule continues with the negotiated suite, not
/// the ticket's: RFC 9846 §4.3.11 lets the server pick any suite with the
/// ticket's hash.
#[test]
fn resumption_with_another_suite_of_the_same_hash() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(8);
    // A server that prefers `suite` over the other one.
    let server = |suite: browntls::SupportedCipherSuite| {
        let suites: Vec<_> = [
            prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
            prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]
        .into_iter()
        .filter(|s| *s != suite)
        .collect();
        let mut config = ServerConfig::builder_with_provider(tls13_provider(
            Some(&[&[suite], &suites[..]].concat()),
            None,
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
        config.session_storage = cache.clone();
        config.ignore_client_order = true;
        Arc::new(config)
    };
    let client_config = Arc::new(client_with_provider(
        &chain,
        Vec::new(),
        tls13_provider(
            Some(&[
                prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
                prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ]),
            None,
        ),
    ));

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut first =
        ServerConnection::new(server(prov::cipher_suite::TLS13_AES_128_GCM_SHA256)).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    transfer(&mut first, &mut client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut second =
        ServerConnection::new(server(prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256)).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(
        suite_of(&client),
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    );
    exchange_data(&mut client, &mut second);
}

// ------------------------------------------- tickets of external-PSK sessions

#[test]
fn tickets_of_external_psk_sessions_keep_the_psk() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let server = |psks: Vec<ExternalPsk>, require: bool| {
        let mut config = cert_and_psk_server(&chain, psks);
        config.session_storage = cache.clone();
        config.require_external_psk = require;
        Arc::new(config)
    };
    let mut client_config = client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    client_config.require_external_psk = true;
    let client_config = Arc::new(client_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut first =
        ServerConnection::new(server(vec![psk(b"k", HashAlgorithm::SHA256)], false)).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    take_tickets(&mut client, &mut first);

    // Resuming reports the identity, and satisfies `require_external_psk`
    // on both sides.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut second =
        ServerConnection::new(server(vec![psk(b"k", HashAlgorithm::SHA256)], true)).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(second.external_psk_identity(), Some(&b"k"[..]));
    assert!(client.peer_certificates().is_none());
    exchange_data(&mut client, &mut second);
    // Tickets issued on a resumed session carry the PSK forward.
    take_tickets(&mut client, &mut second);

    // A server whose resolver no longer has the key does not resume the
    // session (nor select the key): a certificate handshake follows.
    let mut client_config = (*client_config).clone();
    client_config.require_external_psk = false;
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut third = ServerConnection::new(server(Vec::new(), false)).unwrap();
    do_handshake(&mut client, &mut third).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(third.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), None);
    assert_eq!(third.external_psk_identity(), None);
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
}

#[test]
fn imported_psk_tickets_keep_the_import_context() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let server = |context: &[u8]| {
        let mut config = cert_and_psk_server(
            &chain,
            vec![imported(b"epsk", HashAlgorithm::SHA256, context)],
        );
        config.session_storage = cache.clone();
        // Only the first server issues tickets: the client then holds those.
        if context != b"ctx" {
            config.send_tls13_tickets = 0;
        }
        Arc::new(config)
    };
    let client_config = Arc::new(client_with(
        &chain,
        vec![imported(b"epsk", HashAlgorithm::SHA256, b"ctx")],
    ));
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut first = ServerConnection::new(server(b"ctx")).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    take_tickets(&mut client, &mut first);

    // The server now holds the identity with another importer context: the
    // ticket is not resumed, and the key is not selected either.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut second = ServerConnection::new(server(b"other")).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(second.external_psk_identity(), None);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut third = ServerConnection::new(server(b"ctx")).unwrap();
    do_handshake(&mut client, &mut third).unwrap();
    assert_eq!(third.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(&b"epsk"[..]));
    assert_eq!(third.external_psk_identity(), Some(&b"epsk"[..]));
}

#[test]
fn resumption_rechecks_the_alpn_restriction() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let h2 = b"h2".to_vec();
    let http11 = b"http/1.1".to_vec();
    // SHA-384, the hash of the suite the server prefers: without the key,
    // it would still pick a suite the ticket can resume with.
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let server = |protocols: Vec<Vec<u8>>| {
        let mut config = cert_and_psk_server(
            &chain,
            vec![psk(b"k", HashAlgorithm::SHA384).with_alpn_protocol(b"h2".to_vec())],
        );
        config.session_storage = cache.clone();
        // Only servers that would select the key issue tickets: the client
        // then holds tickets of external-PSK sessions only.
        if !protocols.contains(&b"h2".to_vec()) {
            config.send_tls13_tickets = 0;
        }
        config.alpn_protocols = protocols;
        Arc::new(config)
    };
    let mut client_config = client_with(
        &chain,
        vec![psk(b"k", HashAlgorithm::SHA384).with_alpn_protocol(h2.clone())],
    );
    client_config.alpn_protocols = vec![h2.clone(), http11.clone()];
    let client_config = Arc::new(client_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut first = ServerConnection::new(server(vec![h2.clone()])).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    assert_eq!(first.external_psk_identity(), Some(&b"k"[..]));
    take_tickets(&mut client, &mut first);

    // The server now negotiates another protocol: the key's restriction
    // excludes resuming its session as much as selecting it.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut second = ServerConnection::new(server(vec![http11])).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(second.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), None);
    assert_eq!(second.external_psk_identity(), None);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut third = ServerConnection::new(server(vec![h2])).unwrap();
    do_handshake(&mut client, &mut third).unwrap();
    assert_eq!(third.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
}

#[test]
fn which_tickets_go_with_external_psks() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // SHA-384, the hash of the suite the certificate session below uses:
    // its ticket must be usable next to the key.
    let resolver = Arc::new(RecordingResolver {
        keys: vec![Arc::new(psk(b"k", HashAlgorithm::SHA384))],
        ..Default::default()
    });
    let mut server_config = server_config(&chain);
    server_config.external_psks = Some(resolver.clone());
    server_config.cert_with_extern_psk = true;
    let server_config = Arc::new(server_config);
    // How many identities the server was offered.
    let offered = || std::mem::take(&mut *resolver.asked.lock().unwrap()).len();

    // A certificate session, whose tickets go to the client's store.
    let base = client_with(&chain, Vec::new());
    let mut client = ClientConnection::new(Arc::new(base.clone()), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);
    assert_eq!(offered(), 0);

    // Usually the ticket is offered first, then the external PSK.
    let mut with_psk = base.clone();
    with_psk.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA384))];
    let mut client = ClientConnection::new(Arc::new(with_psk.clone()), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(offered(), 2);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), None);
    take_tickets(&mut client, &mut server);

    // A client that requires an external PSK does not offer the ticket of a
    // certificate session.
    let mut required = with_psk.clone();
    required.require_external_psk = true;
    let mut client = ClientConnection::new(Arc::new(required), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(offered(), 1);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    take_tickets(&mut client, &mut server);

    // With RFC 8773, no ticket goes along, not even one of an external-PSK
    // session: the server cannot resume instead of authenticating with its
    // certificate.
    let mut cert_with_psk = with_psk;
    cert_with_psk.cert_with_extern_psk = true;
    let mut client = ClientConnection::new(Arc::new(cert_with_psk), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(offered(), 1);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
}

#[test]
fn server_requiring_an_external_psk_passes_over_other_tickets() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let server = |require: bool| {
        let mut config = cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
        config.session_storage = cache.clone();
        config.require_external_psk = require;
        Arc::new(config)
    };
    let base = client_with(&chain, Vec::new());
    let mut client = ClientConnection::new(Arc::new(base.clone()), server_name()).unwrap();
    let mut first = ServerConnection::new(server(false)).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    assert_eq!(first.external_psk_identity(), None);
    take_tickets(&mut client, &mut first);

    // The certificate session's ticket comes first, but the server takes
    // the external PSK.
    let mut with_psk = base;
    with_psk.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))];
    let mut client = ClientConnection::new(Arc::new(with_psk), server_name()).unwrap();
    let mut second = ServerConnection::new(server(true)).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(second.external_psk_identity(), Some(&b"k"[..]));
}
