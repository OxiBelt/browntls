// Cases included by `cases/delegated_credentials.rs`, which holds the imports
// and the shared helpers: resumption, tickets and 0-RTT data within the
// lifetime of a delegated credential.

#[test]
fn resumption_and_descendants_keep_the_original_expiry() {
    init_logging();
    for stateless in [false, true] {
        let chain = delegation_server_chain(KeyType::EcdsaP256);
        let base = now();
        let expiry = seconds_after(base, 60);
        let client_clock = AdjustableTime::new(base);
        let server_clock = AdjustableTime::new(base);
        let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
        let dc_key = certified_key(&chain)
            .with_delegated_credential(dc.clone(), key)
            .unwrap();

        let mut client_config = dc_client(&chain);
        client_config.time_provider = client_clock.clone();
        let client_config = Arc::new(client_config);

        let mut delegated_server = server_with(dc_key);
        delegated_server.time_provider = server_clock.clone();
        let mut certificate_server = server_with(certified_key(&chain));
        certificate_server.time_provider = server_clock.clone();
        if stateless {
            let ticketer = prov::Ticketer::new().unwrap();
            delegated_server.ticketer = ticketer.clone();
            delegated_server.session_storage =
                Arc::new(browntls::server::NoServerSessionStorage {});
            certificate_server.ticketer = ticketer;
            certificate_server.session_storage =
                Arc::new(browntls::server::NoServerSessionStorage {});
        } else {
            let cache: Arc<dyn browntls::server::StoresServerSessions> =
                browntls::server::ServerSessionMemoryCache::new(16);
            delegated_server.session_storage = cache.clone();
            certificate_server.session_storage = cache;
        }
        let delegated_server = Arc::new(delegated_server);
        let certificate_server = Arc::new(certificate_server);

        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(delegated_server.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.delegated_credential(), Some(&dc));
        take_tickets(&mut client, &mut server);

        client_clock.set(seconds_after(base, 30));
        server_clock.set(seconds_after(base, 30));
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(delegated_server).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        assert!(client.delegated_credential().is_none());
        take_tickets(&mut client, &mut server);

        // The newest ticket is a descendant of the resumed session. The
        // client rejects it at the original exact deadline, while a server
        // clock still before that deadline would otherwise accept it.
        client_clock.set(expiry);
        let mut client = ClientConnection::new(client_config, server_name()).unwrap();
        let mut server = ServerConnection::new(certificate_server).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
        assert!(client.delegated_credential().is_none());
    }
}

#[test]
fn server_rejects_expired_ticket_and_early_data() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);

    let mut client_config = dc_client(&chain);
    client_config.time_provider = client_clock;
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);

    let mut delegated_server = server_with(
        certified_key(&chain)
            .with_delegated_credential(dc, key)
            .unwrap(),
    );
    delegated_server.time_provider = server_clock.clone();
    delegated_server.session_storage = cache.clone();
    delegated_server.max_early_data_size = 1024;
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(delegated_server)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);

    server_clock.set(expiry);
    let mut certificate_server = server_with(certified_key(&chain));
    certificate_server.time_provider = server_clock;
    certificate_server.session_storage = cache;
    certificate_server.max_early_data_size = 1024;
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    client
        .early_data()
        .expect("ticket permits early data before the client deadline")
        .write_all(b"replayable")
        .unwrap();
    let mut server = ServerConnection::new(Arc::new(certificate_server)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
}

#[test]
fn resumption_expiring_before_server_finished_is_aborted() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);

    let mut client_config = dc_client(&chain);
    client_config.time_provider = client_clock.clone();
    let client_config = Arc::new(client_config);
    let mut server_config = server_with(
        certified_key(&chain)
            .with_delegated_credential(dc, key)
            .unwrap(),
    );
    server_config.time_provider = server_clock;
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    client_clock.set(expiry);
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::DelegatedCredentialExpired)
    );
    transfer(&mut client, &mut server);
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::AlertReceived(AlertDescription::IllegalParameter)
    );
}

#[test]
fn expired_ticket_cannot_extend_an_attacker_only_delegated_key() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    // The certificate key is deliberately absent: only the delegated key can
    // authenticate. A full fallback after expiry must therefore fail.
    let attacker_key = CertifiedKey::new(chain.cert_chain(), key.clone())
        .with_delegated_credential(dc, key)
        .unwrap();

    let mut client_config = dc_client(&chain);
    client_config.time_provider = client_clock.clone();
    let client_config = Arc::new(client_config);
    let mut server_config = server_with(attacker_key);
    server_config.time_provider = server_clock;
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);

    client_clock.set(expiry);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    let (client_result, server_result) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_result,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialExpired
        ))
    );
    assert_eq!(
        server_result,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn external_psk_session_keeps_delegated_credential_expiry() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let psk =
        || ExternalPsk::new(b"combined".to_vec(), vec![0x42; 32], HashAlgorithm::SHA256).unwrap();
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let certified = certified_key(&chain)
        .with_delegated_credential(dc.clone(), key)
        .unwrap();

    let mut first_client = dc_client(&chain);
    first_client.time_provider = client_clock.clone();
    first_client.external_psks = vec![Arc::new(psk())];
    first_client.cert_with_extern_psk = true;
    first_client.require_cert_with_extern_psk = true;
    let mut resumed_client = first_client.clone();
    resumed_client.cert_with_extern_psk = false;
    resumed_client.require_cert_with_extern_psk = false;
    let first_client = Arc::new(first_client);
    let resumed_client = Arc::new(resumed_client);

    let mut first_server = server_with(certified.clone());
    first_server.time_provider = server_clock.clone();
    first_server.session_storage = cache.clone();
    first_server.external_psks = Some(Arc::new(vec![Arc::new(psk())]));
    first_server.cert_with_extern_psk = true;
    let mut resumed_server = server_with(certified);
    resumed_server.time_provider = server_clock;
    resumed_server.session_storage = cache;
    resumed_server.external_psks = Some(Arc::new(vec![Arc::new(psk())]));
    let first_server = Arc::new(first_server);
    let resumed_server = Arc::new(resumed_server);

    let mut client = ClientConnection::new(first_client, server_name()).unwrap();
    let mut server = ServerConnection::new(first_server).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.delegated_credential(), Some(&dc));
    assert_eq!(client.external_psk_identity(), Some(&b"combined"[..]));
    take_tickets(&mut client, &mut server);

    let mut client = ClientConnection::new(resumed_client.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(resumed_server.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(&b"combined"[..]));
    take_tickets(&mut client, &mut server);

    client_clock.set(expiry);
    let mut client = ClientConnection::new(resumed_client, server_name()).unwrap();
    let mut server = ServerConnection::new(resumed_server).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"combined"[..]));
    assert!(client.delegated_credential().is_none());
}

#[test]
fn server_rejects_descendant_ticket_at_deadline() {
    for stateless in [false, true] {
        let chain = delegation_server_chain(KeyType::EcdsaP256);
        let base = now();
        let expiry = seconds_after(base, 60);
        let client_clock = AdjustableTime::new(base);
        let server_clock = AdjustableTime::new(base);
        let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
        let dc_key = certified_key(&chain)
            .with_delegated_credential(dc, key)
            .unwrap();

        let mut client_config = dc_client(&chain);
        client_config.time_provider = client_clock;
        let client_config = Arc::new(client_config);

        let mut delegated_server = server_with(dc_key);
        delegated_server.time_provider = server_clock.clone();
        let mut certificate_server = server_with(certified_key(&chain));
        certificate_server.time_provider = server_clock.clone();
        if stateless {
            let ticketer = prov::Ticketer::new().unwrap();
            delegated_server.ticketer = ticketer.clone();
            delegated_server.session_storage =
                Arc::new(browntls::server::NoServerSessionStorage {});
            certificate_server.ticketer = ticketer;
            certificate_server.session_storage =
                Arc::new(browntls::server::NoServerSessionStorage {});
        } else {
            let cache: Arc<dyn browntls::server::StoresServerSessions> =
                browntls::server::ServerSessionMemoryCache::new(16);
            delegated_server.session_storage = cache.clone();
            certificate_server.session_storage = cache;
        }
        let delegated_server = Arc::new(delegated_server);
        let certificate_server = Arc::new(certificate_server);

        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(delegated_server).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        take_tickets(&mut client, &mut server);

        // The first-generation ticket resumes and produces descendant tickets.
        server_clock.set(seconds_after(base, 30));
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(certificate_server.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        take_tickets(&mut client, &mut server);

        // A descendant remains valid immediately before the deadline.
        server_clock.set(seconds_after(base, 59));
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(certificate_server.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        take_tickets(&mut client, &mut server);

        // Only the server clock reaches the deadline, proving that it rejects
        // the newest descendant rather than relying on the client-side check.
        server_clock.set(expiry);
        let mut client = ClientConnection::new(client_config, server_name()).unwrap();
        let mut server = ServerConnection::new(certificate_server).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    }
}

#[test]
fn server_sends_no_ticket_after_delegated_credential_deadline() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let server_clock = AdjustableTime::new(base);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let mut client_config = dc_client(&chain);
    client_config.time_provider = AdjustableTime::new(base);
    let mut server_config = server_with(
        certified_key(&chain)
            .with_delegated_credential(dc.clone(), key)
            .unwrap(),
    );
    server_config.time_provider = server_clock.clone();

    let (mut client, mut server) = connect(client_config, server_config);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.delegated_credential(), Some(&dc));

    server_clock.set(expiry);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(!server.is_handshaking());
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.tls13_tickets_received(), 0);
}

#[test]
fn client_discards_ticket_received_at_delegated_credential_deadline() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let mut client_config = dc_client(&chain);
    client_config.time_provider = client_clock.clone();
    let client_config = Arc::new(client_config);
    let mut server_config = server_with(
        certified_key(&chain)
            .with_delegated_credential(dc, key)
            .unwrap(),
    );
    server_config.time_provider = AdjustableTime::new(base);
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(!client.is_handshaking() && !server.is_handshaking());

    client_clock.set(expiry);
    assert!(transfer(&mut server, &mut client) > 0);
    client.process_new_packets().unwrap();
    assert_eq!(client.tls13_tickets_received(), 0);

    // Rewinding the clock proves no ticket was retained for a later offer.
    client_clock.set(base);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
fn server_rejects_external_psk_ticket_at_delegated_credential_deadline() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let client_clock = AdjustableTime::new(base);
    let server_clock = AdjustableTime::new(base);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let psk =
        || ExternalPsk::new(b"combined".to_vec(), vec![0x42; 32], HashAlgorithm::SHA256).unwrap();
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let certified = certified_key(&chain)
        .with_delegated_credential(dc.clone(), key)
        .unwrap();

    let mut first_client = dc_client(&chain);
    first_client.time_provider = client_clock;
    first_client.external_psks = vec![Arc::new(psk())];
    first_client.cert_with_extern_psk = true;
    first_client.require_cert_with_extern_psk = true;
    let mut resumed_client = first_client.clone();
    resumed_client.cert_with_extern_psk = false;
    resumed_client.require_cert_with_extern_psk = false;

    let mut first_server = server_with(certified.clone());
    first_server.time_provider = server_clock.clone();
    first_server.session_storage = cache.clone();
    first_server.external_psks = Some(Arc::new(vec![Arc::new(psk())]));
    first_server.cert_with_extern_psk = true;
    let mut resumed_server = server_with(certified);
    resumed_server.time_provider = server_clock.clone();
    resumed_server.session_storage = cache;
    resumed_server.external_psks = Some(Arc::new(vec![Arc::new(psk())]));
    let resumed_client = Arc::new(resumed_client);
    let resumed_server = Arc::new(resumed_server);

    let (mut client, mut server) = connect(first_client, first_server);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.delegated_credential(), Some(&dc));
    take_tickets(&mut client, &mut server);

    server_clock.set(seconds_after(base, 59));
    let mut client = ClientConnection::new(resumed_client.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(resumed_server.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    take_tickets(&mut client, &mut server);

    // The client still offers the ticket, while the server rejects it and
    // falls through to the external PSK at the exact deadline.
    server_clock.set(expiry);
    let mut client = ClientConnection::new(resumed_client, server_name()).unwrap();
    let mut server = ServerConnection::new(resumed_server).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"combined"[..]));
}
