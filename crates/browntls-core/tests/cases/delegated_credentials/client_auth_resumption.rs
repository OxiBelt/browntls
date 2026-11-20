// Cases included by `cases/delegated_credentials.rs`, which holds the imports
// and the shared helpers (and `client_auth.rs`, those of client
// authentication): resumption of sessions in which the client authenticated
// with a delegated credential, which must not outlive it (RFC 9345 §4.1.3),
// and a credential expiring while a flight is under way.

/// A client whose credential, for `chain`, expires at `expiry`; it reads
/// `client_clock` and authenticates through the returned resolver.
fn expiring_client(
    server_chain: &Chain,
    chain: &Chain,
    expiry: UnixTime,
    client_clock: Arc<AdjustableTime>,
) -> (
    Arc<ClientConfig>,
    Arc<SwitchingResolver>,
    DelegatedCredential,
) {
    let (dc, key) = issue_for(Side::Client, chain, SignatureScheme::ED25519, expiry);
    let resolver = SwitchingResolver::new(with_client_credentials(chain, vec![(dc.clone(), key)]));
    let mut config = client_switching(server_chain, resolver.clone());
    config.time_provider = client_clock;
    (Arc::new(config), resolver, dc)
}

/// A server accepting client credentials for `chain`, reading
/// `server_clock`, with stateless tickets or a session cache.
fn resuming_server(
    server_chain: &Chain,
    chain: &Chain,
    server_clock: Arc<AdjustableTime>,
    stateless: bool,
) -> ServerConfig {
    let mut config = dc_server(server_chain, PinnedClientVerifier::new(chain, true));
    config.time_provider = server_clock;
    if stateless {
        config.ticketer = prov::Ticketer::new().unwrap();
        config.session_storage = Arc::new(browntls_core::server::NoServerSessionStorage {});
    } else {
        config.session_storage = browntls_core::server::ServerSessionMemoryCache::new(16);
    }
    config
}

/// Runs a full handshake and a resumption; returns the resumed pair.
fn handshake_and_resume(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.client_delegated_credential().is_some());
    take_tickets(&mut client, &mut server);
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    (client, server)
}

#[test]
fn resumed_session_keeps_the_client_certificate_but_not_the_credential() {
    init_logging();
    for stateless in [false, true] {
        let server_chain = server_chain(KeyType::EcdsaP256);
        let chain = delegation_client_chain(KeyType::EcdsaP256);
        let clock = AdjustableTime::new(now());
        let (client_config, _, _) =
            expiring_client(&server_chain, &chain, shifted(3600), clock.clone());
        let server_config = Arc::new(resuming_server(&server_chain, &chain, clock, stateless));
        let (mut client, mut server) = handshake_and_resume(&client_config, &server_config);
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        assert!(server.client_delegated_credential().is_none());
        assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"resumed"),
            b"resumed"
        );
    }
}

#[test]
fn server_rejects_ticket_at_client_credential_deadline() {
    init_logging();
    for stateless in [false, true] {
        let server_chain = server_chain(KeyType::EcdsaP256);
        let chain = delegation_client_chain(KeyType::EcdsaP256);
        let base = now();
        let expiry = seconds_after(base, 60);
        let client_clock = AdjustableTime::new(base);
        let server_clock = AdjustableTime::new(base);
        let (mut client_config, resolver, _) =
            expiring_client(&server_chain, &chain, expiry, client_clock);
        let mut server_config =
            resuming_server(&server_chain, &chain, server_clock.clone(), stateless);
        if !stateless {
            Arc::get_mut(&mut client_config).unwrap().enable_early_data = true;
            server_config.max_early_data_size = 1024;
        }
        let server_config = Arc::new(server_config);

        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        take_tickets(&mut client, &mut server);

        // The ticket resumes, then its descendant immediately before the
        // deadline.
        for at in [30, 59] {
            server_clock.set(seconds_after(base, at));
            let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(
                server.handshake_kind(),
                Some(HandshakeKind::Resumed),
                "{at}"
            );
            take_tickets(&mut client, &mut server);
        }

        // Only the server clock reaches the deadline: the client still
        // offers the descendant, and the server passes over it. The
        // certificate key authenticates the full handshake instead.
        server_clock.set(expiry);
        resolver.set(Some(certified_key(&chain)));
        let mut client = ClientConnection::new(client_config, server_name()).unwrap();
        if !stateless {
            client
                .early_data()
                .expect("the descendant ticket permits early data to the client")
                .write_all(b"early data")
                .unwrap();
        }
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
        assert!(!client.is_early_data_accepted());
        assert!(server.early_data().is_none());
        assert!(server.client_delegated_credential().is_none());
        assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);
    }
}

/// A session the client authenticated with a credential is not resumed by
/// a configuration that no longer accepts client credentials, though it
/// shares the session store.
#[test]
fn client_credential_session_needs_delegated_credentials_enabled() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let clock = AdjustableTime::new(now());
    let (client_config, _, _) =
        expiring_client(&server_chain, &chain, shifted(3600), clock.clone());
    let enabled = Arc::new(resuming_server(&server_chain, &chain, clock, false));
    let mut disabled = (*enabled).clone();
    disabled.enable_delegated_credentials = false;
    let disabled = Arc::new(disabled);

    // The configuration that accepts them resumes.
    let (mut client, mut server) = handshake_and_resume(&client_config, &enabled);
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    take_tickets(&mut client, &mut server);

    // Without them the client is authenticated afresh, with its
    // certificate key (the CertificateRequest has no extension).
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(disabled).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert!(server.client_delegated_credential().is_none());
    assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);
}

/// The announced ticket lifetime ends at the client credential's expiry:
/// a client whose clock passes it no longer offers the ticket, which it
/// otherwise would (as it does without a credential). The client keeps a
/// ticket through the last second of its lifetime, so the check is one
/// second past the deadline.
#[test]
fn ticket_lifetime_is_capped_by_the_client_credential() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    for (with_credential, after, expected) in [
        (true, 59, HandshakeKind::Resumed),
        (true, 61, HandshakeKind::Full),
        (false, 61, HandshakeKind::Resumed),
    ] {
        let base = now();
        let client_clock = AdjustableTime::new(base);
        // The server's clock stays at `base`, where the ticket is valid.
        let server_clock = AdjustableTime::new(base);
        let (client_config, resolver, _) = expiring_client(
            &server_chain,
            &chain,
            seconds_after(base, 60),
            client_clock.clone(),
        );
        if !with_credential {
            resolver.set(Some(certified_key(&chain)));
        }
        let server_config = Arc::new(resuming_server(&server_chain, &chain, server_clock, false));
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            server.client_delegated_credential().is_some(),
            with_credential
        );
        take_tickets(&mut client, &mut server);

        // Past the deadline the client's credential is expired by its own
        // clock, so a full handshake uses the certificate key.
        client_clock.set(seconds_after(base, after));
        let mut client = ClientConnection::new(client_config, server_name()).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            server.handshake_kind(),
            Some(expected),
            "{with_credential} {after}"
        );
    }
}

/// The server's clock reaches the deadline of the credential that
/// authenticated the resumed session between its flight and the client's
/// Finished: it aborts (RFC 9345 §4.1.3).
#[test]
fn resumption_expiring_before_client_finished_is_aborted() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let base = now();
    let expiry = seconds_after(base, 60);
    let server_clock = AdjustableTime::new(base);
    let (client_config, _, _) =
        expiring_client(&server_chain, &chain, expiry, AdjustableTime::new(base));
    let server_config = Arc::new(resuming_server(
        &server_chain,
        &chain,
        server_clock.clone(),
        false,
    ));
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);

    server_clock.set(seconds_after(base, 59));
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    server_clock.set(expiry);
    transfer(&mut client, &mut server);
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::DelegatedCredentialExpired)
    );
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::AlertReceived(AlertDescription::IllegalParameter)
    );
}

/// The TLS records `conn` has queued, one per element.
fn queued_records<A: browntls_core::SideData>(
    conn: &mut browntls_core::ConnectionCommon<A>,
) -> Vec<Vec<u8>> {
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf).unwrap();
    }
    let mut records = Vec::new();
    let mut rest = &buf[..];
    while !rest.is_empty() {
        let len = 5 + usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        records.push(rest[..len].to_vec());
        rest = &rest[len..];
    }
    records
}

/// Hands `server` the client's queued flight with the server clock at
/// `expiry` only for its last record (the Finished); returns the server's
/// result for that record.
fn finished_at(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    server_clock: &AdjustableTime,
    expiry: UnixTime,
) -> Result<(), Error> {
    let mut records = queued_records(client);
    let finished = records.pop().unwrap();
    assert!(!records.is_empty(), "Certificate and CertificateVerify");
    for record in records {
        server.read_tls(&mut &record[..]).unwrap();
        server.process_new_packets().unwrap();
    }
    server_clock.set(expiry);
    server.read_tls(&mut &finished[..]).unwrap();
    server.process_new_packets().map(|_| ())
}

/// The credential was valid at CertificateVerify and expires before the
/// client's Finished: the server aborts, in the handshake and in a
/// post-handshake answer.
#[test]
fn client_credential_expiring_before_finished_is_aborted() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    for after_handshake in [false, true] {
        let base = now();
        let expiry = seconds_after(base, 60);
        let server_clock = AdjustableTime::new(base);
        let (client_config, _, _) =
            expiring_client(&server_chain, &chain, expiry, AdjustableTime::new(base));
        let mut client_config = (*client_config).clone();
        client_config.enable_post_handshake_auth = true;
        let mut server_config = resuming_server(&server_chain, &chain, server_clock.clone(), false);
        server_config.request_client_auth_after_handshake = after_handshake;
        let (mut client, mut server) = connect(client_config, server_config);

        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        if after_handshake {
            transfer(&mut client, &mut server);
            server.process_new_packets().unwrap();
            assert!(!server.is_handshaking());
            server.request_client_auth().unwrap();
            transfer(&mut server, &mut client);
            client.process_new_packets().unwrap();
        }
        assert_eq!(
            finished_at(&mut client, &mut server, &server_clock, expiry),
            Err(Error::PeerMisbehaved(
                PeerMisbehaved::DelegatedCredentialExpired
            )),
            "{after_handshake}"
        );
        // A post-handshake answer only counts once its Finished verifies.
        if after_handshake {
            assert!(server.client_delegated_credential().is_none());
        }
        transfer(&mut server, &mut client);
        assert_eq!(
            client.process_new_packets().unwrap_err(),
            Error::AlertReceived(AlertDescription::IllegalParameter)
        );
    }
}
