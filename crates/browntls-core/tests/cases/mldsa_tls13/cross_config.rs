// Cases included by `cases/mldsa_tls13.rs`, which holds the imports and the
// shared helpers: resumption across configurations with and without the
// opt-in that share a client session store or a server ticketer.

/// A session from an ML-DSA handshake, in a client session store shared
/// with a second configuration without the opt-in: the second
/// configuration does not offer it (a stored session is bound to the
/// verifier that checked it), so it makes a full handshake, which fails
/// against the ML-DSA-only server. The first configuration still resumes.
#[test]
fn client_session_store_shared_with_a_config_without_the_opt_in() {
    use browntls_core::client::Resumption;

    let server = server_id(Alg::Ml(Set::MlDsa65));
    let server_config = Arc::new(server_config(prov::provider_with_ml_dsa(), &server, None));
    let store = Resumption::in_memory_sessions(8);
    let mut opt_in = client_config(
        prov::provider_with_ml_dsa(),
        server_verifier(prov::provider_with_ml_dsa(), &server),
        None,
    );
    opt_in.resumption = store.clone();
    let opt_in = Arc::new(opt_in);
    let mut without = client_config(
        prov::provider(),
        server_verifier(prov::provider(), &server),
        None,
    );
    without.resumption = store;

    let mut c = ClientConnection::new(opt_in.clone(), server_name()).unwrap();
    let mut s = ServerConnection::new(server_config.clone()).unwrap();
    handshake(&mut c, &mut s).unwrap();
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();
    assert!(c.tls13_tickets_received() > 0);

    let mut c = ClientConnection::new(Arc::new(without), server_name()).unwrap();
    let mut s = ServerConnection::new(server_config.clone()).unwrap();
    let hello = common::hello_wire::take_flight(&mut c);
    let types = common::hello_wire::hello_extension_types(&hello, true);
    // pre_shared_key (41): no session offered.
    assert!(!types.contains(&41), "{types:?}");
    assert_eq!(
        feed(&mut s, &hello),
        Err(Error::PeerIncompatible(
            PeerIncompatible::NoSignatureSchemesInCommon
        ))
    );
    assert_eq!(
        pump(&mut s, &mut c),
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );

    let mut c = ClientConnection::new(opt_in, server_name()).unwrap();
    let mut s = ServerConnection::new(server_config).unwrap();
    handshake(&mut c, &mut s).unwrap();
    assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed));
    exchange(&mut c, &mut s);
}

/// A ticket issued after ML-DSA mutual authentication, presented to a
/// second server configuration that shares the ticketer but whose client
/// verifier has no opt-in (and so could not verify the client's chain or
/// signature in a full handshake): the server resumes, without consulting
/// that verifier, and restores the client's ML-DSA chain from the ticket.
/// A configuration's client verifier is not part of what a ticket is
/// checked against; sharing a ticketer shares the authentication.
#[test]
fn ticket_after_ml_dsa_mutual_auth_to_a_config_without_the_opt_in() {
    let server = server_id(Alg::Ml(Set::MlDsa65));
    let client = client_id(Alg::Ml(Set::MlDsa44));
    let ticketer = prov::Ticketer::new().unwrap();
    let opt_in_verifier = client_verifier(prov::provider_with_ml_dsa(), &client, true);
    let mut opt_in = server_config(
        prov::provider_with_ml_dsa(),
        &server,
        Some(opt_in_verifier.clone()),
    );
    opt_in.ticketer = ticketer.clone();
    let plain_verifier = client_verifier(prov::provider(), &client, true);
    let mut without = server_config(
        prov::provider_with_ml_dsa(),
        &server,
        Some(plain_verifier.clone()),
    );
    without.ticketer = ticketer;
    let without = Arc::new(without);
    let client_config = Arc::new(client_config(
        prov::provider_with_ml_dsa(),
        server_verifier(prov::provider_with_ml_dsa(), &server),
        Some(&client),
    ));

    let mut c = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut s = ServerConnection::new(Arc::new(opt_in)).unwrap();
    handshake(&mut c, &mut s).unwrap();
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();
    assert!(c.tls13_tickets_received() > 0);
    assert_eq!(opt_in_verifier.seen(), [SignatureScheme::ML_DSA_44]);

    let mut c = ClientConnection::new(client_config, server_name()).unwrap();
    let mut s = ServerConnection::new(without.clone()).unwrap();
    handshake(&mut c, &mut s).unwrap();
    assert_eq!(s.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(s.peer_certificates().unwrap(), client.chain);
    assert!(plain_verifier.seen().is_empty());
    exchange(&mut c, &mut s);

    // A full handshake with that configuration fails: its
    // CertificateRequest lists no ML-DSA scheme, so the client's ML-DSA key
    // cannot answer it.
    let fresh = Arc::new(client_config_without_resumption(&server, &client));
    let mut c = ClientConnection::new(fresh, server_name()).unwrap();
    let mut s = ServerConnection::new(without).unwrap();
    let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
    assert_eq!(server_res, Err(Error::NoCertificatesPresented));
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::CertificateRequired))
    );
    assert!(plain_verifier.seen().is_empty());
}

fn client_config_without_resumption(server: &Identity, client: &Identity) -> ClientConfig {
    let mut config = client_config(
        prov::provider_with_ml_dsa(),
        server_verifier(prov::provider_with_ml_dsa(), server),
        Some(client),
    );
    config.resumption = browntls_core::client::Resumption::disabled();
    config
}
