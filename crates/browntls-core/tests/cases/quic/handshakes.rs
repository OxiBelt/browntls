// browntls-to-browntls handshakes: every suite, HelloRetryRequest,
// resumption and 0-RTT.
//
// Included by `cases/quic.rs`, which holds the imports and the handshake
// plumbing.

#[test]
fn handshake_every_quic_suite() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let quic_suites: Vec<_> = prov::ALL_CIPHER_SUITES
        .iter()
        .filter(|s| s.usable_for_quic())
        .collect();
    assert!(quic_suites.len() >= 3);
    for suite in quic_suites {
        let mut provider = prov::default_provider();
        provider.cipher_suites = vec![*suite];
        let client_config = Arc::new(b_client_config_with(&chain, provider));
        let mut client = b_client(&client_config);
        let mut server = b_server(&Arc::new(b_server_config(&chain)));
        handshake(&mut client, &mut server).unwrap();
        assert_full_handshake(&mut client, &mut server);
        // Nothing of the TLS record layer is used.
        assert!(!client.conn.tls_records_pending());
        assert!(!server.conn.tls_records_pending());
    }
}

#[test]
fn handshake_with_hello_retry_request() {
    let chain = server_chain(KeyType::Ed25519);
    let mut client_provider = prov::default_provider();
    client_provider.kx_groups = vec![prov::kx_group::X25519, prov::kx_group::SECP256R1];
    let client_config = Arc::new(b_client_config_with(&chain, client_provider));
    let mut server_provider = prov::default_provider();
    server_provider.kx_groups = vec![prov::kx_group::SECP256R1];
    let mut server_config =
        browntls_core::ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
    server_config.alpn_protocols = vec![ALPN.to_vec()];

    let mut client = b_client(&client_config);
    let mut server = b_server(&Arc::new(server_config));
    handshake(&mut client, &mut server).unwrap();
    // HelloRetryRequest and the second ClientHello stay at Initial.
    assert_eq!(client.sent_at, [INITIAL, INITIAL, HANDSHAKE]);
    assert_eq!(server.sent_at[..3], [INITIAL, INITIAL, HANDSHAKE]);
    client.sent_at.remove(0);
    server.sent_at.remove(0);
    assert_full_handshake(&mut client, &mut server);
}

/// A server allowing 0-RTT and a client that offers it.
fn zero_rtt_configs(
    chain: &Chain,
) -> (
    Arc<browntls_core::ClientConfig>,
    Arc<browntls_core::ServerConfig>,
) {
    let mut client_config = b_client_config(chain);
    client_config.enable_early_data = true;
    let mut server_config = b_server_config(chain);
    server_config.max_early_data_size = u32::MAX;
    (Arc::new(client_config), Arc::new(server_config))
}

#[test]
fn resumption_with_zero_rtt() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (client_config, server_config) = zero_rtt_configs(&chain);

    let mut client = b_client(&client_config);
    assert!(client.conn.zero_rtt().is_none(), "no ticket yet");
    let mut server = b_server(&server_config);
    handshake(&mut client, &mut server).unwrap();
    assert!(!client.conn.resumed());

    let mut client = b_client(&client_config);
    let client_early = client.conn.zero_rtt().expect("0-RTT keys from the ticket");
    // Until the server answers, the parameters remembered with the ticket.
    assert_eq!(client.conn.params().as_deref(), Some(SERVER_PARAMS));
    let mut server = b_server(&server_config);
    assert!(pump(&mut client, &mut server).unwrap());
    let server_early = server.conn.zero_rtt().expect("server accepted 0-RTT");
    assert!(server.conn.early_accepted());
    assert_dirs_match(&client_early, &server_early, "0-RTT");

    handshake(&mut client, &mut server).unwrap();
    assert!(client.conn.resumed() && server.conn.resumed());
    assert!(client.conn.early_accepted());
    // No EndOfEarlyData: the client's Handshake flight is Finished alone.
    assert_full_handshake(&mut client, &mut server);
}

#[test]
fn external_psk_rotation_invalidates_quic_ticket() {
    use browntls_core::crypto::hash::HashAlgorithm;
    use browntls_core::psk::ExternalPsk;

    let chain = server_chain(KeyType::EcdsaP256);
    let psk = |key: u8| {
        Arc::new(
            ExternalPsk::new(
                b"quic-rotation".to_vec(),
                vec![key; 32],
                HashAlgorithm::SHA256,
            )
            .unwrap(),
        )
    };
    let cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(16);

    let mut old_client_config = b_client_config(&chain);
    old_client_config.external_psks = vec![psk(0x42)];
    old_client_config.require_external_psk = true;
    let old_client_config = Arc::new(old_client_config);
    let mut old_server_config = b_server_config(&chain);
    old_server_config.external_psks = Some(Arc::new(vec![psk(0x42)]));
    old_server_config.require_external_psk = true;
    old_server_config.session_storage = cache.clone();

    let mut client = b_client(&old_client_config);
    let mut server = b_server(&Arc::new(old_server_config));
    handshake(&mut client, &mut server).unwrap();
    assert!(!client.conn.resumed() && !server.conn.resumed());

    // Cloning retains the ticket store. Replacing the EPSK makes the client
    // reject that old ticket and authenticate a full QUIC handshake instead.
    let mut new_client_config = (*old_client_config).clone();
    new_client_config.external_psks = vec![psk(0x43)];
    let new_client_config = Arc::new(new_client_config);
    let mut new_server_config = b_server_config(&chain);
    new_server_config.external_psks = Some(Arc::new(vec![psk(0x43)]));
    new_server_config.require_external_psk = true;
    new_server_config.session_storage = cache;
    let new_server_config = Arc::new(new_server_config);

    let mut client = b_client(&new_client_config);
    let mut server = b_server(&new_server_config);
    handshake(&mut client, &mut server).unwrap();
    assert!(!client.conn.resumed() && !server.conn.resumed());

    // A ticket issued after rotation is still resumable over QUIC.
    let mut client = b_client(&new_client_config);
    let mut server = b_server(&new_server_config);
    handshake(&mut client, &mut server).unwrap();
    assert!(client.conn.resumed() && server.conn.resumed());
}

#[test]
fn server_rejecting_zero_rtt_gives_no_keys() {
    let chain = server_chain(KeyType::EcdsaP256);
    let (client_config, server_config) = zero_rtt_configs(&chain);
    let mut client = b_client(&client_config);
    let mut server = b_server(&server_config);
    handshake(&mut client, &mut server).unwrap();

    let mut client = b_client(&client_config);
    assert!(client.conn.zero_rtt().is_some());
    let bq_server = match bq::ServerConnection::new(
        server_config.clone(),
        bq::Version::V1,
        SERVER_PARAMS.to_vec(),
    ) {
        Ok(mut conn) => {
            conn.reject_early_data();
            conn
        }
        Err(e) => panic!("{e:?}"),
    };
    let mut server = Peer::new(bq::Connection::Server(bq_server));
    pump(&mut client, &mut server).unwrap();
    assert!(server.conn.zero_rtt().is_none());
    assert!(!server.conn.early_accepted());
    handshake(&mut client, &mut server).unwrap();
    assert!(client.conn.resumed());
    assert!(!client.conn.early_accepted());
    // The refused 0-RTT keys are gone on the client too.
    assert!(client.conn.zero_rtt().is_none());
    assert_full_handshake(&mut client, &mut server);
}

#[test]
fn server_without_early_data_offers_no_zero_rtt() {
    let chain = server_chain(KeyType::EcdsaP256);
    let (client_config, _) = zero_rtt_configs(&chain);
    let server_config = Arc::new(b_server_config(&chain));
    let mut client = b_client(&client_config);
    let mut server = b_server(&server_config);
    handshake(&mut client, &mut server).unwrap();
    // The ticket does not allow early data.
    let client = b_client(&client_config);
    assert!(client.conn.zero_rtt().is_none());
}
