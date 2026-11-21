#[test]
fn rfc9973_strict_server_requires_the_combination() {
    let chain = server_chain(KeyType::EcdsaP256);
    let key = || psk(b"rfc9973", HashAlgorithm::SHA256);
    let mut server_config = cert_and_psk_server(&chain, vec![key()]);
    server_config.require_cert_with_extern_psk = true;
    let server_config = Arc::new(server_config);

    for (configured_key, offer) in [
        (Some(key()), false),
        (None, false),
        (Some(psk(b"unknown", HashAlgorithm::SHA256)), true),
    ] {
        let mut config = client_with(&chain, configured_key.into_iter().collect());
        config.cert_with_extern_psk = offer;
        let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        let (_, result) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            result.unwrap_err(),
            Error::PeerIncompatible(PeerIncompatible::CertWithExternPskRequired)
        );
        assert!(!server.negotiated_cert_with_extern_psk());
    }

    let mut config = client_with(&chain, vec![key()]);
    config.cert_with_extern_psk = true;
    let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    let mut acceptor = browntls_core::server::Acceptor::default();
    let hello = hello_wire::take_flight(&mut client);
    acceptor.read_tls(&mut hello.as_slice()).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    assert!(accepted.client_hello().offers_cert_with_extern_psk());
    let mut server = accepted.into_connection(server_config).unwrap();
    assert!(!client.negotiated_cert_with_extern_psk());
    assert!(!server.negotiated_cert_with_extern_psk());
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.negotiated_cert_with_extern_psk());
    assert!(server.negotiated_cert_with_extern_psk());
    assert_eq!(client.tls13_tickets_received(), 0);
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    exchange_data(&mut client, &mut server);
}

#[test]
fn rfc9973_resumption_reports_only_the_inherited_psk() {
    let chain = server_chain(KeyType::EcdsaP256);
    let key = || psk(b"rfc9973", HashAlgorithm::SHA256);
    let mut config = client_with(&chain, vec![key()]);
    config.cert_with_extern_psk = true;
    let mut server_config = cert_and_psk_server(&chain, vec![key()]);
    server_config.cert_with_extern_psk = true;
    let server_config = Arc::new(server_config);
    let mut client = ClientConnection::new(Arc::new(config.clone()), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.negotiated_cert_with_extern_psk());
    take_tickets(&mut client, &mut server);

    config.cert_with_extern_psk = false;
    let mut strict_config = (*server_config).clone();
    strict_config.require_cert_with_extern_psk = true;
    let mut client = ClientConnection::new(Arc::new(config.clone()), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(strict_config)).unwrap();
    let (_, result) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        result.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::CertWithExternPskRequired)
    );

    let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(key().identity()));
    assert!(!client.negotiated_cert_with_extern_psk());
    assert!(!server.negotiated_cert_with_extern_psk());
}

#[cfg(feature = "tls12")]
#[test]
fn rfc9973_strict_server_refuses_tls12() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = ClientConfig::builder_with_provider(tls13_provider(None, None))
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut server_config =
        cert_and_psk_server(&chain, vec![psk(b"rfc9973", HashAlgorithm::SHA256)]);
    server_config.require_cert_with_extern_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    let (_, result) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        result.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::CertWithExternPskRequired)
    );
}

#[test]
fn rfc9973_rejects_known_ticket_after_the_selection_limit_without_consuming_it() {
    use hello_wire::{fatal_alert, give, hello_extensions, take_flight};

    let chain = server_chain(KeyType::EcdsaP256);
    for stateless in [false, true] {
        let mut server_config = cert_and_psk_server(&chain, vec![]);
        server_config.cert_with_extern_psk = true;
        if stateless {
            server_config.ticketer = prov::Ticketer::new().unwrap();
        }
        let server_config = Arc::new(server_config);
        let config = Arc::new(client_with(&chain, vec![]));
        let mut client = ClientConnection::new(config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        take_tickets(&mut client, &mut server);

        let mut resuming = ClientConnection::new(config, server_name()).unwrap();
        let resume_hello = take_flight(&mut resuming);
        let (_, offer) = hello_extensions(&resume_hello, true).pop().unwrap();
        let len = usize::from(u16::from_be_bytes([offer[2], offer[3]]));
        let ticket = &offer[4..4 + len];

        let keys = (0..16)
            .map(|index| psk(&[index], HashAlgorithm::SHA256))
            .chain(core::iter::once(psk(ticket, HashAlgorithm::SHA256)))
            .collect();
        let mut config = client_with(&chain, keys);
        config.cert_with_extern_psk = true;
        let mut bad = ClientConnection::new(Arc::new(config), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        give(&mut server, &take_flight(&mut bad));
        assert_eq!(
            server.process_new_packets().unwrap_err(),
            Error::PeerMisbehaved(PeerMisbehaved::ResumptionPskOfferedWithCertWithExternPsk)
        );
        assert_eq!(
            fatal_alert(&take_flight(&mut server)),
            Some(u8::from(AlertDescription::IllegalParameter))
        );

        let mut server = ServerConnection::new(server_config).unwrap();
        give(&mut server, &resume_hello);
        server.process_new_packets().unwrap();
        do_handshake(&mut resuming, &mut server).unwrap();
        assert_eq!(resuming.handshake_kind(), Some(HandshakeKind::Resumed));
    }
}

#[test]
fn rfc9973_uses_illegal_parameter_for_a_selected_bad_binder() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut config = client_with(
        &chain,
        vec![ExternalPsk::new(b"key".to_vec(), vec![1; 32], HashAlgorithm::SHA256).unwrap()],
    );
    config.cert_with_extern_psk = true;
    let mut server_config = cert_and_psk_server(&chain, vec![psk(b"key", HashAlgorithm::SHA256)]);
    server_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(config, server_config);
    let (client, server) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server.unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::IncorrectBinder)
    );
    assert_eq!(
        client.unwrap_err(),
        Error::AlertReceived(AlertDescription::IllegalParameter)
    );
}
