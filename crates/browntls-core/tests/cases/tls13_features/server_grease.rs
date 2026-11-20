// Cases included by `cases/tls13_features.rs`, which holds the imports and
// the shared helpers: a server with GREASE on (RFC 8701 §4.1,
// `ServerConfig::enable_grease`) and a browntls client, over TLS records.
// What the TLS 1.3 messages look like is checked where they can be read
// unprotected (`cases/quic/grease.rs`, `cases/kernel.rs`).

/// [`pha_server`] with GREASE on.
fn grease_pha_server(server: &Chain, client: &Chain, defer: bool) -> ServerConfig {
    let mut config = pha_server(server, client, true, defer);
    config.enable_grease = true;
    config
}

#[test]
fn client_ignores_server_grease_in_certificate_requests_and_tickets() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    for &key_type in KeyType::SIGNING {
        let client_chain = client_chain(key_type);
        let client_config = Arc::new(pha_client(&server_chain, &client_chain));
        let server_config = Arc::new(grease_pha_server(&server_chain, &client_chain, false));
        for resuming in [false, true] {
            let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            handshake(&mut client, &mut server);
            // The GREASE tickets of the first connection resume the second.
            let kind = if resuming {
                HandshakeKind::Resumed
            } else {
                HandshakeKind::Full
            };
            assert_eq!(client.handshake_kind(), Some(kind), "{key_type:?}");
            assert_eq!(
                server.peer_certificates().unwrap(),
                client_chain.cert_chain()
            );
            // Post-handshake requests carry GREASE values as well.
            for round in 1..=2 {
                post_handshake_auth(&mut client, &mut server)
                    .unwrap_or_else(|e| panic!("{key_type:?}: {e}"));
                assert_eq!(client.post_handshake_auth_responses(), round);
                assert_eq!(
                    server.post_handshake_auth_status(),
                    Some(PostHandshakeAuthStatus::Authenticated)
                );
            }
            assert_eq!(
                send_and_receive(&mut client, &mut server, b"greased"),
                b"greased"
            );
        }
    }
}

/// RFC 8701 §4.1 names TLS 1.3 messages only: a TLS 1.2 CertificateRequest,
/// which is not protected and can be read here, lists no GREASE scheme.
#[cfg(feature = "tls12")]
#[test]
fn server_grease_leaves_tls12_alone() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    let server_config = grease_pha_server(&server_chain, &client_chain, false);
    let (mut client, mut server) = connect(client_config, server_config);

    feed(&mut server, &take_tls(&mut client));
    server.process_new_packets().unwrap();
    let flight = take_tls(&mut server);
    // ServerHello through ServerHelloDone, in handshake records.
    let mut messages = Vec::new();
    let mut at = 0;
    while at < flight.len() {
        assert_eq!(flight[at], 22, "a handshake record");
        let len = usize::from(u16::from_be_bytes([flight[at + 3], flight[at + 4]]));
        messages.extend_from_slice(&flight[at + 5..at + 5 + len]);
        at += 5 + len;
    }
    let messages = grease_wire::handshake_messages(&messages);
    let request = messages.iter().find(|m| m.0 == 13).expect("a request");
    // certificate_types<1..2^8-1>, supported_signature_algorithms<2..2^16-2>
    let schemes = &request.1[1 + usize::from(request.1[0])..];
    let len = usize::from(u16::from_be_bytes([schemes[0], schemes[1]]));
    let schemes = grease_wire::signature_schemes(&schemes[..2 + len]);
    assert!(!schemes.is_empty());
    assert!(
        schemes.iter().all(|s| !grease_wire::is_grease(*s)),
        "{schemes:x?}"
    );

    feed(&mut client, &flight);
    client.process_new_packets().unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"tls 1.2"),
        b"tls 1.2"
    );
}
