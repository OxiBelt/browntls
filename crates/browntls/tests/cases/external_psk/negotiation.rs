// Cases included by `cases/external_psk.rs`, which holds the imports and the
// shared helpers: PSK-only handshakes, PSK selection and its restrictions,
// configuration checks, a ClientHello without signature_algorithms and
// when the identity is reported.

#[test]
fn psk_only_handshake_sends_no_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"client-1", HashAlgorithm::SHA256)]),
        psk_only_server(vec![psk(b"client-1", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    // The server prefers AES-256-GCM-SHA384, but must pick a suite the
    // SHA-256 PSK can be used with (RFC 9846 §4.3.11).
    assert_eq!(suite_of(&client), CipherSuite::TLS13_AES_128_GCM_SHA256);
    assert_eq!(suite_of(&server), CipherSuite::TLS13_AES_128_GCM_SHA256);
    assert_eq!(client.external_psk_identity(), Some(&b"client-1"[..]));
    assert_eq!(server.external_psk_identity(), Some(&b"client-1"[..]));
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert!(client.peer_certificates().is_none());
    assert!(server.peer_certificates().is_none());
    // psk_dhe_ke: an (EC)DHE exchange always happens.
    assert!(client.negotiated_key_exchange_group().is_some());
    exchange_data(&mut client, &mut server);
}

#[test]
fn every_suite_with_a_pinned_psk() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in prov::ALL_CIPHER_SUITES.iter().filter_map(|s| s.tls13()) {
        let hash = suite.common.hash_provider.algorithm();
        let pinned = || psk(b"pinned", hash).with_cipher_suite(suite.common.suite);
        let mut provider = prov::default_provider();
        provider.cipher_suites = prov::ALL_CIPHER_SUITES.to_vec();
        let provider = Arc::new(provider);
        let (mut client, mut server) = connect(
            client_with_provider(&chain, vec![pinned()], provider.clone()),
            psk_only_server_with_provider(vec![pinned()], provider),
        );
        do_handshake(&mut client, &mut server)
            .unwrap_or_else(|e| panic!("{:?}: {e}", suite.common.suite));
        assert_eq!(suite_of(&server), suite.common.suite);
        assert_eq!(server.external_psk_identity(), Some(&b"pinned"[..]));
        exchange_data(&mut client, &mut server);
    }
}

#[test]
fn sha384_psk_selects_a_sha384_suite() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"k384", HashAlgorithm::SHA384)]),
        psk_only_server(vec![psk(b"k384", HashAlgorithm::SHA384)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(suite_of(&server), CipherSuite::TLS13_AES_256_GCM_SHA384);
    exchange_data(&mut client, &mut server);
}

#[test]
fn hash_mismatch_is_not_selected() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
        psk_only_server(vec![psk(b"k", HashAlgorithm::SHA384)]),
    );
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::NoUsablePskForServerWithoutCertificate)
    );
    assert_eq!(
        client_res.unwrap_err(),
        Error::AlertReceived(AlertDescription::HandshakeFailure)
    );
}

#[test]
fn wrong_key_fails_the_binder_with_decrypt_error() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let wrong = ExternalPsk::new(b"client-1".to_vec(), vec![7; 32], HashAlgorithm::SHA256).unwrap();
    let (mut client, mut server) = connect(
        client_with(&chain, vec![wrong]),
        psk_only_server(vec![psk(b"client-1", HashAlgorithm::SHA256)]),
    );
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::IncorrectBinder)
    );
    assert_eq!(
        client_res.unwrap_err(),
        Error::AlertReceived(AlertDescription::DecryptError)
    );
}

#[test]
fn unknown_identity_fails_on_a_psk_only_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"stranger", HashAlgorithm::SHA256)]),
        psk_only_server(vec![psk(b"client-1", HashAlgorithm::SHA256)]),
    );
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::NoUsablePskForServerWithoutCertificate)
    );
    assert_eq!(
        client_res.unwrap_err(),
        Error::AlertReceived(AlertDescription::HandshakeFailure)
    );
}

#[test]
fn client_without_psk_fails_on_a_psk_only_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, Vec::new()),
        psk_only_server(vec![psk(b"client-1", HashAlgorithm::SHA256)]),
    );
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert!(server_res.is_err());
}

#[test]
fn unknown_identity_falls_back_to_the_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"stranger", HashAlgorithm::SHA256)]),
        cert_and_psk_server(&chain, vec![psk(b"client-1", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), None);
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    // Without a PSK the server keeps its own suite preference.
    assert_eq!(suite_of(&server), CipherSuite::TLS13_AES_256_GCM_SHA384);
    exchange_data(&mut client, &mut server);
}

#[test]
fn server_with_certificate_prefers_the_psk() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"client-1", HashAlgorithm::SHA256)]),
        cert_and_psk_server(&chain, vec![psk(b"client-1", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), Some(&b"client-1"[..]));
    assert!(client.peer_certificates().is_none());
    exchange_data(&mut client, &mut server);
}

#[test]
fn server_picks_the_first_identity_it_knows() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(
            &chain,
            vec![
                psk(b"unknown", HashAlgorithm::SHA256),
                psk(b"second", HashAlgorithm::SHA384),
                psk(b"third", HashAlgorithm::SHA256),
            ],
        ),
        psk_only_server(vec![
            psk(b"third", HashAlgorithm::SHA256),
            psk(b"second", HashAlgorithm::SHA384),
        ]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.external_psk_identity(), Some(&b"second"[..]));
    assert_eq!(client.external_psk_identity(), Some(&b"second"[..]));
    assert_eq!(suite_of(&client), CipherSuite::TLS13_AES_256_GCM_SHA384);
    exchange_data(&mut client, &mut server);
}

#[test]
fn identities_past_the_sixteenth_are_ignored() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut offered: Vec<ExternalPsk> = (0..16)
        .map(|i| psk(format!("unknown-{i}").as_bytes(), HashAlgorithm::SHA256))
        .collect();
    offered.push(psk(b"client-1", HashAlgorithm::SHA256));
    let (mut client, mut server) = connect(
        client_with(&chain, offered),
        psk_only_server(vec![psk(b"client-1", HashAlgorithm::SHA256)]),
    );
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::NoUsablePskForServerWithoutCertificate)
    );
}

#[test]
fn server_name_restrictions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let localhost = DnsName::try_from("localhost").unwrap().to_owned();
    let other = DnsName::try_from("other.example").unwrap().to_owned();

    // Both sides restricted to the name in use.
    let (mut client, mut server) = connect(
        client_with(
            &chain,
            vec![psk(b"k", HashAlgorithm::SHA256).with_server_name(localhost.clone())],
        ),
        psk_only_server(vec![
            psk(b"k", HashAlgorithm::SHA256).with_server_name(localhost),
        ]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.external_psk_identity(), Some(&b"k"[..]));

    // The client does not offer a key restricted to another server.
    let (mut client, mut server) = connect(
        client_with(
            &chain,
            vec![psk(b"k", HashAlgorithm::SHA256).with_server_name(other.clone())],
        ),
        cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.external_psk_identity(), None);

    // The server does not accept a key restricted to another name.
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
        cert_and_psk_server(
            &chain,
            vec![psk(b"k", HashAlgorithm::SHA256).with_server_name(other)],
        ),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.external_psk_identity(), None);
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
}

#[test]
fn alpn_restrictions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let h2 = b"h2".to_vec();
    let http11 = b"http/1.1".to_vec();

    let client = |protocols: Vec<Vec<u8>>, key: ExternalPsk| {
        let mut config = client_with(&chain, vec![key]);
        config.alpn_protocols = protocols;
        config
    };
    let server = |protocols: Vec<Vec<u8>>, key: ExternalPsk| {
        let mut config = cert_and_psk_server(&chain, vec![key]);
        config.alpn_protocols = protocols;
        config
    };

    // Matching restriction: the PSK is used.
    let (mut c, mut s) = connect(
        client(
            vec![h2.clone()],
            psk(b"k", HashAlgorithm::SHA256).with_alpn_protocol(h2.clone()),
        ),
        server(
            vec![h2.clone()],
            psk(b"k", HashAlgorithm::SHA256).with_alpn_protocol(h2.clone()),
        ),
    );
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(s.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(c.alpn_protocol(), Some(&b"h2"[..]));

    // The server negotiates another protocol, so does not select the key.
    let (mut c, mut s) = connect(
        client(
            vec![h2.clone(), http11.clone()],
            psk(b"k", HashAlgorithm::SHA256),
        ),
        server(
            vec![http11.clone()],
            psk(b"k", HashAlgorithm::SHA256).with_alpn_protocol(h2.clone()),
        ),
    );
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(s.external_psk_identity(), None);

    // A client that restricts the key refuses a server that uses it with
    // another protocol.
    let (mut c, mut s) = connect(
        client(
            vec![h2.clone(), http11.clone()],
            psk(b"k", HashAlgorithm::SHA256).with_alpn_protocol(h2.clone()),
        ),
        server(vec![http11], psk(b"k", HashAlgorithm::SHA256)),
    );
    let (client_res, _) = do_handshake_until_error(&mut c, &mut s);
    assert_eq!(
        client_res.unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::SelectedExternalPskWithOtherAlpn)
    );
}

#[test]
fn psk_after_hello_retry_request() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_provider = tls13_provider(
        None,
        Some(&[prov::kx_group::X25519, prov::kx_group::SECP256R1]),
    );
    let server_provider = tls13_provider(None, Some(&[prov::kx_group::SECP256R1]));
    let (mut client, mut server) = connect(
        client_with_provider(
            &chain,
            vec![
                psk(b"k384", HashAlgorithm::SHA384),
                psk(b"k256", HashAlgorithm::SHA256),
            ],
            client_provider,
        ),
        psk_only_server_with_provider(vec![psk(b"k256", HashAlgorithm::SHA256)], server_provider),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp256r1
    );
    assert_eq!(client.external_psk_identity(), Some(&b"k256"[..]));
    exchange_data(&mut client, &mut server);
}

// ------------------------------------------------------------ configuration

#[test]
fn short_keys_are_refused() {
    assert!(ExternalPsk::new(b"id".to_vec(), vec![1; 15], HashAlgorithm::SHA256).is_err());
    assert!(ExternalPsk::new(b"id".to_vec(), vec![1; 16], HashAlgorithm::SHA256).is_ok());
    assert!(ExternalPsk::new(b"id".to_vec(), vec![1; 32], HashAlgorithm::SHA512).is_err());
    // The key does not show in debug output.
    let debug = format!("{:?}", psk(b"id", HashAlgorithm::SHA256));
    assert!(!debug.contains("42, 42") && !debug.contains("4242"));
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_only_server_without_certificate_refuses() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_config(&chain);
    client_config.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))];
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_external_psks_only(Arc::new(vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))]));
    let (mut client, mut server) = connect(client_config, server_config);
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert!(server_res.is_err());
}

// ------------------------------------------- ClientHello without sigalgs

/// `HKDF-Expand-Label(prk, label, context, out.len())`.
fn expand_label(
    expander: &dyn browntls::crypto::tls13::HkdfExpander,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) {
    let len = (out.len() as u16).to_be_bytes();
    let label_len = [(6 + label.len()) as u8];
    let context_len = [context.len() as u8];
    expander
        .expand_slice(
            &[&len, &label_len, b"tls13 ", label, &context_len, context],
            out,
        )
        .unwrap();
}

/// RFC 9846 §4.3.3: a client that offers only TLS 1.3 and a PSK may leave
/// out signature_algorithms. The ClientHello of a browntls client is edited
/// (its signature_algorithms renamed to an unknown extension) and its binder
/// recomputed here, independently of the library's binder code.
#[test]
fn psk_client_hello_without_signature_algorithms() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let provider = tls13_provider(Some(&[prov::cipher_suite::TLS13_AES_128_GCM_SHA256]), None);
    let mut client = ClientConnection::new(
        Arc::new(client_with_provider(
            &chain,
            vec![psk(b"client-1", HashAlgorithm::SHA256)],
            provider.clone(),
        )),
        server_name(),
    )
    .unwrap();
    let mut record = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut record).unwrap();
    }

    // Record header (5), handshake header (4), version (2), random (32),
    // session ID, suites, compression, then the extensions.
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(record[at]);
    at += 2 + usize::from(u16::from_be_bytes([record[at], record[at + 1]]));
    at += 1 + usize::from(record[at]);
    at += 2;
    let mut renamed = false;
    while at + 4 <= record.len() {
        let typ = u16::from_be_bytes([record[at], record[at + 1]]);
        let len = usize::from(u16::from_be_bytes([record[at + 2], record[at + 3]]));
        if typ == 0x000d {
            record[at..at + 2].copy_from_slice(&[0x0a, 0x0a]);
            renamed = true;
        }
        at += 4 + len;
    }
    assert!(renamed);

    // One SHA-256 binder: u16 list length, u8 binder length, 32 bytes.
    let suite = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let hash = suite.common.hash_provider;
    let binders_len = 2 + 1 + 32;
    let truncated = &record[5..record.len() - binders_len];
    let early = suite.hkdf_provider.extract_from_secret(None, &KEY);
    let mut binder_key = [0u8; 32];
    expand_label(
        &*early,
        b"ext binder",
        hash.hash(&[]).as_ref(),
        &mut binder_key,
    );
    let binder_key = browntls::crypto::tls13::OkmBlock::new(&binder_key);
    let mut finished_key = [0u8; 32];
    expand_label(
        &*suite.hkdf_provider.expander_for_okm(&binder_key),
        b"finished",
        &[],
        &mut finished_key,
    );
    let binder = suite.hkdf_provider.hmac_sign(
        &browntls::crypto::tls13::OkmBlock::new(&finished_key),
        hash.hash(truncated).as_ref(),
    );
    let end = record.len();
    record[end - 32..].copy_from_slice(binder.as_ref());

    let mut server = ServerConnection::new(Arc::new(psk_only_server_with_provider(
        vec![psk(b"client-1", HashAlgorithm::SHA256)],
        provider,
    )))
    .unwrap();
    let mut input = &record[..];
    while !input.is_empty() {
        server.read_tls(&mut input).unwrap();
    }
    server.process_new_packets().unwrap();
    // A server without a certificate answers only by selecting the PSK; the
    // identity is reported once the client's Finished verifies.
    assert!(server.wants_write());
    assert_eq!(server.external_psk_identity(), None);

    // A server with a certificate and no external PSKs still requires the
    // extension.
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    let mut input = &record[..];
    while !input.is_empty() {
        server.read_tls(&mut input).unwrap();
    }
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::SignatureAlgorithmsExtensionRequired)
    );
}

// ---------------------------------------------- reported after Finished

#[test]
fn identity_is_reported_once_the_peer_finished() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
        psk_only_server(vec![psk(b"k", HashAlgorithm::SHA256)]),
    );
    // ClientHello: the server selects the key and sends its flight up to
    // its Finished, but has not seen the client's Finished.
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(server.is_handshaking());
    assert_eq!(server.external_psk_identity(), None);

    // The client verifies the server's Finished.
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(server.external_psk_identity(), None);

    // The server verifies the client's Finished.
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(!server.is_handshaking());
    assert_eq!(server.external_psk_identity(), Some(&b"k"[..]));
}

#[test]
fn identity_is_not_reported_when_the_peer_finished_fails() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
        psk_only_server(vec![psk(b"k", HashAlgorithm::SHA256)]),
    );
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    // Corrupt the server's last record (its Finished, encrypted): the client
    // cannot authenticate the server and reports no identity.
    let mut flight = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut flight).unwrap();
    }
    let last = flight.len() - 1;
    flight[last] ^= 1;
    let mut cursor = &flight[..];
    while !cursor.is_empty() {
        client.read_tls(&mut cursor).unwrap();
    }
    assert!(client.process_new_packets().is_err());
    assert_eq!(client.external_psk_identity(), None);
}
