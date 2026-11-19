// The RFC 9001 rules for TLS (ALPN, transport parameters, no session ID,
// no TLS KeyUpdate, the 0-RTT sentinel, encryption-level boundaries) and
// the configurations QUIC cannot use.
//
// Included by `cases/quic.rs`, which holds the imports and the handshake
// plumbing.

fn b_server_conn(config: browntls::ServerConfig) -> bq::ServerConnection {
    bq::ServerConnection::new(Arc::new(config), bq::Version::V1, SERVER_PARAMS.to_vec()).unwrap()
}

#[test]
fn alpn_is_mandatory() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = Arc::new(b_client_config(&chain));

    // The server shares no protocol with the client.
    let mut server_config = b_server_config(&chain);
    server_config.alpn_protocols = vec![b"other".to_vec()];
    let mut client = b_client(&client_config);
    let mut server = Peer::new(bq::Connection::Server(b_server_conn(server_config)));
    let err = handshake(&mut client, &mut server).unwrap_err();
    assert_eq!(
        err,
        Failed::Server(format!("{:?}", Error::NoApplicationProtocol))
    );
    assert_eq!(
        server.conn.alert(),
        Some(u8::from(AlertDescription::NoApplicationProtocol))
    );
    assert_eq!(
        bq::crypto_error_code(AlertDescription::NoApplicationProtocol),
        0x0178
    );

    // The server has no ALPN configuration.
    let mut client = b_client(&client_config);
    let mut server = Peer::new(bq::Connection::Server(b_server_conn(
        common::server_config(&chain),
    )));
    let err = handshake(&mut client, &mut server).unwrap_err();
    assert_eq!(
        err,
        Failed::Server(format!("{:?}", Error::NoApplicationProtocol))
    );
}

/// The handshake messages in the first TLS record `conn` writes.
fn first_record_body(conn: &mut browntls::ClientConnection) -> Vec<u8> {
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    assert_eq!(out[0], 0x16);
    let len = usize::from(u16::from_be_bytes([out[3], out[4]]));
    out[5..5 + len].to_vec()
}

#[test]
fn quic_server_requires_transport_parameters() {
    let chain = server_chain(KeyType::EcdsaP256);
    // A ClientHello from a plain TLS client: no quic_transport_parameters.
    let mut tls_client =
        browntls::ClientConnection::new(Arc::new(b_client_config(&chain)), server_name()).unwrap();
    let hello = first_record_body(&mut tls_client);
    let mut server = b_server_conn(b_server_config(&chain));
    assert_eq!(
        server.read_hs(&hello).unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::MissingQuicTransportParameters)
    );
    assert_eq!(server.alert(), Some(AlertDescription::MissingExtension));
}

/// The QUIC client's ClientHello.
fn quic_client_hello(config: &Arc<browntls::ClientConfig>) -> Vec<u8> {
    let mut client = bq::ClientConnection::new(
        config.clone(),
        bq::Version::V1,
        server_name(),
        CLIENT_PARAMS.to_vec(),
    )
    .unwrap();
    let mut hello = Vec::new();
    assert!(client.write_hs(&mut hello).is_none());
    hello
}

#[test]
fn tls_server_refuses_transport_parameters() {
    let chain = server_chain(KeyType::EcdsaP256);
    let hello = quic_client_hello(&Arc::new(b_client_config(&chain)));
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&u16::try_from(hello.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&hello);

    let mut server = browntls::ServerConnection::new(Arc::new(b_server_config(&chain))).unwrap();
    server.read_tls(&mut &record[..]).unwrap();
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::QuicTransportParametersWithoutQuic)
    );
    let mut alert = Vec::new();
    server.write_tls(&mut alert).unwrap();
    assert_eq!(
        alert,
        [
            0x15,
            0x03,
            0x03,
            0x00,
            0x02,
            0x02,
            u8::from(AlertDescription::UnsupportedExtension)
        ]
    );
}

#[test]
fn quic_client_hello_has_no_session_id() {
    let chain = server_chain(KeyType::EcdsaP256);
    let hello = quic_client_hello(&Arc::new(b_client_config(&chain)));
    // type(1) length(3) legacy_version(2) random(32) legacy_session_id<0..32>
    assert_eq!(hello[0], 0x01);
    assert_eq!(
        hello[38], 0,
        "legacy_session_id must be empty (RFC 9001 §8.4)"
    );

    // A QUIC server refuses a ClientHello with a session ID.
    let mut patched = hello[..39].to_vec();
    patched[38] = 32;
    patched.extend_from_slice(&[0x11; 32]);
    patched.extend_from_slice(&hello[39..]);
    let len = u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) + 32;
    patched[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
    let mut server = b_server_conn(b_server_config(&chain));
    assert_eq!(
        server.read_hs(&patched).unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::NonEmptySessionIdInQuicClientHello)
    );
    // A QUIC PROTOCOL_VIOLATION, not a TLS alert.
    assert_eq!(server.alert(), None);
}

/// The extension types of a ClientHello handshake message.
fn client_hello_extensions(hello: &[u8]) -> Vec<u16> {
    let u16_at = |i: usize| usize::from(u16::from_be_bytes([hello[i], hello[i + 1]]));
    // type(1) length(3) legacy_version(2) random(32) legacy_session_id<0..32>
    let mut i = 39 + usize::from(hello[38]);
    i += 2 + u16_at(i); // cipher_suites
    i += 1 + usize::from(hello[i]); // legacy_compression_methods
    let end = i + 2 + u16_at(i);
    i += 2;
    let mut types = Vec::new();
    while i < end {
        types.push(u16::from_be_bytes([hello[i], hello[i + 1]]));
        i += 4 + u16_at(i + 2);
    }
    assert_eq!(i, hello.len());
    types
}

#[test]
fn no_record_size_limit() {
    // QUIC has no TLS records: record_size_limit (28), on by default, is
    // neither offered nor acknowledged.
    let chain = server_chain(KeyType::EcdsaP256);
    let config = Arc::new(b_client_config(&chain));
    assert!(config.record_size_limit.is_some());
    let types = client_hello_extensions(&quic_client_hello(&config));
    assert!(!types.contains(&28), "record_size_limit offered");
    let (mut client, mut server) = (
        b_client(&config),
        b_server(&Arc::new(b_server_config(&chain))),
    );
    handshake(&mut client, &mut server).unwrap();
    assert_full_handshake(&mut client, &mut server);
}

#[test]
fn no_zero_rtt_with_external_psk() {
    // 0-RTT needs the server's remembered transport parameters (RFC 9000
    // §7.4.1), which an external PSK does not have.
    use browntls::crypto::hash::HashAlgorithm;
    use browntls::psk::ExternalPsk;

    let chain = server_chain(KeyType::EcdsaP256);
    let psk = Arc::new(
        ExternalPsk::new(b"quic-psk".to_vec(), vec![0x42; 32], HashAlgorithm::SHA256)
            .unwrap()
            .with_cipher_suite(browntls::CipherSuite::TLS13_AES_128_GCM_SHA256)
            .with_alpn_protocol(ALPN.to_vec())
            .with_early_data(u32::MAX),
    );
    let mut client_config = b_client_config(&chain);
    client_config.external_psks = vec![psk.clone()];
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);
    let types = client_hello_extensions(&quic_client_hello(&client_config));
    assert!(types.contains(&41), "pre_shared_key");
    assert!(!types.contains(&42), "early_data offered");

    let mut server_config = b_server_config(&chain);
    server_config.external_psks = Some(Arc::new(vec![psk]));
    server_config.max_early_data_size = u32::MAX;
    let (mut client, mut server) = (b_client(&client_config), b_server(&Arc::new(server_config)));
    assert!(client.conn.zero_rtt().is_none());
    handshake(&mut client, &mut server).unwrap();
    assert!(server.conn.zero_rtt().is_none());
    assert!(!client.conn.early_accepted());
}

#[test]
fn no_post_handshake_client_auth() {
    // RFC 9001 §4.4: no post-handshake client authentication in QUIC.
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let mut client_config =
        browntls::ClientConfig::builder_with_provider(Arc::new(prov::default_provider()))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
            .unwrap();
    client_config.alpn_protocols = vec![ALPN.to_vec()];
    client_config.enable_post_handshake_auth = true;
    let client_config = Arc::new(client_config);

    // The client does not offer post_handshake_auth (49) over QUIC...
    let types = client_hello_extensions(&quic_client_hello(&client_config));
    assert!(types.contains(&57), "quic_transport_parameters");
    assert!(!types.contains(&49), "post_handshake_auth offered");

    // ...and a server deferring client authentication still asks for it in
    // the handshake.
    let mut server_config =
        browntls::ServerConfig::builder_with_provider(Arc::new(prov::default_provider()))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
    server_config.alpn_protocols = vec![ALPN.to_vec()];
    server_config.request_client_auth_after_handshake = true;
    let (mut client, mut server) = (b_client(&client_config), b_server(&Arc::new(server_config)));
    handshake(&mut client, &mut server).unwrap();
    assert!(server.conn.peer_certified());
}

#[test]
fn tls_key_update_is_refused() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = Arc::new(b_client_config(&chain));
    let server_config = Arc::new(b_server_config(&chain));
    let mut client = b_client(&client_config);
    let mut server = b_server(&server_config);
    handshake(&mut client, &mut server).unwrap();

    // KeyUpdate(update_not_requested) at 1-RTT (RFC 9001 §6).
    let key_update = [0x18, 0x00, 0x00, 0x01, 0x00];
    let err = client.conn.read_hs(&key_update).unwrap_err();
    assert_eq!(
        err,
        format!(
            "{:?}",
            Error::PeerMisbehaved(PeerMisbehaved::KeyUpdateReceivedInQuicConnection)
        )
    );
    assert_eq!(
        client.conn.alert(),
        Some(u8::from(AlertDescription::UnexpectedMessage))
    );
    assert_eq!(
        bq::crypto_error_code(AlertDescription::UnexpectedMessage),
        0x010a
    );

    let err = server.conn.read_hs(&key_update).unwrap_err();
    assert_eq!(
        err,
        format!(
            "{:?}",
            Error::PeerMisbehaved(PeerMisbehaved::KeyUpdateReceivedInQuicConnection)
        )
    );
}

#[test]
fn ticket_without_early_data_sentinel_is_refused() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = b_client(&Arc::new(b_client_config(&chain)));
    let mut server = b_server(&Arc::new(b_server_config(&chain)));
    handshake(&mut client, &mut server).unwrap();

    // NewSessionTicket with early_data(max_early_data_size = 1000).
    let body = [
        &[0, 0, 0x0e, 0x10][..], // ticket_lifetime
        &[1, 2, 3, 4],           // ticket_age_add
        &[1, 0],                 // ticket_nonce
        &[0, 2, 0xaa, 0xbb],     // ticket
        &[0, 8, 0, 0x2a, 0, 4, 0, 0, 0x03, 0xe8],
    ]
    .concat();
    let mut nst = vec![0x04, 0, 0, u8::try_from(body.len()).unwrap()];
    nst.extend_from_slice(&body);
    let err = client.conn.read_hs(&nst).unwrap_err();
    assert_eq!(
        err,
        format!(
            "{:?}",
            Error::PeerMisbehaved(PeerMisbehaved::InvalidMaxEarlyDataSize)
        )
    );
    // A QUIC PROTOCOL_VIOLATION, not a TLS alert.
    assert_eq!(client.conn.alert(), None);
}

#[test]
fn bytes_mixing_levels_are_refused() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = bq::ClientConnection::new(
        Arc::new(b_client_config(&chain)),
        bq::Version::V1,
        server_name(),
        CLIENT_PARAMS.to_vec(),
    )
    .unwrap();
    let mut server = b_server_conn(b_server_config(&chain));
    let mut hello = Vec::new();
    client.write_hs(&mut hello);
    server.read_hs(&hello).unwrap();

    // The ServerHello (Initial) and the start of EncryptedExtensions
    // (Handshake) delivered together.
    let mut initial = Vec::new();
    assert!(matches!(
        server.write_hs(&mut initial),
        Some(bq::KeyChange::Handshake { .. })
    ));
    let mut handshake_bytes = Vec::new();
    server.write_hs(&mut handshake_bytes);
    let mut mixed = initial;
    mixed.extend_from_slice(&handshake_bytes[..3]);
    assert_eq!(
        client.read_hs(&mixed).unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::KeyEpochWithPendingFragment)
    );
    // A QUIC PROTOCOL_VIOLATION, not a TLS alert.
    assert_eq!(client.alert(), None);
}

#[test]
fn configurations_quic_cannot_use_are_refused() {
    let chain = server_chain(KeyType::EcdsaP256);

    #[cfg(feature = "tls12")]
    {
        let tls12 = browntls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        assert!(matches!(
            bq::ClientConnection::new(Arc::new(tls12), bq::Version::V1, server_name(), vec![]),
            Err(Error::General(_))
        ));

        let tls12 = browntls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        assert!(matches!(
            bq::ServerConnection::new(Arc::new(tls12), bq::Version::V1, vec![]),
            Err(Error::General(_))
        ));
    }

    // RFC 9001 §4.6.1: max_early_data_size is 0 or 0xffffffff.
    let mut config = b_server_config(&chain);
    config.max_early_data_size = 16384;
    assert!(bq::ServerConnection::new(Arc::new(config), bq::Version::V1, vec![]).is_err());

    // Encrypted Client Hello is not supported over QUIC.
    #[cfg(feature = "native")]
    {
        use browntls::crypto::native::hpke::{
            ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128,
        };
        use browntls::ech::{EchGreaseConfig, EchMode, EchServerConfig, EchServerKey};

        let mut config = b_client_config(&chain);
        config.ech_mode = Some(EchMode::Grease(
            EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap(),
        ));
        assert!(matches!(
            bq::ClientConnection::new(Arc::new(config), bq::Version::V1, server_name(), vec![]),
            Err(Error::General(_))
        ));

        let key = EchServerKey::generate(1, "public.example", 32, ALL_SUPPORTED_SUITES).unwrap();
        let mut config = b_server_config(&chain);
        config.ech = Some(Arc::new(EchServerConfig::new(vec![key]).unwrap()));
        assert!(matches!(
            bq::ServerConnection::new(Arc::new(config), bq::Version::V1, vec![]),
            Err(Error::General(_))
        ));

        // Nor is a split-mode back-end server.
        let mut config = b_server_config(&chain);
        config.ech_backend = true;
        assert!(matches!(
            bq::ServerConnection::new(Arc::new(config), bq::Version::V1, vec![]),
            Err(Error::General(_))
        ));
    }
}
