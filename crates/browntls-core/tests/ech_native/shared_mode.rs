//! Shared mode: one server holds the ECH keys and completes the handshake.

use super::*;
#[cfg(feature = "tls12")]
use browntls_core::ProtocolVersion;

#[test]
fn accepted() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let (mut client, mut server) = connect(
        client_config(&certs, enable(ech.ech_config_list())),
        server_config(&certs, Some(&ech), None),
    );
    assert_eq!(client.ech_status(), EchStatus::Offered);
    assert_accepted(&mut client, &mut server);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
fn accepted_with_every_suite() {
    init_logging();
    let certs = Certs::new();
    for suite in ALL_SUPPORTED_SUITES {
        let key = EchServerKey::generate(1, PUBLIC, 0, &[*suite]).unwrap();
        let ech = Arc::new(EchServerConfig::new(vec![key]).unwrap());
        let client_ech = EchConfig::new(ech.ech_config_list(), &[*suite]).unwrap();
        assert_eq!(client_ech.suite(), suite.suite());
        let (mut client, mut server) = connect(
            client_config(&certs, Some(EchMode::Enable(client_ech))),
            server_config(&certs, Some(&ech), None),
        );
        assert_accepted(&mut client, &mut server);
    }
}

#[test]
fn accepted_after_hello_retry_request() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    // The client's first key share is X25519MLKEM768 or X25519; the server
    // wants P-256.
    let (mut client, mut server) = connect(
        client_config(&certs, enable(ech.ech_config_list())),
        server_config(&certs, Some(&ech), Some(&[prov::kx_group::SECP256R1])),
    );
    assert_accepted(&mut client, &mut server);
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
}

#[test]
fn accepted_with_several_keys_sharing_an_id() {
    init_logging();
    let certs = Certs::new();
    let wanted = server_key(3);
    let ech =
        Arc::new(EchServerConfig::new(vec![server_key(3), server_key(4), wanted.clone()]).unwrap());
    let one = Arc::new(EchServerConfig::new(vec![wanted]).unwrap());
    let (mut client, mut server) = connect(
        client_config(&certs, enable(one.ech_config_list())),
        server_config(&certs, Some(&ech), None),
    );
    assert_accepted(&mut client, &mut server);
}

#[test]
fn resumption_inside_ech() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(9)]).unwrap());
    let mut client_config = client_config(&certs, enable(ech.ech_config_list()));
    client_config.resumption = Resumption::in_memory_sessions(8);
    let client_config = Arc::new(client_config);
    let server_config = Arc::new(server_config(&certs, Some(&ech), None));

    let (mut client, mut server) = connect_arc(client_config.clone(), server_config.clone());
    assert_accepted(&mut client, &mut server);
    // Collect the tickets.
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);

    let (mut client, mut server) = connect_arc(client_config, server_config);
    assert_accepted(&mut client, &mut server);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn rejected_with_retry_configs() {
    init_logging();
    let certs = Certs::new();
    let stale = EchServerConfig::new(vec![server_key(1)]).unwrap();
    let current = Arc::new(EchServerConfig::new(vec![server_key(2)]).unwrap());
    let server = Arc::new(server_config(&certs, Some(&current), None));
    let (mut client, mut server_conn) = connect_arc(
        Arc::new(client_config(&certs, enable(stale.ech_config_list()))),
        server.clone(),
    );
    let err = expect_rejected(&mut client, &mut server_conn);
    assert_eq!(server_conn.ech_status(), EchStatus::Rejected);
    let Error::RejectedEch(rejected) = err else {
        panic!("{err:?}");
    };
    assert!(rejected.can_retry());
    assert_eq!(rejected.retry_configs(), Some(current.ech_config_list()));

    // The retry with the new configuration succeeds.
    let (mut client, mut server_conn) = connect_arc(
        Arc::new(client_config(
            &certs,
            enable(rejected.retry_configs().unwrap()),
        )),
        server,
    );
    assert_accepted(&mut client, &mut server_conn);
}

#[test]
fn rejected_after_hello_retry_request() {
    init_logging();
    let certs = Certs::new();
    let stale = EchServerConfig::new(vec![server_key(1)]).unwrap();
    let current = Arc::new(EchServerConfig::new(vec![server_key(2)]).unwrap());
    let (mut client, mut server) = connect(
        client_config(&certs, enable(stale.ech_config_list())),
        server_config(&certs, Some(&current), Some(&[prov::kx_group::SECP256R1])),
    );
    let err = expect_rejected(&mut client, &mut server);
    assert!(
        matches!(&err, Error::RejectedEch(r) if r.can_retry()),
        "{err:?}"
    );
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
}

#[test]
fn rejected_by_server_without_ech() {
    init_logging();
    let certs = Certs::new();
    let unknown = EchServerConfig::new(vec![server_key(1)]).unwrap();
    let (mut client, mut server) = connect(
        client_config(&certs, enable(unknown.ech_config_list())),
        server_config(&certs, None, None),
    );
    let err = expect_rejected(&mut client, &mut server);
    assert_eq!(server.ech_status(), EchStatus::NotOffered);
    // The server saw only the public name.
    assert_eq!(server.server_name(), Some(PUBLIC));
    let Error::RejectedEch(rejected) = err else {
        panic!("{err:?}");
    };
    assert!(!rejected.can_retry());
    assert_eq!(rejected.retry_configs(), None);
}

#[test]
fn rejection_is_authenticated_with_the_public_name() {
    init_logging();
    let certs = Certs::new();
    let unknown = EchServerConfig::new(vec![server_key(1)]).unwrap();
    // A server that answers every name with the hidden name's certificate.
    let server = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs.secret.cert_chain(), certs.secret.private_key())
        .unwrap();
    let (mut client, mut server) = connect(
        client_config(&certs, enable(unknown.ech_config_list())),
        server,
    );
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert!(
        matches!(client_res, Err(Error::InvalidCertificate(_))),
        "{client_res:?}"
    );
}

#[test]
fn rejected_client_sends_no_certificate() {
    init_logging();
    let certs = Certs::new();
    let client_chain = client_chain(KeyType::EcdsaP256);
    let unknown = EchServerConfig::new(vec![server_key(1)]).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(certs.roots(), provider())
        .build()
        .unwrap();
    let mut client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    client.ech_mode = enable(unknown.ech_config_list());
    let server = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, false))
        .with_cert_resolver(certs.resolver());
    let (mut client, mut server) = connect(client, server);
    let err = expect_rejected(&mut client, &mut server);
    assert!(matches!(err, Error::RejectedEch(_)), "{err:?}");
    assert!(server.peer_certificates().is_none());
}

#[test]
fn grease() {
    init_logging();
    let certs = Certs::new();
    let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(5)]).unwrap());
    for (server_ech, groups, server_status) in [
        (None, None, EchStatus::NotOffered),
        (Some(&ech), None, EchStatus::Rejected),
        (
            None,
            Some(&[prov::kx_group::SECP256R1][..]),
            EchStatus::NotOffered,
        ),
        (
            Some(&ech),
            Some(&[prov::kx_group::SECP256R1][..]),
            EchStatus::Rejected,
        ),
    ] {
        let (mut client, mut server) = connect(
            client_config(&certs, Some(EchMode::Grease(grease.clone()))),
            server_config(&certs, server_ech, groups),
        );
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.ech_status(), EchStatus::Grease);
        assert_eq!(server.ech_status(), server_status);
        assert_eq!(server.server_name(), Some(SECRET));
        assert_eq!(send_and_receive(&mut client, &mut server, b"x"), b"x");
    }
}

#[cfg(feature = "tls12")]
#[test]
fn ech_needs_tls13() {
    let certs = Certs::new();
    let ech = EchServerConfig::new(vec![server_key(1)]).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(certs.roots(), provider())
        .build()
        .unwrap();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    config.ech_mode = enable(ech.ech_config_list());
    assert!(
        ClientConnection::new(Arc::new(config), ServerName::try_from(SECRET).unwrap()).is_err()
    );
}

#[test]
fn config_selection() {
    let key = server_key(1);
    // A list whose first entry has an unsupported version, then ours.
    let mut other = key.ech_config().to_vec();
    other[1] = 0x0c;
    let mut list = Vec::new();
    let len = (other.len() + key.ech_config().len()) as u16;
    list.extend_from_slice(&len.to_be_bytes());
    list.extend_from_slice(&other);
    list.extend_from_slice(key.ech_config());
    let config = EchConfig::new(&list, ALL_SUPPORTED_SUITES).unwrap();
    assert_eq!(config.config_id(), 1);
    assert_eq!(config.public_name().as_ref(), PUBLIC);
    // No suite in common.
    let p256_only: Vec<&'static dyn Hpke> = ALL_SUPPORTED_SUITES
        .iter()
        .copied()
        .filter(|s| s.suite().kem == browntls_core::crypto::hpke::HpkeKem::DHKEM_P256_HKDF_SHA256)
        .collect();
    assert!(EchConfig::new(&list, &p256_only).is_err());
    // Malformed.
    assert!(EchConfig::new(&list[..list.len() - 1], ALL_SUPPORTED_SUITES).is_err());

    // A stored key round-trips through its parts.
    let again = EchServerKey::new(
        key.ech_config(),
        key.private_key().clone(),
        ALL_SUPPORTED_SUITES,
    )
    .unwrap();
    assert_eq!(again.ech_config(), key.ech_config());
    assert!(EchServerKey::generate(1, "192.0.2.1", 0, ALL_SUPPORTED_SUITES).is_err());
    assert!(EchServerKey::generate(1, PUBLIC, 0, &[]).is_err());
    assert!(EchServerConfig::new(Vec::new()).is_err());
}

/// Moves the client's next flight to the server through `edit`.
fn transfer_edited(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    edit: impl FnOnce(&mut Vec<u8>),
) {
    let mut buf = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut buf).unwrap();
    }
    edit(&mut buf);
    let mut offset = 0;
    while offset < buf.len() {
        offset += server.read_tls(&mut &buf[offset..]).unwrap();
    }
}

/// Starts an accepted ECH handshake that takes a HelloRetryRequest, up to
/// the client's second flight.
fn up_to_second_client_hello() -> (ClientConnection, ServerConnection) {
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let (mut client, mut server) = connect(
        client_config(&certs, enable(ech.ech_config_list())),
        server_config(&certs, Some(&ech), Some(&[prov::kx_group::SECP256R1])),
    );
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    (client, server)
}

#[test]
fn server_checks_second_client_hello() {
    init_logging();
    // config_id (after type and cipher suite) changed.
    let (mut client, mut server) = up_to_second_client_hello();
    transfer_edited(&mut client, &mut server, |buf| {
        let at = ech_extension_offset(buf);
        buf[at + 5] ^= 1;
    });
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(browntls_core::PeerMisbehaved::EchChangedOnRetry)
    );

    // The sealed payload (its last byte) altered.
    let (mut client, mut server) = up_to_second_client_hello();
    transfer_edited(&mut client, &mut server, |buf| {
        let at = ech_extension_offset(buf);
        let enc_len = usize::from(u16::from_be_bytes([buf[at + 6], buf[at + 7]]));
        assert_eq!(enc_len, 0, "enc is empty after a retry");
        let payload_len = usize::from(u16::from_be_bytes([buf[at + 8], buf[at + 9]]));
        buf[at + 9 + payload_len] ^= 1;
    });
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(browntls_core::PeerMisbehaved::EchDecryptionFailedOnRetry)
    );
}

#[test]
fn server_rejects_unknown_ech_type() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let (mut client, mut server) = connect(
        client_config(&certs, enable(ech.ech_config_list())),
        server_config(&certs, Some(&ech), None),
    );
    transfer_edited(&mut client, &mut server, |buf| {
        let at = ech_extension_offset(buf);
        buf[at] = 5;
    });
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(browntls_core::PeerMisbehaved::IllegalEchClientHelloType)
    );
}

#[test]
fn tampered_payload_fails_the_handshake() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let (mut client, mut server) = connect(
        client_config(&certs, enable(ech.ech_config_list())),
        server_config(&certs, Some(&ech), None),
    );
    // The last byte of the first ClientHello's ECH payload.
    transfer_edited(&mut client, &mut server, |buf| {
        let at = ech_extension_offset(buf);
        let enc_len = usize::from(u16::from_be_bytes([buf[at + 6], buf[at + 7]]));
        let p = at + 8 + enc_len;
        let payload_len = usize::from(u16::from_be_bytes([buf[p], buf[p + 1]]));
        buf[p + 1 + payload_len] ^= 1;
    });
    // The server cannot decrypt, so it continues with the outer hello...
    server.process_new_packets().unwrap();
    assert_eq!(server.ech_status(), EchStatus::Rejected);
    assert_eq!(server.server_name(), Some(PUBLIC));
    // ...whose transcript now differs from the client's: the handshake
    // fails instead of completing.
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert!(client_res.is_err() || server_res.is_err());
    assert_eq!(client.ech_status(), EchStatus::Rejected);
    assert!(client.is_handshaking());
}

/// The extension types of the HelloRetryRequest at the start of `flight`.
fn hello_retry_request_extensions(flight: &[u8]) -> Vec<u16> {
    // Record header (5), handshake header (4), legacy_version (2), random (32).
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(flight[at]); // legacy_session_id_echo
    at += 2 + 1; // cipher_suite, legacy_compression_method
    let end = at + 2 + usize::from(u16::from_be_bytes([flight[at], flight[at + 1]]));
    at += 2;
    let mut types = Vec::new();
    while at < end {
        types.push(u16::from_be_bytes([flight[at], flight[at + 1]]));
        at += 4 + usize::from(u16::from_be_bytes([flight[at + 2], flight[at + 3]]));
    }
    types
}

#[test]
fn hello_retry_request_stays_stateful_with_ech() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(8)]).unwrap());
    let mut server_config = server_config(&certs, Some(&ech), Some(&[prov::kx_group::SECP256R1]));
    server_config.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
    let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
    for mode in [enable(ech.ech_config_list()), Some(EchMode::Grease(grease))] {
        let (mut client, mut server) =
            connect(client_config(&certs, mode.clone()), server_config.clone());
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        let mut flight = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut flight).unwrap();
        }
        // A cookie cannot carry the HPKE context, so none is sent.
        let types = hello_retry_request_extensions(&flight);
        assert!(types.contains(&0xfe0d), "{types:?}");
        assert!(!types.contains(&44), "{types:?}");
        client.read_tls(&mut &flight[..]).unwrap();
        client.process_new_packets().unwrap();
        if matches!(mode, Some(EchMode::Grease(_))) {
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(client.ech_status(), EchStatus::Grease);
        } else {
            assert_accepted(&mut client, &mut server);
        }
    }
}

#[test]
fn accepted_with_grease_padding_and_an_external_psk() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(10)]).unwrap());
    let psk = Arc::new(
        browntls_core::psk::ExternalPsk::new(
            b"inner psk identity".to_vec(),
            vec![0x42; 32],
            browntls_core::crypto::hash::HashAlgorithm::SHA256,
        )
        .unwrap(),
    );
    let mut client_config = client_config(&certs, enable(ech.ech_config_list()));
    client_config.enable_grease = true;
    client_config.client_hello_padding = browntls_core::client::ClientHelloPadding::AtLeast(1500);
    client_config.external_psks = vec![psk.clone()];
    let mut server_config = server_config(&certs, Some(&ech), None);
    server_config.external_psks = Some(Arc::new(vec![psk]));
    let (mut client, mut server) = connect(client_config, server_config);

    let mut flight = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut flight).unwrap();
    }
    // RFC 7685 padding applies to the outer hello as sent, and the PSK
    // identity stays inside the encrypted inner hello.
    assert!(flight.len() >= 5 + 1500, "{}", flight.len());
    assert!(
        !flight
            .windows(b"inner psk identity".len())
            .any(|w| w == b"inner psk identity")
    );
    server.read_tls(&mut &flight[..]).unwrap();
    server.process_new_packets().unwrap();
    assert_accepted(&mut client, &mut server);
    assert_eq!(
        server.external_psk_identity(),
        Some(&b"inner psk identity"[..])
    );
}

/// The legacy_session_id of the first ClientHello or ServerHello in
/// `records` (a flight of plaintext handshake records).
#[cfg(feature = "tls12")]
fn hello_session_id(records: &[u8], msg_type: u8) -> Vec<u8> {
    let mut at = 0;
    while at + 5 <= records.len() {
        let len = usize::from(u16::from_be_bytes([records[at + 3], records[at + 4]]));
        let body = at + 5;
        if records[at] == 22 && records[body] == msg_type {
            // Handshake header, legacy_version, random.
            let p = body + 4 + 2 + 32;
            let sid_len = usize::from(records[p]);
            return records[p + 1..p + 1 + sid_len].to_vec();
        }
        at = body + len;
    }
    panic!("no hello of type {msg_type}");
}

/// A TLS 1.2 session cached for the hidden name is not resumed under ECH,
/// and its session ID never appears in the outer ClientHello: that ID went
/// over the wire next to the hidden name before, so reusing it in the
/// clear would link the ECH connection to that name.
#[cfg(feature = "tls12")]
#[test]
fn outer_hello_never_carries_a_cached_tls12_session_id() {
    init_logging();
    let certs = Certs::new();

    // A TLS 1.2 handshake with the hidden name, through a client that
    // offers both versions and keeps sessions in a shared store.
    let mut plain_client = client_config(&certs, None);
    plain_client.resumption = Resumption::in_memory_sessions(8);
    let plain_client = Arc::new(plain_client);
    let mut tls12_server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(certs.resolver());
    tls12_server.alpn_protocols = vec![b"h2".to_vec()];
    let tls12_server = Arc::new(tls12_server);
    let (mut client, mut server) = connect_arc(plain_client.clone(), tls12_server.clone());
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    let mut server_flight = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut server_flight).unwrap();
    }
    let cached_id = hello_session_id(&server_flight, 2);
    assert_eq!(cached_id.len(), 32, "the server issued a session ID");
    let mut offset = 0;
    while offset < server_flight.len() {
        offset += client.read_tls(&mut &server_flight[offset..]).unwrap();
    }
    client.process_new_packets().unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));

    // The same configuration with ECH enabled, sharing that session store.
    // The server sends no tickets, so the TLS 1.2 session stays the only
    // one cached for the hidden name.
    let ech = Arc::new(EchServerConfig::new(vec![server_key(5)]).unwrap());
    let mut ech_client = (*plain_client).clone();
    ech_client.ech_mode = enable(ech.ech_config_list());
    let ech_client = Arc::new(ech_client);
    let mut ech_server = server_config(&certs, Some(&ech), None);
    ech_server.send_tls13_tickets = 0;
    let ech_server = Arc::new(ech_server);
    for _ in 0..2 {
        let (mut client, mut server) = connect_arc(ech_client.clone(), ech_server.clone());
        let mut first_flight = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut first_flight).unwrap();
        }
        let outer_id = hello_session_id(&first_flight, 1);
        assert_eq!(outer_id.len(), 32, "middlebox compatibility mode");
        assert_ne!(outer_id, cached_id, "the outer hello reuses the cached ID");
        let mut offset = 0;
        while offset < first_flight.len() {
            offset += server.read_tls(&mut &first_flight[offset..]).unwrap();
        }
        server.process_new_packets().unwrap();
        assert_accepted(&mut client, &mut server);
        assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    }

    // ECH left the TLS 1.2 session alone: without ECH it still resumes.
    let (mut client, mut server) = connect_arc(plain_client, tls12_server);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
}
