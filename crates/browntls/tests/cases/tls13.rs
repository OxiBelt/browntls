// Shared cases, included by `tests/tls13.rs` (RustCrypto provider) and
// `tests/tls13_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.

use std::sync::Arc;

use browntls::{
    AlertDescription, CipherSuite, ClientConfig, ClientConnection, Error, HandshakeKind,
    NamedGroup, PeerMisbehaved, ProtocolVersion, ServerConfig, ServerConnection, version,
};
use common::*;

fn tls13_only_client(
    chain: &Chain,
    suites: Option<&[browntls::SupportedCipherSuite]>,
    groups: Option<&[&'static dyn browntls::crypto::SupportedKxGroup]>,
) -> ClientConfig {
    let mut provider = prov::default_provider();
    if let Some(suites) = suites {
        provider.cipher_suites = suites.to_vec();
    }
    if let Some(groups) = groups {
        provider.kx_groups = groups.to_vec();
    }
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn connect(
    client_config: ClientConfig,
    server_config: ServerConfig,
) -> (ClientConnection, ServerConnection) {
    let client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let server = ServerConnection::new(Arc::new(server_config)).unwrap();
    (client, server)
}

#[test]
fn full_handshake_every_suite_group_and_key_type() {
    init_logging();
    for &key_type in KeyType::SIGNING {
        let chain = server_chain(key_type);
        for suite in prov::ALL_CIPHER_SUITES
            .iter()
            .filter(|s| s.tls13().is_some())
        {
            for group in prov::ALL_KX_GROUPS {
                let mut provider = prov::default_provider();
                provider.cipher_suites = prov::ALL_CIPHER_SUITES.to_vec();
                provider.kx_groups = prov::ALL_KX_GROUPS.to_vec();
                let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(chain.cert_chain(), chain.private_key())
                    .unwrap();
                let (mut client, mut server) = connect(
                    tls13_only_client(&chain, Some(&[*suite]), Some(&[*group])),
                    server_config,
                );
                do_handshake(&mut client, &mut server)
                    .unwrap_or_else(|e| panic!("{key_type:?} {suite:?} {group:?}: {e}"));
                assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
                assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
                assert_eq!(
                    client.negotiated_cipher_suite().unwrap().suite(),
                    suite.suite()
                );
                assert_eq!(
                    server.negotiated_cipher_suite().unwrap().suite(),
                    suite.suite()
                );
                assert_eq!(
                    client.negotiated_key_exchange_group().unwrap().name(),
                    group.name()
                );
                assert_eq!(
                    server.negotiated_key_exchange_group().unwrap().name(),
                    group.name()
                );
                assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
                assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
                assert!(server.peer_certificates().is_none());

                assert_eq!(
                    send_and_receive(&mut client, &mut server, b"hello from client"),
                    b"hello from client"
                );
                assert_eq!(
                    send_and_receive(&mut server, &mut client, b"hello from server"),
                    b"hello from server"
                );
            }
        }
    }
}

#[test]
fn hello_retry_request_when_server_prefers_another_group() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // Client offers a key share for X25519 only; the server only speaks P-256.
    let client_config = tls13_only_client(
        &chain,
        None,
        Some(&[prov::kx_group::X25519, prov::kx_group::SECP256R1]),
    );
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::SECP256R1];
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp256r1
    );
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"after hrr"),
        b"after hrr"
    );
}

#[test]
fn server_may_answer_hybrid_share_with_its_classical_half() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_config = tls13_only_client(
        &chain,
        None,
        Some(&[prov::kx_group::X25519MLKEM768, prov::kx_group::X25519]),
    );
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::X25519];
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    // X25519 went out as a second share, so no HelloRetryRequest is needed.
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519
    );
}

#[test]
fn resumption_with_tickets_and_session_cache() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = Arc::new(tls13_only_client(&chain, None, None));
    let server_config = Arc::new(server_config(&chain));

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    // tickets arrive after the handshake, in the server's first flight of traffic
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.tls13_tickets_received(), 2);

    let mut client2 = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server2 = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client2, &mut server2).unwrap();
    assert_eq!(client2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client2.peer_certificates().unwrap(), chain.cert_chain());
    assert_eq!(
        send_and_receive(&mut client2, &mut server2, b"resumed"),
        b"resumed"
    );

    // the second ticket is still usable
    let mut client3 = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server3 = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client3, &mut server3).unwrap();
    assert_eq!(client3.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn resumption_with_aead_ticketer() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_config = Arc::new(tls13_only_client(&chain, None, None));
    let mut server_config = server_config(&chain);
    server_config.ticketer = prov::Ticketer::new().unwrap();
    server_config.session_storage = Arc::new(browntls::server::NoServerSessionStorage {});
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    server.set_resumption_data(b"app state");
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    let mut client2 = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server2 = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client2, &mut server2).unwrap();
    assert_eq!(client2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server2.received_resumption_data(), Some(&b"app state"[..]));
}

#[test]
fn client_auth_every_signing_key_type() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    for &key_type in KeyType::SIGNING {
        let client_chain = client_chain(key_type);
        let client_config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
            .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
            .unwrap();
        let server_config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap();
        let (mut client, mut server) = connect(client_config, server_config);
        do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{key_type:?}: {e}"));
        assert_eq!(
            server.peer_certificates().unwrap(),
            client_chain.cert_chain()
        );
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"authenticated"),
            b"authenticated"
        );
    }
}

#[test]
fn client_auth_mandatory_but_client_has_no_cert() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = tls13_only_client(&server_chain, None, None);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(server_res, Err(Error::NoCertificatesPresented));
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::CertificateRequired))
    );
}

#[test]
fn client_auth_optional_without_cert_succeeds() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = tls13_only_client(&server_chain, None, None);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, false))
        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.peer_certificates().is_none());
}

#[test]
fn alpn_negotiation_and_mismatch() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client_config = tls13_only_client(&chain, None, None);
    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut server_config = server_config(&chain);
    server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    let (mut client, mut server) = connect(client_config.clone(), server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(server.alpn_protocol(), Some(&b"http/1.1"[..]));

    let mut server_config = common::server_config(&chain);
    server_config.alpn_protocols = vec![b"spdy/3".to_vec()];
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(server_res, Err(Error::NoApplicationProtocol));
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(
            AlertDescription::NoApplicationProtocol
        ))
    );
}

#[test]
fn key_update_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"before"),
        b"before"
    );

    client.refresh_traffic_keys().unwrap();
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"after client update"),
        b"after client update"
    );
    // the server answered with its own KeyUpdate
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"server replies"),
        b"server replies"
    );

    server.refresh_traffic_keys().unwrap();
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"after server update"),
        b"after server update"
    );
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"client replies"),
        b"client replies"
    );
}

#[test]
fn close_notify_is_clean_eof() {
    use std::io::Read;
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    client.send_close_notify();
    transfer(&mut client, &mut server);
    let state = server.process_new_packets().unwrap();
    assert!(state.peer_has_closed());
    let mut buf = [0u8; 8];
    assert_eq!(server.reader().read(&mut buf).unwrap(), 0);
    assert!(!server.wants_read());
}

#[test]
fn tampered_record_is_bad_record_mac() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    client.writer().write_all(b"secret").unwrap();
    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();
    let last = buf.len() - 1;
    buf[last] ^= 0x01;
    server.read_tls(&mut &buf[..]).unwrap();
    assert_eq!(server.process_new_packets(), Err(Error::DecryptError));
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets(),
        Err(Error::AlertReceived(AlertDescription::BadRecordMac))
    );
}

#[test]
fn wrong_server_certificate_is_rejected() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let other = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&other, None, None), server_config(&chain));
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res,
        Err(browntls::CertificateError::UnknownIssuer.into())
    );
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(AlertDescription::UnknownCA))
    );
}

#[test]
fn no_common_cipher_suite() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_config = tls13_only_client(
        &chain,
        Some(&[prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256]),
        None,
    );
    let mut provider = prov::default_provider();
    provider.cipher_suites = vec![prov::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res,
        Err(browntls::PeerIncompatible::NoCipherSuitesInCommon.into())
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );
}

#[test]
fn no_common_key_exchange_group() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_config = tls13_only_client(&chain, None, Some(&[prov::kx_group::X25519]));
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::SECP384R1];
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res,
        Err(browntls::PeerIncompatible::NoKxGroupsInCommon.into())
    );
}

#[cfg(feature = "tls12")]
#[test]
fn version_mismatch() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_config = tls13_only_client(&chain, None, None);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res,
        Err(browntls::PeerIncompatible::Tls12NotOfferedOrEnabled.into())
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::ProtocolVersion))
    );
}

#[test]
fn export_keying_material_matches() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    assert_eq!(
        client.export_keying_material([0u8; 16], b"label", None),
        Err(Error::HandshakeNotComplete)
    );
    do_handshake(&mut client, &mut server).unwrap();
    let c = client
        .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"ctx"))
        .unwrap();
    let s = server
        .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"ctx"))
        .unwrap();
    assert_eq!(c, s);
    let s2 = server
        .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"other"))
        .unwrap();
    assert_ne!(c, s2);
}

#[test]
fn large_writes_are_fragmented_and_reassembled() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    client.set_buffer_limit(None);
    server.set_buffer_limit(None);
    let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let got = send_and_receive(&mut client, &mut server, &data);
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data);
}

#[test]
fn plaintext_written_before_handshake_is_flushed_after() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    client.writer().write_all(b"early write").unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut server.reader(), &mut out).ok();
    assert_eq!(out, b"early write");
}

#[test]
fn unexpected_message_during_handshake() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    // feed the server a plaintext alert instead of a ClientHello
    server
        .read_tls(&mut &[0x15u8, 3, 3, 0, 2, 1, 0][..])
        .unwrap();
    let state = server.process_new_packets().unwrap();
    assert!(state.peer_has_closed());
    // and a bogus ClientHello (truncated) to a fresh server
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    server
        .read_tls(&mut &[0x16u8, 3, 3, 0, 5, 1, 0, 0, 1, 0][..])
        .unwrap();
    assert!(matches!(
        server.process_new_packets(),
        Err(Error::InvalidMessage(_))
    ));
    let _ = (
        &mut client,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        PeerMisbehaved::IncorrectBinder,
    );
}

// ------------------------------------------------------------- 0-RTT

/// A server that allows `max` bytes of early data, sharing `cache` across
/// configurations so a session issued by one is found by another.
fn early_data_server(
    chain: &Chain,
    max: u32,
    cache: &Arc<dyn browntls::server::StoresServerSessions>,
) -> Arc<ServerConfig> {
    let mut config = server_config(chain);
    config.max_early_data_size = max;
    config.session_storage = cache.clone();
    Arc::new(config)
}

fn early_data_client(chain: &Chain) -> Arc<ClientConfig> {
    let mut config = tls13_only_client(chain, None, None);
    config.enable_early_data = true;
    Arc::new(config)
}

/// Runs one handshake so the client holds a ticket from `server_config`.
fn prime_ticket(client_config: &Arc<ClientConfig>, server_config: &Arc<ServerConfig>) {
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);
}

#[test]
fn early_data_is_accepted_and_readable() {
    use std::io::{Read, Write};
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(8);
    let server_config = early_data_server(&chain, 1024, &cache);
    let client_config = early_data_client(&chain);

    // No ticket yet: early data is not available on the first connection.
    let mut first = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    assert!(first.early_data().is_none());
    drop(first);
    prime_ticket(&client_config, &server_config);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    {
        let mut early = client.early_data().expect("ticket allows early data");
        assert_eq!(early.bytes_left(), 1024);
        early.write_all(b"GET /idempotent").unwrap();
        assert_eq!(early.bytes_left(), 1024 - b"GET /idempotent".len());
    }
    assert!(
        server.early_data().is_none(),
        "nothing before the ClientHello"
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.is_early_data_accepted());
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));

    let mut got = Vec::new();
    server
        .early_data()
        .expect("server accepted early data")
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, b"GET /idempotent");

    // early data is closed once the handshake is done
    assert!(client.early_data().is_none());
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"1-RTT request"),
        b"1-RTT request"
    );
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"response"),
        b"response"
    );
}

#[test]
fn early_data_respects_the_ticket_limit() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(8);
    let server_config = early_data_server(&chain, 100, &cache);
    let client_config = early_data_client(&chain);
    prime_ticket(&client_config, &server_config);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    {
        let mut early = client.early_data().unwrap();
        assert_eq!(early.write(&[7u8; 150]).unwrap(), 100);
        assert_eq!(early.write(&[7u8; 1]).unwrap(), 0);
        assert_eq!(early.bytes_left(), 0);
    }
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.is_early_data_accepted());
    let mut got = Vec::new();
    std::io::Read::read_to_end(&mut server.early_data().unwrap(), &mut got).unwrap();
    assert_eq!(got, [7u8; 100]);
}

#[test]
fn early_data_is_rejected_when_the_server_no_longer_allows_it() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(8);
    let client_config = early_data_client(&chain);
    prime_ticket(&client_config, &early_data_server(&chain, 1024, &cache));

    // Same session store, but early data is now off: the server must skip
    // the undecryptable records and continue a normal resumption.
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(early_data_server(&chain, 0, &cache)).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"replayable")
        .unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(!client.is_early_data_accepted());
    assert!(client.early_data().is_none());
    assert!(server.early_data().is_none());
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"replayable, resent"),
        b"replayable, resent"
    );
}

#[test]
fn early_data_is_rejected_by_the_application() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(8);
    let server_config = early_data_server(&chain, 1024, &cache);
    let client_config = early_data_client(&chain);
    prime_ticket(&client_config, &server_config);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    server.reject_early_data();
    client
        .early_data()
        .unwrap()
        .write_all(b"no thanks")
        .unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"still fine"),
        b"still fine"
    );
}

#[test]
fn early_data_is_rejected_after_hello_retry_request() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(8);
    let server_config = early_data_server(&chain, 1024, &cache);
    let mut client_config = tls13_only_client(
        &chain,
        None,
        Some(&[prov::kx_group::X25519, prov::kx_group::SECP384R1]),
    );
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);
    prime_ticket(&client_config, &server_config);

    // The second server only takes P-384, forcing a HelloRetryRequest; the
    // early data behind the first ClientHello must be skipped.
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::SECP384R1];
    let mut retry_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    retry_config.max_early_data_size = 1024;
    retry_config.session_storage = cache;

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(retry_config)).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"too early")
        .unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
    // The retried ClientHello still carries the PSK, so the session is
    // resumed (as in rustls, resumption outranks the retry in the kind).
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"after retry"),
        b"after retry"
    );
}

#[test]
fn early_data_is_not_offered_with_stateless_tickets() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut server_config = server_config(&chain);
    server_config.max_early_data_size = 1024;
    server_config.ticketer = prov::Ticketer::new().unwrap();
    server_config.session_storage = Arc::new(browntls::server::NoServerSessionStorage {});
    let server_config = Arc::new(server_config);
    let client_config = early_data_client(&chain);
    prime_ticket(&client_config, &server_config);

    // RFC 8446 §8.1: no single-use guarantee without server state.
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    assert!(client.early_data().is_none());
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn early_data_disabled_in_client_config_is_not_sent() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(8);
    let server_config = early_data_server(&chain, 1024, &cache);
    let client_config = Arc::new(tls13_only_client(&chain, None, None));
    prime_ticket(&client_config, &server_config);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    assert!(client.early_data().is_none());
    assert!(!client.is_early_data_accepted());
}

// ------------------------------------------------ RFC 9846 conformance

/// Takes every queued TLS byte from `conn`.
fn take_tls<A: browntls::SideData>(conn: &mut browntls::ConnectionCommon<A>) -> Vec<u8> {
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf).unwrap();
    }
    buf
}

/// The (content type, header + body) of each TLS record in `buf`.
fn split_records(buf: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = buf;
    while rest.len() >= 5 {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        out.push((rest[0], rest[..5 + len].to_vec()));
        rest = &rest[5 + len..];
    }
    assert!(rest.is_empty(), "trailing partial record");
    out
}

fn feed<A: browntls::SideData>(conn: &mut browntls::ConnectionCommon<A>, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        conn.read_tls(&mut bytes).unwrap();
    }
}

/// A handshake whose tickets have reached the client, so nothing is queued.
fn established() -> (ClientConnection, ServerConnection) {
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert!(!client.wants_write() && !server.wants_write());
    (client, server)
}

#[test]
fn key_update_request_is_not_repeated_until_answered() {
    init_logging();
    let (mut client, mut server) = established();

    // The client asks; the server answers with one KeyUpdate of its own.
    client.refresh_traffic_keys().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    let answer = take_tls(&mut server);
    assert_eq!(split_records(&answer).len(), 1);

    // RFC 9846 §4.7.3: until a KeyUpdate from the server arrives, a second
    // refresh only rotates the client's key, so the server owes nothing.
    client.refresh_traffic_keys().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(!server.wants_write());

    // Once the answer is in, the client may ask again.
    feed(&mut client, &answer);
    client.process_new_packets().unwrap();
    client.refresh_traffic_keys().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert_eq!(split_records(&take_tls(&mut server)).len(), 1);
}

#[test]
fn crossing_key_update_requests_each_get_one_answer() {
    init_logging();
    let (mut client, mut server) = established();
    // RFC 9846 §4.7.3: requests that cross in flight are both answered,
    // each side moving on two generations; data still flows both ways.
    client.refresh_traffic_keys().unwrap();
    server.refresh_traffic_keys().unwrap();
    let from_client = take_tls(&mut client);
    let from_server = take_tls(&mut server);
    feed(&mut server, &from_client);
    feed(&mut client, &from_server);
    server.process_new_packets().unwrap();
    client.process_new_packets().unwrap();
    let server_answer = take_tls(&mut server);
    let client_answer = take_tls(&mut client);
    assert_eq!(split_records(&server_answer).len(), 1);
    assert_eq!(split_records(&client_answer).len(), 1);
    feed(&mut client, &server_answer);
    feed(&mut server, &client_answer);
    client.process_new_packets().unwrap();
    server.process_new_packets().unwrap();
    // Answers to update_requested are update_not_requested: nothing more.
    assert!(!client.wants_write() && !server.wants_write());
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"after crossing"),
        b"after crossing"
    );
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"both ways"),
        b"both ways"
    );
}

/// Runs a handshake up to the client's second ClientHello and returns it,
/// with the configured server, which must answer with a HelloRetryRequest.
fn second_client_hello() -> (ClientConnection, ServerConnection, Vec<u8>) {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = tls13_only_client(
        &chain,
        Some(&[
            prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
            prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]),
        Some(&[prov::kx_group::X25519, prov::kx_group::SECP256R1]),
    );
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::SECP256R1];
    provider.cipher_suites = vec![
        prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
        prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    let ch2 = take_tls(&mut client);
    (client, server, ch2)
}

/// Where the cipher suite list of the ClientHello in `record` starts.
fn cipher_suites_offset(record: &[u8]) -> usize {
    // record header (5), handshake header (4), legacy_version (2), random (32)
    let session_id_len = usize::from(record[5 + 4 + 2 + 32]);
    5 + 4 + 2 + 32 + 1 + session_id_len + 2
}

#[test]
fn retry_must_keep_the_cipher_suite_the_hello_retry_request_chose() {
    init_logging();
    let (_client, mut server, ch2) = second_client_hello();
    // Drop TLS_AES_128_GCM_SHA256 (the HelloRetryRequest's choice) from the
    // second ClientHello, leaving ChaCha20 which the server also accepts.
    let mut out = Vec::new();
    for (typ, mut record) in split_records(&ch2) {
        if typ == 0x16 {
            let at = cipher_suites_offset(&record);
            assert_eq!(record[at..at + 2], [0x13, 0x01]);
            record[at..at + 2].copy_from_slice(&[0x0a, 0x0a]);
        }
        out.extend(record);
    }
    feed(&mut server, &out);
    // RFC 9846 §4.2.4: the server MUST negotiate the same suite.
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::CipherSuiteDifferedOnRetry
        ))
    );
    let alert = take_tls(&mut server);
    assert_eq!(&alert[..1], &[0x15]);
    assert_eq!(
        alert[alert.len() - 1],
        u8::from(AlertDescription::IllegalParameter)
    );
}

#[test]
fn client_hello_with_supported_versions_needs_legacy_version_tls12() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    let mut ch = take_tls(&mut client);
    // ClientHello.legacy_version follows the record and handshake headers.
    assert_eq!(ch[9..11], [3, 3]);
    ch[10] = 1;
    feed(&mut server, &ch);
    // RFC 9846 §4.2.2: anything but 0x0303 is protocol_version.
    assert!(matches!(
        server.process_new_packets(),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalClientHelloLegacyVersion
        ))
    ));
    let alert = take_tls(&mut server);
    assert_eq!(
        alert[alert.len() - 1],
        u8::from(AlertDescription::ProtocolVersion)
    );
}

/// A ticketer announcing a zero ticket lifetime.
#[derive(Debug)]
struct ZeroLifetime(Arc<dyn browntls::server::ProducesTickets>);

impl browntls::server::ProducesTickets for ZeroLifetime {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.0.encrypt(plain)
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.0.decrypt(cipher)
    }
}

#[test]
fn zero_lifetime_tickets_are_not_sent() {
    init_logging();
    // RFC 9846 §4.7.1: a zero lifetime means "discard immediately", so the
    // server does not bother sending such a ticket.
    let chain = server_chain(KeyType::Ed25519);
    let mut server_config = server_config(&chain);
    server_config.ticketer = Arc::new(ZeroLifetime(prov::Ticketer::new().unwrap()));
    let (mut client, mut server) = connect(tls13_only_client(&chain, None, None), server_config);
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(client.tls13_tickets_received(), 0);
}

#[test]
fn stateful_tickets_announce_a_lifetime_and_resume() {
    init_logging();
    // Session-cache tickets used to announce a zero lifetime, which RFC
    // 9846 §4.7.1 defines as "discard immediately".
    let chain = server_chain(KeyType::Ed25519);
    let server_config = Arc::new(server_config(&chain));
    assert!(!server_config.ticketer.enabled());
    let client_config = Arc::new(tls13_only_client(&chain, None, None));
    prime_ticket(&client_config, &server_config);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
}

/// The body of extension `typ` in the ClientHello record `record`.
fn client_hello_extension(record: &[u8], typ: u16) -> Option<Vec<u8>> {
    let mut at = cipher_suites_offset(record);
    let suites_len = usize::from(u16::from_be_bytes([record[at - 2], record[at - 1]]));
    at += suites_len;
    let compression_len = usize::from(record[at]);
    at += 1 + compression_len + 2;
    while at + 4 <= record.len() {
        let ext = u16::from_be_bytes([record[at], record[at + 1]]);
        let len = usize::from(u16::from_be_bytes([record[at + 2], record[at + 3]]));
        if ext == typ {
            return Some(record[at + 4..at + 4 + len].to_vec());
        }
        at += 4 + len;
    }
    None
}

#[test]
fn key_shares_differ_between_connections() {
    init_logging();
    // RFC 9846 §1.2: key shares MUST NOT be reused across connections.
    let chain = server_chain(KeyType::Ed25519);
    let config = Arc::new(tls13_only_client(&chain, None, None));
    let key_share = || {
        let mut client = ClientConnection::new(config.clone(), server_name()).unwrap();
        let hello = take_tls(&mut client);
        client_hello_extension(&hello, 0x0033).expect("key_share offered")
    };
    let first = key_share();
    assert_ne!(first, key_share());
    assert_ne!(first, key_share());
}

#[test]
fn key_shares_follow_supported_groups_order() {
    init_logging();
    // RFC 9846 §4.3.8: shares appear in the order of supported_groups. A
    // hybrid share also sends its classical half.
    let chain = server_chain(KeyType::Ed25519);
    let config = tls13_only_client(
        &chain,
        None,
        Some(&[prov::kx_group::X25519MLKEM768, prov::kx_group::X25519]),
    );
    let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    let hello = take_tls(&mut client);
    let groups = client_hello_extension(&hello, 0x000a).unwrap();
    let groups: Vec<u16> = groups[2..]
        .chunks(2)
        .map(|g| u16::from_be_bytes([g[0], g[1]]))
        .collect();
    let shares = client_hello_extension(&hello, 0x0033).unwrap();
    let mut share_groups = Vec::new();
    let mut at = 2;
    while at < shares.len() {
        share_groups.push(u16::from_be_bytes([shares[at], shares[at + 1]]));
        at += 4 + usize::from(u16::from_be_bytes([shares[at + 2], shares[at + 3]]));
    }
    assert_eq!(share_groups.len(), 2);
    let position = |g: &u16| groups.iter().position(|x| x == g).unwrap();
    assert!(position(&share_groups[0]) < position(&share_groups[1]));
}

/// Runs `edit` over the server's first flight (ServerHello record first)
/// and returns what the client makes of it, plus the alert it sends.
fn client_reaction_to_edited_server_hello(
    edit: impl FnOnce(&mut Vec<u8>),
) -> (Result<browntls::IoState, Error>, u8) {
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls13_only_client(&chain, None, None), server_config(&chain));
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    let mut flight = split_records(&take_tls(&mut server));
    assert_eq!(flight[0].0, 0x16);
    edit(&mut flight[0].1);
    let bytes: Vec<u8> = flight.into_iter().flat_map(|(_, r)| r).collect();
    feed(&mut client, &bytes);
    let result = client.process_new_packets();
    let alert = take_tls(&mut client);
    (result, alert[alert.len() - 1])
}

#[test]
fn server_hello_legacy_version_must_be_tls12() {
    init_logging();
    // RFC 9846 §4.2.3: legacy_version other than 0x0303 is protocol_version.
    let (result, alert) = client_reaction_to_edited_server_hello(|sh| {
        assert_eq!(sh[9..11], [3, 3]);
        sh[10] = 4;
    });
    assert_eq!(
        result,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalServerHelloLegacyVersion
        ))
    );
    assert_eq!(alert, u8::from(AlertDescription::ProtocolVersion));
}

#[test]
fn server_hello_with_unoffered_cipher_suite_is_illegal_parameter() {
    init_logging();
    // RFC 9846 §4.2.3: a cipher suite the client did not offer.
    let (result, alert) = client_reaction_to_edited_server_hello(|sh| {
        let at = 5 + 4 + 2 + 32 + 1 + usize::from(sh[5 + 4 + 2 + 32]);
        sh[at..at + 2].copy_from_slice(&[0xfe, 0xfe]);
    });
    assert_eq!(
        result,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::SelectedUnofferedCipherSuite
        ))
    );
    assert_eq!(alert, u8::from(AlertDescription::IllegalParameter));
}

#[test]
fn writer_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<browntls::Writer<'static>>();
}

/// TLS_AES_128_GCM_SHA256 with a confidentiality limit of `limit` records.
fn suite_with_limit(limit: u64) -> browntls::SupportedCipherSuite {
    let orig = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let suite: &'static browntls::Tls13CipherSuite =
        Box::leak(Box::new(browntls::Tls13CipherSuite {
            common: browntls::CipherSuiteCommon {
                suite: orig.common.suite,
                hash_provider: orig.common.hash_provider,
                confidentiality_limit: limit,
            },
            hkdf_provider: orig.hkdf_provider,
            aead_alg: orig.aead_alg,
        }));
    browntls::SupportedCipherSuite::Tls13(suite)
}

fn limited_pair(limit: u64, half_rtt: bool) -> (ClientConnection, ServerConnection) {
    let chain = server_chain(KeyType::Ed25519);
    let suite = suite_with_limit(limit);
    let client_config = tls13_only_client(&chain, Some(&[suite]), None);
    let mut provider = prov::default_provider();
    provider.cipher_suites = vec![suite];
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    server_config.send_half_rtt_data = half_rtt;
    connect(client_config, server_config)
}

fn read_all<A: browntls::SideData>(conn: &mut browntls::ConnectionCommon<A>) -> Vec<u8> {
    let mut got = Vec::new();
    let _ = std::io::Read::read_to_end(&mut conn.reader(), &mut got);
    got
}

#[test]
fn writes_past_the_confidentiality_limit_rotate_keys() {
    use std::io::Write;
    init_logging();
    // RFC 9846 §5.5: update keys before the limit is reached.
    let (mut client, mut server) = limited_pair(4, false);
    do_handshake(&mut client, &mut server).unwrap();
    for i in 0..20u8 {
        assert_eq!(client.writer().write(&[i]).unwrap(), 1, "write {i}");
    }
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert_eq!(read_all(&mut server), (0..20u8).collect::<Vec<_>>());
    // and the server can still answer under its own (also limited) key
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"still here"),
        b"still here"
    );
}

#[test]
fn plaintext_buffered_before_the_handshake_survives_the_limit() {
    use std::io::Write;
    init_logging();
    let (mut client, mut server) = limited_pair(4, false);
    for i in 0..8u8 {
        assert_eq!(client.writer().write(&[i]).unwrap(), 1);
    }
    do_handshake(&mut client, &mut server).unwrap();
    for _ in 0..4 {
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
    }
    assert_eq!(read_all(&mut server), (0..8u8).collect::<Vec<_>>());
}

#[test]
fn half_rtt_data_at_the_limit_waits_for_the_handshake() {
    use std::io::Write;
    init_logging();
    // The server cannot send a KeyUpdate before it has the client's
    // Finished, so writes past the limit are held back, not failed, and the
    // connection is not closed.
    let (mut client, mut server) = limited_pair(4, true);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert!(server.is_handshaking());
    let mut taken = Vec::new();
    for i in 0..8u8 {
        if server.writer().write(&[i]).unwrap() == 1 {
            taken.push(i);
        }
    }
    assert!(!taken.is_empty() && taken.len() < 8);
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    let state = client.process_new_packets().unwrap();
    assert!(!state.peer_has_closed());
    assert_eq!(read_all(&mut client), taken);
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"after the refresh"),
        b"after the refresh"
    );
}

#[test]
fn no_key_update_after_our_close_notify() {
    init_logging();
    // RFC 9846 §6.1: nothing is sent after close_notify, not even the
    // KeyUpdate the peer asked for.
    let (mut client, mut server) = established();
    client.send_close_notify();
    let _ = take_tls(&mut client);
    server.refresh_traffic_keys().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert!(!client.wants_write());
}
