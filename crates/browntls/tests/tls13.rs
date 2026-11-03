//! In-memory TLS 1.3 handshakes between a browntls client and server.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use browntls::crypto::rustcrypto;
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
    let mut provider = rustcrypto::default_provider();
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
    for key_type in KeyType::SIGNING {
        let chain = server_chain(key_type);
        for suite in rustcrypto::ALL_CIPHER_SUITES
            .iter()
            .filter(|s| s.tls13().is_some())
        {
            for group in rustcrypto::ALL_KX_GROUPS {
                let mut provider = rustcrypto::default_provider();
                provider.kx_groups = rustcrypto::ALL_KX_GROUPS.to_vec();
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
        Some(&[
            rustcrypto::kx_group::X25519,
            rustcrypto::kx_group::SECP256R1,
        ]),
    );
    let mut provider = rustcrypto::default_provider();
    provider.kx_groups = vec![rustcrypto::kx_group::SECP256R1];
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
        Some(&[
            rustcrypto::kx_group::X25519MLKEM768,
            rustcrypto::kx_group::X25519,
        ]),
    );
    let mut provider = rustcrypto::default_provider();
    provider.kx_groups = vec![rustcrypto::kx_group::X25519];
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
    server_config.ticketer = rustcrypto::Ticketer::new().unwrap();
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
    for key_type in KeyType::SIGNING {
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
        Some(&[rustcrypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256]),
        None,
    );
    let mut provider = rustcrypto::default_provider();
    provider.cipher_suites = vec![rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256];
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
    let client_config = tls13_only_client(&chain, None, Some(&[rustcrypto::kx_group::X25519]));
    let mut provider = rustcrypto::default_provider();
    provider.kx_groups = vec![rustcrypto::kx_group::SECP384R1];
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
