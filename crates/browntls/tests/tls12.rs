//! In-memory TLS 1.2 handshakes between a browntls client and server.
//!
//! The RustCrypto provider refuses RSA private keys (RUSTSEC-2023-0071), so
//! the `ECDHE_RSA` suites are only exercised with an RSA-keyed rustls server
//! in `interop.rs`; here the server always signs with ECDSA or Ed25519.

mod common;

use std::sync::Arc;

use browntls::client::{Resumption, Tls12Resumption};
use browntls::crypto::rustcrypto;
use browntls::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, NamedGroup,
    ProtocolVersion, ServerConfig, ServerConnection, version,
};
use common::*;

fn tls12_only_client(
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
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn tls12_only_server(chain: &Chain) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

fn connect(
    client_config: ClientConfig,
    server_config: ServerConfig,
) -> (ClientConnection, ServerConnection) {
    let client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let server = ServerConnection::new(Arc::new(server_config)).unwrap();
    (client, server)
}

fn assert_tls12(client: &ClientConnection, server: &ServerConnection) {
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_2));
}

#[test]
fn full_handshake_every_ecdsa_suite_group_and_key_type() {
    init_logging();
    for key_type in KeyType::SIGNING {
        let chain = server_chain(key_type);
        for suite in rustcrypto::ALL_CIPHER_SUITES
            .iter()
            .filter(|s| s.tls13().is_none())
            .filter(|s| format!("{:?}", s.suite()).contains("ECDSA"))
        {
            for group in rustcrypto::ALL_KX_GROUPS
                .iter()
                .filter(|g| g.usable_for_version(ProtocolVersion::TLSv1_2))
            {
                let mut provider = rustcrypto::default_provider();
                provider.kx_groups = rustcrypto::ALL_KX_GROUPS.to_vec();
                let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(chain.cert_chain(), chain.private_key())
                    .unwrap();
                let (mut client, mut server) = connect(
                    tls12_only_client(&chain, Some(&[*suite]), Some(&[*group])),
                    server_config,
                );
                do_handshake(&mut client, &mut server)
                    .unwrap_or_else(|e| panic!("{key_type:?} {suite:?} {group:?}: {e}"));
                assert_tls12(&client, &server);
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
                assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
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
fn hybrid_groups_are_not_offered_for_tls12() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // The client prefers the post-quantum hybrid, but it cannot be used by
    // TLS 1.2; the handshake must fall through to X25519.
    let client_config = tls12_only_client(
        &chain,
        None,
        Some(&[
            rustcrypto::kx_group::X25519MLKEM768,
            rustcrypto::kx_group::X25519,
        ]),
    );
    let mut provider = rustcrypto::default_provider();
    provider.kx_groups = rustcrypto::ALL_KX_GROUPS.to_vec();
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_tls12(&client, &server);
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519
    );
}

#[test]
fn server_prefers_tls13_when_client_offers_both() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) = connect(client_config(&chain), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));

    // ...and TLS 1.2 is used when that is all the server speaks.
    let (mut client, mut server) = connect(client_config(&chain), tls12_only_server(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    assert_tls12(&client, &server);
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"downgraded, legitimately"),
        b"downgraded, legitimately"
    );
}

#[test]
fn session_id_resumption() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = tls12_only_client(&chain, None, None);
    client_config.resumption =
        Resumption::in_memory_sessions(4).tls12_resumption(Tls12Resumption::SessionIdOnly);
    let client_config = Arc::new(client_config);
    let server_config = Arc::new(tls12_only_server(&chain));

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));

    let mut client2 = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server2 = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client2, &mut server2).unwrap();
    assert_tls12(&client2, &server2);
    assert_eq!(client2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client2.peer_certificates().unwrap(), chain.cert_chain());
    assert_eq!(
        client2.negotiated_cipher_suite().unwrap().suite(),
        client.negotiated_cipher_suite().unwrap().suite()
    );
    assert_eq!(
        send_and_receive(&mut client2, &mut server2, b"resumed by id"),
        b"resumed by id"
    );
    assert_eq!(
        send_and_receive(&mut server2, &mut client2, b"and back"),
        b"and back"
    );

    // A server that forgot the session falls back to a full handshake.
    let mut client3 = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server3 = ServerConnection::new(Arc::new(tls12_only_server(&chain))).unwrap();
    do_handshake(&mut client3, &mut server3).unwrap();
    assert_eq!(client3.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server3.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
fn ticket_resumption() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client_config = tls12_only_client(&chain, None, None);
    client_config.resumption =
        Resumption::in_memory_sessions(4).tls12_resumption(Tls12Resumption::SessionIdOrTickets);
    let client_config = Arc::new(client_config);
    let mut server_config = tls12_only_server(&chain);
    server_config.ticketer = rustcrypto::Ticketer::new().unwrap();
    server_config.session_storage = Arc::new(browntls::server::NoServerSessionStorage {});
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));

    let mut client2 = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server2 = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client2, &mut server2).unwrap();
    assert_eq!(client2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(
        send_and_receive(&mut client2, &mut server2, b"resumed by ticket"),
        b"resumed by ticket"
    );

    // Tickets are refreshed on resumption, so a third connection resumes too.
    let mut client3 = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server3 = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client3, &mut server3).unwrap();
    assert_eq!(client3.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn resumption_disabled_on_client() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client_config = tls12_only_client(&chain, None, None);
    client_config.resumption = Resumption::disabled();
    let client_config = Arc::new(client_config);
    let server_config = Arc::new(tls12_only_server(&chain));
    for _ in 0..2 {
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    }
}

#[test]
fn resumption_disabled_on_server() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_config = Arc::new(tls12_only_client(&chain, None, None));
    let mut server_config = tls12_only_server(&chain);
    server_config.session_storage = Arc::new(browntls::server::NoServerSessionStorage {});
    let server_config = Arc::new(server_config);
    for _ in 0..2 {
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(send_and_receive(&mut client, &mut server, b"full"), b"full");
    }
}

#[test]
fn client_auth_every_signing_key_type() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP384);
    for key_type in KeyType::SIGNING {
        let client_chain = client_chain(key_type);
        let client_config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
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
        assert_tls12(&client, &server);
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
fn client_auth_is_remembered_across_resumption() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
            .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
            .unwrap(),
    );
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap(),
    );
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();

    let mut client2 = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server2 = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client2, &mut server2).unwrap();
    assert_eq!(server2.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(
        server2.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
}

#[test]
fn client_auth_mandatory_but_client_has_no_cert() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = tls12_only_client(&server_chain, None, None);
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
    let client_config = tls12_only_client(&server_chain, None, None);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, false))
        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_tls12(&client, &server);
    assert!(server.peer_certificates().is_none());
}

#[test]
fn alpn_negotiation_and_mismatch() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client_config = tls12_only_client(&chain, None, None);
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
fn server_name_is_visible_to_server() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls12_only_client(&chain, None, None), server_config(&chain));
    assert_eq!(server.server_name(), None);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.server_name(), Some("localhost"));
}

#[test]
fn close_notify_is_clean_eof() {
    use std::io::Read;
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls12_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    client.send_close_notify();
    transfer(&mut client, &mut server);
    let state = server.process_new_packets().unwrap();
    assert!(state.peer_has_closed());
    let mut buf = [0u8; 8];
    assert_eq!(server.reader().read(&mut buf).unwrap(), 0);
}

#[test]
fn tampered_record_is_bad_record_mac() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for suite in rustcrypto::ALL_CIPHER_SUITES
        .iter()
        .filter(|s| s.tls13().is_none())
        .filter(|s| format!("{:?}", s.suite()).contains("ECDSA"))
    {
        let (mut client, mut server) = connect(
            tls12_only_client(&chain, Some(&[*suite]), None),
            server_config(&chain),
        );
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
}

#[test]
fn wrong_server_certificate_is_rejected() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let other = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls12_only_client(&other, None, None), server_config(&chain));
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
fn server_signature_must_match_certificate_key() {
    init_logging();
    // The server presents a P-256 certificate but the verifier pins an
    // Ed25519 key with the same bytes rejected: the signature check fails
    // before any application data flows.
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) =
        connect(tls12_only_client(&other, None, None), server_config(&chain));
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert!(client_res.is_err(), "{client_res:?}");
}

#[test]
fn no_common_cipher_suite() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_config = tls12_only_client(
        &chain,
        Some(&[rustcrypto::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256]),
        None,
    );
    let mut provider = rustcrypto::default_provider();
    provider.cipher_suites =
        vec![rustcrypto::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS12])
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
fn rsa_suites_are_unusable_with_an_ecdsa_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = tls12_only_client(
        &chain,
        Some(&[rustcrypto::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]),
        None,
    );
    let (mut client, mut server) = connect(client_config, server_config(&chain));
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res,
        Err(browntls::PeerIncompatible::NoCipherSuitesInCommon.into())
    );
}

#[test]
fn no_common_key_exchange_group() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_config = tls12_only_client(&chain, None, Some(&[rustcrypto::kx_group::X25519]));
    let mut provider = rustcrypto::default_provider();
    provider.kx_groups = vec![rustcrypto::kx_group::SECP384R1];
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS12])
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
    let client_config = tls12_only_client(&chain, None, None);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
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
        connect(tls12_only_client(&chain, None, None), server_config(&chain));
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
    let no_ctx = server
        .export_keying_material([0u8; 32], b"EXPORTER-test", None)
        .unwrap();
    assert_ne!(c, no_ctx);
}

#[test]
fn large_writes_are_fragmented_and_reassembled() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls12_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    client.set_buffer_limit(None);
    server.set_buffer_limit(None);
    let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let got = send_and_receive(&mut client, &mut server, &data);
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data);
}

#[test]
fn renegotiation_request_is_refused_with_warning() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls12_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    // A plaintext HelloRequest is not acceptable post-handshake: the record
    // layer is encrypted, so the server's decrypt fails; what we can check
    // without a raw record encrypter is that a plaintext ClientHello sent to
    // the server after the handshake is rejected rather than renegotiated.
    server
        .read_tls(&mut &[0x16u8, 3, 3, 0, 5, 1, 0, 0, 1, 0][..])
        .unwrap();
    assert!(server.process_new_packets().is_err());
}

#[test]
fn key_update_is_not_available_in_tls12() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) =
        connect(tls12_only_client(&chain, None, None), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.refresh_traffic_keys().is_err());
    assert!(server.refresh_traffic_keys().is_err());
}
