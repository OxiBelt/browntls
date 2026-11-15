// Shared cases, included by `tests/external_psk.rs` (RustCrypto provider) and
// `tests/external_psk_native.rs` (native provider): TLS 1.3 external PSKs
// (RFC 9846 §4.3.11), the PSK importer (RFC 9258) and certificate
// authentication with an external PSK (RFC 8773). Provider items are reached
// through the including target's `prov` module.

use std::io::{Read, Write};
use std::sync::Arc;

use browntls::crypto::hash::HashAlgorithm;
use browntls::pki_types::DnsName;
use browntls::psk::{ExternalPsk, ImportedIdentity, ResolvesExternalPsk};
use browntls::{
    AlertDescription, CipherSuite, ClientConfig, ClientConnection, Error, HandshakeKind,
    NamedGroup, PeerIncompatible, PeerMisbehaved, ServerConfig, ServerConnection, version,
};
use common::*;

const KEY: [u8; 32] = [0x42; 32];

fn psk(identity: &[u8], hash: HashAlgorithm) -> ExternalPsk {
    ExternalPsk::new(identity.to_vec(), KEY.to_vec(), hash).unwrap()
}

fn tls13_provider(
    suites: Option<&[browntls::SupportedCipherSuite]>,
    groups: Option<&[&'static dyn browntls::crypto::SupportedKxGroup]>,
) -> Arc<browntls::crypto::CryptoProvider> {
    let mut provider = prov::default_provider();
    if let Some(suites) = suites {
        provider.cipher_suites = suites.to_vec();
    }
    if let Some(groups) = groups {
        provider.kx_groups = groups.to_vec();
    }
    Arc::new(provider)
}

/// A TLS 1.3 client offering `psks`; it trusts `chain` should the server
/// authenticate with a certificate instead.
fn client_with(chain: &Chain, psks: Vec<ExternalPsk>) -> ClientConfig {
    client_with_provider(chain, psks, tls13_provider(None, None))
}

fn client_with_provider(
    chain: &Chain,
    psks: Vec<ExternalPsk>,
    provider: Arc<browntls::crypto::CryptoProvider>,
) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth();
    config.external_psks = psks.into_iter().map(Arc::new).collect();
    config
}

/// A server with no certificate that accepts `psks`.
fn psk_only_server(psks: Vec<ExternalPsk>) -> ServerConfig {
    psk_only_server_with_provider(psks, tls13_provider(None, None))
}

fn psk_only_server_with_provider(
    psks: Vec<ExternalPsk>,
    provider: Arc<browntls::crypto::CryptoProvider>,
) -> ServerConfig {
    let resolver: Vec<Arc<ExternalPsk>> = psks.into_iter().map(Arc::new).collect();
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_external_psks_only(Arc::new(resolver))
}

/// A server with `chain`'s certificate that also accepts `psks`.
fn cert_and_psk_server(chain: &Chain, psks: Vec<ExternalPsk>) -> ServerConfig {
    let mut config = server_config(chain);
    let resolver: Vec<Arc<ExternalPsk>> = psks.into_iter().map(Arc::new).collect();
    config.external_psks = Some(Arc::new(resolver));
    config
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

fn exchange_data(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(send_and_receive(client, server, b"ping"), b"ping");
    assert_eq!(send_and_receive(server, client, b"pong"), b"pong");
}

fn suite_of(conn: &browntls::CommonState) -> CipherSuite {
    conn.negotiated_cipher_suite().unwrap().suite()
}

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

// ----------------------------------------------- tickets next to external PSKs

#[test]
fn ticket_and_external_psk_offered_together() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = Arc::new(client_with(
        &chain,
        vec![psk(b"client-1", HashAlgorithm::SHA256)],
    ));
    let server_config = Arc::new(psk_only_server(vec![psk(
        b"client-1",
        HashAlgorithm::SHA256,
    )]));

    // First connection: external PSK, then a ticket.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);

    // Second connection: the ticket comes first and is taken.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    // The ticket came from an external-PSK session and carries its identity.
    assert_eq!(client.external_psk_identity(), Some(&b"client-1"[..]));
    assert_eq!(server.external_psk_identity(), Some(&b"client-1"[..]));
    exchange_data(&mut client, &mut server);

    // Third: a server that does not know the ticket takes the external PSK,
    // the second identity offered.
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(psk_only_server(vec![psk(
        b"client-1",
        HashAlgorithm::SHA256,
    )])))
    .unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"client-1"[..]));
    assert_eq!(server.external_psk_identity(), Some(&b"client-1"[..]));
    exchange_data(&mut client, &mut server);
}

// ------------------------------------------------------------------ 0-RTT

fn early_psk() -> ExternalPsk {
    psk(b"early", HashAlgorithm::SHA256)
        .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)
        .with_early_data(1024)
}

#[test]
fn early_data_with_an_external_psk_when_allowed() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_with(&chain, vec![early_psk()]);
    client_config.enable_early_data = true;
    let (mut client, mut server) = connect(client_config, psk_only_server(vec![early_psk()]));
    {
        let mut early = client.early_data().expect("PSK allows early data");
        assert_eq!(early.bytes_left(), 1024);
        early.write_all(b"GET /idempotent").unwrap();
    }
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.is_early_data_accepted());
    let mut got = Vec::new();
    server
        .early_data()
        .expect("server accepted early data")
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, b"GET /idempotent");
    exchange_data(&mut client, &mut server);
}

#[test]
fn early_data_with_an_external_psk_is_off_by_default() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);

    // Client side: no early data unless the PSK allows it.
    let mut client_config = client_with(
        &chain,
        vec![
            psk(b"early", HashAlgorithm::SHA256)
                .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256),
        ],
    );
    client_config.enable_early_data = true;
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    assert!(client.early_data().is_none());

    // Without a provisioned suite, neither.
    let mut client_config = client_with(
        &chain,
        vec![psk(b"early", HashAlgorithm::SHA256).with_early_data(1024)],
    );
    client_config.enable_early_data = true;
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    assert!(client.early_data().is_none());

    // Server side: a server whose PSK does not allow it rejects the data
    // and the handshake still completes.
    let mut client_config = client_with(&chain, vec![early_psk()]);
    client_config.enable_early_data = true;
    let (mut client, mut server) = connect(
        client_config,
        psk_only_server(vec![
            psk(b"early", HashAlgorithm::SHA256)
                .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256),
        ]),
    );
    client
        .early_data()
        .unwrap()
        .write_all(b"GET /idempotent")
        .unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
    assert_eq!(server.external_psk_identity(), Some(&b"early"[..]));
    exchange_data(&mut client, &mut server);
}

// ------------------------------------------------------- RFC 9258 importer

fn imported(identity: &[u8], hash: HashAlgorithm, context: &[u8]) -> ExternalPsk {
    psk(identity, hash).imported(context.to_vec()).unwrap()
}

#[test]
fn imported_psk_handshake() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for epsk_hash in [HashAlgorithm::SHA256, HashAlgorithm::SHA384] {
        let (mut client, mut server) = connect(
            client_with(&chain, vec![imported(b"epsk", epsk_hash, b"app ctx")]),
            psk_only_server(vec![imported(b"epsk", epsk_hash, b"app ctx")]),
        );
        do_handshake(&mut client, &mut server).unwrap();
        // The client imports for each hash of its suites, SHA-384 first
        // (AES-256-GCM leads its list); the server takes the first.
        assert_eq!(suite_of(&server), CipherSuite::TLS13_AES_256_GCM_SHA384);
        assert_eq!(client.external_psk_identity(), Some(&b"epsk"[..]));
        assert_eq!(server.external_psk_identity(), Some(&b"epsk"[..]));
        assert!(client.peer_certificates().is_none());
        exchange_data(&mut client, &mut server);
    }
}

#[test]
fn imported_psk_for_each_suite_hash() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in [
        prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
        prov::cipher_suite::TLS13_AES_256_GCM_SHA384,
        prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        // The client imports for SHA-384 and SHA-256; the server, which
        // has one suite, takes the identity imported for its hash. (The
        // importer runs HKDF with the EPSK's hash, so that hash must be a
        // suite's of the provider.)
        let hash = suite.tls13().unwrap().common.hash_provider.algorithm();
        let (mut client, mut server) = connect(
            client_with(&chain, vec![imported(b"epsk", hash, b"")]),
            psk_only_server_with_provider(
                vec![imported(b"epsk", hash, b"")],
                tls13_provider(Some(&[suite]), None),
            ),
        );
        do_handshake(&mut client, &mut server)
            .unwrap_or_else(|e| panic!("{:?}: {e}", suite.suite()));
        assert_eq!(suite_of(&server), suite.suite());
        exchange_data(&mut client, &mut server);
    }
}

#[test]
fn imported_psk_context_must_match() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        client_with(
            &chain,
            vec![imported(b"epsk", HashAlgorithm::SHA256, b"one")],
        ),
        psk_only_server(vec![imported(b"epsk", HashAlgorithm::SHA256, b"two")]),
    );
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::NoUsablePskForServerWithoutCertificate)
    );
}

#[test]
fn imported_and_direct_uses_do_not_mix() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // Direct offer, importer-only server key.
    let (mut client, mut server) = connect(
        client_with(&chain, vec![psk(b"epsk", HashAlgorithm::SHA256)]),
        psk_only_server(vec![imported(b"epsk", HashAlgorithm::SHA256, b"")]),
    );
    assert!(
        do_handshake_until_error(&mut client, &mut server)
            .1
            .is_err()
    );
    // Imported offer, direct-only server key.
    let (mut client, mut server) = connect(
        client_with(&chain, vec![imported(b"epsk", HashAlgorithm::SHA256, b"")]),
        psk_only_server(vec![psk(b"epsk", HashAlgorithm::SHA256)]),
    );
    assert!(
        do_handshake_until_error(&mut client, &mut server)
            .1
            .is_err()
    );
}

/// A resolver that records the identities it is asked for.
#[derive(Debug, Default)]
struct RecordingResolver {
    keys: Vec<Arc<ExternalPsk>>,
    asked: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl ResolvesExternalPsk for RecordingResolver {
    fn resolve(&self, identity: &[u8]) -> Option<Arc<ExternalPsk>> {
        self.asked.lock().unwrap().push(identity.to_vec());
        self.keys.iter().find(|k| k.identity() == identity).cloned()
    }
}

#[test]
fn imported_identities_on_the_wire() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let resolver = Arc::new(RecordingResolver {
        keys: vec![Arc::new(imported(b"epsk", HashAlgorithm::SHA256, b"ctx"))],
        ..Default::default()
    });
    let mut server_config = psk_only_server(Vec::new());
    server_config.external_psks = Some(resolver.clone());
    let (mut client, mut server) = connect(
        client_with(
            &chain,
            vec![imported(b"epsk", HashAlgorithm::SHA256, b"ctx")],
        ),
        server_config,
    );
    do_handshake(&mut client, &mut server).unwrap();
    let asked = resolver.asked.lock().unwrap().clone();
    // Each offered identity is first looked up as is; the imported ones then
    // by their external identity.
    let expect = |kdf| ImportedIdentity {
        external_identity: b"epsk".to_vec(),
        context: b"ctx".to_vec(),
        target_protocol: browntls::ProtocolVersion::TLSv1_3,
        target_kdf: kdf,
    };
    assert_eq!(
        asked,
        vec![
            expect(ImportedIdentity::HKDF_SHA384).encode(),
            b"epsk".to_vec(),
            expect(ImportedIdentity::HKDF_SHA256).encode(),
            b"epsk".to_vec(),
        ]
    );
}

// --------------------------------------------------------------- RFC 8773

#[test]
fn certificate_authentication_with_an_external_psk() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    client_config.cert_with_extern_psk = true;
    client_config.require_cert_with_extern_psk = true;
    let mut server_config = cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    server_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(server.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    exchange_data(&mut client, &mut server);
}

#[test]
fn certificate_authentication_with_an_external_psk_and_client_auth() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    client_config.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))];
    client_config.cert_with_extern_psk = true;
    let mut server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    server_config.external_psks = Some(Arc::new(vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))]));
    server_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
    exchange_data(&mut client, &mut server);
}

#[test]
fn certificate_authentication_with_an_external_psk_is_opt_in() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // The server does not enable it: a plain PSK handshake, which a client
    // that only asks accepts...
    let mut client_config = client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    client_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(
        client_config.clone(),
        cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert!(client.peer_certificates().is_none());

    // ...and a client that requires it refuses.
    client_config.require_cert_with_extern_psk = true;
    let (mut client, mut server) = connect(
        client_config,
        cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]),
    );
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::CertWithExternPskRequired)
    );

    // A server without a certificate cannot do it, and does a PSK handshake.
    let mut client_config = client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    client_config.cert_with_extern_psk = true;
    let mut server_config = psk_only_server(vec![psk(b"k", HashAlgorithm::SHA256)]);
    server_config.cert_with_extern_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.peer_certificates().is_none());
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
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

// ------------------------------------------------------------- resumption

/// The resumption key schedule continues with the negotiated suite, not
/// the ticket's: RFC 9846 §4.3.11 lets the server pick any suite with the
/// ticket's hash.
#[test]
fn resumption_with_another_suite_of_the_same_hash() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(8);
    // A server that prefers `suite` over the other one.
    let server = |suite: browntls::SupportedCipherSuite| {
        let suites: Vec<_> = [
            prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
            prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]
        .into_iter()
        .filter(|s| *s != suite)
        .collect();
        let mut config = ServerConfig::builder_with_provider(tls13_provider(
            Some(&[&[suite], &suites[..]].concat()),
            None,
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
        config.session_storage = cache.clone();
        config.ignore_client_order = true;
        Arc::new(config)
    };
    let client_config = Arc::new(client_with_provider(
        &chain,
        Vec::new(),
        tls13_provider(
            Some(&[
                prov::cipher_suite::TLS13_AES_128_GCM_SHA256,
                prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ]),
            None,
        ),
    ));

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut first =
        ServerConnection::new(server(prov::cipher_suite::TLS13_AES_128_GCM_SHA256)).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    transfer(&mut first, &mut client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut second =
        ServerConnection::new(server(prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256)).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(
        suite_of(&client),
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    );
    exchange_data(&mut client, &mut second);
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

// ------------------------------------------------------ require_external_psk

/// Hands the tickets `server` sent to `client`.
fn take_tickets(client: &mut ClientConnection, server: &mut ServerConnection) {
    transfer(server, client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);
}

#[test]
fn client_requiring_an_external_psk_refuses_a_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // The server does not know the client's key and authenticates with its
    // certificate, which the client would accept...
    let mut client_config = client_with(&chain, vec![psk(b"a", HashAlgorithm::SHA256)]);
    let (mut client, mut server) = connect(
        client_config.clone(),
        cert_and_psk_server(&chain, vec![psk(b"b", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), None);
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());

    // ...unless it requires an external PSK.
    client_config.require_external_psk = true;
    let (mut client, mut server) = connect(
        client_config.clone(),
        cert_and_psk_server(&chain, vec![psk(b"b", HashAlgorithm::SHA256)]),
    );
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::ExternalPskRequired)
    );
    assert_eq!(
        server_res.unwrap_err(),
        Error::AlertReceived(AlertDescription::HandshakeFailure)
    );

    // With a server that knows the key, it is used.
    let (mut client, mut server) = connect(
        client_config,
        cert_and_psk_server(&chain, vec![psk(b"a", HashAlgorithm::SHA256)]),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.external_psk_identity(), Some(&b"a"[..]));
}

#[test]
fn server_requiring_an_external_psk_refuses_certificate_clients() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut server_config = cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    server_config.require_external_psk = true;
    let server_config = Arc::new(server_config);

    // A client without the key would get the certificate otherwise.
    let mut client = ClientConnection::new(
        Arc::new(client_with(
            &chain,
            vec![psk(b"other", HashAlgorithm::SHA256)],
        )),
        server_name(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::ExternalPskRequired)
    );
    assert_eq!(
        client_res.unwrap_err(),
        Error::AlertReceived(AlertDescription::HandshakeFailure)
    );

    let mut client = ClientConnection::new(
        Arc::new(client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)])),
        server_name(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.external_psk_identity(), Some(&b"k"[..]));
}

#[cfg(feature = "tls12")]
#[test]
fn requiring_an_external_psk_refuses_tls12() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // Client side: a TLS 1.2 server.
    let mut client_config = client_config(&chain);
    client_config.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))];
    client_config.require_external_psk = true;
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::ExternalPskRequired)
    );

    // Server side: a TLS 1.2 client.
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut server_config = cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    server_config.require_external_psk = true;
    let (mut client, mut server) = connect(client_config, server_config);
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res.unwrap_err(),
        Error::PeerIncompatible(PeerIncompatible::ExternalPskRequired)
    );
}

// ------------------------------------------- tickets of external-PSK sessions

#[test]
fn tickets_of_external_psk_sessions_keep_the_psk() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let server = |psks: Vec<ExternalPsk>, require: bool| {
        let mut config = cert_and_psk_server(&chain, psks);
        config.session_storage = cache.clone();
        config.require_external_psk = require;
        Arc::new(config)
    };
    let mut client_config = client_with(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
    client_config.require_external_psk = true;
    let client_config = Arc::new(client_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut first =
        ServerConnection::new(server(vec![psk(b"k", HashAlgorithm::SHA256)], false)).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    take_tickets(&mut client, &mut first);

    // Resuming reports the identity, and satisfies `require_external_psk`
    // on both sides.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut second =
        ServerConnection::new(server(vec![psk(b"k", HashAlgorithm::SHA256)], true)).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(second.external_psk_identity(), Some(&b"k"[..]));
    assert!(client.peer_certificates().is_none());
    exchange_data(&mut client, &mut second);
    // Tickets issued on a resumed session carry the PSK forward.
    take_tickets(&mut client, &mut second);

    // A server whose resolver no longer has the key does not resume the
    // session (nor select the key): a certificate handshake follows.
    let mut client_config = (*client_config).clone();
    client_config.require_external_psk = false;
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut third = ServerConnection::new(server(Vec::new(), false)).unwrap();
    do_handshake(&mut client, &mut third).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(third.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), None);
    assert_eq!(third.external_psk_identity(), None);
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
}

#[test]
fn imported_psk_tickets_keep_the_import_context() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let server = |context: &[u8]| {
        let mut config = cert_and_psk_server(
            &chain,
            vec![imported(b"epsk", HashAlgorithm::SHA256, context)],
        );
        config.session_storage = cache.clone();
        // Only the first server issues tickets: the client then holds those.
        if context != b"ctx" {
            config.send_tls13_tickets = 0;
        }
        Arc::new(config)
    };
    let client_config = Arc::new(client_with(
        &chain,
        vec![imported(b"epsk", HashAlgorithm::SHA256, b"ctx")],
    ));
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut first = ServerConnection::new(server(b"ctx")).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    take_tickets(&mut client, &mut first);

    // The server now holds the identity with another importer context: the
    // ticket is not resumed, and the key is not selected either.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut second = ServerConnection::new(server(b"other")).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(second.external_psk_identity(), None);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut third = ServerConnection::new(server(b"ctx")).unwrap();
    do_handshake(&mut client, &mut third).unwrap();
    assert_eq!(third.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(&b"epsk"[..]));
    assert_eq!(third.external_psk_identity(), Some(&b"epsk"[..]));
}

#[test]
fn resumption_rechecks_the_alpn_restriction() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let h2 = b"h2".to_vec();
    let http11 = b"http/1.1".to_vec();
    // SHA-384, the hash of the suite the server prefers: without the key,
    // it would still pick a suite the ticket can resume with.
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let server = |protocols: Vec<Vec<u8>>| {
        let mut config = cert_and_psk_server(
            &chain,
            vec![psk(b"k", HashAlgorithm::SHA384).with_alpn_protocol(b"h2".to_vec())],
        );
        config.session_storage = cache.clone();
        // Only servers that would select the key issue tickets: the client
        // then holds tickets of external-PSK sessions only.
        if !protocols.contains(&b"h2".to_vec()) {
            config.send_tls13_tickets = 0;
        }
        config.alpn_protocols = protocols;
        Arc::new(config)
    };
    let mut client_config = client_with(
        &chain,
        vec![psk(b"k", HashAlgorithm::SHA384).with_alpn_protocol(h2.clone())],
    );
    client_config.alpn_protocols = vec![h2.clone(), http11.clone()];
    let client_config = Arc::new(client_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut first = ServerConnection::new(server(vec![h2.clone()])).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    assert_eq!(first.external_psk_identity(), Some(&b"k"[..]));
    take_tickets(&mut client, &mut first);

    // The server now negotiates another protocol: the key's restriction
    // excludes resuming its session as much as selecting it.
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut second = ServerConnection::new(server(vec![http11])).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(second.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), None);
    assert_eq!(second.external_psk_identity(), None);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut third = ServerConnection::new(server(vec![h2])).unwrap();
    do_handshake(&mut client, &mut third).unwrap();
    assert_eq!(third.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
}

#[test]
fn which_tickets_go_with_external_psks() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // SHA-384, the hash of the suite the certificate session below uses:
    // its ticket must be usable next to the key.
    let resolver = Arc::new(RecordingResolver {
        keys: vec![Arc::new(psk(b"k", HashAlgorithm::SHA384))],
        ..Default::default()
    });
    let mut server_config = server_config(&chain);
    server_config.external_psks = Some(resolver.clone());
    server_config.cert_with_extern_psk = true;
    let server_config = Arc::new(server_config);
    // How many identities the server was offered.
    let offered = || std::mem::take(&mut *resolver.asked.lock().unwrap()).len();

    // A certificate session, whose tickets go to the client's store.
    let base = client_with(&chain, Vec::new());
    let mut client = ClientConnection::new(Arc::new(base.clone()), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    take_tickets(&mut client, &mut server);
    assert_eq!(offered(), 0);

    // Usually the ticket is offered first, then the external PSK.
    let mut with_psk = base.clone();
    with_psk.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA384))];
    let mut client = ClientConnection::new(Arc::new(with_psk.clone()), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(offered(), 2);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(client.external_psk_identity(), None);
    take_tickets(&mut client, &mut server);

    // A client that requires an external PSK does not offer the ticket of a
    // certificate session.
    let mut required = with_psk.clone();
    required.require_external_psk = true;
    let mut client = ClientConnection::new(Arc::new(required), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(offered(), 1);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    take_tickets(&mut client, &mut server);

    // With RFC 8773, no ticket goes along, not even one of an external-PSK
    // session: the server cannot resume instead of authenticating with its
    // certificate.
    let mut cert_with_psk = with_psk;
    cert_with_psk.cert_with_extern_psk = true;
    let mut client = ClientConnection::new(Arc::new(cert_with_psk), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(offered(), 1);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(client.external_psk_identity(), Some(&b"k"[..]));
    assert_eq!(client.peer_certificates().unwrap(), chain.cert_chain());
}

#[test]
fn server_requiring_an_external_psk_passes_over_other_tickets() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls::server::StoresServerSessions> =
        browntls::server::ServerSessionMemoryCache::new(16);
    let server = |require: bool| {
        let mut config = cert_and_psk_server(&chain, vec![psk(b"k", HashAlgorithm::SHA256)]);
        config.session_storage = cache.clone();
        config.require_external_psk = require;
        Arc::new(config)
    };
    let base = client_with(&chain, Vec::new());
    let mut client = ClientConnection::new(Arc::new(base.clone()), server_name()).unwrap();
    let mut first = ServerConnection::new(server(false)).unwrap();
    do_handshake(&mut client, &mut first).unwrap();
    assert_eq!(first.external_psk_identity(), None);
    take_tickets(&mut client, &mut first);

    // The certificate session's ticket comes first, but the server takes
    // the external PSK.
    let mut with_psk = base;
    with_psk.external_psks = vec![Arc::new(psk(b"k", HashAlgorithm::SHA256))];
    let mut client = ClientConnection::new(Arc::new(with_psk), server_name()).unwrap();
    let mut second = ServerConnection::new(server(true)).unwrap();
    do_handshake(&mut client, &mut second).unwrap();
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(second.external_psk_identity(), Some(&b"k"[..]));
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
