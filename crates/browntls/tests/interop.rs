//! Interoperability with rustls 0.23 (ring provider), in both directions.
//!
//! rustls validates browntls's run-time generated certificates with its real
//! web-PKI verifier (the CA is installed as a root), so these tests also check
//! that the certificates browntls sends are well-formed. browntls pins the
//! rustls peer's certificate because path validation in `browntls-pki` is not
//! implemented yet.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::sync::Arc;

use browntls::crypto::rustcrypto;
use common::*;
use rustls::crypto::ring as ring_provider;
use rustls_pki_types as rpki;

// ---------------------------------------------------------------- plumbing

/// The subset of the connection API the tests drive, implemented for both
/// libraries so one transport loop serves every direction.
trait Tls {
    fn wants_tx(&self) -> bool;
    fn write_tls_to(&mut self, out: &mut Vec<u8>);
    fn read_tls_from(&mut self, input: &[u8]) -> std::io::Result<usize>;
    fn process(&mut self) -> Result<bool, String>;
    fn handshaking(&self) -> bool;
    fn write_app(&mut self, data: &[u8]) -> usize;
    fn read_app(&mut self, out: &mut Vec<u8>);
    fn set_unlimited_buffer(&mut self);
    fn send_close(&mut self);
    fn refresh_keys(&mut self) -> bool;
    fn version(&self) -> Option<u16>;
    fn suite(&self) -> Option<u16>;
    fn resumed(&self) -> bool;
    fn alpn(&self) -> Option<Vec<u8>>;
    fn peer_certs(&self) -> Option<Vec<Vec<u8>>>;
}

macro_rules! impl_tls {
    ($ty:ty, $resumed:expr) => {
        impl Tls for $ty {
            fn wants_tx(&self) -> bool {
                self.wants_write()
            }
            fn write_tls_to(&mut self, out: &mut Vec<u8>) {
                self.write_tls(out).unwrap();
            }
            fn read_tls_from(&mut self, mut input: &[u8]) -> std::io::Result<usize> {
                self.read_tls(&mut input)
            }
            fn process(&mut self) -> Result<bool, String> {
                self.process_new_packets()
                    .map(|s| s.peer_has_closed())
                    .map_err(|e| format!("{e:?}"))
            }
            fn handshaking(&self) -> bool {
                self.is_handshaking()
            }
            fn write_app(&mut self, data: &[u8]) -> usize {
                self.writer().write(data).unwrap()
            }
            fn read_app(&mut self, out: &mut Vec<u8>) {
                match self.reader().read_to_end(out) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("read failed: {e}"),
                }
            }
            fn set_unlimited_buffer(&mut self) {
                self.set_buffer_limit(None);
            }
            fn send_close(&mut self) {
                self.send_close_notify();
            }
            fn refresh_keys(&mut self) -> bool {
                self.refresh_traffic_keys().is_ok()
            }
            fn version(&self) -> Option<u16> {
                self.protocol_version().map(u16::from)
            }
            fn suite(&self) -> Option<u16> {
                self.negotiated_cipher_suite().map(|s| u16::from(s.suite()))
            }
            fn resumed(&self) -> bool {
                $resumed(self)
            }
            fn alpn(&self) -> Option<Vec<u8>> {
                self.alpn_protocol().map(|p| p.to_vec())
            }
            fn peer_certs(&self) -> Option<Vec<Vec<u8>>> {
                self.peer_certificates()
                    .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
            }
        }
    };
}

impl_tls!(
    browntls::ClientConnection,
    |c: &browntls::ClientConnection| c.handshake_kind() == Some(browntls::HandshakeKind::Resumed)
);
impl_tls!(
    browntls::ServerConnection,
    |c: &browntls::ServerConnection| c.handshake_kind() == Some(browntls::HandshakeKind::Resumed)
);
impl_tls!(rustls::ClientConnection, |c: &rustls::ClientConnection| c
    .handshake_kind()
    == Some(rustls::HandshakeKind::Resumed));
impl_tls!(rustls::ServerConnection, |c: &rustls::ServerConnection| c
    .handshake_kind()
    == Some(rustls::HandshakeKind::Resumed));

/// Moves every queued TLS byte from `from` into `to`, processing when `to`'s
/// buffer fills up.
fn transfer(from: &mut dyn Tls, to: &mut dyn Tls) {
    let mut buf = Vec::new();
    while from.wants_tx() {
        from.write_tls_to(&mut buf);
    }
    let mut offset = 0;
    while offset < buf.len() {
        match to.read_tls_from(&buf[offset..]) {
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::Other => {
                to.process().unwrap();
            }
            Err(e) => panic!("read_tls failed: {e}"),
        }
    }
}

/// Runs the handshake to completion; returns `(client error, server error)`.
fn handshake(
    client: &mut dyn Tls,
    server: &mut dyn Tls,
) -> (Result<(), String>, Result<(), String>) {
    let mut client_res = Ok(());
    let mut server_res = Ok(());
    for _ in 0..16 {
        if !client.handshaking() && !server.handshaking() {
            break;
        }
        transfer(client, server);
        if let Err(e) = server.process() {
            server_res = Err(e);
            transfer(server, client);
            client_res = client.process().map(|_| ());
            break;
        }
        transfer(server, client);
        if let Err(e) = client.process() {
            client_res = Err(e);
            transfer(client, server);
            server_res = server.process().map(|_| ());
            break;
        }
    }
    (client_res, server_res)
}

fn handshake_ok(client: &mut dyn Tls, server: &mut dyn Tls) {
    let (c, s) = handshake(client, server);
    assert_eq!(c, Ok(()), "client");
    assert_eq!(s, Ok(()), "server");
    assert!(!client.handshaking() && !server.handshaking());
    assert_eq!(client.version(), server.version());
    assert_eq!(client.suite(), server.suite());
}

fn exchange(from: &mut dyn Tls, to: &mut dyn Tls, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut written = 0;
    while written < data.len() || from.wants_tx() {
        written += from.write_app(&data[written..]);
        let mut tls = Vec::new();
        while from.wants_tx() {
            from.write_tls_to(&mut tls);
        }
        let mut offset = 0;
        while offset < tls.len() {
            match to.read_tls_from(&tls[offset..]) {
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::Other => {}
                Err(e) => panic!("read_tls failed: {e}"),
            }
            to.process().unwrap();
            to.read_app(&mut out);
        }
    }
    out
}

fn round_trip(client: &mut dyn Tls, server: &mut dyn Tls) {
    assert_eq!(
        exchange(client, server, b"ping from client"),
        b"ping from client"
    );
    assert_eq!(
        exchange(server, client, b"pong from server"),
        b"pong from server"
    );
}

// ------------------------------------------------------------ rustls config

fn r_certs(chain: &Chain) -> Vec<rpki::CertificateDer<'static>> {
    chain
        .cert_chain()
        .iter()
        .map(|c| rpki::CertificateDer::from(c.as_ref().to_vec()))
        .collect()
}

fn r_key(chain: &Chain) -> rpki::PrivateKeyDer<'static> {
    rpki::PrivateKeyDer::Pkcs8(rpki::PrivatePkcs8KeyDer::from(chain.end_entity_key.clone()))
}

fn r_roots(chain: &Chain) -> Arc<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rpki::CertificateDer::from(chain.ca.as_ref().to_vec()))
        .unwrap();
    Arc::new(roots)
}

static R_TLS12: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
static R_TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
static B_TLS12: [&browntls::SupportedProtocolVersion; 1] = [&browntls::version::TLS12];
static B_TLS13: [&browntls::SupportedProtocolVersion; 1] = [&browntls::version::TLS13];

fn r_versions(version: u16) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match version {
        0x0303 => &R_TLS12,
        0x0304 => &R_TLS13,
        _ => rustls::ALL_VERSIONS,
    }
}

fn b_versions(version: u16) -> &'static [&'static browntls::SupportedProtocolVersion] {
    match version {
        0x0303 => &B_TLS12,
        0x0304 => &B_TLS13,
        _ => browntls::ALL_VERSIONS,
    }
}

/// The ring provider restricted to `suite` and `group` (code points), or
/// everything when `None`.
fn r_provider(suite: Option<u16>, group: Option<u16>) -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = ring_provider::default_provider();
    if let Some(suite) = suite {
        provider
            .cipher_suites
            .retain(|s| u16::from(s.suite()) == suite);
        assert!(
            !provider.cipher_suites.is_empty(),
            "rustls lacks suite {suite:#06x}"
        );
    }
    if let Some(group) = group {
        provider.kx_groups.retain(|g| u16::from(g.name()) == group);
        assert!(
            !provider.kx_groups.is_empty(),
            "rustls lacks group {group:#06x}"
        );
    }
    Arc::new(provider)
}

fn b_provider(suite: Option<u16>, group: Option<u16>) -> Arc<browntls::crypto::CryptoProvider> {
    let mut provider = rustcrypto::default_provider();
    if let Some(suite) = suite {
        provider
            .cipher_suites
            .retain(|s| u16::from(s.suite()) == suite);
    }
    if let Some(group) = group {
        provider.kx_groups.retain(|g| u16::from(g.name()) == group);
    }
    Arc::new(provider)
}

fn r_server(
    chain: &Chain,
    version: u16,
    suite: Option<u16>,
    group: Option<u16>,
) -> rustls::ServerConfig {
    rustls::ServerConfig::builder_with_provider(r_provider(suite, group))
        .with_protocol_versions(r_versions(version))
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(r_certs(chain), r_key(chain))
        .unwrap()
}

fn r_server_with_client_auth(
    chain: &Chain,
    client_chain: &Chain,
    version: u16,
) -> rustls::ServerConfig {
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        r_roots(client_chain),
        r_provider(None, None),
    )
    .build()
    .unwrap();
    rustls::ServerConfig::builder_with_provider(r_provider(None, None))
        .with_protocol_versions(r_versions(version))
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(r_certs(chain), r_key(chain))
        .unwrap()
}

fn r_client(
    chain: &Chain,
    version: u16,
    suite: Option<u16>,
    group: Option<u16>,
) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(r_provider(suite, group))
        .with_protocol_versions(r_versions(version))
        .unwrap()
        .with_root_certificates(r_roots(chain))
        .with_no_client_auth()
}

fn r_client_with_auth(chain: &Chain, client_chain: &Chain, version: u16) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(r_provider(None, None))
        .with_protocol_versions(r_versions(version))
        .unwrap()
        .with_root_certificates(r_roots(chain))
        .with_client_auth_cert(r_certs(client_chain), r_key(client_chain))
        .unwrap()
}

fn r_connect_client(config: rustls::ClientConfig) -> rustls::ClientConnection {
    rustls::ClientConnection::new(
        Arc::new(config),
        rpki::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap()
}

// ---------------------------------------------------------- browntls config

fn b_server(
    chain: &Chain,
    version: u16,
    suite: Option<u16>,
    group: Option<u16>,
) -> browntls::ServerConfig {
    browntls::ServerConfig::builder_with_provider(b_provider(suite, group))
        .with_protocol_versions(b_versions(version))
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

fn b_server_with_client_auth(
    chain: &Chain,
    client_chain: &Chain,
    version: u16,
) -> browntls::ServerConfig {
    browntls::ServerConfig::builder_with_provider(b_provider(None, None))
        .with_protocol_versions(b_versions(version))
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(client_chain, true))
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

fn b_client(
    chain: &Chain,
    version: u16,
    suite: Option<u16>,
    group: Option<u16>,
) -> browntls::ClientConfig {
    browntls::ClientConfig::builder_with_provider(b_provider(suite, group))
        .with_protocol_versions(b_versions(version))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn b_client_with_auth(chain: &Chain, client_chain: &Chain, version: u16) -> browntls::ClientConfig {
    browntls::ClientConfig::builder_with_provider(b_provider(None, None))
        .with_protocol_versions(b_versions(version))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap()
}

fn b_connect_client(config: browntls::ClientConfig) -> browntls::ClientConnection {
    browntls::ClientConnection::new(Arc::new(config), server_name()).unwrap()
}

/// Every (version, suite) the two libraries share, with the key types a
/// server needs for that suite.
fn suite_matrix() -> Vec<(u16, u16, &'static [KeyType])> {
    const ECDSA_KEYS: &[KeyType] = &[KeyType::Ed25519, KeyType::EcdsaP256, KeyType::EcdsaP384];
    const RSA_KEYS: &[KeyType] = &[KeyType::Rsa2048];
    const ALL_KEYS: &[KeyType] = &[
        KeyType::Ed25519,
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::Rsa2048,
    ];
    rustcrypto::ALL_CIPHER_SUITES
        .iter()
        .map(|s| {
            let code = u16::from(s.suite());
            let name = format!("{:?}", s.suite());
            let version = u16::from(s.version().version);
            let keys = if s.tls13().is_some() {
                ALL_KEYS
            } else if name.contains("ECDSA") {
                ECDSA_KEYS
            } else {
                RSA_KEYS
            };
            (version, code, keys)
        })
        .collect()
}

/// The classical groups both providers offer (rustls/ring has no ML-KEM).
const COMMON_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018];

// ----------------------------------------------------------------- matrix

#[test]
fn browntls_client_to_rustls_server_every_suite_group_and_key() {
    init_logging();
    for (version, suite, keys) in suite_matrix() {
        for &key_type in keys {
            let chain = server_chain(key_type);
            for &group in COMMON_GROUPS {
                let mut client =
                    b_connect_client(b_client(&chain, version, Some(suite), Some(group)));
                let mut server =
                    rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None)))
                        .unwrap();
                let (c, s) = handshake(&mut client, &mut server);
                assert_eq!(
                    c,
                    Ok(()),
                    "{version:#06x} {suite:#06x} {group:#06x} {key_type:?}"
                );
                assert_eq!(
                    s,
                    Ok(()),
                    "{version:#06x} {suite:#06x} {group:#06x} {key_type:?}"
                );
                assert_eq!(client.version(), Some(version));
                assert_eq!(client.suite(), Some(suite));
                assert_eq!(server.suite(), Some(suite));
                assert_eq!(
                    client.negotiated_key_exchange_group().unwrap().name(),
                    browntls::NamedGroup::from(group)
                );
                assert_eq!(
                    client.peer_certs().unwrap(),
                    chain
                        .cert_chain()
                        .iter()
                        .map(|c| c.as_ref().to_vec())
                        .collect::<Vec<_>>()
                );
                round_trip(&mut client, &mut server);
            }
        }
    }
}

#[test]
fn rustls_client_to_browntls_server_every_suite_group_and_key() {
    init_logging();
    for (version, suite, keys) in suite_matrix() {
        // The RustCrypto provider does not sign with RSA keys.
        for &key_type in keys.iter().filter(|k| **k != KeyType::Rsa2048) {
            let chain = server_chain(key_type);
            for &group in COMMON_GROUPS {
                let mut client =
                    r_connect_client(r_client(&chain, version, Some(suite), Some(group)));
                let mut server = browntls::ServerConnection::new(Arc::new(b_server(
                    &chain, version, None, None,
                )))
                .unwrap();
                let (c, s) = handshake(&mut client, &mut server);
                assert_eq!(
                    c,
                    Ok(()),
                    "{version:#06x} {suite:#06x} {group:#06x} {key_type:?}"
                );
                assert_eq!(
                    s,
                    Ok(()),
                    "{version:#06x} {suite:#06x} {group:#06x} {key_type:?}"
                );
                assert_eq!(server.version(), Some(version));
                assert_eq!(server.suite(), Some(suite));
                assert_eq!(
                    server.negotiated_key_exchange_group().unwrap().name(),
                    browntls::NamedGroup::from(group)
                );
                assert_eq!(server.server_name(), Some("localhost"));
                round_trip(&mut client, &mut server);
            }
        }
    }
}

// --------------------------------------------------------- version choice

#[test]
fn default_configs_pick_tls13_and_post_quantum_free_group() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);

    let mut client = b_connect_client(b_client(&chain, 0, None, None));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(client.version(), Some(0x0304));
    // browntls offered X25519MLKEM768 first; ring does not know it, so the
    // handshake continues on the X25519 share also sent (no HelloRetryRequest).
    assert_eq!(client.handshake_kind(), Some(browntls::HandshakeKind::Full));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        browntls::NamedGroup::X25519
    );

    let mut client = r_connect_client(r_client(&chain, 0, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(server.version(), Some(0x0304));
    assert_eq!(server.handshake_kind(), Some(browntls::HandshakeKind::Full));
}

#[test]
fn tls12_only_client_accepts_downgrade_sentinel_from_dual_version_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // rustls server (both versions) writes the TLS 1.2 sentinel into
    // ServerHello.random; a client that never offered 1.3 must accept it.
    let mut client = b_connect_client(b_client(&chain, 0x0303, None, None));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(client.version(), Some(0x0303));

    // and the browntls server does the same for a TLS 1.2-only rustls client
    let mut client = r_connect_client(r_client(&chain, 0x0303, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(server.version(), Some(0x0303));
    round_trip(&mut client, &mut server);
}

#[test]
fn version_mismatch_is_a_protocol_version_alert() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = b_connect_client(b_client(&chain, 0x0303, None, None));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, None))).unwrap();
    let (c, s) = handshake(&mut client, &mut server);
    assert!(s.is_err());
    assert_eq!(
        c,
        Err(format!(
            "{:?}",
            browntls::Error::AlertReceived(browntls::AlertDescription::ProtocolVersion)
        ))
    );

    let mut client = r_connect_client(r_client(&chain, 0x0304, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0x0303, None, None))).unwrap();
    let (c, s) = handshake(&mut client, &mut server);
    assert_eq!(
        s,
        Err(format!(
            "{:?}",
            browntls::Error::from(browntls::PeerIncompatible::Tls12NotOfferedOrEnabled)
        ))
    );
    assert_eq!(
        c,
        Err(format!(
            "{:?}",
            rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion)
        ))
    );
}

// ------------------------------------------------------- hello retry request

#[test]
fn hello_retry_request_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);

    // browntls client shares X25519 (its first group) but the rustls server
    // only accepts P-256, which the client also supports.
    let client_provider = {
        let mut p = rustcrypto::default_provider();
        p.kx_groups = vec![
            rustcrypto::kx_group::X25519,
            rustcrypto::kx_group::SECP256R1,
        ];
        Arc::new(p)
    };
    let client_config = browntls::ClientConfig::builder_with_provider(client_provider)
        .with_protocol_versions(&[&browntls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut client = b_connect_client(client_config);
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, Some(0x0017))))
            .unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(
        client.handshake_kind(),
        Some(browntls::HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(rustls::HandshakeKind::FullWithHelloRetryRequest)
    );
    round_trip(&mut client, &mut server);

    // rustls client shares X25519; browntls server only accepts P-256.
    let mut client = r_connect_client(r_client(&chain, 0x0304, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0x0304, None, Some(0x0017))))
            .unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(
        client.handshake_kind(),
        Some(rustls::HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(browntls::HandshakeKind::FullWithHelloRetryRequest)
    );
    round_trip(&mut client, &mut server);
}

// ---------------------------------------------------------------- resumption

#[test]
fn resumption_browntls_client_rustls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in [0x0304u16, 0x0303] {
        for tickets in [false, true] {
            let client_config = Arc::new(b_client(&chain, version, None, None));
            let mut server_config = r_server(&chain, version, None, None);
            if tickets {
                server_config.ticketer = ring_provider::Ticketer::new().unwrap();
                server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            }
            let server_config = Arc::new(server_config);

            let mut client =
                browntls::ClientConnection::new(client_config.clone(), server_name()).unwrap();
            let mut server = rustls::ServerConnection::new(server_config.clone()).unwrap();
            handshake_ok(&mut client, &mut server);
            assert!(!client.resumed());
            // TLS 1.3 tickets arrive after the handshake
            transfer(&mut server, &mut client);
            client.process().unwrap();

            let mut client = browntls::ClientConnection::new(client_config, server_name()).unwrap();
            let mut server = rustls::ServerConnection::new(server_config).unwrap();
            handshake_ok(&mut client, &mut server);
            assert!(
                client.resumed(),
                "{version:#06x} tickets={tickets}: client not resumed"
            );
            assert!(
                server.resumed(),
                "{version:#06x} tickets={tickets}: server not resumed"
            );
            assert_eq!(client.version(), Some(version));
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn resumption_rustls_client_browntls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in [0x0304u16, 0x0303] {
        for tickets in [false, true] {
            let client_config = Arc::new(r_client(&chain, version, None, None));
            let mut server_config = b_server(&chain, version, None, None);
            if tickets {
                server_config.ticketer = rustcrypto::Ticketer::new().unwrap();
                server_config.session_storage =
                    Arc::new(browntls::server::NoServerSessionStorage {});
            }
            let server_config = Arc::new(server_config);

            let mut client = r_connect_client_from(client_config.clone());
            let mut server = browntls::ServerConnection::new(server_config.clone()).unwrap();
            handshake_ok(&mut client, &mut server);
            transfer(&mut server, &mut client);
            client.process().unwrap();

            let mut client = r_connect_client_from(client_config);
            let mut server = browntls::ServerConnection::new(server_config).unwrap();
            handshake_ok(&mut client, &mut server);
            assert!(
                client.resumed(),
                "{version:#06x} tickets={tickets}: client not resumed"
            );
            assert!(
                server.resumed(),
                "{version:#06x} tickets={tickets}: server not resumed"
            );
            round_trip(&mut client, &mut server);
        }
    }
}

fn r_connect_client_from(config: Arc<rustls::ClientConfig>) -> rustls::ClientConnection {
    rustls::ClientConnection::new(config, rpki::ServerName::try_from("localhost").unwrap()).unwrap()
}

// --------------------------------------------------------------- client auth

#[test]
fn client_auth_browntls_client_rustls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in [0x0304u16, 0x0303] {
        for key_type in KeyType::SIGNING {
            let client_chain = client_chain(key_type);
            let mut client = b_connect_client(b_client_with_auth(&chain, &client_chain, version));
            let mut server = rustls::ServerConnection::new(Arc::new(r_server_with_client_auth(
                &chain,
                &client_chain,
                version,
            )))
            .unwrap();
            let (c, s) = handshake(&mut client, &mut server);
            assert_eq!(c, Ok(()), "{version:#06x} {key_type:?}");
            assert_eq!(s, Ok(()), "{version:#06x} {key_type:?}");
            assert_eq!(
                server.peer_certs().unwrap(),
                client_chain
                    .cert_chain()
                    .iter()
                    .map(|c| c.as_ref().to_vec())
                    .collect::<Vec<_>>()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn client_auth_rustls_client_browntls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in [0x0304u16, 0x0303] {
        for key_type in KeyType::ALL {
            let client_chain = client_chain(key_type);
            let mut client = r_connect_client(r_client_with_auth(&chain, &client_chain, version));
            let mut server = browntls::ServerConnection::new(Arc::new(b_server_with_client_auth(
                &chain,
                &client_chain,
                version,
            )))
            .unwrap();
            let (c, s) = handshake(&mut client, &mut server);
            assert_eq!(c, Ok(()), "{version:#06x} {key_type:?}");
            assert_eq!(s, Ok(()), "{version:#06x} {key_type:?}");
            assert_eq!(
                server.peer_certs().unwrap(),
                client_chain
                    .cert_chain()
                    .iter()
                    .map(|c| c.as_ref().to_vec())
                    .collect::<Vec<_>>()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn missing_client_certificate_is_rejected_by_both() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    for version in [0x0304u16, 0x0303] {
        let mut client = b_connect_client(b_client(&chain, version, None, None));
        let mut server = rustls::ServerConnection::new(Arc::new(r_server_with_client_auth(
            &chain,
            &client_chain,
            version,
        )))
        .unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(
            s,
            Err(format!("{:?}", rustls::Error::NoCertificatesPresented))
        );
        assert!(c.is_err());

        let mut client = r_connect_client(r_client(&chain, version, None, None));
        let mut server = browntls::ServerConnection::new(Arc::new(b_server_with_client_auth(
            &chain,
            &client_chain,
            version,
        )))
        .unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(
            s,
            Err(format!("{:?}", browntls::Error::NoCertificatesPresented))
        );
        assert_eq!(
            c,
            Err(format!(
                "{:?}",
                rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRequired)
            ))
        );
    }
}

// -------------------------------------------------------- certificate errors

#[test]
fn rustls_rejects_browntls_server_with_unknown_root() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    for version in [0x0304u16, 0x0303] {
        let mut client = r_connect_client(r_client(&other, version, None, None));
        let mut server =
            browntls::ServerConnection::new(Arc::new(b_server(&chain, version, None, None)))
                .unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        // Both test CAs carry the same subject name, so webpki may try the
        // wrong root and report a bad signature instead of an unknown issuer.
        let unknown = format!(
            "{:?}",
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        );
        let bad_sig = format!(
            "{:?}",
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        );
        assert!(c == Err(unknown) || c == Err(bad_sig), "{c:?}");
        // ...with the matching alert (unknown_ca or decrypt_error) on our side.
        let unknown_ca = format!(
            "{:?}",
            browntls::Error::AlertReceived(browntls::AlertDescription::UnknownCA)
        );
        let decrypt_error = format!(
            "{:?}",
            browntls::Error::AlertReceived(browntls::AlertDescription::DecryptError)
        );
        assert!(s == Err(unknown_ca) || s == Err(decrypt_error), "{s:?}");
    }
}

#[test]
fn browntls_rejects_unexpected_rustls_server_certificate() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    for version in [0x0304u16, 0x0303] {
        let mut client = b_connect_client(b_client(&other, version, None, None));
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(
            c,
            Err(format!(
                "{:?}",
                browntls::Error::from(browntls::CertificateError::UnknownIssuer)
            ))
        );
        assert_eq!(
            s,
            Err(format!(
                "{:?}",
                rustls::Error::AlertReceived(rustls::AlertDescription::UnknownCA)
            ))
        );
    }
}

// ----------------------------------------------------------- post-handshake

#[test]
fn alpn_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for version in [0x0304u16, 0x0303] {
        let mut cc = b_client(&chain, version, None, None);
        cc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut sc = r_server(&chain, version, None, None);
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut client = b_connect_client(cc);
        let mut server = rustls::ServerConnection::new(Arc::new(sc)).unwrap();
        handshake_ok(&mut client, &mut server);
        assert_eq!(client.alpn(), Some(b"http/1.1".to_vec()));
        assert_eq!(server.alpn(), Some(b"http/1.1".to_vec()));

        let mut cc = r_client(&chain, version, None, None);
        cc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut sc = b_server(&chain, version, None, None);
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut client = r_connect_client(cc);
        let mut server = browntls::ServerConnection::new(Arc::new(sc)).unwrap();
        handshake_ok(&mut client, &mut server);
        assert_eq!(client.alpn(), Some(b"http/1.1".to_vec()));
        assert_eq!(server.alpn(), Some(b"http/1.1".to_vec()));
    }
}

#[test]
fn key_update_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);

    let mut client = b_connect_client(b_client(&chain, 0x0304, None, None));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(client.refresh_keys());
    round_trip(&mut client, &mut server);
    assert!(server.refresh_keys());
    round_trip(&mut client, &mut server);

    let mut client = r_connect_client(r_client(&chain, 0x0304, None, None));
    let mut server =
        browntls::ServerConnection::new(Arc::new(b_server(&chain, 0x0304, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(client.refresh_keys());
    round_trip(&mut client, &mut server);
    assert!(server.refresh_keys());
    round_trip(&mut client, &mut server);
}

#[test]
fn large_transfers_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    for version in [0x0304u16, 0x0303] {
        let mut client = b_connect_client(b_client(&chain, version, None, None));
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        handshake_ok(&mut client, &mut server);
        client.set_unlimited_buffer();
        server.set_unlimited_buffer();
        assert_eq!(exchange(&mut client, &mut server, &data), data);
        assert_eq!(exchange(&mut server, &mut client, &data), data);

        let mut client = r_connect_client(r_client(&chain, version, None, None));
        let mut server =
            browntls::ServerConnection::new(Arc::new(b_server(&chain, version, None, None)))
                .unwrap();
        handshake_ok(&mut client, &mut server);
        client.set_unlimited_buffer();
        server.set_unlimited_buffer();
        assert_eq!(exchange(&mut client, &mut server, &data), data);
        assert_eq!(exchange(&mut server, &mut client, &data), data);
    }
}

#[test]
fn close_notify_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for version in [0x0304u16, 0x0303] {
        let mut client = b_connect_client(b_client(&chain, version, None, None));
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        handshake_ok(&mut client, &mut server);
        client.send_close();
        transfer(&mut client, &mut server);
        assert_eq!(server.process(), Ok(true));

        let mut client = r_connect_client(r_client(&chain, version, None, None));
        let mut server =
            browntls::ServerConnection::new(Arc::new(b_server(&chain, version, None, None)))
                .unwrap();
        handshake_ok(&mut client, &mut server);
        server.send_close();
        transfer(&mut server, &mut client);
        assert_eq!(client.process(), Ok(true));
    }
}

#[test]
fn exporter_matches_rustls() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for version in [0x0304u16, 0x0303] {
        let mut client = b_connect_client(b_client(&chain, version, None, None));
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        handshake_ok(&mut client, &mut server);
        let c = client
            .export_keying_material([0u8; 48], b"EXPORTER-interop", Some(b"ctx"))
            .unwrap();
        let s = server
            .export_keying_material([0u8; 48], b"EXPORTER-interop", Some(b"ctx"))
            .unwrap();
        assert_eq!(c, s, "{version:#06x}");
        let c = client
            .export_keying_material([0u8; 48], b"EXPORTER-interop", None)
            .unwrap();
        let s = server
            .export_keying_material([0u8; 48], b"EXPORTER-interop", None)
            .unwrap();
        assert_eq!(c, s, "{version:#06x} (no context)");
    }
}

// ------------------------------------------------------------------ 0-RTT

#[test]
fn early_data_browntls_client_rustls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut cc = b_client(&chain, 0x0304, None, None);
    cc.enable_early_data = true;
    let client_config = Arc::new(cc);
    let mut sc = r_server(&chain, 0x0304, None, None);
    sc.max_early_data_size = 1024;
    let server_config = Arc::new(sc);

    let mut client = browntls::ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = rustls::ServerConnection::new(server_config.clone()).unwrap();
    handshake_ok(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process().unwrap();

    // accepted
    let mut client = browntls::ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"early to rustls")
        .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(client.is_early_data_accepted());
    let mut got = Vec::new();
    server.early_data().unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"early to rustls");
    round_trip(&mut client, &mut server);

    // rejected: the rustls server no longer allows early data
    let mut client = browntls::ClientConnection::new(client_config, server_name()).unwrap();
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, None))).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"discarded")
        .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
    round_trip(&mut client, &mut server);
}

#[test]
fn early_data_rustls_client_browntls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut cc = r_client(&chain, 0x0304, None, None);
    cc.enable_early_data = true;
    let client_config = Arc::new(cc);
    let mut sc = b_server(&chain, 0x0304, None, None);
    sc.max_early_data_size = 1024;
    let cache = sc.session_storage.clone();
    let server_config = Arc::new(sc);

    let mut client = r_connect_client_from(client_config.clone());
    let mut server = browntls::ServerConnection::new(server_config.clone()).unwrap();
    handshake_ok(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process().unwrap();

    // accepted
    let mut client = r_connect_client_from(client_config.clone());
    let mut server = browntls::ServerConnection::new(server_config).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"early to browntls")
        .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(client.is_early_data_accepted());
    let mut got = Vec::new();
    server.early_data().unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"early to browntls");
    round_trip(&mut client, &mut server);

    // rejected: same sessions, early data switched off
    let mut sc = b_server(&chain, 0x0304, None, None);
    sc.session_storage = cache;
    let mut client = r_connect_client_from(client_config);
    let mut server = browntls::ServerConnection::new(Arc::new(sc)).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"discarded")
        .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
    assert_eq!(
        server.handshake_kind(),
        Some(browntls::HandshakeKind::Resumed)
    );
    round_trip(&mut client, &mut server);
}

// ---------------------------------------------------------- raw public keys

/// A rustls verifier pinning one RFC 7250 raw public key.
#[derive(Debug)]
struct RustlsRawKeyVerifier {
    spki: Vec<u8>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for RustlsRawKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rpki::CertificateDer<'_>,
        _intermediates: &[rpki::CertificateDer<'_>],
        _server_name: &rpki::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rpki::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.spki {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rpki::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "raw keys are TLS 1.3 only here".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &rpki::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &rpki::SubjectPublicKeyInfoDer::from(self.spki.as_slice()),
            dss,
            &self.algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// A rustls resolver serving one raw public key.
#[derive(Debug)]
struct RustlsRawKeyResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for RustlsRawKeyResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

fn rustls_raw_key(chain: &Chain) -> Arc<rustls::sign::CertifiedKey> {
    let key = ring_provider::sign::any_supported_type(&r_key(chain)).unwrap();
    Arc::new(rustls::sign::CertifiedKey::new(
        vec![rpki::CertificateDer::from(chain.end_entity_spki.clone())],
        key,
    ))
}

#[test]
fn raw_public_keys_both_directions() {
    init_logging();
    for key_type in KeyType::SIGNING {
        let chain = server_chain(key_type);
        let spki = rpki::CertificateDer::from(chain.end_entity_spki.clone());

        // browntls client, rustls raw-key server
        let server_config = rustls::ServerConfig::builder_with_provider(r_provider(None, None))
            .with_protocol_versions(r_versions(0x0304))
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RustlsRawKeyResolver(rustls_raw_key(&chain))));
        let client_config = browntls::ClientConfig::builder_with_provider(b_provider(None, None))
            .with_protocol_versions(b_versions(0x0304))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::raw_public_key(&chain))
            .with_no_client_auth();
        let mut client = b_connect_client(client_config);
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        handshake_ok(&mut client, &mut server);
        assert_eq!(client.peer_certs().unwrap(), [spki.as_ref().to_vec()]);
        round_trip(&mut client, &mut server);

        // rustls client, browntls raw-key server
        let client_config = rustls::ClientConfig::builder_with_provider(r_provider(None, None))
            .with_protocol_versions(r_versions(0x0304))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RustlsRawKeyVerifier {
                spki: chain.end_entity_spki.clone(),
                algs: ring_provider::default_provider().signature_verification_algorithms,
            }))
            .with_no_client_auth();
        let server_config = browntls::ServerConfig::builder_with_provider(b_provider(None, None))
            .with_protocol_versions(b_versions(0x0304))
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(RawKeyResolver::new(&chain));
        let mut client = r_connect_client(client_config);
        let mut server = browntls::ServerConnection::new(Arc::new(server_config)).unwrap();
        handshake_ok(&mut client, &mut server);
        assert_eq!(client.peer_certs().unwrap(), [spki.as_ref().to_vec()]);
        round_trip(&mut client, &mut server);
    }
}
