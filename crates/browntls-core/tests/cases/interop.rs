// Shared cases, included by `tests/interop.rs` (RustCrypto provider) and
// `tests/interop_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.

use std::io::{Read, Write};
use std::sync::Arc;

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
    browntls_core::ClientConnection,
    |c: &browntls_core::ClientConnection| c.handshake_kind()
        == Some(browntls_core::HandshakeKind::Resumed)
);
impl_tls!(
    browntls_core::ServerConnection,
    |c: &browntls_core::ServerConnection| c.handshake_kind()
        == Some(browntls_core::HandshakeKind::Resumed)
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

#[cfg(feature = "tls12")]
static R_TLS12: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
static R_TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
#[cfg(feature = "tls12")]
static B_TLS12: [&browntls_core::SupportedProtocolVersion; 1] = [&browntls_core::version::TLS12];
static B_TLS13: [&browntls_core::SupportedProtocolVersion; 1] = [&browntls_core::version::TLS13];

/// The versions the per-version cases run with (code points).
#[cfg(feature = "tls12")]
const VERSIONS: [u16; 2] = [0x0304, 0x0303];
#[cfg(not(feature = "tls12"))]
const VERSIONS: [u16; 1] = [0x0304];

fn r_versions(version: u16) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match version {
        #[cfg(feature = "tls12")]
        0x0303 => &R_TLS12,
        0x0304 => &R_TLS13,
        _ => rustls::ALL_VERSIONS,
    }
}

fn b_versions(version: u16) -> &'static [&'static browntls_core::SupportedProtocolVersion] {
    match version {
        #[cfg(feature = "tls12")]
        0x0303 => &B_TLS12,
        0x0304 => &B_TLS13,
        _ => browntls_core::ALL_VERSIONS,
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

/// A rustls provider offering exactly `groups`, in that order.
fn r_provider_with_groups(
    suite: Option<u16>,
    groups: &[u16],
) -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = Arc::unwrap_or_clone(r_provider(suite, None));
    provider.kx_groups = groups
        .iter()
        .map(|group| {
            provider
                .kx_groups
                .iter()
                .copied()
                .find(|g| u16::from(g.name()) == *group)
                .unwrap_or_else(|| panic!("rustls lacks group {group:#06x}"))
        })
        .collect();
    Arc::new(provider)
}

/// `group` first, plus the curve of a `key_type` ECDSA certificate for TLS
/// 1.2: RFC 8422 §5.3 forbids a server from using an ECDSA certificate on a
/// curve the client did not list in `supported_groups`.
fn client_groups(group: u16, version: u16, key_type: KeyType) -> Vec<u16> {
    let mut groups = vec![group];
    let cert_curve = match key_type {
        KeyType::EcdsaP256 => Some(0x0017),
        KeyType::EcdsaP384 => Some(0x0018),
        _ => None,
    };
    if version == 0x0303
        && let Some(curve) = cert_curve
        && curve != group
    {
        groups.push(curve);
    }
    groups
}

fn b_provider(
    suite: Option<u16>,
    group: Option<u16>,
) -> Arc<browntls_core::crypto::CryptoProvider> {
    let mut provider = prov::default_provider();
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
) -> browntls_core::ServerConfig {
    browntls_core::ServerConfig::builder_with_provider(b_provider(suite, group))
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
) -> browntls_core::ServerConfig {
    browntls_core::ServerConfig::builder_with_provider(b_provider(None, None))
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
) -> browntls_core::ClientConfig {
    browntls_core::ClientConfig::builder_with_provider(b_provider(suite, group))
        .with_protocol_versions(b_versions(version))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn b_client_with_auth(
    chain: &Chain,
    client_chain: &Chain,
    version: u16,
) -> browntls_core::ClientConfig {
    browntls_core::ClientConfig::builder_with_provider(b_provider(None, None))
        .with_protocol_versions(b_versions(version))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap()
}

fn b_connect_client(config: browntls_core::ClientConfig) -> browntls_core::ClientConnection {
    browntls_core::ClientConnection::new(Arc::new(config), server_name()).unwrap()
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
    // rustls with ring implements neither AES-CCM suite (RFC 9846
    // Appendix B.4), so the matrix covers the suites both sides implement.
    prov::ALL_CIPHER_SUITES
        .iter()
        .filter(|s| {
            ring_provider::ALL_CIPHER_SUITES
                .iter()
                .any(|r| u16::from(r.suite()) == u16::from(s.suite()))
        })
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

include!("interop/handshakes.rs");
include!("interop/features.rs");
