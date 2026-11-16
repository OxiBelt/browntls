//! Encrypted Client Hello (RFC 9849) between a browntls client and server,
//! with the native provider's HPKE suites.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls::client::{Resumption, WebPkiServerVerifier};
use browntls::crypto::hpke::Hpke;
use browntls::crypto::native::hpke::{ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128};
use browntls::ech::{
    EchConfig, EchGreaseConfig, EchMode, EchServerConfig, EchServerKey, EchStatus,
};
use browntls::pki_types::ServerName;
use browntls::server::ResolvesServerCertUsingSni;
use browntls::sign::CertifiedKey;
use browntls::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, RootCertStore,
    ServerConfig, ServerConnection, version,
};
use common::*;

const SECRET: &str = "secret.example";
const PUBLIC: &str = "public.example";

/// Certificates for the hidden name and the public name, from separate CAs.
struct Certs {
    secret: Chain,
    public: Chain,
}

impl Certs {
    fn new() -> Self {
        let purpose = rcgen::ExtendedKeyUsagePurpose::ServerAuth;
        Self {
            secret: gen_chain(KeyType::EcdsaP256, &[SECRET], purpose.clone()),
            public: gen_chain(KeyType::Ed25519, &[PUBLIC], purpose),
        }
    }

    fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.secret.ca.clone()).unwrap();
        roots.add(self.public.ca.clone()).unwrap();
        Arc::new(roots)
    }

    fn resolver(&self) -> Arc<ResolvesServerCertUsingSni> {
        let mut resolver = ResolvesServerCertUsingSni::new();
        for (name, chain) in [(SECRET, &self.secret), (PUBLIC, &self.public)] {
            resolver
                .add(
                    name,
                    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider())
                        .unwrap(),
                )
                .unwrap();
        }
        Arc::new(resolver)
    }
}

fn server_key(config_id: u8) -> EchServerKey {
    EchServerKey::generate(config_id, PUBLIC, 32, ALL_SUPPORTED_SUITES).unwrap()
}

fn server_config(
    certs: &Certs,
    ech: Option<&Arc<EchServerConfig>>,
    groups: Option<&[&'static dyn browntls::crypto::SupportedKxGroup]>,
) -> ServerConfig {
    let mut provider = prov::default_provider();
    if let Some(groups) = groups {
        provider.kx_groups = groups.to_vec();
    }
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(certs.resolver());
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ech = ech.cloned();
    config.send_tls13_tickets = 2;
    config
}

fn client_config(certs: &Certs, mode: Option<EchMode>) -> ClientConfig {
    let verifier = WebPkiServerVerifier::builder_with_provider(certs.roots(), provider())
        .build()
        .unwrap();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ech_mode = mode;
    config
}

fn enable(list: &[u8]) -> Option<EchMode> {
    Some(EchMode::Enable(
        EchConfig::new(list, ALL_SUPPORTED_SUITES).unwrap(),
    ))
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    connect_arc(Arc::new(client), Arc::new(server))
}

fn connect_arc(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(client, ServerName::try_from(SECRET).unwrap()).unwrap(),
        ServerConnection::new(server).unwrap(),
    )
}

fn assert_accepted(client: &mut ClientConnection, server: &mut ServerConnection) {
    do_handshake(client, server).unwrap();
    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(server.ech_status(), EchStatus::Accepted);
    // The server saw the inner hello: its name and its ALPN offer.
    assert_eq!(server.server_name(), Some(SECRET));
    assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(
        send_and_receive(client, server, b"hidden hello"),
        b"hidden hello"
    );
    assert_eq!(send_and_receive(server, client, b"reply"), b"reply");
}

/// Runs a handshake the server rejects ECH in; returns the client's error.
fn expect_rejected(client: &mut ClientConnection, server: &mut ServerConnection) -> Error {
    let (client_res, server_res) = do_handshake_until_error(client, server);
    assert_eq!(client.ech_status(), EchStatus::Rejected);
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(
            AlertDescription::EncryptedClientHelloRequired
        ))
    );
    client_res.unwrap_err()
}

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
        .filter(|s| s.suite().kem == browntls::crypto::hpke::HpkeKem::DHKEM_P256_HKDF_SHA256)
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

/// The offset in `records` (a client flight) of the ECH extension body of
/// its ClientHello.
fn ech_extension_offset(records: &[u8]) -> usize {
    let mut at = 0;
    while at + 5 <= records.len() {
        let len = usize::from(u16::from_be_bytes([records[at + 3], records[at + 4]]));
        let body = at + 5;
        if records[at] == 22 && records[body] == 1 {
            // Handshake header, version, random, session ID, suites,
            // compression methods.
            let mut p = body + 4 + 2 + 32;
            p += 1 + usize::from(records[p]);
            p += 2 + usize::from(u16::from_be_bytes([records[p], records[p + 1]]));
            p += 1 + usize::from(records[p]);
            let end = p + 2 + usize::from(u16::from_be_bytes([records[p], records[p + 1]]));
            p += 2;
            while p < end {
                let typ = u16::from_be_bytes([records[p], records[p + 1]]);
                let ext_len = usize::from(u16::from_be_bytes([records[p + 2], records[p + 3]]));
                if typ == 0xfe0d {
                    return p + 4;
                }
                p += 4 + ext_len;
            }
        }
        at = body + len;
    }
    panic!("no ClientHello with ECH");
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
        Error::PeerMisbehaved(browntls::PeerMisbehaved::EchChangedOnRetry)
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
        Error::PeerMisbehaved(browntls::PeerMisbehaved::EchDecryptionFailedOnRetry)
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
        Error::PeerMisbehaved(browntls::PeerMisbehaved::IllegalEchClientHelloType)
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
        browntls::psk::ExternalPsk::new(
            b"inner psk identity".to_vec(),
            vec![0x42; 32],
            browntls::crypto::hash::HashAlgorithm::SHA256,
        )
        .unwrap(),
    );
    let mut client_config = client_config(&certs, enable(ech.ech_config_list()));
    client_config.enable_grease = true;
    client_config.client_hello_padding = browntls::client::ClientHelloPadding::AtLeast(1500);
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

// ------------------------------------------------------------- split mode

use browntls::InvalidMessage;
use browntls::ech::split::{ClientFacing, ClientFacingDecision};

/// A back-end server of split mode (RFC 9849 §7.2): no keys, the hidden
/// name's certificate.
fn backend_config(
    certs: &Certs,
    groups: Option<&[&'static dyn browntls::crypto::SupportedKxGroup]>,
) -> ServerConfig {
    let mut config = server_config(certs, None, groups);
    config.ech_backend = true;
    config
}

/// The first error of each party of a split-mode connection.
#[derive(Debug, Default)]
struct SplitErrors {
    client: Option<Error>,
    front: Option<Error>,
    server: Option<Error>,
}

/// An edit of bytes in flight.
type Edit = Box<dyn FnMut(&mut Vec<u8>)>;

/// A client, a client-facing server, and the server that completes the
/// handshake: the back-end server after `Forward`, a local server after
/// `Local`.
struct Split {
    client: ClientConnection,
    front: Option<ClientFacing>,
    backend: Option<ServerConnection>,
    local: Option<ServerConnection>,
    backend_config: Arc<ServerConfig>,
    local_config: Arc<ServerConfig>,
    /// The largest piece of input the client-facing server gets at once.
    chunk: usize,
    /// Applied to each batch the client-facing server forwards to the
    /// back-end server.
    edit_forwarded: Option<Edit>,
    errors: SplitErrors,
}

fn drain<S: browntls::SideData>(conn: &mut browntls::ConnectionCommon<S>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

/// Gives `data` to `conn`, processing when its buffer fills up (an error
/// then stays with the connection, for its next `process_new_packets`).
fn feed<S: browntls::SideData>(conn: &mut browntls::ConnectionCommon<S>, mut data: &[u8]) {
    while !data.is_empty() {
        match conn.read_tls(&mut data) {
            Ok(n) if n > 0 => {}
            _ => {
                if conn.process_new_packets().is_err() {
                    break;
                }
            }
        }
    }
}

impl Split {
    fn new(
        certs: &Certs,
        client: ClientConfig,
        ech: &Arc<EchServerConfig>,
        backend: ServerConfig,
    ) -> Self {
        let local_config = Arc::new(server_config(certs, Some(ech), None));
        Self {
            client: ClientConnection::new(Arc::new(client), ServerName::try_from(SECRET).unwrap())
                .unwrap(),
            front: Some(ClientFacing::new(ech.clone())),
            backend: None,
            local: None,
            backend_config: Arc::new(backend),
            local_config,
            chunk: usize::MAX,
            edit_forwarded: None,
            errors: SplitErrors::default(),
        }
    }

    fn front(&self) -> &ClientFacing {
        self.front.as_ref().expect("still client-facing")
    }

    /// The server completing the handshake.
    fn server(&mut self) -> &mut ServerConnection {
        self.backend
            .as_mut()
            .or(self.local.as_mut())
            .expect("a server")
    }

    /// Moves bytes until nothing changes.
    fn pump(&mut self) {
        for _ in 0..64 {
            let mut moved = false;

            // Client to the client-facing server or the local server.
            let out = drain(&mut self.client);
            moved |= !out.is_empty();
            if let Some(local) = &mut self.local {
                feed(local, &out);
            } else if let Some(front) = &mut self.front {
                for piece in out.chunks(self.chunk.max(1)) {
                    if let Err(e) = front.read_client(piece) {
                        self.errors.front.get_or_insert(e);
                        break;
                    }
                }
            }

            // The decision.
            match self.front.as_ref().and_then(ClientFacing::decision) {
                Some(ClientFacingDecision::Local) if self.local.is_none() => {
                    let front = self.front.take().unwrap();
                    self.local = Some(
                        front
                            .into_server_connection(self.local_config.clone())
                            .unwrap(),
                    );
                    moved = true;
                }
                Some(ClientFacingDecision::Forward) if self.backend.is_none() => {
                    self.backend =
                        Some(ServerConnection::new(self.backend_config.clone()).unwrap());
                    moved = true;
                }
                _ => {}
            }
            if let Some(local) = &mut self.local
                && self.errors.server.is_none()
                && let Err(e) = local.process_new_packets()
            {
                self.errors.server = Some(e);
            }

            // Client-facing server and back-end server.
            if let (Some(front), Some(backend)) = (&mut self.front, &mut self.backend) {
                let mut forwarded = front.take_for_backend();
                if let Some(edit) = &mut self.edit_forwarded
                    && !forwarded.is_empty()
                {
                    edit(&mut forwarded);
                }
                moved |= !forwarded.is_empty();
                feed(backend, &forwarded);
                if self.errors.server.is_none()
                    && let Err(e) = backend.process_new_packets()
                {
                    self.errors.server = Some(e);
                }
                let answer = drain(backend);
                moved |= !answer.is_empty();
                for piece in answer.chunks(self.chunk.max(1)) {
                    if let Err(e) = front.read_backend(piece) {
                        self.errors.front.get_or_insert(e);
                        break;
                    }
                }
            }

            // To the client.
            let to_client = match (&mut self.front, &mut self.local) {
                (_, Some(local)) => drain(local),
                (Some(front), None) => front.take_for_client(),
                (None, None) => Vec::new(),
            };
            moved |= !to_client.is_empty();
            feed(&mut self.client, &to_client);
            if self.errors.client.is_none()
                && let Err(e) = self.client.process_new_packets()
            {
                self.errors.client = Some(e);
            }
            if !moved {
                break;
            }
        }
    }

    /// Application data both ways, through the relay.
    fn exchange(&mut self) {
        self.client.writer().write_all(b"hidden hello").unwrap();
        self.pump();
        let mut got = [0u8; 12];
        self.server().reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hidden hello");
        self.server().writer().write_all(b"reply").unwrap();
        let out = drain(self.server());
        match (&mut self.front, &mut self.local) {
            (_, Some(_)) => feed(&mut self.client, &out),
            (Some(front), None) => {
                front.read_backend(&out).unwrap();
                let out = front.take_for_client();
                feed(&mut self.client, &out);
            }
            (None, None) => unreachable!(),
        }
        self.client.process_new_packets().unwrap();
        let mut got = [0u8; 5];
        self.client.reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, b"reply");
    }

    fn assert_forwarded(&mut self) {
        assert!(
            self.errors.client.is_none()
                && self.errors.front.is_none()
                && self.errors.server.is_none(),
            "{:?}",
            self.errors
        );
        assert!(!self.client.is_handshaking());
        let front = self.front();
        assert_eq!(front.decision(), Some(ClientFacingDecision::Forward));
        assert_eq!(front.ech_status(), EchStatus::Accepted);
        assert_eq!(front.server_name(), Some(SECRET));
        assert!(front.is_relaying());
        assert_eq!(self.client.ech_status(), EchStatus::Accepted);
        let backend = self.backend.as_ref().unwrap();
        assert_eq!(backend.ech_status(), EchStatus::Accepted);
        assert_eq!(backend.server_name(), Some(SECRET));
        assert_eq!(self.client.alpn_protocol(), Some(&b"h2"[..]));
        self.exchange();
    }
}

use std::io::{Read as _, Write as _};

#[test]
fn split_mode_accepted() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let mut split = Split::new(
        &certs,
        client_config(&certs, enable(ech.ech_config_list())),
        &ech,
        backend_config(&certs, None),
    );
    split.pump();
    split.assert_forwarded();
    assert_eq!(split.client.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
fn split_mode_accepted_after_hello_retry_request() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let mut split = Split::new(
        &certs,
        client_config(&certs, enable(ech.ech_config_list())),
        &ech,
        backend_config(&certs, Some(&[prov::kx_group::SECP256R1])),
    );
    split.pump();
    split.assert_forwarded();
    assert_eq!(
        split.client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
}

#[test]
fn split_mode_byte_by_byte() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    for groups in [None, Some(&[prov::kx_group::SECP256R1][..])] {
        for chunk in [1, 3, 200] {
            let mut split = Split::new(
                &certs,
                client_config(&certs, enable(ech.ech_config_list())),
                &ech,
                backend_config(&certs, groups),
            );
            split.chunk = chunk;
            split.pump();
            split.assert_forwarded();
        }
    }
}

#[test]
fn split_mode_with_large_inner_hello() {
    init_logging();
    let certs = Certs::new();
    // A long maximum name length and many ALPN values push the inner
    // ClientHello past one record.
    let key = EchServerKey::generate(3, PUBLIC, 255, ALL_SUPPORTED_SUITES).unwrap();
    let ech = Arc::new(EchServerConfig::new(vec![key]).unwrap());
    let mut client = client_config(&certs, enable(ech.ech_config_list()));
    client.alpn_protocols = (0..1500u32)
        .map(|i| format!("proto-{i:06}").into_bytes())
        .chain([b"h2".to_vec()])
        .collect();
    let mut split = Split::new(&certs, client, &ech, backend_config(&certs, None));
    split.pump();
    split.assert_forwarded();
}

#[test]
fn split_mode_resumption() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(9)]).unwrap());
    let mut client = client_config(&certs, enable(ech.ech_config_list()));
    client.resumption = Resumption::in_memory_sessions(8);
    let client = Arc::new(client);
    let backend = backend_config(&certs, None);
    let mut split = Split::new(&certs, (*client).clone(), &ech, backend.clone());
    split.client =
        ClientConnection::new(client.clone(), ServerName::try_from(SECRET).unwrap()).unwrap();
    split.pump();
    split.assert_forwarded();
    assert!(split.client.tls13_tickets_received() > 0);

    let backend_arc = split.backend_config.clone();
    let mut again = Split::new(&certs, (*client).clone(), &ech, backend);
    again.backend_config = backend_arc;
    again.client = ClientConnection::new(client, ServerName::try_from(SECRET).unwrap()).unwrap();
    again.pump();
    again.assert_forwarded();
    assert_eq!(again.client.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn split_mode_rejected_locally_with_retry_configs() {
    init_logging();
    let certs = Certs::new();
    let stale = EchServerConfig::new(vec![server_key(1)]).unwrap();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(2)]).unwrap());
    for groups in [None, Some(&[prov::kx_group::SECP256R1][..])] {
        let mut split = Split::new(
            &certs,
            client_config(&certs, enable(stale.ech_config_list())),
            &ech,
            backend_config(&certs, groups),
        );
        if groups.is_some() {
            split.local_config = Arc::new(server_config(&certs, Some(&ech), groups));
        }
        split.pump();
        assert!(split.backend.is_none());
        let local = split.local.as_ref().unwrap();
        assert_eq!(local.ech_status(), EchStatus::Rejected);
        assert_eq!(local.server_name(), Some(PUBLIC));
        let Some(Error::RejectedEch(rejected)) = split.errors.client.clone() else {
            panic!("{:?}", split.errors);
        };
        assert_eq!(rejected.retry_configs(), Some(ech.ech_config_list()));

        // The retry reaches the back-end server.
        let mut split = Split::new(
            &certs,
            client_config(&certs, enable(rejected.retry_configs().unwrap())),
            &ech,
            backend_config(&certs, groups),
        );
        split.pump();
        split.assert_forwarded();
    }
}

#[test]
fn split_mode_grease_and_no_ech_stay_local() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(5)]).unwrap());
    let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
    for (mode, status) in [
        (Some(EchMode::Grease(grease)), EchStatus::Rejected),
        (None, EchStatus::NotOffered),
    ] {
        let mut split = Split::new(
            &certs,
            client_config(&certs, mode.clone()),
            &ech,
            backend_config(&certs, None),
        );
        // Before the decision, nothing is forwarded.
        let first = drain(&mut split.client);
        let (head, tail) = first.split_at(first.len() / 2);
        let front = split.front.as_mut().unwrap();
        front.read_client(head).unwrap();
        assert_eq!(front.decision(), None);
        assert!(front.read_backend(b"x").is_err());
        front.read_client(tail).unwrap();
        assert_eq!(front.decision(), Some(ClientFacingDecision::Local));
        assert_eq!(front.ech_status(), status);
        assert_eq!(front.server_name(), Some(SECRET));
        assert!(front.take_for_backend().is_empty());
        let received = split.front.take().unwrap().into_received();
        assert_eq!(received, first);

        // The local server completes the handshake.
        let mut local = ServerConnection::new(split.local_config.clone()).unwrap();
        feed(&mut local, &received);
        local.process_new_packets().unwrap();
        do_handshake(&mut split.client, &mut local).unwrap();
        assert_eq!(local.ech_status(), status);
        assert_eq!(send_and_receive(&mut split.client, &mut local, b"x"), b"x");
    }
}

#[test]
fn split_mode_local_for_unreadable_input() {
    init_logging();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(5)]).unwrap());
    for input in [
        &b"GET / HTTP/1.1\r\n\r\n"[..],
        // A handshake record that is not a ClientHello.
        &[22, 3, 1, 0, 4, 2, 0, 0, 0],
        // A ClientHello that does not parse.
        &[22, 3, 1, 0, 6, 1, 0, 0, 2, 3, 3],
    ] {
        let mut front = ClientFacing::new(ech.clone());
        front.read_client(input).unwrap();
        assert_eq!(
            front.decision(),
            Some(ClientFacingDecision::Local),
            "{input:?}"
        );
        assert_eq!(front.ech_status(), EchStatus::NotOffered);
        // Later bytes are kept for the local server too.
        front.read_client(b"more").unwrap();
        let mut expected = input.to_vec();
        expected.extend_from_slice(b"more");
        assert_eq!(front.into_received(), expected);
    }
    // Not decided yet: no local connection.
    let front = ClientFacing::new(ech);
    assert!(
        front
            .into_server_connection(Arc::new(server_config(&Certs::new(), None, None)))
            .is_err()
    );
}

#[test]
fn split_mode_refuses_malformed_client_hello_framing() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(5)]).unwrap());
    let refused = |input: &[u8], expected: InvalidMessage| {
        let mut front = ClientFacing::new(ech.clone());
        assert_eq!(
            front.read_client(input).unwrap_err(),
            Error::InvalidMessage(expected),
            "{input:?}"
        );
        assert_eq!(front.decision(), None);
        let alert = front.take_for_client();
        assert_eq!(&alert[..5], &[21, 3, 3, 0, 2], "{input:?}");
        // The error stays.
        assert!(front.read_client(&[22]).is_err());
    };
    // A ClientHello followed by more handshake data in its record.
    refused(
        &[22, 3, 1, 0, 5, 1, 0, 0, 0, 9],
        InvalidMessage::TrailingData("ClientHello"),
    );
    // A ClientHello over the handshake message limit.
    refused(
        &[22, 3, 1, 0, 4, 1, 1, 0, 1],
        InvalidMessage::MessageTooLarge,
    );
    // Empty handshake records (RFC 8446 §5.1), which would otherwise be
    // buffered without end, also between fragments of a ClientHello.
    refused(&[22, 3, 1, 0, 0], InvalidMessage::InvalidEmptyPayload);
    refused(
        &[22, 3, 1, 0, 2, 1, 0, 22, 3, 1, 0, 0],
        InvalidMessage::InvalidEmptyPayload,
    );

    // A real ClientHelloOuter with a byte after it in the same record is
    // refused, rather than handed to a local server that would decrypt it
    // and answer for the inner name before noticing.
    let mut client = ClientConnection::new(
        Arc::new(client_config(&certs, enable(ech.ech_config_list()))),
        ServerName::try_from(SECRET).unwrap(),
    )
    .unwrap();
    let mut flight = drain(&mut client);
    let len = usize::from(u16::from_be_bytes([flight[3], flight[4]]));
    assert_eq!(flight.len(), 5 + len, "one record");
    flight.push(0);
    flight[3..5].copy_from_slice(&u16::try_from(len + 1).unwrap().to_be_bytes());
    refused(&flight, InvalidMessage::TrailingData("ClientHello"));
}

#[test]
fn split_mode_refuses_inner_extension_from_the_client() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let mut client = ClientConnection::new(
        Arc::new(client_config(&certs, enable(ech.ech_config_list()))),
        ServerName::try_from(SECRET).unwrap(),
    )
    .unwrap();
    let mut flight = drain(&mut client);
    // An inner ClientHello as forwarded to a back-end server, sent by a
    // client.
    let mut forwarded = ClientFacing::new(ech.clone());
    forwarded.read_client(&flight).unwrap();
    let inner = forwarded.take_for_backend();
    let mut front = ClientFacing::new(ech.clone());
    assert_eq!(
        front.read_client(&inner).unwrap_err(),
        Error::PeerMisbehaved(browntls::PeerMisbehaved::IllegalEchClientHelloType)
    );
    // An unknown type.
    let at = ech_extension_offset(&flight);
    flight[at] = 5;
    let mut front = ClientFacing::new(ech);
    let err = front.read_client(&flight).unwrap_err();
    assert_eq!(
        err,
        Error::PeerMisbehaved(browntls::PeerMisbehaved::IllegalEchClientHelloType)
    );
    // A plaintext illegal_parameter alert for the client.
    assert_eq!(front.take_for_client(), vec![21, 3, 3, 0, 2, 2, 47]);
    assert_eq!(front.read_client(b"x").unwrap_err(), err);
    assert_eq!(front.decision(), None);
}

/// Runs a split-mode handshake with a HelloRetryRequest, editing the
/// client's second flight before the client-facing server reads it.
fn split_second_hello_edited(edit: impl FnOnce(&mut Vec<u8>)) -> (Error, Vec<u8>) {
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let mut client = ClientConnection::new(
        Arc::new(client_config(&certs, enable(ech.ech_config_list()))),
        ServerName::try_from(SECRET).unwrap(),
    )
    .unwrap();
    let mut backend = ServerConnection::new(Arc::new(backend_config(
        &certs,
        Some(&[prov::kx_group::SECP256R1]),
    )))
    .unwrap();
    let mut front = ClientFacing::new(ech);
    front.read_client(&drain(&mut client)).unwrap();
    feed(&mut backend, &front.take_for_backend());
    backend.process_new_packets().unwrap();
    front.read_backend(&drain(&mut backend)).unwrap();
    assert!(!front.is_relaying());
    feed(&mut client, &front.take_for_client());
    client.process_new_packets().unwrap();
    let mut second = drain(&mut client);
    edit(&mut second);
    let err = front.read_client(&second).unwrap_err();
    (err, front.take_for_client())
}

#[test]
fn split_mode_checks_the_second_client_hello() {
    init_logging();
    // config_id changed.
    let (err, alert) = split_second_hello_edited(|buf| {
        let at = ech_extension_offset(buf);
        buf[at + 5] ^= 1;
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(browntls::PeerMisbehaved::EchChangedOnRetry)
    );
    assert_eq!(alert, vec![21, 3, 3, 0, 2, 2, 47]);
    // The payload's last byte altered: decrypt_error.
    let (err, alert) = split_second_hello_edited(|buf| {
        let at = ech_extension_offset(buf);
        let payload_len = usize::from(u16::from_be_bytes([buf[at + 8], buf[at + 9]]));
        buf[at + 9 + payload_len] ^= 1;
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(browntls::PeerMisbehaved::EchDecryptionFailedOnRetry)
    );
    assert_eq!(alert, vec![21, 3, 3, 0, 2, 2, 51]);
    // No ECH extension: its type renamed.
    let (err, alert) = split_second_hello_edited(|buf| {
        let at = ech_extension_offset(buf);
        buf[at - 3] ^= 0x01;
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(browntls::PeerMisbehaved::MissingEchExtensionInSecondClientHello)
    );
    assert_eq!(alert, vec![21, 3, 3, 0, 2, 2, 109]);
    // An extension of an unknown type in its place.
    let (err, _) = split_second_hello_edited(|buf| {
        let at = ech_extension_offset(buf);
        buf[at] = 5;
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(browntls::PeerMisbehaved::IllegalEchClientHelloType)
    );
}

/// The offset of the body of the first `inner` ECH extension (type,
/// length 1, value 1) in `buf`.
fn inner_extension_offset(buf: &[u8]) -> usize {
    buf.windows(5)
        .position(|w| w == [0xfe, 0x0d, 0, 1, 1])
        .expect("an inner ECH extension")
}

#[test]
fn backend_checks_the_forwarded_hellos() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    // The second inner ClientHello loses its `inner` extension, or gets
    // one of another type.
    for (value, expected) in [
        (
            None,
            browntls::PeerMisbehaved::MissingEchExtensionInSecondClientHello,
        ),
        (
            Some(5u8),
            browntls::PeerMisbehaved::IllegalEchClientHelloType,
        ),
    ] {
        let mut split = Split::new(
            &certs,
            client_config(&certs, enable(ech.ech_config_list())),
            &ech,
            backend_config(&certs, Some(&[prov::kx_group::SECP256R1])),
        );
        let mut batches = 0;
        split.edit_forwarded = Some(Box::new(move |buf: &mut Vec<u8>| {
            batches += 1;
            if batches == 2 {
                let at = inner_extension_offset(buf);
                match value {
                    None => buf[at + 1] = 0x0e,
                    Some(v) => buf[at + 4] = v,
                }
            }
        }));
        split.pump();
        assert_eq!(
            split.errors.server,
            Some(Error::PeerMisbehaved(expected.clone())),
            "{:?}",
            split.errors
        );
        assert!(split.errors.client.is_some());
    }

    // An inner ClientHello offering TLS 1.2 (supported_versions rewritten
    // in place: TLS 1.3 becomes TLS 1.2).
    let mut split = Split::new(
        &certs,
        client_config(&certs, enable(ech.ech_config_list())),
        &ech,
        backend_config(&certs, None),
    );
    split.edit_forwarded = Some(Box::new(|buf: &mut Vec<u8>| {
        if let Some(at) = buf.windows(7).position(|w| w == [0, 43, 0, 3, 2, 3, 4]) {
            buf[at + 6] = 3;
        }
    }));
    split.pump();
    assert_eq!(
        split.errors.server,
        Some(Error::PeerMisbehaved(
            browntls::PeerMisbehaved::IllegalEchInnerClientHello
        ))
    );
}

#[test]
fn backend_refuses_outer_extensions() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
    // A client reaching the back-end server directly with ECH or GREASE.
    for mode in [enable(ech.ech_config_list()), Some(EchMode::Grease(grease))] {
        let (mut client, mut server) =
            connect(client_config(&certs, mode), backend_config(&certs, None));
        let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            server_res,
            Err(Error::PeerMisbehaved(
                browntls::PeerMisbehaved::IllegalEchClientHelloType
            ))
        );
    }
    // Without ECH, the back-end server is an ordinary server.
    let (mut client, mut server) =
        connect(client_config(&certs, None), backend_config(&certs, None));
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.ech_status(), EchStatus::NotOffered);
    assert_eq!(client.ech_status(), EchStatus::NotOffered);
}

#[test]
fn backend_and_shared_mode_exclude_each_other() {
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let mut config = server_config(&certs, Some(&ech), None);
    config.ech_backend = true;
    let config = Arc::new(config);
    assert!(ServerConnection::new(config.clone()).is_err());
    // Also through the acceptor.
    let client = ClientConnection::new(
        Arc::new(client_config(&certs, enable(ech.ech_config_list()))),
        ServerName::try_from(SECRET).unwrap(),
    );
    let mut client = client.unwrap();
    let mut acceptor = browntls::server::Acceptor::default();
    let flight = drain(&mut client);
    acceptor.read_tls(&mut &flight[..]).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    assert!(accepted.into_connection(config).is_err());
}

#[test]
fn backend_through_the_acceptor() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let mut client = ClientConnection::new(
        Arc::new(client_config(&certs, enable(ech.ech_config_list()))),
        ServerName::try_from(SECRET).unwrap(),
    )
    .unwrap();
    let mut front = ClientFacing::new(ech);
    front.read_client(&drain(&mut client)).unwrap();
    let mut acceptor = browntls::server::Acceptor::default();
    acceptor
        .read_tls(&mut &front.take_for_backend()[..])
        .unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    assert_eq!(accepted.client_hello().server_name(), Some(SECRET));
    let mut backend = accepted
        .into_connection(Arc::new(backend_config(&certs, None)))
        .unwrap();
    assert_eq!(backend.ech_status(), EchStatus::Accepted);
    front.read_backend(&drain(&mut backend)).unwrap();
    assert!(front.is_relaying());
    feed(&mut client, &front.take_for_client());
    client.process_new_packets().unwrap();
    assert_eq!(client.ech_status(), EchStatus::Accepted);
    do_handshake(&mut client, &mut backend).unwrap();
    assert_eq!(send_and_receive(&mut client, &mut backend, b"y"), b"y");
}

#[test]
fn backend_alert_reaches_the_client() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    // A back-end server without the hidden name's certificate.
    let mut backend = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new()));
    backend.ech_backend = true;
    let mut split = Split::new(
        &certs,
        client_config(&certs, enable(ech.ech_config_list())),
        &ech,
        backend,
    );
    split.pump();
    assert!(split.errors.server.is_some());
    assert!(
        matches!(split.errors.client, Some(Error::AlertReceived(_))),
        "{:?}",
        split.errors
    );
    assert!(split.front().is_relaying());
}

#[test]
fn trial_decryption_with_random_config_ids() {
    init_logging();
    let certs = Certs::new();
    let key = server_key(7);
    let ech = Arc::new(
        EchServerConfig::new(vec![server_key(1), key.clone()])
            .unwrap()
            .with_trial_decryption()
            .with_public_name_check(),
    );
    assert!(ech.trial_decryption() && ech.public_name_check());
    let one = EchServerConfig::new(vec![key]).unwrap();
    let config = EchConfig::new(one.ech_config_list(), ALL_SUPPORTED_SUITES)
        .unwrap()
        .with_random_config_id();
    assert!(config.random_config_id());
    let mut ids = Vec::new();
    for groups in [None, Some(&[prov::kx_group::SECP256R1][..])] {
        for _ in 0..4 {
            // Shared mode.
            let (mut client, mut server) = connect(
                client_config(&certs, Some(EchMode::Enable(config.clone()))),
                server_config(&certs, Some(&ech), groups),
            );
            let flight = drain(&mut client);
            ids.push(flight[ech_extension_offset(&flight) + 5]);
            feed(&mut server, &flight);
            server.process_new_packets().unwrap();
            assert_accepted(&mut client, &mut server);

            // Split mode.
            let mut split = Split::new(
                &certs,
                client_config(&certs, Some(EchMode::Enable(config.clone()))),
                &ech,
                backend_config(&certs, groups),
            );
            split.pump();
            split.assert_forwarded();
        }
    }
    // The identifiers sent are random (eight equal to 7 by chance:
    // probability 2^-64).
    assert!(ids.iter().any(|id| *id != 7), "{ids:?}");
}

#[cfg(feature = "rustcrypto")]
#[test]
fn backend_on_the_rustcrypto_provider() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    // The back-end server needs no HPKE: only HKDF for the confirmations.
    let provider = Arc::new(browntls::crypto::rustcrypto::default_provider());
    let resolver = {
        let mut resolver = ResolvesServerCertUsingSni::new();
        resolver
            .add(
                SECRET,
                CertifiedKey::from_der(
                    certs.secret.cert_chain(),
                    certs.secret.private_key(),
                    &provider,
                )
                .unwrap(),
            )
            .unwrap();
        Arc::new(resolver)
    };
    for groups in [false, true] {
        let mut prov = (*provider).clone();
        if groups {
            prov.kx_groups = vec![browntls::crypto::rustcrypto::kx_group::SECP256R1];
        }
        let mut backend = ServerConfig::builder_with_provider(Arc::new(prov))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        backend.alpn_protocols = vec![b"h2".to_vec()];
        backend.ech_backend = true;
        let mut split = Split::new(
            &certs,
            client_config(&certs, enable(ech.ech_config_list())),
            &ech,
            backend,
        );
        split.pump();
        split.assert_forwarded();
    }
}
