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
