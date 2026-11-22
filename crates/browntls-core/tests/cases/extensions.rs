// Shared cases, included by `tests/extensions.rs` (RustCrypto provider) and
// `tests/extensions_native.rs` (native provider): `record_size_limit`
// (RFC 8449), `ticket_request` (RFC 9149), GREASE (RFC 8701) and `padding`
// (RFC 7685). Provider items are reached through the including target's
// `prov` module.
//
// Several cases look at, or change, the bytes on the wire: the hello
// messages are unprotected, so a changed ServerHello reaches the client's
// checks before any transcript does.

use std::sync::Arc;

use browntls_core::client::{ClientHelloPadding, TicketRequest};
use browntls_core::{
    ClientConfig, ClientConnection, Error, HandshakeKind, NamedGroup, PeerMisbehaved, ServerConfig,
    ServerConnection, version,
};
use common::*;

#[path = "extensions/record_size_limit.rs"]
mod record_size_limit;

// ------------------------------------------------------------- wire helpers

const EXT_PADDING: u16 = 0x0015;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_TICKET_REQUEST: u16 = 0x003a;

fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

/// One extension of a hello message: its type, where its body starts in
/// the buffer, and the body.
#[derive(Debug, Clone)]
struct Ext {
    typ: u16,
    at: usize,
    body: Vec<u8>,
}

/// A ClientHello or ServerHello at the start of `buf` (one record).
#[derive(Debug)]
struct Hello {
    /// The handshake message length, header included.
    message_len: usize,
    /// The offered suites (ClientHello) or the selected one (ServerHello).
    suites: Vec<u16>,
    /// Where the (first) cipher suite is in the buffer.
    suites_at: usize,
    exts: Vec<Ext>,
}

impl Hello {
    fn parse(buf: &[u8], client: bool) -> Self {
        assert_eq!(buf[0], 22, "not a handshake record");
        assert_eq!(buf[5], if client { 1 } else { 2 });
        let message_len = 4 + (usize::from(buf[6]) << 16 | usize::from(u16_at(buf, 7)));
        let mut at = 9 + 2 + 32;
        at += 1 + usize::from(buf[at]);
        let (suites, suites_at) = if client {
            let len = usize::from(u16_at(buf, at));
            let suites = (0..len / 2).map(|i| u16_at(buf, at + 2 + 2 * i)).collect();
            let suites_at = at + 2;
            at += 2 + len;
            at += 1 + usize::from(buf[at]);
            (suites, suites_at)
        } else {
            let suite = u16_at(buf, at);
            at += 3;
            (vec![suite], at - 3)
        };
        let end = at + 2 + usize::from(u16_at(buf, at));
        at += 2;
        let mut exts = Vec::new();
        while at < end {
            let typ = u16_at(buf, at);
            let len = usize::from(u16_at(buf, at + 2));
            exts.push(Ext {
                typ,
                at: at + 4,
                body: buf[at + 4..at + 4 + len].to_vec(),
            });
            at += 4 + len;
        }
        assert_eq!(at, end);
        assert_eq!(end, 5 + message_len, "hello spans more than one record");
        Self {
            message_len,
            suites,
            suites_at,
            exts,
        }
    }

    fn ext(&self, typ: u16) -> Option<&Ext> {
        self.exts.iter().find(|e| e.typ == typ)
    }

    fn types(&self) -> Vec<u16> {
        self.exts.iter().map(|e| e.typ).collect()
    }
}

/// The u16 list in an extension body with a u16 length prefix.
fn u16_list(body: &[u8]) -> Vec<u16> {
    assert_eq!(usize::from(u16_at(body, 0)), body.len() - 2);
    (0..(body.len() - 2) / 2)
        .map(|i| u16_at(body, 2 + 2 * i))
        .collect()
}

fn flight(conn: &mut browntls_core::ConnectionCommon<impl browntls_core::SideData>) -> Vec<u8> {
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf).unwrap();
    }
    buf
}

fn feed(
    conn: &mut browntls_core::ConnectionCommon<impl browntls_core::SideData>,
    mut bytes: &[u8],
) {
    while !bytes.is_empty() {
        conn.read_tls(&mut bytes).unwrap();
    }
}

/// The records in `buf`: content type and body.
fn records(mut buf: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let len = usize::from(u16_at(buf, 3));
        out.push((buf[0], buf[5..5 + len].to_vec()));
        buf = &buf[5 + len..];
    }
    out
}

fn client_with(
    chain: &Chain,
    versions: &[&'static browntls_core::SupportedProtocolVersion],
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn client_with_groups(chain: &Chain, groups: &[NamedGroup]) -> ClientConfig {
    let mut provider = prov::default_provider();
    provider.kx_groups = groups
        .iter()
        .map(|name| {
            *prov::ALL_KX_GROUPS
                .iter()
                .find(|g| g.name() == *name)
                .unwrap()
        })
        .collect();
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn server_with(
    chain: &Chain,
    versions: &[&'static browntls_core::SupportedProtocolVersion],
) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

fn all_versions() -> Vec<&'static browntls_core::SupportedProtocolVersion> {
    let mut v = vec![&version::TLS13];
    if cfg!(feature = "tls12") {
        v.push(versions_tls12());
    }
    v
}

#[cfg(feature = "tls12")]
fn versions_tls12() -> &'static browntls_core::SupportedProtocolVersion {
    &version::TLS12
}

#[cfg(not(feature = "tls12"))]
fn versions_tls12() -> &'static browntls_core::SupportedProtocolVersion {
    &version::TLS13
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

/// The largest record body `from` sends while transferring `len` bytes of
/// application data; checks the data arrives intact.
fn largest_app_record(
    from: &mut browntls_core::ConnectionCommon<impl browntls_core::SideData>,
    to: &mut browntls_core::ConnectionCommon<impl browntls_core::SideData>,
    len: usize,
) -> usize {
    use std::io::{Read, Write};
    let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
    from.writer().write_all(&data).unwrap();
    let bytes = flight(from);
    let largest = records(&bytes)
        .iter()
        .filter(|(typ, _)| *typ == 23)
        .map(|(_, body)| body.len())
        .max()
        .unwrap();
    let mut got = Vec::new();
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        // A full receive buffer is processed and drained below.
        let _ = to.read_tls(&mut rest);
        to.process_new_packets().unwrap();
        let _ = to.reader().read_to_end(&mut got);
    }
    assert_eq!(got, data);
    largest
}

// -------------------------------------------------------- record_size_limit

/// The largest TLS 1.3 record body for a TLSInnerPlaintext limit: the AEAD
/// tag of every suite in the default lists is 16 bytes.
const TLS13_TAG: usize = 16;
/// TLS 1.2 AES-GCM: 8-byte explicit nonce and 16-byte tag.
const TLS12_GCM_EXPANSION: usize = 24;

#[test]
fn record_size_limits_bound_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in all_versions() {
        let tls13 = version.version == browntls_core::ProtocolVersion::TLSv1_3;
        let mut client_config = client_with(&chain, &[version]);
        client_config.record_size_limit = Some(64);
        // AES-GCM, whose TLS 1.2 expansion is known.
        let mut provider = prov::default_provider();
        provider.cipher_suites.retain(|s| {
            matches!(
                s.suite(),
                browntls_core::CipherSuite::TLS13_AES_128_GCM_SHA256
                    | browntls_core::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            )
        });
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        server_config.record_size_limit = Some(100);

        let (mut client, mut server) = connect(client_config, server_config);
        // The server's protected handshake records already respect the
        // client's limit (TLS 1.3: EncryptedExtensions onwards).
        feed(&mut server, &flight(&mut client));
        server.process_new_packets().unwrap();
        let server_flight = flight(&mut server);
        let expansion = if tls13 {
            TLS13_TAG
        } else {
            TLS12_GCM_EXPANSION
        };
        for (typ, body) in records(&server_flight) {
            if typ == 23 {
                assert!(body.len() <= 64 + expansion, "{version:?}: {}", body.len());
            }
        }
        feed(&mut client, &server_flight);
        client.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();

        let from_server = largest_app_record(&mut server, &mut client, 5000);
        let from_client = largest_app_record(&mut client, &mut server, 5000);
        assert_eq!(from_server, 64 + expansion, "{version:?}");
        assert_eq!(from_client, 100 + expansion, "{version:?}");
    }
}

#[test]
fn record_size_limit_and_max_fragment_size_smaller_wins() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // The local setting is smaller: 37 bytes including the header, 32 of
    // plaintext, plus the content type and tag in TLS 1.3.
    let mut client_config = client_with(&chain, &[&version::TLS13]);
    client_config.max_fragment_size = Some(37);
    let mut server_config = server_with(&chain, &[&version::TLS13]);
    server_config.record_size_limit = Some(1000);
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        largest_app_record(&mut client, &mut server, 3000),
        32 + 1 + TLS13_TAG
    );

    // The peer's limit is smaller.
    let mut client_config = client_with(&chain, &[&version::TLS13]);
    client_config.max_fragment_size = Some(2000);
    let mut server_config = server_with(&chain, &[&version::TLS13]);
    server_config.record_size_limit = Some(64);
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        largest_app_record(&mut client, &mut server, 3000),
        64 + TLS13_TAG
    );
}

#[test]
fn record_size_limit_defaults_announce_the_protocol_maximum() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    // TLS 1.3 offered: 2^14 + 1, also when configured higher.
    for limit in [Some(16_385), Some(u16::MAX)] {
        let mut config = client_config(&chain);
        config.record_size_limit = limit;
        let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
        let hello = Hello::parse(&flight(&mut client), true);
        assert_eq!(
            hello.ext(EXT_RECORD_SIZE_LIMIT).unwrap().body,
            16_385u16.to_be_bytes()
        );
    }
    // Not sent at all.
    let mut config = client_config(&chain);
    config.record_size_limit = None;
    let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    assert!(
        Hello::parse(&flight(&mut client), true)
            .ext(EXT_RECORD_SIZE_LIMIT)
            .is_none()
    );

    // Full-sized records flow with the default limits.
    let (mut client, mut server) = connect(client_config(&chain), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        largest_app_record(&mut client, &mut server, 40_000),
        16_384 + 1 + TLS13_TAG
    );
    assert_eq!(
        largest_app_record(&mut server, &mut client, 40_000),
        16_384 + 1 + TLS13_TAG
    );
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_record_size_limit_is_clamped_and_answered_in_server_hello() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_with(&chain, &[&version::TLS12]);
    client_config.record_size_limit = Some(u16::MAX);
    let mut server_config = server_with(&chain, &[&version::TLS12]);
    server_config.record_size_limit = Some(u16::MAX);
    let (mut client, mut server) = connect(client_config, server_config);
    let client_hello = flight(&mut client);
    assert_eq!(
        Hello::parse(&client_hello, true)
            .ext(EXT_RECORD_SIZE_LIMIT)
            .unwrap()
            .body,
        16_384u16.to_be_bytes()
    );
    feed(&mut server, &client_hello);
    server.process_new_packets().unwrap();
    let server_flight = flight(&mut server);
    assert_eq!(
        Hello::parse(&server_flight, false)
            .ext(EXT_RECORD_SIZE_LIMIT)
            .unwrap()
            .body,
        16_384u16.to_be_bytes()
    );
    feed(&mut client, &server_flight);
    client.process_new_packets().unwrap();
    do_handshake(&mut client, &mut server).unwrap();

    // A server configured without the extension does not answer, and
    // neither side's limit applies.
    let mut client_config = client_with(&chain, &[&version::TLS12]);
    client_config.record_size_limit = Some(64);
    let mut server_config = server_with(&chain, &[&version::TLS12]);
    server_config.record_size_limit = None;
    let (mut client, mut server) = connect(client_config, server_config);
    feed(&mut server, &flight(&mut client));
    server.process_new_packets().unwrap();
    let server_flight = flight(&mut server);
    assert!(
        Hello::parse(&server_flight, false)
            .ext(EXT_RECORD_SIZE_LIMIT)
            .is_none()
    );
    feed(&mut client, &server_flight);
    client.process_new_packets().unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(largest_app_record(&mut server, &mut client, 5000) > 4000);
}

#[test]
fn record_size_limit_below_64_is_refused() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut config = client_config(&chain);
    config.record_size_limit = Some(63);
    assert_eq!(
        ClientConnection::new(Arc::new(config), server_name()).err(),
        Some(Error::BadRecordSizeLimit)
    );
    let mut config = server_config(&chain);
    config.record_size_limit = Some(63);
    assert_eq!(
        ServerConnection::new(Arc::new(config)).err(),
        Some(Error::BadRecordSizeLimit)
    );

    // From the client: the server answers illegal_parameter (RFC 8449 §4).
    for configured in [Some(64), None] {
        let mut config = client_config(&chain);
        config.record_size_limit = Some(64);
        let mut server_config = server_config(&chain);
        server_config.record_size_limit = configured;
        let (mut client, mut server) = connect(config, server_config);
        let mut hello = flight(&mut client);
        let at = Hello::parse(&hello, true)
            .ext(EXT_RECORD_SIZE_LIMIT)
            .unwrap()
            .at;
        hello[at..at + 2].copy_from_slice(&63u16.to_be_bytes());
        feed(&mut server, &hello);
        assert_eq!(
            server.process_new_packets().err(),
            Some(Error::PeerMisbehaved(
                PeerMisbehaved::IllegalRecordSizeLimit
            ))
        );
        let alert = records(&flight(&mut server));
        assert_eq!(alert, [(21, vec![2, 47])]);
    }
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_server_record_size_limit_below_64_is_refused() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut server_config = server_with(&chain, &[&version::TLS12]);
    server_config.record_size_limit = Some(64);
    let (mut client, mut server) = connect(client_with(&chain, &[&version::TLS12]), server_config);
    feed(&mut server, &flight(&mut client));
    server.process_new_packets().unwrap();
    let mut server_flight = flight(&mut server);
    let at = Hello::parse(&server_flight, false)
        .ext(EXT_RECORD_SIZE_LIMIT)
        .unwrap()
        .at;
    server_flight[at..at + 2].copy_from_slice(&10u16.to_be_bytes());
    feed(&mut client, &server_flight);
    assert_eq!(
        client.process_new_packets().err(),
        Some(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalRecordSizeLimit
        ))
    );
}

// ------------------------------------------------------------ ticket_request

/// Runs a TLS 1.3 handshake plus the server's first post-handshake flight
/// and returns how many tickets the client received.
fn tickets_received(client: &mut ClientConnection, server: &mut ServerConnection) -> u32 {
    do_handshake(client, server).unwrap();
    transfer(server, client);
    client.process_new_packets().unwrap();
    client.tls13_tickets_received()
}

#[test]
fn ticket_request_bounds_the_tickets_sent() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for (requested, server_max, expected) in [(1, 3, 1), (0, 3, 0), (5, 3, 3), (2, 0, 0)] {
        let mut client_config = client_with(&chain, &[&version::TLS13]);
        client_config.tls13_ticket_request = Some(TicketRequest {
            new_session_count: requested,
            resumption_count: 0,
        });
        let mut server_config = server_config(&chain);
        server_config.send_tls13_tickets = server_max;
        let (mut client, mut server) = connect(client_config, server_config);
        assert_eq!(
            tickets_received(&mut client, &mut server),
            expected,
            "requested {requested}, server maximum {server_max}"
        );
    }

    // Without the extension the server sends its own number.
    let (mut client, mut server) = connect(
        client_with(&chain, &[&version::TLS13]),
        server_config(&chain),
    );
    assert_eq!(tickets_received(&mut client, &mut server), 2);
}

#[test]
fn client_ticket_limit_bounds_acceptance() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for limit in [0, 3, 8, 255] {
        let mut client_config = client_with(&chain, &[&version::TLS13]);
        client_config.max_tls13_tickets_per_connection = limit;
        let mut server_config = server_config(&chain);
        server_config.send_tls13_tickets = limit + 2;
        let (mut client, mut server) = connect(client_config, server_config);
        assert_eq!(tickets_received(&mut client, &mut server), limit as u32);
        assert!(!client.is_handshaking());
    }
}

#[test]
fn client_ticket_limit_validates_and_clamps_the_request() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut config = client_with(&chain, &[&version::TLS13]);
    config.max_tls13_tickets_per_connection = 256;
    assert!(matches!(
        ClientConnection::new(Arc::new(config), server_name()),
        Err(Error::BadTls13TicketLimit)
    ));

    for (limit, expected) in [(0, 0), (3, 3), (255, 200)] {
        let mut config = client_with(&chain, &[&version::TLS13]);
        config.max_tls13_tickets_per_connection = limit;
        config.tls13_ticket_request = Some(TicketRequest {
            new_session_count: 200,
            resumption_count: 6,
        });
        let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
        let hello = Hello::parse(&flight(&mut client), true);
        let body = &hello.ext(EXT_TICKET_REQUEST).unwrap().body;
        assert_eq!(body, &[expected, 6.min(expected)]);
    }
}

#[test]
fn ticket_request_resumption_count_applies_to_resumed_sessions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_with(&chain, &[&version::TLS13]);
    client_config.tls13_ticket_request = Some(TicketRequest {
        new_session_count: 3,
        resumption_count: 1,
    });
    let client_config = Arc::new(client_config);
    let mut server_config = server_config(&chain);
    server_config.send_tls13_tickets = 4;
    let server_config = Arc::new(server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    assert_eq!(tickets_received(&mut client, &mut server), 3);

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    assert_eq!(tickets_received(&mut client, &mut server), 1);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn ticket_request_is_sent_only_with_tls13() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let request = Some(TicketRequest {
        new_session_count: 1,
        resumption_count: 1,
    });
    let mut config = client_config(&chain);
    config.tls13_ticket_request = request;
    let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    assert_eq!(
        Hello::parse(&flight(&mut client), true)
            .ext(EXT_TICKET_REQUEST)
            .unwrap()
            .body,
        [1, 1]
    );
    if cfg!(feature = "tls12") {
        let mut config = client_with(&chain, &[versions_tls12()]);
        config.tls13_ticket_request = request;
        let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
        assert!(
            Hello::parse(&flight(&mut client), true)
                .ext(EXT_TICKET_REQUEST)
                .is_none()
        );
    }
}

// ------------------------------------------------------------------- GREASE

#[test]
fn grease_values_fill_the_client_hello_and_are_ignored() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_config(&chain);
    client_config.enable_grease = true;
    // Padding forced, to check its place before pre_shared_key.
    client_config.client_hello_padding = ClientHelloPadding::AtLeast(2000);
    let client_config = Arc::new(client_config);
    let server_config = Arc::new(server_config(&chain));

    for resuming in [false, true] {
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        let bytes = flight(&mut client);
        let hello = Hello::parse(&bytes, true);
        assert!(is_grease(hello.suites[0]));
        assert!(hello.suites[1..].iter().all(|s| !is_grease(*s)));

        let first = &hello.exts[0];
        assert!(is_grease(first.typ) && first.body.is_empty());
        let others: Vec<&Ext> = hello.exts[1..]
            .iter()
            .filter(|e| is_grease(e.typ))
            .collect();
        assert_eq!(others.len(), 1);
        assert_ne!(others[0].typ, first.typ);
        assert!(!others[0].body.is_empty());

        let groups = u16_list(&hello.ext(EXT_SUPPORTED_GROUPS).unwrap().body);
        assert!(is_grease(groups[0]));
        let schemes = u16_list(&hello.ext(EXT_SIGNATURE_ALGORITHMS).unwrap().body);
        assert!(is_grease(schemes[0]));
        let versions = &hello.ext(EXT_SUPPORTED_VERSIONS).unwrap().body;
        assert!(is_grease(u16_at(versions, 1)));
        let modes = &hello.ext(EXT_PSK_KEY_EXCHANGE_MODES).unwrap().body;
        assert_eq!(usize::from(modes[0]), modes.len() - 1);
        assert!(
            modes[1] >= 0x0b && (modes[1] - 0x0b).is_multiple_of(0x1f),
            "{:#x}",
            modes[1]
        );
        let shares = &hello.ext(EXT_KEY_SHARE).unwrap().body;
        // The first share: the GREASE group of supported_groups, one byte.
        assert_eq!(u16_at(shares, 2), groups[0]);
        assert_eq!(u16_at(shares, 4), 1);

        // Order: ..., second GREASE, padding, pre_shared_key.
        let types = hello.types();
        let n = types.len();
        if resuming {
            assert_eq!(types[n - 1], EXT_PRE_SHARED_KEY);
            assert_eq!(types[n - 2], EXT_PADDING);
            assert_eq!(types[n - 3], others[0].typ);
        } else {
            assert_eq!(types[n - 1], EXT_PADDING);
            assert_eq!(types[n - 2], others[0].typ);
        }
        assert!(hello.message_len >= 2000);
        assert!(hello.ext(EXT_PADDING).unwrap().body.iter().all(|b| *b == 0));

        feed(&mut server, &bytes);
        server.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.handshake_kind(),
            Some(if resuming {
                HandshakeKind::Resumed
            } else {
                HandshakeKind::Full
            })
        );
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"grease"),
            b"grease"
        );
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
    }

    if cfg!(feature = "tls12") {
        // A TLS 1.2-only server ignores the GREASE values too.
        let mut config = common::client_config(&chain);
        config.enable_grease = true;
        let (mut client, mut server) = connect(config, server_with(&chain, &[versions_tls12()]));
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.protocol_version(), Some(versions_tls12().version));
    }
}

#[test]
fn grease_values_survive_a_hello_retry_request_without_a_grease_key_share() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config =
        client_with_groups(&chain, &[NamedGroup::secp384r1, NamedGroup::X25519]);
    client_config.enable_grease = true;
    let mut provider = prov::default_provider();
    provider
        .kx_groups
        .retain(|g| g.name() == NamedGroup::X25519);
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);

    let first_bytes = flight(&mut client);
    let first = Hello::parse(&first_bytes, true);
    feed(&mut server, &first_bytes);
    server.process_new_packets().unwrap();
    feed(&mut client, &flight(&mut server));
    client.process_new_packets().unwrap();
    let second_bytes = flight(&mut client);
    // The second ClientHello follows a ChangeCipherSpec record.
    let start = if second_bytes[0] == 20 { 6 } else { 0 };
    let second = Hello::parse(&second_bytes[start..], true);

    assert_eq!(first.suites, second.suites);
    assert_eq!(first.exts[0].typ, second.exts[0].typ);
    for typ in [
        EXT_SUPPORTED_GROUPS,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_SUPPORTED_VERSIONS,
    ] {
        assert_eq!(first.ext(typ).unwrap().body, second.ext(typ).unwrap().body);
    }
    // Exactly one key share, for the group the server asked for.
    let shares = &second.ext(EXT_KEY_SHARE).unwrap().body;
    assert_eq!(u16_at(shares, 2), u16::from(NamedGroup::X25519));
    assert_eq!(usize::from(u16_at(shares, 0)), 4 + 32);

    feed(&mut server, &second_bytes);
    server.process_new_packets().unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
}

/// Runs a GREASE ClientHello through a server, lets `patch` change the
/// server's flight using the ClientHello, and returns the client's error.
fn client_error_after_patch(
    client_config: ClientConfig,
    server_config: ServerConfig,
    patch: impl FnOnce(&Hello, &Hello, &mut Vec<u8>),
) -> Error {
    let (mut client, mut server) = connect(client_config, server_config);
    let client_hello = flight(&mut client);
    feed(&mut server, &client_hello);
    server.process_new_packets().unwrap();
    let mut server_flight = flight(&mut server);
    let ch = Hello::parse(&client_hello, true);
    let sh = Hello::parse(&server_flight, false);
    patch(&ch, &sh, &mut server_flight);
    feed(&mut client, &server_flight);
    let err = client.process_new_packets().unwrap_err();
    assert_eq!(records(&flight(&mut client)).first().map(|r| r.0), Some(21));
    err
}

#[test]
fn client_rejects_a_server_selecting_grease() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let grease_client = || {
        let mut c = client_config(&chain);
        c.enable_grease = true;
        c
    };

    // The cipher suite (RFC 8701 §3; illegal_parameter, RFC 9846 §4.2.3).
    let err = client_error_after_patch(grease_client(), server_config(&chain), |ch, sh, sf| {
        sf[sh.suites_at..sh.suites_at + 2].copy_from_slice(&ch.suites[0].to_be_bytes());
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedCipherSuite)
    );

    // The version in supported_versions.
    let err = client_error_after_patch(grease_client(), server_config(&chain), |ch, sh, sf| {
        let grease = u16_at(&ch.ext(EXT_SUPPORTED_VERSIONS).unwrap().body, 1);
        let at = sh.ext(EXT_SUPPORTED_VERSIONS).unwrap().at;
        sf[at..at + 2].copy_from_slice(&grease.to_be_bytes());
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedVersion)
    );

    // The key share group.
    let err = client_error_after_patch(grease_client(), server_config(&chain), |ch, sh, sf| {
        let grease = u16_list(&ch.ext(EXT_SUPPORTED_GROUPS).unwrap().body)[0];
        let at = sh.ext(EXT_KEY_SHARE).unwrap().at;
        sf[at..at + 2].copy_from_slice(&grease.to_be_bytes());
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(PeerMisbehaved::WrongGroupForKeyShare)
    );

    // An extension of a GREASE type: unsupported_extension.
    let err = client_error_after_patch(grease_client(), server_config(&chain), |ch, sh, sf| {
        let at = sh.ext(EXT_KEY_SHARE).unwrap().at;
        sf[at - 4..at - 2].copy_from_slice(&ch.exts[0].typ.to_be_bytes());
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(PeerMisbehaved::UnsolicitedServerHelloExtension)
    );
}

// ------------------------------------------------------------------ padding

/// The handshake message length of the ClientHello `config` produces.
fn client_hello_len(config: ClientConfig) -> (usize, Option<Vec<u8>>) {
    let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    let hello = Hello::parse(&flight(&mut client), true);
    (
        hello.message_len,
        hello.ext(EXT_PADDING).map(|e| e.body.clone()),
    )
}

#[test]
fn padding_avoids_256_to_511_byte_client_hellos() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut in_range = 0;
    // Grow the ClientHello one byte at a time with an ALPN protocol name.
    for alpn_len in 1..=255 {
        let config = |padding| {
            let mut c = client_with_groups(&chain, &[NamedGroup::X25519]);
            c.alpn_protocols = vec![vec![b'a'; alpn_len]];
            c.client_hello_padding = padding;
            c
        };
        let (unpadded, none) = client_hello_len(config(ClientHelloPadding::Disabled));
        assert!(none.is_none());
        let (padded, padding) = client_hello_len(config(ClientHelloPadding::default()));
        if (256..512).contains(&unpadded) {
            in_range += 1;
            assert_eq!(padded, unpadded.max(508) + 4, "{unpadded}");
            assert!(padding.unwrap().iter().all(|b| *b == 0));
        } else {
            assert_eq!(padded, unpadded);
            assert!(padding.is_none());
        }
    }
    assert!(in_range > 100, "only {in_range} lengths in range");

    // A fixed target.
    let mut c = client_with_groups(&chain, &[NamedGroup::X25519]);
    c.client_hello_padding = ClientHelloPadding::AtLeast(1000);
    let (len, padding) = client_hello_len(c);
    assert_eq!(len, 1000);
    assert!(padding.unwrap().iter().all(|b| *b == 0));
    // A target the hello already exceeds adds nothing.
    let mut c = client_with_groups(&chain, &[NamedGroup::X25519]);
    c.client_hello_padding = ClientHelloPadding::AtLeast(100);
    let (len, _) = client_hello_len(c);
    assert!(!(256..512).contains(&len));
}

#[test]
fn server_ignores_padding_content() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut config = client_config(&chain);
    config.client_hello_padding = ClientHelloPadding::AtLeast(3000);
    let (mut client, mut server) = connect(config, server_config(&chain));
    let mut hello = flight(&mut client);
    let padding = Hello::parse(&hello, true).ext(EXT_PADDING).unwrap().clone();
    hello[padding.at..padding.at + padding.body.len()].fill(0xff);
    feed(&mut server, &hello);
    server.process_new_packets().unwrap();
    let reply = flight(&mut server);
    // A ServerHello, without padding.
    assert!(Hello::parse(&reply, false).ext(EXT_PADDING).is_none());
}
