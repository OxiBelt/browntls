// Cases included by `cases/tls13_features.rs`, which holds the imports and
// the shared helpers: HelloRetryRequest cookies, the `tls-exporter` channel
// binding and the early exporter.

// ------------------------------------------- HelloRetryRequest cookies

/// A clock `offset` seconds ahead of the system clock.
#[derive(Debug)]
struct OffsetClock(u64);

impl TimeProvider for OffsetClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            UnixTime::now().as_secs() + self.0,
        )))
    }
}

fn sealer() -> Arc<dyn ProducesTickets> {
    prov::Ticketer::new().unwrap()
}

/// A server that only speaks P-256 (so an X25519-first client gets a
/// HelloRetryRequest), with `cookies` sealing its cookies.
fn retrying_server(
    chain: &Chain,
    cookies: Option<Arc<dyn ProducesTickets>>,
    clock_offset: u64,
) -> Arc<ServerConfig> {
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::SECP256R1];
    let mut config =
        ServerConfig::builder_with_details(Arc::new(provider), Arc::new(OffsetClock(clock_offset)))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
    config.hello_retry_cookies = cookies;
    Arc::new(config)
}

fn retrying_client(chain: &Chain) -> ClientConnection {
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::X25519, prov::kx_group::SECP256R1];
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth();
    ClientConnection::new(Arc::new(config), server_name()).unwrap()
}

/// The extensions of the handshake message in the first record of `bytes`
/// (a ServerHello-shaped HelloRetryRequest or a ClientHello), as
/// `(type, offset of the body in bytes, body)`.
fn hello_extensions(bytes: &[u8]) -> Vec<(u16, usize, Vec<u8>)> {
    assert_eq!(bytes[0], 0x16, "a handshake record");
    let body = 5 + 4;
    let session_id_at = body + 2 + 32;
    let mut at = session_id_at + 1 + usize::from(bytes[session_id_at]);
    if bytes[5] == 1 {
        // ClientHello: cipher_suites<2..>, compression_methods<1..>.
        at += 2 + usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
        at += 1 + usize::from(bytes[at]);
    } else {
        // ServerHello: cipher_suite, compression_method.
        at += 3;
    }
    let end = at + 2 + usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
    at += 2;
    let mut out = Vec::new();
    while at < end {
        let typ = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        let len = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
        out.push((typ, at + 4, bytes[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    out
}

const COOKIE: u16 = 0x002c;

/// The first flight up to the client's second ClientHello: returns the
/// server that sent the HelloRetryRequest, the HelloRetryRequest flight and
/// the client's answer (change_cipher_spec and second ClientHello).
fn first_round(
    client: &mut ClientConnection,
    config: &Arc<ServerConfig>,
) -> (ServerConnection, Vec<u8>, Vec<u8>) {
    let mut server = ServerConnection::new(config.clone()).unwrap();
    transfer(client, &mut server);
    server.process_new_packets().unwrap();
    let hrr = take_tls(&mut server);
    feed(client, &hrr);
    client.process_new_packets().unwrap();
    let second = take_tls(client);
    (server, hrr, second)
}

/// A change_cipher_spec record.
const CCS: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

/// Where the ClientHello record of `flight` starts (after a
/// change_cipher_spec, if any).
fn client_hello_record(flight: &[u8]) -> usize {
    if flight[..6] == CCS { 6 } else { 0 }
}

/// `flight` with a change_cipher_spec in front, as a middlebox-compatible
/// client may send it ahead of its second ClientHello (RFC 9846 §4.3.2).
fn with_ccs(flight: &[u8]) -> Vec<u8> {
    let mut out = CCS.to_vec();
    out.extend_from_slice(&flight[client_hello_record(flight)..]);
    out
}

#[test]
fn hello_retry_request_carries_a_cookie_only_when_configured() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for cookies in [None, Some(sealer())] {
        let configured = cookies.is_some();
        let config = retrying_server(&chain, cookies, 0);
        let mut client = retrying_client(&chain);
        let (mut server, hrr, second) = first_round(&mut client, &config);
        let cookie = hello_extensions(&hrr)
            .into_iter()
            .find(|(typ, ..)| *typ == COOKIE);
        assert_eq!(cookie.is_some(), configured);
        // RFC 9846 §4.3.2: the client echoes it.
        let echoed = hello_extensions(&second[client_hello_record(&second)..])
            .into_iter()
            .find(|(typ, ..)| *typ == COOKIE);
        assert_eq!(
            echoed.map(|(_, _, body)| body),
            cookie.map(|(_, _, body)| body)
        );
        // The connection that sent the HelloRetryRequest carries on.
        feed(&mut server, &second);
        server.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            server.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
    }
}

#[test]
fn stateless_retry_completes_on_a_fresh_connection() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let config = retrying_server(&chain, Some(sealer()), 0);
    let mut client = retrying_client(&chain);
    let (first, _, second) = first_round(&mut client, &config);
    drop(first);

    // No state survives: a new connection continues from the cookie, and
    // ignores a change_cipher_spec ahead of the ClientHello.
    let mut server = ServerConnection::new(config).unwrap();
    feed(&mut server, &with_ccs(&second));
    server.process_new_packets().unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    for kind in [client.handshake_kind(), server.handshake_kind()] {
        assert_eq!(kind, Some(HandshakeKind::FullWithHelloRetryRequest));
    }
    assert_eq!(
        server.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp256r1
    );
    assert_eq!(server.server_name(), Some("localhost"));
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"stateless"),
        b"stateless"
    );
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"retry"),
        b"retry"
    );
}

#[test]
fn stateless_retry_through_the_acceptor() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let config = retrying_server(&chain, Some(sealer()), 0);
    let mut client = retrying_client(&chain);
    let (_, _, second) = first_round(&mut client, &config);

    let mut acceptor = browntls_core::server::Acceptor::default();
    acceptor.read_tls(&mut &with_ccs(&second)[..]).unwrap();
    let accepted = acceptor.accept().unwrap().expect("a ClientHello");
    let mut server = accepted.into_connection(config).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
}

/// Feeds the client's second flight, with `edit` applied to the cookie
/// extension (type and body), to a server built from `config` (a fresh one
/// unless `stateful`), and returns its error and alert.
fn edited_cookie(
    config: Arc<ServerConfig>,
    issuing: &Arc<ServerConfig>,
    stateful: bool,
    edit: impl Fn(&mut [u8], usize, usize),
) -> (Error, u8) {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = retrying_client(&chain);
    let (first, _, mut second) = first_round(&mut client, issuing);
    let at = client_hello_record(&second);
    let (_, body_at, body) = hello_extensions(&second[at..])
        .into_iter()
        .find(|(typ, ..)| *typ == COOKIE)
        .expect("a cookie");
    edit(&mut second, at + body_at, body.len());
    let (mut server, second) = if stateful {
        (first, second)
    } else {
        (ServerConnection::new(config).unwrap(), with_ccs(&second))
    };
    feed(&mut server, &second);
    let err = server.process_new_packets().unwrap_err();
    (err, last_alert(&take_tls(&mut server)))
}

#[test]
fn tampered_cookies_are_illegal_parameter() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let issuing = retrying_server(&chain, Some(sealer()), 0);
    let invalid = (
        Error::PeerMisbehaved(PeerMisbehaved::InvalidHelloRetryRequestCookie),
        u8::from(AlertDescription::IllegalParameter),
    );
    for stateful in [false, true] {
        // A flipped bit anywhere in the sealed cookie.
        for position in [2, 20] {
            assert_eq!(
                edited_cookie(issuing.clone(), &issuing, stateful, |bytes, at, _| {
                    bytes[at + position] ^= 0x01
                }),
                invalid,
                "stateful={stateful} position={position}"
            );
        }
    }
    // A cookie sealed under another key.
    let other_key = retrying_server(&chain, Some(sealer()), 0);
    assert_eq!(
        edited_cookie(other_key, &issuing, false, |_, _, _| {}),
        invalid
    );
    // An expired cookie (61 seconds later).
    let later = retrying_server(&chain, issuing.hello_retry_cookies.clone(), 61);
    assert_eq!(edited_cookie(later, &issuing, false, |_, _, _| {}), invalid);
    // Still valid within its lifetime.
    let soon = retrying_server(&chain, issuing.hello_retry_cookies.clone(), 30);
    let mut client = retrying_client(&chain);
    let (_, _, second) = first_round(&mut client, &issuing);
    let mut server = ServerConnection::new(soon).unwrap();
    feed(&mut server, &second);
    server.process_new_packets().unwrap();
    do_handshake(&mut client, &mut server).unwrap();
}

#[test]
fn second_client_hello_must_echo_the_cookie() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let issuing = retrying_server(&chain, Some(sealer()), 0);
    // Renaming the extension (to a GREASE type) leaves the second ClientHello
    // without a cookie.
    let (err, alert) = edited_cookie(issuing.clone(), &issuing, true, |bytes, at, _| {
        bytes[at - 4..at - 2].copy_from_slice(&[0x0a, 0x0a])
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(PeerMisbehaved::MissingCookieInSecondClientHello)
    );
    assert_eq!(alert, u8::from(AlertDescription::MissingExtension));

    // A fresh connection sees a first ClientHello without a cookie: the
    // HelloRetryRequest it answers with is a retry of its own, but the
    // change_cipher_spec ahead of it is unexpected.
    let (err, alert) = edited_cookie(issuing.clone(), &issuing, false, |bytes, at, _| {
        bytes[at - 4..at - 2].copy_from_slice(&[0x0a, 0x0a])
    });
    // (`edited_cookie` puts a change_cipher_spec ahead of a fresh
    // connection's ClientHello.)
    assert_eq!(
        err,
        Error::PeerMisbehaved(PeerMisbehaved::IllegalMiddleboxChangeCipherSpec)
    );
    assert_eq!(alert, u8::from(AlertDescription::UnexpectedMessage));
}

#[test]
fn change_cipher_spec_before_a_first_client_hello_is_unexpected() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let config = retrying_server(&chain, Some(sealer()), 0);
    let mut client = retrying_client(&chain);
    let mut flight = CCS.to_vec();
    flight.extend(take_tls(&mut client));
    let mut server = ServerConnection::new(config).unwrap();
    feed(&mut server, &flight);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalMiddleboxChangeCipherSpec
        ))
    );
    assert_eq!(
        last_alert(&take_tls(&mut server)),
        u8::from(AlertDescription::UnexpectedMessage)
    );
}

// ---------------------------------------------------- exporters

#[test]
fn cookie_sealer_must_not_be_the_ticketer() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut config = server_config(&chain);
    config.ticketer = sealer();
    config.hello_retry_cookies = Some(config.ticketer.clone());
    let config = Arc::new(config);
    assert!(matches!(
        ServerConnection::new(config.clone()),
        Err(Error::General(_))
    ));

    // The Acceptor path refuses it too.
    let mut client = retrying_client(&chain);
    let mut acceptor = browntls_core::server::Acceptor::default();
    let flight = take_tls(&mut client);
    acceptor.read_tls(&mut &flight[..]).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    assert!(matches!(
        accepted.into_connection(config),
        Err((Error::General(_), _))
    ));

    // A separate sealer is fine.
    let mut config = server_config(&chain);
    config.ticketer = sealer();
    config.hello_retry_cookies = Some(sealer());
    ServerConnection::new(Arc::new(config)).unwrap();
}

#[test]
fn tls_exporter_channel_binding_tls13() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (mut client, mut server) = connect(tls13_client(&chain), server_config(&chain));
    assert!(client.tls_exporter_channel_binding().is_err());
    do_handshake(&mut client, &mut server).unwrap();
    let binding = client.tls_exporter_channel_binding().unwrap();
    assert_eq!(binding, server.tls_exporter_channel_binding().unwrap());
    // RFC 9266 §2: label EXPORTER-Channel-Binding, empty context, 32 bytes;
    // in TLS 1.3 an empty context equals no context.
    for context in [Some(&[][..]), None] {
        assert_eq!(
            binding,
            client
                .export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", context)
                .unwrap()
        );
    }
    let (mut client2, mut server2) = connect(tls13_client(&chain), server_config(&chain));
    do_handshake(&mut client2, &mut server2).unwrap();
    assert_ne!(binding, client2.tls_exporter_channel_binding().unwrap());
}

#[cfg(feature = "tls12")]
#[test]
fn tls_exporter_channel_binding_tls12_with_extended_master_secret() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let (mut client, mut server) = connect(client_config, server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    let binding = client.tls_exporter_channel_binding().unwrap();
    assert_eq!(binding, server.tls_exporter_channel_binding().unwrap());
    // RFC 5705: in TLS 1.2 an empty context differs from no context.
    assert_eq!(
        binding,
        client
            .export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", Some(&[]))
            .unwrap()
    );
    assert_ne!(
        binding,
        client
            .export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", None)
            .unwrap()
    );
}

/// Client and server configurations sharing a session cache, with 0-RTT.
fn early_data_pair(chain: &Chain) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut client = tls13_client(chain);
    client.enable_early_data = true;
    let mut server = server_config(chain);
    server.max_early_data_size = 1024;
    server.session_storage = browntls_core::server::ServerSessionMemoryCache::new(8);
    let (client, server) = (Arc::new(client), Arc::new(server));
    let mut c = ClientConnection::new(client.clone(), server_name()).unwrap();
    let mut s = ServerConnection::new(server.clone()).unwrap();
    handshake(&mut c, &mut s);
    (client, server)
}

fn early_export<A: browntls_core::SideData>(
    conn: &browntls_core::ConnectionCommon<A>,
) -> Result<[u8; 32], Error> {
    conn.export_early_keying_material([0u8; 32], b"EXPORTER-early-test", Some(b"ctx"))
}

#[test]
fn early_exporter_agrees_when_0rtt_is_accepted() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (client_config, server_config) = early_data_pair(&chain);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    // The client has it as soon as 0-RTT is offered, before any reply.
    let early = early_export(&client).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"bound to the early exporter")
        .unwrap();
    assert!(early_export(&server).is_err(), "nothing received yet");

    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.is_early_data_accepted());
    assert_eq!(early_export(&server).unwrap(), early);
    assert_eq!(early_export(&client).unwrap(), early);
    // A separate interface with separate values (RFC 9846 §7.5).
    assert_ne!(
        client
            .export_keying_material([0u8; 32], b"EXPORTER-early-test", Some(b"ctx"))
            .unwrap(),
        early
    );
}

#[test]
fn early_exporter_is_withdrawn_when_0rtt_is_rejected() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (client_config, server_config) = early_data_pair(&chain);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    server.reject_early_data();
    assert!(early_export(&client).is_ok());
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert!(!client.is_early_data_accepted());
    assert!(early_export(&client).is_err());
    assert!(early_export(&server).is_err());
}

#[test]
fn early_exporter_needs_0rtt() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(tls13_client(&chain), server_config(&chain));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(early_export(&client).is_err());
    assert!(early_export(&server).is_err());
}
