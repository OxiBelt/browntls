// Cases included by `cases/tls13.rs`, which holds the imports and the shared
// helpers: 0-RTT data.

// ------------------------------------------------------------- 0-RTT

/// A server that allows `max` bytes of early data, sharing `cache` across
/// configurations so a session issued by one is found by another.
fn early_data_server(
    chain: &Chain,
    max: u32,
    cache: &Arc<dyn browntls_core::server::StoresServerSessions>,
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
fn early_data_alpn_belongs_to_the_ticket_not_the_new_offer() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = Arc::unwrap_or_clone(early_data_client(&chain));
    client_config.alpn_protocols = vec![b"first".to_vec(), b"ticket".to_vec()];
    let client_config = Arc::new(client_config);
    let mut server_config = server_config(&chain);
    server_config.alpn_protocols = vec![b"ticket".to_vec()];
    server_config.max_early_data_size = 1024;
    let mut next_server_config = server_config.clone();
    next_server_config.alpn_protocols = vec![b"first".to_vec()];
    let server_config = Arc::new(server_config);
    prime_ticket(&client_config, &server_config);

    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(next_server_config)).unwrap();
    assert_eq!(client.early_data_alpn(), Some(&b"ticket"[..]));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(!client.is_early_data_accepted());
    assert_eq!(client.alpn_protocol(), Some(&b"first"[..]));
    assert_eq!(client.early_data_alpn(), Some(&b"ticket"[..]));

    prime_ticket(&client_config, &server_config);
    let client =
        browntls_core::client::UnbufferedClientConnection::new(client_config, server_name())
            .unwrap();
    assert_eq!(client.early_data_alpn(), Some(&b"ticket"[..]));
    assert_eq!(client.early_data_bytes_left(), 1024);
}

#[test]
fn early_data_is_accepted_and_readable() {
    use std::io::{Read, Write};
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(8);
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
    let cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(8);
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
    let cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(8);
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
    let cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(8);
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

/// Runs a resumed handshake whose 0-RTT data the server rejects, with the
/// server's skip budget `server_max`, after the client sent `writes` (one
/// record each) under a ticket that allowed `ticket_max` bytes.
fn reject_early_data_writes(
    ticket_max: u32,
    server_max: u32,
    writes: &[&[u8]],
) -> (Result<(), Error>, Result<(), Error>) {
    use std::io::Write;
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(8);
    let client_config = early_data_client(&chain);
    prime_ticket(
        &client_config,
        &early_data_server(&chain, ticket_max, &cache),
    );

    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(early_data_server(&chain, server_max, &cache)).unwrap();
    server.reject_early_data();
    for data in writes {
        client.early_data().unwrap().write_all(data).unwrap();
    }
    let result = do_handshake_until_error(&mut client, &mut server);
    if result.0.is_ok() && result.1.is_ok() {
        assert!(!client.is_early_data_accepted());
        assert!(server.early_data().is_none());
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"resent over 1-RTT"),
            b"resent over 1-RTT"
        );
    }
    result
}

#[test]
fn rejected_early_data_is_skipped_by_its_plaintext_size() {
    init_logging();
    // RFC 9846 §4.3.10: the server skips rejected 0-RTT records "up to the
    // configured max_early_data_size", which counts plaintext, not the
    // record's tag and content type byte.
    assert_eq!(
        reject_early_data_writes(16, 16, &[b"four"]),
        (Ok(()), Ok(()))
    );
    // Exactly the limit, in one record and in four.
    assert_eq!(
        reject_early_data_writes(16, 16, &[&[7u8; 16]]),
        (Ok(()), Ok(()))
    );
    assert_eq!(
        reject_early_data_writes(16, 16, &[b"aaaa", b"bbbb", b"cccc", b"dddd"]),
        (Ok(()), Ok(()))
    );
}

#[test]
fn rejected_early_data_past_the_skip_limit_fails() {
    init_logging();
    // A ticket that allowed more than this server skips: one byte past the
    // limit, alone or spread over records, is a decryption failure.
    for writes in [
        &[&[7u8; 17][..]][..],
        &[b"aaaa", b"bbbb", b"cccc", b"dddd", b"e"],
    ] {
        let (client, server) = reject_early_data_writes(1024, 16, writes);
        assert_eq!(server, Err(Error::DecryptError));
        assert_eq!(
            client,
            Err(Error::AlertReceived(AlertDescription::BadRecordMac))
        );
    }
}

#[test]
fn early_data_is_rejected_after_hello_retry_request() {
    use std::io::Write;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(8);
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
    server_config.session_storage = Arc::new(browntls_core::server::NoServerSessionStorage {});
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
    let cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(8);
    let server_config = early_data_server(&chain, 1024, &cache);
    let client_config = Arc::new(tls13_only_client(&chain, None, None));
    prime_ticket(&client_config, &server_config);
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    assert!(client.early_data().is_none());
    assert!(!client.is_early_data_accepted());
}

/// Offers 0-RTT data under a ticket the server (budget `server_max`, its own
/// empty session store) does not recognise, so it rejects the early data and
/// skips records, then feeds it up to `count` forged application_data
/// records of `payload_len` bytes. With `retry`, the server only takes P-384
/// and answers with a HelloRetryRequest first, so it skips records without
/// a decryption key. Returns how many it skipped before failing, and the
/// error.
fn skip_forged_early_records(
    suite: browntls_core::SupportedCipherSuite,
    server_max: u32,
    retry: bool,
    payload_len: u16,
    count: usize,
) -> (usize, Option<Error>) {
    use std::io::Write;
    let chain = server_chain(KeyType::EcdsaP256);
    let groups = [prov::kx_group::X25519, prov::kx_group::SECP384R1];
    let mut client_config = tls13_only_client(&chain, Some(&[suite]), Some(&groups));
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);
    let issuer_cache: Arc<dyn browntls_core::server::StoresServerSessions> =
        browntls_core::server::ServerSessionMemoryCache::new(8);
    prime_ticket(
        &client_config,
        &early_data_server(&chain, 1024, &issuer_cache),
    );

    let mut provider = prov::default_provider();
    if retry {
        provider.kx_groups = vec![prov::kx_group::SECP384R1];
    }
    let mut target = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    target.max_early_data_size = server_max;
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(target)).unwrap();
    client.early_data().unwrap().write_all(b"").unwrap();
    // The ClientHello only: no genuine early data record is charged.
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    server.read_tls(&mut &hello[..]).unwrap();
    server.process_new_packets().unwrap();
    assert!(server.is_handshaking());
    let kind = if retry {
        HandshakeKind::FullWithHelloRetryRequest
    } else {
        HandshakeKind::Full
    };
    assert_eq!(server.handshake_kind(), Some(kind));

    let mut record = vec![0x17, 0x03, 0x03];
    record.extend_from_slice(&payload_len.to_be_bytes());
    record.resize(5 + usize::from(payload_len), 0xa5);
    for sent in 0..count {
        let mut input = &record[..];
        while !input.is_empty() {
            server.read_tls(&mut input).unwrap();
        }
        if let Err(err) = server.process_new_packets() {
            return (sent, Some(err));
        }
    }
    (count, None)
}

#[test]
fn rejected_early_data_charges_every_skipped_record() {
    init_logging();
    // Records no longer than the AEAD expansion carry no plaintext, but each
    // still costs an authentication attempt: each is charged one byte, so
    // the number of skipped records never exceeds the skip budget.
    let mut wrong = Vec::new();
    for suite in prov::default_provider().cipher_suites.clone() {
        // CCM_8 has a shorter tag and its own integrity limit.
        if suite.version() != &version::TLS13
            || suite.suite() == CipherSuite::TLS13_AES_128_CCM_8_SHA256
        {
            continue;
        }
        // AES-GCM, AES-CCM, ChaCha20-Poly1305: a 16-byte tag and the content
        // type.
        let expansion = 1 + 16;
        let cases = [
            (16, 0, 1000),
            (16, 1, 1000),
            (16, 16, 1000),
            (16, expansion, 1000),
        ]
        .into_iter()
        // Early data off: the 16384-byte fallback budget.
        .chain([(0, expansion, 20_000)]);
        for (server_max, payload_len, count) in cases {
            let budget = if server_max == 0 {
                16_384
            } else {
                server_max as usize
            };
            let got = skip_forged_early_records(suite, server_max, false, payload_len, count);
            if got != (budget, Some(Error::DecryptError)) {
                wrong.push(format!(
                    "{suite:?}, budget {budget}, {payload_len}-byte records: {got:?}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn rejected_early_data_after_hello_retry_request_charges_empty_records() {
    init_logging();
    // After a HelloRetryRequest no key is tried: records are charged their
    // length, and an empty one byte. Past the budget, the next record is
    // read as the second ClientHello would be.
    let suite = prov::default_provider().cipher_suites[0];
    for (server_max, payload_len, budget, count) in [
        (16, 0, 16, 1000),
        (16, 1, 16, 1000),
        (16, 4, 4, 1000),
        (0, 0, 16_384, 20_000),
    ] {
        let (skipped, err) = skip_forged_early_records(suite, server_max, true, payload_len, count);
        assert_eq!(
            skipped, budget,
            "budget {server_max}, {payload_len}-byte records"
        );
        assert!(
            matches!(err, Some(Error::InappropriateMessage { .. })),
            "{err:?}"
        );
    }
}
