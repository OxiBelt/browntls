// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: 0-RTT data.

fn early_data_configs(chain: &Chain, max: u32) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut cc = versioned_client(chain, ProtocolVersion::TLSv1_3);
    cc.enable_early_data = true;
    let mut sc = versioned_server(chain, ProtocolVersion::TLSv1_3);
    sc.max_early_data_size = max;
    (Arc::new(cc), Arc::new(sc))
}

fn prime(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>) {
    let mut c = ub_client(cc, Feed::Whole);
    let mut s = ub_server(sc, Feed::Whole);
    handshake(&mut c, &mut s);
    exchange(&mut c, &mut s, b"prime");
    assert!(c.conn.tls13_tickets_received() > 0);
}

#[test]
fn early_data_unbuffered_both_sides() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (cc, sc) = early_data_configs(&chain, 1024);
    for feed in [Feed::Whole, Feed::ByteByByte] {
        prime(&cc, &sc);
        let mut c = ub_client(&cc, feed);
        c.early_to_send = b"GET /idempotent".to_vec();
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        assert!(c.early_to_send.is_empty(), "early data was offered");
        assert!(c.conn.is_early_data_accepted());
        assert_eq!(s.received_early, b"GET /idempotent");
        assert!(s.states.contains(&"ReadEarlyData"));
        assert!(s.received.is_empty(), "0-RTT is not reported as 1-RTT data");
        exchange(&mut c, &mut s, b"1-RTT");
    }
}

#[test]
fn early_data_against_buffered_peers() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let (cc, sc) = early_data_configs(&chain, 1024);

    // Unbuffered client, buffered server.
    prime(&cc, &sc);
    let mut c = ub_client(&cc, Feed::Whole);
    c.early_to_send = b"early to buffered".to_vec();
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);
    assert!(c.conn.is_early_data_accepted());
    let mut got = Vec::new();
    s.conn.early_data().unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"early to buffered");
    exchange(&mut c, &mut s, b"after");

    // Buffered client, unbuffered server.
    prime(&cc, &sc);
    let mut c = b_client(&cc);
    c.conn
        .early_data()
        .unwrap()
        .write_all(b"early to unbuffered")
        .unwrap();
    let mut s = ub_server(&sc, Feed::ByteByByte);
    handshake(&mut c, &mut s);
    assert!(c.conn.is_early_data_accepted());
    assert_eq!(s.received_early, b"early to unbuffered");
    exchange(&mut c, &mut s, b"after");
}

#[test]
fn early_data_limits_and_rejection() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (cc, sc) = early_data_configs(&chain, 16);
    prime(&cc, &sc);

    // The ticket's limit is enforced before anything is written.
    let mut conn = UnbufferedClientConnection::new(cc.clone(), server_name()).unwrap();
    let mut hello = vec![0u8; 4096];
    let n = match conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::EncodeTlsData(mut e)) => e.encode(&mut hello).unwrap(),
        other => panic!("{other:?}"),
    };
    hello.truncate(n);
    match conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::TransmitTlsData(mut t)) => {
            let mut early = t.may_encrypt_early_data().expect("ticket allows 0-RTT");
            assert_eq!(early.bytes_left(), 16);
            assert_eq!(
                early.encrypt(&[0u8; 17], &mut [0u8; 1024]),
                Err(EarlyDataError::ExceededAllowedEarlyData)
            );
            assert_eq!(early.bytes_left(), 16);
            assert!(early.encrypt(&[1u8; 16], &mut [0u8; 1024]).unwrap() > 16);
            assert_eq!(early.bytes_left(), 0);
            t.done();
        }
        other => panic!("{other:?}"),
    }

    // A server that rejects 0-RTT: the client learns it, data goes 1-RTT.
    // (The server skips rejected 0-RTT records up to `max_early_data_size`
    // bytes of ciphertext, so this needs a limit above one record's
    // overhead.)
    let (cc, sc) = early_data_configs(&chain, 1024);
    prime(&cc, &sc);
    let mut c = ub_client(&cc, Feed::Whole);
    c.early_to_send = b"0rtt".to_vec();
    let mut s = ub_server(&sc, Feed::Whole);
    s.conn.reject_early_data();
    handshake(&mut c, &mut s);
    assert!(c.early_to_send.is_empty());
    assert!(!c.conn.is_early_data_accepted());
    assert!(s.received_early.is_empty());
    exchange(&mut c, &mut s, b"retry over 1-RTT");

    // Without a ticket there is no early data state at all.
    let fresh = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let mut conn = UnbufferedClientConnection::new(fresh, server_name()).unwrap();
    let mut buf = vec![0u8; 4096];
    if let Ok(ConnectionState::EncodeTlsData(mut e)) = conn.process_tls_records(&mut []).state {
        e.encode(&mut buf).unwrap();
    }
    match conn.process_tls_records(&mut []).state {
        Ok(ConnectionState::TransmitTlsData(mut t)) => {
            assert!(t.may_encrypt_early_data().is_none());
            assert!(t.may_encrypt_app_data().is_none());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn reject_early_data_after_accepting_it_does_nothing() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (cc, sc) = early_data_configs(&chain, 1024);
    prime(&cc, &sc);
    let mut c = b_client(&cc);
    c.conn.early_data().unwrap().write_all(b"one ").unwrap();
    let mut s = ub_server(&sc, Feed::Whole);
    let flight = c.take_output();
    s.give_input(&flight);
    assert_eq!(s.received_early, b"one ");
    // Too late: the server already accepted the client's 0-RTT data.
    s.conn.reject_early_data();
    c.conn.early_data().unwrap().write_all(b"two").unwrap();
    handshake(&mut c, &mut s);
    assert!(c.conn.is_early_data_accepted());
    assert_eq!(s.received_early, b"one two");
}
