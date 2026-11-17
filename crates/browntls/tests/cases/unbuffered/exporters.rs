// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: the early exporter (RFC 9846 §7.5) and the RFC 9266
// `tls-exporter` channel binding on unbuffered connections. (Uses
// `early_data_configs` and `prime` from `unbuffered/early_data.rs`.)

const EARLY_LABEL: &[u8] = b"EXPORTER-early-test";

/// The early exporter of an unbuffered connection, or `None` when it is
/// unavailable.
fn ub_early<C, D>(conn: &C) -> Option<[u8; 32]>
where
    C: std::ops::Deref<Target = UnbufferedConnectionCommon<D>>,
    D: SideData,
{
    conn.export_early_keying_material([0u8; 32], EARLY_LABEL, Some(b"ctx"))
        .ok()
}

#[test]
fn early_exporter_on_unbuffered_connections() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let (cc, sc) = early_data_configs(&chain, 1024);
    for feed in [Feed::Whole, Feed::ByteByByte] {
        // Both unbuffered, 0-RTT accepted: both sides agree. The client
        // has the value as soon as its ClientHello offers 0-RTT, which
        // `new` builds.
        prime(&cc, &sc);
        let mut c = ub_client(&cc, feed);
        let offered = ub_early(&c.conn).expect("available once 0-RTT is offered");
        c.early_to_send = b"early".to_vec();
        let flight = c.take_output();
        assert_eq!(ub_early(&c.conn), Some(offered));
        let mut s = ub_server(&sc, feed);
        s.give_input(&flight);
        handshake(&mut c, &mut s);
        assert!(c.conn.is_early_data_accepted());
        assert_eq!(ub_early(&s.conn), Some(offered), "{feed:?}");
        assert_eq!(ub_early(&c.conn), Some(offered));
        // Not the regular exporter, and other labels and contexts differ.
        let regular = c
            .conn
            .export_keying_material([0u8; 32], EARLY_LABEL, Some(b"ctx"))
            .unwrap();
        assert_ne!(regular, offered);
        let other = c
            .conn
            .export_early_keying_material([0u8; 32], EARLY_LABEL, None)
            .unwrap();
        assert_ne!(other, offered);
        exchange(&mut c, &mut s, b"1-RTT");
    }

    // Against buffered peers, both ways: the same value.
    prime(&cc, &sc);
    let mut c = ub_client(&cc, Feed::Whole);
    c.early_to_send = b"early".to_vec();
    let mut s = b_server(&sc);
    handshake(&mut c, &mut s);
    let buffered = s
        .conn
        .export_early_keying_material([0u8; 32], EARLY_LABEL, Some(b"ctx"))
        .unwrap();
    assert_eq!(ub_early(&c.conn), Some(buffered));

    prime(&cc, &sc);
    let mut c = b_client(&cc);
    c.conn.early_data().unwrap().write_all(b"early").unwrap();
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    let buffered = c
        .conn
        .export_early_keying_material([0u8; 32], EARLY_LABEL, Some(b"ctx"))
        .unwrap();
    assert_eq!(ub_early(&s.conn), Some(buffered));
}

#[test]
fn early_exporter_unavailable_without_accepted_0rtt() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);

    // A full handshake offers no 0-RTT.
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    let mut c = ub_client(&cc, Feed::Whole);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    assert_eq!(ub_early(&c.conn), None);
    assert_eq!(ub_early(&s.conn), None);

    // Rejected 0-RTT: the client loses the value it had.
    let (cc, sc) = early_data_configs(&chain, 1024);
    prime(&cc, &sc);
    let mut c = ub_client(&cc, Feed::Whole);
    c.early_to_send = b"0rtt".to_vec();
    let flight = c.take_output();
    assert!(ub_early(&c.conn).is_some());
    let mut s = ub_server(&sc, Feed::Whole);
    s.conn.reject_early_data();
    s.give_input(&flight);
    handshake(&mut c, &mut s);
    assert!(!c.conn.is_early_data_accepted());
    assert_eq!(ub_early(&c.conn), None);
    assert_eq!(ub_early(&s.conn), None);

    // Arguments are checked before anything is derived.
    prime(&cc, &sc);
    let mut c = ub_client(&cc, Feed::Whole);
    c.early_to_send = b"0rtt".to_vec();
    c.take_output();
    assert!(
        c.conn
            .export_early_keying_material(Vec::new(), EARLY_LABEL, None)
            .is_err(),
        "empty output"
    );
    assert!(
        c.conn
            .export_early_keying_material([0u8; 8], EARLY_LABEL, Some(&[0u8; 65_536]))
            .is_err(),
        "context longer than 2^16 - 1 bytes"
    );
}

#[test]
fn channel_binding_on_unbuffered_connections() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));

        // Not before the handshake has completed.
        let conn = UnbufferedServerConnection::new(sc.clone()).unwrap();
        assert!(conn.tls_exporter_channel_binding().is_err());

        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        let binding = c.conn.tls_exporter_channel_binding().unwrap();
        assert_eq!(
            binding,
            s.conn.tls_exporter_channel_binding().unwrap(),
            "{v:?}"
        );
        assert_eq!(
            binding,
            c.conn
                .export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", Some(&[]))
                .unwrap()
        );

        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, Feed::ByteByByte);
        handshake(&mut c, &mut s);
        assert_eq!(
            s.conn.tls_exporter_channel_binding().unwrap(),
            c.conn.tls_exporter_channel_binding().unwrap(),
            "{v:?}"
        );

        // Fixed for the connection, also across a KeyUpdate.
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = ub_server(&sc, Feed::Whole);
        handshake(&mut c, &mut s);
        let before = s.conn.tls_exporter_channel_binding().unwrap();
        assert_eq!(c.conn.tls_exporter_channel_binding().unwrap(), before);
        if v == ProtocolVersion::TLSv1_3 {
            c.refresh_requested = true;
            exchange(&mut c, &mut s, b"rekeyed");
            assert_eq!(s.conn.tls_exporter_channel_binding().unwrap(), before);
        }
    }
}
