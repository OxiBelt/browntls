// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: handshakes, application data, output buffer sizes,
// closure, resumption, alerts and the exporter.

#[test]
fn handshake_and_data_every_pairing() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));
        for feed in [Feed::Whole, Feed::ByteByByte] {
            let data: &[u8] = if feed == Feed::Whole {
                &big_payload()
            } else {
                b"hello over one-byte reads"
            };

            // unbuffered client, buffered server
            let mut c = ub_client(&cc, feed);
            let mut s = b_server(&sc);
            handshake(&mut c, &mut s);
            assert_eq!(c.conn.protocol_version(), Some(v));
            exchange(&mut c, &mut s, data);
            assert!(c.insufficient_seen > 0, "{v:?} {feed:?}");

            // buffered client, unbuffered server
            let mut c = b_client(&cc);
            let mut s = ub_server(&sc, feed);
            handshake(&mut c, &mut s);
            assert_eq!(s.conn.protocol_version(), Some(v));
            assert_eq!(s.conn.server_name(), Some("localhost"));
            exchange(&mut c, &mut s, data);

            // both unbuffered
            let mut c = ub_client(&cc, feed);
            let mut s = ub_server(&sc, feed);
            handshake(&mut c, &mut s);
            exchange(&mut c, &mut s, data);
            assert!(!c.states.contains(&"Err") && !s.states.contains(&"Err"));
        }
    }
}

#[test]
fn every_suite_both_unbuffered() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for suite in prov::default_provider().cipher_suites {
        if format!("{:?}", suite.suite()).contains("_RSA_") {
            continue; // the certificate is ECDSA
        }
        let mut p = prov::default_provider();
        p.cipher_suites = vec![suite];
        let p = Arc::new(p);
        let cc = Arc::new(
            ClientConfig::builder_with_provider(p.clone())
                .with_protocol_versions(&[suite.version()])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
                .with_no_client_auth(),
        );
        let sc = Arc::new(
            ServerConfig::builder_with_provider(p)
                .with_protocol_versions(&[suite.version()])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain.cert_chain(), chain.private_key())
                .unwrap(),
        );
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = ub_server(&sc, Feed::Whole);
        pump(&mut c, &mut s);
        assert!(
            !c.failed() && !s.failed(),
            "{:?}: client {}, server {}",
            suite.suite(),
            c.describe(),
            s.describe()
        );
        assert_eq!(
            c.conn.negotiated_cipher_suite().unwrap().suite(),
            suite.suite()
        );
        exchange(&mut c, &mut s, &big_payload());
    }
}

#[test]
fn small_fragments_split_records() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let mut cfg = versioned_client(&chain, v);
        cfg.max_fragment_size = Some(64);
        let cc = Arc::new(cfg);
        let sc = Arc::new(versioned_server(&chain, v));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = ub_server(&sc, Feed::Whole);
        handshake(&mut c, &mut s);
        c.send(&[7u8; 1000]);
        let wire = c.take_output();
        // 1000 bytes in records of at most 59 bytes of plaintext.
        assert!(wire.len() > 1000 + 16 * 5, "{v:?}: {}", wire.len());
        s.give_input(&wire);
        assert_eq!(s.take_received(), vec![7u8; 1000]);
        assert!(
            s.states.iter().filter(|s| **s == "ReadTraffic").count() >= 17,
            "one ReadTraffic per record"
        );
    }
}

#[test]
fn insufficient_size_reports_exact_requirement() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let mut conn = UnbufferedClientConnection::new(cc, server_name()).unwrap();
    let status = conn.process_tls_records(&mut []);
    assert_eq!(status.discard, 0);
    let Ok(ConnectionState::EncodeTlsData(mut e)) = status.state else {
        panic!("expected the ClientHello");
    };
    let required = match e.encode(&mut [0u8; 10]) {
        Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
            required_size
        }
        other => panic!("{other:?}"),
    };
    let mut buf = vec![0u8; required - 1];
    assert!(e.encode(&mut buf).is_err(), "one byte short still fails");
    let mut buf = vec![0u8; required];
    assert_eq!(e.encode(&mut buf).unwrap(), required);
    assert_eq!(buf[0], 0x16, "a handshake record");
    assert_eq!(e.encode(&mut buf).unwrap(), 0, "nothing more queued");
    let status = conn.process_tls_records(&mut []);
    let Ok(ConnectionState::TransmitTlsData(t)) = status.state else {
        panic!("expected TransmitTlsData");
    };
    t.done();
    let status = conn.process_tls_records(&mut []);
    assert!(matches!(
        status.state,
        Ok(ConnectionState::BlockedHandshake)
    ));
}

#[test]
fn write_traffic_size_check_consumes_nothing() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        let status = c.conn.process_tls_records(&mut c.incoming);
        let Ok(ConnectionState::WriteTraffic(mut w)) = status.state else {
            panic!("expected WriteTraffic");
        };
        let data = b"exactly sized";
        let required = match w.encrypt(data, &mut [0u8; 8]) {
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                required_size
            }
            other => panic!("{other:?}"),
        };
        assert!(matches!(
            w.encrypt(data, &mut vec![0u8; required - 1]),
            Err(EncryptError::InsufficientSize(_))
        ));
        let mut buf = vec![0u8; required];
        assert_eq!(w.encrypt(data, &mut buf).unwrap(), required);
        assert_eq!(w.encrypt(&[], &mut buf).unwrap(), 0);
        // The failed attempts used no sequence numbers: the peer decrypts.
        s.give_input(&buf);
        assert!(!s.failed());
        assert_eq!(s.take_received(), data);
    }
}

#[test]
fn close_notify_both_ways() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));

        // Unbuffered client closes; buffered server sees it.
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        c.to_send = b"last words".to_vec();
        c.close_requested = true;
        pump(&mut c, &mut s);
        assert_eq!(s.take_received(), b"last words");
        let io = s.conn.process_new_packets().unwrap();
        assert!(io.peer_has_closed());
        // Writing after close_notify is refused.
        let status = c.conn.process_tls_records(&mut c.incoming);
        match status.state {
            Ok(ConnectionState::WriteTraffic(mut w)) => {
                assert_eq!(
                    w.encrypt(b"x", &mut [0u8; 100]),
                    Err(EncryptError::AlreadyClosed)
                );
                assert_eq!(w.queue_close_notify(&mut [0u8; 100]), Ok(0));
            }
            other => panic!("{other:?}"),
        }
        // The server answers; the client reports PeerClosed once, then Closed.
        s.conn.send_close_notify();
        pump(&mut c, &mut s);
        assert!(c.peer_closed && c.closed, "{:?}", c.states);
        assert_eq!(c.states.iter().filter(|s| **s == "PeerClosed").count(), 1);
        let status = c.conn.process_tls_records(&mut []);
        assert!(matches!(status.state, Ok(ConnectionState::Closed)));

        // Buffered client closes first; the unbuffered server may still
        // write after PeerClosed, then closes too.
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, Feed::ByteByByte);
        handshake(&mut c, &mut s);
        c.conn.send_close_notify();
        pump(&mut c, &mut s);
        assert!(s.peer_closed && !s.closed);
        s.to_send = b"half-closed reply".to_vec();
        s.close_requested = true;
        pump(&mut c, &mut s);
        assert!(s.closed, "{:?}", s.states);
        assert_eq!(c.take_received(), b"half-closed reply");
        assert!(c.conn.process_new_packets().unwrap().peer_has_closed());
    }
}

#[test]
fn bytes_after_close_notify_are_not_processed() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    let mut c = b_client(&cc);
    let mut s = ub_server(&sc, Feed::Whole);
    handshake(&mut c, &mut s);
    c.conn.send_close_notify();
    let mut wire = c.take_output();
    wire.extend_from_slice(&[0x17, 3, 3, 0, 1, 0xff]);
    s.give_input(&wire);
    assert!(s.peer_closed && s.error.is_none());
    assert_eq!(s.incoming, [0x17, 3, 3, 0, 1, 0xff], "left undiscarded");
}

#[test]
fn resumption_unbuffered_both_sides() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        for feed in [Feed::Whole, Feed::ByteByByte] {
            // Fresh session stores for each run.
            let cc = Arc::new(versioned_client(&chain, v));
            let sc = Arc::new(versioned_server(&chain, v));
            let mut c = ub_client(&cc, feed);
            let mut s = ub_server(&sc, feed);
            s.conn.set_resumption_data(b"app state");
            handshake(&mut c, &mut s);
            assert_eq!(c.conn.handshake_kind(), Some(HandshakeKind::Full));
            // TLS 1.3 tickets arrive after the handshake.
            exchange(&mut c, &mut s, b"first");
            if v == ProtocolVersion::TLSv1_3 {
                assert!(c.conn.tls13_tickets_received() > 0);
            }

            let mut c = ub_client(&cc, feed);
            let mut s = ub_server(&sc, feed);
            handshake(&mut c, &mut s);
            assert_eq!(c.conn.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(s.conn.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(s.conn.received_resumption_data(), Some(&b"app state"[..]));
            exchange(&mut c, &mut s, b"second");
        }
    }
}

#[test]
fn tampered_record_sends_alert_then_fails() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, Feed::Whole);
        handshake(&mut c, &mut s);
        c.send(b"tamper with me");
        let mut wire = c.take_output();
        let last = wire.len() - 1;
        wire[last] ^= 1;
        s.give_input(&wire);
        assert_eq!(s.error, Some(Error::DecryptError));
        // The alert was encoded before the error was reported.
        let n = s.states.len();
        assert_eq!(
            &s.states[n - 3..],
            ["EncodeTlsData", "TransmitTlsData", "Err"],
            "{v:?}"
        );
        let alert = s.take_output();
        c.give_input(&alert);
        assert_eq!(
            c.error,
            Some(Error::AlertReceived(
                browntls_core::AlertDescription::BadRecordMac
            ))
        );
        // The error is sticky.
        let status = s.conn.process_tls_records(&mut []);
        assert_eq!(status.state.err(), Some(Error::DecryptError));
    }
}

#[test]
fn handshake_failure_is_reported_with_alert() {
    init_logging();
    // The server presents a certificate the client does not pin.
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&other, v));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = ub_server(&sc, Feed::Whole);
        pump(&mut c, &mut s);
        assert!(
            matches!(c.error, Some(Error::InvalidCertificate(_))),
            "{:?}",
            c.error
        );
        assert!(
            matches!(s.error, Some(Error::AlertReceived(_))),
            "{:?}",
            s.error
        );
    }
}

#[test]
fn server_waits_for_client_hello() {
    let chain = server_chain(KeyType::EcdsaP256);
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    let mut conn = UnbufferedServerConnection::new(sc).unwrap();
    let status = conn.process_tls_records(&mut []);
    assert_eq!(status.discard, 0);
    assert!(matches!(
        status.state,
        Ok(ConnectionState::BlockedHandshake)
    ));
    // A partial record header is left alone.
    let mut partial = [0x16, 3, 1];
    let status = conn.process_tls_records(&mut partial);
    assert_eq!(status.discard, 0);
    assert!(matches!(
        status.state,
        Ok(ConnectionState::BlockedHandshake)
    ));
    // Garbage fails with an alert first.
    let mut garbage = [0x99u8, 3, 3, 0, 1, 0];
    let status = conn.process_tls_records(&mut garbage);
    assert!(matches!(
        status.state,
        Ok(ConnectionState::EncodeTlsData(_))
    ));
    let mut buf = [0u8; 64];
    if let Ok(ConnectionState::EncodeTlsData(mut e)) = conn.process_tls_records(&mut garbage).state
    {
        assert_eq!(e.encode(&mut buf).unwrap(), 7);
    }
    if let Ok(ConnectionState::TransmitTlsData(t)) = conn.process_tls_records(&mut []).state {
        t.done();
    }
    assert!(conn.process_tls_records(&mut []).state.is_err());
}

#[test]
fn export_keying_material_matches_buffered_peer() {
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let cc = Arc::new(versioned_client(&chain, v));
        let sc = Arc::new(versioned_server(&chain, v));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        let a = c
            .conn
            .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"ctx"))
            .unwrap();
        let b = s
            .conn
            .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"ctx"))
            .unwrap();
        assert_eq!(a, b);
    }
}
