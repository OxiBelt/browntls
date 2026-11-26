// Cases included inside `mod acceptor` by `unbuffered/acceptor.rs`, which
// holds the imports and the `Accepting` plumbing: what the acceptors refuse.

#[test]
fn what_is_not_a_client_hello_is_refused_with_an_alert() {
    init_logging();
    let unexpected = u8::from(AlertDescription::UnexpectedMessage);
    let decode = u8::from(AlertDescription::DecodeError);
    let cases: [(&[u8], u8); 5] = [
        // A well-formed handshake message that is not a ClientHello
        // (ServerHelloDone).
        (&[0x16, 3, 1, 0, 4, 0x0e, 0, 0, 0], unexpected),
        // Application data, then an alert, before any ClientHello.
        (&[0x17, 3, 3, 0, 1, 0xaa], unexpected),
        (&[0x15, 3, 3, 0, 2, 2, 40], unexpected),
        // A ClientHello whose body does not parse.
        (&[0x16, 3, 1, 0, 8, 0x01, 0, 0, 4, 3, 3, 0, 0], decode),
        // Not a TLS record at all.
        (&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], unexpected),
    ];
    for (bytes, description) in cases {
        for feed in [Feed::Whole, Feed::ByteByByte] {
            let (err, alert, _) = unbuffered_refusal(bytes, feed, None);
            assert_eq!(fatal_alert(&alert), description, "{bytes:?}: {err:?}");
            // The buffered acceptor (the model) refuses the same way.
            assert_eq!((err, alert), buffered_refusal(bytes, None), "{bytes:?}");
        }
    }
    // The error kinds, for the record.
    let (err, ..) = unbuffered_refusal(cases[0].0, Feed::Whole, None);
    assert!(
        matches!(err, Error::InappropriateHandshakeMessage { .. }),
        "{err:?}"
    );
    let (err, ..) = unbuffered_refusal(cases[1].0, Feed::Whole, None);
    assert!(matches!(err, Error::InappropriateMessage { .. }), "{err:?}");
    let (err, ..) = unbuffered_refusal(cases[4].0, Feed::Whole, None);
    assert_eq!(
        err,
        Error::InvalidMessage(InvalidMessage::InvalidContentType)
    );
}

#[test]
fn an_incomplete_client_hello_is_kept_and_the_acceptor_is_spent_after_success() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client_config = versioned_client(&chain, ProtocolVersion::TLSv1_3);
    // Records of 64 bytes, so that the ClientHello spans several.
    client_config.max_fragment_size = Some(64);
    let hello = client_hello_of(&Arc::new(client_config));
    assert!(hello.len() > 3 * 64);
    let mut acceptor = UnbufferedAcceptor::new();
    assert!(format!("{acceptor:?}").contains("done: false"));

    // Nothing yet, then whole records are taken into the joiner while
    // a partial record is left in place.
    let status = acceptor.accept(&mut []);
    assert_eq!(status.discard, 0);
    assert!(status.state.unwrap().is_none());
    let mut incoming = hello[..100].to_vec();
    let status = acceptor.accept(&mut incoming);
    assert_eq!(status.discard, 64);
    assert!(status.state.unwrap().is_none());
    incoming.drain(..64);
    incoming.extend_from_slice(&hello[100..]);
    incoming.extend_from_slice(b"what follows");
    let status = acceptor.accept(&mut incoming);
    assert_eq!(status.discard, hello.len() - 64);
    let accepted = status.state.unwrap().expect("a ClientHello");
    assert_eq!(accepted.client_hello().server_name(), Some("localhost"));
    assert!(format!("{accepted:?}").starts_with("UnbufferedAccepted"));

    // The acceptor is spent.
    assert!(format!("{acceptor:?}").contains("done: true"));
    let status = acceptor.accept(&mut incoming);
    assert_eq!(status.discard, 0);
    let (err, alert) = status.state.unwrap_err();
    assert!(matches!(err, Error::General(_)), "{err:?}");
    assert!(alert.is_empty());
}

#[test]
fn a_short_alert_buffer_is_reported_with_the_size_needed() {
    init_logging();
    let mut acceptor = UnbufferedAcceptor::default();
    let mut incoming = vec![0x16, 3, 1, 0, 4, 0x0e, 0, 0, 0];
    let status = acceptor.accept(&mut incoming);
    assert_eq!(status.discard, incoming.len());
    let (_, mut alert) = status.state.unwrap_err();
    assert!(!alert.is_empty());
    assert!(format!("{alert:?}").contains("queued: 7"));
    for len in 0..7 {
        let mut buf = vec![0xa5u8; len];
        assert_eq!(
            alert.encode(&mut buf),
            Err(EncodeError::InsufficientSize(InsufficientSizeError {
                required_size: 7
            }))
        );
        assert!(buf.iter().all(|&b| b == 0xa5), "nothing written");
        assert!(!alert.is_empty(), "nothing consumed");
    }
    let mut buf = [0u8; 7];
    assert_eq!(alert.encode(&mut buf), Ok(7));
    assert_eq!(
        fatal_alert(&buf),
        u8::from(AlertDescription::UnexpectedMessage)
    );
    assert!(alert.is_empty());
    assert_eq!(alert.encode(&mut buf), Ok(0));
}

#[test]
fn an_invalid_configuration_is_refused_with_an_alert() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let hello = client_hello_of(&Arc::new(versioned_client(
        &chain,
        ProtocolVersion::TLSv1_3,
    )));
    let internal = u8::from(AlertDescription::InternalError);

    let mut fragment = versioned_server(&chain, ProtocolVersion::TLSv1_3);
    fragment.max_fragment_size = Some(10);
    let mut record_size = versioned_server(&chain, ProtocolVersion::TLSv1_3);
    record_size.record_size_limit = Some(10);
    let mut cookie = versioned_server(&chain, ProtocolVersion::TLSv1_3);
    cookie.ticketer = prov::Ticketer::new().unwrap();
    cookie.hello_retry_cookies = Some(cookie.ticketer.clone());

    for config in [fragment, record_size, cookie] {
        let config = Arc::new(config);
        let refused = UnbufferedServerConnection::new(config.clone()).unwrap_err();
        assert!(
            matches!(
                refused,
                Error::BadMaxFragmentSize | Error::BadRecordSizeLimit | Error::General(_)
            ),
            "{refused:?}"
        );
        for feed in [Feed::Whole, Feed::ByteByByte] {
            let (err, alert, discarded) = unbuffered_refusal(&hello, feed, Some(config.clone()));
            // The checks of a connection created with the configuration.
            assert_eq!(err, refused);
            assert_eq!(discarded, hello.len());
            assert_eq!(fatal_alert(&alert), internal, "{err:?}");
            assert_eq!((err, alert), buffered_refusal(&hello, Some(config.clone())));
        }
    }
}

#[test]
fn a_configuration_that_cannot_serve_the_client_hello_is_refused() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = versioned_client(&chain, ProtocolVersion::TLSv1_3);
    client.alpn_protocols = vec![b"h2".to_vec()];
    let hello = client_hello_of(&Arc::new(client));
    let mut server = versioned_server(&chain, ProtocolVersion::TLSv1_3);
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server = Arc::new(server);
    for feed in [Feed::Whole, Feed::ByteByByte] {
        let (err, alert, _) = unbuffered_refusal(&hello, feed, Some(server.clone()));
        assert_eq!(err, Error::NoApplicationProtocol);
        assert_eq!(
            fatal_alert(&alert),
            u8::from(AlertDescription::NoApplicationProtocol)
        );
        assert_eq!((err, alert), buffered_refusal(&hello, Some(server.clone())));
    }
}

/// The acceptor reads a ClientHello of either version: the version policy
/// is the configuration's, and a TLS 1.3-only one refuses a TLS 1.2 hello.
#[cfg(feature = "tls12")]
#[test]
fn a_tls13_only_configuration_refuses_the_hello_of_a_tls12_client() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let hello = client_hello_of(&Arc::new(versioned_client(
        &chain,
        ProtocolVersion::TLSv1_2,
    )));
    let server = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    for feed in [Feed::Whole, Feed::ByteByByte] {
        let (err, alert, _) = unbuffered_refusal(&hello, feed, Some(server.clone()));
        assert_eq!(
            err,
            Error::PeerIncompatible(browntls_core::PeerIncompatible::Tls12NotOfferedOrEnabled)
        );
        assert_eq!(
            fatal_alert(&alert),
            u8::from(AlertDescription::ProtocolVersion)
        );
        assert_eq!((err, alert), buffered_refusal(&hello, Some(server.clone())));
    }
}

/// `flight`, one TLS 1.3 ClientHello record, with `tail` appended to that
/// record as handshake bytes following the ClientHello.
fn with_handshake_tail(flight: &[u8], tail: &[u8]) -> Vec<u8> {
    assert_eq!(flight[0], 0x16);
    let len = usize::from(u16::from_be_bytes([flight[3], flight[4]]));
    assert_eq!(flight.len(), 5 + len, "one record");
    let mut out = flight.to_vec();
    out.extend_from_slice(tail);
    out[3..5].copy_from_slice(&u16::try_from(len + tail.len()).unwrap().to_be_bytes());
    out
}

#[test]
fn handshake_bytes_after_a_key_changing_client_hello_are_refused() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_3));
    let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
    // RFC 8446 §5.1: the ClientHello changes the read key, so it must end
    // its record. A Finished header, then a whole (plaintext) Finished.
    let header = [0x14, 0, 0, 0x20];
    let finished = [&header[..], &[0u8; 32]].concat();
    for tail in [&header[..], &finished[..]] {
        // A connection created with the configuration, the unbuffered
        // acceptor (whole and byte-by-byte input) and the buffered one.
        for server in 0..4 {
            let mut client = b_client(&cc);
            let flight = with_handshake_tail(&client.take_output(), tail);
            let (err, output) = match server {
                0 => {
                    let mut s = ub_server(&sc, Feed::Whole);
                    s.give_input(&flight);
                    (s.error.clone().expect("refused"), s.take_output())
                }
                1 | 2 => {
                    let feed = [Feed::Whole, Feed::ByteByByte][server - 1];
                    let (err, alert, discarded) =
                        unbuffered_refusal(&flight, feed, Some(sc.clone()));
                    assert_eq!(discarded, flight.len());
                    (err, alert)
                }
                _ => buffered_refusal(&flight, Some(sc.clone())),
            };
            assert_eq!(
                err,
                Error::PeerMisbehaved(PeerMisbehaved::KeyEpochWithPendingFragment),
                "server {server}"
            );
            // The server's flight, then the alert under its new key.
            client.give_input(&output);
            assert_eq!(
                client.error,
                Some(Error::AlertReceived(AlertDescription::UnexpectedMessage)),
                "server {server}"
            );
        }
    }
}

/// The `extended_master_secret` extension type (RFC 7627).
#[cfg(feature = "tls12")]
const EXTENDED_MASTER_SECRET: u16 = 23;

#[cfg(feature = "tls12")]
#[test]
fn a_refused_tls12_resumption_forgets_the_session() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let cc = Arc::new(versioned_client(&chain, ProtocolVersion::TLSv1_2));
    let mut sc = versioned_server(&chain, ProtocolVersion::TLSv1_2);
    sc.require_ems = false;
    let sc = Arc::new(sc);
    // A connection created with the configuration, the unbuffered acceptor
    // (whole and byte-by-byte input) and the buffered one.
    for server in 0..4 {
        // A session with the extended master secret.
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, Feed::Whole);
        handshake(&mut c, &mut s);

        // Its resumption without the extension is refused (RFC 7627 §5.3)
        // after the session was looked up.
        let mut hello = b_client(&cc).take_output();
        let ems = extension_body(&hello, EXTENDED_MASTER_SECRET);
        hello[ems - 4..ems - 2].copy_from_slice(&[0x42, 0x42]);
        let at = 5 + 4 + 2 + 32;
        let id = hello[at + 1..at + 1 + usize::from(hello[at])].to_vec();
        assert!(!id.is_empty(), "the client resumes by session ID");
        assert!(sc.session_storage.get(&id).is_some(), "resumable");
        let (err, alert) = match server {
            0 => {
                let mut s = ub_server(&sc, Feed::Whole);
                s.give_input(&hello);
                (s.error.clone().expect("refused"), s.take_output())
            }
            1 | 2 => {
                let feed = [Feed::Whole, Feed::ByteByByte][server - 1];
                let (err, alert, _) = unbuffered_refusal(&hello, feed, Some(sc.clone()));
                (err, alert)
            }
            _ => buffered_refusal(&hello, Some(sc.clone())),
        };
        assert_eq!(
            err,
            Error::PeerMisbehaved(PeerMisbehaved::ResumptionAttemptedWithVariedEms),
            "server {server}"
        );
        assert_eq!(
            fatal_alert(&alert),
            u8::from(AlertDescription::HandshakeFailure)
        );

        // RFC 5246 §7.2.2: the session of a failed connection is not
        // resumable any more.
        assert!(sc.session_storage.get(&id).is_none(), "server {server}");
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, Feed::Whole);
        handshake(&mut c, &mut s);
        assert_eq!(s.conn.handshake_kind(), Some(HandshakeKind::Full));
    }
}
