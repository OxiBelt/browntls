// CertificateURL messages built by hand, and the unbuffered API; included
// by `cases/client_certificate_url.rs`.

/// `flight` with its first record, which must hold exactly one handshake
/// message, replaced by a record holding a message of type `typ` with
/// `body`.
fn replace_first_message(flight: &[u8], typ: u8, body: &[u8]) -> Vec<u8> {
    let (content_type, record) = first_record(flight).unwrap();
    assert_eq!(content_type, 22);
    let len = usize::from(record[1]) << 16 | usize::from(record[2]) << 8 | usize::from(record[3]);
    assert_eq!(4 + len, record.len(), "one message per record");
    let mut out = vec![22, 3, 3];
    out.extend(u16::try_from(4 + body.len()).unwrap().to_be_bytes());
    out.push(typ);
    out.extend(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out.extend_from_slice(&flight[5 + record.len()..]);
    out
}

/// A CertificateURL body: `typ`, then `entries` as `URLAndHash` structures
/// with `padding`.
fn certificate_url_body(typ: u8, entries: &[&str], padding: u8) -> Vec<u8> {
    let mut list = Vec::new();
    for url in entries {
        list.extend(u16::try_from(url.len()).unwrap().to_be_bytes());
        list.extend_from_slice(url.as_bytes());
        list.push(padding);
        list.extend([0x5a; 20]);
    }
    let mut body = vec![typ];
    body.extend(u16::try_from(list.len()).unwrap().to_be_bytes());
    body.extend(list);
    body
}

/// The client's second flight, up to the server; returns the server's
/// error and alert for it after `edit`.
fn server_error_for_client_flight(
    s: &Setup,
    policy: Option<ClientCertificateUrlPolicy>,
    edit: impl FnOnce(&[u8]) -> Vec<u8>,
) -> (Error, Option<u8>) {
    let (mut client, mut server) = connect(
        s.client(&TLS12, s.key(Some(s.individual()), true), true),
        s.server(&TLS12, true, policy),
    );
    let (_, flight) = hello_round(&mut client, &mut server);
    give(&mut client, &flight);
    client.process_new_packets().unwrap();
    give(&mut server, &edit(&take_flight(&mut client)));
    let err = server.process_new_packets().unwrap_err();
    assert!(server.pending_client_certificate_url().is_none());
    (err, fatal_alert(&take_flight(&mut server)))
}

#[test]
fn malformed_certificate_url_messages() {
    init_logging();
    let s = Setup::new();
    let cases = [
        // RFC 6066 §5: padding MUST be 0x01.
        (
            certificate_url_body(0, &[EE_URL], 0),
            InvalidMessage::IllegalCertificateUrlPadding,
            ALERT_ILLEGAL_PARAMETER,
        ),
        // A pkipath list holds one URL.
        (
            certificate_url_body(1, &[PATH_URL, PATH_URL], 1),
            InvalidMessage::IllegalPkiPathUrlCount,
            ALERT_ILLEGAL_PARAMETER,
        ),
        (
            certificate_url_body(2, &[EE_URL], 1),
            InvalidMessage::UnknownCertChainType,
            ALERT_DECODE_ERROR,
        ),
        (
            certificate_url_body(0, &[], 1),
            InvalidMessage::IllegalEmptyList("URLAndHash"),
            ALERT_DECODE_ERROR,
        ),
        (
            certificate_url_body(0, &[""], 1),
            InvalidMessage::IllegalEmptyValue,
            ALERT_DECODE_ERROR,
        ),
    ];
    for (body, err, alert) in cases {
        let result = server_error_for_client_flight(&s, policy(), |flight| {
            replace_first_message(flight, CERTIFICATE_URL, &body)
        });
        assert_eq!(result, (Error::InvalidMessage(err), Some(alert)));
    }
    // The client's own message, with a padding byte of 0x00.
    let result = server_error_for_client_flight(&s, policy(), |flight| {
        let mut flight = flight.to_vec();
        let padding = 5 + 4 + 1 + 2 + 2 + EE_URL.len();
        assert_eq!(flight[padding], 1);
        flight[padding] = 0;
        flight
    });
    assert_eq!(
        result,
        (
            Error::InvalidMessage(InvalidMessage::IllegalCertificateUrlPadding),
            Some(ALERT_ILLEGAL_PARAMETER)
        )
    );
}

/// Without the acknowledgement a CertificateURL is a message out of place.
#[test]
fn certificate_url_without_acknowledgement_is_unexpected() {
    init_logging();
    let s = Setup::new();
    let body = certificate_url_body(0, &[EE_URL], 1);
    let result = server_error_for_client_flight(&s, None, |flight| {
        assert_eq!(first_record(flight).unwrap().1[0], 11, "a Certificate");
        replace_first_message(flight, CERTIFICATE_URL, &body)
    });
    assert_eq!(
        result,
        (
            Error::InappropriateHandshakeMessage {
                expect_types: vec![HandshakeType::Certificate],
                got_type: HandshakeType::CertificateURL,
            },
            Some(ALERT_UNEXPECTED_MESSAGE)
        )
    );
}

/// The pause through the unbuffered API: a buffered client against an
/// unbuffered server.
#[test]
fn the_unbuffered_server_pauses_and_resumes() {
    use browntls_core::server::UnbufferedServerConnection;
    use browntls_core::unbuffered::ConnectionState;

    init_logging();
    let s = Setup::new();
    let mut client = ClientConnection::new(
        Arc::new(s.client(&TLS12, s.key(Some(s.pkipath()), false), true)),
        server_name(),
    )
    .unwrap();
    let mut server =
        UnbufferedServerConnection::new(Arc::new(s.server(&TLS12, true, policy()))).unwrap();

    enum Next {
        Nothing,
        Send,
        Input,
        Query,
        Done,
    }
    let mut incoming = Vec::new();
    let mut outgoing = Vec::new();
    let mut queries = 0;
    for _ in 0..64 {
        let status = server.process_tls_records(&mut incoming);
        let discard = status.discard;
        let next = match status.state.unwrap() {
            ConnectionState::EncodeTlsData(mut encoder) => {
                let mut buf = vec![0; 32 * 1024];
                let n = encoder.encode(&mut buf).unwrap();
                outgoing.extend_from_slice(&buf[..n]);
                Next::Nothing
            }
            ConnectionState::TransmitTlsData(transmit) => {
                transmit.done();
                Next::Send
            }
            ConnectionState::BlockedHandshake => Next::Input,
            ConnectionState::PendingClientCertificateUrl => Next::Query,
            ConnectionState::WriteTraffic(_) => Next::Done,
            other => panic!("unexpected {other:?}"),
        };
        incoming.drain(..discard);
        match next {
            Next::Nothing => {}
            Next::Send => {
                give(&mut client, &outgoing);
                outgoing.clear();
                client.process_new_packets().unwrap();
            }
            Next::Input => {
                let flight = take_flight(&mut client);
                assert!(!flight.is_empty(), "stuck");
                incoming.extend(flight);
            }
            Next::Query => {
                queries += 1;
                // Asking again changes nothing.
                assert!(matches!(
                    server.process_tls_records(&mut incoming).state,
                    Ok(ConnectionState::PendingClientCertificateUrl)
                ));
                let query = server.pending_client_certificate_url().unwrap().clone();
                assert!(
                    server
                        .resolve_client_certificate_url(query.id() + 1, s.fetch(&query))
                        .is_err()
                );
                server
                    .resolve_client_certificate_url(query.id(), s.fetch(&query))
                    .unwrap();
            }
            Next::Done => break,
        }
    }
    assert_eq!(queries, 1);
    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    assert_eq!(
        server.peer_certificates().unwrap(),
        s.client.cert_chain().as_slice()
    );
}
