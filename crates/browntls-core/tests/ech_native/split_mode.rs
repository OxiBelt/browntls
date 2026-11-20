//! Split mode: the client-facing server in front of a back-end server, and
//! the connections it keeps or refuses.

use super::*;

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
        Error::PeerMisbehaved(browntls_core::PeerMisbehaved::IllegalEchClientHelloType)
    );
    // An unknown type.
    let at = ech_extension_offset(&flight);
    flight[at] = 5;
    let mut front = ClientFacing::new(ech);
    let err = front.read_client(&flight).unwrap_err();
    assert_eq!(
        err,
        Error::PeerMisbehaved(browntls_core::PeerMisbehaved::IllegalEchClientHelloType)
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
        Error::PeerMisbehaved(browntls_core::PeerMisbehaved::EchChangedOnRetry)
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
        Error::PeerMisbehaved(browntls_core::PeerMisbehaved::EchDecryptionFailedOnRetry)
    );
    assert_eq!(alert, vec![21, 3, 3, 0, 2, 2, 51]);
    // No ECH extension: its type renamed.
    let (err, alert) = split_second_hello_edited(|buf| {
        let at = ech_extension_offset(buf);
        buf[at - 3] ^= 0x01;
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(
            browntls_core::PeerMisbehaved::MissingEchExtensionInSecondClientHello
        )
    );
    assert_eq!(alert, vec![21, 3, 3, 0, 2, 2, 109]);
    // An extension of an unknown type in its place.
    let (err, _) = split_second_hello_edited(|buf| {
        let at = ech_extension_offset(buf);
        buf[at] = 5;
    });
    assert_eq!(
        err,
        Error::PeerMisbehaved(browntls_core::PeerMisbehaved::IllegalEchClientHelloType)
    );
}
