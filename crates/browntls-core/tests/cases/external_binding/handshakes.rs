// Buffered handshakes: matching values, mismatches detected by either side,
// and peers that omit the extensions.

#[test]
fn matching_bindings_complete_and_are_reported() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let (c, s) = pair();
        let (mut client, mut server) = connect(
            client_for(&chain, v, Some(c.clone())),
            server_for(&chain, v, Some(s.clone())),
        );
        let hello = flight(&mut client);
        assert_eq!(
            extension(&hello, EXT_EXTERNAL_ID_HASH),
            Some(hash(1).to_extension_data())
        );
        assert_eq!(
            extension(&hello, EXT_EXTERNAL_SESSION_ID),
            Some(tls_id("client").to_extension_data())
        );
        feed(&mut server, &hello);
        server.process_new_packets().unwrap();
        // The server's values were checked and are reported at once.
        assert_eq!(server.peer_external_id_hash(), Some(&hash(1)));
        assert_eq!(server.peer_external_session_id(), Some(&tls_id("client")));
        let reply = flight(&mut server);
        let in_server_hello = extension(&reply, EXT_EXTERNAL_SESSION_ID);
        if v == ProtocolVersion::TLSv1_3 {
            // RFC 8844 §4.3: EncryptedExtensions, never the ServerHello.
            assert_eq!(in_server_hello, None);
            assert_eq!(extension(&reply, EXT_EXTERNAL_ID_HASH), None);
        } else {
            assert_eq!(in_server_hello, Some(tls_id("server").to_extension_data()));
            assert_eq!(
                extension(&reply, EXT_EXTERNAL_ID_HASH),
                Some(hash(2).to_extension_data())
            );
        }
        feed(&mut client, &reply);
        client.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.peer_external_id_hash(), Some(&hash(2)), "{v:?}");
        assert_eq!(client.peer_external_session_id(), Some(&tls_id("server")));
        assert_eq!(server.peer_external_id_hash(), Some(&hash(1)));
        assert_eq!(server.peer_external_session_id(), Some(&tls_id("client")));
        assert_eq!(
            send_and_receive(&mut *client, &mut *server, b"ping"),
            b"ping"
        );
    }
}

#[test]
fn without_a_binding_nothing_is_sent_or_reported() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let (mut client, mut server) = connect(
            client_for(&chain, v, None),
            server_for(&chain, v, Some(pair().1)),
        );
        let hello = flight(&mut client);
        assert_eq!(extension(&hello, EXT_EXTERNAL_ID_HASH), None);
        assert_eq!(extension(&hello, EXT_EXTERNAL_SESSION_ID), None);
        feed(&mut server, &hello);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.peer_external_id_hash(), None);
        assert_eq!(client.peer_external_session_id(), None);
        // A configured server records nothing it was not sent.
        assert_eq!(server.peer_external_id_hash(), None);
        assert_eq!(server.peer_external_session_id(), None);
    }
}

/// Runs a handshake expected to fail: the side that detects the problem
/// reports `detector`, the other one receives the matching alert.
fn assert_fails(
    v: ProtocolVersion,
    client: ClientConfig,
    server: ServerConfig,
    server_detects: bool,
    detector: Error,
) {
    let missing = matches!(detector, Error::PeerIncompatible(_));
    let (mut client, mut server) = connect(client, server);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    let (detected, alerted) = if server_detects {
        (server_res, client_res)
    } else {
        (client_res, server_res)
    };
    assert_eq!(detected, Err(detector), "{v:?}");
    assert_eq!(alerted, Err(alert_for(v, missing)), "{v:?}");
}

#[test]
fn mismatches_are_illegal_parameter() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let id_mismatch = Error::PeerMisbehaved(PeerMisbehaved::ExternalIdHashMismatch);
    let session_mismatch = Error::PeerMisbehaved(PeerMisbehaved::ExternalSessionIdMismatch);
    for v in VERSIONS {
        let (c, s) = pair();
        let run = |c: ExternalBinding, s: ExternalBinding, server_detects, why: &Error| {
            assert_fails(
                v,
                client_for(&chain, v, Some(c)),
                server_for(&chain, v, Some(s)),
                server_detects,
                why.clone(),
            );
        };

        // The server expects another hash than the client sends.
        let mut other = s.clone();
        other.peer_id_hash = Some(hash(9));
        run(c.clone(), other, true, &id_mismatch);
        // An empty hash where a full one is expected, and the reverse.
        let mut empty = c.clone();
        empty.id_hash = Some(ExternalIdHash::EMPTY);
        run(empty.clone(), s.clone(), true, &id_mismatch);
        let mut expects_empty = s.clone();
        expects_empty.peer_id_hash = Some(ExternalIdHash::EMPTY);
        run(c.clone(), expects_empty, true, &id_mismatch);
        // Another session identifier than the server expects.
        let mut other = c.clone();
        other.session_id = Some(tls_id("someone else"));
        run(other, s.clone(), true, &session_mismatch);

        // The client detects: the server's hash, its session identifier,
        // an empty hash.
        let mut other = s.clone();
        other.id_hash = Some(hash(9));
        run(c.clone(), other, false, &id_mismatch);
        let mut other = s.clone();
        other.session_id = Some(tls_id("someone else"));
        run(c.clone(), other, false, &session_mismatch);
        let mut other = s.clone();
        other.id_hash = None;
        other.peer_id_hash = None;
        // A server without an assertion of its own answers with the empty
        // hash (RFC 8844 §3.2), whether or not it expects one: not the
        // client's expectation.
        run(c.clone(), other.clone(), false, &id_mismatch);
        other.peer_id_hash = Some(hash(1));
        run(c.clone(), other, false, &id_mismatch);
    }
}

#[test]
fn an_unconfigured_server_does_not_answer() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let (c, _) = pair();
        // Accepted by default (RFC 8844 lets the client continue)...
        let (mut client, mut server) = connect(
            client_for(&chain, v, Some(c.clone())),
            server_for(&chain, v, None),
        );
        feed(&mut server, &flight(&mut client));
        server.process_new_packets().unwrap();
        let reply = flight(&mut server);
        assert_eq!(extension(&reply, EXT_EXTERNAL_ID_HASH), None);
        assert_eq!(extension(&reply, EXT_EXTERNAL_SESSION_ID), None);
        feed(&mut client, &reply);
        client.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.peer_external_id_hash(), None);
        assert_eq!(client.peer_external_session_id(), None);
        assert_eq!(server.peer_external_session_id(), None);

        // ...refused when the client requires support.
        let mut required = c.clone();
        required.require_peer_support = true;
        assert_fails(
            v,
            client_for(&chain, v, Some(required.clone())),
            server_for(&chain, v, None),
            false,
            Error::PeerIncompatible(PeerIncompatible::ExternalIdHashExtensionRequired),
        );
        // Only the session identifier expected.
        required.peer_id_hash = None;
        assert_fails(
            v,
            client_for(&chain, v, Some(required)),
            server_for(&chain, v, None),
            false,
            Error::PeerIncompatible(PeerIncompatible::ExternalSessionIdExtensionRequired),
        );
    }
}

#[test]
fn a_silent_client_is_accepted_unless_support_is_required() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let (_, s) = pair();
        let (mut client, mut server) = connect(
            client_for(&chain, v, None),
            server_for(&chain, v, Some(s.clone())),
        );
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(server.peer_external_id_hash(), None);

        let mut required = s.clone();
        required.require_peer_support = true;
        assert_fails(
            v,
            client_for(&chain, v, None),
            server_for(&chain, v, Some(required.clone())),
            true,
            Error::PeerIncompatible(PeerIncompatible::ExternalIdHashExtensionRequired),
        );
        // A client that sends only the hash still lacks the session ID.
        let partial = ExternalBinding {
            id_hash: s.peer_id_hash,
            ..Default::default()
        };
        assert_fails(
            v,
            client_for(&chain, v, Some(partial)),
            server_for(&chain, v, Some(required)),
            true,
            Error::PeerIncompatible(PeerIncompatible::ExternalSessionIdExtensionRequired),
        );
    }
}

#[test]
fn without_expectations_values_are_only_reported() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        // Each side sends its values and compares nothing; the
        // application checks what the accessors report.
        let client = ExternalBinding {
            session_id: Some(tls_id("client")),
            ..Default::default()
        };
        let server = ExternalBinding {
            id_hash: Some(hash(2)),
            session_id: Some(tls_id("server")),
            ..Default::default()
        };
        let (mut c, mut s) = connect(
            client_for(&chain, v, Some(client)),
            server_for(&chain, v, Some(server)),
        );
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(s.peer_external_session_id(), Some(&tls_id("client")));
        // A configured binding always sends the hash, empty without an
        // assertion of our own (RFC 8844 §3.2); the server answers it.
        assert_eq!(s.peer_external_id_hash(), Some(&ExternalIdHash::EMPTY));
        assert_eq!(c.peer_external_session_id(), Some(&tls_id("server")));
        assert_eq!(c.peer_external_id_hash(), Some(&hash(2)));

        // The same with an expectation: the empty hash, answered with the
        // server's own.
        let client = ExternalBinding {
            peer_id_hash: Some(hash(2)),
            ..Default::default()
        };
        let server = ExternalBinding {
            id_hash: Some(hash(2)),
            peer_id_hash: Some(ExternalIdHash::EMPTY),
            ..Default::default()
        };
        let (mut c, mut s) = connect(
            client_for(&chain, v, Some(client)),
            server_for(&chain, v, Some(server)),
        );
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(s.peer_external_id_hash(), Some(&ExternalIdHash::EMPTY));
        assert_eq!(c.peer_external_id_hash(), Some(&hash(2)));
    }
}

#[test]
fn a_client_expecting_the_server_session_id_must_send_its_own() {
    let chain = server_chain(KeyType::EcdsaP256);
    let binding = ExternalBinding {
        peer_session_id: Some(tls_id("server")),
        ..Default::default()
    };
    let config = Arc::new(client_for(&chain, ProtocolVersion::TLSv1_3, Some(binding)));
    assert_eq!(
        ClientConnection::new(config, server_name()).unwrap_err(),
        Error::InconsistentExternalBinding
    );
}

#[test]
fn assertion_hash_uses_sha256() {
    let digest = ExternalIdHash::for_assertion(&provider(), b"abc").unwrap();
    // FIPS 180-2 appendix B.1.
    assert_eq!(
        digest.as_bytes(),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
}
