// Messages changed on the wire: unsolicited answers, an answer in a TLS 1.3
// ServerHello, malformed bodies, and the second ClientHello after a
// HelloRetryRequest.

/// Feeds the client's first flight to the server and the server's answer,
/// changed by `patch`, back to the client; returns the client's error and
/// checks it sent an alert record.
fn client_error_after_patch(
    client: ClientConfig,
    server: ServerConfig,
    patch: impl FnOnce(&mut Vec<u8>),
) -> Error {
    let (mut client, mut server) = connect(client, server);
    feed(&mut server, &flight(&mut client));
    server.process_new_packets().unwrap();
    let mut reply = flight(&mut server);
    patch(&mut reply);
    feed(&mut client, &reply);
    let err = client.process_new_packets().unwrap_err();
    assert_eq!(flight(&mut client).first(), Some(&21), "an alert record");
    err
}

#[test]
fn an_unsolicited_answer_is_refused() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        // A client that sent neither extension.
        for typ in [EXT_EXTERNAL_ID_HASH, EXT_EXTERNAL_SESSION_ID] {
            let body = if typ == EXT_EXTERNAL_ID_HASH {
                ExternalIdHash::EMPTY.to_extension_data()
            } else {
                tls_id("server").to_extension_data()
            };
            let err = client_error_after_patch(
                client_for(&chain, v, None),
                server_for(&chain, v, None),
                |reply| append_extension(reply, typ, &body),
            );
            let expected = if v == ProtocolVersion::TLSv1_3 {
                // RFC 9846 §4.3: never allowed in a TLS 1.3 ServerHello.
                PeerMisbehaved::UnexpectedCleartextExtension
            } else {
                PeerMisbehaved::UnsolicitedServerHelloExtension
            };
            assert_eq!(err, Error::PeerMisbehaved(expected), "{v:?} {typ}");
        }
    }
}

#[test]
fn an_answer_in_a_tls13_server_hello_is_illegal_parameter() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let v = ProtocolVersion::TLSv1_3;
    let (c, s) = pair();
    // Even when the client sent the extension: TLS 1.3 servers answer in
    // EncryptedExtensions only.
    let err = client_error_after_patch(
        client_for(&chain, v, Some(c)),
        server_for(&chain, v, Some(s)),
        |reply| {
            append_extension(
                reply,
                EXT_EXTERNAL_SESSION_ID,
                &tls_id("server").to_extension_data(),
            )
        },
    );
    assert_eq!(
        err,
        Error::PeerMisbehaved(PeerMisbehaved::UnexpectedCleartextExtension)
    );
}

#[cfg(feature = "tls12")]
#[test]
fn a_malformed_answer_is_decode_error() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let v = ProtocolVersion::TLSv1_2;
    let (c, s) = pair();
    // The server's answer, in the clear in a TLS 1.2 ServerHello, with the
    // hash's length byte lowered from 32 to 31.
    let err = client_error_after_patch(
        client_for(&chain, v, Some(c)),
        server_for(&chain, v, Some(s)),
        |reply| {
            let (_, at, _) = hello_extensions(reply)
                .into_iter()
                .find(|(t, _, _)| *t == EXT_EXTERNAL_ID_HASH)
                .unwrap();
            // binding_hash<0..32> of 31 bytes plus one stray byte.
            reply[at] = 31;
        },
    );
    assert_eq!(
        err,
        Error::InvalidMessage(browntls_core::InvalidMessage::InvalidExternalIdHash)
    );
}

#[test]
fn a_malformed_client_extension_is_decode_error_for_any_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        for configured in [true, false] {
            for (typ, body, why) in [
                (
                    EXT_EXTERNAL_ID_HASH,
                    vec![1, 0],
                    browntls_core::InvalidMessage::InvalidExternalIdHash,
                ),
                (
                    EXT_EXTERNAL_SESSION_ID,
                    [&[19u8][..], &[b'x'; 19]].concat(),
                    browntls_core::InvalidMessage::InvalidExternalSessionId,
                ),
            ] {
                let (mut client, mut server) = connect(
                    client_for(&chain, v, None),
                    server_for(&chain, v, configured.then(|| pair().1)),
                );
                let mut hello = flight(&mut client);
                append_extension(&mut hello, typ, &body);
                feed(&mut server, &hello);
                assert_eq!(
                    server.process_new_packets().unwrap_err(),
                    Error::InvalidMessage(why)
                );
                let alert = flight(&mut server);
                assert_eq!(alert[0], 21);
                assert_eq!(
                    alert[6],
                    u8::from(AlertDescription::DecodeError),
                    "{v:?} {typ}"
                );
            }
        }
    }
}

/// A server that only has P-256, so that a default client is asked to
/// retry.
fn p256_server(chain: &Chain, binding: Option<ExternalBinding>) -> ServerConfig {
    let mut provider = prov::default_provider();
    provider.kx_groups = prov::ALL_KX_GROUPS
        .iter()
        .copied()
        .filter(|g| g.name() == NamedGroup::secp256r1)
        .collect();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.external_binding = binding;
    config
}

#[test]
fn the_second_client_hello_repeats_the_values() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let v = ProtocolVersion::TLSv1_3;
    let (c, s) = pair();
    let (mut client, mut server) =
        connect(client_for(&chain, v, Some(c)), p256_server(&chain, Some(s)));
    let first = flight(&mut client);
    feed(&mut server, &first);
    server.process_new_packets().unwrap();
    feed(&mut client, &flight(&mut server));
    client.process_new_packets().unwrap();
    let second = flight(&mut client);
    for typ in [EXT_EXTERNAL_ID_HASH, EXT_EXTERNAL_SESSION_ID] {
        let body = extension(&second, typ);
        assert!(body.is_some());
        assert_eq!(body, extension(&first, typ));
    }
    feed(&mut server, &second);
    server.process_new_packets().unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(client.peer_external_session_id(), Some(&tls_id("server")));
    assert_eq!(server.peer_external_session_id(), Some(&tls_id("client")));
}

#[test]
fn a_second_client_hello_that_changes_the_values_is_refused() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let v = ProtocolVersion::TLSv1_3;
    // Without expectations, so that only the comparison with the first
    // ClientHello can fail.
    let client = ExternalBinding {
        id_hash: Some(hash(1)),
        session_id: Some(tls_id("client")),
        ..Default::default()
    };
    let (mut client, mut server) = connect(
        client_for(&chain, v, Some(client)),
        p256_server(&chain, Some(ExternalBinding::default())),
    );
    feed(&mut server, &flight(&mut client));
    server.process_new_packets().unwrap();
    feed(&mut client, &flight(&mut server));
    client.process_new_packets().unwrap();
    let mut second = flight(&mut client);
    // Drop the session identifier: an unknown extension type instead.
    retype_extension(&mut second, EXT_EXTERNAL_SESSION_ID, 0x7777);
    feed(&mut server, &second);
    assert_eq!(
        server.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::ExternalBindingChangedOnRetry)
    );
}
