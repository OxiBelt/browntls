// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: a server with GREASE on (RFC 8701 §4.1,
// `ServerConfig::enable_grease`) behind the unbuffered API. What the
// messages look like on the wire is checked in `cases/quic/grease.rs` and
// `cases/kernel.rs`; here the same messages go through the unbuffered
// record path on either side.

/// A TLS 1.3 server with GREASE on that requires `client`'s certificate,
/// during the handshake or, when `defer`, on request after it.
fn grease_server(server: &Chain, client: &Chain, defer: bool) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(client, true))
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap();
    config.session_storage = browntls_core::server::ServerSessionMemoryCache::new(16);
    config.request_client_auth_after_handshake = defer;
    config.enable_grease = true;
    Arc::new(config)
}

#[test]
fn unbuffered_server_with_grease_authenticates_clients_and_resumes() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    for feed in [Feed::Whole, Feed::ByteByByte] {
        // An unbuffered client reads the GREASE CertificateRequest and
        // tickets of an unbuffered server; its second connection resumes.
        let cc = pha_client(&server_chain, Some(&client_chain));
        let sc = grease_server(&server_chain, &client_chain, false);
        for resuming in [false, true] {
            let mut c = ub_client(&cc, feed);
            let mut s = ub_server(&sc, feed);
            handshake(&mut c, &mut s);
            let kind = if resuming {
                HandshakeKind::Resumed
            } else {
                HandshakeKind::Full
            };
            assert_eq!(c.conn.handshake_kind(), Some(kind), "{feed:?}");
            assert_eq!(s.conn.handshake_kind(), Some(kind), "{feed:?}");
            assert_eq!(
                s.conn.peer_certificates().unwrap(),
                client_chain.cert_chain()
            );
            exchange(&mut c, &mut s, b"greased");
        }

        // A buffered client, and a buffered server for an unbuffered one.
        let cc = pha_client(&server_chain, Some(&client_chain));
        let mut c = b_client(&cc);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        exchange(&mut c, &mut s, b"buffered client");
        let mut c = ub_client(&cc, feed);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        assert_eq!(c.conn.handshake_kind(), Some(HandshakeKind::Resumed));
        exchange(&mut c, &mut s, b"buffered server");
    }
}

#[test]
fn unbuffered_server_with_grease_requests_client_auth_after_the_handshake() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let cc = pha_client(&server_chain, Some(&client_chain));
    let sc = grease_server(&server_chain, &client_chain, true);
    for feed in [Feed::Whole, Feed::ByteByByte] {
        let mut c = ub_client(&cc, feed);
        let mut s = ub_server(&sc, feed);
        handshake(&mut c, &mut s);
        assert!(s.conn.peer_certificates().is_none(), "deferred");
        for round in 1..=2 {
            ub_request_client_auth(&mut c, &mut s);
            assert!(!s.failed() && !c.failed(), "{feed:?} round {round}");
            assert_eq!(c.conn.post_handshake_auth_responses(), round);
            assert_eq!(
                s.conn.post_handshake_auth_status(),
                Some(PostHandshakeAuthStatus::Authenticated)
            );
            exchange(&mut c, &mut s, b"still talking");
        }
        assert_eq!(
            s.conn.peer_certificates().unwrap(),
            client_chain.cert_chain()
        );
    }
}
