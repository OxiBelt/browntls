// Cases included by `cases/delegated_credentials.rs`, which holds the imports
// and the shared helpers (and `client_auth.rs`, those of client
// authentication): post-handshake client authentication (RFC 9846 §4.7.2)
// answered with a delegated credential (RFC 9345 §4.1.2).

/// Requests post-handshake client authentication and carries the exchange
/// through.
fn post_handshake_auth(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), Error> {
    server.request_client_auth().unwrap();
    transfer(server, client);
    client.process_new_packets()?;
    transfer(client, server);
    server.process_new_packets()?;
    Ok(())
}

/// A client set up for post-handshake authentication through `resolver`,
/// and a server that defers optional client authentication to after the
/// handshake and accepts client credentials.
fn post_handshake_pair(
    server_chain: &Chain,
    chain: &Chain,
    resolver: Arc<SwitchingResolver>,
) -> (ClientConnection, ServerConnection) {
    let mut client_config = client_switching(server_chain, resolver);
    client_config.enable_post_handshake_auth = true;
    let mut server_config = dc_server(server_chain, PinnedClientVerifier::new(chain, false));
    server_config.request_client_auth_after_handshake = true;
    connect(client_config, server_config)
}

/// Every post-handshake CertificateRequest carries the extension; the
/// accessor follows the latest successful authentication.
#[test]
fn client_answers_post_handshake_auth_with_a_credential() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let (dc, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let (other_dc, other_key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(7200),
    );
    let resolver = SwitchingResolver::new(with_client_credentials(&chain, vec![(dc.clone(), key)]));
    let (mut client, mut server) = post_handshake_pair(&server_chain, &chain, resolver.clone());
    do_handshake(&mut client, &mut server).unwrap();
    assert!(server.peer_certificates().is_none(), "deferred");
    assert!(server.client_delegated_credential().is_none());

    let authenticated = Some(PostHandshakeAuthStatus::Authenticated);
    post_handshake_auth(&mut client, &mut server).unwrap();
    assert_eq!(server.post_handshake_auth_status(), authenticated);
    assert_eq!(server.client_delegated_credential(), Some(&dc));
    assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"delegated"),
        b"delegated"
    );

    // The certificate key answers the next request: no credential.
    resolver.set(Some(certified_key(&chain)));
    post_handshake_auth(&mut client, &mut server).unwrap();
    assert_eq!(server.post_handshake_auth_status(), authenticated);
    assert!(server.client_delegated_credential().is_none());
    assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);

    // Another credential answers the one after.
    resolver.set(Some(with_client_credentials(
        &chain,
        vec![(other_dc.clone(), other_key)],
    )));
    post_handshake_auth(&mut client, &mut server).unwrap();
    assert_eq!(server.post_handshake_auth_status(), authenticated);
    assert_eq!(server.client_delegated_credential(), Some(&other_dc));

    // A declined request leaves the latest successful authentication.
    resolver.set(None);
    post_handshake_auth(&mut client, &mut server).unwrap();
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Declined)
    );
    assert_eq!(server.client_delegated_credential(), Some(&other_dc));
    assert_eq!(server.peer_certificates().unwrap()[0], chain.end_entity);
    assert_eq!(
        send_and_receive(&mut server, &mut client, b"still up"),
        b"still up"
    );
}

/// An invalid credential in a post-handshake answer is refused like one
/// in the handshake.
#[test]
fn server_rejects_invalid_credential_after_the_handshake() {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let (mut dc, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    dc.credential.valid_time -= 1;
    let resolver = SwitchingResolver::new(with_client_credentials(&chain, vec![(dc, key)]));
    let (mut client, mut server) = post_handshake_pair(&server_chain, &chain, resolver);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(
        post_handshake_auth(&mut client, &mut server),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialBadSignature
        ))
    );
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::AlertReceived(AlertDescription::IllegalParameter)
    );
    assert!(server.client_delegated_credential().is_none());
}

/// Capture the ordinary schemes that arrived in CertificateRequest and
/// supply the delegated credential that answers it.
#[derive(Debug)]
struct RequestRecordingResolver {
    key: Arc<CertifiedKey>,
    received: std::sync::Mutex<Vec<SignatureScheme>>,
}

impl browntls_core::client::ResolvesClientCert for RequestRecordingResolver {
    fn resolve(&self, _: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        *self.received.lock().unwrap() = schemes.to_vec();
        Some(self.key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn client_auth_verifies_with_the_schemes_sent_in_each_greased_request() {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let chain = delegation_client_chain(KeyType::EcdsaP256);
    let (dc, key) = issue_for(
        Side::Client,
        &chain,
        SignatureScheme::ED25519,
        shifted(3600),
    );
    let credential_key = with_client_credentials(&chain, vec![(dc.clone(), key)]);

    for post_handshake in [false, true] {
        let resolver = Arc::new(RequestRecordingResolver {
            key: Arc::new(credential_key.clone()),
            received: Default::default(),
        });
        let mut client_config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
            .with_client_cert_resolver(resolver.clone());
        client_config.enable_post_handshake_auth = post_handshake;
        let verifier = SchemeRecordingClientVerifier::new(
            PinnedClientVerifier::new(&chain, !post_handshake),
            &[SignatureScheme::ECDSA_NISTP384_SHA384],
        );
        verifier.set_first_offer(vec![
            dc.algorithm,
            SignatureScheme::ED25519,
            SignatureScheme::Unknown(0x0a0a),
        ]);
        let mut server_config = dc_server(&server_chain, verifier.clone());
        server_config.enable_grease = true;
        server_config.request_client_auth_after_handshake = post_handshake;
        let (mut client, mut server) = connect(client_config, server_config);
        do_handshake(&mut client, &mut server).unwrap();
        if post_handshake {
            assert!(resolver.received.lock().unwrap().is_empty());
            post_handshake_auth(&mut client, &mut server).unwrap();
        }

        let received = resolver.received.lock().unwrap();
        assert_eq!(
            received.len(),
            3,
            "one GREASE scheme followed by two real schemes"
        );
        assert!(grease_wire::is_grease(received[0].into()));
        assert_eq!(received[1..], [dc.algorithm, SignatureScheme::ED25519]);
        assert_eq!(server.client_delegated_credential(), Some(&dc));
        assert_eq!(verifier.seen(), [dc.algorithm, SignatureScheme::ED25519]);
    }
}
