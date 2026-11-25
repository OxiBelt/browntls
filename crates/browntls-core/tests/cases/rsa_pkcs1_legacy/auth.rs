// Cases included by `cases/rsa_pkcs1_legacy.rs`, which holds the imports
// and the shared helpers: a token key authenticating a TLS 1.3 client with
// each legacy scheme, in the handshake and after it, what the
// CertificateRequest offers with and without the opt-in, and a server
// without the opt-in.

/// Each legacy scheme authenticates a TLS 1.3 client to an opted-in
/// server: the key prefers that scheme, the server verifies exactly it
/// against the client's chain, and application data flows afterwards.
#[test]
fn mutual_authentication_with_each_legacy_scheme() {
    for scheme in LEGACY {
        let key = TokenKey::legacy(scheme, Sig::Pkcs1);
        let mut outcome = authenticate(
            prov::provider_with_rsa_pkcs1_legacy(),
            true,
            rsa_client(),
            key.clone(),
        );
        outcome.completed();
        assert_eq!(outcome.verifier.seen(), [scheme], "{scheme:?}");
        assert_eq!(
            outcome.server.peer_certificates().unwrap(),
            rsa_client().cert_chain()
        );
        assert_eq!(
            outcome.client.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert_eq!(key.offered().len(), 1);
        assert!(OPT_IN_ORDER.iter().all(|s| key.offered()[0].contains(s)));
    }
}

/// An opted-in server's TLS 1.3 CertificateRequest lists the provider's
/// default TLS 1.3 schemes, in their order, then 0x0620, 0x0520 and 0x0420;
/// the client's resolver and key are given exactly that. A default
/// server's request lists no legacy scheme, so the key finds nothing to
/// sign with and the client sends an empty Certificate, which a server
/// with optional client authentication accepts.
#[test]
fn certificate_request_lists_the_legacy_schemes_last() {
    let key = TokenKey::legacy(S::RSA_PKCS1_SHA256_LEGACY, Sig::Pkcs1);
    let mut default = authenticate(prov::provider(), false, rsa_client(), key.clone());
    default.completed();
    assert!(default.server.peer_certificates().is_none());
    assert!(default.verifier.seen().is_empty());
    assert_eq!(default.resolver.seen(), [default_tls13_schemes()]);
    assert_eq!(key.offered(), [default_tls13_schemes()]);

    let key = TokenKey::legacy(S::RSA_PKCS1_SHA256_LEGACY, Sig::Pkcs1);
    let mut opt_in = authenticate(
        prov::provider_with_rsa_pkcs1_legacy(),
        false,
        rsa_client(),
        key.clone(),
    );
    opt_in.completed();
    let mut expected = default_tls13_schemes();
    expected.extend(OPT_IN_ORDER);
    assert_eq!(opt_in.resolver.seen(), [expected.clone()]);
    assert_eq!(key.offered(), [expected]);
    assert_eq!(opt_in.verifier.seen(), [S::RSA_PKCS1_SHA256_LEGACY]);
    assert_eq!(
        opt_in.server.peer_certificates().unwrap(),
        rsa_client().cert_chain()
    );
}

/// Post-handshake client authentication (RFC 9846 §4.6.2) with each legacy
/// scheme against an opted-in server that defers client authentication:
/// the CertificateRequest after the handshake lists the legacy schemes as
/// the one in the handshake would, the key signs with its scheme, and the
/// server authenticates the client's chain.
#[test]
fn post_handshake_authentication_with_a_legacy_scheme() {
    for scheme in LEGACY {
        let key = TokenKey::legacy(scheme, Sig::Pkcs1);
        let verifier = client_verifier(prov::provider_with_rsa_pkcs1_legacy(), rsa_client(), true);
        let resolver = Recording::new(Some(CertifiedKey::new(
            rsa_client().cert_chain(),
            key.clone(),
        )));
        let mut client_config = client_config_for(prov::provider(), &TLS13, resolver.clone());
        client_config.enable_post_handshake_auth = true;
        let mut server_config = server_config_for(
            prov::provider_with_rsa_pkcs1_legacy(),
            &TLS13,
            verifier.clone(),
        );
        server_config.request_client_auth_after_handshake = true;
        let mut client =
            ClientConnection::new(Arc::new(client_config), common::server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        common::do_handshake(&mut client, &mut server).unwrap();
        assert!(server.post_handshake_auth_offered());
        assert!(server.peer_certificates().is_none(), "deferred");
        assert!(key.offered().is_empty());

        server.request_client_auth().unwrap();
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        assert_eq!(
            server.post_handshake_auth_status(),
            Some(PostHandshakeAuthStatus::Authenticated),
            "{scheme:?}"
        );
        assert_eq!(client.post_handshake_auth_responses(), 1);
        assert_eq!(verifier.seen(), [scheme]);
        assert_eq!(
            server.peer_certificates().unwrap(),
            rsa_client().cert_chain()
        );
        let mut expected = default_tls13_schemes();
        expected.extend(OPT_IN_ORDER);
        assert_eq!(resolver.seen(), [expected.clone()]);
        assert_eq!(key.offered(), [expected]);
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"authenticated"),
            b"authenticated"
        );
    }
}

/// A client whose key signs with the legacy schemes only, against a server
/// without the opt-in: the key is never offered a legacy scheme, so the
/// client sends an empty Certificate. Mandatory client authentication then
/// fails with `certificate_required` (RFC 9846 §4.4.2.4); optional client
/// authentication completes without a client certificate.
#[test]
fn legacy_only_client_against_a_default_server() {
    for mandatory in [true, false] {
        let key = TokenKey::legacy(S::RSA_PKCS1_SHA256_LEGACY, Sig::Pkcs1);
        let mut outcome = authenticate(prov::provider(), mandatory, rsa_client(), key.clone());
        assert_eq!(key.offered(), [default_tls13_schemes()]);
        assert!(key.offered().iter().flatten().all(|s| !is_legacy(s)));
        assert!(outcome.verifier.seen().is_empty());
        if mandatory {
            outcome.refused(
                Error::NoCertificatesPresented,
                AlertDescription::CertificateRequired,
                "mandatory",
            );
        } else {
            outcome.completed();
            assert!(outcome.server.peer_certificates().is_none());
        }
    }
}

/// A key that names a legacy scheme the CertificateRequest did not list
/// (here, a default server's) is treated by the browntls client as one
/// that cannot sign: the client sends an empty Certificate rather than a
/// CertificateVerify the server must refuse (RFC 9963 §3). The case where
/// such a CertificateVerify does reach the server is in
/// `rustls_peers.rs`, with a rustls client.
#[test]
fn browntls_client_does_not_sign_with_an_unoffered_legacy_scheme() {
    for mandatory in [true, false] {
        let key = TokenKey::ignoring_offer(S::RSA_PKCS1_SHA256_LEGACY, Sig::Pkcs1);
        let mut outcome = authenticate(prov::provider(), mandatory, rsa_client(), key.clone());
        assert_eq!(key.offered(), [default_tls13_schemes()]);
        assert!(outcome.verifier.seen().is_empty());
        if mandatory {
            outcome.refused(
                Error::NoCertificatesPresented,
                AlertDescription::CertificateRequired,
                "mandatory",
            );
        } else {
            outcome.completed();
            assert!(outcome.server.peer_certificates().is_none());
        }
    }
}

/// Both sides opted in everywhere (the client's configuration and its
/// server verifier too): the ClientHello still lists no legacy scheme and
/// its `signature_algorithms` are those of a default client, a server
/// verifier built with the opt-in table advertises no legacy scheme, and
/// the client still authenticates with a legacy scheme.
#[test]
fn client_hello_is_unchanged_by_the_opt_in() {
    let hello_schemes = |provider: CryptoProvider| {
        let config = ClientConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier(provider, server()))
            .with_client_cert_resolver(Recording::new(None));
        let mut client = ClientConnection::new(Arc::new(config), common::server_name()).unwrap();
        let flight = common::hello_wire::take_flight(&mut client);
        let extensions = common::hello_wire::hello_extensions(&flight, true);
        let (_, body) = extensions
            .iter()
            .find(|(typ, _)| *typ == 0x000d)
            .expect("signature_algorithms");
        common::grease_wire::signature_schemes(body)
    };
    let default = hello_schemes(prov::provider());
    let opt_in = hello_schemes(prov::provider_with_rsa_pkcs1_legacy());
    assert_eq!(opt_in, default);
    assert!(
        opt_in
            .iter()
            .all(|s| !matches!(s, 0x0420 | 0x0520 | 0x0620)),
        "{opt_in:x?}"
    );
    // The opt-in table does map the schemes; only the hello leaves them out.
    let table = prov::provider_with_rsa_pkcs1_legacy()
        .signature_verification_algorithms
        .supported_schemes();
    assert!(OPT_IN_ORDER.iter().all(|s| table.contains(s)));

    let key = TokenKey::legacy(S::RSA_PKCS1_SHA384_LEGACY, Sig::Pkcs1);
    let verifier = server_verifier(prov::provider_with_rsa_pkcs1_legacy(), server());
    assert!(
        verifier
            .supported_verify_schemes()
            .iter()
            .all(|s| !is_legacy(s))
    );
    let mut outcome = authenticate_with(
        prov::provider_with_rsa_pkcs1_legacy(),
        prov::provider_with_rsa_pkcs1_legacy(),
        true,
        rsa_client(),
        key,
    );
    outcome.completed();
    assert_eq!(outcome.verifier.seen(), [S::RSA_PKCS1_SHA384_LEGACY]);
}
