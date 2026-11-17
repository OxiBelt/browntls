// Cases included by `cases/tls13_features.rs`, which holds the imports and
// the shared helpers: post-handshake client authentication.

// ------------------------------------- post-handshake client authentication

#[test]
fn post_handshake_auth_after_a_handshake_without_client_auth() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    for &key_type in KeyType::SIGNING {
        let client_chain = client_chain(key_type);
        let (mut client, mut server) = connect(
            pha_client(&server_chain, &client_chain),
            pha_server(&server_chain, &client_chain, true, true),
        );
        handshake(&mut client, &mut server);
        assert!(server.post_handshake_auth_offered());
        assert!(server.peer_certificates().is_none(), "deferred");
        assert_eq!(server.post_handshake_auth_status(), None);

        post_handshake_auth(&mut client, &mut server)
            .unwrap_or_else(|e| panic!("{key_type:?}: {e}"));
        assert_eq!(client.post_handshake_auth_responses(), 1);
        assert_eq!(
            server.post_handshake_auth_status(),
            Some(PostHandshakeAuthStatus::Authenticated)
        );
        assert_eq!(
            server.peer_certificates().unwrap(),
            client_chain.cert_chain()
        );
        assert_eq!(
            send_and_receive(&mut client, &mut server, b"authenticated"),
            b"authenticated"
        );

        // Each request has its own context and transcript.
        post_handshake_auth(&mut client, &mut server).unwrap();
        assert_eq!(client.post_handshake_auth_responses(), 2);
        assert_eq!(
            server.post_handshake_auth_status(),
            Some(PostHandshakeAuthStatus::Authenticated)
        );
        assert_eq!(
            send_and_receive(&mut server, &mut client, b"still fine"),
            b"still fine"
        );
    }
}

#[test]
fn post_handshake_auth_repeats_handshake_client_auth() {
    init_logging();
    let server_chain = server_chain(KeyType::Ed25519);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        pha_client(&server_chain, &client_chain),
        pha_server(&server_chain, &client_chain, true, false),
    );
    handshake(&mut client, &mut server);
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain(),
        "authenticated in the handshake"
    );
    post_handshake_auth(&mut client, &mut server).unwrap();
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
}

#[test]
fn post_handshake_auth_after_resumption() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = Arc::new(pha_client(&server_chain, &client_chain));
    let server_config = Arc::new(pha_server(&server_chain, &client_chain, false, true));
    let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    handshake(&mut client, &mut server);
    assert!(client.tls13_tickets_received() > 0);

    // RFC 9846 §4.4.2: a PSK handshake carries no CertificateRequest, but
    // post-handshake authentication is allowed.
    let mut client = ClientConnection::new(client_config, server_name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    handshake(&mut client, &mut server);
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    post_handshake_auth(&mut client, &mut server).unwrap();
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
}

#[test]
fn post_handshake_auth_survives_a_client_key_update_before_the_answer() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        pha_client(&server_chain, &client_chain),
        pha_server(&server_chain, &client_chain, true, true),
    );
    handshake(&mut client, &mut server);
    server.request_client_auth().unwrap();
    // A second request while one is outstanding is refused locally.
    assert!(server.request_client_auth().is_err());
    // The client rotates its key and sends data before it reads the
    // request: the answer's Finished then uses the next application secret.
    client.refresh_traffic_keys().unwrap();
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"before answering"),
        b"before answering"
    );
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Authenticated)
    );
}

/// Has certificates but never finds one acceptable.
#[derive(Debug)]
struct DeclinesEveryRequest;

impl ResolvesClientCert for DeclinesEveryRequest {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn declining_client(server: &Chain) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(server))
        .with_client_cert_resolver(Arc::new(DeclinesEveryRequest));
    config.enable_post_handshake_auth = true;
    config
}

#[test]
fn post_handshake_auth_declined_when_optional() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        declining_client(&server_chain),
        pha_server(&server_chain, &client_chain, false, true),
    );
    handshake(&mut client, &mut server);
    post_handshake_auth(&mut client, &mut server).unwrap();
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Declined)
    );
    assert!(server.peer_certificates().is_none());
    assert_eq!(
        send_and_receive(&mut client, &mut server, b"anonymous"),
        b"anonymous"
    );
}

#[test]
fn post_handshake_auth_declined_when_mandatory_is_certificate_required() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        declining_client(&server_chain),
        pha_server(&server_chain, &client_chain, true, true),
    );
    handshake(&mut client, &mut server);
    assert_eq!(
        post_handshake_auth(&mut client, &mut server),
        Err(Error::NoCertificatesPresented)
    );
    transfer(&mut server, &mut client);
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::AlertReceived(AlertDescription::CertificateRequired)
    );
}

#[test]
fn post_handshake_auth_with_a_certificate_the_verifier_refuses() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let expected = client_chain(KeyType::EcdsaP256);
    let presented = client_chain(KeyType::Ed25519);
    let (mut client, mut server) = connect(
        pha_client(&server_chain, &presented),
        pha_server(&server_chain, &expected, true, true),
    );
    handshake(&mut client, &mut server);
    let err = post_handshake_auth(&mut client, &mut server).unwrap_err();
    assert!(
        matches!(err, Error::InvalidCertificate(_)),
        "unexpected error {err:?}"
    );
    assert!(server.peer_certificates().is_none());
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Requested)
    );
}

#[test]
fn post_handshake_auth_needs_the_client_offer() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    // A client with a certificate that did not enable it does not offer.
    let mut no_offer = pha_client(&server_chain, &client_chain);
    no_offer.enable_post_handshake_auth = false;
    let (mut client, mut server) = connect(
        no_offer,
        pha_server(&server_chain, &client_chain, false, true),
    );
    // The client did not offer, so authentication stays in the handshake.
    handshake(&mut client, &mut server);
    assert!(!server.post_handshake_auth_offered());
    assert_eq!(
        server.peer_certificates().unwrap(),
        client_chain.cert_chain()
    );
    assert!(server.request_client_auth().is_err());
    assert!(!server.wants_write());

    // Nor does a client with nothing to present.
    let mut no_certs = tls13_client(&server_chain);
    no_certs.enable_post_handshake_auth = true;
    let (mut client, mut server) = connect(
        no_certs,
        pha_server(&server_chain, &client_chain, false, true),
    );
    handshake(&mut client, &mut server);
    assert!(!server.post_handshake_auth_offered());
}

/// The server side of a finished TLS 1.3 connection, driven by the test:
/// its traffic keys are extracted so the test can send what a browntls
/// server never would.
struct ForgedServer {
    suite: &'static browntls::Tls13CipherSuite,
    /// The current `server_application_traffic_secret_N`.
    secret: Vec<u8>,
    encrypter: Box<dyn MessageEncrypter>,
    seq: u64,
}

/// Keeps the server's first application traffic secret.
#[derive(Debug, Default)]
struct ServerTrafficSecret(std::sync::Mutex<Option<Vec<u8>>>);

impl browntls::KeyLog for ServerTrafficSecret {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if label == "SERVER_TRAFFIC_SECRET_0" {
            *self.0.lock().unwrap() = Some(secret.to_vec());
        }
    }
}

/// HKDF-Expand-Label (RFC 9846 §7.1) with an empty context.
fn expand_label(
    suite: &browntls::Tls13CipherSuite,
    secret: &[u8],
    label: &[u8],
    len: usize,
) -> Vec<u8> {
    let expander = suite
        .hkdf_provider
        .expander_for_okm(&browntls::crypto::tls13::OkmBlock::new(secret));
    let out_len = u16::try_from(len).unwrap().to_be_bytes();
    let label_len = [u8::try_from(6 + label.len()).unwrap()];
    let mut out = vec![0u8; len];
    expander
        .expand_slice(&[&out_len, &label_len, b"tls13 ", label, &[0]], &mut out)
        .unwrap();
    out
}

impl ForgedServer {
    fn connect(client: ClientConfig, server_chain: &Chain) -> (ClientConnection, Self) {
        let key_log = Arc::new(ServerTrafficSecret::default());
        let mut server_config = server_config(server_chain);
        server_config.enable_secret_extraction = true;
        server_config.key_log = key_log.clone();
        let mut client = ClientConnection::new(Arc::new(client), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        handshake(&mut client, &mut server);
        let suite = client.negotiated_cipher_suite().unwrap().tls13().unwrap();
        let (seq, secrets) = server.dangerous_extract_secrets().unwrap().tx;
        let (key, iv) = match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv }
            | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
            | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (key, iv),
            _ => panic!("unexpected suite"),
        };
        let encrypter = suite.aead_alg.encrypter(key, iv);
        let secret = key_log.0.lock().unwrap().clone().unwrap();
        let forged = Self {
            suite,
            secret,
            encrypter,
            seq,
        };
        (client, forged)
    }

    /// A KeyUpdate (RFC 9846 §4.7.3) with `update_requested`; later records
    /// use the next traffic secret.
    fn key_update_requested(&mut self) -> Vec<u8> {
        let wire = self.record(ContentType::Handshake, &[24, 0, 0, 1, 1]);
        let suite = self.suite;
        let hash_len = suite.common.hash_provider.output_len();
        self.secret = expand_label(suite, &self.secret, b"traffic upd", hash_len);
        let key = expand_label(suite, &self.secret, b"key", suite.aead_alg.key_len());
        let iv: [u8; 12] = expand_label(suite, &self.secret, b"iv", 12)
            .try_into()
            .unwrap();
        self.encrypter = suite.aead_alg.encrypter(
            browntls::crypto::cipher::AeadKey::new(&key),
            browntls::crypto::cipher::Iv::new(iv),
        );
        self.seq = 0;
        wire
    }

    fn record(&mut self, typ: ContentType, payload: &[u8]) -> Vec<u8> {
        let msg = OutboundPlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let wire = self.encrypter.encrypt(msg, self.seq).unwrap().encode();
        self.seq += 1;
        wire
    }

    /// A CertificateRequest (RFC 9846 §4.4.2) with `context`, asking for
    /// ECDSA P-256 or Ed25519 signatures.
    fn certificate_request(&mut self, context: &[u8]) -> Vec<u8> {
        let mut body = vec![u8::try_from(context.len()).unwrap()];
        body.extend_from_slice(context);
        // extensions: signature_algorithms [ecdsa_secp256r1_sha256, ed25519]
        body.extend_from_slice(&[0, 10, 0, 13, 0, 6, 0, 4, 0x04, 0x03, 0x08, 0x07]);
        let mut message = vec![13, 0, 0, u8::try_from(body.len()).unwrap()];
        message.extend_from_slice(&body);
        self.record(ContentType::Handshake, &message)
    }
}

/// A client offering post-handshake authentication to a [`ForgedServer`]
/// with the returned chain.
fn forged_pha_client() -> (ClientConfig, Chain) {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let config = pha_client(&server_chain, &client_chain(KeyType::EcdsaP256));
    (config, server_chain)
}

#[test]
fn unsolicited_post_handshake_certificate_request_is_unexpected() {
    init_logging();
    let (mut config, chain) = forged_pha_client();
    config.enable_post_handshake_auth = false;
    let (mut client, mut server) = ForgedServer::connect(config, &chain);
    feed(&mut client, &server.certificate_request(&[1; 32]));
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::UnsolicitedPostHandshakeCertificateRequest)
    );
    assert_eq!(client.post_handshake_auth_responses(), 0);
}

#[test]
fn post_handshake_certificate_request_needs_a_context() {
    init_logging();
    let (config, chain) = forged_pha_client();
    let (mut client, mut server) = ForgedServer::connect(config, &chain);
    feed(&mut client, &server.certificate_request(&[]));
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::IllegalCertificateRequestContext)
    );
    assert_eq!(client.post_handshake_auth_responses(), 0);
}

#[test]
fn client_bounds_certificate_requests_without_application_data() {
    init_logging();
    let (config, chain) = forged_pha_client();
    let (mut client, mut server) = ForgedServer::connect(config, &chain);
    // Eight requests are answered, application data resets the count, and
    // eight more are answered too.
    for i in 0..8u8 {
        feed(&mut client, &server.certificate_request(&[i; 8]));
    }
    feed(
        &mut client,
        &server.record(ContentType::ApplicationData, b"data"),
    );
    for i in 8..16u8 {
        feed(&mut client, &server.certificate_request(&[i; 8]));
    }
    client.process_new_packets().unwrap();
    assert_eq!(client.post_handshake_auth_responses(), 16);
    let mut data = [0u8; 4];
    client.reader().read_exact(&mut data).unwrap();
    assert_eq!(&data, b"data");
    take_tls(&mut client);

    // A ninth request in a row is refused.
    feed(&mut client, &server.certificate_request(&[0xff; 8]));
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::TooManyPostHandshakeCertificateRequests)
    );
    assert_eq!(client.post_handshake_auth_responses(), 16);
}

#[test]
fn post_handshake_auth_is_refused_before_the_handshake_and_without_a_verifier() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let (mut client, mut server) = connect(
        pha_client(&server_chain, &client_chain),
        server_config(&server_chain),
    );
    assert_eq!(
        server.request_client_auth(),
        Err(Error::HandshakeNotComplete)
    );
    handshake(&mut client, &mut server);
    assert!(server.post_handshake_auth_offered());
    // `with_no_client_auth` offers no client authentication.
    assert!(server.request_client_auth().is_err());
    assert_eq!(server.post_handshake_auth_status(), None);
}

#[cfg(feature = "tls12")]
#[test]
fn post_handshake_auth_is_tls13_only() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    client_config.enable_post_handshake_auth = true;
    let (mut client, mut server) = connect(
        client_config,
        pha_server(&server_chain, &client_chain, false, true),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    // TLS 1.2 authenticated the client in the handshake.
    assert!(server.peer_certificates().is_some());
    assert!(server.request_client_auth().is_err());
}

// ------------------------------------------- post-handshake request budgets

#[test]
fn empty_application_data_does_not_renew_the_certificate_request_budget() {
    init_logging();
    let (config, chain) = forged_pha_client();
    let (mut client, mut server) = ForgedServer::connect(config, &chain);
    for i in 0..8u8 {
        feed(&mut client, &server.certificate_request(&[i; 8]));
        // RFC 9846 §5.1 allows zero-length application data records.
        feed(
            &mut client,
            &server.record(ContentType::ApplicationData, b""),
        );
        client.process_new_packets().unwrap();
        take_tls(&mut client);
    }
    assert_eq!(client.post_handshake_auth_responses(), 8);
    assert!(client.wants_read());

    feed(&mut client, &server.certificate_request(&[8; 8]));
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::TooManyPostHandshakeCertificateRequests)
    );
    assert_eq!(client.post_handshake_auth_responses(), 8);
}

#[test]
fn empty_application_data_does_not_renew_the_key_update_budget() {
    init_logging();
    let (config, chain) = forged_pha_client();
    let (mut client, mut server) = ForgedServer::connect(config, &chain);
    for _ in 0..8 {
        feed(&mut client, &server.key_update_requested());
        feed(
            &mut client,
            &server.record(ContentType::ApplicationData, b""),
        );
        client.process_new_packets().unwrap();
        take_tls(&mut client);
    }
    feed(&mut client, &server.key_update_requested());
    assert_eq!(
        client.process_new_packets().unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::TooManyKeyUpdateRequests)
    );
}

#[test]
fn application_data_renews_the_key_update_budget() {
    init_logging();
    let (config, chain) = forged_pha_client();
    let (mut client, mut server) = ForgedServer::connect(config, &chain);
    for _ in 0..16 {
        feed(&mut client, &server.key_update_requested());
        feed(
            &mut client,
            &server.record(ContentType::ApplicationData, b"x"),
        );
        client.process_new_packets().unwrap();
        let mut byte = [0u8; 1];
        client.reader().read_exact(&mut byte).unwrap();
        take_tls(&mut client);
    }
}
