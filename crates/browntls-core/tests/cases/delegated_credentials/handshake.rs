// Cases included by `cases/delegated_credentials.rs`, which holds the imports
// and the shared helpers: handshakes with a delegated credential, the
// credentials either side refuses and the wire format.

#[test]
fn handshake_with_delegated_credential() {
    init_logging();
    for &cert_type in KeyType::SIGNING {
        let chain = delegation_server_chain(cert_type);
        for dc_scheme in [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ] {
            let (dc, key) = issue(&chain, dc_scheme, shifted(24 * 3600));
            let ck = certified_key(&chain)
                .with_delegated_credential(dc.clone(), key)
                .unwrap();
            let verifier = SchemeRecordingServerVerifier::new(
                PinnedServerVerifier::new(&chain),
                &prov::SUPPORTED_SIG_ALGS.supported_schemes(),
            );
            let mut client_config = client_config(&chain);
            client_config.enable_delegated_credentials = true;
            client_config
                .dangerous()
                .set_certificate_verifier(verifier.clone());
            let (mut client, mut server) = connect(client_config, server_with(ck));
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
            assert_eq!(
                client.delegated_credential(),
                Some(&dc),
                "{cert_type:?} {dc_scheme:?}"
            );
            // The credential's signature (certificate key), then
            // CertificateVerify (credential key).
            assert_eq!(verifier.seen(), [dc.algorithm, dc_scheme]);
            assert_eq!(client.peer_certificates().unwrap()[0], chain.end_entity);
            assert_eq!(
                send_and_receive(&mut client, &mut server, b"hello"),
                b"hello"
            );
            assert_eq!(
                send_and_receive(&mut server, &mut client, b"world"),
                b"world"
            );
        }
    }
}

#[test]
fn not_used_unless_both_sides_opt_in() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, shifted(3600));
    let ck = certified_key(&chain)
        .with_delegated_credential(dc, key)
        .unwrap();

    // The client did not offer the extension: the certificate key signs.
    let (mut client, mut server) = connect(client_config(&chain), server_with(ck.clone()));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.delegated_credential().is_none());

    // The server has no credential.
    let (mut client, mut server) = connect(dc_client(&chain), server_with(certified_key(&chain)));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.delegated_credential().is_none());

    // TLS 1.2: delegated credentials are TLS 1.3 only.
    #[cfg(feature = "tls12")]
    {
        let server = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&browntls_core::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(ck.clone())));
        let (mut client, mut server) = connect(dc_client(&chain), server);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
        assert!(client.delegated_credential().is_none());
    }

    // The client accepts no scheme the credential uses: the server falls
    // back to its certificate key.
    let mut client_config = client_config(&chain);
    client_config.enable_delegated_credentials = true;
    client_config
        .dangerous()
        .set_certificate_verifier(SchemeRecordingServerVerifier::new(
            PinnedServerVerifier::new(&chain),
            &[SignatureScheme::ECDSA_NISTP256_SHA256],
        ));
    let (mut client, mut server) = connect(client_config, server_with(ck));
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client.delegated_credential().is_none());
}

#[test]
fn server_skips_unusable_credentials() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    // Expired, then valid for too long, then a good one.
    let (expired, k1) = issue(&chain, SignatureScheme::ED25519, shifted(-60));
    let (too_long, k2) = issue(
        &chain,
        SignatureScheme::ED25519,
        shifted(MAX_VALIDITY.as_secs() as i64 + 3600),
    );
    let (good, k3) = issue(
        &chain,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        shifted(3600),
    );
    let ck = certified_key(&chain)
        .with_delegated_credential(expired, k1)
        .unwrap()
        .with_delegated_credential(too_long, k2)
        .unwrap()
        .with_delegated_credential(good.clone(), k3)
        .unwrap();
    let (mut client, mut server) = connect(dc_client(&chain), server_with(ck));
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.delegated_credential(), Some(&good));
}

/// A server whose clock is `skew` seconds off sends a credential the client
/// rejects.
fn rejected_by_client(
    expiry: UnixTime,
    server_skew: i64,
) -> (Result<(), Error>, Result<(), Error>) {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (dc, key) = issue(&chain, SignatureScheme::ED25519, expiry);
    let ck = certified_key(&chain)
        .with_delegated_credential(dc, key)
        .unwrap();
    let mut server = server_with(ck);
    server.time_provider = Arc::new(FixedTime(shifted(server_skew)));
    let (mut client, mut server) = connect(dc_client(&chain), server);
    do_handshake_until_error(&mut client, &mut server)
}

#[test]
fn expired_credential_is_illegal_parameter() {
    let (client, server) = rejected_by_client(shifted(-3600), -2 * 3600);
    assert_eq!(
        client,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialExpired
        ))
    );
    assert_eq!(
        server,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn credential_valid_too_long_is_illegal_parameter() {
    let week = MAX_VALIDITY.as_secs() as i64;
    let (client, server) = rejected_by_client(shifted(week + 3600), 2 * 3600);
    assert_eq!(
        client,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialValidityTooLong
        ))
    );
    assert_eq!(
        server,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn tampered_credential_is_illegal_parameter() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (mut dc, key) = issue(&chain, SignatureScheme::ED25519, shifted(3600));
    // Moving the expiry by a second invalidates the signature.
    dc.credential.valid_time -= 1;
    let ck = certified_key(&chain)
        .with_delegated_credential(dc, key)
        .unwrap();
    let (mut client, mut server) = connect(dc_client(&chain), server_with(ck));
    let (client, server) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        client,
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialBadSignature
        ))
    );
    assert_eq!(
        server,
        Err(Error::AlertReceived(AlertDescription::IllegalParameter))
    );
}

#[test]
fn credential_key_must_match() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let (dc, _) = issue(
        &chain,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        shifted(3600),
    );
    let (other_key, _) = dc_key(&rcgen::PKCS_ECDSA_P256_SHA256);
    assert!(
        certified_key(&chain)
            .with_delegated_credential(dc.clone(), other_key)
            .is_err()
    );
    // A key that cannot sign with the credential's scheme.
    let (ed_key, _) = dc_key(&rcgen::PKCS_ED25519);
    assert!(
        certified_key(&chain)
            .with_delegated_credential(dc, ed_key)
            .is_err()
    );
}

#[test]
fn certificate_must_permit_delegation() {
    // Without the DelegationUsage extension, no credential can be issued or
    // attached.
    let chain = server_chain(KeyType::EcdsaP256);
    let (_, spki) = dc_key(&rcgen::PKCS_ED25519);
    let cert_key = provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    let credential = Credential {
        valid_time: valid_time_until(&chain.end_entity, shifted(3600)).unwrap(),
        dc_cert_verify_algorithm: SignatureScheme::ED25519,
        public_key: spki,
    };
    assert!(
        DelegatedCredential::issue(
            Side::Server,
            &chain.end_entity,
            &*cert_key,
            chain.key_type.schemes(),
            credential.clone(),
        )
        .is_err()
    );
    // Nor attached to its certificate.
    let delegation = delegation_server_chain(KeyType::EcdsaP256);
    let (dc, key) = issue(&delegation, SignatureScheme::ED25519, shifted(3600));
    assert!(
        certified_key(&chain)
            .with_delegated_credential(dc, key)
            .is_err()
    );
}

#[test]
fn wire_round_trip() {
    let chain = delegation_server_chain(KeyType::Ed25519);
    let (dc, _) = issue(
        &chain,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        shifted(3600),
    );
    let bytes = dc.to_bytes();
    assert_eq!(DelegatedCredential::from_bytes(&bytes).unwrap(), dc);
    let expiry = dc.expiry(&chain.end_entity).unwrap().as_secs();
    assert!(expiry.abs_diff(shifted(3600).as_secs()) <= 1);
}

/// Records the secrets a connection derives.
#[derive(Debug, Default)]
struct SecretLog(std::sync::Mutex<Vec<(String, Vec<u8>)>>);

impl browntls_core::KeyLog for SecretLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.to_string(), secret.to_vec()));
    }
}

/// HKDF-Expand-Label with an empty context (RFC 9846 §7.1).
fn expand_label<T: From<[u8; N]>, const N: usize>(
    expander: &dyn browntls_core::crypto::tls13::HkdfExpander,
    label: &[u8],
    len: u16,
) -> T {
    let label_len = [u8::try_from(6 + label.len()).unwrap()];
    browntls_core::crypto::tls13::expand(
        expander,
        &[&len.to_be_bytes(), &label_len, b"tls13 ", label, &[0]],
    )
}

/// The record key and IV of a TLS 1.3 traffic secret (RFC 9846 §7.3).
fn traffic_key_iv(
    suite: &browntls_core::Tls13CipherSuite,
    secret: &[u8],
) -> (
    browntls_core::crypto::cipher::AeadKey,
    browntls_core::crypto::cipher::Iv,
) {
    let expander = suite
        .hkdf_provider
        .expander_for_okm(&browntls_core::crypto::tls13::OkmBlock::new(secret));
    let key_len = suite.aead_alg.key_len();
    let key: browntls_core::crypto::cipher::AeadKey =
        expand_label(&*expander, b"key", u16::try_from(key_len).unwrap());
    (
        key.with_length(key_len),
        expand_label(&*expander, b"iv", 12),
    )
}

/// Hands the server of `server_config` (serving `server_chain`) a client
/// Certificate made of `entries`, each a certificate and the delegated
/// credential on its entry, instead of the client's own flight: the
/// server's flight is dropped and the Certificate is encrypted under the
/// client handshake traffic key. Returns the server's error and the
/// plaintext of the alert it then sends.
fn hand_made_client_certificate(
    server_chain: &Chain,
    mut server_config: ServerConfig,
    entries: &[(&[u8], Option<&DelegatedCredential>)],
) -> (Error, Vec<u8>) {
    let log = Arc::new(SecretLog::default());
    server_config.key_log = log.clone();
    let (mut client, mut server) = connect(client_config(server_chain), server_config);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    // The server's flight is dropped: the client never answers it.
    while server.wants_write() {
        server.write_tls(&mut std::io::sink()).unwrap();
    }

    let u24 = |len: usize| u32::try_from(len).unwrap().to_be_bytes()[1..].to_vec();
    let u16 = |len: usize| u16::try_from(len).unwrap().to_be_bytes().to_vec();
    let mut list = Vec::new();
    for (cert, dc) in entries {
        let mut extensions = Vec::new();
        if let Some(dc) = dc {
            let dc = dc.to_bytes();
            extensions.extend([0x00, 0x22]);
            extensions.extend(u16(dc.len()));
            extensions.extend(&dc);
        }
        list.extend(u24(cert.len()));
        list.extend(*cert);
        list.extend(u16(extensions.len()));
        list.extend(&extensions);
    }
    let mut body = vec![0]; // empty certificate_request_context
    body.extend(u24(list.len()));
    body.extend(&list);
    let mut message = vec![11]; // Certificate
    message.extend(u24(body.len()));
    message.extend(&body);

    let suite = server.negotiated_cipher_suite().unwrap().tls13().unwrap();
    let secret = |name: &str| {
        log.0
            .lock()
            .unwrap()
            .iter()
            .find(|(label, _)| label == name)
            .unwrap()
            .1
            .clone()
    };
    let (key, iv) = traffic_key_iv(suite, &secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET"));
    let record = suite
        .aead_alg
        .encrypter(key, iv)
        .encrypt(
            browntls_core::crypto::cipher::OutboundPlainMessage {
                typ: browntls_core::ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: browntls_core::crypto::cipher::OutboundChunks::Single(&message),
            },
            0,
        )
        .unwrap()
        .encode();

    server.read_tls(&mut &record[..]).unwrap();
    let error = server.process_new_packets().unwrap_err();

    // After its Finished the server writes with its first application
    // traffic key, from sequence number 0.
    let mut alert = Vec::new();
    server.write_tls(&mut alert).unwrap();
    let (key, iv) = traffic_key_iv(suite, &secret("SERVER_TRAFFIC_SECRET_0"));
    assert_eq!(alert[0], 0x17);
    let plain = suite
        .aead_alg
        .decrypter(key, iv)
        .decrypt(
            browntls_core::crypto::cipher::InboundOpaqueMessage::new(
                browntls_core::ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut alert[5..],
            ),
            0,
        )
        .unwrap();
    assert_eq!(plain.typ, browntls_core::ContentType::Alert);
    (error, plain.payload.to_vec())
}

/// A server that did not ask for client delegated credentials
/// (`ServerConfig::enable_delegated_credentials` is off) answers a client
/// Certificate entry carrying one with `unexpected_message` (RFC 9345
/// §4.1.2).
#[test]
fn server_rejects_a_client_credential() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = delegation_server_chain(KeyType::EcdsaP256);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&browntls_core::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
        .unwrap();
    let (_, spki) = dc_key(&rcgen::PKCS_ED25519);
    let dc = DelegatedCredential {
        credential: Credential {
            valid_time: 3600,
            dc_cert_verify_algorithm: SignatureScheme::ED25519,
            public_key: spki,
        },
        algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
        signature: vec![1; 64],
    };
    let (error, alert) = hand_made_client_certificate(
        &server_chain,
        server_config,
        &[(client_chain.end_entity.as_ref(), Some(&dc))],
    );
    assert_eq!(
        error,
        Error::PeerMisbehaved(PeerMisbehaved::UnsolicitedDelegatedCredential)
    );
    assert_eq!(alert, [2, u8::from(AlertDescription::UnexpectedMessage)]);
}
