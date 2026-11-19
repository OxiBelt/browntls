// Cases included by `cases/interop.rs`, which holds the imports, the
// plumbing and the configurations: ALPN, KeyUpdate, large transfers,
// closure, the exporter, 0-RTT data, raw public keys and the optional
// ClientHello extensions.

// ----------------------------------------------------------- post-handshake

#[test]
fn alpn_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for version in VERSIONS {
        let mut cc = b_client(&chain, version, None, None);
        cc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut sc = r_server(&chain, version, None, None);
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut client = b_connect_client(cc);
        let mut server = rustls::ServerConnection::new(Arc::new(sc)).unwrap();
        handshake_ok(&mut client, &mut server);
        assert_eq!(client.alpn(), Some(b"http/1.1".to_vec()));
        assert_eq!(server.alpn(), Some(b"http/1.1".to_vec()));

        let mut cc = r_client(&chain, version, None, None);
        cc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut sc = b_server(&chain, version, None, None);
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut client = r_connect_client(cc);
        let mut server = browntls_core::ServerConnection::new(Arc::new(sc)).unwrap();
        handshake_ok(&mut client, &mut server);
        assert_eq!(client.alpn(), Some(b"http/1.1".to_vec()));
        assert_eq!(server.alpn(), Some(b"http/1.1".to_vec()));
    }
}

#[test]
fn key_update_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);

    let mut client = b_connect_client(b_client(&chain, 0x0304, None, None));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, None))).unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(client.refresh_keys());
    round_trip(&mut client, &mut server);
    assert!(server.refresh_keys());
    round_trip(&mut client, &mut server);

    let mut client = r_connect_client(r_client(&chain, 0x0304, None, None));
    let mut server =
        browntls_core::ServerConnection::new(Arc::new(b_server(&chain, 0x0304, None, None)))
            .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(client.refresh_keys());
    round_trip(&mut client, &mut server);
    assert!(server.refresh_keys());
    round_trip(&mut client, &mut server);
}

#[test]
fn large_transfers_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    for version in VERSIONS {
        let mut client = b_connect_client(b_client(&chain, version, None, None));
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        handshake_ok(&mut client, &mut server);
        client.set_unlimited_buffer();
        server.set_unlimited_buffer();
        assert_eq!(exchange(&mut client, &mut server, &data), data);
        assert_eq!(exchange(&mut server, &mut client, &data), data);

        let mut client = r_connect_client(r_client(&chain, version, None, None));
        let mut server =
            browntls_core::ServerConnection::new(Arc::new(b_server(&chain, version, None, None)))
                .unwrap();
        handshake_ok(&mut client, &mut server);
        client.set_unlimited_buffer();
        server.set_unlimited_buffer();
        assert_eq!(exchange(&mut client, &mut server, &data), data);
        assert_eq!(exchange(&mut server, &mut client, &data), data);
    }
}

#[test]
fn close_notify_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for version in VERSIONS {
        let mut client = b_connect_client(b_client(&chain, version, None, None));
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        handshake_ok(&mut client, &mut server);
        client.send_close();
        transfer(&mut client, &mut server);
        assert_eq!(server.process(), Ok(true));

        let mut client = r_connect_client(r_client(&chain, version, None, None));
        let mut server =
            browntls_core::ServerConnection::new(Arc::new(b_server(&chain, version, None, None)))
                .unwrap();
        handshake_ok(&mut client, &mut server);
        server.send_close();
        transfer(&mut server, &mut client);
        assert_eq!(client.process(), Ok(true));
    }
}

#[test]
fn exporter_matches_rustls() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for version in VERSIONS {
        let mut client = b_connect_client(b_client(&chain, version, None, None));
        let mut server =
            rustls::ServerConnection::new(Arc::new(r_server(&chain, version, None, None))).unwrap();
        handshake_ok(&mut client, &mut server);
        let c = client
            .export_keying_material([0u8; 48], b"EXPORTER-interop", Some(b"ctx"))
            .unwrap();
        let s = server
            .export_keying_material([0u8; 48], b"EXPORTER-interop", Some(b"ctx"))
            .unwrap();
        assert_eq!(c, s, "{version:#06x}");
        let c = client
            .export_keying_material([0u8; 48], b"EXPORTER-interop", None)
            .unwrap();
        let s = server
            .export_keying_material([0u8; 48], b"EXPORTER-interop", None)
            .unwrap();
        assert_eq!(c, s, "{version:#06x} (no context)");
    }
}

// ------------------------------------------------------------------ 0-RTT

#[test]
fn early_data_browntls_client_rustls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut cc = b_client(&chain, 0x0304, None, None);
    cc.enable_early_data = true;
    let client_config = Arc::new(cc);
    let mut sc = r_server(&chain, 0x0304, None, None);
    sc.max_early_data_size = 1024;
    let server_config = Arc::new(sc);

    let mut client =
        browntls_core::ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = rustls::ServerConnection::new(server_config.clone()).unwrap();
    handshake_ok(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process().unwrap();

    // accepted
    let mut client =
        browntls_core::ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"early to rustls")
        .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(client.is_early_data_accepted());
    let mut got = Vec::new();
    server.early_data().unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"early to rustls");
    round_trip(&mut client, &mut server);

    // rejected: the rustls server no longer allows early data
    let mut client = browntls_core::ClientConnection::new(client_config, server_name()).unwrap();
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, None))).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"discarded")
        .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
    round_trip(&mut client, &mut server);
}

#[test]
fn early_data_rustls_client_browntls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut cc = r_client(&chain, 0x0304, None, None);
    cc.enable_early_data = true;
    let client_config = Arc::new(cc);
    let mut sc = b_server(&chain, 0x0304, None, None);
    sc.max_early_data_size = 1024;
    let cache = sc.session_storage.clone();
    let server_config = Arc::new(sc);

    let mut client = r_connect_client_from(client_config.clone());
    let mut server = browntls_core::ServerConnection::new(server_config.clone()).unwrap();
    handshake_ok(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process().unwrap();

    // accepted
    let mut client = r_connect_client_from(client_config.clone());
    let mut server = browntls_core::ServerConnection::new(server_config).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"early to browntls")
        .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(client.is_early_data_accepted());
    let mut got = Vec::new();
    server.early_data().unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"early to browntls");
    round_trip(&mut client, &mut server);

    // rejected: same sessions, early data switched off
    let mut sc = b_server(&chain, 0x0304, None, None);
    sc.session_storage = cache;
    let mut client = r_connect_client_from(client_config);
    let mut server = browntls_core::ServerConnection::new(Arc::new(sc)).unwrap();
    client
        .early_data()
        .unwrap()
        .write_all(b"discarded")
        .unwrap();
    handshake_ok(&mut client, &mut server);
    assert!(!client.is_early_data_accepted());
    assert!(server.early_data().is_none());
    assert_eq!(
        server.handshake_kind(),
        Some(browntls_core::HandshakeKind::Resumed)
    );
    round_trip(&mut client, &mut server);
}

// ---------------------------------------------------------- raw public keys

/// A rustls verifier pinning one RFC 7250 raw public key.
#[derive(Debug)]
struct RustlsRawKeyVerifier {
    spki: Vec<u8>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for RustlsRawKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rpki::CertificateDer<'_>,
        _intermediates: &[rpki::CertificateDer<'_>],
        _server_name: &rpki::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rpki::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.spki {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rpki::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "raw keys are TLS 1.3 only here".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &rpki::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &rpki::SubjectPublicKeyInfoDer::from(self.spki.as_slice()),
            dss,
            &self.algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// A rustls resolver serving one raw public key.
#[derive(Debug)]
struct RustlsRawKeyResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for RustlsRawKeyResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

fn rustls_raw_key(chain: &Chain) -> Arc<rustls::sign::CertifiedKey> {
    let key = ring_provider::sign::any_supported_type(&r_key(chain)).unwrap();
    Arc::new(rustls::sign::CertifiedKey::new(
        vec![rpki::CertificateDer::from(chain.end_entity_spki.clone())],
        key,
    ))
}

#[test]
fn raw_public_keys_both_directions() {
    init_logging();
    for &key_type in KeyType::SIGNING {
        let chain = server_chain(key_type);
        let spki = rpki::CertificateDer::from(chain.end_entity_spki.clone());

        // browntls client, rustls raw-key server
        let server_config = rustls::ServerConfig::builder_with_provider(r_provider(None, None))
            .with_protocol_versions(r_versions(0x0304))
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RustlsRawKeyResolver(rustls_raw_key(&chain))));
        let client_config =
            browntls_core::ClientConfig::builder_with_provider(b_provider(None, None))
                .with_protocol_versions(b_versions(0x0304))
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::raw_public_key(&chain))
                .with_no_client_auth();
        let mut client = b_connect_client(client_config);
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        handshake_ok(&mut client, &mut server);
        assert_eq!(client.peer_certs().unwrap(), [spki.as_ref().to_vec()]);
        round_trip(&mut client, &mut server);

        // rustls client, browntls raw-key server
        let client_config = rustls::ClientConfig::builder_with_provider(r_provider(None, None))
            .with_protocol_versions(r_versions(0x0304))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RustlsRawKeyVerifier {
                spki: chain.end_entity_spki.clone(),
                algs: ring_provider::default_provider().signature_verification_algorithms,
            }))
            .with_no_client_auth();
        let server_config =
            browntls_core::ServerConfig::builder_with_provider(b_provider(None, None))
                .with_protocol_versions(b_versions(0x0304))
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(RawKeyResolver::new(&chain));
        let mut client = r_connect_client(client_config);
        let mut server = browntls_core::ServerConnection::new(Arc::new(server_config)).unwrap();
        handshake_ok(&mut client, &mut server);
        assert_eq!(client.peer_certs().unwrap(), [spki.as_ref().to_vec()]);
        round_trip(&mut client, &mut server);
    }
}

/// Turns on every optional ClientHello extension of a browntls client:
/// GREASE (RFC 8701), a small `record_size_limit` (RFC 8449), which rustls
/// does not implement and ignores, `ticket_request` (RFC 9149) and padding
/// (RFC 7685).
fn with_optional_extensions(
    mut config: browntls_core::ClientConfig,
) -> browntls_core::ClientConfig {
    config.enable_grease = true;
    config.record_size_limit = Some(64);
    config.tls13_ticket_request = Some(browntls_core::client::TicketRequest {
        new_session_count: 1,
        resumption_count: 1,
    });
    config.client_hello_padding = browntls_core::client::ClientHelloPadding::AtLeast(600);
    config
}

#[test]
fn browntls_client_with_grease_and_optional_extensions_to_rustls_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let versions: &[u16] = if cfg!(feature = "tls12") {
        &[0x0304, 0x0303]
    } else {
        &[0x0304]
    };
    for &version in versions {
        // Full handshake, then a resumption with the same configuration
        // (GREASE in psk_key_exchange_modes, padding before pre_shared_key).
        let client_config = Arc::new(with_optional_extensions(b_client(
            &chain, version, None, None,
        )));
        let server_config = Arc::new(r_server(&chain, version, None, None));
        for resumed in [false, true] {
            let mut client =
                browntls_core::ClientConnection::new(client_config.clone(), server_name()).unwrap();
            let mut server = rustls::ServerConnection::new(server_config.clone()).unwrap();
            handshake_ok(&mut client, &mut server);
            assert_eq!(client.version(), Some(version));
            assert_eq!(Tls::resumed(&client), resumed, "version {version:#06x}");
            round_trip(&mut client, &mut server);
            let big = vec![0x5a; 40_000];
            assert_eq!(exchange(&mut client, &mut server, &big), big);
            assert_eq!(exchange(&mut server, &mut client, &big), big);
        }
    }

    // A HelloRetryRequest: the client's first key share is for P-384, which
    // this rustls server does not take; the second ClientHello repeats the
    // GREASE values but carries only the requested key share.
    let mut provider = prov::default_provider();
    provider.kx_groups.retain(|g| {
        matches!(
            g.name(),
            browntls_core::NamedGroup::secp384r1 | browntls_core::NamedGroup::X25519
        )
    });
    provider
        .kx_groups
        .sort_by_key(|g| g.name() != browntls_core::NamedGroup::secp384r1);
    let client_config = browntls_core::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(b_versions(0x0304))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut client = b_connect_client(with_optional_extensions(client_config));
    let mut server =
        rustls::ServerConnection::new(Arc::new(r_server(&chain, 0x0304, None, Some(0x001d))))
            .unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(
        client.handshake_kind(),
        Some(browntls_core::HandshakeKind::FullWithHelloRetryRequest)
    );
    round_trip(&mut client, &mut server);
}
