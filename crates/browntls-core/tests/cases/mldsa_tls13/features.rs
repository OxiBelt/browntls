// Cases included by `cases/mldsa_tls13.rs`, which holds the imports and the
// shared helpers: ML-DSA authentication with the other TLS 1.3 features
// (HelloRetryRequest, resumption, post-handshake client authentication,
// certificate compression and raw public keys).

/// The first ClientHello carries no share for the only group the server
/// accepts, so the server answers with a HelloRetryRequest; the handshake
/// then completes with ML-DSA server authentication, and with ML-DSA
/// mutual authentication.
#[test]
fn hello_retry_request() {
    let server = server_id(Alg::Ml(Set::MlDsa65));
    let client = client_id(Alg::Ml(Set::MlDsa44));
    let groups = prov::provider_with_ml_dsa().kx_groups;
    let mut server_provider = prov::provider_with_ml_dsa();
    server_provider.kx_groups = vec![*groups.last().unwrap()];
    for client_id in [None, Some(&client)] {
        let server_verifier = server_verifier(prov::provider_with_ml_dsa(), &server);
        let client_verifier = client_verifier(prov::provider_with_ml_dsa(), &client, true);
        let (mut c, mut s) = connect(
            client_config(
                prov::provider_with_ml_dsa(),
                server_verifier.clone(),
                client_id,
            ),
            server_config(
                server_provider.clone(),
                &server,
                client_id.map(|_| client_verifier.clone() as Arc<dyn ClientCertVerifier>),
            ),
        );
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(
            c.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(server_verifier.seen(), [SignatureScheme::ML_DSA_65]);
        if client_id.is_some() {
            assert_eq!(client_verifier.seen(), [SignatureScheme::ML_DSA_44]);
            assert_eq!(s.peer_certificates().unwrap(), client.chain);
        }
        exchange(&mut c, &mut s);
    }
}

/// A full ML-DSA handshake with client authentication, then a PSK
/// resumption: no `CertificateVerify` the second time, and the server
/// still knows the client's chain (here two ML-DSA-87 certificates, about
/// 15 KB, which the ticket carries).
#[test]
fn resumption_after_ml_dsa_authentication() {
    let ml87 = Alg::Ml(Set::MlDsa87);
    let server = server_id(Alg::Ml(Set::MlDsa65));
    for client in [
        None,
        Some(identity(ml87, &[ml87, ml87], Purpose::Client, "resumption")),
    ] {
        let client = client.as_ref();
        let server_verifier = server_verifier(prov::provider_with_ml_dsa(), &server);
        // Without a client identity, a verifier that is never consulted.
        let client_verifier = client_verifier(
            prov::provider_with_ml_dsa(),
            client.unwrap_or(&server),
            true,
        );
        let client_config = Arc::new(client_config(
            prov::provider_with_ml_dsa(),
            server_verifier.clone(),
            client,
        ));
        let server_config = Arc::new(server_config(
            prov::provider_with_ml_dsa(),
            &server,
            client.map(|_| client_verifier.clone() as Arc<dyn ClientCertVerifier>),
        ));
        let mut c = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut s = ServerConnection::new(server_config.clone()).unwrap();
        handshake(&mut c, &mut s).unwrap();
        transfer(&mut s, &mut c);
        c.process_new_packets().unwrap();
        assert!(c.tls13_tickets_received() > 0);

        let mut c = ClientConnection::new(client_config, server_name()).unwrap();
        let mut s = ServerConnection::new(server_config).unwrap();
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(s.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(server_verifier.seen(), [SignatureScheme::ML_DSA_65]);
        if let Some(client) = client {
            assert_eq!(client_verifier.seen(), [SignatureScheme::ML_DSA_87]);
            assert_eq!(s.peer_certificates().unwrap(), client.chain);
        }
        exchange(&mut c, &mut s);
    }
}

/// Post-handshake client authentication (RFC 9846 §4.6.2) with an ML-DSA
/// client certificate, after a handshake without client authentication.
#[test]
fn post_handshake_auth_with_an_ml_dsa_client() {
    let server = server_id(Alg::P256);
    let client = client_id(Alg::Ml(Set::MlDsa65));
    let client_verifier = client_verifier(prov::provider_with_ml_dsa(), &client, true);
    let mut client_config = client_config(
        prov::provider_with_ml_dsa(),
        server_verifier(prov::provider_with_ml_dsa(), &server),
        Some(&client),
    );
    client_config.enable_post_handshake_auth = true;
    let mut server_config = server_config(
        prov::provider_with_ml_dsa(),
        &server,
        Some(client_verifier.clone()),
    );
    server_config.request_client_auth_after_handshake = true;
    let (mut c, mut s) = connect(client_config, server_config);
    handshake(&mut c, &mut s).unwrap();
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();
    assert!(s.peer_certificates().is_none());
    assert!(client_verifier.seen().is_empty());

    s.request_client_auth().unwrap();
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    assert_eq!(
        s.post_handshake_auth_status(),
        Some(browntls_core::server::PostHandshakeAuthStatus::Authenticated)
    );
    assert_eq!(client_verifier.seen(), [SignatureScheme::ML_DSA_65]);
    assert_eq!(s.peer_certificates().unwrap(), client.chain);
    exchange(&mut c, &mut s);
}

/// Certificate compression (RFC 8879) of ML-DSA chains in both directions:
/// each side decompresses the other's Certificate message once. ML-DSA
/// keys and signatures are high-entropy, so little is saved; the point is
/// that the large messages round-trip.
#[cfg(any(feature = "zlib", feature = "brotli", feature = "zstd"))]
#[test]
fn certificate_compression_of_ml_dsa_chains() {
    use browntls_core::compress::CertDecompressor;

    fn counting(list: &mut Vec<&'static dyn CertDecompressor>) -> Vec<&'static Counting> {
        let counters: Vec<&'static Counting> = list.iter().map(|d| Counting::new(*d)).collect();
        *list = counters
            .iter()
            .map(|c| *c as &'static dyn CertDecompressor)
            .collect();
        counters
    }

    let ml87 = Alg::Ml(Set::MlDsa87);
    let server = identity(ml87, &[ml87, ml87], Purpose::Server, "compression");
    let client = identity(
        Alg::Ml(Set::MlDsa44),
        &[ml87],
        Purpose::Client,
        "compression",
    );
    let server_verifier = server_verifier(prov::provider_with_ml_dsa(), &server);
    let client_verifier = client_verifier(prov::provider_with_ml_dsa(), &client, true);
    let mut client_config = client_config(
        prov::provider_with_ml_dsa(),
        server_verifier.clone(),
        Some(&client),
    );
    let mut server_config = server_config(
        prov::provider_with_ml_dsa(),
        &server,
        Some(client_verifier.clone()),
    );
    assert!(!client_config.cert_compressors.is_empty());
    assert!(!server_config.cert_compressors.is_empty());
    let client_counts = counting(&mut client_config.cert_decompressors);
    let server_counts = counting(&mut server_config.cert_decompressors);
    let (mut c, mut s) = connect(client_config, server_config);
    handshake(&mut c, &mut s).unwrap();
    let total = |counts: &[&Counting]| counts.iter().map(|c| c.calls()).sum::<usize>();
    assert_eq!(total(&client_counts), 1);
    assert_eq!(total(&server_counts), 1);
    assert_eq!(server_verifier.seen(), [SignatureScheme::ML_DSA_87]);
    assert_eq!(client_verifier.seen(), [SignatureScheme::ML_DSA_44]);
    assert_eq!(c.peer_certificates().unwrap(), server.chain);
    assert_eq!(s.peer_certificates().unwrap(), client.chain);
    exchange(&mut c, &mut s);
}

/// The RFC 9881 `SubjectPublicKeyInfo` of `id`'s ML-DSA key, as the loaded
/// key reports it and as the certificate builder encodes it.
fn ml_dsa_spki(id: &Identity) -> CertificateDer<'static> {
    let key = id.signing_key(&prov::provider_with_ml_dsa());
    let spki = key.public_key().unwrap().as_ref().to_vec();
    assert_eq!(spki, x509::spki_of(&id.ml.as_ref().unwrap().oracle));
    CertificateDer::from(spki)
}

/// RFC 7250 raw public keys: an ML-DSA `SubjectPublicKeyInfo` as the
/// server's raw public key, then as both sides' raw public keys.
#[test]
fn raw_public_keys() {
    let server = server_id(Alg::Ml(Set::MlDsa65));
    let client = client_id(Alg::Ml(Set::MlDsa87));
    let algs = prov::provider_with_ml_dsa().signature_verification_algorithms;
    for mutual in [false, true] {
        let server_spki = ml_dsa_spki(&server);
        let server_verifier = SchemeRecordingServerVerifier::new(
            Arc::new(common::PinnedServerVerifier {
                expected: server_spki.clone(),
                spki: server_spki.as_ref().to_vec().into(),
                algs,
                raw: true,
            }),
            &algs.supported_schemes(),
        );
        let client_spki = ml_dsa_spki(&client);
        let client_verifier = SchemeRecordingClientVerifier::new(
            Arc::new(common::PinnedClientVerifier {
                expected: client_spki.clone(),
                spki: client_spki.as_ref().to_vec().into(),
                algs,
                mandatory: true,
                hints: Vec::new(),
                raw: true,
            }),
            &algs.supported_schemes(),
        );
        let raw_key = |id: &Identity, spki: CertificateDer<'static>| {
            Arc::new(common::RawKeyResolver(Arc::new(CertifiedKey::new(
                vec![spki],
                id.signing_key(&prov::provider_with_ml_dsa()),
            ))))
        };
        let builder = ClientConfig::builder_with_provider(arc(prov::provider_with_ml_dsa()))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier.clone());
        let client_config = match mutual {
            true => builder.with_client_cert_resolver(raw_key(&client, client_spki.clone())),
            false => builder.with_no_client_auth(),
        };
        let builder = ServerConfig::builder_with_provider(arc(prov::provider_with_ml_dsa()))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap();
        let server_config = match mutual {
            true => builder.with_client_cert_verifier(client_verifier.clone()),
            false => builder.with_no_client_auth(),
        }
        .with_cert_resolver(raw_key(&server, server_spki.clone()));
        let (mut c, mut s) = connect(client_config, server_config);
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(server_verifier.seen(), [SignatureScheme::ML_DSA_65]);
        assert_eq!(c.peer_certificates().unwrap(), [server_spki]);
        if mutual {
            assert_eq!(client_verifier.seen(), [SignatureScheme::ML_DSA_87]);
            assert_eq!(s.peer_certificates().unwrap(), [client_spki]);
        }
        exchange(&mut c, &mut s);
    }
}
