// Included inside resumption_cases; no synthetic peer messages.

#[test]
fn every_ecdhe_aead_suite_resumes_mutually_authenticated_sessions() {
    for suite in provider()
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| s.version() == &version::TLS12 && !s.is_tls12_block_cipher())
    {
        let key_type =
            if suite.usable_for_signature_algorithm(browntls_core::SignatureAlgorithm::ECDSA) {
                KeyType::EcdsaP256
            } else if prov::SIGNS_RSA {
                KeyType::Rsa2048
            } else {
                continue;
            };
        let server_chain = server_chain(key_type);
        let client_chain = client_chain(KeyType::EcdsaP256);
        let mut p = (*provider()).clone();
        p.cipher_suites = vec![suite];
        let client = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(p.clone()))
                .with_protocol_versions(&[&version::TLS12])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
                .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
                .unwrap(),
        );
        let mut server = ServerConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap();
        server.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
        server.enable_dtls12_resumption().unwrap();
        for tickets in [false, true] {
            if tickets {
                server.dtls12_ticketer = prov::Ticketer::new().unwrap();
                server.session_storage = Arc::new(NoServerSessionStorage {});
            }
            let mut client = (*client).clone();
            client.resumption = Resumption::in_memory_sessions(16);
            let client = Arc::new(client);
            let server = Arc::new(server.clone());
            for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
                let mut pair = pair(&client, &server);
                pair.client.set_mtu(300).unwrap();
                pair.server.set_mtu(300).unwrap();
                let mut sim = Sim::perfect();
                pair.handshake(&mut sim)
                    .unwrap_or_else(|e| panic!("{suite:?}, {tickets}: {e:?}"));
                kind(&pair, expected);
                assert_eq!(
                    pair.client.peer_certificates().unwrap(),
                    server_chain.cert_chain()
                );
                assert_eq!(
                    pair.server.peer_certificates().unwrap(),
                    client_chain.cert_chain()
                );
                pair.exchange(&mut sim, "resumed mutual certificates");
            }
        }
    }
}

#[test]
fn new_required_client_auth_policy_rejects_old_unauthenticated_sessions() {
    for tickets in [false, true] {
        let (client, server, _) = configs(tickets);
        prime(&client, &server);
        let server_chain = server_chain(KeyType::EcdsaP256);
        let client_chain = client_chain(KeyType::EcdsaP256);
        let mut required = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap();
        required.cert_resolver = server.cert_resolver.clone();
        required.session_storage = server.session_storage.clone();
        required.hello_retry_cookies = server.hello_retry_cookies.clone();
        required.dtls12_ticketer = server.dtls12_ticketer.clone();
        required.enable_dtls12_resumption().unwrap();
        let mut attempted = pair(&client, &Arc::new(required));
        assert!(matches!(
            attempted.handshake(&mut Sim::perfect()),
            Err(Failure::Server(_))
        ));
        assert_eq!(attempted.server.handshake_kind(), Some(HandshakeKind::Full));
        assert!(attempted.server.is_handshaking());
    }
}

#[test]
fn external_authentication_binding_keeps_full_handshakes_and_no_cached_state() {
    use browntls_core::external_binding::{ExternalBinding, ExternalIdHash};
    let (client, server, store) = configs(true);
    let mut c = (*client).clone();
    let mut s = (*server).clone();
    let hash = ExternalIdHash::from_sha256([7; 32]);
    c.external_binding = Some(ExternalBinding {
        id_hash: Some(hash),
        peer_id_hash: Some(hash),
        require_peer_support: true,
        ..Default::default()
    });
    s.external_binding = c.external_binding.clone();
    let c = Arc::new(c);
    let s = Arc::new(s);
    for _ in 0..2 {
        let mut bound = pair(&c, &s);
        bound.handshake(&mut Sim::perfect()).unwrap();
        kind(&bound, HandshakeKind::Full);
        assert!(store.dtls12_session(&server_name()).is_none());
    }
}

#[test]
fn client_final_flight_is_retained_after_immediate_close_on_resumption() {
    for tickets in [false, true] {
        let (client, server, _) = configs(tickets);
        prime(&client, &server);
        let mut pair = pair(&client, &server);
        let mut sim = Sim::perfect();
        // Stop as soon as the client verifies the server's Finished, before
        // transmitting the client's final CCS/Finished flight.
        for _ in 0..20 {
            let mut out = Vec::new();
            while pair.client.write_datagram(&mut out, sim.now).unwrap() {
                pair.server.read_datagram(&mut out, sim.now).unwrap();
                out.clear();
            }
            while pair.server.write_datagram(&mut out, sim.now).unwrap() {
                pair.client.read_datagram(&mut out, sim.now).unwrap();
                out.clear();
            }
            if !pair.client.is_handshaking() {
                break;
            }
        }
        assert!(!pair.client.is_handshaking());
        assert!(pair.server.is_handshaking());
        pair.client.send_close_notify();
        let mut lose_first = true;
        sim.to_server = Link::new(move |_, _| {
            if core::mem::take(&mut lose_first) {
                Fate::Drop
            } else {
                Fate::Deliver
            }
        });
        pair.handshake(&mut sim).unwrap();
        kind(&pair, HandshakeKind::Resumed);
        assert!(sim.now > Duration::from_secs(1000));
        // The retained client flight completed the server before closure.
        assert!(pair.server.peer_has_closed());
    }
}

#[test]
fn ticket_cookie_validation_precedes_decryption() {
    use browntls_core::server::ProducesTickets;
    #[derive(Debug)]
    struct CountedTickets {
        inner: Arc<dyn ProducesTickets>,
        decrypts: AtomicUsize,
    }
    impl ProducesTickets for CountedTickets {
        fn enabled(&self) -> bool {
            self.inner.enabled()
        }
        fn lifetime(&self) -> u32 {
            self.inner.lifetime()
        }
        fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
            self.inner.encrypt(plain)
        }
        fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
            self.decrypts.fetch_add(1, Ordering::SeqCst);
            self.inner.decrypt(cipher)
        }
    }
    let (client, server, _) = configs(true);
    let tickets = Arc::new(CountedTickets {
        inner: server.dtls12_ticketer.clone(),
        decrypts: AtomicUsize::new(0),
    });
    let mut config = (*server).clone();
    config.dtls12_ticketer = tickets.clone();
    let config = Arc::new(config);
    prime(&client, &config);
    let mut pair = pair(&client, &config);
    let now = Duration::from_secs(1000);
    let mut first = Vec::new();
    pair.client.write_datagram(&mut first, now).unwrap();
    pair.server.read_datagram(&mut first, now).unwrap();
    assert_eq!(tickets.decrypts.load(Ordering::SeqCst), 0);
    assert_eq!(pair.server.handshake_kind(), None);
    pair.handshake(&mut Sim::perfect()).unwrap();
    kind(&pair, HandshakeKind::Resumed);
    assert_eq!(tickets.decrypts.load(Ordering::SeqCst), 1);
}

#[test]
fn dual_version_ticket_resumption_uses_empty_id_and_can_upgrade_to_dtls13() {
    for tickets in [false, true] {
        let (client, server, _) = configs(tickets);
        prime(&client, &server);
        // No DTLS 1.3 ticket exists yet. The dual-version client offers its
        // DTLS 1.2 session, with a cached ID or an empty ID for a ticket.
        let mut resumed = make_pair(
            &client,
            &server,
            dtls::Versions::V1_2And1_3,
            dtls::Versions::V1_2,
        );
        let mut sim = Sim::new(
            Link::new(|n, _| if n == 1 { Fate::Hold } else { Fate::Deliver }),
            Link::perfect(),
        );
        resumed.handshake(&mut sim).unwrap();
        kind(&resumed, HandshakeKind::Resumed);
        let mut upgraded = make_pair(
            &client,
            &server,
            dtls::Versions::V1_2And1_3,
            dtls::Versions::V1_2And1_3,
        );
        upgraded.handshake(&mut Sim::perfect()).unwrap();
        assert_dtls13(&upgraded);
        assert_ne!(
            upgraded.server.handshake_kind(),
            Some(HandshakeKind::Resumed)
        );
        let mut v12 = pair(&client, &server);
        v12.handshake(&mut Sim::perfect()).unwrap();
        kind(&v12, HandshakeKind::Resumed);
    }
}

#[test]
fn declined_empty_id_ticket_continues_a_verified_full_handshake() {
    let (client, server, _) = configs(true);
    prime(&client, &server);
    let mut rotated = (*server).clone();
    rotated.dtls12_ticketer = prov::Ticketer::new().unwrap();
    let rotated = Arc::new(rotated);
    let mut full = make_pair(
        &client,
        &rotated,
        dtls::Versions::V1_2And1_3,
        dtls::Versions::V1_2,
    );
    full.handshake(&mut Sim::perfect()).unwrap();
    kind(&full, HandshakeKind::Full);
    let mut resumed = make_pair(
        &client,
        &rotated,
        dtls::Versions::V1_2And1_3,
        dtls::Versions::V1_2,
    );
    resumed.handshake(&mut Sim::perfect()).unwrap();
    kind(&resumed, HandshakeKind::Resumed);
}

#[test]
fn changed_alpn_and_unavailable_cached_suite_require_full_handshakes() {
    let suites: Vec<_> = provider()
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| {
            s.version() == &version::TLS12
                && !s.is_tls12_block_cipher()
                && s.usable_for_signature_algorithm(browntls_core::SignatureAlgorithm::ECDSA)
        })
        .collect();
    assert!(suites.len() >= 2);
    let chain = server_chain(KeyType::EcdsaP256);
    let verifier = PinnedServerVerifier::new(&chain);
    let store = Arc::new(ClientSessionMemoryCache::new(16));
    let mut provider_one = (*provider()).clone();
    provider_one.cipher_suites = vec![suites[0]];
    let mut first = ClientConfig::builder_with_provider(Arc::new(provider_one))
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    first.resumption = Resumption::store(store.clone());
    first.alpn_protocols = vec![b"first".to_vec()];
    let mut server = dtls_server_config(&chain);
    server.alpn_protocols = vec![b"first".to_vec(), b"second".to_vec()];
    server.enable_dtls12_resumption().unwrap();
    let server = Arc::new(server);
    let first = Arc::new(first);
    prime(&first, &server);

    let mut changed = (*first).clone();
    changed.alpn_protocols = vec![b"second".to_vec()];
    let changed = Arc::new(changed);
    prime(&changed, &server);
    let mut resumed = pair(&changed, &server);
    resumed.handshake(&mut Sim::perfect()).unwrap();
    kind(&resumed, HandshakeKind::Resumed);

    let mut provider_two = (*provider()).clone();
    provider_two.cipher_suites = vec![suites[1]];
    let mut different_suite = ClientConfig::builder_with_provider(Arc::new(provider_two))
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    different_suite.client_auth_cert_resolver = first.client_auth_cert_resolver.clone();
    different_suite.resumption = Resumption::store(store);
    different_suite.alpn_protocols = changed.alpn_protocols.clone();
    let different_suite = Arc::new(different_suite);
    prime(&different_suite, &server);
    let mut resumed = pair(&different_suite, &server);
    resumed.handshake(&mut Sim::perfect()).unwrap();
    kind(&resumed, HandshakeKind::Resumed);
    assert_eq!(resumed.client.negotiated_cipher_suite(), Some(suites[1]));
}

#[test]
fn changed_credentials_from_the_same_resolver_are_not_resumed() {
    use browntls_core::server::{ClientHello, ResolvesServerCert};
    use browntls_core::sign::CertifiedKey;
    use std::sync::Mutex;
    #[derive(Debug)]
    struct CurrentKey(Mutex<Arc<CertifiedKey>>);
    impl ResolvesServerCert for CurrentKey {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            self.0.lock().ok().map(|key| key.clone())
        }
    }
    for tickets in [false, true] {
        let chain = server_chain(KeyType::EcdsaP256);
        let replacement = server_chain(KeyType::EcdsaP256);
        let resolver = Arc::new(CurrentKey(Mutex::new(Arc::new(
            CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap(),
        ))));
        let client = Arc::new(client_config(&chain));
        let mut server = dtls_server_config(&chain);
        server.cert_resolver = resolver.clone();
        server.enable_dtls12_resumption().unwrap();
        if tickets {
            server.dtls12_ticketer = prov::Ticketer::new().unwrap();
        }
        let server = Arc::new(server);
        prime(&client, &server);
        *resolver.0.lock().unwrap() = Arc::new(
            CertifiedKey::from_der(
                replacement.cert_chain(),
                replacement.private_key(),
                &provider(),
            )
            .unwrap(),
        );
        let mut attempted = pair(&client, &server);
        assert!(matches!(
            attempted.handshake(&mut Sim::perfect()),
            Err(Failure::Client(_))
        ));
        assert_eq!(attempted.server.handshake_kind(), Some(HandshakeKind::Full));
    }
}
