// Included inside dtls12_cases so all traffic uses the public datagram API.
mod resumption_cases {
    use super::*;
    use browntls_core::client::{
        ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12Resumption,
    };
    use browntls_core::server::{
        NoServerSessionStorage, ServerSessionMemoryCache, StoresServerSessions,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pair(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Pair {
        make_pair(client, server, dtls::Versions::V1_2, dtls::Versions::V1_2)
    }

    fn kind(pair: &Pair, expected: HandshakeKind) {
        for common in [
            &**pair.client as &browntls_core::CommonState,
            &**pair.server,
        ] {
            assert_eq!(common.protocol_version(), Some(ProtocolVersion::DTLSv1_2));
            assert_eq!(common.handshake_kind(), Some(expected));
            assert!(!common.is_handshaking());
        }
        assert_eq!(pair.client.tls13_tickets_received(), 0);
        let mut client_export = [0; 32];
        let mut server_export = [0; 32];
        pair.client
            .export_keying_material(&mut client_export, b"dtls12 resume", None)
            .unwrap();
        pair.server
            .export_keying_material(&mut server_export, b"dtls12 resume", None)
            .unwrap();
        assert_eq!(client_export, server_export);
    }

    fn configs(
        tickets: bool,
    ) -> (
        Arc<ClientConfig>,
        Arc<ServerConfig>,
        Arc<ClientSessionMemoryCache>,
    ) {
        let chain = server_chain(KeyType::EcdsaP256);
        let store = Arc::new(ClientSessionMemoryCache::new(32));
        let mut client = client_config(&chain);
        client.resumption = Resumption::store(store.clone());
        let mut server = dtls_server_config(&chain);
        server.enable_dtls12_resumption().unwrap();
        if tickets {
            server.dtls12_ticketer = prov::Ticketer::new().unwrap();
            server.session_storage = Arc::new(NoServerSessionStorage {});
        }
        (Arc::new(client), Arc::new(server), store)
    }

    fn prime(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) {
        let mut first = pair(client, server);
        first.handshake(&mut Sim::perfect()).unwrap();
        kind(&first, HandshakeKind::Full);
    }

    #[test]
    fn session_ids_and_rfc5077_tickets_resume_through_public_apis() {
        for tickets in [false, true] {
            let (client, server, store) = configs(tickets);
            for expected in [
                HandshakeKind::Full,
                HandshakeKind::Resumed,
                HandshakeKind::Resumed,
            ] {
                let mut pair = pair(&client, &server);
                pair.server.set_resumption_data(b"application context");
                let mut sim = Sim::perfect();
                pair.handshake(&mut sim).unwrap();
                kind(&pair, expected);
                assert!(pair.client.peer_certificates().is_some());
                assert!(store.tls12_session(&server_name()).is_none());
                assert_eq!(
                    store
                        .dtls12_session(&server_name())
                        .unwrap()
                        .protocol_version(),
                    ProtocolVersion::DTLSv1_2
                );
                if expected == HandshakeKind::Resumed {
                    assert_eq!(
                        pair.server.received_resumption_data(),
                        Some(&b"application context"[..])
                    );
                }
                pair.exchange(&mut sim, "resumed session");
            }
        }
    }

    #[test]
    fn abbreviated_flights_recover_every_single_loss_and_reordering() {
        for tickets in [false, true] {
            let (client, server, _) = configs(tickets);
            prime(&client, &server);
            for direction in 0..2 {
                for lost in 0..8 {
                    let mut pair = pair(&client, &server);
                    pair.client.set_mtu(300).unwrap();
                    pair.server.set_mtu(300).unwrap();
                    let policy = move |n: usize, _: &[u8]| {
                        if n == lost {
                            Fate::Drop
                        } else if n % 4 == 1 {
                            Fate::Hold
                        } else if n % 4 == 2 {
                            Fate::Duplicate
                        } else {
                            Fate::Deliver
                        }
                    };
                    let mut sim = if direction == 0 {
                        Sim::new(Link::new(policy), Link::perfect())
                    } else {
                        Sim::new(Link::perfect(), Link::new(policy))
                    };
                    pair.handshake(&mut sim).unwrap_or_else(|e| {
                        panic!("tickets {tickets}, direction {direction}, loss {lost}: {e:?}")
                    });
                    kind(&pair, HandshakeKind::Resumed);
                    pair.exchange(&mut sim, "abbreviated loss recovery");
                }
            }
        }
    }

    #[test]
    fn ticket_key_rotation_and_policy_context_rotation_fall_back_to_full() {
        for tickets in [false, true] {
            let (client, server, _) = configs(tickets);
            prime(&client, &server);
            let mut changed = (*server).clone();
            if tickets {
                changed.dtls12_ticketer = prov::Ticketer::new().unwrap();
            } else {
                changed.enable_dtls12_resumption().unwrap();
            }
            let changed = Arc::new(changed);
            let mut full = pair(&client, &changed);
            full.handshake(&mut Sim::perfect()).unwrap();
            kind(&full, HandshakeKind::Full);
            let mut resumed = pair(&client, &changed);
            resumed.handshake(&mut Sim::perfect()).unwrap();
            kind(&resumed, HandshakeKind::Resumed);
        }
    }

    #[test]
    fn server_context_and_selected_credentials_do_not_cross_configurations() {
        for tickets in [false, true] {
            let (client, server, _) = configs(tickets);
            prime(&client, &server);
            // A new configuration shares storage and ticket keys, but has a
            // different verifier/resolver policy and explicit context.
            let chain = server_chain(KeyType::EcdsaP256);
            let mut other = dtls_server_config(&chain);
            other.session_storage = server.session_storage.clone();
            other.dtls12_ticketer = server.dtls12_ticketer.clone();
            other.enable_dtls12_resumption().unwrap();
            let mut attempted = pair(&client, &Arc::new(other));
            assert!(matches!(
                attempted.handshake(&mut Sim::perfect()),
                Err(Failure::Client(_))
            ));
            assert_eq!(attempted.server.handshake_kind(), Some(HandshakeKind::Full));

            prime(&client, &server);
            // Replacing only the resolver in a cloned config invalidates
            // the old context, even when the new credentials are equivalent.
            let mut changed = (*server).clone();
            changed.cert_resolver = server_config(&chain).cert_resolver;
            let mut attempted = pair(&client, &Arc::new(changed));
            assert!(matches!(
                attempted.handshake(&mut Sim::perfect()),
                Err(Failure::Client(_))
            ));
            assert_eq!(attempted.server.handshake_kind(), Some(HandshakeKind::Full));
        }
    }

    #[test]
    fn client_verifier_and_client_credentials_are_bound_to_the_session() {
        let (client, server, store) = configs(false);
        prime(&client, &server);
        let wrong = server_chain(KeyType::EcdsaP384);
        let mut changed = (*client).clone();
        changed
            .dangerous()
            .set_certificate_verifier(PinnedServerVerifier::new(&wrong));
        let mut refused = pair(&Arc::new(changed), &server);
        assert!(matches!(
            refused.handshake(&mut Sim::perfect()),
            Err(Failure::Client(_))
        ));
        assert_eq!(refused.server.handshake_kind(), Some(HandshakeKind::Full));

        prime(&client, &server);
        let mut changed = (*client).clone();
        changed.client_auth_cert_resolver = client_config(&wrong).client_auth_cert_resolver;
        changed.resumption = Resumption::store(store);
        let mut full = pair(&Arc::new(changed), &server);
        full.handshake(&mut Sim::perfect()).unwrap();
        kind(&full, HandshakeKind::Full);
    }

    #[test]
    fn dtls12_stream_tls12_and_dtls13_keep_separate_client_sessions() {
        let chain = server_chain(KeyType::EcdsaP256);
        let verifier = PinnedServerVerifier::new(&chain);
        let store = Arc::new(ClientSessionMemoryCache::new(32));
        let mut client = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        client.resumption = Resumption::store(store.clone());
        let mut server = dtls_server_config(&chain);
        server.dtls12_ticketer = prov::Ticketer::new().unwrap();
        server.session_storage = ServerSessionMemoryCache::new(64);
        server.enable_dtls12_resumption().unwrap();
        let client = Arc::new(client);
        let server = Arc::new(server);
        // The same name, config objects, stores and server ticketer settings
        // serve all three protocols; only the DTLS 1.2 producer is distinct.
        for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
            let mut stream_client =
                browntls_core::ClientConnection::new(client.clone(), server_name()).unwrap();
            let mut stream_server = browntls_core::ServerConnection::new(server.clone()).unwrap();
            do_handshake(&mut stream_client, &mut stream_server).unwrap();
            // The stream negotiates TLS 1.3 here, and its tickets coexist.
            assert_eq!(
                stream_client.protocol_version(),
                Some(ProtocolVersion::TLSv1_3)
            );
            let mut v13 = Pair::new(&client, &server);
            v13.handshake(&mut Sim::perfect()).unwrap();
            assert_dtls13(&v13);
            let expected_v13 = match expected {
                HandshakeKind::Full => HandshakeKind::FullWithHelloRetryRequest,
                resumed => resumed,
            };
            assert_eq!(v13.server.handshake_kind(), Some(expected_v13));
            let mut v12 = pair(&client, &server);
            v12.handshake(&mut Sim::perfect()).unwrap();
            kind(&v12, expected);
        }
        // Clear the TLS 1.3 ticket queue before testing the two legacy
        // session slots independently of TLS 1.3 ticket preference.
        while store.take_tls13_ticket(&server_name()).is_some() {}
        // Restrict the shared configurations to TLS 1.2 using the public
        // builders while retaining the same authentication objects.
        let chain = server_chain(KeyType::EcdsaP256);
        let mut c12 = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        c12.client_auth_cert_resolver = client.client_auth_cert_resolver.clone();
        c12.resumption = Resumption::store(store.clone());
        let mut s12 = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        s12.cert_resolver = server.cert_resolver.clone();
        s12.session_storage = server.session_storage.clone();
        s12.ticketer = server.ticketer.clone();
        let c12 = Arc::new(c12);
        let s12 = Arc::new(s12);
        for expected in [HandshakeKind::Full, HandshakeKind::Resumed] {
            let mut c = browntls_core::ClientConnection::new(c12.clone(), server_name()).unwrap();
            let mut s = browntls_core::ServerConnection::new(s12.clone()).unwrap();
            do_handshake(&mut c, &mut s).unwrap();
            assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_2));
            assert_eq!(c.handshake_kind(), Some(expected));
            assert_eq!(
                store
                    .tls12_session(&server_name())
                    .unwrap()
                    .protocol_version(),
                ProtocolVersion::TLSv1_2
            );
            let mut dtls = pair(&client, &server);
            dtls.handshake(&mut Sim::perfect()).unwrap();
            kind(&dtls, HandshakeKind::Resumed);
        }
        let wrong = server_chain(KeyType::EcdsaP384);
        let mut rejecting = (*client).clone();
        rejecting
            .dangerous()
            .set_certificate_verifier(PinnedServerVerifier::new(&wrong));
        let mut failed = pair(&Arc::new(rejecting), &server);
        assert!(matches!(
            failed.handshake(&mut Sim::perfect()),
            Err(Failure::Client(_))
        ));
        // Fatal DTLS errors invalidate only DTLS 1.2, not stream TLS 1.2.
        assert!(store.dtls12_session(&server_name()).is_none());
        assert!(store.tls12_session(&server_name()).is_some());
        let mut full = pair(&client, &server);
        full.handshake(&mut Sim::perfect()).unwrap();
        kind(&full, HandshakeKind::Full);
        store.remove_tls12_session(&server_name());
        assert!(store.dtls12_session(&server_name()).is_some());
    }

    #[derive(Debug)]
    struct CountedStore {
        inner: Arc<dyn StoresServerSessions>,
        gets: AtomicUsize,
    }

    impl StoresServerSessions for CountedStore {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            self.inner.put(key, value)
        }
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(key)
        }
        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.take(key)
        }
        fn can_cache(&self) -> bool {
            true
        }
    }

    #[test]
    fn stateless_cookie_validation_precedes_session_lookup() {
        let (client, server, _) = configs(false);
        let counted = Arc::new(CountedStore {
            inner: ServerSessionMemoryCache::new(32),
            gets: AtomicUsize::new(0),
        });
        let mut config = (*server).clone();
        config.session_storage = counted.clone();
        let config = Arc::new(config);
        prime(&client, &config);
        counted.gets.store(0, Ordering::SeqCst);
        let acceptor = dtls::Acceptor::new_with_versions(config, dtls::Versions::V1_2).unwrap();
        let mut client =
            dtls::ClientConnection::new_with_versions(client, server_name(), dtls::Versions::V1_2)
                .unwrap();
        let now = Duration::from_secs(1000);
        let mut first = Vec::new();
        client.write_datagram(&mut first, now).unwrap();
        let mut retry = Vec::new();
        assert!(matches!(
            acceptor.accept(&mut first, PEER, &mut retry, now).unwrap(),
            dtls::Accepted::Retry
        ));
        assert_eq!(counted.gets.load(Ordering::SeqCst), 0);
        client.read_datagram(&mut retry, now).unwrap();
        let mut second = Vec::new();
        client.write_datagram(&mut second, now).unwrap();
        assert!(matches!(
            acceptor
                .accept(&mut second.clone(), b"other", &mut Vec::new(), now)
                .unwrap(),
            dtls::Accepted::Ignored
        ));
        assert_eq!(counted.gets.load(Ordering::SeqCst), 0);
        let dtls::Accepted::Connection(server) = acceptor
            .accept(&mut second, PEER, &mut Vec::new(), now)
            .unwrap()
        else {
            panic!("validated resuming hello was refused")
        };
        assert_eq!(counted.gets.load(Ordering::SeqCst), 1);
        let mut pair = Pair {
            client,
            server: *server,
        };
        pair.handshake(&mut Sim::perfect()).unwrap();
        kind(&pair, HandshakeKind::Resumed);
    }

    #[test]
    fn disabled_and_session_id_only_client_policies_are_preserved() {
        let (client, server, _) = configs(true);
        let mut disabled = (*client).clone();
        disabled.resumption = Resumption::disabled();
        let disabled = Arc::new(disabled);
        for _ in 0..2 {
            let mut full = pair(&disabled, &server);
            full.handshake(&mut Sim::perfect()).unwrap();
            kind(&full, HandshakeKind::Full);
        }
        let mut ids = (*client).clone();
        ids.resumption = ids
            .resumption
            .tls12_resumption(Tls12Resumption::SessionIdOnly);
        let mut caching_server = (*server).clone();
        caching_server.session_storage = ServerSessionMemoryCache::new(32);
        let ids = Arc::new(ids);
        let caching_server = Arc::new(caching_server);
        prime(&ids, &caching_server);
        let mut resumed = pair(&ids, &caching_server);
        resumed.handshake(&mut Sim::perfect()).unwrap();
        kind(&resumed, HandshakeKind::Resumed);
    }

    #[test]
    fn dtls12_ticket_producer_must_be_distinct_from_tls_and_cookie_producers() {
        let (_, server, _) = configs(true);
        for producer in [
            server.ticketer.clone(),
            server.hello_retry_cookies.as_ref().unwrap().clone(),
        ] {
            let mut bad = (*server).clone();
            bad.dtls12_ticketer = producer;
            assert!(
                dtls::ServerConnection::new_with_versions(
                    Arc::new(bad),
                    PEER,
                    dtls::Versions::V1_2
                )
                .is_err()
            );
        }
    }
    include!("dtls12_resumption_auth.rs");
    include!("dtls12_resumption_cache.rs");
}
