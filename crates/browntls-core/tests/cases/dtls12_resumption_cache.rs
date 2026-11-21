// Included inside resumption_cases; storage changes use only public APIs.

#[test]
fn existing_client_store_implementations_default_to_no_dtls12_resumption() {
    use browntls_core::NamedGroup;
    use browntls_core::client::{Tls12ClientSessionValue, Tls13ClientSessionValue};
    use browntls_pki::ServerName;
    #[derive(Debug)]
    struct LegacyStore(ClientSessionMemoryCache);
    // This implements exactly the pre-DTLS-1.2 trait methods.
    impl ClientSessionStore for LegacyStore {
        fn set_kx_hint(&self, n: ServerName<'static>, g: NamedGroup) {
            self.0.set_kx_hint(n, g);
        }
        fn kx_hint(&self, n: &ServerName<'_>) -> Option<NamedGroup> {
            self.0.kx_hint(n)
        }
        fn set_tls12_session(&self, n: ServerName<'static>, v: Tls12ClientSessionValue) {
            self.0.set_tls12_session(n, v);
        }
        fn tls12_session(&self, n: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
            self.0.tls12_session(n)
        }
        fn remove_tls12_session(&self, n: &ServerName<'static>) {
            self.0.remove_tls12_session(n);
        }
        fn insert_tls13_ticket(&self, n: ServerName<'static>, v: Tls13ClientSessionValue) {
            self.0.insert_tls13_ticket(n, v);
        }
        fn take_tls13_ticket(&self, n: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
            self.0.take_tls13_ticket(n)
        }
    }
    let (client, server, _) = configs(false);
    let store = Arc::new(LegacyStore(ClientSessionMemoryCache::new(16)));
    let mut client = (*client).clone();
    client.resumption = Resumption::store(store.clone());
    let client = Arc::new(client);
    for _ in 0..2 {
        prime(&client, &server);
    }
    assert!(store.dtls12_session(&server_name()).is_none());
    assert!(store.tls12_session(&server_name()).is_none());
}

#[test]
fn incorrectly_filed_client_transport_values_are_declined() {
    let (client, server, store) = configs(false);
    prime(&client, &server);
    let dtls_value = store.dtls12_session(&server_name()).unwrap();
    // Custom stores see the same public value type for both transports.
    // Filing a DTLS value in the stream slot must not make it resumable.
    store.set_tls12_session(server_name(), dtls_value);
    let chain = server_chain(KeyType::EcdsaP256);
    let mut c = client_config(&chain);
    c.resumption = Resumption::store(store.clone());
    // The full stream handshake replaces the misfiled value with a TLS
    // value. This also exercises the normal stream authentication path.
    let mut s = server_config(&chain);
    s.ticketer = server.ticketer.clone();
    let mut c12 = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    c12.resumption = c.resumption;
    let mut stream_client =
        browntls_core::ClientConnection::new(Arc::new(c12), server_name()).unwrap();
    let mut stream_server = browntls_core::ServerConnection::new(Arc::new(s)).unwrap();
    do_handshake(&mut stream_client, &mut stream_server).unwrap();
    assert_eq!(stream_client.handshake_kind(), Some(HandshakeKind::Full));
    let tls_value = store.tls12_session(&server_name()).unwrap();
    assert_eq!(tls_value.protocol_version(), ProtocolVersion::TLSv1_2);
    store.set_dtls12_session(server_name(), tls_value);
    // The DTLS connection must likewise decline the stream-tagged value.
    prime(&client, &server);
    assert_eq!(
        store
            .dtls12_session(&server_name())
            .unwrap()
            .protocol_version(),
        ProtocolVersion::DTLSv1_2
    );
}

#[test]
fn expired_client_sessions_and_expired_server_tickets_require_full_handshakes() {
    use browntls_core::time_provider::TimeProvider;
    use browntls_pki::UnixTime;
    use std::sync::atomic::AtomicU64;
    #[derive(Debug)]
    struct Clock(AtomicU64);
    impl TimeProvider for Clock {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(
                self.0.load(Ordering::SeqCst),
            )))
        }
    }
    for tickets in [false, true] {
        let (client, server, store) = configs(tickets);
        let initial = server.time_provider.current_time().unwrap().as_secs();
        let clock = Arc::new(Clock(AtomicU64::new(initial)));
        let mut server = (*server).clone();
        server.time_provider = clock.clone();
        let server = Arc::new(server);
        prime(&client, &server);
        if tickets {
            let mut expired = store.dtls12_session(&server_name()).unwrap();
            expired.rewind_epoch(8 * 24 * 60 * 60);
            store.set_dtls12_session(server_name(), expired);
            prime(&client, &server);
            // Keep the client clock and credential unchanged: the server
            // must independently reject its expired stateless ticket.
            clock.0.store(
                initial + u64::from(server.dtls12_ticketer.lifetime()) + 1,
                Ordering::SeqCst,
            );
        } else {
            let mut old = store.dtls12_session(&server_name()).unwrap();
            // Stateful client entries have an unknown lifetime; server
            // state still has an explicit seven-day retention bound.
            old.rewind_epoch(8 * 24 * 60 * 60);
            store.set_dtls12_session(server_name(), old);
            clock.0.store(initial + 8 * 24 * 60 * 60, Ordering::SeqCst);
        }
        let mut full = pair(&client, &server);
        full.handshake(&mut Sim::perfect()).unwrap();
        kind(&full, HandshakeKind::Full);
    }
}

#[test]
fn empty_ticket_renewal_preserves_the_original_resumption_credential() {
    use browntls_core::server::ProducesTickets;
    #[derive(Debug)]
    struct FailRenewal {
        inner: Arc<dyn ProducesTickets>,
        encrypts: AtomicUsize,
    }
    impl ProducesTickets for FailRenewal {
        fn enabled(&self) -> bool {
            true
        }
        fn lifetime(&self) -> u32 {
            self.inner.lifetime()
        }
        fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
            self.inner.decrypt(ticket)
        }
        fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
            if self.encrypts.fetch_add(1, Ordering::SeqCst) == 1 {
                None
            } else {
                self.inner.encrypt(plain)
            }
        }
    }
    let (client, server, _) = configs(true);
    let mut server = (*server).clone();
    server.dtls12_ticketer = Arc::new(FailRenewal {
        inner: server.dtls12_ticketer.clone(),
        encrypts: AtomicUsize::new(0),
    });
    let server = Arc::new(server);
    prime(&client, &server);
    for _ in 0..2 {
        let mut resumed = make_pair(
            &client,
            &server,
            dtls::Versions::V1_2And1_3,
            dtls::Versions::V1_2,
        );
        resumed.handshake(&mut Sim::perfect()).unwrap();
        kind(&resumed, HandshakeKind::Resumed);
    }
}
