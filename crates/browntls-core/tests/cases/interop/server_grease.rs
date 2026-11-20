// A rustls client against a browntls server with `enable_grease` on (RFC
// 8701 §4.1): the TLS 1.3 CertificateRequest lists a GREASE signature
// scheme and carries GREASE extensions, and every NewSessionTicket carries
// GREASE extensions. rustls must ignore all of them.

/// A rustls ticket store that counts the TLS 1.3 tickets it is given.
#[derive(Debug)]
struct CountingTicketStore {
    inner: rustls::client::ClientSessionMemoryCache,
    tls13_tickets: std::sync::atomic::AtomicUsize,
}

impl CountingTicketStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: rustls::client::ClientSessionMemoryCache::new(8),
            tls13_tickets: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn tls13_tickets(&self) -> usize {
        self.tls13_tickets.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl rustls::client::ClientSessionStore for CountingTicketStore {
    fn set_kx_hint(&self, server_name: rpki::ServerName<'static>, group: rustls::NamedGroup) {
        self.inner.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &rpki::ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.inner.kx_hint(server_name)
    }

    fn set_tls12_session(
        &self,
        server_name: rpki::ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.inner.set_tls12_session(server_name, value);
    }

    fn tls12_session(
        &self,
        server_name: &rpki::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &rpki::ServerName<'static>) {
        self.inner.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: rpki::ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.tls13_tickets
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &rpki::ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(server_name)
    }
}

/// A TLS 1.3 browntls server with GREASE on that verifies `client_chain`
/// (mandatory or optional client authentication).
fn b_grease_server(
    chain: &Chain,
    client_chain: &Chain,
    mandatory: bool,
) -> browntls_core::ServerConfig {
    let mut config = browntls_core::ServerConfig::builder_with_provider(b_provider(None, None))
        .with_protocol_versions(b_versions(0x0304))
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(client_chain, mandatory))
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.enable_grease = true;
    config
}

fn der_chain(chain: &Chain) -> Vec<Vec<u8>> {
    chain
        .cert_chain()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect()
}

#[test]
fn rustls_client_auth_with_browntls_grease_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for key_type in KeyType::ALL {
        let client_chain = client_chain(key_type);
        let mut client = r_connect_client(r_client_with_auth(&chain, &client_chain, 0x0304));
        let mut server = browntls_core::ServerConnection::new(Arc::new(b_grease_server(
            &chain,
            &client_chain,
            true,
        )))
        .unwrap();
        let (c, s) = handshake(&mut client, &mut server);
        assert_eq!(c, Ok(()), "{key_type:?}");
        assert_eq!(s, Ok(()), "{key_type:?}");
        assert_eq!(client.version(), Some(0x0304));
        assert_eq!(server.peer_certs().unwrap(), der_chain(&client_chain));
        round_trip(&mut client, &mut server);
    }
}

#[test]
fn rustls_client_resumes_from_browntls_grease_server_tickets() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    for stateless in [false, true] {
        let store = CountingTicketStore::new();
        let mut client_config = r_client_with_auth(&chain, &client_chain, 0x0304);
        client_config.resumption = rustls::client::Resumption::store(store.clone());
        let client_config = Arc::new(client_config);
        let mut server_config = b_grease_server(&chain, &client_chain, true);
        if stateless {
            server_config.ticketer = prov::Ticketer::new().unwrap();
            server_config.session_storage =
                Arc::new(browntls_core::server::NoServerSessionStorage {});
        }
        let tickets = server_config.send_tls13_tickets;
        assert!(tickets > 0);
        let server_config = Arc::new(server_config);

        let mut client = r_connect_client_from(client_config.clone());
        let mut server = browntls_core::ServerConnection::new(server_config.clone()).unwrap();
        handshake_ok(&mut client, &mut server);
        assert!(!client.resumed());
        assert_eq!(server.peer_certs().unwrap(), der_chain(&client_chain));
        round_trip(&mut client, &mut server);
        transfer(&mut server, &mut client);
        client.process().unwrap();
        assert_eq!(store.tls13_tickets(), tickets, "stateless={stateless}");

        let mut client = r_connect_client_from(client_config);
        let mut server = browntls_core::ServerConnection::new(server_config).unwrap();
        handshake_ok(&mut client, &mut server);
        assert!(
            client.resumed(),
            "stateless={stateless}: client not resumed"
        );
        assert!(
            server.resumed(),
            "stateless={stateless}: server not resumed"
        );
        round_trip(&mut client, &mut server);
    }
}

#[test]
fn rustls_client_declines_optional_auth_from_browntls_grease_server() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let mut client = r_connect_client(r_client(&chain, 0x0304, None, None));
    let mut server = browntls_core::ServerConnection::new(Arc::new(b_grease_server(
        &chain,
        &client_chain,
        false,
    )))
    .unwrap();
    handshake_ok(&mut client, &mut server);
    assert_eq!(client.version(), Some(0x0304));
    assert!(server.peer_certs().is_none_or(|certs| certs.is_empty()));
    round_trip(&mut client, &mut server);
}
