// Server-side GREASE (RFC 8701 §4.1). Over QUIC the handshake messages
// leave `write_hs` unprotected, so the server's CertificateRequest and
// NewSessionTickets can be read as they are sent.
//
// Included by `cases/quic.rs`, which holds the imports and the handshake
// plumbing.

/// A server that asks for (but does not require) `client`'s certificate.
fn grease_server_config(
    chain: &Chain,
    client: &Chain,
    grease: bool,
) -> Arc<browntls_core::ServerConfig> {
    let mut config = browntls_core::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(client, false))
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_grease = grease;
    Arc::new(config)
}

/// A client that authenticates with `client`.
fn grease_client_config(chain: &Chain, client: &Chain) -> Arc<browntls_core::ClientConfig> {
    let mut config = browntls_core::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_client_auth_cert(client.cert_chain(), client.private_key())
        .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(config)
}

/// Runs the handshake and returns the handshake messages the server sent,
/// at every level.
fn handshake_keeping_server_messages(client: &mut Peer, server: &mut Peer) -> Vec<(u8, Vec<u8>)> {
    let mut sent = Vec::new();
    for _ in 0..16 {
        let c = pump(client, server).unwrap();
        server.poll();
        for (_, bytes) in &server.outbox {
            sent.extend_from_slice(bytes);
        }
        let s = pump(server, client).unwrap();
        if !c && !s && !client.conn.handshaking() && !server.conn.handshaking() {
            return grease_wire::handshake_messages(&sent);
        }
    }
    panic!("handshake did not finish");
}

/// The bodies of the messages of type `typ`.
fn bodies(messages: &[(u8, Vec<u8>)], typ: u8) -> Vec<&[u8]> {
    let of_type = messages.iter().filter(|m| m.0 == typ);
    of_type.map(|m| m.1.as_slice()).collect()
}

const CERTIFICATE_REQUEST: u8 = 13;
const NEW_SESSION_TICKET: u8 = 4;

#[test]
fn server_grease_fills_the_certificate_request_and_tickets() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = grease_client_config(&chain, &client_chain);
    let server_config = grease_server_config(&chain, &client_chain, true);

    // The first GREASE extension type of every message.
    let mut first_types = std::collections::BTreeSet::new();
    for connection in 0..12 {
        let mut client = b_client(&client_config);
        let mut server = b_server(&server_config);
        let sent = handshake_keeping_server_messages(&mut client, &mut server);
        // Tickets with GREASE extensions are stored and resumed; a resumed
        // handshake has no CertificateRequest.
        assert_eq!(client.conn.resumed(), connection > 0);
        assert!(server.conn.peer_certified());

        let requests = bodies(&sent, CERTIFICATE_REQUEST);
        assert_eq!(requests.len(), usize::from(connection == 0));
        for request in requests {
            let [_, first, _] = grease_wire::assert_greased_certificate_request(request);
            first_types.insert(first);
        }
        let tickets = bodies(&sent, NEW_SESSION_TICKET);
        assert_eq!(tickets.len(), 2, "the default ticket count");
        for ticket in tickets {
            let exts = grease_wire::new_session_ticket_extensions(ticket);
            let (first, _) = grease_wire::assert_grease_extensions(&exts);
            first_types.insert(first);
        }
    }
    // RFC 8701 §5: the values are chosen at random. 25 messages each drew
    // one of sixteen values for this place: not the same one every time.
    assert!(first_types.len() > 1, "{first_types:x?}");
}

#[test]
fn server_grease_is_off_by_default() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let server_config = grease_server_config(&chain, &client_chain, false);
    assert!(!b_server_config(&chain).enable_grease);

    let mut client = b_client(&grease_client_config(&chain, &client_chain));
    let mut server = b_server(&server_config);
    let sent = handshake_keeping_server_messages(&mut client, &mut server);
    let requests = bodies(&sent, CERTIFICATE_REQUEST);
    assert_eq!(requests.len(), 1);
    grease_wire::assert_plain_certificate_request(requests[0]);
    let tickets = bodies(&sent, NEW_SESSION_TICKET);
    assert_eq!(tickets.len(), 2);
    for ticket in tickets {
        let exts = grease_wire::new_session_ticket_extensions(ticket);
        assert!(exts.iter().all(|e| !grease_wire::is_grease(e.0)));
    }
}

#[test]
fn rustls_client_ignores_server_grease() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = r_client_config(&chain);
    let server_config = grease_server_config(&chain, &client_chain, true);

    for resuming in [false, true] {
        let mut client = r_client(&client_config);
        let mut server = b_server(&server_config);
        let sent = handshake_keeping_server_messages(&mut client, &mut server);
        assert_eq!(client.conn.resumed(), resuming);
        assert_eq!(server.conn.resumed(), resuming);
        // rustls has no certificate here and declines the request.
        assert!(!server.conn.peer_certified());
        if !resuming {
            let requests = bodies(&sent, CERTIFICATE_REQUEST);
            assert_eq!(requests.len(), 1);
            grease_wire::assert_greased_certificate_request(requests[0]);
        }
        for ticket in bodies(&sent, NEW_SESSION_TICKET) {
            let exts = grease_wire::new_session_ticket_extensions(ticket);
            grease_wire::assert_grease_extensions(&exts);
        }
    }
}

/// A client key whose signatures claim the scheme in `claimed`, whatever
/// the real one is.
#[derive(Debug)]
struct ClaimsScheme {
    key: Arc<dyn browntls_core::sign::SigningKey>,
    claimed: Arc<std::sync::atomic::AtomicU16>,
}

#[derive(Debug)]
struct ClaimingSigner {
    signer: Box<dyn browntls_core::sign::Signer>,
    claimed: Arc<std::sync::atomic::AtomicU16>,
}

impl browntls_core::sign::SigningKey for ClaimsScheme {
    fn choose_scheme(
        &self,
        offered: &[browntls_core::SignatureScheme],
    ) -> Option<Box<dyn browntls_core::sign::Signer>> {
        Some(Box::new(ClaimingSigner {
            signer: self.key.choose_scheme(offered)?,
            claimed: self.claimed.clone(),
        }))
    }

    fn algorithm(&self) -> browntls_core::SignatureAlgorithm {
        self.key.algorithm()
    }
}

impl browntls_core::sign::Signer for ClaimingSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.signer.sign(message)
    }

    fn scheme(&self) -> browntls_core::SignatureScheme {
        self.claimed
            .load(std::sync::atomic::Ordering::Relaxed)
            .into()
    }
}

#[derive(Debug)]
struct OneKey(Arc<browntls_core::sign::CertifiedKey>);

impl browntls_core::client::ResolvesClientCert for OneKey {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[browntls_core::SignatureScheme],
    ) -> Option<Arc<browntls_core::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// RFC 8701 §4.1: a server must reject a GREASE value the client selects.
/// The one case a client can select from a CertificateRequest is the
/// signature scheme of its CertificateVerify.
#[test]
fn server_rejects_a_certificate_verify_with_its_grease_scheme() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let claimed = Arc::new(std::sync::atomic::AtomicU16::new(0));
    let key = provider()
        .key_provider
        .load_private_key(client_chain.private_key())
        .unwrap();
    let key = Arc::new(ClaimsScheme {
        key,
        claimed: claimed.clone(),
    });
    let certified = browntls_core::sign::CertifiedKey::new(client_chain.cert_chain(), key);
    let mut client_config = browntls_core::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_client_cert_resolver(Arc::new(OneKey(Arc::new(certified))));
    client_config.alpn_protocols = vec![ALPN.to_vec()];

    let mut client = b_client(&Arc::new(client_config));
    let mut server = b_server(&grease_server_config(&chain, &client_chain, true));
    assert!(pump(&mut client, &mut server).unwrap());
    // The server's flight waits in its outbox: read the GREASE scheme of
    // its CertificateRequest and have the client sign with that.
    let mut flight = Vec::new();
    for (_, bytes) in &server.outbox {
        flight.extend_from_slice(bytes);
    }
    let flight = grease_wire::handshake_messages(&flight);
    let requests = bodies(&flight, CERTIFICATE_REQUEST);
    let [scheme, _, _] = grease_wire::assert_greased_certificate_request(requests[0]);
    claimed.store(scheme, std::sync::atomic::Ordering::Relaxed);

    assert!(pump(&mut server, &mut client).unwrap());
    let err = pump(&mut client, &mut server).unwrap_err();
    assert!(
        err.contains("SignedHandshakeWithUnadvertisedSigScheme"),
        "{err}"
    );
    assert_eq!(
        server.conn.alert(),
        Some(u8::from(AlertDescription::IllegalParameter))
    );
}
