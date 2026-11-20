// Choosing the server configuration from the client's `tls-id` on the
// ClientHello view, with the buffered and the unbuffered acceptor.

/// The signaled sessions a server knows: the client's `tls-id` and the
/// binding to serve it with.
fn signaled_sessions() -> Vec<(ExternalSessionId, ExternalBinding)> {
    ["alice", "bob"]
        .into_iter()
        .map(|peer| {
            let binding = ExternalBinding {
                id_hash: Some(ExternalIdHash::EMPTY),
                session_id: Some(tls_id(&format!("server for {peer}"))),
                peer_session_id: Some(tls_id(peer)),
                require_peer_support: true,
                ..Default::default()
            };
            (tls_id(peer), binding)
        })
        .collect()
}

/// The per-connection configuration for a ClientHello, looked up by its
/// `external_session_id`.
fn config_for_hello(
    base: &ServerConfig,
    hello: &browntls_core::server::ClientHello<'_>,
) -> Arc<ServerConfig> {
    // Present whether or not the base configuration has a binding.
    assert!(base.external_binding.is_none());
    assert_eq!(hello.external_id_hash(), Some(&ExternalIdHash::EMPTY));
    let id = hello.external_session_id().expect("the client's tls-id");
    let (_, binding) = signaled_sessions()
        .into_iter()
        .find(|(known, _)| known == id)
        .expect("a signaled session");
    let mut config = base.clone();
    config.external_binding = Some(binding);
    Arc::new(config)
}

fn client_of(chain: &Chain, v: ProtocolVersion, peer: &str) -> ClientConfig {
    client_for(
        chain,
        v,
        Some(ExternalBinding {
            peer_id_hash: Some(ExternalIdHash::EMPTY),
            session_id: Some(tls_id(peer)),
            peer_session_id: Some(tls_id(&format!("server for {peer}"))),
            require_peer_support: true,
            ..Default::default()
        }),
    )
}

#[test]
fn acceptor_chooses_the_configuration_by_tls_id() {
    use browntls_core::server::Acceptor;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let base = server_for(&chain, v, None);
        for peer in ["alice", "bob"] {
            let mut client =
                ClientConnection::new(Arc::new(client_of(&chain, v, peer)), server_name()).unwrap();
            let hello = flight(&mut client);
            let mut acceptor = Acceptor::default();
            acceptor.read_tls(&mut &hello[..]).unwrap();
            let accepted = acceptor.accept().unwrap().expect("a complete ClientHello");
            let config = config_for_hello(&base, &accepted.client_hello());
            let mut server = accepted.into_connection(config).unwrap();
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(
                client.peer_external_session_id(),
                Some(&tls_id(&format!("server for {peer}")))
            );
            assert_eq!(server.peer_external_session_id(), Some(&tls_id(peer)));
        }
    }
}

#[test]
fn unbuffered_acceptor_chooses_the_configuration_by_tls_id() {
    use browntls_core::server::UnbufferedAcceptor;
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for v in VERSIONS {
        let base = server_for(&chain, v, None);
        let client_config = Arc::new(client_of(&chain, v, "bob"));
        let mut client = ub_client(&client_config);
        let mut incoming = client.take_output();
        let mut acceptor = UnbufferedAcceptor::new();
        let status = acceptor.accept(&mut incoming);
        incoming.drain(..status.discard);
        let accepted = status.state.unwrap().expect("a complete ClientHello");
        let config = config_for_hello(&base, &accepted.client_hello());
        let conn = accepted.into_connection(config).unwrap();
        let mut server = UbEnd::new(conn);
        server.incoming = incoming;
        pump(&mut client, &mut server);
        assert!(client.error.is_none() && server.error.is_none());
        assert_eq!(
            client.conn.peer_external_session_id(),
            Some(&tls_id("server for bob"))
        );
        assert_eq!(server.conn.peer_external_session_id(), Some(&tls_id("bob")));
        assert!(!client.conn.is_handshaking() && !server.conn.is_handshaking());
    }
}
