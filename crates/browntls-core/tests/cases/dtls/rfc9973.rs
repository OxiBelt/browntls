#[test]
fn rfc9973_direct_and_imported_keys_survive_cookie_retry() {
    use browntls_core::crypto::hash::HashAlgorithm;
    use browntls_core::psk::ExternalPsk;

    let chain = server_chain(KeyType::EcdsaP256);
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::SECP256R1];
    let provider = Arc::new(provider);
    let now = Duration::from_secs(5);
    for (hash, imported) in [
        (HashAlgorithm::SHA256, false),
        (HashAlgorithm::SHA256, true),
        (HashAlgorithm::SHA384, true),
    ] {
        let psk = ExternalPsk::new(b"dtls-rfc9973".to_vec(), vec![42; 32], hash).unwrap();
        let psk = Arc::new(if imported {
            psk.imported(b"dtls-test".to_vec()).unwrap()
        } else {
            psk
        });
        let mut client_config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&browntls_core::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        client_config.cert_with_extern_psk = true;
        client_config.require_cert_with_extern_psk = true;
        client_config.require_external_psk = true;
        client_config.external_psks = vec![psk.clone()];
        let mut server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&browntls_core::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        server_config.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
        server_config.require_cert_with_extern_psk = true;
        server_config.external_psks = Some(Arc::new(vec![psk]));

        let mut client =
            dtls::ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let config = Arc::new(server_config);
        let acceptor = dtls::Acceptor::new(config.clone()).unwrap();
        let mut first = client_datagrams(&mut client, now);
        assert_eq!(first.len(), 1);
        let mut retry = Vec::new();
        assert!(matches!(
            acceptor
                .accept(&mut first[0], PEER, &mut retry, now)
                .unwrap(),
            dtls::Accepted::Retry
        ));
        client.read_datagram(&mut retry, now).unwrap();
        let mut second = client_datagrams(&mut client, now);
        assert_eq!(second.len(), 1);
        let dtls::Accepted::Connection(server) = dtls::Acceptor::new(config)
            .unwrap()
            .accept(&mut second[0], PEER, &mut Vec::new(), now)
            .unwrap()
        else {
            panic!("the new acceptor should continue the RFC 9973 cookie retry");
        };
        let mut pair = Pair {
            client,
            server: *server,
        };
        let mut sim = Sim::perfect();
        sim.now = now;
        pair.handshake(&mut sim).unwrap();
        assert!(pair.client.negotiated_cert_with_extern_psk());
        assert!(pair.server.negotiated_cert_with_extern_psk());
        assert_eq!(pair.client.peer_certificates().unwrap(), chain.cert_chain());
        pair.exchange(&mut sim, "RFC 9973");
    }
}
