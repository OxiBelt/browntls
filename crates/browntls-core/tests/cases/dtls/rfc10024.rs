// RFC 10024 fragmentation with a stateless DTLS 1.3 acceptor.

use super::*;

#[test]
fn hybrid_shares_fit_the_stateless_retry_flight() {
    let chain = server_chain(KeyType::EcdsaP256);
    for hybrid in [
        prov::kx_group::X25519MLKEM768,
        prov::kx_group::SECP256R1MLKEM768,
        prov::kx_group::SECP384R1MLKEM1024,
    ] {
        let mut provider = prov::default_provider();
        provider.kx_groups = vec![hybrid];
        let provider = Arc::new(provider);
        let client = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        let mut server = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        server.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
        let acceptor = dtls::Acceptor::new(Arc::new(server)).unwrap();
        let mut client = dtls::ClientConnection::new(Arc::new(client), server_name()).unwrap();
        let now = Duration::from_secs(5);

        let mut first = client_datagrams(&mut client, now);
        assert_eq!(first.len(), 1);
        assert!(first[0].len() <= 1200);
        let mut retry = Vec::new();
        assert!(matches!(
            acceptor
                .accept(&mut first[0], PEER, &mut retry, now)
                .unwrap(),
            dtls::Accepted::Retry
        ));
        client.read_datagram(&mut retry, now).unwrap();

        let second = client_datagrams(&mut client, now);
        assert!(second.len() > 1, "{hybrid:?}");
        assert!(second.iter().all(|d| d.len() <= 1200));
        let mut datagrams = second.into_iter();
        let dtls::Accepted::Connection(mut server) = acceptor
            .accept(&mut datagrams.next().unwrap(), PEER, &mut Vec::new(), now)
            .unwrap()
        else {
            panic!("the cookie in the first fragment must permit reassembly");
        };
        for mut fragment in datagrams {
            server.read_datagram(&mut fragment, now).unwrap();
        }
        let mut pair = Pair {
            client,
            server: *server,
        };
        let mut sim = Sim::perfect();
        sim.now = now;
        pair.handshake(&mut sim).unwrap();
        assert_dtls13(&pair);
        assert_eq!(
            pair.client.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        for common in [
            &**pair.client as &browntls_core::CommonState,
            &**pair.server,
        ] {
            assert_eq!(
                common.negotiated_key_exchange_group().unwrap().name(),
                hybrid.name()
            );
        }
        pair.exchange(&mut sim, "fragmented hybrid");
    }
}
