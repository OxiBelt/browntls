// Deterministic DTLS 1.2 cases using the same public datagram APIs and
// virtual clock as the DTLS 1.3 regression suite. No raw peer messages.

#[cfg(feature = "tls12")]
mod dtls12_cases {
    use super::*;
    use browntls_core::version;

    fn make_pair(
        client: &Arc<ClientConfig>,
        server: &Arc<ServerConfig>,
        client_versions: dtls::Versions,
        server_versions: dtls::Versions,
    ) -> Pair {
        Pair {
            client: dtls::ClientConnection::new_with_versions(
                client.clone(),
                server_name(),
                client_versions,
            )
            .unwrap(),
            server: dtls::ServerConnection::new_with_versions(
                server.clone(),
                PEER,
                server_versions,
            )
            .unwrap(),
        }
    }

    fn assert_v12(pair: &Pair) {
        for common in [
            &**pair.client as &browntls_core::CommonState,
            &**pair.server,
        ] {
            assert_eq!(common.protocol_version(), Some(ProtocolVersion::DTLSv1_2));
            assert_eq!(common.handshake_kind(), Some(HandshakeKind::Full));
            assert!(!common.is_handshaking());
        }
        assert_eq!(pair.client.tls13_tickets_received(), 0);
    }

    #[test]
    fn stateless_acceptor_challenges_a_fragmented_initial_dtls12_hello() {
        let chain = server_chain(KeyType::EcdsaP256);
        let mut config = client_config(&chain);
        config.alpn_protocols = vec![vec![b'x'; 230], vec![b'y'; 230]];
        let mut client = dtls::ClientConnection::new_with_versions(
            Arc::new(config),
            server_name(),
            dtls::Versions::V1_2,
        )
        .unwrap();
        client.set_mtu(256).unwrap();
        let acceptor = dtls::Acceptor::new_with_versions(
            Arc::new(dtls_server_config(&chain)),
            dtls::Versions::V1_2,
        )
        .unwrap();
        let now = Duration::from_secs(1);
        let mut first = Vec::new();
        assert!(client.write_datagram(&mut first, now).unwrap());
        let first_len = first.len();
        let mut second = Vec::new();
        assert!(client.write_datagram(&mut second, now).unwrap());
        let mut challenge = Vec::new();
        assert!(matches!(
            acceptor
                .accept(&mut second, PEER, &mut challenge, now)
                .unwrap(),
            dtls::Accepted::Ignored
        ));
        assert!(challenge.is_empty());
        assert!(matches!(
            acceptor
                .accept(&mut first, PEER, &mut challenge, now)
                .unwrap(),
            dtls::Accepted::Retry
        ));
        assert!(challenge.len() <= first_len);
        client.read_datagram(&mut challenge, now).unwrap();
        let mut answer = Vec::new();
        assert!(client.write_datagram(&mut answer, now).unwrap());
        let dtls::Accepted::Connection(server) = acceptor
            .accept(&mut answer, PEER, &mut Vec::new(), now)
            .unwrap()
        else {
            panic!("the retry cookie must allow allocation before the final fragment");
        };
        let mut pair = Pair {
            client,
            server: *server,
        };
        pair.handshake(&mut Sim::perfect()).unwrap();
        assert_v12(&pair);
    }

    #[test]
    fn endpoint_policy_negotiates_highest_mutual_version() {
        use dtls::Versions::{V1_2, V1_2And1_3, V1_3};
        let chain = server_chain(KeyType::EcdsaP256);
        let client = Arc::new(client_config(&chain));
        let server = Arc::new(dtls_server_config(&chain));
        for (c, s) in [
            (V1_2, V1_2),
            (V1_2And1_3, V1_2),
            (V1_2, V1_2And1_3),
            (V1_3, V1_2And1_3),
            (V1_2And1_3, V1_3),
            (V1_2And1_3, V1_2And1_3),
        ] {
            let mut pair = make_pair(&client, &server, c, s);
            let mut sim = Sim::perfect();
            pair.handshake(&mut sim).unwrap();
            if c == V1_2 || s == V1_2 {
                assert_v12(&pair);
            } else {
                assert_dtls13(&pair);
            }
            pair.exchange(&mut sim, "negotiated endpoint policy");
        }
    }

    #[test]
    fn every_existing_ecdhe_aead_suite_with_mutual_certificates() {
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
            let mut provider = (*provider()).clone();
            provider.cipher_suites = vec![suite];
            let client = Arc::new(
                ClientConfig::builder_with_provider(Arc::new(provider.clone()))
                    .with_protocol_versions(&[&version::TLS12])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
                    .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
                    .unwrap(),
            );
            let mut server = ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&version::TLS12])
                .unwrap()
                .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
                .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
                .unwrap();
            server.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
            let server = Arc::new(server);
            let mut pair = make_pair(&client, &server, dtls::Versions::V1_2, dtls::Versions::V1_2);
            pair.client.set_mtu(300).unwrap();
            pair.server.set_mtu(300).unwrap();
            let mut sim = Sim::perfect();
            pair.handshake(&mut sim)
                .unwrap_or_else(|e| panic!("{suite:?}: {e:?}"));
            assert_v12(&pair);
            assert_eq!(
                pair.server.peer_certificates().unwrap(),
                client_chain.cert_chain()
            );
            assert_eq!(
                pair.client.peer_certificates().unwrap(),
                server_chain.cert_chain()
            );
            let mut client_export = [0; 32];
            let mut server_export = [0; 32];
            pair.client
                .export_keying_material(&mut client_export, b"dtls12 test", None)
                .unwrap();
            pair.server
                .export_keying_material(&mut server_export, b"dtls12 test", None)
                .unwrap();
            assert_eq!(client_export, server_export);
            pair.exchange(&mut sim, "mutually authenticated");
        }
    }

    #[test]
    fn lost_reordered_and_duplicated_flights_recover() {
        let chain = server_chain(KeyType::EcdsaP256);
        let client = Arc::new(client_config(&chain));
        let server = Arc::new(dtls_server_config(&chain));
        for lost in 0..8 {
            let mut pair = make_pair(&client, &server, dtls::Versions::V1_2, dtls::Versions::V1_2);
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
            let mut sim = Sim::new(Link::new(policy), Link::new(policy));
            pair.handshake(&mut sim)
                .unwrap_or_else(|e| panic!("loss {lost}: {e:?}"));
            assert_v12(&pair);
            pair.exchange(&mut sim, "after flight recovery");
        }
    }

    #[test]
    fn resumption_is_opt_in_and_application_replays_are_dropped() {
        let chain = server_chain(KeyType::EcdsaP256);
        let client = Arc::new(client_config(&chain));
        let server = Arc::new(dtls_server_config(&chain));
        for _ in 0..2 {
            let mut pair = make_pair(&client, &server, dtls::Versions::V1_2, dtls::Versions::V1_2);
            let mut sim = Sim::perfect();
            pair.handshake(&mut sim).unwrap();
            assert_v12(&pair);
            let mut data = Vec::new();
            pair.client.send(b"once", &mut data).unwrap();
            let mut duplicate = data.clone();
            assert_eq!(
                pair.server
                    .read_datagram(&mut data, sim.now)
                    .unwrap()
                    .app_data()
                    .len(),
                1
            );
            assert!(
                pair.server
                    .read_datagram(&mut duplicate, sim.now)
                    .unwrap()
                    .app_data()
                    .is_empty()
            );
        }
    }

    #[test]
    fn stateless_acceptor_binds_the_cookie_to_the_address() {
        let chain = server_chain(KeyType::EcdsaP256);
        let config = Arc::new(dtls_server_config(&chain));
        let acceptor = dtls::Acceptor::new_with_versions(config, dtls::Versions::V1_2).unwrap();
        let mut client = dtls::ClientConnection::new_with_versions(
            Arc::new(client_config(&chain)),
            server_name(),
            dtls::Versions::V1_2,
        )
        .unwrap();
        let now = Duration::from_secs(1000);
        let mut first = Vec::new();
        client.write_datagram(&mut first, now).unwrap();
        let mut reply = Vec::new();
        assert!(matches!(
            acceptor.accept(&mut first, PEER, &mut reply, now).unwrap(),
            dtls::Accepted::Retry
        ));
        client.read_datagram(&mut reply, now).unwrap();
        let mut second = Vec::new();
        client.write_datagram(&mut second, now).unwrap();
        assert!(matches!(
            acceptor
                .accept(&mut second.clone(), b"other address", &mut Vec::new(), now)
                .unwrap(),
            dtls::Accepted::Ignored
        ));
        let dtls::Accepted::Connection(server) = acceptor
            .accept(&mut second, PEER, &mut Vec::new(), now)
            .unwrap()
        else {
            panic!("valid cookie refused")
        };
        let mut pair = Pair {
            client,
            server: *server,
        };
        let mut sim = Sim::perfect();
        pair.handshake(&mut sim).unwrap();
        assert_v12(&pair);
    }

    #[test]
    fn required_client_certificate_and_server_verification_are_preserved() {
        let chain = server_chain(KeyType::EcdsaP256);
        let expected_client = client_chain(KeyType::EcdsaP256);
        let client = Arc::new(client_config(&chain));
        let mut server = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(PinnedClientVerifier::new(&expected_client, true))
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        server.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
        let mut pair = make_pair(
            &client,
            &Arc::new(server),
            dtls::Versions::V1_2,
            dtls::Versions::V1_2,
        );
        assert!(matches!(
            pair.handshake(&mut Sim::perfect()),
            Err(Failure::Server(_))
        ));
        assert!(pair.server.is_handshaking());

        let untrusted = server_chain(KeyType::EcdsaP384);
        let server = Arc::new(dtls_server_config(&untrusted));
        let mut pair = make_pair(&client, &server, dtls::Versions::V1_2, dtls::Versions::V1_2);
        assert!(matches!(
            pair.handshake(&mut Sim::perfect()),
            Err(Failure::Client(_))
        ));
        assert!(pair.client.is_handshaking());
    }

    #[test]
    fn default_policy_and_timeouts_do_not_downgrade() {
        let chain = server_chain(KeyType::EcdsaP256);
        let config = Arc::new(client_config(&chain));
        let server = Arc::new(dtls_server_config(&chain));
        let mut pair = Pair {
            client: dtls::ClientConnection::new(config.clone(), server_name()).unwrap(),
            server: dtls::ServerConnection::new_with_versions(
                server.clone(),
                PEER,
                dtls::Versions::V1_2,
            )
            .unwrap(),
        };
        assert!(pair.handshake(&mut Sim::perfect()).is_err());
        let mut pair = make_pair(
            &config,
            &server,
            dtls::Versions::V1_2And1_3,
            dtls::Versions::V1_2And1_3,
        );
        let mut sim = Sim::new(Link::new(|_, _| Fate::Drop), Link::perfect());
        assert!(pair.handshake(&mut sim).is_err());
        assert_eq!(pair.client.protocol_version(), None);
    }
    include!("dtls12_resumption.rs");
}
