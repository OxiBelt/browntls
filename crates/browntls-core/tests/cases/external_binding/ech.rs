// Encrypted Client Hello (RFC 9849): the values go in the ClientHelloInner
// only. The HPKE suites are the native provider's.

mod ech {
    use super::*;
    use browntls_core::crypto::native::hpke::{
        ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128,
    };
    use browntls_core::ech::{
        EchConfig, EchGreaseConfig, EchMode, EchServerConfig, EchServerKey, EchStatus,
    };

    fn ech_keys(config_id: u8) -> Arc<EchServerConfig> {
        let key =
            EchServerKey::generate(config_id, "public.example", 32, ALL_SUPPORTED_SUITES).unwrap();
        Arc::new(EchServerConfig::new(vec![key]).unwrap())
    }

    fn ech_pair(
        chain: &Chain,
        mode: EchMode,
        keys: &Arc<EchServerConfig>,
        (client_requires, server_requires): (bool, bool),
    ) -> (ClientConnection, ServerConnection) {
        let v = ProtocolVersion::TLSv1_3;
        let (mut c, mut s) = pair();
        c.require_peer_support = client_requires;
        s.require_peer_support = server_requires;
        let mut client = client_for(chain, v, Some(c));
        client.ech_mode = Some(mode);
        let mut server = server_for(chain, v, Some(s));
        server.ech = Some(keys.clone());
        connect(client, server)
    }

    #[test]
    fn the_values_are_inner_only() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let keys = ech_keys(7);
        let mode =
            EchMode::Enable(EchConfig::new(keys.ech_config_list(), ALL_SUPPORTED_SUITES).unwrap());
        let (mut client, mut server) = ech_pair(&chain, mode, &keys, (true, true));
        let outer = flight(&mut client);
        assert_eq!(extension(&outer, EXT_EXTERNAL_ID_HASH), None);
        assert_eq!(extension(&outer, EXT_EXTERNAL_SESSION_ID), None);
        feed(&mut server, &outer);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.ech_status(), EchStatus::Accepted);
        // The server read them from the inner hello.
        assert_eq!(server.peer_external_session_id(), Some(&tls_id("client")));
        assert_eq!(server.peer_external_id_hash(), Some(&hash(1)));
        assert_eq!(client.peer_external_session_id(), Some(&tls_id("server")));
    }

    #[test]
    fn a_grease_offer_sends_them_in_the_clear() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
        // The server, which holds ECH keys, sees a rejected offer and checks
        // the ClientHello it answers: the real one.
        let (mut client, mut server) =
            ech_pair(&chain, EchMode::Grease(grease), &ech_keys(7), (true, true));
        let hello = flight(&mut client);
        assert!(extension(&hello, EXT_EXTERNAL_SESSION_ID).is_some());
        feed(&mut server, &hello);
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(server.ech_status(), EchStatus::Rejected);
        assert_eq!(client.peer_external_session_id(), Some(&tls_id("server")));
        assert_eq!(server.peer_external_session_id(), Some(&tls_id("client")));
    }

    #[test]
    fn a_rejection_still_delivers_the_retry_configurations() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let stale = ech_keys(1);
        let current = ech_keys(2);
        let mode =
            EchMode::Enable(EchConfig::new(stale.ech_config_list(), ALL_SUPPORTED_SUITES).unwrap());
        // The client requires support, but the handshake with the outer
        // hello, which carries neither extension, ends with ech_required,
        // not missing_extension.
        let (mut client, mut server) = ech_pair(&chain, mode.clone(), &current, (true, false));
        let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(client.ech_status(), EchStatus::Rejected);
        assert_eq!(
            server_res,
            Err(Error::AlertReceived(
                AlertDescription::EncryptedClientHelloRequired
            ))
        );
        let Err(Error::RejectedEch(rejected)) = client_res else {
            panic!("{client_res:?}");
        };
        assert_eq!(rejected.retry_configs(), Some(current.ech_config_list()));
        assert_eq!(server.peer_external_session_id(), None);

        // A server that requires support cannot tell this outer hello from
        // a GREASE client's real one, and keeps refusing a client without
        // the extensions: no retry configurations then.
        let (mut client, mut server) = ech_pair(&chain, mode, &current, (true, true));
        let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            server_res,
            Err(Error::PeerIncompatible(
                PeerIncompatible::ExternalIdHashExtensionRequired
            ))
        );
        assert_eq!(
            client_res,
            Err(Error::AlertReceived(AlertDescription::MissingExtension))
        );
    }

    #[test]
    fn a_rejection_at_the_retry_keeps_them_out_of_the_second_hello() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let stale = ech_keys(1);
        let (c, s) = pair();
        let mut client = client_for(&chain, ProtocolVersion::TLSv1_3, Some(c));
        client.ech_mode = Some(EchMode::Enable(
            EchConfig::new(stale.ech_config_list(), ALL_SUPPORTED_SUITES).unwrap(),
        ));
        // Only P-256: the server asks for a retry, and rejects the offer
        // in its HelloRetryRequest.
        let mut server = p256_server(&chain, Some(s));
        server.ech = Some(ech_keys(2));
        let (mut client, mut server) = connect(client, server);
        let first = flight(&mut client);
        assert_eq!(extension(&first, EXT_EXTERNAL_SESSION_ID), None);
        feed(&mut server, &first);
        server.process_new_packets().unwrap();
        feed(&mut client, &flight(&mut server));
        client.process_new_packets().unwrap();
        assert_eq!(client.ech_status(), EchStatus::Rejected);
        // The second ClientHello follows the outer one: neither extension.
        let second = flight(&mut client);
        assert!(extension(&second, 0x0000).is_some());
        assert_eq!(extension(&second, EXT_EXTERNAL_ID_HASH), None);
        assert_eq!(extension(&second, EXT_EXTERNAL_SESSION_ID), None);
        feed(&mut server, &second);
        let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
        assert!(
            matches!(&client_res, Err(Error::RejectedEch(r)) if r.can_retry()),
            "{client_res:?}"
        );
        assert_eq!(
            client.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(server.peer_external_session_id(), None);
    }
}
