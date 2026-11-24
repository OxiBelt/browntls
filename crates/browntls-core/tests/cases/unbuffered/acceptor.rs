// Cases included by `cases/unbuffered.rs`, which holds the imports and the
// shared plumbing: `UnbufferedAcceptor`, which reads the ClientHello from the
// caller's buffer before the configuration is chosen.

mod acceptor {
    use std::mem;

    use browntls_core::server::{
        Acceptor, ClientHello, UnbufferedAcceptedAlert, UnbufferedAcceptor,
    };
    use browntls_core::{AlertDescription, InvalidMessage, PeerMisbehaved};

    use super::*;

    /// Chooses the configuration for a ClientHello.
    type Chooser = Box<dyn FnMut(&ClientHello<'_>) -> Arc<ServerConfig>>;

    #[test]
    fn rfc9973_offer_drives_unbuffered_config_selection() {
        use browntls_core::crypto::hash::HashAlgorithm;
        use browntls_core::psk::ExternalPsk;

        let chain = server_chain(KeyType::EcdsaP256);
        let version = ProtocolVersion::TLSv1_3;
        let key = Arc::new(
            ExternalPsk::new(
                b"lazy-rfc9973".to_vec(),
                vec![42; 32],
                HashAlgorithm::SHA256,
            )
            .unwrap(),
        );
        let mut client = versioned_client(&chain, version);
        client.external_psks = vec![key.clone()];
        client.cert_with_extern_psk = true;
        let mut server = versioned_server(&chain, version);
        server.external_psks = Some(Arc::new(vec![key]));
        server.require_cert_with_extern_psk = true;
        let config = Arc::new(server);
        let mut server = Accepting::new(Feed::Whole, move |hello| {
            assert!(hello.offers_cert_with_extern_psk());
            config.clone()
        });

        let mut client = ub_client(&Arc::new(client), Feed::Whole);
        handshake(&mut client, &mut server);
        assert!(client.conn.negotiated_cert_with_extern_psk());
        assert!(server.server().conn.negotiated_cert_with_extern_psk());
        exchange(&mut client, &mut server, b"lazy RFC 9973");
    }

    #[test]
    fn rfc10024_hybrids_through_direct_and_acceptor_paths() {
        let chain = server_chain(KeyType::EcdsaP256);
        for group in [
            prov::kx_group::X25519MLKEM768,
            prov::kx_group::SECP256R1MLKEM768,
            prov::kx_group::SECP384R1MLKEM1024,
        ] {
            let mut provider = prov::default_provider();
            provider.kx_groups = vec![group];
            let provider = Arc::new(provider);
            let cc = Arc::new(
                ClientConfig::builder_with_provider(provider.clone())
                    .with_protocol_versions(&[&version::TLS13])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
                    .with_no_client_auth(),
            );
            let sc = Arc::new(
                ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&version::TLS13])
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(chain.cert_chain(), chain.private_key())
                    .unwrap(),
            );

            let mut client = ub_client(&cc, Feed::Whole);
            let mut server = ub_server(&sc, Feed::Whole);
            handshake(&mut client, &mut server);
            assert_eq!(
                client.conn.negotiated_key_exchange_group().unwrap().name(),
                group.name()
            );
            assert_eq!(
                server.conn.negotiated_key_exchange_group().unwrap().name(),
                group.name()
            );
            exchange(&mut client, &mut server, b"direct RFC 10024");

            let mut client = ub_client(&cc, Feed::Whole);
            let mut server = Accepting::with(Feed::Whole, &sc);
            handshake(&mut client, &mut server);
            assert_eq!(
                client.conn.negotiated_key_exchange_group().unwrap().name(),
                group.name()
            );
            assert_eq!(
                server
                    .server()
                    .conn
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                group.name()
            );
            exchange(&mut client, &mut server, b"acceptor RFC 10024");
        }
    }

    /// An unbuffered server that reads the ClientHello with an
    /// `UnbufferedAcceptor`, chooses its configuration from it, then goes on
    /// as an `UnbufferedServerConnection` with the bytes not discarded.
    struct Accepting {
        acceptor: UnbufferedAcceptor,
        choose: Chooser,
        feed: Feed,
        incoming: Vec<u8>,
        /// The server name and ALPN protocols the ClientHello offered.
        hello: Option<(Option<String>, Vec<Vec<u8>>)>,
        server: Option<UbServer>,
        /// The encoded alert after a refusal, until taken.
        alert: Vec<u8>,
        error: Option<Error>,
        /// Bytes after the ClientHello handed from the acceptor's buffer
        /// to the connection's.
        carried: usize,
    }

    impl Accepting {
        fn new(
            feed: Feed,
            choose: impl FnMut(&ClientHello<'_>) -> Arc<ServerConfig> + 'static,
        ) -> Self {
            Self {
                acceptor: UnbufferedAcceptor::default(),
                choose: Box::new(choose),
                feed,
                incoming: Vec::new(),
                hello: None,
                server: None,
                alert: Vec::new(),
                error: None,
                carried: 0,
            }
        }

        fn with(feed: Feed, config: &Arc<ServerConfig>) -> Self {
            let config = config.clone();
            Self::new(feed, move |_| config.clone())
        }

        fn server(&mut self) -> &mut UbServer {
            self.server.as_mut().expect("accepted")
        }

        /// One `accept` over `incoming`; true once the acceptor is done.
        fn accept(&mut self) -> bool {
            let status = self.acceptor.accept(&mut self.incoming);
            self.incoming.drain(..status.discard);
            let accepted = match status.state {
                Ok(None) => return false,
                Ok(Some(accepted)) => accepted,
                Err((err, mut alert)) => {
                    self.alert = encode_alert(&mut alert);
                    self.error = Some(err);
                    return true;
                }
            };
            let hello = accepted.client_hello();
            self.hello = Some((
                hello.server_name().map(str::to_owned),
                hello
                    .alpn()
                    .map(|alpn| alpn.map(<[u8]>::to_vec).collect())
                    .unwrap_or_default(),
            ));
            let config = (self.choose)(&hello);
            match accepted.into_connection(config) {
                Ok(conn) => {
                    let mut server = Unbuffered::new(conn, self.feed);
                    // What followed the ClientHello (0-RTT data, say).
                    server.incoming = mem::take(&mut self.incoming);
                    self.carried = server.incoming.len();
                    server.run();
                    self.server = Some(server);
                }
                Err((err, mut alert)) => {
                    self.alert = encode_alert(&mut alert);
                    self.error = Some(err);
                }
            }
            true
        }
    }

    impl Endpoint for Accepting {
        fn take_output(&mut self) -> Vec<u8> {
            match &mut self.server {
                Some(server) => server.take_output(),
                None => mem::take(&mut self.alert),
            }
        }

        fn give_input(&mut self, bytes: &[u8]) {
            if let Some(server) = &mut self.server {
                return server.give_input(bytes);
            }
            if self.error.is_some() {
                return;
            }
            match self.feed {
                Feed::Whole => {
                    self.incoming.extend_from_slice(bytes);
                    self.accept();
                }
                Feed::ByteByByte => {
                    for (i, &byte) in bytes.iter().enumerate() {
                        self.incoming.push(byte);
                        if self.accept() {
                            if let Some(server) = &mut self.server {
                                server.give_input(&bytes[i + 1..]);
                            }
                            return;
                        }
                    }
                }
            }
        }

        fn failed(&self) -> bool {
            self.error.is_some() || self.server.as_ref().is_some_and(|s| s.failed())
        }

        fn describe(&self) -> String {
            match &self.server {
                Some(server) => server.describe(),
                None => format!("acceptor: {:?}", self.error),
            }
        }

        fn handshaking(&self) -> bool {
            self.server.as_ref().is_none_or(|s| s.handshaking())
        }

        fn send(&mut self, data: &[u8]) {
            self.server().send(data);
        }

        fn take_received(&mut self) -> Vec<u8> {
            self.server
                .as_mut()
                .map(|s| s.take_received())
                .unwrap_or_default()
        }
    }

    /// Encodes all of `alert` starting from a one-byte buffer, so that every
    /// record goes through the `InsufficientSize` path first.
    fn encode_alert(alert: &mut UnbufferedAcceptedAlert) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1];
        while !alert.is_empty() {
            match alert.encode(&mut buf) {
                Ok(n) => {
                    assert!(n > 0);
                    out.extend_from_slice(&buf[..n]);
                }
                Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                    assert!(required_size > buf.len());
                    buf.resize(required_size, 0);
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert_eq!(alert.encode(&mut []), Ok(0));
        out
    }

    /// The (only) alert description in `records`, which must be one plaintext
    /// fatal alert record.
    fn fatal_alert(records: &[u8]) -> u8 {
        assert_eq!(records.len(), 7, "one alert record: {records:?}");
        assert_eq!(records[0], 0x15, "an alert record");
        assert_eq!(&records[3..5], [0, 2]);
        assert_eq!(records[5], 2, "fatal");
        records[6]
    }

    /// The buffered `Acceptor` fed `bytes` (the model): its error and the
    /// alert bytes it writes.
    fn buffered_refusal(bytes: &[u8], config: Option<Arc<ServerConfig>>) -> (Error, Vec<u8>) {
        let mut acceptor = Acceptor::default();
        let mut rest = bytes;
        let refusal = loop {
            acceptor.read_tls(&mut rest).unwrap();
            match acceptor.accept() {
                Ok(None) if rest.is_empty() => panic!("the buffered acceptor wants more"),
                Ok(None) => {}
                Ok(Some(accepted)) => {
                    let config = config.expect("refused before a configuration");
                    break accepted.into_connection(config).map(|_| ()).unwrap_err();
                }
                Err(refusal) => break refusal,
            }
        };
        let (err, mut alert) = refusal;
        let mut out = Vec::new();
        alert.write_all(&mut out).unwrap();
        (err, out)
    }

    /// An `UnbufferedAcceptor` fed `bytes`: its error, the alert, and the
    /// bytes it discarded in all.
    fn unbuffered_refusal(
        bytes: &[u8],
        feed: Feed,
        config: Option<Arc<ServerConfig>>,
    ) -> (Error, Vec<u8>, usize) {
        let mut acceptor = UnbufferedAcceptor::new();
        let mut incoming = Vec::new();
        let mut discarded = 0;
        let step = match feed {
            Feed::Whole => bytes.len(),
            Feed::ByteByByte => 1,
        };
        let mut chunks = bytes.chunks(step);
        let (err, mut alert) = loop {
            incoming.extend_from_slice(chunks.next().expect("refused before the end"));
            let status = acceptor.accept(&mut incoming);
            discarded += status.discard;
            incoming.drain(..status.discard);
            match status.state {
                Ok(None) => {}
                Ok(Some(accepted)) => {
                    let config = config.clone().expect("refused before a configuration");
                    break accepted.into_connection(config).map(|_| ()).unwrap_err();
                }
                Err(refusal) => break refusal,
            }
        };
        let alert = encode_alert(&mut alert);
        // Spent: every later call fails, with nothing to send.
        let mut more = bytes.to_vec();
        let status = acceptor.accept(&mut more);
        assert_eq!(status.discard, 0);
        let (later, mut empty) = status.state.unwrap_err();
        assert!(matches!(later, Error::General(_)), "{later:?}");
        assert!(empty.is_empty());
        assert_eq!(empty.encode(&mut []), Ok(0));
        (err, alert, discarded)
    }

    fn client_hello_of(config: &Arc<ClientConfig>) -> Vec<u8> {
        let mut client = b_client(config);
        client.take_output()
    }

    fn alpn_client(chain: &Chain, v: ProtocolVersion, alpn: &[u8]) -> Arc<ClientConfig> {
        let mut config = versioned_client(chain, v);
        config.alpn_protocols = vec![alpn.to_vec()];
        Arc::new(config)
    }

    // ------------------------------------------------------- handshakes

    #[test]
    fn configuration_chosen_from_server_name_and_alpn() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        for v in VERSIONS {
            let mut h2 = versioned_server(&chain, v);
            h2.alpn_protocols = vec![b"h2".to_vec()];
            let mut http11 = versioned_server(&chain, v);
            http11.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (h2, http11) = (Arc::new(h2), Arc::new(http11));
            let chooser = |feed| {
                let (h2, http11) = (h2.clone(), http11.clone());
                Accepting::new(feed, move |hello: &ClientHello<'_>| {
                    assert_eq!(hello.server_name(), Some("localhost"));
                    assert!(!hello.cipher_suites().is_empty());
                    assert!(!hello.signature_schemes().is_empty());
                    let offered: Vec<&[u8]> = hello.alpn().unwrap().collect();
                    match offered[..] {
                        [b"h2"] => h2.clone(),
                        [b"http/1.1"] => http11.clone(),
                        _ => panic!("unexpected offer {offered:?}"),
                    }
                })
            };
            for feed in [Feed::Whole, Feed::ByteByByte] {
                // An unbuffered client.
                let mut c = ub_client(&alpn_client(&chain, v, b"http/1.1"), feed);
                let mut s = chooser(feed);
                handshake(&mut c, &mut s);
                assert_eq!(s.server().conn.alpn_protocol(), Some(&b"http/1.1"[..]));
                assert_eq!(s.server().conn.protocol_version(), Some(v));
                assert_eq!(s.server().conn.server_name(), Some("localhost"));
                assert_eq!(
                    s.hello,
                    Some((Some("localhost".into()), vec![b"http/1.1".to_vec()]))
                );
                exchange(&mut c, &mut s, &big_payload());

                // A buffered client.
                let mut c = b_client(&alpn_client(&chain, v, b"h2"));
                let mut s = chooser(feed);
                handshake(&mut c, &mut s);
                assert_eq!(c.conn.alpn_protocol(), Some(&b"h2"[..]));
                assert_eq!(s.server().conn.alpn_protocol(), Some(&b"h2"[..]));
                exchange(&mut c, &mut s, &big_payload());
                c.conn.send_close_notify();
                pump(&mut c, &mut s);
                assert!(s.server().peer_closed);

                // A rustls client.
                let mut c = rustls_client(&chain, v, b"http/1.1");
                let mut s = chooser(feed);
                handshake(&mut c, &mut s);
                assert_eq!(s.server().conn.alpn_protocol(), Some(&b"http/1.1"[..]));
                exchange(&mut c, &mut s, &big_payload());
            }
        }
    }

    #[test]
    fn sessions_resume_through_the_acceptor() {
        init_logging();
        let chain = server_chain(KeyType::Ed25519);
        for v in VERSIONS {
            for feed in [Feed::Whole, Feed::ByteByByte] {
                let cc = Arc::new(versioned_client(&chain, v));
                let sc = Arc::new(versioned_server(&chain, v));
                let mut c = ub_client(&cc, feed);
                let mut s = Accepting::with(feed, &sc);
                handshake(&mut c, &mut s);
                exchange(&mut c, &mut s, b"first");
                assert_eq!(s.server().conn.handshake_kind(), Some(HandshakeKind::Full));

                let mut c = ub_client(&cc, feed);
                let mut s = Accepting::with(feed, &sc);
                handshake(&mut c, &mut s);
                assert_eq!(c.conn.handshake_kind(), Some(HandshakeKind::Resumed));
                assert_eq!(
                    s.server().conn.handshake_kind(),
                    Some(HandshakeKind::Resumed)
                );
                exchange(&mut c, &mut s, b"resumed");
            }
        }
    }

    #[test]
    fn early_data_is_read_in_place_after_the_acceptor() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let (cc, sc) = early_data_configs(&chain, 1024);
        for feed in [Feed::Whole, Feed::ByteByByte] {
            // From an unbuffered client: with whole input, the 0-RTT records
            // arrive with the ClientHello and are left for the connection.
            prime(&cc, &sc);
            let mut c = ub_client(&cc, feed);
            c.early_to_send = b"GET /idempotent".to_vec();
            let mut s = Accepting::with(feed, &sc);
            handshake(&mut c, &mut s);
            assert!(c.conn.is_early_data_accepted());
            assert_eq!(s.server().received_early, b"GET /idempotent");
            assert!(s.server().states.contains(&"ReadEarlyData"));
            assert_eq!(
                s.carried > 0,
                feed == Feed::Whole,
                "0-RTT records carried over"
            );
            assert!(s.server().received.is_empty());
            exchange(&mut c, &mut s, b"1-RTT");

            // From a buffered client.
            prime(&cc, &sc);
            let mut c = b_client(&cc);
            c.conn
                .early_data()
                .unwrap()
                .write_all(b"early to the acceptor")
                .unwrap();
            let mut s = Accepting::with(feed, &sc);
            handshake(&mut c, &mut s);
            assert!(c.conn.is_early_data_accepted());
            assert_eq!(s.server().received_early, b"early to the acceptor");
            exchange(&mut c, &mut s, b"after");
        }
    }

    #[test]
    fn external_psk_early_data_policy_applies_to_deferred_accept() {
        use browntls_core::CipherSuite;
        use browntls_core::crypto::hash::HashAlgorithm;
        use browntls_core::pki_types::UnixTime;
        use browntls_core::psk::{
            ExternalPsk, ExternalPskReplayDecision, ExternalPskReplayKey, ExternalPskReplayPolicy,
        };
        use std::sync::Mutex;
        use std::time::Duration;

        #[derive(Debug, Default)]
        struct OneMark(Mutex<Option<Vec<u8>>>);

        impl ExternalPskReplayPolicy for OneMark {
            fn check_and_mark(
                &self,
                key: &ExternalPskReplayKey,
                _expires_at: UnixTime,
            ) -> ExternalPskReplayDecision {
                let mut mark = self.0.lock().unwrap();
                if mark.is_some() {
                    return ExternalPskReplayDecision::Unavailable;
                }
                *mark = Some(key.as_ref().to_vec());
                ExternalPskReplayDecision::FirstUse
            }
        }

        let chain = server_chain(KeyType::EcdsaP256);
        let psk = Arc::new(
            ExternalPsk::new(b"external".to_vec(), vec![0x73; 32], HashAlgorithm::SHA256)
                .unwrap()
                .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)
                .with_early_data(1024)
                .with_early_data_expiry(UnixTime::since_unix_epoch(Duration::from_secs(u64::MAX)))
                .imported(b"unit-test".to_vec())
                .unwrap(),
        );
        let mut cc = versioned_client(&chain, ProtocolVersion::TLSv1_3);
        cc.external_psks.push(psk.clone());
        cc.enable_early_data = true;
        let cc = Arc::new(cc);
        for (accept, feed) in [(true, Feed::Whole), (false, Feed::ByteByByte)] {
            let mut sc = versioned_server(&chain, ProtocolVersion::TLSv1_3);
            sc.external_psks = Some(Arc::new(vec![psk.clone()]));
            sc.send_tls13_tickets = 0;
            let policy = Arc::new(OneMark::default());
            if accept {
                sc.external_psk_replay_policy = Some(policy.clone());
            }
            let sc = Arc::new(sc);
            let mut client = ub_client(&cc, feed);
            let mut server = Accepting::with(feed, &sc);
            client.early_to_send = b"early".to_vec();
            handshake(&mut client, &mut server);
            assert_eq!(client.conn.is_early_data_accepted(), accept);
            assert_eq!(policy.0.lock().unwrap().is_some(), accept);
            let expected: &[u8] = if accept { b"early" } else { &[] };
            assert_eq!(server.server().received_early, expected);
            exchange(&mut client, &mut server, b"ordinary");
        }
    }

    /// A server that only speaks P-256, so that a client offering X25519
    /// first is sent a HelloRetryRequest, with stateless cookies.
    fn retrying_server(chain: &Chain) -> Arc<ServerConfig> {
        let mut provider = prov::default_provider();
        provider.kx_groups = vec![prov::kx_group::SECP256R1];
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        config.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
        Arc::new(config)
    }

    fn retrying_client(chain: &Chain) -> Arc<ClientConfig> {
        let mut provider = prov::default_provider();
        provider.kx_groups = vec![prov::kx_group::X25519, prov::kx_group::SECP256R1];
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
                .with_no_client_auth(),
        )
    }

    const CCS: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

    /// The `cookie` extension type (RFC 9846 §4.3.2).
    const COOKIE: u16 = 44;

    /// Where the body of extension `typ` starts in `record`, a handshake
    /// record holding a whole ClientHello.
    fn extension_body(record: &[u8], typ: u16) -> usize {
        let u16_at = |at: usize| usize::from(u16::from_be_bytes([record[at], record[at + 1]]));
        assert_eq!(record[0], 0x16);
        assert_eq!(record[5], 0x01, "a ClientHello");
        // Record and handshake headers, legacy_version and random.
        let mut at = 5 + 4 + 2 + 32;
        at += 1 + usize::from(record[at]); // legacy_session_id
        at += 2 + u16_at(at); // cipher_suites
        at += 1 + usize::from(record[at]); // legacy_compression_methods
        let end = at + 2 + u16_at(at);
        at += 2;
        while at < end {
            let len = u16_at(at + 2);
            if u16_at(at) == usize::from(typ) {
                return at + 4;
            }
            at += 4 + len;
        }
        panic!("no extension {typ}");
    }

    /// The client's second flight after a HelloRetryRequest from an
    /// acceptor-made server, with a change_cipher_spec in front if
    /// `with_ccs`.
    fn after_retry(
        client: &mut UbClient,
        config: &Arc<ServerConfig>,
        feed: Feed,
        with_ccs: bool,
    ) -> Vec<u8> {
        let mut first = Accepting::with(feed, config);
        first.give_input(&client.take_output());
        let retry = first.take_output();
        assert!(!first.failed(), "{}", first.describe());
        client.give_input(&retry);
        let second = client.take_output();
        let start = if second.starts_with(&CCS) {
            CCS.len()
        } else {
            0
        };
        let mut flight = if with_ccs { CCS.to_vec() } else { Vec::new() };
        flight.extend_from_slice(&second[start..]);
        flight
    }

    #[test]
    fn stateless_retry_continues_in_a_fresh_acceptor() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let config = retrying_server(&chain);
        for feed in [Feed::Whole, Feed::ByteByByte] {
            for with_ccs in [false, true] {
                // A fresh client configuration: a resumed one would offer
                // the server's group at once.
                let mut c = ub_client(&retrying_client(&chain), feed);
                let flight = after_retry(&mut c, &config, feed, with_ccs);
                // No state survives the first server: a fresh acceptor
                // continues from the cookie.
                let mut s = Accepting::with(feed, &config);
                s.give_input(&flight);
                handshake(&mut c, &mut s);
                for kind in [c.conn.handshake_kind(), s.server().conn.handshake_kind()] {
                    assert_eq!(kind, Some(HandshakeKind::FullWithHelloRetryRequest));
                }
                exchange(&mut c, &mut s, b"stateless");
            }
        }
    }

    #[test]
    fn tampered_retry_cookie_is_refused_after_the_acceptor() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let config = retrying_server(&chain);
        for feed in [Feed::Whole, Feed::ByteByByte] {
            let mut c = ub_client(&retrying_client(&chain), feed);
            let mut flight = after_retry(&mut c, &config, feed, true);
            let cookie = extension_body(&flight[CCS.len()..], COOKIE) + CCS.len();
            // A bit inside the sealed cookie (past its two length bytes).
            flight[cookie + 2 + 8] ^= 1;
            let (err, alert, _) = unbuffered_refusal(&flight, feed, Some(config.clone()));
            assert_eq!(
                err,
                Error::PeerMisbehaved(PeerMisbehaved::InvalidHelloRetryRequestCookie)
            );
            assert_eq!(
                fatal_alert(&alert),
                u8::from(AlertDescription::IllegalParameter)
            );
            assert_eq!(
                (err, alert),
                buffered_refusal(&flight, Some(config.clone()))
            );
        }
    }

    #[test]
    fn change_cipher_spec_before_a_first_client_hello_is_refused() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let config = retrying_server(&chain);
        let mut flight = CCS.to_vec();
        flight.extend(client_hello_of(&retrying_client(&chain)));
        for feed in [Feed::Whole, Feed::ByteByByte] {
            let (err, alert, discarded) = unbuffered_refusal(&flight, feed, Some(config.clone()));
            assert_eq!(
                err,
                Error::PeerMisbehaved(PeerMisbehaved::IllegalMiddleboxChangeCipherSpec)
            );
            assert_eq!(
                fatal_alert(&alert),
                u8::from(AlertDescription::UnexpectedMessage)
            );
            assert_eq!(discarded, flight.len());
            assert_eq!(
                (err.clone(), alert.clone()),
                buffered_refusal(&flight, Some(config.clone()))
            );

            // As a connection created with the configuration refuses it.
            let mut s = ub_server(&config, feed);
            s.give_input(&flight);
            assert_eq!(s.error, Some(err));
            assert_eq!(s.take_output(), alert);
        }
    }

    // ------------------------------------------------------------ refusals

    include!("acceptor_refusals.rs");

    // ------------------------------------------------------------ rustls

    /// A rustls 0.23 client on the buffered API.
    struct RustlsClient {
        conn: rustls::ClientConnection,
        received: Vec<u8>,
        failed: bool,
    }

    fn rustls_client(chain: &Chain, v: ProtocolVersion, alpn: &[u8]) -> RustlsClient {
        use rustls_pki_types as rpki;
        static R_TLS12: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
        static R_TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
        let versions: &[&rustls::SupportedProtocolVersion] = match v {
            ProtocolVersion::TLSv1_2 => &R_TLS12,
            _ => &R_TLS13,
        };
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rpki::CertificateDer::from(chain.ca.as_ref().to_vec()))
            .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        RustlsClient {
            conn: rustls::ClientConnection::new(
                Arc::new(config),
                rpki::ServerName::try_from("localhost").unwrap(),
            )
            .unwrap(),
            received: Vec::new(),
            failed: false,
        }
    }

    impl Endpoint for RustlsClient {
        fn take_output(&mut self) -> Vec<u8> {
            let mut out = Vec::new();
            while self.conn.wants_write() {
                self.conn.write_tls(&mut out).unwrap();
            }
            out
        }

        fn give_input(&mut self, mut bytes: &[u8]) {
            while !bytes.is_empty() && !self.failed {
                self.conn.read_tls(&mut bytes).unwrap();
                if self.conn.process_new_packets().is_err() {
                    self.failed = true;
                }
                match self.conn.reader().read_to_end(&mut self.received) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("read: {e}"),
                }
            }
        }

        fn failed(&self) -> bool {
            self.failed
        }

        fn describe(&self) -> String {
            format!("rustls failed: {}", self.failed)
        }

        fn handshaking(&self) -> bool {
            self.conn.is_handshaking()
        }

        fn send(&mut self, data: &[u8]) {
            self.conn.writer().write_all(data).unwrap();
        }

        fn take_received(&mut self) -> Vec<u8> {
            mem::take(&mut self.received)
        }
    }

    // --------------------------------------------------------------- ECH

    /// Encrypted Client Hello (RFC 9849) needs the native provider's HPKE.
    #[cfg(feature = "native")]
    mod ech {
        use browntls_core::RootCertStore;
        use browntls_core::client::WebPkiServerVerifier;
        use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
        use browntls_core::ech::{EchConfig, EchMode, EchServerConfig, EchServerKey, EchStatus};
        use browntls_core::pki_types::ServerName;
        use browntls_core::server::ResolvesServerCertUsingSni;
        use browntls_core::sign::CertifiedKey;

        use super::*;

        const SECRET: &str = "secret.example";
        const PUBLIC: &str = "public.example";

        #[test]
        fn encrypted_client_hello_is_accepted_after_the_acceptor() {
            init_logging();
            let purpose = rcgen::ExtendedKeyUsagePurpose::ServerAuth;
            let secret = gen_chain(KeyType::EcdsaP256, &[SECRET], purpose.clone());
            let public = gen_chain(KeyType::Ed25519, &[PUBLIC], purpose);
            let mut resolver = ResolvesServerCertUsingSni::new();
            let mut roots = RootCertStore::empty();
            for (name, chain) in [(SECRET, &secret), (PUBLIC, &public)] {
                let key =
                    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider());
                resolver.add(name, key.unwrap()).unwrap();
                roots.add(chain.ca.clone()).unwrap();
            }
            let ech = Arc::new(
                EchServerConfig::new(vec![
                    EchServerKey::generate(7, PUBLIC, 32, ALL_SUPPORTED_SUITES).unwrap(),
                ])
                .unwrap(),
            );
            let mut server = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));
            server.ech = Some(ech.clone());
            let server = Arc::new(server);
            let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .unwrap();
            let mut client = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_webpki_verifier(verifier)
                .with_no_client_auth();
            client.ech_mode = Some(EchMode::Enable(
                EchConfig::new(ech.ech_config_list(), ALL_SUPPORTED_SUITES).unwrap(),
            ));
            let client = Arc::new(client);
            let secret_name = || ServerName::try_from(SECRET).unwrap();

            let accepting = |feed| {
                let server = server.clone();
                Accepting::new(feed, move |hello: &ClientHello<'_>| {
                    // Only the outer ClientHello is visible before the keys
                    // of a configuration decrypt the inner one.
                    assert_eq!(hello.server_name(), Some(PUBLIC));
                    server.clone()
                })
            };
            for feed in [Feed::Whole, Feed::ByteByByte] {
                let mut c =
                    Buffered::new(ClientConnection::new(client.clone(), secret_name()).unwrap());
                let mut s = accepting(feed);
                handshake(&mut c, &mut s);
                assert_eq!(c.conn.ech_status(), EchStatus::Accepted);
                assert_eq!(s.server().conn.ech_status(), EchStatus::Accepted);
                assert_eq!(s.server().conn.server_name(), Some(SECRET));
                exchange(&mut c, &mut s, b"hidden");

                let mut c = Unbuffered::new(
                    UnbufferedClientConnection::new(client.clone(), secret_name()).unwrap(),
                    feed,
                );
                let mut s = accepting(feed);
                handshake(&mut c, &mut s);
                assert_eq!(c.conn.ech_status(), EchStatus::Accepted);
                assert_eq!(s.server().conn.ech_status(), EchStatus::Accepted);
                assert_eq!(s.server().conn.server_name(), Some(SECRET));
                exchange(&mut c, &mut s, &big_payload());
            }
        }
    }
}
