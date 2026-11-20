// Cases included by `cases/trusted_ca_keys.rs` with the `tls12` feature:
// negotiation of `trusted_ca_keys` (RFC 6066 §6), on the buffered and the
// unbuffered API.

mod tls12 {
    use std::sync::Mutex;

    use browntls_core::client::{Resumption, Tls12Resumption};
    use browntls_core::server::{
        Acceptor, ClientHello, ResolvesServerCert, ResolvesServerCertUsingTrustedCaKeys,
        UnbufferedAcceptor, UnbufferedServerConnection,
    };
    use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
    use browntls_core::unbuffered::{ConnectionState, UnbufferedConnectionCommon};
    use browntls_core::{
        HandshakeKind, InvalidMessage, NamedGroup, ServerConfig, ServerConnection, SideData,
        SupportedProtocolVersion,
    };

    use super::*;

    const ALERT_DECODE_ERROR: u8 = 50;

    const TLS12: &[&SupportedProtocolVersion] = &[&version::TLS12];
    const BOTH: &[&SupportedProtocolVersion] = &[&version::TLS13, &version::TLS12];

    /// A resolver that serves one chain, records the lists it saw and
    /// acknowledges them if told to.
    #[derive(Debug)]
    struct Recording {
        key: Arc<CertifiedKey>,
        acknowledge: bool,
        seen: Mutex<Vec<Option<Vec<TrustedAuthority>>>>,
    }

    impl Recording {
        fn new(chain: &Chain, acknowledge: bool) -> Arc<Self> {
            Arc::new(Self {
                key: certified_key(chain),
                acknowledge,
                seen: Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> Vec<Option<Vec<TrustedAuthority>>> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl ResolvesServerCert for Recording {
        fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            self.seen
                .lock()
                .unwrap()
                .push(hello.trusted_ca_keys().map(<[_]>::to_vec));
            if self.acknowledge {
                hello.acknowledge_trusted_ca_keys();
            }
            Some(self.key.clone())
        }
    }

    fn certified_key(chain: &Chain) -> Arc<CertifiedKey> {
        Arc::new(
            CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap(),
        )
    }

    fn server_with(
        resolver: Arc<dyn ResolvesServerCert>,
        versions: &[&'static SupportedProtocolVersion],
    ) -> ServerConfig {
        ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver)
    }

    /// Chains A and B registered with the resolver, F its fallback.
    struct Setup {
        a: Chain,
        b: Chain,
        f: Chain,
        resolver: Arc<ResolvesServerCertUsingTrustedCaKeys>,
    }

    fn setup() -> Setup {
        let (a, b, f) = (
            server_chain(KeyType::EcdsaP256),
            server_chain(KeyType::EcdsaP256),
            server_chain(KeyType::EcdsaP256),
        );
        let fallback = Arc::new(SingleCertAndKey::from(certified_key(&f)));
        let mut resolver = ResolvesServerCertUsingTrustedCaKeys::new(fallback);
        resolver
            .add_for_root(&a.ca, sha1, certified_key(&a))
            .unwrap();
        resolver
            .add_for_root(&b.ca, sha1, certified_key(&b))
            .unwrap();
        Setup {
            a,
            b,
            f,
            resolver: Arc::new(resolver),
        }
    }

    impl Setup {
        fn client(&self, list: Option<Vec<TrustedAuthority>>) -> ClientConfig {
            client_trusting(&[&self.a, &self.b, &self.f], TLS12, list)
        }

        fn server(&self) -> ServerConfig {
            server_with(self.resolver.clone(), TLS12)
        }
    }

    /// Runs the handshake; returns the server's first flight (its
    /// ServerHello first).
    fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Vec<u8> {
        give(server, &take_flight(client));
        server.process_new_packets().unwrap();
        let flight = take_flight(server);
        give(client, &flight);
        client.process_new_packets().unwrap();
        do_handshake(client, server).unwrap();
        flight
    }

    fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
        (
            ClientConnection::new(Arc::new(client), server_name()).unwrap(),
            ServerConnection::new(Arc::new(server)).unwrap(),
        )
    }

    fn served(client: &ClientConnection) -> CertificateDer<'static> {
        client.peer_certificates().unwrap()[0].clone()
    }

    /// The client's list names B's root: the resolver serves chain B and
    /// acknowledges, the ServerHello carries the empty extension, and the
    /// client reports it.
    #[test]
    fn the_resolver_serves_the_listed_chain_and_acknowledges() {
        init_logging();
        let s = setup();
        let list = ids_for(&s.b);
        let (mut client, mut server) = connect(s.client(Some(list.clone())), s.server());

        let hello = take_flight(&mut client);
        // RFC 6066 §6: TrustedAuthorities, as the codec encodes it.
        let mut body = Vec::new();
        for id in &list {
            match id {
                TrustedAuthority::KeySha1Hash(hash) => {
                    body.push(1);
                    body.extend(hash);
                }
                TrustedAuthority::CertSha1Hash(hash) => {
                    body.push(3);
                    body.extend(hash);
                }
                other => panic!("{other:?}"),
            }
        }
        let mut expected = (body.len() as u16).to_be_bytes().to_vec();
        expected.extend(body);
        assert_eq!(trusted_ca_keys_ext(&hello, true), Some(expected));

        give(&mut server, &hello);
        server.process_new_packets().unwrap();
        let flight = take_flight(&mut server);
        assert_eq!(trusted_ca_keys_ext(&flight, false), Some(Vec::new()));
        give(&mut client, &flight);
        client.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();

        assert!(client.trusted_ca_keys_acknowledged());
        assert_eq!(served(&client), s.b.end_entity);
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    }

    /// Each identifier kind selects the chain on its own; `pre_agreed`
    /// selects a chain registered under it.
    #[test]
    fn every_identifier_kind_selects() {
        let s = setup();
        let mut resolver = ResolvesServerCertUsingTrustedCaKeys::new(Arc::new(
            SingleCertAndKey::from(certified_key(&s.f)),
        ));
        resolver.add(vec![TrustedAuthority::PreAgreed], certified_key(&s.a));
        resolver
            .add_for_root(&s.b.ca, sha1, certified_key(&s.b))
            .unwrap();
        let resolver = Arc::new(resolver);
        let cases = [
            (TrustedAuthority::cert_sha1_hash(&s.b.ca, sha1), &s.b),
            (
                TrustedAuthority::key_sha1_hash(&s.b.ca, sha1).unwrap(),
                &s.b,
            ),
            (TrustedAuthority::x509_name(&s.b.ca).unwrap(), &s.b),
            (TrustedAuthority::PreAgreed, &s.a),
        ];
        for (id, chain) in cases {
            let (mut client, mut server) = connect(
                s.client(Some(vec![id.clone()])),
                server_with(resolver.clone(), TLS12),
            );
            handshake(&mut client, &mut server);
            assert!(client.trusted_ca_keys_acknowledged(), "{id:?}");
            assert_eq!(served(&client), chain.end_entity, "{id:?}");
        }
    }

    /// The roots of A and B share their subject name, as an old and a new
    /// root do after a CA key rollover. A hash the client lists wins over
    /// the name, wherever it stands in either list; the name alone selects
    /// the first chain registered.
    #[test]
    fn a_hash_match_wins_over_a_shared_name() {
        let s = setup();
        let name = TrustedAuthority::x509_name(&s.b.ca).unwrap();
        assert_eq!(name, TrustedAuthority::x509_name(&s.a.ca).unwrap());
        let mut roots = RootCertStore::empty();
        roots.add(s.b.ca.clone()).unwrap();
        let key_b = TrustedAuthority::key_sha1_hash_of_anchor(&roots.roots[0], sha1).unwrap();
        let cases = [
            (
                vec![
                    name.clone(),
                    TrustedAuthority::cert_sha1_hash(&s.b.ca, sha1),
                ],
                &s.b,
            ),
            (vec![name.clone(), key_b], &s.b),
            (vec![name], &s.a),
        ];
        for (list, chain) in cases {
            let (mut client, mut server) = connect(s.client(Some(list.clone())), s.server());
            handshake(&mut client, &mut server);
            assert!(client.trusted_ca_keys_acknowledged(), "{list:?}");
            assert_eq!(served(&client), chain.end_entity, "{list:?}");
        }
    }

    /// No list, an empty list, or a list naming none of the registered
    /// roots: the fallback chain, without acknowledgement.
    #[test]
    fn otherwise_the_fallback_answers_unacknowledged() {
        init_logging();
        let s = setup();
        for list in [
            None,
            Some(Vec::new()),
            Some(vec![TrustedAuthority::CertSha1Hash([0; 20])]),
            Some(ids_for(&s.f)),
        ] {
            let (mut client, mut server) = connect(s.client(list.clone()), s.server());
            let flight = handshake(&mut client, &mut server);
            assert_eq!(trusted_ca_keys_ext(&flight, false), None, "{list:?}");
            assert!(!client.trusted_ca_keys_acknowledged(), "{list:?}");
            assert_eq!(served(&client), s.f.end_entity, "{list:?}");
        }
    }

    /// A chain whose key cannot sign with the client's schemes is passed
    /// over even when its root is listed.
    #[test]
    fn a_chain_that_cannot_sign_is_not_chosen() {
        let s = setup();
        let mut config = s.client(Some(ids_for(&s.a)));
        // The verifier offers only Ed25519; chain A is ECDSA.
        let ed = server_chain(KeyType::Ed25519);
        config
            .dangerous()
            .set_certificate_verifier(SchemeRecordingServerVerifier::new(
                PinnedServerVerifier::new(&ed),
                &[browntls_core::SignatureScheme::ED25519],
            ));
        let mut resolver = ResolvesServerCertUsingTrustedCaKeys::new(Arc::new(
            SingleCertAndKey::from(certified_key(&ed)),
        ));
        resolver
            .add_for_root(&s.a.ca, sha1, certified_key(&s.a))
            .unwrap();
        let (mut client, mut server) = connect(config, server_with(Arc::new(resolver), TLS12));
        let flight = handshake(&mut client, &mut server);
        assert_eq!(trusted_ca_keys_ext(&flight, false), None);
        assert!(!client.trusted_ca_keys_acknowledged());
        assert_eq!(served(&client), ed.end_entity);
    }

    /// A resolver that reads the list without acknowledging it sends no
    /// extension; one that acknowledges does.
    #[test]
    fn only_an_acknowledging_resolver_answers() {
        let chain = server_chain(KeyType::EcdsaP256);
        for acknowledge in [false, true] {
            let resolver = Recording::new(&chain, acknowledge);
            let (mut client, mut server) = connect(
                client_trusting(&[&chain], TLS12, Some(ids_for(&chain))),
                server_with(resolver.clone(), TLS12),
            );
            let flight = handshake(&mut client, &mut server);
            assert_eq!(resolver.seen(), [Some(ids_for(&chain))]);
            assert_eq!(trusted_ca_keys_ext(&flight, false).is_some(), acknowledge);
            assert_eq!(client.trusted_ca_keys_acknowledged(), acknowledge);
        }
        // Acknowledging a client that sent nothing sends nothing.
        let resolver = Recording::new(&chain, true);
        let (mut client, mut server) = connect(
            client_trusting(&[&chain], TLS12, None),
            server_with(resolver.clone(), TLS12),
        );
        let flight = handshake(&mut client, &mut server);
        assert_eq!(resolver.seen(), [None]);
        assert_eq!(trusted_ca_keys_ext(&flight, false), None);
    }

    /// TLS 1.3 negotiated: the resolver sees the list and acknowledges,
    /// yet nothing is sent (a TLS 1.3 client refuses the extension in a
    /// ServerHello or EncryptedExtensions with illegal_parameter, so the
    /// handshake completing shows its absence from both).
    #[test]
    fn nothing_is_acknowledged_in_tls13() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let resolver = Recording::new(&chain, true);
        let (mut client, mut server) = connect(
            client_trusting(&[&chain], BOTH, Some(ids_for(&chain))),
            server_with(resolver.clone(), BOTH),
        );
        let hello = take_flight(&mut client);
        assert!(trusted_ca_keys_ext(&hello, true).is_some());
        give(&mut server, &hello);
        server.process_new_packets().unwrap();
        let flight = take_flight(&mut server);
        assert_eq!(trusted_ca_keys_ext(&flight, false), None);
        give(&mut client, &flight);
        client.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.protocol_version(),
            Some(browntls_core::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(resolver.seen(), [Some(ids_for(&chain))]);
        assert!(!client.trusted_ca_keys_acknowledged());
    }

    /// After a HelloRetryRequest the second ClientHello carries the same
    /// extension.
    #[test]
    fn the_list_is_sent_again_after_hello_retry_request() {
        init_logging();
        let chain = server_chain(KeyType::EcdsaP256);
        let mut server_provider = prov::default_provider();
        server_provider
            .kx_groups
            .retain(|g| g.name() == NamedGroup::secp384r1);
        let server = ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_protocol_versions(BOTH)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
        let (mut client, mut server) = connect(
            client_trusting(&[&chain], BOTH, Some(ids_for(&chain))),
            server,
        );
        let first = take_flight(&mut client);
        give(&mut server, &first);
        server.process_new_packets().unwrap();
        give(&mut client, &take_flight(&mut server));
        client.process_new_packets().unwrap();
        let mut second = take_flight(&mut client);
        // A change_cipher_spec record (RFC 9846 §D.4) may come first.
        if second[0] == 20 {
            second.drain(..6);
        }
        assert_ne!(first, second, "no second ClientHello");
        assert!(trusted_ca_keys_ext(&first, true).is_some());
        assert_eq!(
            trusted_ca_keys_ext(&second, true),
            trusted_ca_keys_ext(&first, true)
        );
        give(&mut server, &second);
        server.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            server.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
    }

    /// A resumed TLS 1.2 session sends no certificate, so no
    /// acknowledgement either, by session ID or by ticket.
    #[test]
    fn a_resumed_session_is_not_acknowledged() {
        init_logging();
        let s = setup();
        for tickets in [false, true] {
            let mut client = s.client(Some(ids_for(&s.b)));
            client.resumption = Resumption::in_memory_sessions(4).tls12_resumption(if tickets {
                Tls12Resumption::SessionIdOrTickets
            } else {
                Tls12Resumption::SessionIdOnly
            });
            let mut server = s.server();
            if tickets {
                server.ticketer = prov::Ticketer::new().unwrap();
                server.session_storage = Arc::new(browntls_core::server::NoServerSessionStorage {});
            }
            let (client, server) = (Arc::new(client), Arc::new(server));
            for round in 0..2 {
                let mut c = ClientConnection::new(client.clone(), server_name()).unwrap();
                let mut sv = ServerConnection::new(server.clone()).unwrap();
                let flight = handshake(&mut c, &mut sv);
                let resumed = round == 1;
                assert_eq!(
                    sv.handshake_kind(),
                    Some(if resumed {
                        HandshakeKind::Resumed
                    } else {
                        HandshakeKind::Full
                    }),
                    "tickets {tickets}"
                );
                assert_eq!(trusted_ca_keys_ext(&flight, false).is_some(), !resumed);
                assert_eq!(c.trusted_ca_keys_acknowledged(), !resumed);
                assert_eq!(served(&c), s.b.end_entity);
            }
        }
    }

    /// RFC 6066 §6: the acknowledgement is empty; a body is a decode_error.
    #[test]
    fn an_acknowledgement_with_a_body_is_a_decode_error() {
        let chain = server_chain(KeyType::EcdsaP256);
        let (mut client, mut server) = connect(
            client_trusting(&[&chain], TLS12, Some(ids_for(&chain))),
            server_with(Recording::new(&chain, false), TLS12),
        );
        give(&mut server, &take_flight(&mut client));
        server.process_new_packets().unwrap();
        let mut flight = take_flight(&mut server);
        add_hello_extension(&mut flight, false, EXT_TRUSTED_CA_KEYS, &[0]);
        give(&mut client, &flight);
        assert_eq!(
            client.process_new_packets().unwrap_err(),
            Error::InvalidMessage(InvalidMessage::TrailingData("extension"))
        );
        assert_eq!(
            fatal_alert(&take_flight(&mut client)),
            Some(ALERT_DECODE_ERROR)
        );
    }

    /// A list that fits the extension but makes the ClientHello longer than
    /// a handshake message fails connection creation.
    #[test]
    fn a_list_too_long_for_the_client_hello_fails_connection_creation() {
        let chain = server_chain(KeyType::EcdsaP256);
        // 1023 entries of 3 + 61 bytes: 65472 bytes, under the 65533 an
        // extension body can hold, but the rest of the hello does not fit.
        let name = TrustedAuthority::X509Name(DistinguishedName::new(vec![0x30; 61]));
        let config = Arc::new(client_trusting(&[&chain], TLS12, Some(vec![name; 1023])));
        assert!(matches!(
            ClientConnection::new(config.clone(), server_name()),
            Err(Error::General(_))
        ));
        assert!(matches!(
            UnbufferedClientConnection::new(config, server_name()),
            Err(Error::General(_))
        ));
    }

    /// `Acceptor`: the ClientHello read before a configuration is chosen
    /// shows the list, and acknowledging there does nothing; the resolver
    /// of the chosen configuration decides.
    #[test]
    fn the_acceptor_shows_the_list() {
        let s = setup();
        let list = ids_for(&s.a);
        let mut client =
            ClientConnection::new(Arc::new(s.client(Some(list.clone()))), server_name()).unwrap();
        let mut acceptor = Acceptor::default();
        acceptor
            .read_tls(&mut &take_flight(&mut client)[..])
            .unwrap();
        let accepted = acceptor.accept().unwrap().unwrap();
        let hello = accepted.client_hello();
        assert_eq!(hello.trusted_ca_keys(), Some(&list[..]));
        hello.acknowledge_trusted_ca_keys();
        let fallback_only =
            server_with(Arc::new(SingleCertAndKey::from(certified_key(&s.f))), TLS12);
        let mut server = accepted
            .into_connection(Arc::new(fallback_only))
            .map_err(|(e, _)| e)
            .unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert!(!client.trusted_ca_keys_acknowledged());
        assert_eq!(served(&client), s.f.end_entity);

        // With the resolver's configuration, chain A is acknowledged.
        let mut client =
            ClientConnection::new(Arc::new(s.client(Some(list))), server_name()).unwrap();
        let mut acceptor = Acceptor::default();
        acceptor
            .read_tls(&mut &take_flight(&mut client)[..])
            .unwrap();
        let accepted = acceptor.accept().unwrap().unwrap();
        let mut server = accepted
            .into_connection(Arc::new(s.server()))
            .map_err(|(e, _)| e)
            .unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert!(client.trusted_ca_keys_acknowledged());
        assert_eq!(served(&client), s.a.end_entity);
    }

    /// Drives an unbuffered connection until it needs input or may write
    /// application data; appends what it sends to `out`.
    fn pump<D: SideData>(
        conn: &mut UnbufferedConnectionCommon<D>,
        incoming: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> bool {
        for _ in 0..100 {
            let status = conn.process_tls_records(incoming);
            let discard = status.discard;
            let mut done = None;
            match status.state.unwrap() {
                ConnectionState::EncodeTlsData(mut e) => {
                    let mut buf = vec![0u8; 0x1_0000];
                    let n = e.encode(&mut buf).unwrap();
                    out.extend_from_slice(&buf[..n]);
                }
                ConnectionState::TransmitTlsData(t) => t.done(),
                ConnectionState::BlockedHandshake => done = Some(false),
                ConnectionState::WriteTraffic(_) => done = Some(true),
                other => panic!("unexpected state {other:?}"),
            }
            incoming.drain(..discard);
            if let Some(writable) = done {
                return writable;
            }
        }
        panic!("unbuffered connection did not settle");
    }

    /// The unbuffered API: `UnbufferedAcceptor` shows the list, and the
    /// unbuffered client reports the acknowledgement.
    #[test]
    fn the_unbuffered_api_negotiates() {
        init_logging();
        let s = setup();
        let list = ids_for(&s.b);
        let mut client =
            UnbufferedClientConnection::new(Arc::new(s.client(Some(list.clone()))), server_name())
                .unwrap();
        let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
        pump(&mut client, &mut Vec::new(), &mut to_server);

        let mut acceptor = UnbufferedAcceptor::default();
        let status = acceptor.accept(&mut to_server);
        to_server.drain(..status.discard);
        let accepted = status.state.map_err(|(e, _)| e).unwrap().unwrap();
        assert_eq!(accepted.client_hello().trusted_ca_keys(), Some(&list[..]));
        let mut server: UnbufferedServerConnection = accepted
            .into_connection(Arc::new(s.server()))
            .map_err(|(e, _)| e)
            .unwrap();

        let mut finished = false;
        for _ in 0..8 {
            let server_done = pump(&mut server, &mut to_server, &mut to_client);
            let client_done = pump(&mut client, &mut to_client, &mut to_server);
            if server_done && client_done && to_server.is_empty() && to_client.is_empty() {
                finished = true;
                break;
            }
        }
        assert!(finished, "handshake did not complete");
        assert!(client.trusted_ca_keys_acknowledged());
        assert_eq!(client.peer_certificates().unwrap()[0], s.b.end_entity);
    }
}
