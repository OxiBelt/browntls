// RFC 10024 negotiation and alert checks, shared by both provider targets.

use browntls_core::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};

fn rfc10024_groups() -> [(&'static dyn SupportedKxGroup, &'static dyn SupportedKxGroup); 3] {
    use prov::kx_group as kx;
    [
        (kx::X25519MLKEM768, kx::X25519),
        (kx::SECP256R1MLKEM768, kx::SECP256R1),
        (kx::SECP384R1MLKEM1024, kx::SECP384R1),
    ]
}

fn rfc10024_server(chain: &Chain, groups: &[&'static dyn SupportedKxGroup]) -> ServerConfig {
    let mut provider = prov::default_provider();
    provider.kx_groups = groups.to_vec();
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

#[test]
fn rfc10024_first_shares_retry_and_classical_policy() {
    let chain = server_chain(KeyType::Ed25519);
    for (hybrid, classical) in rfc10024_groups() {
        for (client_groups, server_group, kind) in [
            (&[hybrid][..], hybrid, HandshakeKind::Full),
            (
                &[classical, hybrid][..],
                hybrid,
                HandshakeKind::FullWithHelloRetryRequest,
            ),
            (&[hybrid, classical][..], classical, HandshakeKind::Full),
        ] {
            let (mut client, mut server) = connect(
                tls13_only_client(&chain, None, Some(client_groups)),
                rfc10024_server(&chain, &[server_group]),
            );
            do_handshake(&mut client, &mut server).unwrap();
            for side in [&**client as &browntls_core::CommonState, &**server] {
                assert_eq!(side.handshake_kind(), Some(kind));
                assert_eq!(
                    side.negotiated_key_exchange_group().unwrap().name(),
                    server_group.name()
                );
            }
        }

        let (mut client, mut server) = connect(
            tls13_only_client(&chain, None, Some(&[hybrid])),
            rfc10024_server(&chain, &[classical]),
        );
        let (client_result, server_result) = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            client_result,
            Err(Error::AlertReceived(AlertDescription::HandshakeFailure)),
        );
        assert!(matches!(server_result, Err(Error::PeerIncompatible(_))));
    }
}

#[derive(Debug)]
struct FailingHybridClient {
    inner: &'static dyn SupportedKxGroup,
    error: fn() -> Error,
}

impl SupportedKxGroup for FailingHybridClient {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(FailingHybridShare {
            inner: self.inner.start()?,
            error: self.error,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.inner.name()
    }
}

struct FailingHybridShare {
    inner: Box<dyn ActiveKeyExchange>,
    error: fn() -> Error,
}

impl ActiveKeyExchange for FailingHybridShare {
    fn complete(self: Box<Self>, _: &[u8]) -> Result<SharedSecret, Error> {
        Err((self.error)())
    }

    fn pub_key(&self) -> &[u8] {
        self.inner.pub_key()
    }

    fn group(&self) -> NamedGroup {
        self.inner.group()
    }
}

#[test]
fn rfc10024_alerts_distinguish_peer_input_and_local_failure() {
    let chain = server_chain(KeyType::Ed25519);
    for (hybrid, _) in rfc10024_groups() {
        let cases: [(fn() -> Error, AlertDescription); 2] = [
            (
                || Error::from(PeerMisbehaved::InvalidKeyShare),
                AlertDescription::IllegalParameter,
            ),
            (
                || Error::General("injected provider failure".into()),
                AlertDescription::InternalError,
            ),
        ];
        for (error, alert) in cases {
            let group = Box::leak(Box::new(FailingHybridClient {
                inner: hybrid,
                error,
            }));
            let (mut client, mut server) = connect(
                tls13_only_client(&chain, None, Some(&[group])),
                rfc10024_server(&chain, &[hybrid]),
            );
            transfer(&mut client, &mut server);
            server.process_new_packets().unwrap();
            transfer(&mut server, &mut client);
            assert_eq!(client.process_new_packets(), Err(error()));
            assert_eq!(
                take_tls(&mut client),
                [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, u8::from(alert)],
            );
        }
    }
}
