//! The ECH records of the key log (RFC 9850 §2.3): `ECH_SECRET` and
//! `ECH_CONFIG`, which side writes them, when, and under which random.

use std::sync::Mutex;

use browntls_core::KeyLog;
#[cfg(feature = "key-log")]
use browntls_core::crypto::hpke::{
    EncapsulatedSecret, HpkeKem, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
#[cfg(feature = "key-log")]
use hello_wire::take_flight;

use super::*;

/// `(label, client_random, value)` as handed to the key log.
type Record = (String, Vec<u8>, Vec<u8>);

/// A key log that keeps what it is given, except the labels in `refuse`,
/// which it says it does not take.
#[derive(Debug, Default)]
struct Log {
    refuse: &'static [&'static str],
    records: Mutex<Vec<Record>>,
}

impl KeyLog for Log {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        assert!(!self.refuse.contains(&label), "{label} was refused");
        self.records.lock().unwrap().push((
            label.to_string(),
            client_random.to_vec(),
            secret.to_vec(),
        ));
    }

    fn will_log(&self, label: &str) -> bool {
        !self.refuse.contains(&label)
    }
}

#[cfg(feature = "key-log")]
impl Log {
    fn new() -> Arc<Self> {
        Arc::default()
    }

    fn refusing(refuse: &'static [&'static str]) -> Arc<Self> {
        Arc::new(Self {
            refuse,
            records: Mutex::default(),
        })
    }

    /// The ECH records, in the order written.
    fn ech(&self) -> Vec<Record> {
        let records = self.records.lock().unwrap();
        records
            .iter()
            .filter(|(label, ..)| label.starts_with("ECH_"))
            .cloned()
            .collect()
    }

    /// The distinct randoms that identify the TLS secrets.
    fn tls_randoms(&self) -> Vec<Vec<u8>> {
        let records = self.records.lock().unwrap();
        let mut randoms: Vec<Vec<u8>> = records
            .iter()
            .filter(|(label, ..)| !label.starts_with("ECH_"))
            .map(|(_, random, _)| random.clone())
            .collect();
        randoms.sort();
        randoms.dedup();
        randoms
    }

    /// Asserts that the ECH records are exactly one `ECH_SECRET` and then
    /// one `ECH_CONFIG` holding `config`, both identified by `outer`.
    /// Returns the secret.
    fn one_pair(&self, outer: &[u8], config: &[u8]) -> Vec<u8> {
        let ech = self.ech();
        let [secret, logged_config] = &ech[..] else {
            panic!("expected one ECH_SECRET and one ECH_CONFIG: {ech:?}");
        };
        assert_eq!(secret.0, "ECH_SECRET");
        assert_eq!(secret.1, outer, "ECH_SECRET is not under the outer random");
        assert_eq!(
            *logged_config,
            ("ECH_CONFIG".to_string(), outer.to_vec(), config.to_vec())
        );
        // The value is no TLS secret, and nothing visible on the wire.
        let records = self.records.lock().unwrap();
        assert!(
            records
                .iter()
                .all(|(label, _, value)| label == "ECH_SECRET" || *value != secret.2)
        );
        secret.2.clone()
    }
}

/// The random of the ClientHello at the start of `flight`: after the
/// record header, the handshake header and the version.
#[cfg(feature = "key-log")]
fn hello_random(flight: &[u8]) -> Vec<u8> {
    assert_eq!((flight[0], flight[5]), (22, 1), "not a ClientHello");
    flight[11..43].to_vec()
}

/// The only `ECHConfig` of `config`: its list without the length prefix.
#[cfg(feature = "key-log")]
fn only_config(config: &EchServerConfig) -> &[u8] {
    &config.ech_config_list()[2..]
}

/// A client and a server with a key log each; the client's first flight
/// has reached the server. Returns the outer ClientHello's random as it
/// was on the wire.
#[cfg(feature = "key-log")]
fn start(
    mut client: ClientConfig,
    mut server: ServerConfig,
    client_log: &Arc<Log>,
    server_log: &Arc<Log>,
) -> (ClientConnection, ServerConnection, Vec<u8>) {
    client.key_log = client_log.clone();
    server.key_log = server_log.clone();
    let (mut client, mut server) = connect(client, server);
    let flight = take_flight(&mut client);
    let outer = hello_random(&flight);
    hello_wire::give(&mut server, &flight);
    (client, server, outer)
}

#[cfg(feature = "key-log")]
#[test]
fn accepted_offer_logs_one_pair_on_each_side_under_the_outer_random() {
    init_logging();
    let certs = Certs::new();
    // `Nsecret` of each KEM (RFC 9180 §7.1).
    for (kem, nsecret) in [
        (HpkeKem::DHKEM_X25519_HKDF_SHA256, 32),
        (HpkeKem::DHKEM_P256_HKDF_SHA256, 32),
        (HpkeKem::DHKEM_P384_HKDF_SHA384, 48),
        (HpkeKem::DHKEM_P521_HKDF_SHA512, 64),
        (HpkeKem::DHKEM_X448_HKDF_SHA512, 64),
    ] {
        let suites: Vec<&'static dyn Hpke> = ALL_SUPPORTED_SUITES
            .iter()
            .copied()
            .filter(|s| s.suite().kem == kem)
            .collect();
        let key = EchServerKey::generate(7, PUBLIC, 32, &suites).unwrap();
        let ech = Arc::new(EchServerConfig::new(vec![key]).unwrap());
        let (client_log, server_log) = (Log::new(), Log::new());
        let (mut client, mut server, outer) = start(
            client_config(&certs, enable(ech.ech_config_list())),
            server_config(&certs, Some(&ech), None),
            &client_log,
            &server_log,
        );
        // The client wrote its records with the offer, before any answer.
        let sent = client_log.one_pair(&outer, only_config(&ech));
        assert_eq!(sent.len(), nsecret, "{kem:?}");
        assert!(server_log.ech().is_empty(), "before processing");
        server.process_new_packets().unwrap();
        assert_accepted(&mut client, &mut server);

        // Both sides hold the same KEM secret, logged once.
        assert_eq!(client_log.one_pair(&outer, only_config(&ech)), sent);
        assert_eq!(server_log.one_pair(&outer, only_config(&ech)), sent);

        // The TLS secrets are identified by the inner ClientHello's random
        // (RFC 9850 §2.1), which is not the outer one.
        let inner = client_log.tls_randoms();
        assert_eq!(inner.len(), 1, "{kem:?}");
        assert_ne!(inner[0], outer);
        assert_eq!(server_log.tls_randoms(), inner);
    }
}

#[cfg(feature = "key-log")]
#[test]
fn rejected_offer_is_logged_by_the_client_alone() {
    init_logging();
    let certs = Certs::new();
    let offered = EchServerConfig::new(vec![server_key(19)]).unwrap();
    // A server without ECH; one whose key has the offer's identifier, so
    // that it sets a context up and fails to open the payload; one with
    // trial decryption, which does that for a key of another identifier.
    let same_id = Arc::new(EchServerConfig::new(vec![server_key(19)]).unwrap());
    let trial = Arc::new(
        EchServerConfig::new(vec![server_key(20), server_key(21)])
            .unwrap()
            .with_trial_decryption(),
    );
    for server_ech in [None, Some(&same_id), Some(&trial)] {
        let (client_log, server_log) = (Log::new(), Log::new());
        let (mut client, mut server, outer) = start(
            client_config(&certs, enable(offered.ech_config_list())),
            server_config(&certs, server_ech, None),
            &client_log,
            &server_log,
        );
        server.process_new_packets().unwrap();
        expect_rejected(&mut client, &mut server);

        // RFC 9850 §2.3: the client logs whatever the server answers.
        client_log.one_pair(&outer, only_config(&offered));
        // The server decrypted nothing: no ECH record, whichever contexts
        // it set up on the way.
        assert!(server_log.ech().is_empty(), "{:?}", server_log.ech());
        // The connection continued with the outer ClientHello.
        assert_eq!(client_log.tls_randoms(), core::slice::from_ref(&outer));
        assert_eq!(server_log.tls_randoms(), core::slice::from_ref(&outer));
    }
}

/// RFC 9850 §2.3 lets a client log "if it offered ECH". A handshake that
/// fails after the HPKE context was set up and before a ClientHello exists
/// offered nothing, so it leaves no record, and no KEM secret, behind.
#[cfg(feature = "key-log")]
#[test]
fn an_offer_whose_client_hello_is_never_sent_logs_nothing() {
    init_logging();
    let certs = Certs::new();
    let ech = EchServerConfig::new(vec![server_key(23)]).unwrap();
    let client_log = Log::new();
    let mut config = client_config(&certs, enable(ech.ech_config_list()));
    config.key_log = client_log.clone();
    // More ALPN names than a handshake message can carry.
    config.alpn_protocols = vec![vec![b'a'; 200]; 400];
    let err =
        ClientConnection::new(Arc::new(config), ServerName::try_from(SECRET).unwrap()).unwrap_err();
    assert!(
        matches!(&err, Error::General(reason) if reason.contains("longer than")),
        "{err:?}"
    );
    assert!(client_log.records.lock().unwrap().is_empty());

    // The same configuration with an offer that fits is logged.
    let mut config = client_config(&certs, enable(ech.ech_config_list()));
    config.key_log = client_log.clone();
    let mut client =
        ClientConnection::new(Arc::new(config), ServerName::try_from(SECRET).unwrap()).unwrap();
    let outer = hello_random(&take_flight(&mut client));
    client_log.one_pair(&outer, &ech.ech_config_list()[2..]);
}

#[cfg(feature = "key-log")]
#[test]
fn grease_is_never_logged() {
    init_logging();
    let certs = Certs::new();
    let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
    let ech = Arc::new(
        EchServerConfig::new(vec![server_key(5), server_key(6)])
            .unwrap()
            .with_trial_decryption(),
    );
    for server_ech in [None, Some(&ech)] {
        for groups in [None, Some(&[prov::kx_group::SECP256R1][..])] {
            let (client_log, server_log) = (Log::new(), Log::new());
            let (mut client, mut server, outer) = start(
                client_config(&certs, Some(EchMode::Grease(grease.clone()))),
                server_config(&certs, server_ech, groups),
                &client_log,
                &server_log,
            );
            server.process_new_packets().unwrap();
            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(client.ech_status(), EchStatus::Grease);
            // The GREASE extension has an HPKE context behind it too, set
            // up with a placeholder key: it is not an offer.
            assert!(client_log.ech().is_empty(), "{:?}", client_log.ech());
            assert!(server_log.ech().is_empty(), "{:?}", server_log.ech());
            assert_eq!(client_log.tls_randoms(), core::slice::from_ref(&outer));
            assert_eq!(server_log.tls_randoms(), core::slice::from_ref(&outer));
        }
    }
}

#[cfg(feature = "key-log")]
#[test]
fn hello_retry_request_does_not_repeat_the_records() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let stale = EchServerConfig::new(vec![server_key(7)]).unwrap();
    let groups = Some(&[prov::kx_group::SECP256R1][..]);

    // Accepted in both ClientHellos: the second reuses the HPKE context.
    let (client_log, server_log) = (Log::new(), Log::new());
    let (mut client, mut server, outer) = start(
        client_config(&certs, enable(ech.ech_config_list())),
        server_config(&certs, Some(&ech), groups),
        &client_log,
        &server_log,
    );
    server.process_new_packets().unwrap();
    assert_accepted(&mut client, &mut server);
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    let sent = client_log.one_pair(&outer, only_config(&ech));
    assert_eq!(server_log.one_pair(&outer, only_config(&ech)), sent);

    // Rejected, with a HelloRetryRequest on the way.
    let (client_log, server_log) = (Log::new(), Log::new());
    let (mut client, mut server, outer) = start(
        client_config(&certs, enable(stale.ech_config_list())),
        server_config(&certs, Some(&ech), groups),
        &client_log,
        &server_log,
    );
    server.process_new_packets().unwrap();
    expect_rejected(&mut client, &mut server);
    client_log.one_pair(&outer, only_config(&stale));
    assert!(server_log.ech().is_empty());
}

#[cfg(feature = "key-log")]
#[test]
fn acceptor_logs_like_a_server_connection() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let (client_log, server_log) = (Log::new(), Log::new());
    let mut client_config = client_config(&certs, enable(ech.ech_config_list()));
    client_config.key_log = client_log.clone();
    let mut server_config = server_config(&certs, Some(&ech), None);
    server_config.key_log = server_log.clone();
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from(SECRET).unwrap(),
    )
    .unwrap();
    let flight = take_flight(&mut client);
    let outer = hello_random(&flight);

    let mut acceptor = browntls_core::server::Acceptor::default();
    acceptor.read_tls(&mut &flight[..]).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    // Reading the ClientHello decrypts nothing and logs nothing.
    assert!(server_log.ech().is_empty());
    let mut server = accepted.into_connection(Arc::new(server_config)).unwrap();
    assert_accepted(&mut client, &mut server);
    let sent = client_log.one_pair(&outer, only_config(&ech));
    assert_eq!(server_log.one_pair(&outer, only_config(&ech)), sent);
}

#[cfg(feature = "key-log")]
#[test]
fn the_sink_chooses_the_labels() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    for refuse in [
        &["ECH_SECRET"][..],
        &["ECH_CONFIG"][..],
        &["ECH_SECRET", "ECH_CONFIG"][..],
    ] {
        let (client_log, server_log) = (Log::refusing(refuse), Log::refusing(refuse));
        let (mut client, mut server, outer) = start(
            client_config(&certs, enable(ech.ech_config_list())),
            server_config(&certs, Some(&ech), None),
            &client_log,
            &server_log,
        );
        server.process_new_packets().unwrap();
        assert_accepted(&mut client, &mut server);
        for log in [&client_log, &server_log] {
            // `Log::log` panics on a refused label; what is left is the
            // other record, if any, under the outer random.
            let labels: Vec<String> = log.ech().into_iter().map(|r| r.0).collect();
            let expected: Vec<&str> = ["ECH_SECRET", "ECH_CONFIG"]
                .into_iter()
                .filter(|l| !refuse.contains(l))
                .collect();
            assert_eq!(labels, expected);
            assert!(log.ech().iter().all(|r| r.1 == outer));
            // The TLS secrets are logged as before.
            assert_eq!(log.tls_randoms().len(), 1);
        }
    }
}

/// An HPKE suite of another library: the native one behind the public
/// trait alone, as any implementation outside this crate is.
#[cfg(feature = "key-log")]
#[derive(Debug)]
struct Foreign(&'static dyn Hpke);

#[cfg(feature = "key-log")]
impl Hpke for Foreign {
    fn suite(&self) -> HpkeSuite {
        self.0.suite()
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
        self.0.setup_sealer(info, pub_key)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error> {
        self.0.setup_opener(enc, info, secret_key)
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        self.0.generate_key_pair()
    }
}

#[cfg(feature = "key-log")]
#[test]
fn a_suite_of_another_library_logs_the_configuration_only() {
    init_logging();
    let certs = Certs::new();
    let foreign: &'static [&'static dyn Hpke] = Box::leak(Box::new([
        &*Box::leak(Box::new(Foreign(DH_KEM_X25519_HKDF_SHA256_AES_128))) as &'static dyn Hpke,
    ]));
    let native = &[DH_KEM_X25519_HKDF_SHA256_AES_128][..];
    for (client_suites, server_suites) in [(foreign, native), (native, foreign), (foreign, foreign)]
    {
        let key = EchServerKey::generate(7, PUBLIC, 32, server_suites).unwrap();
        let ech = Arc::new(EchServerConfig::new(vec![key]).unwrap());
        let (client_log, server_log) = (Log::new(), Log::new());
        let mode = Some(EchMode::Enable(
            EchConfig::new(ech.ech_config_list(), client_suites).unwrap(),
        ));
        let (mut client, mut server, outer) = start(
            client_config(&certs, mode),
            server_config(&certs, Some(&ech), None),
            &client_log,
            &server_log,
        );
        server.process_new_packets().unwrap();
        assert_accepted(&mut client, &mut server);
        for (log, suites) in [(&client_log, client_suites), (&server_log, server_suites)] {
            if core::ptr::eq(suites, native) {
                log.one_pair(&outer, only_config(&ech));
            } else {
                // No value stands in for the secret this side cannot get.
                assert_eq!(
                    log.ech(),
                    [(
                        "ECH_CONFIG".to_string(),
                        outer.clone(),
                        only_config(&ech).to_vec()
                    )]
                );
            }
        }
    }
}

/// A split-mode connection whose three parties log; the client's first
/// flight has reached the client-facing server. Returns the logs of the
/// client, the client-facing server and the terminating server (back-end
/// or local), and the outer random.
#[cfg(feature = "key-log")]
fn split_start(
    certs: &Certs,
    mode: Option<EchMode>,
    ech: &Arc<EchServerConfig>,
    groups: Option<&[&'static dyn browntls_core::crypto::SupportedKxGroup]>,
) -> (Split, [Arc<Log>; 3], Vec<u8>) {
    let logs = [Log::new(), Log::new(), Log::new()];
    let mut client = client_config(certs, mode);
    client.key_log = logs[0].clone();
    let mut backend = backend_config(certs, groups);
    backend.key_log = logs[2].clone();
    let mut split = Split::new(certs, client, ech, backend);
    let mut local = server_config(certs, Some(ech), groups);
    local.key_log = logs[2].clone();
    split.local_config = Arc::new(local);
    split.front = Some(ClientFacing::new(ech.clone()).with_key_log(logs[1].clone()));

    let flight = take_flight(&mut split.client);
    let outer = hello_random(&flight);
    split.front.as_mut().unwrap().read_client(&flight).unwrap();
    (split, logs, outer)
}

#[cfg(feature = "key-log")]
#[test]
fn split_mode_front_logs_an_accepted_offer_and_the_backend_none() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    for groups in [None, Some(&[prov::kx_group::SECP256R1][..])] {
        let (mut split, [client_log, front_log, backend_log], outer) =
            split_start(&certs, enable(ech.ech_config_list()), &ech, groups);
        // Written with the decision, once.
        assert_eq!(
            split.front().decision(),
            Some(ClientFacingDecision::Forward)
        );
        let sent = client_log.one_pair(&outer, only_config(&ech));
        assert_eq!(front_log.one_pair(&outer, only_config(&ech)), sent);
        split.pump();
        split.assert_forwarded();
        assert_eq!(
            split.client.handshake_kind() == Some(HandshakeKind::FullWithHelloRetryRequest),
            groups.is_some()
        );

        // Still once, also after a second ClientHello.
        assert_eq!(client_log.one_pair(&outer, only_config(&ech)), sent);
        assert_eq!(front_log.one_pair(&outer, only_config(&ech)), sent);
        // The client-facing server has no TLS secret to log.
        assert!(front_log.tls_randoms().is_empty());
        // The back-end server has no ECH secret, and identifies its TLS
        // secrets by the inner ClientHello's random, as the client does.
        assert!(backend_log.ech().is_empty(), "{:?}", backend_log.ech());
        let inner = client_log.tls_randoms();
        assert_eq!(inner.len(), 1);
        assert_ne!(inner[0], outer);
        assert_eq!(backend_log.tls_randoms(), inner);
    }
}

#[cfg(feature = "key-log")]
#[test]
fn split_mode_local_decisions_log_nothing_at_the_servers() {
    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(
        EchServerConfig::new(vec![server_key(2), server_key(3)])
            .unwrap()
            .with_trial_decryption(),
    );
    let stale = EchServerConfig::new(vec![server_key(2)]).unwrap();
    let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128).unwrap();
    for (mode, offered) in [
        (enable(stale.ech_config_list()), true),
        (Some(EchMode::Grease(grease)), false),
        (None, false),
    ] {
        let (mut split, [client_log, front_log, local_log], outer) =
            split_start(&certs, mode, &ech, None);
        assert_eq!(split.front().decision(), Some(ClientFacingDecision::Local));
        split.pump();
        assert!(split.backend.is_none());
        assert_eq!(
            matches!(split.errors.client, Some(Error::RejectedEch(_))),
            offered,
            "{:?}",
            split.errors
        );

        // The client-facing server tried its keys and opened nothing; the
        // local server it handed the connection to did the same again.
        assert!(front_log.records.lock().unwrap().is_empty());
        assert!(local_log.ech().is_empty(), "{:?}", local_log.ech());
        assert_eq!(local_log.tls_randoms(), core::slice::from_ref(&outer));
        if offered {
            client_log.one_pair(&outer, only_config(&stale));
        } else {
            assert!(client_log.ech().is_empty());
        }
    }
}

/// Without the `key-log` feature no ECH path reaches a key log, whether it
/// was installed in a configuration or on the client-facing server.
#[cfg(not(feature = "key-log"))]
#[test]
fn ech_records_are_compiled_out() {
    #[derive(Debug)]
    struct Unexpected;
    impl KeyLog for Unexpected {
        fn log(&self, _: &str, _: &[u8], _: &[u8]) {
            panic!("feature-off connection called KeyLog::log");
        }

        fn will_log(&self, _: &str) -> bool {
            panic!("feature-off connection called KeyLog::will_log");
        }
    }
    // The capturing sink is unused in this build.
    let _ = Log::default().records.lock().unwrap().len();
    let _: Option<Record> = None;

    init_logging();
    let certs = Certs::new();
    let ech = Arc::new(EchServerConfig::new(vec![server_key(7)]).unwrap());
    let stale = EchServerConfig::new(vec![server_key(7)]).unwrap();
    let logging = |list: &[u8]| {
        let mut client = client_config(&certs, enable(list));
        client.key_log = Arc::new(Unexpected);
        client
    };
    let mut server_config = server_config(&certs, Some(&ech), None);
    server_config.key_log = Arc::new(Unexpected);

    // Shared mode, accepted and rejected.
    let (mut client, mut server) = connect(logging(ech.ech_config_list()), server_config.clone());
    assert_accepted(&mut client, &mut server);
    let (mut client, mut server) = connect(logging(stale.ech_config_list()), server_config);
    expect_rejected(&mut client, &mut server);

    // Split mode with a key log on the client-facing server.
    let mut backend = backend_config(&certs, None);
    backend.key_log = Arc::new(Unexpected);
    let mut split = Split::new(&certs, logging(ech.ech_config_list()), &ech, backend);
    split.front = Some(ClientFacing::new(ech.clone()).with_key_log(Arc::new(Unexpected)));
    split.pump();
    split.assert_forwarded();
}
