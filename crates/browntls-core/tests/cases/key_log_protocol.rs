// ---------------------------------------------------------------- key log

#[cfg(not(feature = "key-log"))]
#[test]
fn key_log_callbacks_are_compiled_out() {
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

    let chain = server_chain(KeyType::Ed25519);
    let check_handshake = |v| {
        let mut client_config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[v])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        client_config.key_log = Arc::new(Unexpected);
        let mut server_config = server_config(&chain);
        server_config.key_log = Arc::new(Unexpected);
        let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
    };
    check_handshake(&version::TLS13);
    #[cfg(feature = "tls12")]
    check_handshake(&version::TLS12);
}

/// `(label, client_random, secret)` as handed to the key log.
#[cfg(feature = "key-log")]
type LoggedSecret = (String, Vec<u8>, Vec<u8>);

#[cfg(feature = "key-log")]
#[derive(Debug, Default)]
struct CapturingKeyLog(Mutex<Vec<LoggedSecret>>);

#[cfg(feature = "key-log")]
impl KeyLog for CapturingKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.to_string(), client_random.to_vec(), secret.to_vec()));
    }
}

#[cfg(feature = "key-log")]
#[test]
fn key_log_receives_every_tls13_secret() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_log = Arc::new(CapturingKeyLog::default());
    let server_log = Arc::new(CapturingKeyLog::default());
    let mut client_config = client_config(&chain);
    client_config.key_log = client_log.clone();
    let mut server_config = server_config(&chain);
    server_config.key_log = server_log.clone();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();

    let client_entries = client_log.0.lock().unwrap().clone();
    let server_entries = server_log.0.lock().unwrap().clone();
    let labels: Vec<&str> = client_entries.iter().map(|(l, _, _)| l.as_str()).collect();
    for expected in [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
    ] {
        assert!(
            labels.contains(&expected),
            "missing {expected} in {labels:?}"
        );
    }
    // both sides log the same secrets under the same client random
    let mut c = client_entries.clone();
    let mut s = server_entries.clone();
    c.sort();
    s.sort();
    assert!(c == s, "endpoint key log entries differ");
    assert!(c.iter().all(|(_, random, _)| random.len() == 32));
}

#[cfg(all(feature = "key-log", feature = "tls12"))]
#[test]
fn key_log_receives_the_tls12_master_secret_on_full_and_resumed_handshakes() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let client_log = Arc::new(CapturingKeyLog::default());
    let server_log = Arc::new(CapturingKeyLog::default());
    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    client_config.key_log = client_log.clone();
    let mut server_config = server_config(&chain);
    server_config.key_log = server_log.clone();
    let (client_config, server_config) = (Arc::new(client_config), Arc::new(server_config));
    for expected in [
        browntls_core::HandshakeKind::Full,
        browntls_core::HandshakeKind::Resumed,
    ] {
        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.handshake_kind(), Some(expected));
        assert_eq!(server.handshake_kind(), Some(expected));
    }
    let client = client_log.0.lock().unwrap();
    let server = server_log.0.lock().unwrap();
    assert!(
        client.as_slice() == server.as_slice(),
        "endpoint key log entries differ"
    );
    assert_eq!(client.len(), 2);
    for (label, random, secret) in client.iter() {
        assert_eq!(label, "CLIENT_RANDOM");
        assert_eq!(random.len(), 32);
        assert_eq!(secret.len(), 48);
    }
    assert!(
        client[0].1 != client[1].1,
        "resumption must use the new client random"
    );
    assert!(
        client[0].2 == client[1].2,
        "TLS 1.2 resumption uses the same master secret"
    );
}
