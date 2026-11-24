#[cfg(feature = "key-log")]
#[test]
fn dtls13_client_and_server_emit_tls13_key_log_labels() {
    #[derive(Debug, Default)]
    struct Labels(std::sync::Mutex<Vec<String>>);

    impl browntls_core::KeyLog for Labels {
        fn log(&self, label: &str, _: &[u8], _: &[u8]) {
            self.0.lock().unwrap().push(label.to_owned());
        }
    }

    fn assert_logged(log: &Labels) {
        let labels = log.0.lock().unwrap();
        for expected in ["CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"] {
            assert!(labels.iter().any(|label| label == expected));
        }
    }

    let chain = server_chain(KeyType::EcdsaP256);
    let client_log = Arc::new(Labels::default());
    let server_log = Arc::new(Labels::default());
    let mut client_config = client_config(&chain);
    client_config.key_log = client_log.clone();
    let mut server_config = dtls_server_config(&chain);
    server_config.key_log = server_log.clone();
    let mut pair = Pair::new(&Arc::new(client_config), &Arc::new(server_config));

    pair.handshake(&mut Sim::perfect()).unwrap();

    assert_dtls13(&pair);
    assert_logged(&client_log);
    assert_logged(&server_log);
}
