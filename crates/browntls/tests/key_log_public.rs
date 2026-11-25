//! The facade exposes the shared key-log API from its crate root.

#![cfg(all(feature = "std", feature = "native"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use browntls::{ClientConnection, KeyLog, ProtocolVersion, ServerConnection, StreamOwned};
use common::*;

const LABELS: [&str; 5] = [
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];

#[derive(Debug, Default)]
struct CountingKeyLog(Mutex<[usize; LABELS.len() + 1]>);

impl KeyLog for CountingKeyLog {
    fn log(&self, label: &str, _: &[u8], _: &[u8]) {
        let index = LABELS.iter().position(|known| *known == label);
        self.0.lock().unwrap()[index.unwrap_or(LABELS.len())] += 1;
    }
}

impl CountingKeyLog {
    fn assert_handshake_labels(&self) -> [usize; LABELS.len() + 1] {
        let counts = self.counts();
        let enabled = [1, 1, 1, 1, 1, 0];
        let disabled = [0; LABELS.len() + 1];
        if require_disabled_key_log() {
            assert_eq!(counts, disabled);
        } else if cfg!(feature = "key-log") {
            assert_eq!(counts, enabled);
        } else {
            // Another workspace member can enable the core dependency feature.
            assert!(counts == enabled || counts == disabled);
        }
        counts
    }

    fn counts(&self) -> [usize; LABELS.len() + 1] {
        *self.0.lock().unwrap()
    }
}

fn require_disabled_key_log() -> bool {
    std::env::var("BROWNTLS_KEY_LOG_REQUIRE_DISABLED").is_ok_and(|value| value == "1")
}

#[test]
fn facade_root_key_log_configures_both_peers() {
    let pki = Pki::new();
    let client_log = Arc::new(CountingKeyLog::default());
    let server_log = Arc::new(CountingKeyLog::default());
    let mut client_config = pki.client_config();
    client_config.key_log = client_log.clone();
    let mut server_config = pki.server_config();
    server_config.key_log = server_log.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut tcp = TcpStream::connect(address).unwrap();
    let (mut server_tcp, _) = listener.accept().unwrap();
    let timeout = Some(Duration::from_secs(30));
    for socket in [&tcp, &server_tcp] {
        socket.set_read_timeout(timeout).unwrap();
        socket.set_write_timeout(timeout).unwrap();
    }

    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            connection.complete_io(&mut server_tcp).unwrap();
            assert_eq!(
                connection.protocol_version(),
                Some(ProtocolVersion::TLSv1_3)
            );
            let labels = server_log.assert_handshake_labels();
            let mut stream = StreamOwned::new(connection, server_tcp);
            let mut request = [0; 1];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [0]);
            stream.write_all(&[1]).unwrap();
            stream.flush().unwrap();
            assert_eq!(server_log.counts(), labels);
        });
        let mut connection = ClientConnection::new(Arc::new(client_config), localhost()).unwrap();
        connection.complete_io(&mut tcp).unwrap();
        assert_eq!(
            connection.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        let labels = client_log.assert_handshake_labels();
        let mut stream = StreamOwned::new(connection, tcp);
        stream.write_all(&[0]).unwrap();
        let mut reply = [0; 1];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [1]);
        assert_eq!(client_log.counts(), labels);
        server.join().unwrap();
    });
}

#[cfg(not(all(feature = "key-log", target_os = "linux")))]
#[test]
fn facade_file_sink_is_inert_when_unavailable() {
    use browntls::KeyLogFile;

    if cfg!(target_os = "linux") && !require_disabled_key_log() {
        return;
    }
    assert_eq!(
        KeyLogFile::try_from_path("").unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
    assert!(!KeyLogFile::new().will_log(LABELS[0]));
}

/// The facade's paths reach everything an application uses for the ECH
/// records of RFC 9850 §2.3: the shared-mode configuration, and the
/// client-facing server's own opt-in.
#[test]
fn facade_paths_reach_the_ech_key_log_records() {
    use browntls::crypto::hpke::Hpke;
    use browntls::crypto::native::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    use browntls::ech::split::{ClientFacing, ClientFacingDecision};
    use browntls::ech::{EchConfig, EchMode, EchServerConfig, EchServerKey, EchStatus};

    /// The ECH labels a party logged, in order.
    #[derive(Debug, Default)]
    struct EchLabels(Mutex<Vec<String>>);

    impl KeyLog for EchLabels {
        fn log(&self, label: &str, _: &[u8], _: &[u8]) {
            if label.starts_with("ECH_") {
                self.0.lock().unwrap().push(label.to_owned());
            }
        }
    }

    impl EchLabels {
        fn assert_one_pair(&self) {
            let labels = self.0.lock().unwrap();
            let pair = ["ECH_SECRET", "ECH_CONFIG"];
            if require_disabled_key_log() {
                assert!(labels.is_empty());
            } else if cfg!(feature = "key-log") {
                assert_eq!(*labels, pair);
            } else {
                // Another workspace member can enable the core dependency
                // feature.
                assert!(labels.is_empty() || *labels == pair);
            }
        }
    }

    const SUITES: &[&dyn Hpke] = &[DH_KEM_X25519_HKDF_SHA256_AES_128];
    let pki = Pki::new();
    let key = EchServerKey::generate(7, "public.example", 32, SUITES).unwrap();
    let ech = Arc::new(EchServerConfig::new(vec![key]).unwrap());
    let logs = [(); 3].map(|()| Arc::new(EchLabels::default()));

    // A client that offers ECH: its records exist once the ClientHello does.
    let mut client_config = pki.client_config();
    client_config.ech_mode = Some(EchMode::Enable(
        EchConfig::new(ech.ech_config_list(), SUITES).unwrap(),
    ));
    client_config.key_log = logs[0].clone();
    let mut client = ClientConnection::new(Arc::new(client_config), localhost()).unwrap();
    let mut flight = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut flight).unwrap();
    }
    logs[0].assert_one_pair();

    // A server in shared mode, with the key log of its configuration.
    let mut server_config = pki.server_config();
    server_config.ech = Some(ech.clone());
    server_config.key_log = logs[1].clone();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    server.read_tls(&mut &flight[..]).unwrap();
    server.process_new_packets().unwrap();
    assert_eq!(server.ech_status(), EchStatus::Accepted);
    logs[1].assert_one_pair();

    // A client-facing server of split mode: it forwards with and without
    // a sink, and writes the records to the one it was given. That it
    // writes nothing otherwise is `browntls-core`'s own test.
    let mut front = ClientFacing::new(ech.clone());
    front.read_client(&flight).unwrap();
    assert_eq!(front.decision(), Some(ClientFacingDecision::Forward));
    let mut front = ClientFacing::new(ech).with_key_log(logs[2].clone());
    front.read_client(&flight).unwrap();
    assert_eq!(front.decision(), Some(ClientFacingDecision::Forward));
    logs[2].assert_one_pair();
}
