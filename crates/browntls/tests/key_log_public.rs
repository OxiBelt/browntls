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
