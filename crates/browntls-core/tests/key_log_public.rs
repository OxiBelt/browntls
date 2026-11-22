//! Public key-log entry points. The sink counts callbacks and never retains
//! or displays client randoms or secret bytes.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(feature = "key-log")]
#[path = "providers/rustcrypto.rs"]
mod prov;

#[cfg(feature = "key-log")]
mod common;

#[cfg(feature = "key-log")]
use std::sync::Arc;
#[cfg(feature = "key-log")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "key-log")]
use browntls_core::{ClientConnection, KeyLog, ServerConnection};
#[cfg(feature = "key-log")]
use common::*;

#[cfg(feature = "key-log")]
#[derive(Debug, Default)]
struct CountingKeyLog(AtomicUsize);

#[cfg(feature = "key-log")]
impl KeyLog for CountingKeyLog {
    fn log(&self, _: &str, _: &[u8], _: &[u8]) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
#[cfg(feature = "key-log")]
fn default_is_noop_and_explicit_sink_receives_events() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_config(&chain);
    let mut server_config = server_config(&chain);
    assert!(!client_config.key_log.will_log("CLIENT_TRAFFIC_SECRET_0"));
    assert!(!server_config.key_log.will_log("SERVER_TRAFFIC_SECRET_0"));
    let client_log = Arc::new(CountingKeyLog::default());
    let server_log = Arc::new(CountingKeyLog::default());
    client_config.key_log = client_log.clone();
    server_config.key_log = server_log.clone();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    assert!(client_log.0.load(Ordering::Relaxed) > 0);
    assert!(server_log.0.load(Ordering::Relaxed) > 0);
}

#[cfg(all(feature = "key-log", target_os = "linux"))]
#[test]
fn explicit_file_sink_logs_without_exposing_secret_values() {
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct PrivateTempDir(PathBuf);

    impl Drop for PrivateTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_root = fs::canonicalize(std::env::temp_dir()).unwrap();
    let dir = temp_root.join(format!("browntls-key-log-{}-{nonce}", std::process::id()));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let _private_dir = PrivateTempDir(dir.clone());
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let path = dir.join("session.log");
    let sink = Arc::new(browntls_core::KeyLogFile::try_from_path(&path).unwrap());
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_config = client_config(&chain);
    let mut server_config = server_config(&chain);
    client_config.key_log = sink.clone();
    server_config.key_log = sink;
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();

    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let contents = fs::read_to_string(&path).unwrap();
    assert!(contents.lines().count() >= 5);
    assert!(contents.lines().all(|line| {
        let mut fields = line.split_ascii_whitespace();
        let label = fields.next().unwrap_or_default();
        let random = fields.next().unwrap_or_default();
        let secret = fields.next().unwrap_or_default();
        fields.next().is_none()
            && !label.is_empty()
            && random.len() == 64
            && random.bytes().all(|byte| byte.is_ascii_hexdigit())
            && secret.len() >= 64
            && secret.len() % 2 == 0
            && secret.bytes().all(|byte| byte.is_ascii_hexdigit())
    }));
}

#[cfg(feature = "key-log")]
#[test]
fn blocking_stream_tcp_logs_handshake_labels_on_both_endpoints() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Labels(Mutex<Vec<String>>);

    impl KeyLog for Labels {
        fn log(&self, label: &str, _: &[u8], _: &[u8]) {
            self.0.lock().unwrap().push(label.to_owned());
        }
    }

    fn assert_tls13_labels(log: &Labels) {
        let labels = log.0.lock().unwrap();
        assert!(
            labels
                .iter()
                .any(|label| label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        );
        assert!(
            labels
                .iter()
                .any(|label| label == "CLIENT_TRAFFIC_SECRET_0")
        );
    }

    let chain = server_chain(KeyType::EcdsaP256);
    let client_log = Arc::new(Labels::default());
    let server_log = Arc::new(Labels::default());
    let mut client_config = client_config(&chain);
    client_config.key_log = client_log.clone();
    let mut server_config = server_config(&chain);
    server_config.key_log = server_log.clone();
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let connection = ServerConnection::new(server_config).unwrap();
        let mut stream = browntls_core::StreamOwned::new(connection, socket);
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).unwrap();
        stream.write_all(&request).unwrap();
    });

    let socket = TcpStream::connect(addr).unwrap();
    let connection = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut stream = browntls_core::StreamOwned::new(connection, socket);
    stream.write_all(b"test").unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"test");
    server.join().unwrap();
    assert_tls13_labels(&client_log);
    assert_tls13_labels(&server_log);
}

#[cfg(not(all(feature = "key-log", target_os = "linux")))]
#[test]
fn file_sink_reports_unsupported_when_unavailable() {
    assert_eq!(
        browntls_core::KeyLogFile::try_from_path("unused")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
}
