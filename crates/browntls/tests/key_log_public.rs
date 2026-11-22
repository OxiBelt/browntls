//! The facade exposes the shared key-log API from its crate root.

#![cfg(all(feature = "key-log", feature = "std", feature = "native"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use browntls::{ClientConnection, KeyLog, ServerConnection, StreamOwned};
use common::*;

#[derive(Debug, Default)]
struct CountingKeyLog(AtomicUsize);

impl KeyLog for CountingKeyLog {
    fn log(&self, _: &str, _: &[u8], _: &[u8]) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
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
    let tcp = TcpStream::connect(address).unwrap();

    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (socket, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, socket);
            let mut request = [0; 1];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [0]);
            stream.write_all(&[1]).unwrap();
            stream.flush().unwrap();
        });
        let connection = ClientConnection::new(Arc::new(client_config), localhost()).unwrap();
        let mut stream = StreamOwned::new(connection, tcp);
        stream.write_all(&[0]).unwrap();
        let mut reply = [0; 1];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [1]);
        server.join().unwrap();
    });

    assert!(client_log.0.load(Ordering::Relaxed) > 0);
    assert!(server_log.0.load(Ordering::Relaxed) > 0);
}
