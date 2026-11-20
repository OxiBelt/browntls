// Shared cases, included by `tests/dtls_udp.rs` (RustCrypto provider) and
// `tests/dtls_udp_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.
//
// The blocking DTLS 1.3 API over loopback UDP sockets: `dtls::UdpClient`
// and `dtls::UdpServer`.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use browntls_core::dtls::{self, ServerEvent, UdpClient, UdpServer};
use browntls_core::{ProtocolVersion, ServerConfig};
use common::*;

fn dtls_server_config(chain: &Chain) -> ServerConfig {
    let mut config = server_config(chain);
    config.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
    config.ticketer = prov::Ticketer::new().unwrap();
    config
}

fn loopback() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}

fn server(chain: &Chain) -> UdpServer {
    let mut server = UdpServer::new(Arc::new(dtls_server_config(chain)), loopback()).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(20)));
    server
}

fn client_socket(server: SocketAddr) -> UdpSocket {
    let socket = loopback();
    socket.connect(server).unwrap();
    socket
}

/// Echoes every datagram back until `clients` clients have closed, and
/// returns the events it saw.
fn echo(mut server: UdpServer, clients: usize) -> Vec<String> {
    let mut log = Vec::new();
    let mut closed = 0;
    while closed < clients {
        match server.next_event().unwrap() {
            ServerEvent::Connected(peer) => {
                let conn = server.connection(peer).unwrap();
                assert_eq!(conn.protocol_version(), Some(ProtocolVersion::DTLSv1_3));
                log.push("connected".to_string());
            }
            ServerEvent::Received(peer, data) => {
                server.send_to(&data, peer).unwrap();
                log.push(String::from_utf8(data).unwrap());
            }
            ServerEvent::Closed(_) => {
                closed += 1;
                log.push("closed".to_string());
            }
            ServerEvent::Failed(_, err) => panic!("{err}"),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(server.peers().count(), 0);
    assert_eq!(server.handshakes(), 0);
    log
}

#[test]
fn a_client_and_a_server_exchange_datagrams() {
    let chain = server_chain(KeyType::EcdsaP256);
    let server = server(&chain);
    let addr = server.socket().local_addr().unwrap();
    let echo = thread::spawn(move || echo(server, 1));

    let config = Arc::new(client_config(&chain));
    let mut client = UdpClient::connect(config, server_name(), client_socket(addr)).unwrap();
    assert_eq!(
        client.connection().protocol_version(),
        Some(ProtocolVersion::DTLSv1_3)
    );
    client.set_read_timeout(Some(Duration::from_secs(20)));
    let mut buf = [0; 2048];
    for message in ["one", "two", "three"] {
        client.send(message.as_bytes()).unwrap();
        let len = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], message.as_bytes());
    }

    // A buffer too short for the datagram keeps it for the next call.
    client.send(b"0123456789").unwrap();
    let err = client.recv(&mut buf[..4]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    let len = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..len], b"0123456789");

    // An empty datagram, echoed, is skipped: 0 means only a close.
    client.send(b"").unwrap();
    client.send(b"after empty").unwrap();
    let len = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..len], b"after empty");

    // Fresh keys in both directions, then more data.
    client.connection_mut().refresh_traffic_keys().unwrap();
    client.send(b"after update").unwrap();
    let len = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..len], b"after update");

    client.close().unwrap();
    let log = echo.join().unwrap();
    assert_eq!(
        log,
        [
            "connected",
            "one",
            "two",
            "three",
            "0123456789",
            "",
            "after empty",
            "after update",
            "closed"
        ]
    );
}

#[test]
fn a_server_serves_several_clients_at_once() {
    let chain = server_chain(KeyType::EcdsaP256);
    let server = server(&chain);
    let addr = server.socket().local_addr().unwrap();
    let echo = thread::spawn(move || echo(server, 3));

    let config = Arc::new(client_config(&chain));
    let clients: Vec<_> = (0..3)
        .map(|n| {
            let config = config.clone();
            thread::spawn(move || {
                let mut client =
                    UdpClient::connect(config, server_name(), client_socket(addr)).unwrap();
                client.set_read_timeout(Some(Duration::from_secs(20)));
                let mut buf = [0; 64];
                for round in 0..5 {
                    let message = format!("client {n} round {round}");
                    client.send(message.as_bytes()).unwrap();
                    let len = client.recv(&mut buf).unwrap();
                    assert_eq!(&buf[..len], message.as_bytes());
                }
                client.close().unwrap();
            })
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
    let log = echo.join().unwrap();
    assert_eq!(log.iter().filter(|e| *e == "connected").count(), 3);
    assert_eq!(log.iter().filter(|e| *e == "closed").count(), 3);
    assert_eq!(log.len(), 3 + 15 + 3);
}

#[test]
fn the_server_sends_close_notify() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut server = server(&chain);
    let addr = server.socket().local_addr().unwrap();
    let config = Arc::new(client_config(&chain));
    let client = thread::spawn(move || {
        let mut client = UdpClient::connect(config, server_name(), client_socket(addr)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(20)));
        client.send(b"hello").unwrap();
        // The server closes instead of answering.
        assert_eq!(client.recv(&mut [0; 64]).unwrap(), 0);
        assert!(client.connection().peer_has_closed());
    });
    let peer = match server.next_event().unwrap() {
        ServerEvent::Connected(peer) => peer,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        server.next_event().unwrap(),
        ServerEvent::Received(from, data) if from == peer && data == b"hello"
    ));
    server.close(peer);
    assert!(server.connection(peer).is_none());
    // The client's acknowledgements of the alert reach no connection.
    client.join().unwrap();
}

#[test]
fn a_silent_server_times_the_client_out() {
    let silent = loopback();
    let chain = server_chain(KeyType::EcdsaP256);
    let conn = dtls::ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut client = UdpClient::from_connection(conn, client_socket(silent.local_addr().unwrap()));
    client.set_read_timeout(Some(Duration::from_millis(300)));
    let err = client.complete_handshake().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    // The first ClientHello was sent.
    let mut buf = [0; 2048];
    silent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (len, _) = silent.recv_from(&mut buf).unwrap();
    assert_eq!(buf[0], 22, "a plaintext handshake record");
    assert!(len > 100);
}

/// Sends the datagrams the low-level `client` has queued from `socket`.
fn send_all(client: &mut dtls::ClientConnection, socket: &UdpSocket) {
    let mut out = Vec::new();
    while client.write_datagram(&mut out, Duration::ZERO).unwrap() {
        socket.send(&out).unwrap();
        out.clear();
    }
}

#[test]
fn unanswered_handshakes_leave_no_state() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut server = server(&chain);
    server.set_handshake_timeout(Duration::from_millis(300));
    server.set_read_timeout(Some(Duration::from_millis(100)));
    let addr = server.socket().local_addr().unwrap();
    let socket = client_socket(addr);
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut client =
        dtls::ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();

    // The first ClientHello is answered and nothing is kept.
    send_all(&mut client, &socket);
    let err = server.next_event().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(server.handshakes(), 0);
    let mut buf = vec![0; 65535];
    let len = socket.recv(&mut buf).unwrap();
    client
        .read_datagram(&mut buf[..len], Duration::ZERO)
        .unwrap();

    // The second, with the cookie, starts a handshake, which the client
    // then abandons.
    send_all(&mut client, &socket);
    assert!(server.next_event().is_err());
    assert_eq!(server.handshakes(), 1);
    assert_eq!(server.peers().count(), 0);
    thread::sleep(Duration::from_millis(400));
    assert!(server.next_event().is_err());
    assert_eq!(server.handshakes(), 0);
}

#[test]
fn a_server_needs_a_cookie_sealer() {
    let chain = server_chain(KeyType::EcdsaP256);
    let err = UdpServer::new(Arc::new(server_config(&chain)), loopback()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn a_zero_read_timeout_still_takes_a_waiting_datagram() {
    let chain = server_chain(KeyType::EcdsaP256);
    let server = server(&chain);
    let addr = server.socket().local_addr().unwrap();
    let echo = thread::spawn(move || echo(server, 1));
    let config = Arc::new(client_config(&chain));
    let mut client = UdpClient::connect(config, server_name(), client_socket(addr)).unwrap();
    client.send(b"ping").unwrap();
    thread::sleep(Duration::from_millis(200));
    client.set_read_timeout(Some(Duration::ZERO));
    let mut buf = [0; 16];
    assert_eq!(client.recv(&mut buf).unwrap(), 4);
    let err = client.recv(&mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    client.close().unwrap();
    echo.join().unwrap();
}

#[test]
fn a_forged_close_notify_reports_nothing() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut server = server(&chain);
    server.set_read_timeout(Some(Duration::from_millis(200)));
    let addr = server.socket().local_addr().unwrap();
    let socket = client_socket(addr);
    let mut client =
        dtls::ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // The cookie exchange, then the second ClientHello.
    send_all(&mut client, &socket);
    assert!(server.next_event().is_err());
    let mut buf = vec![0; 65535];
    let len = socket.recv(&mut buf).unwrap();
    client
        .read_datagram(&mut buf[..len], Duration::ZERO)
        .unwrap();
    send_all(&mut client, &socket);
    assert!(server.next_event().is_err());
    assert_eq!(server.handshakes(), 1);
    // An unprotected close_notify from the client's address.
    let mut alert = vec![21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 2, 1, 0];
    socket.send(&alert).unwrap();
    alert.clear();
    match server.next_event() {
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::TimedOut),
        Ok(event) => panic!("{event:?}"),
    }
    assert_eq!(server.handshakes(), 1, "the handshake goes on");
}

#[test]
fn a_stream_of_junk_does_not_hold_off_the_read_timeout() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut server = server(&chain);
    server.set_read_timeout(Some(Duration::from_millis(200)));
    let addr = server.socket().local_addr().unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let junk = {
        let stop = stop.clone();
        thread::spawn(move || {
            let socket = client_socket(addr);
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = socket.send(&[0x16; 40]);
                thread::sleep(Duration::from_micros(200));
            }
        })
    };
    let start = std::time::Instant::now();
    let err = server.next_event().unwrap_err();
    let waited = start.elapsed();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    junk.join().unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(waited < Duration::from_secs(2), "{waited:?}");
}
