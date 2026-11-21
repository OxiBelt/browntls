// Shared cases, included by `tests/dtls_udp.rs` (RustCrypto provider) and
// `tests/dtls_udp_native.rs` (native provider). Provider items are reached
// through the including target's `prov` module.
//
// The blocking DTLS 1.3 API over loopback UDP sockets: `dtls::UdpClient`
// and `dtls::UdpServer`.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use browntls_core::dtls::{self, ServerEvent, UdpClient, UdpServer};
use browntls_core::server::ProducesTickets;
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

#[test]
fn blocking_udp_adapters_negotiate_rfc9973() {
    use browntls_core::crypto::hash::HashAlgorithm;
    use browntls_core::psk::ExternalPsk;

    let chain = server_chain(KeyType::EcdsaP256);
    let key = Arc::new(
        ExternalPsk::new(b"udp-rfc9973".to_vec(), vec![42; 32], HashAlgorithm::SHA256).unwrap(),
    );
    let mut server_config = dtls_server_config(&chain);
    server_config.external_psks = Some(Arc::new(vec![key.clone()]));
    server_config.require_cert_with_extern_psk = true;
    let mut server = UdpServer::new(Arc::new(server_config), loopback()).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(10)));
    let addr = server.socket().local_addr().unwrap();
    let server_task = thread::spawn(move || {
        let ServerEvent::Connected(peer) = server.next_event().unwrap() else {
            panic!("unexpected handshake event");
        };
        assert!(
            server
                .connection(peer)
                .unwrap()
                .negotiated_cert_with_extern_psk()
        );
        let ServerEvent::Received(peer, data) = server.next_event().unwrap() else {
            panic!("expected an authenticated datagram");
        };
        server.send_to(&data, peer).unwrap();
    });
    let mut client_config = client_config(&chain);
    client_config.external_psks = vec![key];
    client_config.cert_with_extern_psk = true;
    let mut client =
        UdpClient::connect(Arc::new(client_config), server_name(), client_socket(addr)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(10)));
    assert!(client.connection().negotiated_cert_with_extern_psk());
    assert_eq!(
        client.connection().peer_certificates().unwrap(),
        chain.cert_chain()
    );
    client.send(b"hello").unwrap();
    let mut data = [0; 32];
    let len = client.recv(&mut data).unwrap();
    assert_eq!(&data[..len], b"hello");
    server_task.join().unwrap();
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
            while !stop.load(Ordering::Relaxed) {
                let _ = socket.send(&[0x16; 40]);
                thread::sleep(Duration::from_micros(200));
            }
        })
    };
    let start = Instant::now();
    let err = server.next_event().unwrap_err();
    let waited = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    junk.join().unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(waited < Duration::from_secs(2), "{waited:?}");
}

/// Completes the cookie exchange and reads the server's flight, leaving
/// the client's Finished queued. The server still counts a handshake.
fn client_before_finished(
    server: &mut UdpServer,
    chain: &Chain,
    socket: &UdpSocket,
) -> dtls::ClientConnection {
    server.set_read_timeout(Some(Duration::ZERO));
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut client =
        dtls::ClientConnection::new(Arc::new(client_config(chain)), server_name()).unwrap();
    let mut buf = vec![0; 65535];
    send_all(&mut client, socket);
    assert_eq!(
        server.next_event().unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(server.handshakes(), 0);
    let len = socket.recv(&mut buf).unwrap();
    client
        .read_datagram(&mut buf[..len], Duration::ZERO)
        .unwrap();
    send_all(&mut client, socket);
    assert_eq!(
        server.next_event().unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(server.handshakes(), 1);
    while client.is_handshaking() {
        let len = socket.recv(&mut buf).unwrap();
        client
            .read_datagram(&mut buf[..len], Duration::ZERO)
            .unwrap();
    }
    client
}

/// Combines only records produced by the public API, preserving their
/// order: queued handshake records, optional application data, then close.
fn send_flight_and_close(client: &mut dtls::ClientConnection, socket: &UdpSocket, with_data: bool) {
    let mut datagram = Vec::new();
    while client
        .write_datagram(&mut datagram, Duration::ZERO)
        .unwrap()
    {}
    if with_data {
        client.send(b"before close", &mut datagram).unwrap();
    }
    client.send_close_notify();
    while client
        .write_datagram(&mut datagram, Duration::ZERO)
        .unwrap()
    {}
    socket.send(&datagram).unwrap();
}

#[test]
fn close_events_keep_the_connection_until_prior_events_are_returned() {
    for (complete_first, with_data) in [(false, false), (false, true), (true, true)] {
        let chain = server_chain(KeyType::EcdsaP256);
        let mut server = server(&chain);
        let socket = client_socket(server.socket().local_addr().unwrap());
        let peer = socket.local_addr().unwrap();
        let mut client = client_before_finished(&mut server, &chain, &socket);

        if complete_first {
            send_all(&mut client, &socket);
            assert!(matches!(
                server.next_event().unwrap(),
                ServerEvent::Connected(addr) if addr == peer
            ));
        }
        send_flight_and_close(&mut client, &socket, with_data);
        if !complete_first {
            assert!(matches!(
                server.next_event().unwrap(),
                ServerEvent::Connected(addr) if addr == peer
            ));
        }
        assert_eq!(server.handshakes(), 0);
        let conn = server.connection(peer).unwrap();
        assert_eq!(conn.protocol_version(), Some(ProtocolVersion::DTLSv1_3));
        if !complete_first {
            assert!(conn.peer_has_closed());
        }
        assert_eq!(server.peers().collect::<Vec<_>>(), [peer]);
        if with_data {
            assert!(matches!(
                server.next_event().unwrap(),
                ServerEvent::Received(addr, data) if addr == peer && data == b"before close"
            ));
            assert!(server.connection(peer).unwrap().peer_has_closed());
        }
        assert!(matches!(
            server.next_event().unwrap(),
            ServerEvent::Closed(addr) if addr == peer
        ));
        assert!(server.connection(peer).is_none());
        assert_eq!(server.peers().count(), 0);
        assert_eq!(server.handshakes(), 0);
        assert_eq!(
            server.next_event().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}

#[test]
fn explicitly_forgetting_a_peer_discards_its_remaining_events() {
    for close in [false, true] {
        let chain = server_chain(KeyType::EcdsaP256);
        let mut server = server(&chain);
        let socket = client_socket(server.socket().local_addr().unwrap());
        let peer = socket.local_addr().unwrap();
        let mut client = client_before_finished(&mut server, &chain, &socket);
        send_flight_and_close(&mut client, &socket, true);
        assert!(matches!(
            server.next_event().unwrap(),
            ServerEvent::Connected(addr) if addr == peer
        ));
        // Also exercise cleanup of pending connection_mut work.
        assert!(server.connection_mut(peer).is_some());
        if close {
            server.close(peer);
        } else {
            assert!(server.remove(peer).is_some());
        }
        assert!(server.connection(peer).is_none());
        assert_eq!(server.peers().count(), 0);
        assert_eq!(server.handshakes(), 0);
        assert_eq!(
            server.next_event().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}

#[test]
fn rewrapping_a_client_keeps_its_clock_and_services_an_overdue_retransmission() {
    let chain = server_chain(KeyType::EcdsaP256);
    let silent = loopback();
    silent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let socket = client_socket(silent.local_addr().unwrap());
    let peer = socket.local_addr().unwrap();
    let mut conn =
        dtls::ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let start = Instant::now() - Duration::from_secs(120);
    // A first flight lost two seconds ago: its retransmission is due.
    // Advance the supplied monotonic time without a wall-clock sleep.
    let sent_at = start.elapsed() - Duration::from_secs(2);
    let mut lost = Vec::new();
    assert!(conn.write_datagram(&mut lost, sent_at).unwrap());
    // With post-quantum key shares the ClientHello can span datagrams.
    loop {
        lost.clear();
        if !conn.write_datagram(&mut lost, sent_at).unwrap() {
            break;
        }
    }
    let due = conn.next_timeout().unwrap();
    assert!(due < start.elapsed());

    let client = UdpClient::from_connection_with_clock(conn, socket, start);
    assert_eq!(client.connection().next_timeout(), Some(due));
    let (conn, socket, clock) = client.into_parts_with_clock();
    assert_eq!(clock, start);
    assert_eq!(socket.local_addr().unwrap(), peer);
    assert_eq!(conn.next_timeout(), Some(due));
    let mut client = UdpClient::from_connection_with_clock(conn, socket, clock);
    assert_eq!(client.read_timeout(), None);
    client.set_read_timeout(Some(Duration::ZERO));
    assert_eq!(
        client.complete_handshake().unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    // Resetting the origin would defer this send by about two minutes.
    let mut buf = [0; 2048];
    let (len, from) = silent.recv_from(&mut buf).unwrap();
    assert_eq!(from, peer);
    assert_eq!(buf[0], 22);
    assert!(len > 100);
    assert!(client.connection().is_handshaking());
    assert!(client.connection().next_timeout().unwrap() > due);
    let (_, _, clock) = client.into_parts_with_clock();
    assert_eq!(clock, start);
}

/// Checks the normal cookie-sealing path without altering its encryption
/// or sending a cookie from a different source. The encoded source is the
/// last length-prefixed field, followed by the group_named flag.
#[derive(Debug)]
struct SourceBoundCookies {
    inner: Arc<dyn ProducesTickets>,
    address: Vec<u8>,
    sealed: AtomicUsize,
}

impl ProducesTickets for SourceBoundCookies {
    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.inner.lifetime()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let (flag, body) = plain.split_last().unwrap();
        assert!(*flag <= 1);
        assert!(body.ends_with(&self.address));
        self.sealed.fetch_add(1, Ordering::Relaxed);
        self.inner.encrypt(plain)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.inner.decrypt(cipher)
    }
}

#[test]
fn ipv6_loopback_exchanges_data_with_a_source_bound_cookie() {
    let chain = server_chain(KeyType::EcdsaP256);
    let server_socket = UdpSocket::bind("[::1]:0").unwrap();
    let socket = UdpSocket::bind("[::1]:0").unwrap();
    socket.connect(server_socket.local_addr().unwrap()).unwrap();
    let SocketAddr::V6(peer) = socket.local_addr().unwrap() else {
        panic!("expected an IPv6 source");
    };
    let mut address = vec![0, 19, 6];
    address.extend_from_slice(&peer.ip().octets());
    address.extend_from_slice(&peer.port().to_be_bytes());
    let cookies = Arc::new(SourceBoundCookies {
        inner: prov::Ticketer::new().unwrap(),
        address,
        sealed: AtomicUsize::new(0),
    });
    let mut config = dtls_server_config(&chain);
    config.hello_retry_cookies = Some(cookies.clone());
    let mut server = UdpServer::new(Arc::new(config), server_socket).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(20)));
    let echo = thread::spawn(move || echo(server, 1));
    let conn = dtls::ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut client = UdpClient::from_connection(conn, socket);
    client.set_read_timeout(Some(Duration::from_secs(20)));
    client.complete_handshake().unwrap();
    client.send(b"IPv6").unwrap();
    let mut buf = [0; 16];
    let len = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..len], b"IPv6");
    client.close().unwrap();
    assert_eq!(echo.join().unwrap(), ["connected", "IPv6", "closed"]);
    assert!(cookies.sealed.load(Ordering::Relaxed) > 0);
}

fn migration_settings(versions: dtls::Versions, receive_len: u8) -> dtls::Settings {
    dtls::Settings::default()
        .with_versions(versions)
        .with_return_routability_checks(dtls::ConnectionIdPolicy::new(receive_len, true).unwrap())
}

#[test]
fn local_socket_replacement_preserves_the_association_and_stable_server_handle() {
    for selection in [dtls::rrc::Selection::Basic, dtls::rrc::Selection::Enhanced] {
        exchange_across_rebind(dtls::Versions::V1_3, selection);
    }
}

#[cfg(feature = "tls12")]
#[test]
fn dtls12_local_socket_replacement_preserves_the_association() {
    for selection in [dtls::rrc::Selection::Basic, dtls::rrc::Selection::Enhanced] {
        exchange_across_rebind(dtls::Versions::V1_2, selection);
    }
}

fn exchange_across_rebind(versions: dtls::Versions, selection: dtls::rrc::Selection) {
    // The client may have an empty receiving CID: its remote never changes.
    for client_cid_len in [0, 8] {
        let chain = server_chain(KeyType::EcdsaP256);
        let mut server = UdpServer::new_with_settings(
            Arc::new(dtls_server_config(&chain)),
            loopback(),
            migration_settings(versions, 8),
        )
        .unwrap();
        server.set_path_selection(selection);
        server.set_read_timeout(Some(Duration::from_millis(100)));
        let remote = server.socket().local_addr().unwrap();
        let socket = client_socket(remote);
        let admitted = socket.local_addr().unwrap();
        let replacement = client_socket(remote);
        let migrated = replacement.local_addr().unwrap();
        let serving = thread::spawn(move || {
            let stop = Instant::now() + Duration::from_secs(20);
            let mut connected = false;
            let mut announced = false;
            let mut received = Vec::new();
            loop {
                assert!(Instant::now() < stop, "migration did not finish");
                match server.next_event() {
                    Ok(ServerEvent::Connected(peer)) => {
                        assert_eq!(peer, admitted);
                        assert!(!connected);
                        connected = true;
                        assert!(
                            server
                                .connection(peer)
                                .unwrap()
                                .return_routability_checks_negotiated()
                        );
                    }
                    Ok(ServerEvent::Received(peer, data)) => {
                        assert_eq!(peer, admitted);
                        assert_ne!(data, b"unvalidated");
                        server.send_to(&data, peer).unwrap();
                        received.push(data);
                    }
                    Ok(ServerEvent::Closed(peer)) => {
                        assert_eq!(peer, admitted);
                        assert!(server.connection(peer).is_none());
                        assert!(server.peer_addr(peer).is_none());
                        assert_eq!(server.peers().count(), 0);
                        return received;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
                    other => panic!("{other:?}"),
                }
                if !announced && server.peer_addr(admitted) == Some(migrated) {
                    assert_eq!(server.peers().collect::<Vec<_>>(), [admitted]);
                    assert!(server.connection(migrated).is_none());
                    server.send_to(b"validated", admitted).unwrap();
                    announced = true;
                }
            }
        });
        let conn = dtls::ClientConnection::new_with_settings(
            Arc::new(client_config(&chain)),
            server_name(),
            migration_settings(versions, client_cid_len),
        )
        .unwrap();
        let start = Instant::now();
        let mut client = UdpClient::from_connection_with_clock(conn, socket, start);
        let timeout = Some(Duration::from_secs(10));
        client.set_read_timeout(timeout);
        client.complete_handshake().unwrap();
        client.send(b"before").unwrap();
        // Preserve already queued plaintext across the replacement too.
        assert_eq!(
            client.recv(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        let wrong_remote = loopback();
        let wrong = client_socket(wrong_remote.local_addr().unwrap());
        assert_eq!(
            client.replace_socket(wrong).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(client.socket().local_addr().unwrap(), admitted);
        drop(client.replace_socket(replacement).unwrap());
        assert_eq!(client.read_timeout(), timeout);
        assert_eq!(client.socket().peer_addr().unwrap(), remote);
        let mut buf = [0; 32];
        let len = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"before");
        client.send(b"unvalidated").unwrap();
        let len = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"validated");
        client.send(b"after").unwrap();
        let len = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"after");
        client.close().unwrap();
        assert_eq!(client.into_parts_with_clock().2, start);
        assert_eq!(
            serving.join().unwrap(),
            [b"before".to_vec(), b"after".to_vec()]
        );
    }
}

#[test]
fn default_client_does_not_replace_its_socket() {
    let chain = server_chain(KeyType::EcdsaP256);
    let server = server(&chain);
    let remote = server.socket().local_addr().unwrap();
    let serving = thread::spawn(move || echo(server, 1));
    let socket = client_socket(remote);
    let admitted = socket.local_addr().unwrap();
    let conn = dtls::ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut client = UdpClient::from_connection(conn, socket);
    client.set_read_timeout(Some(Duration::from_secs(10)));
    client.complete_handshake().unwrap();
    assert!(!client.connection().return_routability_checks_negotiated());
    assert_eq!(
        client
            .replace_socket(client_socket(remote))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotConnected
    );
    assert_eq!(client.socket().local_addr().unwrap(), admitted);
    client.close().unwrap();
    assert_eq!(serving.join().unwrap(), ["connected", "closed"]);
}

#[test]
fn socket_replacement_requires_the_servers_nonempty_receiving_cid() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut server = UdpServer::new_with_settings(
        Arc::new(dtls_server_config(&chain)),
        loopback(),
        migration_settings(dtls::Versions::V1_3, 0),
    )
    .unwrap();
    server.set_read_timeout(Some(Duration::from_secs(20)));
    let remote = server.socket().local_addr().unwrap();
    let serving = thread::spawn(move || echo(server, 1));
    let mut client = UdpClient::connect_with_settings(
        Arc::new(client_config(&chain)),
        server_name(),
        client_socket(remote),
        migration_settings(dtls::Versions::V1_3, 8),
    )
    .unwrap();
    let admitted = client.socket().local_addr().unwrap();
    assert!(client.connection().return_routability_checks_negotiated());
    assert_eq!(
        client
            .replace_socket(client_socket(remote))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(client.socket().local_addr().unwrap(), admitted);
    client.close().unwrap();
    assert_eq!(serving.join().unwrap(), ["connected", "closed"]);
}
