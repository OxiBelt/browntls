//! Loopback and cancellation coverage for the Tokio DTLS server adapter.
#![cfg(all(feature = "dtls", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use browntls_core::dtls::ClientConnection;
use browntls_core::pki_types::ServerName;
use browntls_core::{ClientConfig, ProtocolVersion, ServerConfig};
use browntls_tokio::dtls::{ServerEvent, UdpServer};
use common::Pki;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

const LIMIT: Duration = Duration::from_secs(5);

// Poll both participants directly: these tests need no spawned tasks,
// macros, external services or dependencies beyond the existing helpers.
async fn together<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let mut a = pin!(a);
    let mut b = pin!(b);
    let mut a_result = None;
    let mut b_result = None;
    poll_fn(|cx| {
        if a_result.is_none()
            && let Poll::Ready(result) = a.as_mut().poll(cx)
        {
            a_result = Some(result);
        }
        if b_result.is_none()
            && let Poll::Ready(result) = b.as_mut().poll(cx)
        {
            b_result = Some(result);
        }
        if a_result.is_some() && b_result.is_some() {
            Poll::Ready((a_result.take().unwrap(), b_result.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

fn run(test: impl Future<Output = ()>) {
    run_with_limit(LIMIT, test);
}

fn run_with_limit(limit: Duration, test: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { timeout(limit, test).await.unwrap() });
}

fn config(pki: &Pki) -> Arc<ServerConfig> {
    config_for(pki, &browntls_core::version::TLS13)
}

fn config_for(
    pki: &Pki,
    version: &'static browntls_core::SupportedProtocolVersion,
) -> Arc<ServerConfig> {
    let mut config = pki.server_config_with_client_auth(version);
    #[cfg(feature = "native")]
    let cookies = Arc::new(
        browntls_core::ticketer::TicketRotator::new(3600, || {
            Ok(Box::new(
                browntls_core::crypto::native::ticketer::AeadTicketProducer::new()?,
            ))
        })
        .unwrap(),
    );
    #[cfg(not(feature = "native"))]
    let cookies = browntls_core::crypto::rustcrypto::Ticketer::new().unwrap();
    config.hello_retry_cookies = Some(cookies);
    // No post-handshake tickets to leave outstanding in timer tests.
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

async fn server(pki: &Pki) -> UdpServer {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    UdpServer::new(config(pki), socket).unwrap()
}

#[cfg(feature = "tls12")]
#[test]
fn tokio_adapters_apply_the_explicit_dtls12_policy() {
    use browntls_core::dtls::Versions;
    use browntls_core::version::TLS12;
    use browntls_tokio::dtls::UdpClient;

    run(async {
        let pki = Pki::new();
        let listening = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = listening.local_addr().unwrap();
        let mut server =
            UdpServer::new_with_versions(config_for(&pki, &TLS12), listening, Versions::V1_2)
                .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = socket.local_addr().unwrap();
        socket.connect(remote).await.unwrap();
        let mut client = UdpClient::new_with_versions(
            Arc::new(pki.client_config_with_cert(&TLS12)),
            common::localhost(),
            socket,
            Versions::V1_2,
        )
        .unwrap();
        let (handshake, event) = together(client.complete_handshake(), server.next_event()).await;
        handshake.unwrap();
        assert!(matches!(event.unwrap(), ServerEvent::Connected(addr) if addr == peer));
        assert_eq!(
            client.connection().protocol_version(),
            Some(ProtocolVersion::DTLSv1_2)
        );
        let (sent, received) = together(client.send(b"tokio dtls12"), server.next_event()).await;
        sent.unwrap();
        assert!(
            matches!(received.unwrap(), ServerEvent::Received(addr, data)
                         if addr == peer && data == b"tokio dtls12")
        );
    });
}

// Use the core API as the client oracle, independently of the other
// worker's Tokio client implementation and its tests.
struct Client {
    conn: ClientConnection,
    socket: UdpSocket,
    start: Instant,
    buf: Vec<u8>,
    received: VecDeque<Vec<u8>>,
}

impl Client {
    async fn new(pki: &Pki, server: SocketAddr) -> Self {
        Self::with_config(
            Arc::new(pki.client_config_with_cert(&browntls_core::version::TLS13)),
            server,
        )
        .await
    }

    async fn with_config(config: Arc<ClientConfig>, server: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(server).await.unwrap();
        Self {
            conn: ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
                .unwrap(),
            socket,
            start: Instant::now(),
            buf: vec![0; 65_535],
            received: VecDeque::new(),
        }
    }

    async fn flush(&mut self) {
        let mut out = Vec::new();
        while self
            .conn
            .write_datagram(&mut out, self.start.elapsed())
            .unwrap()
        {
            assert_eq!(self.socket.send(&out).await.unwrap(), out.len());
            out.clear();
        }
    }

    async fn read(&mut self) {
        let len = self.socket.recv(&mut self.buf).await.unwrap();
        let received = self
            .conn
            .read_datagram(&mut self.buf[..len], self.start.elapsed())
            .unwrap();
        for range in received.app_data() {
            self.received.push_back(self.buf[range.clone()].to_vec());
        }
        self.flush().await;
    }

    async fn handshake(&mut self) {
        self.flush().await;
        while self.conn.is_handshaking() {
            self.read().await;
        }
    }

    async fn send(&mut self, data: &[u8]) {
        let mut out = Vec::new();
        self.conn.send(data, &mut out).unwrap();
        assert_eq!(self.socket.send(&out).await.unwrap(), out.len());
        self.flush().await;
    }

    async fn recv(&mut self) -> Vec<u8> {
        loop {
            if let Some(data) = self.received.pop_front() {
                return data;
            }
            self.read().await;
        }
    }
}

async fn connect(server: &mut UdpServer, client: &mut Client) -> SocketAddr {
    let (event, ()) = together(server.next_event(), client.handshake()).await;
    match event.unwrap() {
        ServerEvent::Connected(peer) => {
            assert_eq!(peer, client.socket.local_addr().unwrap());
            peer
        }
        event => panic!("expected a connection, got {event:?}"),
    }
}

async fn no_event(server: &mut UdpServer) {
    let err = server.next_event().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
}

// Complete only the cookie exchange, leaving the server's handshake
// flight unanswered. Each read timeout is an absolute operation deadline.
async fn pending(server: &mut UdpServer, client: &mut Client) {
    server.set_read_timeout(Some(Duration::from_millis(10)));
    client.flush().await;
    no_event(server).await;
    assert_eq!(server.handshakes(), 0, "the first hello is stateless");
    client.read().await;
    // read() has sent the validated second ClientHello.
    no_event(server).await;
    assert_eq!(server.handshakes(), 1);
}

#[test]
fn mutually_authenticated_peers_exchange_whole_and_empty_datagrams() {
    run(async {
        let pki = Pki::new();
        let mut server = server(&pki).await;
        let addr = server.socket().local_addr().unwrap();
        let mut first = Client::new(&pki, addr).await;
        let mut second = Client::new(&pki, addr).await;
        for client in [&mut first, &mut second] {
            let peer = connect(&mut server, client).await;
            let conn = server.connection(peer).unwrap();
            assert_eq!(conn.protocol_version(), Some(ProtocolVersion::DTLSv1_3));
            assert_eq!(
                conn.peer_certificates().unwrap(),
                pki.client_chain.as_slice()
            );
            for data in [&b""[..], &b"whole datagram"[..]] {
                client.send(data).await;
                assert!(matches!(
                    server.next_event().await.unwrap(),
                    ServerEvent::Received(from, received) if from == peer && received == data
                ));
                server.send_to(data, peer).await.unwrap();
                assert_eq!(client.recv().await, data);
            }
            server
                .connection_mut(peer)
                .unwrap()
                .refresh_traffic_keys()
                .unwrap();
            server.send_to(b"fresh keys", peer).await.unwrap();
            assert_eq!(client.recv().await, b"fresh keys");
        }
        assert_eq!(server.peers().count(), 2);
        let peer = first.socket.local_addr().unwrap();
        first.conn.send_close_notify();
        first.flush().await;
        assert!(
            matches!(server.next_event().await.unwrap(), ServerEvent::Closed(from) if from == peer)
        );
        assert!(server.connection(peer).is_none());
        let peer = second.socket.local_addr().unwrap();
        server.close(peer).await.unwrap();
        while !second.conn.peer_has_closed() {
            second.read().await;
        }
        assert_eq!(server.peers().count(), 0);
    });
}

#[test]
fn cancelling_receive_preserves_control_progress_and_buffered_records() {
    run(async {
        let pki = Pki::new();
        let mut server = server(&pki).await;
        let mut client = Client::new(&pki, server.socket().local_addr().unwrap()).await;
        let peer = connect(&mut server, &mut client).await;
        client.conn.refresh_traffic_keys().unwrap();
        client.flush().await;
        server.socket().readable().await.unwrap();
        // Consume control input, but cancel the receive before any
        // application event exists. All protocol progress lives in server.
        poll_fn(|cx| {
            let mut event = pin!(server.next_event());
            assert!(event.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        let mut out = Vec::new();
        client.conn.send(b"first", &mut out).unwrap();
        client.conn.send(b"", &mut out).unwrap();
        client.conn.send(b"third", &mut out).unwrap();
        client.socket.send(&out).await.unwrap();
        assert!(matches!(
            server.next_event().await.unwrap(),
            ServerEvent::Received(from, data) if from == peer && data == b"first"
        ));
        // Constructing and dropping a new receive must not consume the
        // remaining records, which already belong to the event queue.
        drop(server.next_event());
        for expected in [&b""[..], &b"third"[..]] {
            assert!(matches!(
                server.next_event().await.unwrap(),
                ServerEvent::Received(from, data) if from == peer && data == expected
            ));
        }
        server.send_to(b"after cancellation", peer).await.unwrap();
        assert_eq!(client.recv().await, b"after cancellation");
    });
}

#[test]
fn handshake_retransmission_and_expiry_progress_before_queued_junk() {
    run_with_limit(Duration::from_secs(3600), async {
        let pki = Pki::new();
        let mut server = server(&pki).await;
        server.set_handshake_timeout(Duration::from_secs(5));
        let addr = server.socket().local_addr().unwrap();
        let mut client = Client::new(&pki, addr).await;
        pending(&mut server, &mut client).await;
        let mut buf = vec![0; 65_535];
        assert!(client.socket.recv(&mut buf).await.unwrap() > 0);
        while client.socket.try_recv(&mut buf).is_ok() {}

        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(2)).await;
        server.set_read_timeout(Some(Duration::ZERO));
        no_event(&mut server).await;
        let len = client.socket.recv(&mut buf).await.unwrap();
        assert!(len > 0, "an unanswered handshake flight is retransmitted");

        let junk = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..128 {
            junk.send_to(&[0x16; 40], addr).await.unwrap();
        }
        tokio::time::advance(Duration::from_secs(4)).await;
        no_event(&mut server).await;
        assert_eq!(
            server.handshakes(),
            0,
            "ready traffic cannot postpone expiry"
        );
        assert_eq!(server.peers().count(), 0);
    });
}

#[test]
fn a_peer_retransmission_failure_leaves_another_peer_usable() {
    run_with_limit(Duration::from_secs(3600), async {
        let pki = Pki::new();
        let mut server = server(&pki).await;
        let addr = server.socket().local_addr().unwrap();
        let mut silent = Client::new(&pki, addr).await;
        let mut healthy = Client::new(&pki, addr).await;
        let silent_peer = connect(&mut server, &mut silent).await;
        let healthy_peer = connect(&mut server, &mut healthy).await;
        server
            .connection_mut(silent_peer)
            .unwrap()
            .refresh_traffic_keys()
            .unwrap();
        server.set_read_timeout(Some(Duration::ZERO));
        no_event(&mut server).await;
        tokio::time::pause();
        let mut failed = false;
        // The core backs off up to one minute and fails after bounded
        // unanswered retransmissions. Leave the first client's socket idle.
        for _ in 0..12 {
            tokio::time::advance(Duration::from_secs(61)).await;
            match server.next_event().await {
                Ok(ServerEvent::Failed(peer, _)) => {
                    assert_eq!(peer, silent_peer);
                    failed = true;
                    break;
                }
                Err(err) => assert_eq!(err.kind(), io::ErrorKind::TimedOut),
                event => panic!("unexpected event: {event:?}"),
            }
        }
        assert!(failed, "the unacknowledged key update must eventually fail");
        assert!(server.connection(silent_peer).is_none());
        assert!(server.connection(healthy_peer).is_some());
        tokio::time::resume();
        server.set_read_timeout(Some(LIMIT));
        healthy.send(b"still usable").await;
        assert!(matches!(
            server.next_event().await.unwrap(),
            ServerEvent::Received(peer, data) if peer == healthy_peer && data == b"still usable"
        ));
        server.send_to(b"yes", healthy_peer).await.unwrap();
        assert_eq!(healthy.recv().await, b"yes");
    });
}

#[test]
fn handshake_slots_are_bounded_and_cookie_validation_precedes_eviction() {
    run(async {
        let pki = Pki::new();
        let mut server = server(&pki).await;
        server.set_max_handshakes(1);
        let addr = server.socket().local_addr().unwrap();
        let mut first = Client::new(&pki, addr).await;
        pending(&mut server, &mut first).await;
        let mut second = Client::new(&pki, addr).await;
        second.flush().await;
        no_event(&mut server).await;
        assert_eq!(
            server.handshakes(),
            1,
            "a first hello costs no handshake slot"
        );
        second.read().await;
        no_event(&mut server).await;
        assert_eq!(server.handshakes(), 1);
        assert!(server.remove(first.socket.local_addr().unwrap()).is_none());
        assert!(server.remove(second.socket.local_addr().unwrap()).is_some());
        assert_eq!(server.handshakes(), 0);
    });
}

#[test]
fn established_limit_and_invalid_send_leave_existing_peer_usable() {
    run(async {
        let pki = Pki::new();
        let mut server = server(&pki).await;
        server.set_max_peers(1);
        let addr = server.socket().local_addr().unwrap();
        let mut first = Client::new(&pki, addr).await;
        let peer = connect(&mut server, &mut first).await;
        let mut second = Client::new(&pki, addr).await;
        server.set_read_timeout(Some(Duration::from_millis(250)));
        let (event, ()) = together(server.next_event(), second.handshake()).await;
        assert_eq!(event.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(server.peers().collect::<Vec<_>>(), vec![peer]);
        let err = server.send_to(&vec![0; 65_535], peer).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(server.connection(peer).is_some());
        server.send_to(b"after rejected send", peer).await.unwrap();
        assert_eq!(first.recv().await, b"after rejected send");
        let absent = second.socket.local_addr().unwrap();
        let err = server.send_to(b"no association", absent).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    });
}

#[test]
fn invalid_configuration_and_connected_sockets_are_rejected() {
    run(async {
        let pki = Pki::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let no_cookies = Arc::new(pki.server_config(&browntls_core::version::TLS13));
        let err = UdpServer::new(no_cookies, socket).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(remote.local_addr().unwrap()).await.unwrap();
        let err = UdpServer::new(config(&pki), socket).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    });
}

async fn event_migration(
    version: &'static browntls_core::SupportedProtocolVersion,
    versions: browntls_core::dtls::Versions,
    selection: browntls_core::dtls::rrc::Selection,
) {
    use browntls_core::dtls::{ConnectionIdPolicy, Settings};
    use browntls_tokio::dtls::{Recv, UdpClient};

    let settings = || {
        Settings::default()
            .with_versions(versions)
            .with_return_routability_checks(ConnectionIdPolicy::new(8, true).unwrap())
    };
    let pki = Pki::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = socket.local_addr().unwrap();
    let mut server =
        UdpServer::new_with_settings(config_for(&pki, version), socket, settings()).unwrap();
    server.set_path_selection(selection);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(remote).await.unwrap();
    let admitted = socket.local_addr().unwrap();
    let mut client = UdpClient::new_with_settings(
        Arc::new(pki.client_config_with_cert(version)),
        common::localhost(),
        socket,
        settings(),
    )
    .unwrap();
    let (handshake, event) = together(client.complete_handshake(), server.next_event()).await;
    handshake.unwrap();
    assert!(matches!(event.unwrap(), ServerEvent::Connected(peer) if peer == admitted));
    let replacement = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    replacement.connect(remote).await.unwrap();
    let migrated = replacement.local_addr().unwrap();
    drop(client.replace_socket(replacement).unwrap());
    client.send(b"candidate").await.unwrap();
    together(async {
        let event = server.next_event().await.unwrap();
        assert!(matches!(event, ServerEvent::PeerAddressChanged(peer, addr) if peer == admitted && addr == migrated));
        assert_eq!(server.peer_addr(admitted), Some(migrated));
        assert!(server.connection(migrated).is_none());
        server.send_to(b"validated", admitted).await.unwrap();
    }, async {
        let mut buf = [0; 32];
        assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Data(9));
        assert_eq!(&buf[..9], b"validated");
    }).await;
    let (sent, event) = together(client.send(b"after"), server.next_event()).await;
    sent.unwrap();
    assert!(
        matches!(event.unwrap(), ServerEvent::Received(peer, data) if peer == admitted && data == b"after")
    );
}

#[test]
fn event_server_migrates_dtls13_in_both_modes() {
    use browntls_core::dtls::{Versions, rrc::Selection};
    run_with_limit(Duration::from_secs(20), async {
        for selection in [Selection::Basic, Selection::Enhanced] {
            event_migration(&browntls_core::version::TLS13, Versions::V1_3, selection).await;
        }
    });
}

#[cfg(feature = "tls12")]
#[test]
fn event_server_migrates_dtls12_in_both_modes() {
    use browntls_core::dtls::{Versions, rrc::Selection};
    run_with_limit(Duration::from_secs(20), async {
        for selection in [Selection::Basic, Selection::Enhanced] {
            event_migration(&browntls_core::version::TLS12, Versions::V1_2, selection).await;
        }
    });
}

#[test]
fn coalesced_path_challenges_each_receive_a_protected_reply() {
    use browntls_core::dtls::rrc::{Message, MessageType};
    use browntls_core::dtls::{ConnectionIdPolicy, Settings};

    run(async {
        let pki = Pki::new();
        let settings = Settings::default()
            .with_return_routability_checks(ConnectionIdPolicy::new(8, true).unwrap());
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let mut server =
            UdpServer::new_with_settings(config(&pki), socket, settings.clone()).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(address).await.unwrap();
        let mut client = Client {
            conn: ClientConnection::new_with_settings(
                Arc::new(pki.client_config_with_cert(&browntls_core::version::TLS13)),
                ServerName::try_from("localhost").unwrap(),
                settings,
            )
            .unwrap(),
            socket,
            start: Instant::now(),
            buf: vec![0; 65_535],
            received: VecDeque::new(),
        };
        connect(&mut server, &mut client).await;

        let cookies = [[0x31; 8], [0x58; 8]];
        let mut datagram = Vec::new();
        for cookie in cookies {
            client
                .conn
                .send_rrc(
                    &Message {
                        kind: MessageType::Challenge,
                        cookie,
                    },
                    &mut datagram,
                )
                .unwrap();
        }
        client.socket.send(&datagram).await.unwrap();
        server.set_read_timeout(Some(Duration::from_millis(100)));
        let received = async {
            let mut replies = Vec::new();
            let mut input = [0; 1200];
            while replies.len() < cookies.len() {
                let len = client.socket.recv(&mut input).await.unwrap();
                let input = &mut input[..len];
                let records = client
                    .conn
                    .read_datagram(input, client.start.elapsed())
                    .unwrap();
                for range in records
                    .authenticated_records()
                    .iter()
                    .filter_map(|metadata| metadata.rrc_payload_range())
                {
                    let message = Message::decode(&input[range]).unwrap().unwrap();
                    assert_eq!(message.kind, MessageType::Response);
                    replies.push(message.cookie);
                }
            }
            replies
        };
        let (event, replies) = together(server.next_event(), received).await;
        assert_eq!(event.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(replies, cookies);
    });
}

// This peer uses the core DTLS record boundary, but drives the RFC 9853
// exchange directly instead of running the library's path validator.
async fn reference_path_exchange(
    version: &'static browntls_core::SupportedProtocolVersion,
    versions: browntls_core::dtls::Versions,
    selection: browntls_core::dtls::rrc::Selection,
) {
    use browntls_core::dtls::rrc::{Message, MessageType, Selection};
    use browntls_core::dtls::{ConnectionIdPolicy, Settings};

    async fn challenge(socket: &UdpSocket, conn: &mut ClientConnection, start: Instant) -> [u8; 8] {
        let mut datagram = [0; 1200];
        loop {
            let len = socket.recv(&mut datagram).await.unwrap();
            let input = &mut datagram[..len];
            let received = conn.read_datagram(input, start.elapsed()).unwrap();
            for metadata in received.authenticated_records() {
                if let Some(range) = metadata.rrc_payload_range() {
                    let payload = &input[range];
                    assert_eq!(payload.len(), 9);
                    assert_eq!(payload[0], 0);
                    return payload[1..].try_into().unwrap();
                }
            }
        }
    }

    async fn answer(
        socket: &UdpSocket,
        conn: &mut ClientConnection,
        kind: MessageType,
        cookie: [u8; 8],
    ) {
        let mut datagram = Vec::new();
        conn.send_rrc(&Message { kind, cookie }, &mut datagram)
            .unwrap();
        assert_eq!(socket.send(&datagram).await.unwrap(), datagram.len());
    }

    let pki = Pki::new();
    let settings = Settings::default()
        .with_versions(versions)
        .with_return_routability_checks(ConnectionIdPolicy::new(8, true).unwrap());
    let listening = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = listening.local_addr().unwrap();
    let mut server =
        UdpServer::new_with_settings(config_for(&pki, version), listening, settings.clone())
            .unwrap();
    server.set_path_selection(selection);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    let mut client = Client {
        conn: ClientConnection::new_with_settings(
            Arc::new(pki.client_config_with_cert(version)),
            ServerName::try_from("localhost").unwrap(),
            settings,
        )
        .unwrap(),
        socket,
        start: Instant::now(),
        buf: vec![0; 65_535],
        received: VecDeque::new(),
    };
    let admitted = connect(&mut server, &mut client).await;
    let new = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    new.connect(address).await.unwrap();
    let changed = new.local_addr().unwrap();
    let mut datagram = Vec::new();
    client.conn.send(b"path trigger", &mut datagram).unwrap();
    assert_eq!(new.send(&datagram).await.unwrap(), datagram.len());
    let reference = async {
        if selection == Selection::Enhanced {
            let old_cookie = challenge(&client.socket, &mut client.conn, client.start).await;
            answer(
                &client.socket,
                &mut client.conn,
                MessageType::Drop,
                old_cookie,
            )
            .await;
        }
        let new_cookie = challenge(&new, &mut client.conn, client.start).await;
        answer(&new, &mut client.conn, MessageType::Response, new_cookie).await;
    };
    let (event, ()) = together(server.next_event(), reference).await;
    assert!(matches!(
        event.unwrap(),
        ServerEvent::PeerAddressChanged(peer, path) if peer == admitted && path == changed
    ));
    assert_eq!(server.peer_addr(admitted), Some(changed));
}

#[test]
fn reference_peer_controls_basic_and_enhanced_path_selection() {
    use browntls_core::dtls::{Versions, rrc::Selection};
    run(async {
        for selection in [Selection::Basic, Selection::Enhanced] {
            reference_path_exchange(&browntls_core::version::TLS13, Versions::V1_3, selection)
                .await;
            #[cfg(feature = "tls12")]
            reference_path_exchange(&browntls_core::version::TLS12, Versions::V1_2, selection)
                .await;
        }
    });
}
