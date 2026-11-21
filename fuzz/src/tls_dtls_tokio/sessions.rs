//! Caller-polled session programs and reusable public API contracts.
//!
//! The driver is deliberately not polled during cancellation setup, so
//! pending commands cannot execute before their callers are dropped.

use std::io;
use std::pin::Pin;

use browntls_core::ServerConfig;
use browntls_core::dtls::Versions;
use browntls_tokio::dtls::{Recv, SessionLimits, UdpListener, UdpSession};

use super::*;

// Keep one driver future alive across operations without spawning a task.
// Completion is permitted only after the listener and all handles drop.
async fn drive<F: Future<Output = io::Result<()>>, A: Future>(
    mut driver: Pin<&mut F>,
    application: A,
) -> A::Output {
    let mut application = pin!(application);
    poll_fn(|cx| {
        if let Poll::Ready(value) = application.as_mut().poll(cx) {
            return Poll::Ready(value);
        }
        if let Poll::Ready(result) = driver.as_mut().poll(cx) {
            panic!("session driver stopped while handles are live: {result:?}");
        }
        Poll::Pending
    })
    .await
}

pub(super) async fn exercise(
    config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    constructor: usize,
    flags: u8,
    mtu: usize,
    mut input: Input<'_>,
) {
    let limits = SessionLimits {
        max_sessions: 2,
        accept_queue: 2,
        receive_queue: 2 + mtu % 3,
        command_queue: 1 + usize::from(mtu == 512),
    };
    // Exercise the public default without retaining its larger queues.
    let defaults = SessionLimits::default();
    assert!(defaults.accept_queue <= defaults.max_sessions);
    assert!(!format!("{defaults:?}").is_empty());
    if flags & 0x10 != 0 {
        rejected(&server_config, limits).await;
    }
    let transport = socket().await;
    let server_addr = transport.local_addr().unwrap();
    let (mut listener, driver) = if constructor & 1 == 0 {
        let pair = UdpListener::new(server_config, transport, limits).unwrap();
        reached("listener new");
        pair
    } else {
        let pair = UdpListener::new_with_versions(server_config, transport, Versions::V1_3, limits)
            .unwrap();
        reached("listener versions");
        pair
    };
    assert!(format!("{listener:?}").contains("UdpListener"));
    assert!(format!("{driver:?}").contains("SessionDriver"));
    // Cancellation must not consume a future authenticated handle.
    cancel_pending(listener.accept()).await;
    reached("accept cancellation");
    let mut driver = Box::pin(driver.run());
    let client = make_client(
        constructor,
        config.clone(),
        connected_socket(server_addr).await,
        mtu,
    );
    let first = drive(driver.as_mut(), Association::accept(&mut listener, client)).await;
    let mut world = World {
        listener: Some(listener),
        peers: vec![first],
        config,
        server_addr,
        constructor,
        mtu,
        admitted: 1,
    };
    let cancelled = drive(driver.as_mut(), world.program(&mut input)).await;
    if cancelled {
        drop(driver);
        world.driver_gone().await;
        reached("driver cancellation");
    } else {
        drop(world);
        bounded(driver)
            .await
            .expect("driver shutdown after last drop");
        reached("driver shutdown");
    }
}

async fn rejected(config: &Arc<ServerConfig>, valid: SessionLimits) {
    // Validate counts and checked byte accounting before channel allocation.
    for limits in [
        SessionLimits {
            max_sessions: 0,
            ..valid
        },
        SessionLimits {
            max_sessions: 1025,
            ..valid
        },
        SessionLimits {
            accept_queue: 0,
            ..valid
        },
        SessionLimits {
            accept_queue: 3,
            ..valid
        },
        SessionLimits {
            receive_queue: 0,
            ..valid
        },
        SessionLimits {
            receive_queue: usize::MAX,
            ..valid
        },
        SessionLimits {
            receive_queue: 1024,
            ..valid
        },
        SessionLimits {
            command_queue: 0,
            ..valid
        },
        SessionLimits {
            command_queue: usize::MAX,
            ..valid
        },
        SessionLimits {
            command_queue: 64,
            ..valid
        },
    ] {
        assert_eq!(
            UdpListener::new(config.clone(), socket().await, limits)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }
    let destination = socket().await;
    let connected = connected_socket(destination.local_addr().unwrap()).await;
    assert_eq!(
        UdpListener::new(config.clone(), connected, valid)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    let mut no_cookies = (**config).clone();
    no_cookies.hello_retry_cookies = None;
    assert!(UdpListener::new(Arc::new(no_cookies), socket().await, valid).is_err());
    reached("session limits rejected");
}

struct Association {
    client: UdpClient,
    session: UdpSession,
}

impl Association {
    async fn accept(listener: &mut UdpListener, mut client: UdpClient) -> Self {
        client.set_timeout(Some(LIMIT));
        let (handshake, accepted) = together(client.complete_handshake(), listener.accept()).await;
        handshake.expect("verified session handshake");
        let session = accepted.expect("authenticated session");
        let association = Self { client, session };
        association.inspect();
        reached("session accepted");
        association
    }

    fn inspect(&self) {
        assert_eq!(
            self.session.peer_addr(),
            self.client.socket().local_addr().unwrap()
        );
        assert!(self.session.peer_addr().ip().is_loopback());
        assert!(!self.client.connection().is_handshaking());
        assert_eq!(
            self.client.connection().protocol_version(),
            Some(ProtocolVersion::DTLSv1_3)
        );
        assert!(format!("{:?}", self.session).contains("UdpSession"));
        reached("session accessors");
    }

    // Clamp short_field payloads to the client's MTU-dependent limit.
    async fn send_to_server(&mut self, data: &[u8]) {
        let max = self.client.connection().max_application_data().unwrap();
        let data = &data[..data.len().min(max)];
        bounded(self.client.send(data)).await.unwrap();
        self.received(data).await;
    }

    async fn received(&mut self, expected: &[u8]) {
        assert_eq!(
            bounded(self.session.recv()).await.unwrap().as_deref(),
            Some(expected)
        );
        reached("session receive");
        if expected.is_empty() {
            reached("session empty receive");
        }
    }

    async fn send_to_client(&mut self, data: &[u8]) {
        bounded(self.session.send(data)).await.unwrap();
        self.receive(data).await;
    }

    async fn receive(&mut self, expected: &[u8]) {
        let mut buffer = [0; 256];
        assert_eq!(
            bounded(self.client.recv(&mut buffer)).await.unwrap(),
            Recv::Data(expected.len())
        );
        assert_eq!(&buffer[..expected.len()], expected);
        reached("session send");
        if expected.is_empty() {
            reached("session empty send");
        }
    }

    async fn datagrams(&mut self, data: &[u8]) {
        // At least two receive slots; no intentional UDP loss in this model.
        let max = self.client.connection().max_application_data().unwrap();
        let client_data = &data[..data.len().min(max)];
        bounded(self.client.send(client_data)).await.unwrap();
        bounded(self.client.send(b"second input")).await.unwrap();
        self.received(client_data).await;
        self.received(b"second input").await;
        bounded(self.session.send(data)).await.unwrap();
        bounded(self.session.send(b"second output")).await.unwrap();
        self.receive(data).await;
        self.receive(b"second output").await;
        reached("session datagram boundaries");
    }

    async fn closed(&mut self, remote: bool) {
        if remote {
            bounded(self.client.send(b"before close")).await.unwrap();
            bounded(self.client.close()).await.unwrap();
            self.received(b"before close").await;
        } else {
            bounded(self.session.close()).await.unwrap();
            assert_eq!(
                bounded(self.client.recv(&mut [])).await.unwrap(),
                Recv::Closed
            );
        }
        assert_eq!(bounded(self.session.recv()).await.unwrap(), None);
        assert_eq!(bounded(self.session.recv()).await.unwrap(), None);
        bounded(self.session.close()).await.unwrap();
        assert_eq!(
            bounded(self.session.send(b"closed"))
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::NotConnected
        );
        reached(if remote {
            "session remote close"
        } else {
            "session local close"
        });
    }
}

struct World {
    listener: Option<UdpListener>,
    peers: Vec<Association>,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    constructor: usize,
    mtu: usize,
    admitted: usize,
}

impl World {
    // A true result asks the outer owner to drop the driver, then check
    // failure propagation with the still-live listener and sessions.
    async fn program(&mut self, input: &mut Input<'_>) -> bool {
        for _ in 0..MAX_ACTIONS {
            if input.is_empty() {
                break;
            }
            let selector = input.byte();
            let index = usize::from(selector >> 4) % self.peers.len();
            match selector & 15 {
                0 => self.peers[index].send_to_server(input.short_field()).await,
                1 => self.peers[index].send_to_client(input.short_field()).await,
                2 => self.peers[index].datagrams(input.short_field()).await,
                3 => {
                    cancel_pending(self.peers[index].session.recv()).await;
                    if let Some(listener) = &mut self.listener {
                        cancel_pending(listener.accept()).await;
                    }
                    self.peers[index]
                        .send_to_server(b"after cancelled receive")
                        .await;
                    reached("session receive cancellation");
                }
                4 => {
                    // Driver excluded from these polls: one queued send,
                    // followed by a close either queued or awaiting capacity.
                    let session = &self.peers[index].session;
                    cancel_pending(session.send(b"cancelled command")).await;
                    cancel_pending(session.close()).await;
                    self.peers[index]
                        .send_to_client(b"after cancelled commands")
                        .await;
                    self.peers[index].send_to_server(b"still open").await;
                    reached("session command cancellation");
                }
                5 => {
                    assert_eq!(
                        bounded(self.peers[index].session.send(&vec![0; 65_536]))
                            .await
                            .unwrap_err()
                            .kind(),
                        ErrorKind::InvalidInput
                    );
                    self.peers[index]
                        .send_to_client(b"after size rejection")
                        .await;
                    reached("session oversized rejected");
                }
                6 => self.second().await,
                7 => {
                    drop(self.listener.take());
                    self.peers[index]
                        .send_to_client(b"after listener drop")
                        .await;
                    self.peers[index]
                        .send_to_server(b"admissions stopped")
                        .await;
                    reached("listener drop preserves sessions");
                }
                8 | 9 => {
                    self.peers[index].closed(selector & 15 == 8).await;
                    for (other, peer) in self.peers.iter_mut().enumerate() {
                        if other != index {
                            peer.send_to_server(b"unrelated peer").await;
                            peer.send_to_client(b"unrelated reply").await;
                            reached("session close isolation");
                        }
                    }
                    return false;
                }
                10 => return true,
                11 => {
                    drop(self.peers.remove(index));
                    reached("session handle drop");
                    return false;
                }
                12 => self.peers[index].inspect(),
                13 => {
                    self.peers[index].send_to_server(b"").await;
                    self.peers[index].send_to_client(b"").await;
                }
                14 => {
                    cancel_pending(self.peers[index].session.close()).await;
                    self.peers[index]
                        .send_to_client(b"after cancelled close")
                        .await;
                    reached("session close cancellation");
                }
                _ => {
                    for peer in &mut self.peers {
                        peer.send_to_server(b"separate association").await;
                        peer.send_to_client(b"separate reply").await;
                    }
                    if self.peers.len() == 2 {
                        reached("session peer isolation");
                    }
                }
            }
        }
        // No datagram is owed. Pump real I/O until the short idle deadline
        // to detect unexpected duplicate output or a delayed cancelled close.
        for peer in &mut self.peers {
            assert!(
                timeout(Duration::from_millis(1), peer.session.recv())
                    .await
                    .is_err()
            );
            peer.client.set_timeout(Some(Duration::from_millis(1)));
            assert_eq!(
                bounded(peer.client.recv(&mut [0; 256]))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::TimedOut
            );
        }
        false
    }

    async fn second(&mut self) {
        // At most two handshakes in any input, even after handle drops.
        if self.admitted == 2 {
            return;
        }
        if let Some(listener) = &mut self.listener {
            let client = make_client(
                self.constructor,
                self.config.clone(),
                connected_socket(self.server_addr).await,
                self.mtu,
            );
            self.peers.push(Association::accept(listener, client).await);
            self.admitted += 1;
            reached("second session");
        }
    }

    async fn driver_gone(&mut self) {
        for peer in &mut self.peers {
            assert_eq!(
                bounded(peer.session.recv()).await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );
            assert_eq!(
                bounded(peer.session.send(b"late"))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::BrokenPipe
            );
            assert_eq!(
                bounded(peer.session.close()).await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );
        }
        if let Some(listener) = &mut self.listener {
            assert_eq!(
                bounded(listener.accept()).await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );
        }
    }
}
