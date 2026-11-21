//! Client-only DTLS loopback tests against the existing sans-I/O server.

#![cfg(all(feature = "dtls", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::dtls::{ClientConnection, ServerConnection, Settings};
use browntls_core::version::TLS13;
use browntls_core::{Error, ProtocolVersion};
use browntls_tokio::dtls::{Recv, UdpClient};
use common::{Pki, localhost};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

const LIMIT: Duration = Duration::from_secs(10);

// This oracle uses the existing core API directly. The fixed connected
// loopback peer is trusted, so the test does not need a cookie exchange.
struct Peer {
    conn: ServerConnection,
    socket: UdpSocket,
    start: Instant,
    received: VecDeque<Vec<u8>>,
}

impl Peer {
    async fn flush(&mut self) -> Result<(), Error> {
        let mut out = Vec::new();
        while self.conn.write_datagram(&mut out, self.start.elapsed())? {
            assert_eq!(self.socket.send(&out).await.unwrap(), out.len());
            out.clear();
        }
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Error> {
        let mut input = vec![0; 65_535];
        let len = self.socket.recv(&mut input).await.unwrap();
        let received = self
            .conn
            .read_datagram(&mut input[..len], self.start.elapsed())?;
        for range in received.app_data() {
            self.received.push_back(input[range.clone()].to_vec());
        }
        self.flush().await
    }

    async fn handshake(&mut self) -> Result<(), Error> {
        while self.conn.is_handshaking() {
            self.step().await?;
        }
        self.flush().await
    }

    async fn recv(&mut self) -> Vec<u8> {
        loop {
            if let Some(data) = self.received.pop_front() {
                return data;
            }
            self.step().await.unwrap();
        }
    }

    async fn send(&mut self, data: &[u8]) {
        let mut out = Vec::new();
        self.conn.send(data, &mut out).unwrap();
        assert_eq!(self.socket.send(&out).await.unwrap(), out.len());
        self.flush().await.unwrap();
    }
}

async fn sockets() -> (UdpSocket, UdpSocket) {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(server.local_addr().unwrap()).await.unwrap();
    server.connect(client.local_addr().unwrap()).await.unwrap();
    (client, server)
}

fn localhost_identity(reference: &str) -> browntls_core::ClientServerIdentity {
    use browntls_core::pki_types::DnsName;
    use browntls_core::{ReferenceIdentifier, ServiceIdentity};

    browntls_core::ClientServerIdentity::new(
        localhost(),
        ServiceIdentity::new(vec![ReferenceIdentifier::Dns(
            DnsName::try_from(reference).unwrap().to_owned(),
        )])
        .unwrap(),
    )
}

#[tokio::test]
async fn identity_constructor_authenticates_and_reports_the_reference() {
    timeout(LIMIT, async {
        let pki = Pki::new();
        let config = Arc::new(pki.client_config(&TLS13));
        let unconnected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            UdpClient::new_with_identity(
                config.clone(),
                localhost_identity("localhost"),
                unconnected
            )
            .is_err()
        );
        let (socket, server_socket) = sockets().await;
        let mut client = UdpClient::new_with_identity_and_settings(
            config,
            localhost_identity("localhost"),
            socket,
            Settings::default(),
        )
        .unwrap();
        let conn = ServerConnection::new_without_cookie_exchange(
            Arc::new(pki.server_config(&TLS13)),
            b"connected loopback identity test",
        )
        .unwrap();
        let mut peer = Peer {
            conn,
            socket: server_socket,
            start: Instant::now(),
            received: VecDeque::new(),
        };
        let (client_result, server_result) =
            tokio::join!(client.complete_handshake(), peer.handshake());
        client_result.unwrap();
        server_result.unwrap();
        assert_eq!(
            client.connection().matched_service_identity(),
            Some(&browntls_core::ReferenceIdentifier::Dns(
                browntls_core::pki_types::DnsName::try_from("localhost")
                    .unwrap()
                    .to_owned()
            ))
        );
    })
    .await
    .expect("identity handshake timed out");
}

async fn pair(pki: &Pki) -> (UdpClient, Peer) {
    let (client, server) = sockets().await;
    let mut conn = ClientConnection::new(Arc::new(pki.client_config(&TLS13)), localhost()).unwrap();
    conn.set_mtu(256).unwrap(); // Exercise fragmentation in both directions.
    let client = UdpClient::from_connection(conn, client).unwrap();
    let mut conn = ServerConnection::new_without_cookie_exchange(
        Arc::new(pki.server_config(&TLS13)),
        b"connected loopback test peer",
    )
    .unwrap();
    conn.set_mtu(256).unwrap();
    (
        client,
        Peer {
            conn,
            socket: server,
            start: Instant::now(),
            received: VecDeque::new(),
        },
    )
}

#[tokio::test]
async fn datagrams_empty_records_short_buffers_and_close_are_distinct() {
    timeout(LIMIT, async {
        let (mut client, mut peer) = pair(&Pki::new()).await;
        client.set_timeout(Some(LIMIT));
        let server = async {
            peer.handshake().await.unwrap();
            for data in [b"first".as_slice(), b"", b"longer record", b"last"] {
                assert_eq!(peer.recv().await, data);
                peer.send(data).await;
            }
            peer.conn.send_close_notify();
            peer.flush().await.unwrap();
            while !peer.conn.peer_has_closed() {
                peer.step().await.unwrap();
            }
        };
        let client = async {
            client.complete_handshake().await.unwrap();
            assert_eq!(
                client.connection().protocol_version(),
                Some(ProtocolVersion::DTLSv1_3)
            );
            assert!(!client.connection().is_handshaking());
            assert!(client.connection().negotiated_cipher_suite().is_some());
            assert_eq!(client.timeout(), Some(LIMIT));
            assert_eq!(client.connection().mtu(), 256);
            let max = client.connection().max_application_data().unwrap();
            assert_eq!(
                client.send(&vec![0; max + 1]).await.unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            for data in [b"first".as_slice(), b"", b"longer record", b"last"] {
                client.send(data).await.unwrap();
                let mut buf = [0; 256];
                if data == b"longer record" {
                    assert_eq!(
                        client.recv(&mut buf[..2]).await.unwrap_err().kind(),
                        io::ErrorKind::InvalidInput
                    );
                }
                assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Data(data.len()));
                assert_eq!(&buf[..data.len()], data);
            }
            assert_eq!(client.recv(&mut []).await.unwrap(), Recv::Closed);
            assert_eq!(client.recv(&mut []).await.unwrap(), Recv::Closed);
            client.close().await.unwrap();
            client.close().await.unwrap();
            assert_eq!(
                client.send(b"no").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        };
        tokio::join!(client, server);
    })
    .await
    .expect("loopback test timed out");
}

#[tokio::test]
async fn cancelling_handshake_and_receive_retains_the_client() {
    timeout(LIMIT, async {
        let (mut client, mut peer) = pair(&Pki::new()).await;
        // Cancel after a ClientHello has really crossed the socket. Keep
        // that packet and continue the server using it after cancellation.
        let mut input = vec![0; 65_535];
        let mut handshake = Box::pin(client.complete_handshake());
        let len = tokio::select! {
            result = &mut handshake => panic!("unexpected completion: {result:?}"),
            len = peer.socket.recv(&mut input) => len.unwrap(),
        };
        drop(handshake);
        assert!(client.connection().is_handshaking());
        peer.conn
            .read_datagram(&mut input[..len], peer.start.elapsed())
            .unwrap();
        let server = async {
            peer.flush().await.unwrap();
            peer.handshake().await.unwrap();
        };
        let (result, ()) = tokio::join!(client.complete_handshake(), server);
        result.unwrap();

        // Handshake completion and protocol ACKs may precede cancellation,
        // but the receive has not consumed application data from the peer.
        let mut buf = [0; 64];
        let mut receiving = Box::pin(client.recv(&mut buf));
        std::future::poll_fn(|cx| {
            assert!(receiving.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(receiving);
        peer.send(b"after cancellation").await;
        assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Data(18));
        assert_eq!(&buf[..18], b"after cancellation");
    })
    .await
    .expect("cancellation test timed out");
}

#[tokio::test]
async fn cancelling_a_send_at_socket_backpressure_keeps_the_accepted_datagram() {
    timeout(LIMIT, async {
        let (mut client, mut peer) = pair(&Pki::new()).await;
        let (client_result, server_result) =
            tokio::join!(client.complete_handshake(), peer.handshake());
        client_result.unwrap();
        server_result.unwrap();
        client.complete_handshake().await.unwrap();

        let mut sending = Box::pin(client.send(b"accepted before cancellation"));
        std::future::poll_fn(|cx| {
            // Tokio 1.53 UDP polling takes its cooperative budget before
            // touching the socket. Exhaust it in this same task poll to
            // deterministically block the send after application sealing.
            let mut exhausted = false;
            for _ in 0..256 {
                match tokio::task::coop::poll_proceed(cx) {
                    std::task::Poll::Ready(guard) => guard.made_progress(),
                    std::task::Poll::Pending => {
                        exhausted = true;
                        break;
                    }
                }
            }
            assert!(exhausted, "test must run in a budgeted Tokio task");
            assert!(sending.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(sending);

        // An operation with no new application plaintext must first finish
        // sending the ciphertext accepted by the cancelled operation.
        client.complete_handshake().await.unwrap();
        assert_eq!(peer.recv().await, b"accepted before cancellation");
        client.send(b"next datagram").await.unwrap();
        assert_eq!(peer.recv().await, b"next datagram");
    })
    .await
    .expect("send cancellation test timed out");
}

#[tokio::test]
async fn coalesced_records_and_close_keep_all_plaintext_ranges_in_order() {
    timeout(LIMIT, async {
        let (mut client, mut peer) = pair(&Pki::new()).await;
        let (client_result, server_result) =
            tokio::join!(client.complete_handshake(), peer.handshake());
        client_result.unwrap();
        server_result.unwrap();
        peer.conn.set_mtu(16_384).unwrap();
        let data = vec![91; 8_192];
        let mut out = Vec::new();
        peer.conn.send(b"", &mut out).unwrap();
        peer.conn.send(&data, &mut out).unwrap();
        peer.conn.send(b"last", &mut out).unwrap();
        peer.conn.send_close_notify();
        // Append control records to the same UDP payload, in particular
        // close_notify after all application records.
        while peer
            .conn
            .write_datagram(&mut out, peer.start.elapsed())
            .unwrap()
        {}
        assert!(out.len() > 8_192);
        assert_eq!(peer.socket.send(&out).await.unwrap(), out.len());

        assert_eq!(client.recv(&mut []).await.unwrap(), Recv::Data(0));
        assert_eq!(
            client.recv(&mut [0; 8]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let mut buf = vec![0; data.len()];
        assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Data(data.len()));
        assert_eq!(buf, data);
        assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Data(4));
        assert_eq!(&buf[..4], b"last");
        assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Closed);
    })
    .await
    .expect("coalesced record test timed out");
}

#[tokio::test]
async fn construction_rejects_an_unconnected_socket() {
    let pki = Pki::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(UdpClient::new(Arc::new(pki.client_config(&TLS13)), localhost(), socket).is_err());
}

#[tokio::test]
async fn closing_an_incomplete_handshake_terminates_later_operations() {
    let pki = Pki::new();
    let (socket, _silent_peer) = sockets().await;
    let mut client =
        UdpClient::new(Arc::new(pki.client_config(&TLS13)), localhost(), socket).unwrap();
    assert_eq!(client.timeout(), None);
    timeout(LIMIT, async {
        client.close().await.unwrap();
        let error = client.complete_handshake().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        let error = client.recv(&mut [0; 8]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    })
    .await
    .expect("local close must stop an incomplete handshake");
}

#[tokio::test]
async fn authentication_failure_stays_a_protocol_error() {
    timeout(LIMIT, async {
        let pki = Pki::new();
        let stranger = Pki::new();
        let (client_socket, server_socket) = sockets().await;
        let mut client = UdpClient::new(
            Arc::new(stranger.client_config(&TLS13)),
            localhost(),
            client_socket,
        )
        .unwrap();
        let mut peer = Peer {
            conn: ServerConnection::new_without_cookie_exchange(
                Arc::new(pki.server_config(&TLS13)),
                b"connected loopback test peer",
            )
            .unwrap(),
            socket: server_socket,
            start: Instant::now(),
            received: VecDeque::new(),
        };
        // Sending a fatal alert is best effort if the socket blocks; the
        // client failure must not depend on the peer receiving that alert.
        let client_result = {
            let mut client_handshake = Box::pin(client.complete_handshake());
            let mut server_handshake = Box::pin(peer.handshake());
            tokio::select! {
                result = &mut client_handshake => result,
                result = &mut server_handshake => {
                    assert!(result.is_err());
                    client_handshake.await
                }
            }
        };
        let error = client_result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.get_ref().unwrap().downcast_ref::<Error>().is_some());
        assert_eq!(
            client.complete_handshake().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    })
    .await
    .expect("authentication test timed out");
}

#[tokio::test]
async fn elapsed_timeout_survives_junk_input_and_can_be_resumed() {
    let pki = Pki::new();
    let (socket, peer) = sockets().await;
    // Establish readiness before pausing: an awaited real socket readiness
    // event must not let paused-time auto-advance choose the test's clock.
    socket.writable().await.unwrap();
    peer.writable().await.unwrap();
    tokio::time::pause();
    let mut client =
        UdpClient::new(Arc::new(pki.client_config(&TLS13)), localhost(), socket).unwrap();
    let limit = Duration::from_millis(100);
    client.set_timeout(Some(limit));
    let start = Instant::now();
    let mut handshake = Box::pin(client.complete_handshake());
    // Poll the operation, inject unauthenticated garbage, and advance time
    // explicitly. No wall-clock sleep or scheduler race decides the limit.
    for _ in 0..5 {
        std::future::poll_fn(|cx| {
            assert!(handshake.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        peer.send(&[0; 32]).await.unwrap();
        tokio::time::advance(Duration::from_millis(20)).await;
    }
    assert_eq!(handshake.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(start.elapsed(), limit);
    assert!(client.connection().is_handshaking());
    client.set_timeout(Some(Duration::ZERO));
    assert_eq!(
        client.complete_handshake().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    // The initial flight is retained in core; a fresh operation can resume
    // waiting after the caller extends its deadline.
    client.set_timeout(Some(LIMIT));
    let mut resumed = Box::pin(client.complete_handshake());
    std::future::poll_fn(|cx| {
        assert!(resumed.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(resumed);
    tokio::time::resume();
}

#[tokio::test]
async fn a_lost_clienthello_is_retransmitted_on_tokio_time() {
    timeout(LIMIT, async {
        let (mut client, mut peer) = pair(&Pki::new()).await;
        let mut handshake = Box::pin(client.complete_handshake());
        let mut input = vec![0; 65_535];
        // Deliberately discard the first datagram, rather than relying on
        // packet loss. Core's initial retransmission deadline is one second.
        tokio::select! {
            result = &mut handshake => panic!("unexpected completion: {result:?}"),
            len = peer.socket.recv(&mut input) => { assert!(len.unwrap() > 0); }
        }
        let received = Instant::now();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::resume();
        let (result, server_result) = tokio::join!(&mut handshake, peer.handshake());
        result.unwrap();
        server_result.unwrap();
        assert!(received.elapsed() >= Duration::from_secs(1));
    })
    .await
    .expect("retransmission test timed out");
}
