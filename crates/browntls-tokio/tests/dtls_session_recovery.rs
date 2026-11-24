//! DTLS 1.3 session admission after recovery of the final client flight.

#![cfg(all(feature = "dtls", any(feature = "native", feature = "rustcrypto")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::dtls::ClientConnection;
use browntls_core::version::TLS13;
use browntls_tokio::dtls::{SessionLimits, UdpListener};
use common::{Pki, localhost};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

#[tokio::test]
async fn lost_client_finished_recovers_one_session() {
    let pki = Pki::new();
    let mut config = pki.server_config(&TLS13);
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
    config.send_tls13_tickets = 0;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server.local_addr().unwrap()).await.unwrap();
    let (mut listener, driver) = UdpListener::new(
        Arc::new(config),
        server,
        SessionLimits {
            max_sessions: 1,
            accept_queue: 1,
            ..SessionLimits::default()
        },
    )
    .unwrap();

    let application = async move {
        let start = Instant::now();
        let mut client =
            ClientConnection::new(Arc::new(pki.client_config(&TLS13)), localhost()).unwrap();
        let mut input = vec![0; 65_535];
        let mut out = Vec::new();
        while client.is_handshaking() {
            while client.write_datagram(&mut out, start.elapsed()).unwrap() {
                socket.send(&out).await.unwrap();
                out.clear();
            }
            let len = socket.recv(&mut input).await.unwrap();
            client
                .read_datagram(&mut input[..len], start.elapsed())
                .unwrap();
        }
        // Discard Finished. The server driver needs its own timer to make
        // progress: this client never calls handle_timeout.
        while client.write_datagram(&mut out, start.elapsed()).unwrap() {}
        assert!(!out.is_empty());
        out.clear();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::resume();
        let mut session = loop {
            tokio::select! {
                session = listener.accept() => break session.unwrap(),
                len = socket.recv(&mut input) => {
                    client.read_datagram(&mut input[..len.unwrap()], start.elapsed()).unwrap();
                    while client.write_datagram(&mut out, start.elapsed()).unwrap() {
                        socket.send(&out).await.unwrap();
                        out.clear();
                    }
                }
            }
        };
        assert_eq!(session.peer_addr(), socket.local_addr().unwrap());
        client.send(b"after recovery", &mut out).unwrap();
        socket.send(&out).await.unwrap();
        assert_eq!(session.recv().await.unwrap().unwrap(), b"after recovery");
    };
    timeout(Duration::from_secs(10), async {
        let (result, ()) = tokio::join!(driver.run(), application);
        result.unwrap();
    })
    .await
    .unwrap();
}
