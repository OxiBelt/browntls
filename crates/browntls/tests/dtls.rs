//! DTLS 1.3 recovery and migration through the facade's re-exports.
#![cfg(all(feature = "dtls", feature = "native"))]
#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls::dtls::{ConnectionIdPolicy, Settings, rrc::Selection};
use browntls::tokio::dtls::{Recv, ServerEvent, UdpClient, UdpServer};
use common::{Pki, localhost};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test]
async fn facade_dtls_recovers_a_lost_hello_and_preserves_the_peer_on_rebind() {
    timeout(Duration::from_secs(15), async {
        let pki = Pki::new();
        let mut config = pki.server_config();
        config.hello_retry_cookies = Some(Arc::new(
            browntls::ticketer::TicketRotator::new(3600, || {
                Ok(Box::new(
                    browntls::crypto::native::ticketer::AeadTicketProducer::new()?,
                ))
            })
            .unwrap(),
        ));
        let settings = Settings::default()
            .with_return_routability_checks(ConnectionIdPolicy::new(8, true).unwrap());
        let listening = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = listening.local_addr().unwrap();
        let mut server = UdpServer::new_with_settings(
            Arc::new(config), listening, settings.clone(),
        ).unwrap();
        server.set_path_selection(Selection::Basic);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(address).await.unwrap();
        let admitted = socket.local_addr().unwrap();
        let mut client = UdpClient::new_with_settings(
            Arc::new(pki.client_config()), localhost(), socket, settings,
        ).unwrap();

        let (handshake, connected) = tokio::join!(client.complete_handshake(), async {
            // Simulate a dropped first ClientHello before the server
            // processes any input. Its only admission comes from retry.
            let mut ignored = [0; 65_535];
            let (len, source) = server.socket().recv_from(&mut ignored).await.unwrap();
            assert!(len > 0);
            assert_eq!(source, admitted);
            assert_eq!(server.handshakes(), 0);
            server.next_event().await.unwrap()
        });
        handshake.unwrap();
        assert!(matches!(connected, ServerEvent::Connected(peer) if peer == admitted));
        assert!(client.connection().return_routability_checks_negotiated());

        let replacement = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        replacement.connect(address).await.unwrap();
        let migrated = replacement.local_addr().unwrap();
        drop(client.replace_socket(replacement).unwrap());
        client.send(b"candidate").await.unwrap();
        let ((), ()) = tokio::join!(async {
            assert!(matches!(server.next_event().await.unwrap(),
                ServerEvent::PeerAddressChanged(peer, path) if peer == admitted && path == migrated
            ));
            assert_eq!(server.peers().collect::<Vec<_>>(), [admitted]);
            server.send_to(b"validated", admitted).await.unwrap();
        }, async {
            let mut data = [0; 32];
            assert_eq!(client.recv(&mut data).await.unwrap(), Recv::Data(9));
            assert_eq!(&data[..9], b"validated");
        });
        client.send(b"after validation").await.unwrap();
        assert!(matches!(server.next_event().await.unwrap(),
            ServerEvent::Received(peer, data) if peer == admitted && data == b"after validation"
        ));
    }).await.unwrap();
}
