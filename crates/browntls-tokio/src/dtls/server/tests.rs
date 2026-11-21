//! Adapter queue failure coverage.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::poll_fn;
use std::sync::Arc;

use browntls_core::server::ResolvesServerCertUsingSni;

use super::*;

#[tokio::test]
async fn a_failed_path_reply_is_reported_to_its_association() {
    #[cfg(feature = "native")]
    let (provider, cookies) = (
        browntls_core::crypto::native::default_provider(),
        Arc::new(
            browntls_core::ticketer::TicketRotator::new(3600, || {
                Ok(Box::new(
                    browntls_core::crypto::native::ticketer::AeadTicketProducer::new()?,
                ))
            })
            .unwrap(),
        ),
    );
    #[cfg(not(feature = "native"))]
    let (provider, cookies) = (
        browntls_core::crypto::rustcrypto::default_provider(),
        browntls_core::crypto::rustcrypto::Ticketer::new().unwrap(),
    );
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new()));
    config.hello_retry_cookies = Some(cookies);
    let config = Arc::new(config);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let owner = SocketAddr::from(([127, 0, 0, 1], 12345));
    let invalid = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut server = UdpServer::new(config.clone(), socket).unwrap();
    server.peers.insert(
        owner,
        Peer {
            conn: ServerConnection::new(config, &address_bytes(owner)).unwrap(),
            started: Duration::ZERO,
            expires: Duration::from_secs(10),
            connected: true,
            retiring: false,
            serviced_timeout: None,
            out: Vec::new(),
            active: owner,
            paths: None,
            probe: None,
        },
    );
    // A socket error on one failed reply discards the rest of that
    // association's batch and is observable to both callers and events.
    server.replies.push_back((owner, invalid, vec![1]));
    server.replies.push_back((owner, invalid, vec![2]));
    let error = poll_fn(|cx| {
        let result = server.poll_output(cx, &mut 4, Some(owner));
        if result.is_ok() && !server.replies.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(result)
        }
    })
    .await;
    assert!(error.is_err());
    assert!(server.replies.is_empty());
    assert!(server.connection(owner).is_none());
    assert!(matches!(
        server.events.pop_front(),
        Some(ServerEvent::Failed(peer, _)) if peer == owner
    ));
}
