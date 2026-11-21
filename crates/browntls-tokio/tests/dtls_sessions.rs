//! Real loopback coverage of the caller-driven DTLS session layer.
#![cfg(all(feature = "dtls", any(feature = "native", feature = "rustcrypto")))]
#![deny(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::ServerConfig;
use browntls_core::pki_types::ServerName;
use browntls_tokio::dtls::{
    Recv, SessionDriver, SessionLimits, UdpClient, UdpListener, UdpSession,
};
use common::Pki;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);

fn config(
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
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

async fn listener(pki: &Pki) -> (SocketAddr, UdpListener, SessionDriver) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (listener, driver) = UdpListener::new(
        config(pki, &browntls_core::version::TLS13),
        socket,
        SessionLimits::default(),
    )
    .unwrap();
    (address, listener, driver)
}

async fn client(pki: &Pki, server: SocketAddr, local: SocketAddr) -> UdpClient {
    let socket = UdpSocket::bind(local).await.unwrap();
    socket.connect(server).await.unwrap();
    UdpClient::new(
        Arc::new(pki.client_config_with_cert(&browntls_core::version::TLS13)),
        ServerName::try_from("localhost").unwrap(),
        socket,
    )
    .unwrap()
}

async fn accept(listener: &mut UdpListener, client: &mut UdpClient) -> UdpSession {
    let (handshake, accepted) = tokio::join!(client.complete_handshake(), listener.accept());
    handshake.unwrap();
    let session = accepted.unwrap();
    assert_eq!(session.peer_addr(), client.socket().local_addr().unwrap());
    session
}

async fn drive(driver: SessionDriver, application: impl Future<Output = ()>) {
    let (result, ()) = timeout(DEADLINE, async { tokio::join!(driver.run(), application) })
        .await
        .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn whole_datagrams_empty_records_and_local_close_without_background_tasks() {
    let pki = Pki::new();
    let (address, mut listener, driver) = listener(&pki).await;
    let mut client = client(&pki, address, "127.0.0.1:0".parse().unwrap()).await;
    drive(driver, async move {
        let mut session = accept(&mut listener, &mut client).await;
        // Existing sessions keep working after admissions stop.
        drop(listener);
        client.send(b"").await.unwrap();
        client.send(b"one whole datagram").await.unwrap();
        assert_eq!(session.recv().await.unwrap(), Some(vec![]));
        assert_eq!(
            session.recv().await.unwrap(),
            Some(b"one whole datagram".to_vec())
        );

        session.send(b"").await.unwrap();
        session.send(b"reply").await.unwrap();
        let mut buf = [0; 64];
        assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Data(0));
        assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Data(5));
        assert_eq!(&buf[..5], b"reply");

        session.close().await.unwrap();
        assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Closed);
        assert_eq!(session.recv().await.unwrap(), None);
        session.close().await.unwrap();
        assert_eq!(
            session.send(b"late").await.unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        drop(session);
    })
    .await;
}

#[tokio::test]
async fn remote_close_drains_queued_data_and_preserves_unrelated_sessions() {
    let pki = Pki::new();
    let (address, mut listener, driver) = listener(&pki).await;
    let mut first = client(&pki, address, "127.0.0.1:0".parse().unwrap()).await;
    let mut second = client(&pki, address, "127.0.0.1:0".parse().unwrap()).await;
    drive(driver, async move {
        let mut first_session = accept(&mut listener, &mut first).await;
        let mut second_session = accept(&mut listener, &mut second).await;
        first.send(b"last datagram").await.unwrap();
        first.close().await.unwrap();
        assert_eq!(
            first_session.recv().await.unwrap(),
            Some(b"last datagram".to_vec())
        );
        assert_eq!(first_session.recv().await.unwrap(), None);

        second.send(b"still connected").await.unwrap();
        assert_eq!(
            second_session.recv().await.unwrap(),
            Some(b"still connected".to_vec())
        );
        second_session.send(b"ack").await.unwrap();
        let mut buf = [0; 16];
        assert_eq!(second.recv(&mut buf).await.unwrap(), Recv::Data(3));
        assert_eq!(&buf[..3], b"ack");
        drop(first_session);
        drop(second_session);
        drop(listener);
    })
    .await;
}

#[tokio::test]
async fn retained_stale_handle_cannot_send_to_or_close_a_reconnected_peer() {
    let pki = Pki::new();
    let (address, mut listener, driver) = listener(&pki).await;
    let mut first = client(&pki, address, "127.0.0.1:0".parse().unwrap()).await;
    drive(driver, async {
        let mut old = accept(&mut listener, &mut first).await;
        let reused = old.peer_addr();
        first.close().await.unwrap();
        assert_eq!(old.recv().await.unwrap(), None);
        drop(first);
        // UDP has no TIME_WAIT: reuse the exact local address, with a new
        // authenticated association while the old handle is retained.
        let mut replacement = client(&pki, address, reused).await;
        let mut current = accept(&mut listener, &mut replacement).await;
        assert_eq!(
            old.send(b"stale").await.unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        old.close().await.unwrap();
        replacement.send(b"new association").await.unwrap();
        assert_eq!(
            current.recv().await.unwrap(),
            Some(b"new association".to_vec())
        );
        current.send(b"new reply").await.unwrap();
        let mut buf = [0; 32];
        assert_eq!(replacement.recv(&mut buf).await.unwrap(), Recv::Data(9));
        assert_eq!(&buf[..9], b"new reply");
        drop(old);
        drop(current);
        drop(listener);
    })
    .await;
}

#[cfg(feature = "tls12")]
#[tokio::test]
async fn session_listener_accepts_opt_in_dtls12() {
    use browntls_core::{dtls::Versions, version::TLS12};

    let pki = Pki::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (mut listener, driver) = UdpListener::new_with_versions(
        config(&pki, &TLS12),
        socket,
        Versions::V1_2,
        SessionLimits::default(),
    )
    .unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(address).await.unwrap();
    let mut client = UdpClient::new_with_versions(
        Arc::new(pki.client_config_with_cert(&TLS12)),
        ServerName::try_from("localhost").unwrap(),
        client_socket,
        Versions::V1_2,
    )
    .unwrap();
    drive(driver, async move {
        let mut session = accept(&mut listener, &mut client).await;
        client.send(b"legacy datagram").await.unwrap();
        assert_eq!(
            session.recv().await.unwrap(),
            Some(b"legacy datagram".to_vec())
        );
        session.close().await.unwrap();
        let mut out = [0; 32];
        assert_eq!(client.recv(&mut out).await.unwrap(), Recv::Closed);
        drop(listener);
    })
    .await;
}
