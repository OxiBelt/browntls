//! RFC 8773 certificate authentication with an external PSK through the
//! buffered, unbuffered, and lazy Tokio stream adapters.

#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![deny(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::psk::ExternalPsk;
use browntls_core::server::{Acceptor, UnbufferedAcceptor};
use browntls_core::{ClientConfig, ServerConfig};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::{Pki, localhost};
use tokio::io::duplex;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(20);

fn psk() -> Arc<ExternalPsk> {
    Arc::new(
        ExternalPsk::new(
            b"tokio-certificate-psk".to_vec(),
            vec![0x5a; 32],
            HashAlgorithm::SHA256,
        )
        .unwrap(),
    )
}

fn client_config(pki: &Pki) -> Arc<ClientConfig> {
    let mut config = pki.client_config(&browntls_core::version::TLS13);
    config.external_psks = vec![psk()];
    config.cert_with_extern_psk = true;
    config.require_cert_with_extern_psk = true;
    config.require_external_psk = true;
    Arc::new(config)
}

fn server_config(pki: &Pki) -> Arc<ServerConfig> {
    let mut config = pki.server_config(&browntls_core::version::TLS13);
    config.external_psks = Some(Arc::new(vec![psk()]));
    // Requiring the RFC 8773 negotiation also opts the server in.
    config.require_cert_with_extern_psk = true;
    Arc::new(config)
}

fn assert_negotiated(
    client: &browntls_tokio::client::TlsStream<tokio::io::DuplexStream>,
    server: &browntls_tokio::server::TlsStream<tokio::io::DuplexStream>,
) {
    assert!(client.get_ref().1.negotiated_cert_with_extern_psk());
    assert!(server.get_ref().1.negotiated_cert_with_extern_psk());
    assert_eq!(
        client.get_ref().1.external_psk_identity(),
        Some(&b"tokio-certificate-psk"[..])
    );
    assert_eq!(
        server.get_ref().1.external_psk_identity(),
        Some(&b"tokio-certificate-psk"[..])
    );
}

#[tokio::test]
async fn buffered_direct_streams_negotiate_certificate_and_external_psk() {
    let pki = Pki::new();
    let (client_io, server_io) = duplex(64 * 1024);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            TlsConnector::from(client_config(&pki)).connect(localhost(), client_io),
            TlsAcceptor::from(server_config(&pki)).accept(server_io),
        )
    })
    .await
    .unwrap();
    let (client, server) = (client.unwrap(), server.unwrap());
    assert_negotiated(&client, &server);
}

#[tokio::test]
async fn unbuffered_direct_streams_negotiate_certificate_and_external_psk() {
    use browntls_tokio::unbuffered;

    let pki = Pki::new();
    let (client_io, server_io) = duplex(64 * 1024);
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            unbuffered::TlsConnector::from(client_config(&pki)).connect(localhost(), client_io),
            unbuffered::TlsAcceptor::from(server_config(&pki)).accept(server_io),
        )
    })
    .await
    .unwrap();
    let (client, server) = (client.unwrap(), server.unwrap());
    assert!(client.get_ref().1.negotiated_cert_with_extern_psk());
    assert!(server.get_ref().1.negotiated_cert_with_extern_psk());
    assert_eq!(
        client.get_ref().1.external_psk_identity(),
        Some(&b"tokio-certificate-psk"[..])
    );
    assert_eq!(
        server.get_ref().1.external_psk_identity(),
        Some(&b"tokio-certificate-psk"[..])
    );
}

#[tokio::test]
async fn buffered_lazy_acceptor_observes_offer_and_negotiates_it() {
    let pki = Pki::new();
    let (client_io, server_io) = duplex(64 * 1024);
    let server = async {
        let start = browntls_tokio::LazyConfigAcceptor::new(Acceptor::default(), server_io).await?;
        assert!(start.client_hello().offers_cert_with_extern_psk());
        start.into_stream(server_config(&pki)).await
    };
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            TlsConnector::from(client_config(&pki)).connect(localhost(), client_io),
            server,
        )
    })
    .await
    .unwrap();
    let (client, server) = (client.unwrap(), server.unwrap());
    assert_negotiated(&client, &server);
}

#[tokio::test]
async fn unbuffered_lazy_acceptor_observes_offer_and_negotiates_it() {
    use browntls_tokio::unbuffered;

    let pki = Pki::new();
    let (client_io, server_io) = duplex(64 * 1024);
    let server = async {
        let start =
            unbuffered::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), server_io).await?;
        assert!(start.client_hello().offers_cert_with_extern_psk());
        start.into_stream(server_config(&pki)).await
    };
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            unbuffered::TlsConnector::from(client_config(&pki)).connect(localhost(), client_io),
            server,
        )
    })
    .await
    .unwrap();
    let (client, server) = (client.unwrap(), server.unwrap());
    assert!(client.get_ref().1.negotiated_cert_with_extern_psk());
    assert!(server.get_ref().1.negotiated_cert_with_extern_psk());
    assert_eq!(
        client.get_ref().1.external_psk_identity(),
        Some(&b"tokio-certificate-psk"[..])
    );
    assert_eq!(
        server.get_ref().1.external_psk_identity(),
        Some(&b"tokio-certificate-psk"[..])
    );
}

#[tokio::test]
async fn required_client_negotiation_fails_when_server_does_not_opt_in() {
    let pki = Pki::new();
    let (client_io, server_io) = duplex(64 * 1024);
    let mut config = pki.server_config(&browntls_core::version::TLS13);
    assert!(!config.require_cert_with_extern_psk);
    config.external_psks = Some(Arc::new(vec![psk()]));
    let (client, server) = timeout(LIMIT, async {
        tokio::join!(
            TlsConnector::from(client_config(&pki)).connect(localhost(), client_io),
            TlsAcceptor::from(Arc::new(config)).accept(server_io),
        )
    })
    .await
    .unwrap();
    assert!(client.is_err());
    assert!(server.is_err());
}

#[cfg(feature = "dtls")]
mod dtls {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use super::common::Pki;
    use browntls_core::pki_types::ServerName;
    use browntls_core::{ClientConfig, ServerConfig};
    use browntls_tokio::dtls::{
        Recv, ServerEvent, SessionLimits, UdpClient, UdpListener, UdpServer,
    };
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    const LIMIT: Duration = Duration::from_secs(20);

    fn client_config(pki: &Pki) -> Arc<ClientConfig> {
        super::client_config(pki)
    }

    fn server_config(pki: &Pki) -> Arc<ServerConfig> {
        let mut config = pki.server_config(&browntls_core::version::TLS13);
        config.external_psks = Some(Arc::new(vec![super::psk()]));
        config.require_cert_with_extern_psk = true;
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
        Arc::new(config)
    }

    fn client(pki: &Pki, server: SocketAddr) -> UdpClient {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(server).unwrap();
        socket.set_nonblocking(true).unwrap();
        UdpClient::new(
            client_config(pki),
            ServerName::try_from("localhost").unwrap(),
            UdpSocket::from_std(socket).unwrap(),
        )
        .unwrap()
    }

    fn assert_client_negotiated(client: &UdpClient) {
        assert!(client.connection().negotiated_cert_with_extern_psk());
        assert_eq!(
            client.connection().external_psk_identity(),
            Some(&b"tokio-certificate-psk"[..])
        );
    }

    #[tokio::test]
    async fn event_server_negotiates_certificate_and_external_psk() {
        let pki = Pki::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let mut server = UdpServer::new(server_config(&pki), socket).unwrap();
        let mut client = client(&pki, address);
        let (handshake, event) = timeout(LIMIT, async {
            tokio::join!(client.complete_handshake(), server.next_event())
        })
        .await
        .unwrap();
        handshake.unwrap();
        let ServerEvent::Connected(peer) = event.unwrap() else {
            panic!("expected a completed DTLS association");
        };
        assert_client_negotiated(&client);
        let conn = server.connection(peer).expect("connected peer");
        assert!(conn.negotiated_cert_with_extern_psk());
        assert_eq!(
            conn.external_psk_identity(),
            Some(&b"tokio-certificate-psk"[..])
        );
    }

    #[tokio::test]
    async fn session_driver_negotiates_and_carries_application_data() {
        let pki = Pki::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (mut listener, driver) =
            UdpListener::new(server_config(&pki), socket, SessionLimits::default()).unwrap();
        let mut client = client(&pki, address);
        let application = async {
            let (handshake, accepted) =
                tokio::join!(client.complete_handshake(), listener.accept());
            handshake.unwrap();
            let session = accepted.unwrap();
            assert_client_negotiated(&client);
            session.send(b"external PSK session").await.unwrap();
            let mut received = [0; 32];
            assert_eq!(
                client.recv(&mut received).await.unwrap(),
                Recv::Data(b"external PSK session".len())
            );
            assert_eq!(
                &received[..b"external PSK session".len()],
                b"external PSK session"
            );
            drop(session);
            drop(listener);
        };
        let (driver_result, ()) = timeout(LIMIT, async { tokio::join!(driver.run(), application) })
            .await
            .unwrap();
        driver_result.unwrap();
    }
}
