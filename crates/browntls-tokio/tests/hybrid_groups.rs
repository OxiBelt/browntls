//! Positive adapter coverage for the three standardized hybrid groups.
#![cfg(any(feature = "native", feature = "rustcrypto"))]
#![deny(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::crypto::CryptoProvider;
use browntls_core::{ClientConfig, NamedGroup, ServerConfig};
use browntls_tokio::{TlsAcceptor, TlsConnector};
use common::{Pki, localhost};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(20);

struct GroupCase {
    name: &'static str,
    provider: CryptoProvider,
    named: NamedGroup,
}

fn cases() -> Vec<GroupCase> {
    let mut cases = Vec::new();
    #[cfg(feature = "native")]
    {
        let groups = [
            (
                "X25519MLKEM768",
                browntls_core::crypto::native::kx_group::X25519MLKEM768,
                NamedGroup::X25519MLKEM768,
            ),
            (
                "SecP256r1MLKEM768",
                browntls_core::crypto::native::kx_group::SECP256R1MLKEM768,
                NamedGroup::secp256r1MLKEM768,
            ),
            (
                "SecP384r1MLKEM1024",
                browntls_core::crypto::native::kx_group::SECP384R1MLKEM1024,
                NamedGroup::secp384r1MLKEM1024,
            ),
        ];
        for (name, group, named) in groups {
            let mut provider = browntls_core::crypto::native::default_provider();
            provider.kx_groups = vec![group];
            cases.push(GroupCase {
                name,
                provider,
                named,
            });
        }
    }
    #[cfg(feature = "rustcrypto")]
    {
        let groups = [
            (
                "X25519MLKEM768",
                browntls_core::crypto::rustcrypto::kx_group::X25519MLKEM768,
                NamedGroup::X25519MLKEM768,
            ),
            (
                "SecP256r1MLKEM768",
                browntls_core::crypto::rustcrypto::kx_group::SECP256R1MLKEM768,
                NamedGroup::secp256r1MLKEM768,
            ),
            (
                "SecP384r1MLKEM1024",
                browntls_core::crypto::rustcrypto::kx_group::SECP384R1MLKEM1024,
                NamedGroup::secp384r1MLKEM1024,
            ),
        ];
        for (name, group, named) in groups {
            let mut provider = browntls_core::crypto::rustcrypto::default_provider();
            provider.kx_groups = vec![group];
            cases.push(GroupCase {
                name,
                provider,
                named,
            });
        }
    }
    cases
}

fn configs(pki: &Pki, case: &GroupCase) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let provider = Arc::new(case.provider.clone());
    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&browntls_core::version::TLS13])
        .unwrap()
        .with_root_certificates(pki.roots())
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&browntls_core::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.server_chain.clone(), pki.server_key())
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

macro_rules! assert_group {
    ($connection:expr, $expected:expr, $context:expr) => {
        assert_eq!(
            $connection.negotiated_key_exchange_group().unwrap().name(),
            $expected,
            "{}",
            $context
        )
    };
}

async fn exchange_streams(
    client: &mut (impl AsyncRead + AsyncWrite + Unpin),
    server: &mut (impl AsyncRead + AsyncWrite + Unpin),
) {
    timeout(LIMIT, async {
        client.write_all(b"request").await.unwrap();
        client.flush().await.unwrap();
        let mut request = [0; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        server.write_all(b"reply").await.unwrap();
        server.flush().await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn direct_and_lazy_buffered_and_unbuffered_streams_negotiate_each_hybrid_group() {
    use browntls_core::server::{Acceptor, UnbufferedAcceptor};
    use browntls_tokio::unbuffered;

    for case in cases() {
        let pki = Pki::new();

        let (client_io, server_io) = duplex(128 * 1024);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                TlsConnector::from(configs(&pki, &case).0).connect(localhost(), client_io),
                TlsAcceptor::from(configs(&pki, &case).1).accept(server_io),
            )
        })
        .await
        .unwrap();
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_group!(
            client.get_ref().1,
            case.named,
            format!("{} buffered direct client", case.name)
        );
        assert_group!(
            server.get_ref().1,
            case.named,
            format!("{} buffered direct server", case.name)
        );
        exchange_streams(&mut client, &mut server).await;

        let (client_io, server_io) = duplex(128 * 1024);
        let lazy_server = async {
            let start =
                browntls_tokio::LazyConfigAcceptor::new(Acceptor::default(), server_io).await?;
            start.into_stream(configs(&pki, &case).1).await
        };
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                TlsConnector::from(configs(&pki, &case).0).connect(localhost(), client_io),
                lazy_server,
            )
        })
        .await
        .unwrap();
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_group!(
            client.get_ref().1,
            case.named,
            format!("{} buffered lazy client", case.name)
        );
        assert_group!(
            server.get_ref().1,
            case.named,
            format!("{} buffered lazy server", case.name)
        );
        exchange_streams(&mut client, &mut server).await;

        let (client_io, server_io) = duplex(128 * 1024);
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                unbuffered::TlsConnector::from(configs(&pki, &case).0)
                    .connect(localhost(), client_io),
                unbuffered::TlsAcceptor::from(configs(&pki, &case).1).accept(server_io),
            )
        })
        .await
        .unwrap();
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_group!(
            client.get_ref().1,
            case.named,
            format!("{} unbuffered direct client", case.name)
        );
        assert_group!(
            server.get_ref().1,
            case.named,
            format!("{} unbuffered direct server", case.name)
        );
        exchange_streams(&mut client, &mut server).await;

        let (client_io, server_io) = duplex(128 * 1024);
        let lazy_server = async {
            let start =
                unbuffered::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), server_io).await?;
            start.into_stream(configs(&pki, &case).1).await
        };
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                unbuffered::TlsConnector::from(configs(&pki, &case).0)
                    .connect(localhost(), client_io),
                lazy_server,
            )
        })
        .await
        .unwrap();
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_group!(
            client.get_ref().1,
            case.named,
            format!("{} unbuffered lazy client", case.name)
        );
        assert_group!(
            server.get_ref().1,
            case.named,
            format!("{} unbuffered lazy server", case.name)
        );
        exchange_streams(&mut client, &mut server).await;
    }
}

#[cfg(feature = "dtls")]
#[tokio::test]
async fn dtls_event_and_session_adapters_negotiate_each_hybrid_group() {
    use browntls_core::pki_types::ServerName;
    use browntls_tokio::dtls::{
        Recv, ServerEvent, SessionLimits, UdpClient, UdpListener, UdpServer,
    };
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    for case in cases() {
        let pki = Pki::new();
        let (client_config, mut server_config) = configs(&pki, &case);
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
        let config = Arc::get_mut(&mut server_config).unwrap();
        config.hello_retry_cookies = Some(cookies);
        config.send_tls13_tickets = 0;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = socket.local_addr().unwrap();
        let mut server = UdpServer::new(server_config.clone(), socket).unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_socket.connect(address).await.unwrap();
        let mut client = UdpClient::new(
            client_config.clone(),
            ServerName::try_from("localhost").unwrap(),
            client_socket,
        )
        .unwrap();
        let (result, event) = timeout(LIMIT, async {
            tokio::join!(client.complete_handshake(), server.next_event())
        })
        .await
        .unwrap();
        result.unwrap();
        let ServerEvent::Connected(peer) = event.unwrap() else {
            panic!("expected connected DTLS peer")
        };
        assert_group!(
            client.connection(),
            case.named,
            format!("{} DTLS event client", case.name)
        );
        assert_group!(
            server.connection(peer).unwrap(),
            case.named,
            format!("{} DTLS event server", case.name)
        );
        timeout(LIMIT, async {
            client.send(b"request").await.unwrap();
            let ServerEvent::Received(sender, data) = server.next_event().await.unwrap() else {
                panic!("expected application data");
            };
            assert_eq!(sender, peer);
            assert_eq!(data, b"request");
            server.send_to(b"reply", peer).await.unwrap();
            let mut reply = [0; 5];
            assert_eq!(client.recv(&mut reply).await.unwrap(), Recv::Data(5));
            assert_eq!(&reply, b"reply");
        })
        .await
        .unwrap();

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (mut listener, driver) =
            UdpListener::new(server_config, socket, SessionLimits::default()).unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_socket.connect(address).await.unwrap();
        let mut client = UdpClient::new(
            client_config,
            ServerName::try_from("localhost").unwrap(),
            client_socket,
        )
        .unwrap();
        let expected = case.named;
        let name = case.name;
        let application = async move {
            let (handshake, accepted) =
                tokio::join!(client.complete_handshake(), listener.accept());
            handshake.unwrap();
            let mut session = accepted.unwrap();
            drop(listener);
            assert_group!(
                client.connection(),
                expected,
                format!("{} DTLS session client", name)
            );
            client.send(b"request").await.unwrap();
            assert_eq!(
                session.recv().await.unwrap().as_deref(),
                Some(&b"request"[..])
            );
            session.send(b"hybrid DTLS").await.unwrap();
            let mut buf = [0; 32];
            assert_eq!(client.recv(&mut buf).await.unwrap(), Recv::Data(11));
            assert_eq!(&buf[..11], b"hybrid DTLS");
        };
        let (driver_result, ()) = timeout(LIMIT, async { tokio::join!(driver.run(), application) })
            .await
            .unwrap();
        driver_result.unwrap();
    }
}
