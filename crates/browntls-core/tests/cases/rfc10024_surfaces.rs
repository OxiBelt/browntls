use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use browntls_core::dtls::{self, ServerEvent, UdpClient, UdpServer};
use browntls_core::server::Acceptor;
use browntls_core::{ClientConnection, CommonState, ServerConnection, version};
use common::*;

fn rfc10024_groups() -> [&'static dyn browntls_core::crypto::SupportedKxGroup; 3] {
    [
        prov::kx_group::SECP256R1MLKEM768,
        prov::kx_group::SECP384R1MLKEM1024,
        prov::kx_group::X25519MLKEM768,
    ]
}

fn assert_group(
    client: &CommonState,
    server: &CommonState,
    group: &'static dyn browntls_core::crypto::SupportedKxGroup,
) {
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        group.name()
    );
    assert_eq!(
        server.negotiated_key_exchange_group().unwrap().name(),
        group.name()
    );
}

fn configs(
    chain: &Chain,
    group: &'static dyn browntls_core::crypto::SupportedKxGroup,
) -> (browntls_core::ClientConfig, browntls_core::ServerConfig) {
    let mut client_provider = prov::default_provider();
    client_provider.kx_groups = vec![group];
    let client_config =
        browntls_core::ClientConfig::builder_with_provider(Arc::new(client_provider))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
            .with_no_client_auth();

    let mut server_provider = prov::default_provider();
    server_provider.kx_groups = vec![group];
    let server_config =
        browntls_core::ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.cert_chain(), chain.private_key())
            .unwrap();
    (client_config, server_config)
}

#[test]
fn buffered_tls_direct_and_acceptor_negotiate_each_hybrid_group() {
    let chain = server_chain(KeyType::EcdsaP256);
    for group in rfc10024_groups() {
        let (client_config, server_config) = configs(&chain, group);
        let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config.clone())).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_group(&client, &server, group);
        exchange_tls(&mut client, &mut server);

        let (client_config, server_config) = configs(&chain, group);
        let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let mut acceptor = Acceptor::default();
        acceptor.read_tls(&mut &hello[..]).unwrap();
        let accepted = acceptor.accept().unwrap().unwrap();
        let mut server = accepted
            .into_connection(Arc::new(server_config))
            .map_err(|(error, _alert)| error)
            .unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_group(&client, &server, group);
        exchange_tls(&mut client, &mut server);
    }
}

fn exchange_tls(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(send_and_receive(client, server, b"request"), b"request");
    assert_eq!(send_and_receive(server, client, b"reply"), b"reply");
}

#[test]
fn tls13_psk_dhe_resumption_keeps_each_hybrid_group() {
    let chain = server_chain(KeyType::EcdsaP256);
    for group in rfc10024_groups() {
        let (client_config, mut server_config) = configs(&chain, group);
        server_config.ticketer = prov::Ticketer::new().unwrap();
        server_config.send_tls13_tickets = 1;
        let client_config = Arc::new(client_config);
        let server_config = Arc::new(server_config);

        let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        assert!(client.tls13_tickets_received() > 0);

        let mut client = ClientConnection::new(client_config, server_name()).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.handshake_kind(),
            Some(browntls_core::HandshakeKind::Resumed)
        );
        assert_group(&client, &server, group);
    }
}

#[test]
fn dtls_connection_negotiates_each_hybrid_group() {
    let chain = server_chain(KeyType::EcdsaP256);
    for group in rfc10024_groups() {
        let (client_config, mut server_config) = configs(&chain, group);
        server_config.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
        let mut client =
            dtls::ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
        let mut server =
            dtls::ServerConnection::new(Arc::new(server_config), b"127.0.0.1:4433").unwrap();
        let now = Duration::from_secs(1000);
        for _ in 0..100 {
            let mut progressed = false;
            let mut datagram = Vec::new();
            while client.write_datagram(&mut datagram, now).unwrap() {
                server.read_datagram(&mut datagram, now).unwrap();
                datagram.clear();
                progressed = true;
            }
            while server.write_datagram(&mut datagram, now).unwrap() {
                client.read_datagram(&mut datagram, now).unwrap();
                datagram.clear();
                progressed = true;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
            assert!(progressed, "DTLS handshake stalled for {:?}", group.name());
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert_group(&client, &server, group);
    }
}

fn loopback() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}

fn client_socket(server: SocketAddr) -> UdpSocket {
    let socket = loopback();
    socket.connect(server).unwrap();
    socket
}

#[test]
fn blocking_dtls_udp_adapters_negotiate_each_hybrid_group() {
    let chain = server_chain(KeyType::EcdsaP256);
    for group in rfc10024_groups() {
        let (client_config, mut server_config) = configs(&chain, group);
        server_config.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
        let mut server = UdpServer::new(Arc::new(server_config), loopback()).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(20)));
        let addr = server.socket().local_addr().unwrap();
        let expected = group.name();
        let server_task = thread::spawn(move || {
            let ServerEvent::Connected(peer) = server.next_event().unwrap() else {
                panic!("expected connected peer");
            };
            let connection = server.connection(peer).unwrap();
            assert_eq!(
                connection.negotiated_key_exchange_group().unwrap().name(),
                expected
            );
            let ServerEvent::Received(sender, data) = server.next_event().unwrap() else {
                panic!("expected application data");
            };
            assert_eq!(sender, peer);
            assert_eq!(data, b"request");
            server.send_to(b"reply", peer).unwrap();
        });
        let mut client =
            UdpClient::connect(Arc::new(client_config), server_name(), client_socket(addr))
                .unwrap();
        client.set_read_timeout(Some(Duration::from_secs(20)));
        assert_eq!(
            client
                .connection()
                .negotiated_key_exchange_group()
                .unwrap()
                .name(),
            expected
        );
        client.send(b"request").unwrap();
        let mut reply = [0; 5];
        assert_eq!(client.recv(&mut reply).unwrap(), reply.len());
        assert_eq!(&reply, b"reply");
        server_task.join().unwrap();
    }
}
