// Shared scoped IPv6 cookie identity cases for both crypto providers.

fn scoped_ipv6_peer(scope_id: u32) -> [u8; 23] {
    let mut peer = [0; 23];
    peer[0] = 6;
    peer[1..17].copy_from_slice(&"fe80::1234".parse::<std::net::Ipv6Addr>().unwrap().octets());
    peer[17..21].copy_from_slice(&scope_id.to_be_bytes());
    peer[21..23].copy_from_slice(&4433u16.to_be_bytes());
    peer
}

#[test]
fn stateless_cookie_binds_scoped_ipv6_peer_identity() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = Arc::new(client_config(&chain));
    let server_config = Arc::new(dtls_server_config(&chain));
    let acceptor = dtls::Acceptor::new(server_config).unwrap();
    let now = Duration::from_secs(5);
    let mut client = dtls::ClientConnection::new(client_config, server_name()).unwrap();

    let mut first = client_datagrams(&mut client, now).remove(0);
    let scope_two = scoped_ipv6_peer(2);
    let scope_three = scoped_ipv6_peer(3);
    let mut retry = Vec::new();
    assert!(matches!(
        acceptor
            .accept(&mut first, &scope_two, &mut retry, now)
            .unwrap(),
        dtls::Accepted::Retry
    ));
    client.read_datagram(&mut retry, now).unwrap();

    let mut second = client_datagrams(&mut client, now).remove(0);
    let mut wrong_scope_output = Vec::new();
    assert!(matches!(
        acceptor
            .accept(
                &mut second.clone(),
                &scope_three,
                &mut wrong_scope_output,
                now
            )
            .unwrap(),
        dtls::Accepted::Ignored
    ));
    assert!(wrong_scope_output.is_empty());

    let dtls::Accepted::Connection(server) = acceptor
        .accept(&mut second, &scope_two, &mut Vec::new(), now)
        .unwrap()
    else {
        panic!("the cookie must admit the original scoped IPv6 peer");
    };
    let mut pair = Pair {
        client,
        server: *server,
    };
    let mut sim = Sim::perfect();
    sim.now = now;
    pair.handshake(&mut sim).unwrap();
    assert_dtls13(&pair);
}
