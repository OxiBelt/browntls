// Shared cases, included after `cases/dtls.rs` by `tests/dtls.rs`
// (RustCrypto provider) and `tests/dtls_native.rs` (native provider).
//
// Forged unprotected DTLS 1.3 input, which anyone who knows an address can
// send: it must neither make a stateless server keep state, nor stop,
// slow or amplify a handshake.

/// An unprotected DTLSPlaintext record (RFC 9147 §4) of `typ`.
fn plaintext_record(typ: u8, record_seq: u64, body: &[u8]) -> Vec<u8> {
    let mut out = vec![typ, 0xfe, 0xfd, 0, 0];
    out.extend_from_slice(&record_seq.to_be_bytes()[2..]);
    out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// An unprotected handshake record holding one fragment.
fn handshake_fragment(
    record_seq: u64,
    typ: u8,
    message_seq: u16,
    length: u32,
    fragment: &[u8],
) -> Vec<u8> {
    let mut body = vec![typ];
    body.extend_from_slice(&length.to_be_bytes()[1..]);
    body.extend_from_slice(&message_seq.to_be_bytes());
    body.extend_from_slice(&[0, 0, 0]);
    body.extend_from_slice(&u32::try_from(fragment.len()).unwrap().to_be_bytes()[1..]);
    body.extend_from_slice(fragment);
    plaintext_record(22, record_seq, &body)
}

/// Every datagram `from` has to send, delivered to `to`.
fn pump(from: &mut dyn Endpoint, to: &mut dyn Endpoint, now: Duration) {
    let mut out = Vec::new();
    while from.write(&mut out, now) {
        to.read(&mut out, now).unwrap();
        out.clear();
    }
}

/// Every datagram `from` has to send, lost.
fn lose(from: &mut dyn Endpoint, now: Duration) -> usize {
    let mut out = Vec::new();
    let mut bytes = 0;
    while from.write(&mut out, now) {
        bytes += out.len();
        out.clear();
    }
    bytes
}

/// A pair whose server has answered the second ClientHello: its flight
/// is queued, and outstanding once written.
fn pair_after_second_client_hello(now: Duration) -> Pair {
    let (mut pair, ..) = Pair::default_pair();
    pump(&mut *pair.client, &mut *pair.server, now);
    pump(&mut *pair.server, &mut *pair.client, now);
    pump(&mut *pair.client, &mut *pair.server, now);
    pair
}

#[test]
fn a_first_client_hello_relabelled_as_second_keeps_no_state() {
    let chain = server_chain(KeyType::EcdsaP256);
    let acceptor = dtls::Acceptor::new(Arc::new(dtls_server_config(&chain))).unwrap();
    let now = Duration::from_secs(5);
    let mut client =
        dtls::ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut first = client_datagrams(&mut client, now).remove(0);
    // message_seq follows the record header (13 bytes), the type and the
    // length.
    first[17..19].copy_from_slice(&[0, 1]);
    assert!(matches!(
        acceptor
            .accept(&mut first, PEER, &mut Vec::new(), now)
            .unwrap(),
        dtls::Accepted::Ignored
    ));
}

#[test]
fn a_split_second_client_hello_is_kept_once_its_cookie_arrives() {
    let chain = server_chain(KeyType::EcdsaP256);
    let acceptor = dtls::Acceptor::new(Arc::new(dtls_server_config(&chain))).unwrap();
    let now = Duration::from_secs(5);
    let mut client =
        dtls::ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut first = client_datagrams(&mut client, now);
    let mut retry = Vec::new();
    acceptor
        .accept(&mut first[0], PEER, &mut retry, now)
        .unwrap();
    client.read_datagram(&mut retry, now).unwrap();
    client.set_mtu(400).unwrap();
    let mut second = client_datagrams(&mut client, now);
    assert!(second.len() > 1, "the second ClientHello is split");

    // A later fragment alone proves nothing.
    assert!(matches!(
        acceptor
            .accept(&mut second[1].clone(), PEER, &mut Vec::new(), now)
            .unwrap(),
        dtls::Accepted::Ignored
    ));
    // Nor does the first one from another address.
    assert!(matches!(
        acceptor
            .accept(&mut second[0].clone(), b"198.51.100.7:9", &mut Vec::new(), now)
            .unwrap(),
        dtls::Accepted::Ignored
    ));
    let mut server = match acceptor
        .accept(&mut second[0], PEER, &mut Vec::new(), now)
        .unwrap()
    {
        dtls::Accepted::Connection(conn) => *conn,
        other => panic!("{other:?}"),
    };
    for datagram in &mut second[1..] {
        server.read_datagram(datagram, now).unwrap();
    }
    let mut pair = Pair { client, server };
    let mut sim = Sim::perfect();
    sim.now = now;
    pair.handshake(&mut sim).unwrap();
    pair.exchange(&mut sim, "split");
}

#[test]
fn a_forged_client_hello_cannot_use_up_the_servers_record_numbers() {
    let now = Duration::from_secs(1000);
    let mut pair = pair_after_second_client_hello(now);
    let forged = handshake_fragment((1 << 48) - 1, 1, 7, 0, &[]);
    pair.server
        .read_datagram(&mut forged.clone(), now)
        .unwrap();
    // The flight is lost a few times: every retransmission needs fresh
    // record numbers.
    let mut sim = Sim::new(
        Link::perfect(),
        Link::new(|n, _| if n < 6 { Fate::Drop } else { Fate::Deliver }),
    );
    sim.now = now;
    pair.server
        .read_datagram(&mut forged.clone(), now)
        .unwrap();
    pair.handshake(&mut sim).unwrap();
    pair.exchange(&mut sim, "after forgery");
}

#[test]
fn forged_repetitions_do_not_amplify() {
    let now = Duration::from_secs(1000);
    let (mut pair, ..) = Pair::default_pair();
    pump(&mut *pair.client, &mut *pair.server, now);
    pump(&mut *pair.server, &mut *pair.client, now);
    let second = client_datagrams(&mut pair.client, now);
    for datagram in &mut second.clone() {
        pair.server.read_datagram(datagram, now).unwrap();
    }
    let flight = lose(&mut *pair.server, now);
    assert!(flight > 0);

    // A hundred copies of the second ClientHello, which the server has
    // answered, at once.
    let mut sent = 0;
    for _ in 0..100 {
        pair.server
            .read_datagram(&mut second[0].clone(), now)
            .unwrap();
        sent += lose(&mut *pair.server, now);
    }
    assert!(sent <= flight, "{sent} bytes sent for a {flight}-byte flight");

    // A repetition one timeout later is answered.
    let later = now + Duration::from_secs(1);
    pair.server
        .read_datagram(&mut second[0].clone(), later)
        .unwrap();
    assert!(lose(&mut *pair.server, later) > 0);
}

#[test]
fn forged_hello_fragments_cannot_fill_the_reassembly_buffer() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    for (seq, len) in [(14, 0xffff), (15, 0xffff), (1, 0xffff)] {
        let mut forged = handshake_fragment(seq.into(), 2, seq, len, &[0; 1000]);
        pair.client
            .read_datagram(&mut forged, sim.now)
            .unwrap();
    }
    pair.handshake(&mut sim).unwrap();
    assert_dtls13(&pair);
}

#[test]
fn a_received_fatal_alert_stops_retransmissions() {
    let (mut pair, ..) = Pair::default_pair();
    let now = Duration::from_secs(1000);
    assert!(lose(&mut *pair.client, now) > 0);
    assert!(pair.client.next_timeout().is_some());
    // handshake_failure
    let mut alert = plaintext_record(21, 0, &[2, 40]);
    assert!(pair
        .client
        .read_datagram(&mut alert, now)
        .is_err());
    assert_eq!(pair.client.next_timeout(), None);
    assert_eq!(lose(&mut *pair.client, now + Duration::from_secs(5)), 0);
}

#[test]
fn forged_unprotected_acks_are_ignored() {
    let (mut pair, ..) = Pair::default_pair();
    let now = Duration::from_secs(1000);
    assert!(lose(&mut *pair.client, now) > 0);
    // ACK of record {epoch 0, seq 0}: the ClientHello.
    let mut body = 16u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0; 16]);
    let mut ack = plaintext_record(26, 0, &body);
    pair.client.read_datagram(&mut ack, now).unwrap();
    let timeout = pair.client.next_timeout().unwrap();
    pair.client.handle_timeout(timeout).unwrap();
    assert!(lose(&mut *pair.client, timeout) > 0, "ClientHello resent");
}
