//! RFC 9147 recovery across independent record, message, and epoch numbers.

use super::*;

fn app_record(client: &mut dtls::ClientConnection, data: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    client.send(data, &mut record).unwrap();
    record
}

fn receive_app(
    server: &mut dtls::ServerConnection,
    mut record: Vec<u8>,
    now: Duration,
    data: &[u8],
) -> (u64, u64) {
    let received = server.read_datagram(&mut record, now).unwrap();
    let [range] = received.app_data() else {
        panic!("expected exactly one application record");
    };
    assert_eq!(&record[range.clone()], data);
    let [metadata] = received.authenticated_records() else {
        panic!("expected one authenticated record");
    };
    (metadata.epoch(), metadata.sequence_number())
}

#[test]
fn lost_key_update_ack_retains_the_old_epoch_across_the_retry_deadline() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    let now = sim.now;
    let delayed = app_record(&mut pair.client, b"before update");
    pair.client.refresh_traffic_keys().unwrap();
    flush_to(&mut pair.client, &mut pair.server, now);
    let due = pair.client.next_timeout().unwrap();

    // Lose the server's entire response, including the ACK of the update.
    let mut lost = Vec::new();
    while pair.server.write_datagram(&mut lost, now).unwrap() {}
    assert!(!lost.is_empty());

    let early = due - Duration::from_nanos(1);
    pair.client.handle_timeout(early).unwrap();
    assert!(client_datagrams(&mut pair.client, early).is_empty());
    assert_eq!(pair.client.next_timeout(), Some(due));
    pair.client.handle_timeout(due).unwrap();
    let retries = client_datagrams(&mut pair.client, due);
    let [mut retry]: [_; 1] = retries.try_into().unwrap();
    let received = pair.server.read_datagram(&mut retry, due).unwrap();
    assert_eq!(received.authenticated_records().len(), 1);
    assert_eq!(received.authenticated_records()[0].epoch(), 3);
    assert!(received.app_data().is_empty());

    let pending = app_record(&mut pair.client, b"awaiting ACK");
    assert_eq!(
        receive_app(&mut pair.server, pending, due, b"awaiting ACK").0,
        3
    );
    assert_eq!(
        receive_app(&mut pair.server, delayed, due, b"before update").0,
        3
    );

    flush_to(&mut pair.server, &mut pair.client, due);
    let fresh = app_record(&mut pair.client, b"after ACK");
    assert_eq!(receive_app(&mut pair.server, fresh, due, b"after ACK").0, 4);
    sim.now = due;
    pair.run(&mut sim, settled).unwrap();
    pair.exchange(&mut sim, "recovered");
}

// At one deadline an event loop can service either the timer or its input
// first. An ACK received before the next write cancels either kind of retry.
#[test]
fn ack_at_deadline_cancels_a_scheduled_retransmission() {
    for timer_first in [false, true] {
        let (mut pair, ..) = Pair::default_pair();
        let mut sim = Sim::perfect();
        pair.handshake(&mut sim).unwrap();
        pair.client.refresh_traffic_keys().unwrap();
        flush_to(&mut pair.client, &mut pair.server, sim.now);
        let due = pair.client.next_timeout().unwrap();
        // Reading the peer's response may also queue an ACK for its
        // reciprocal update. That ACK alone does not start a flight timer.
        if timer_first {
            pair.client.handle_timeout(due).unwrap();
            assert!(pair.client.wants_write(due));
        }
        flush_to(&mut pair.server, &mut pair.client, due);
        pair.client.handle_timeout(due).unwrap();
        flush_to(&mut pair.client, &mut pair.server, due);
        assert_eq!(pair.client.next_timeout(), None);
        assert_eq!(pair.server.next_timeout(), None);
        let record = app_record(&mut pair.client, b"at deadline");
        assert_eq!(
            receive_app(&mut pair.server, record, due, b"at deadline").0,
            4
        );
    }
}

#[test]
fn successive_key_updates_wrap_the_two_wire_epoch_bits() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    for epoch in 3u64..=8 {
        if epoch != 3 {
            pair.client.refresh_traffic_keys().unwrap();
            pair.run(&mut sim, settled).unwrap();
        }
        let payload = epoch.to_be_bytes();
        let record = app_record(&mut pair.client, &payload);
        assert_eq!(u64::from(record[0] & 3), epoch % 4);
        assert_eq!(
            receive_app(&mut pair.server, record, sim.now, &payload).0,
            epoch
        );
    }
}

#[test]
fn reordered_application_records_at_the_receive_window_boundary() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    // This implementation remembers 128 record numbers per receive epoch.
    let outside = app_record(&mut pair.client, &[0]);
    let inside = app_record(&mut pair.client, &[1]);
    for i in 2..128 {
        let _ = app_record(&mut pair.client, &[i]);
    }
    let high = app_record(&mut pair.client, &[128]);
    let (epoch, highest) = receive_app(&mut pair.server, high, sim.now, &[128]);
    assert_eq!(
        receive_app(&mut pair.server, inside.clone(), sim.now, &[1]),
        (epoch, highest - 127)
    );
    for mut old in [outside, inside] {
        let received = pair.server.read_datagram(&mut old, sim.now).unwrap();
        assert!(received.app_data().is_empty());
        assert!(received.authenticated_records().is_empty());
    }
}

#[test]
fn partial_acks_recover_a_missing_handshake_datagram_before_timeout() {
    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    let now = sim.now;
    pair.server.set_mtu(256).unwrap();
    // Complete the cookie exchange and collect the fragmented server flight.
    flush_to(&mut pair.client, &mut pair.server, now);
    flush_to(&mut pair.server, &mut pair.client, now);
    flush_to(&mut pair.client, &mut pair.server, now);
    let mut flight = Vec::new();
    let mut datagram = Vec::new();
    while pair.server.write_datagram(&mut datagram, now).unwrap() {
        assert!(datagram.len() <= 256);
        flight.push(std::mem::take(&mut datagram));
    }
    // ServerHello itself may span several plaintext datagrams depending
    // on the negotiated group. Keep it so the later fragments decrypt.
    let first_protected = flight
        .iter()
        .position(|part| part[0] & 0xe0 == 0x20)
        .unwrap();
    assert!(flight.len() > first_protected + 1);
    let missing = flight.remove(first_protected);
    let mut acks = Vec::new();
    for mut part in flight {
        pair.client.read_datagram(&mut part, now).unwrap();
        acks.extend(client_datagrams(&mut pair.client, now));
    }
    assert!(pair.client.is_handshaking());
    assert!(pair.server.next_timeout().unwrap() > now);
    assert!(acks.len() >= 2, "expected distinct partial ACKs to reorder");
    // Deliver the most complete ACK first, then any older partial ACKs.
    for mut ack in acks.into_iter().rev() {
        pair.server.read_datagram(&mut ack, now).unwrap();
    }
    let mut repaired_bytes = 0;
    while pair.server.write_datagram(&mut datagram, now).unwrap() {
        repaired_bytes += datagram.len();
        pair.client.read_datagram(&mut datagram, now).unwrap();
        datagram.clear();
    }
    assert!(repaired_bytes > 0);
    assert!(
        repaired_bytes <= missing.len(),
        "only the omitted fragments need retransmission"
    );
    pair.handshake(&mut sim).unwrap();
    assert_eq!(sim.now, now, "recovery did not require a timer");
    assert_dtls13(&pair);
}

#[cfg(feature = "std")]
#[test]
fn blocking_receive_services_an_overdue_update_before_reading_queued_data() {
    use std::net::UdpSocket;
    use std::time::Instant;

    let (mut pair, ..) = Pair::default_pair();
    let mut sim = Sim::perfect();
    sim.now = Duration::ZERO;
    pair.handshake(&mut sim).unwrap();
    pair.client.refresh_traffic_keys().unwrap();
    flush_to(&mut pair.client, &mut pair.server, sim.now);
    let mut out = Vec::new();
    while pair.server.write_datagram(&mut out, sim.now).unwrap() {}
    assert!(!out.is_empty());
    out.clear();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(peer.local_addr().unwrap()).unwrap();
    peer.connect(socket.local_addr().unwrap()).unwrap();
    let limit = Duration::from_secs(3);
    peer.set_read_timeout(Some(limit)).unwrap();
    // Transfer the simulated connection just as its lost ACK causes the
    // first deadline to fall due. The adapter now owns that same timeline.
    let due = pair.client.next_timeout().unwrap();
    let origin = Instant::now() - due;
    let mut client = dtls::UdpClient::from_connection_with_clock(pair.client, socket, origin);
    client.set_read_timeout(Some(limit));

    pair.server.send(b"ready", &mut out).unwrap();
    peer.send(&out).unwrap();
    out.clear();
    let mut data = [0; 16];
    assert_eq!(client.recv(&mut data).unwrap(), 5);
    assert_eq!(&data[..5], b"ready");

    let mut retry = [0; 1200];
    let len = peer.recv(&mut retry).unwrap();
    let received = pair
        .server
        .read_datagram(&mut retry[..len], origin.elapsed())
        .unwrap();
    assert!(received.app_data().is_empty());
    assert_eq!(received.authenticated_records().len(), 1);
    assert_eq!(received.authenticated_records()[0].epoch(), 3);
    while pair
        .server
        .write_datagram(&mut out, origin.elapsed())
        .unwrap()
    {
        peer.send(&out).unwrap();
        out.clear();
    }
    pair.server.send(b"ACK sent", &mut out).unwrap();
    peer.send(&out).unwrap();
    assert_eq!(client.recv(&mut data).unwrap(), 8);
    assert_eq!(&data[..8], b"ACK sent");
    assert_eq!(client.connection().next_timeout(), None);
    client.send(b"updated").unwrap();
    loop {
        let len = peer.recv(&mut retry).unwrap();
        let received = pair
            .server
            .read_datagram(&mut retry[..len], origin.elapsed())
            .unwrap();
        if let [range] = received.app_data() {
            assert_eq!(&retry[range.clone()], b"updated");
            assert_eq!(received.authenticated_records()[0].epoch(), 4);
            break;
        }
        assert!(received.app_data().is_empty());
    }
}

#[test]
fn ack_of_a_delayed_original_fragment_settles_the_flight() {
    for retry_in_flight in [false, true] {
        delayed_original_fragment(retry_in_flight);
    }
}

fn delayed_original_fragment(retry_in_flight: bool) {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut config = dtls_server_config(&chain);
    config.send_tls13_tickets = 4;
    let mut pair = Pair::new(&Arc::new(client_config(&chain)), &Arc::new(config));
    let now = Duration::from_secs(10);
    for _ in 0..2 {
        flush_to(&mut pair.client, &mut pair.server, now);
        flush_to(&mut pair.server, &mut pair.client, now);
    }
    pair.server.set_mtu(256).unwrap();
    flush_to(&mut pair.client, &mut pair.server, now);
    assert_dtls13(&pair);
    let mut tickets = Vec::new();
    let mut out = Vec::new();
    while pair.server.write_datagram(&mut out, now).unwrap() {
        tickets.push(std::mem::take(&mut out));
    }
    assert!(tickets.len() > 1);

    // Deliver the last record and its ACK first. The earlier fragments
    // appear lost but are still in transit.
    pair.client
        .read_datagram(&mut tickets.pop().unwrap(), now)
        .unwrap();
    flush_to(&mut pair.client, &mut pair.server, now);
    assert!(pair.server.wants_write(now));
    if retry_in_flight {
        while pair.server.write_datagram(&mut out, now).unwrap() {}
        assert!(!out.is_empty());
        out.clear();
    }
    for mut original in tickets {
        pair.client.read_datagram(&mut original, now).unwrap();
    }
    flush_to(&mut pair.client, &mut pair.server, now);
    assert_eq!(pair.client.tls13_tickets_received(), 4);
    // All the original records have now been received and acknowledged.
    assert!(!pair.server.write_datagram(&mut out, now).unwrap());
    assert_eq!(pair.server.next_timeout(), None);
}
