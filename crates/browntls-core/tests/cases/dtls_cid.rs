// Shared DTLS-only CID cases. The simulator supplies a deterministic clock
// and delivery schedule; assertions use the actual random IDs, not guesses.

fn cid_settings(len: u8, sending: bool) -> dtls::Settings {
    dtls::Settings::default()
        .with_connection_ids(dtls::ConnectionIdPolicy::new(len, sending).unwrap())
}

fn cid_pair(client_settings: dtls::Settings, server_settings: dtls::Settings) -> Pair {
    let chain = server_chain(KeyType::EcdsaP256);
    Pair {
        client: dtls::ClientConnection::new_with_settings(
            Arc::new(client_config(&chain)),
            server_name(),
            client_settings,
        )
        .unwrap(),
        server: dtls::ServerConnection::new_with_settings(
            Arc::new(dtls_server_config(&chain)),
            PEER,
            server_settings,
        )
        .unwrap(),
    }
}

#[test]
fn cid_handshakes_directions_empty_ids_and_default_decline() {
    for (client, server, client_ids, server_ids) in [
        (cid_settings(8, true), cid_settings(32, true), 1, 1),
        (cid_settings(0, true), cid_settings(16, false), 0, 1),
        (cid_settings(8, false), cid_settings(0, true), 1, 0),
        (cid_settings(0, false), cid_settings(0, false), 0, 0),
        (cid_settings(8, true), dtls::Settings::default(), 0, 0),
        (dtls::Settings::default(), cid_settings(8, true), 0, 0),
        (cid_settings(8, true), cid_settings(8, false), 0, 0),
    ] {
        let mut pair = cid_pair(client, server);
        let mut sim = Sim::perfect();
        pair.handshake(&mut sim).unwrap();
        assert_dtls13(&pair);
        assert_eq!(pair.client.local_connection_ids().count(), client_ids);
        assert_eq!(pair.server.local_connection_ids().count(), server_ids);
        pair.exchange(&mut sim, "directional CID policy");
        let mut data = Vec::new();
        pair.client.send(b"checked", &mut data).unwrap();
        assert_eq!(data[0] & 0x10 != 0, server_ids != 0);
        let received = pair.server.read_datagram(&mut data, sim.now).unwrap();
        let records = received.authenticated_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].epoch(), 3);
        assert_eq!(records[0].range(), 0..data.len());
        assert_eq!(records[0].connection_id().is_some(), server_ids != 0);
    }
}

#[test]
fn cid_updates_wait_for_ack_requests_wait_for_fulfillment_and_keys_update() {
    let mut pair = cid_pair(cid_settings(8, true), cid_settings(16, true));
    let mut sim = Sim::perfect();
    assert_eq!(
        pair.client.request_connection_ids(1),
        Err(Error::HandshakeNotComplete)
    );
    pair.handshake(&mut sim).unwrap();
    pair.client.request_connection_ids(2).unwrap();
    assert!(pair.client.request_connection_ids(1).is_err());
    pair.run(&mut sim, settled).unwrap();
    assert_eq!(pair.server.local_connection_ids().count(), 3);
    // A response and ACK have both arrived, so a new request is allowed.
    pair.client.request_connection_ids(1).unwrap();
    pair.run(&mut sim, settled).unwrap();
    assert_eq!(pair.server.local_connection_ids().count(), 4);

    let initial = pair.server.local_connection_ids().next().unwrap().to_vec();
    pair.server
        .issue_connection_ids(1, dtls::ConnectionIdUsage::Immediate)
        .unwrap();
    assert!(
        pair.server
            .issue_connection_ids(1, dtls::ConnectionIdUsage::Spare)
            .is_err()
    );
    pair.run(&mut sim, settled).unwrap();
    let latest = pair.server.local_connection_ids().last().unwrap().to_vec();
    assert_ne!(latest, initial);
    let mut data = Vec::new();
    pair.client.send(b"new receiving ID", &mut data).unwrap();
    let received = pair.server.read_datagram(&mut data, sim.now).unwrap();
    assert_eq!(
        received.authenticated_records()[0].connection_id(),
        Some(latest.as_slice())
    );

    pair.client.refresh_traffic_keys().unwrap();
    pair.server.refresh_traffic_keys().unwrap();
    pair.run(&mut sim, settled).unwrap();
    pair.exchange(&mut sim, "CID survives KeyUpdate");
    pair.server
        .issue_connection_ids(255, dtls::ConnectionIdUsage::Spare)
        .unwrap();
    pair.run(&mut sim, settled).unwrap();
    assert_eq!(
        pair.server.local_connection_ids().count(),
        dtls::MAX_CONNECTION_IDS
    );
    assert!(
        pair.server
            .issue_connection_ids(1, dtls::ConnectionIdUsage::Immediate)
            .is_err()
    );
    assert_eq!(
        pair.server
            .issue_connection_ids(1, dtls::ConnectionIdUsage::Spare)
            .unwrap(),
        0
    );
    pair.run(&mut sim, settled).unwrap();
    pair.client.request_connection_ids(1).unwrap();
    pair.run(&mut sim, settled).unwrap();
    // Even a zero-ID response fulfills the request.
    pair.client.request_connection_ids(1).unwrap();
    pair.run(&mut sim, settled).unwrap();
    assert_eq!(
        pair.server.local_connection_ids().count(),
        dtls::MAX_CONNECTION_IDS
    );
}

#[test]
fn cid_updates_retransmit_with_loss_duplicates_and_reordering() {
    let mut pair = cid_pair(cid_settings(8, true), cid_settings(16, true));
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    sim.to_client = Link::new(|n, _| match n {
        0 => Fate::Drop,
        1 => Fate::Duplicate,
        2 => Fate::Hold,
        _ => Fate::Deliver,
    });
    sim.to_server = Link::new(|n, _| if n == 0 { Fate::Drop } else { Fate::Deliver });
    pair.server
        .issue_connection_ids(2, dtls::ConnectionIdUsage::Immediate)
        .unwrap();
    pair.client.request_connection_ids(1).unwrap();
    pair.run(&mut sim, settled).unwrap();
    assert_eq!(pair.server.local_connection_ids().count(), 4);
    assert_eq!(pair.client.local_connection_ids().count(), 1);
    pair.exchange(&mut sim, "reliable CID update");
}

#[test]
fn cid_metadata_requires_authentication_and_replay_and_header_checks() {
    let mut pair = cid_pair(cid_settings(8, true), cid_settings(16, true));
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    pair.server
        .issue_connection_ids(1, dtls::ConnectionIdUsage::Spare)
        .unwrap();
    pair.run(&mut sim, settled).unwrap();
    let ids: Vec<Vec<u8>> = pair
        .server
        .local_connection_ids()
        .map(<[u8]>::to_vec)
        .collect();
    let mut original = Vec::new();
    pair.client
        .send(b"authenticated header", &mut original)
        .unwrap();
    let mut changed = original.clone();
    // Another valid local ID names this same association, but changing
    // the authenticated header must still fail AEAD authentication.
    changed[1..17].copy_from_slice(&ids[1]);
    let received = pair.server.read_datagram(&mut changed, sim.now).unwrap();
    assert!(received.authenticated_records().is_empty());
    assert!(received.app_data().is_empty());
    let mut replay = original.clone();
    let received = pair.server.read_datagram(&mut original, sim.now).unwrap();
    assert_eq!(received.authenticated_records().len(), 1);
    assert_eq!(
        received.authenticated_records()[0].connection_id(),
        Some(ids[0].as_slice())
    );
    assert_eq!(
        &original[received.app_data()[0].clone()],
        b"authenticated header"
    );
    let received = pair.server.read_datagram(&mut replay, sim.now).unwrap();
    assert!(received.authenticated_records().is_empty());
    assert!(received.app_data().is_empty());
}

#[test]
fn cid_missing_or_wrong_association_discards_the_remaining_datagram() {
    let mut pair = cid_pair(cid_settings(8, true), cid_settings(16, true));
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    for missing in [false, true] {
        let mut first = Vec::new();
        let mut middle = Vec::new();
        let mut last = Vec::new();
        pair.client.send(b"first", &mut first).unwrap();
        pair.client.send(b"middle", &mut middle).unwrap();
        pair.client.send(b"last", &mut last).unwrap();
        if missing {
            middle[0] &= !0x10;
            middle.drain(1..17);
        } else {
            middle[1] ^= 1;
        }
        let mut datagram = first;
        datagram.extend_from_slice(&middle);
        datagram.extend_from_slice(&last);
        let received = pair.server.read_datagram(&mut datagram, sim.now).unwrap();
        assert_eq!(received.authenticated_records().len(), 1);
        assert_eq!(received.app_data().len(), 1);
        assert_eq!(&datagram[received.app_data()[0].clone()], b"first");
        // The final record was not processed or marked as replayed.
        let received = pair.server.read_datagram(&mut last, sim.now).unwrap();
        assert_eq!(received.authenticated_records().len(), 1);
        assert_eq!(&last[received.app_data()[0].clone()], b"last");
    }
}

#[test]
fn cid_empty_directions_disable_inapplicable_updates() {
    let mut pair = cid_pair(cid_settings(0, true), cid_settings(16, false));
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    assert!(
        pair.client
            .issue_connection_ids(1, dtls::ConnectionIdUsage::Spare)
            .is_err()
    );
    assert!(pair.server.request_connection_ids(1).is_err());
    pair.client.request_connection_ids(1).unwrap();
    pair.run(&mut sim, settled).unwrap();
    assert_eq!(pair.server.local_connection_ids().count(), 2);
    pair.exchange(&mut sim, "empty receive direction");
}

#[test]
fn cid_on_an_already_verified_pinned_path_and_mtu_accounting() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut pair = Pair {
        client: dtls::ClientConnection::new_with_settings(
            Arc::new(client_config(&chain)),
            server_name(),
            cid_settings(8, true),
        )
        .unwrap(),
        server: dtls::ServerConnection::new_without_cookie_exchange_with_settings(
            Arc::new(server_config(&chain)),
            PEER,
            cid_settings(32, true),
        )
        .unwrap(),
    };
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    pair.client.set_mtu(256).unwrap();
    pair.server.set_mtu(256).unwrap();
    let largest = pair.client.max_application_data().unwrap();
    let data = vec![0x42; largest];
    let mut packet = Vec::new();
    pair.client.send(&data, &mut packet).unwrap();
    assert_eq!(packet.len(), 256);
    let received = pair.server.read_datagram(&mut packet, sim.now).unwrap();
    assert_eq!(&packet[received.app_data()[0].clone()], data);
    assert!(
        pair.client
            .send(&vec![0; largest + 1], &mut Vec::new())
            .is_err()
    );
    pair.server.send_close_notify();
    assert!(
        pair.server
            .issue_connection_ids(1, dtls::ConnectionIdUsage::Spare)
            .is_err()
    );
    assert!(pair.server.request_connection_ids(1).is_err());
}
