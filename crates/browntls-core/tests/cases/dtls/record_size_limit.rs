use super::*;

#[test]
fn dtls13_record_size_limit_survives_cookies_retransmission_and_key_update() {
    check_limits(dtls::Versions::V1_3, true, 1);
}

#[cfg(feature = "tls12")]
#[test]
fn dtls12_record_size_limit_counts_cid_inner_type() {
    check_limits(dtls::Versions::V1_2, true, 1);
    check_limits(dtls::Versions::V1_2, false, 0);
}

fn check_limits(versions: dtls::Versions, cid: bool, inner_type: usize) {
    let chain = server_chain(KeyType::EcdsaP256);
    let settings = |limit| {
        let settings = dtls::Settings::default()
            .with_versions(versions)
            .with_record_size_limit(Some(limit))
            .unwrap();
        if cid {
            settings.with_connection_ids(dtls::ConnectionIdPolicy::new(8, true).unwrap())
        } else {
            settings
        }
    };
    let mut pair = Pair {
        client: dtls::ClientConnection::new_with_settings(
            Arc::new(client_config(&chain)),
            server_name(),
            settings(64),
        )
        .unwrap(),
        server: dtls::ServerConnection::new_with_settings(
            Arc::new(dtls_server_config(&chain)),
            PEER,
            settings(92),
        )
        .unwrap(),
    };
    let mut sim = Sim::new(
        Link::perfect(),
        Link::new(|index, _| {
            if index == 1 {
                Fate::Drop
            } else {
                Fate::Deliver
            }
        }),
    );
    pair.handshake(&mut sim).unwrap();
    assert_eq!(pair.client.max_application_data(), Some(92 - inner_type));
    assert_eq!(pair.server.max_application_data(), Some(64 - inner_type));
    for mtu in [1400, 256] {
        pair.client.set_mtu(mtu).unwrap();
        pair.server.set_mtu(mtu).unwrap();
        assert_eq!(pair.client.max_application_data(), Some(92 - inner_type));
        assert_eq!(pair.server.max_application_data(), Some(64 - inner_type));
    }
    if versions == dtls::Versions::V1_3 {
        pair.client.refresh_traffic_keys().unwrap();
        pair.run(&mut sim, settled).unwrap();
    }
    let mut out = Vec::new();
    assert!(
        pair.server
            .send(&vec![0; 65 - inner_type], &mut out)
            .is_err()
    );
    assert!(out.is_empty());
    let expected = vec![0x61; 64 - inner_type];
    pair.server.send(&expected, &mut out).unwrap();
    let received = pair.client.read_datagram(&mut out, sim.now).unwrap();
    assert_eq!(received.app_data().len(), 1);
    assert_eq!(&out[received.app_data()[0].clone()], expected);
    pair.exchange(&mut sim, "record size limit");
}
