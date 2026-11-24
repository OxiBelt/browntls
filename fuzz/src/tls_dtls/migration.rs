//! CID and path validation over established simulated connections.

use std::net::SocketAddr;

use browntls_core::dtls::{self, rrc};

use super::{Net, Pair, settled};

pub(super) fn exercise(pair: &mut Pair, net: &mut Net<'_>) {
    if !pair.client.return_routability_checks_negotiated()
        || !pair.server.return_routability_checks_negotiated()
    {
        return;
    }
    assert!(dtls::ConnectionIdPolicy::new(7, true).is_err());
    let _ = dtls::Settings::default()
        .with_versions(dtls::Versions::V1_3)
        .with_connection_ids(dtls::ConnectionIdPolicy::new(0, false).unwrap());
    let message = rrc::Message {
        kind: rrc::MessageType::Challenge,
        cookie: [42; 8],
    };
    assert_eq!(
        rrc::Message::decode(&message.encode()).unwrap(),
        Some(message)
    );
    assert!(rrc::decode_extension(&[]).is_ok());

    pair.client.request_connection_ids(1).unwrap();
    net.run(&mut pair.client, &mut pair.server, settled)
        .unwrap();
    pair.server
        .issue_connection_ids(1, dtls::ConnectionIdUsage::Immediate)
        .unwrap();
    net.run(&mut pair.client, &mut pair.server, settled)
        .unwrap();
    let ids: Vec<Vec<u8>> = pair
        .server
        .local_connection_ids()
        .map(<[u8]>::to_vec)
        .collect();
    assert_eq!(
        pair.client.outbound_connection_id(),
        ids.last().map(Vec::as_slice)
    );
    let mut packet = Vec::new();
    pair.client.send(b"candidate path", &mut packet).unwrap();
    let mut demux = dtls::CidDemux::default();
    demux.replace(1u8, ids.iter().map(Vec::as_slice));
    assert!(dtls::CidDemux::<u8>::has_cid(&packet));
    assert_eq!(demux.lookup(&packet), Some(1));
    demux.remove(1);
    assert_eq!(demux.lookup(&packet), None);

    let mut server_validation = pair
        .server
        .new_path_validation("old", rrc::Selection::Basic, rrc::DEFAULT_TIMEOUT)
        .unwrap();
    let mut client_validation = pair
        .client
        .new_path_validation("server", rrc::Selection::Basic, rrc::DEFAULT_TIMEOUT)
        .unwrap();
    let received = pair.server.read_datagram(&mut packet, net.now).unwrap();
    let record = &received.authenticated_records()[0];
    assert!(record.connection_id().is_some());
    let _ = (
        record.range(),
        record.epoch(),
        record.sequence_number(),
        record.rrc_payload_range(),
    );
    assert!(record.path_validation_record(&packet).is_ok());
    assert_eq!(
        pair.server
            .handle_path_record(
                &mut server_validation,
                record,
                &packet,
                "new",
                true,
                net.now
            )
            .unwrap(),
        rrc::Action::None
    );
    assert_eq!(server_validation.bound_path(), &"old");
    assert_eq!(server_validation.pending_path(), Some(&"new"));
    let _ = server_validation.deadline();
    assert!(server_validation.reserve_send(&"old", 1));
    let rrc::Action::Send { path, message } = pair
        .server
        .poll_path_validation(&mut server_validation, net.now)
        .unwrap()
    else {
        panic!("challenge expected")
    };
    assert_eq!(path, "new");
    let mut challenge = Vec::new();
    pair.server.send_rrc(&message, &mut challenge).unwrap();
    assert_eq!(challenge.len(), pair.server.rrc_record_len().unwrap());
    let received = pair.client.read_datagram(&mut challenge, net.now).unwrap();
    let rrc::Action::Send { message, .. } = pair
        .client
        .handle_path_record(
            &mut client_validation,
            &received.authenticated_records()[0],
            &challenge,
            "server",
            true,
            net.now,
        )
        .unwrap()
    else {
        panic!("response expected")
    };
    let mut response = Vec::new();
    pair.client.send_rrc(&message, &mut response).unwrap();
    let received = pair.server.read_datagram(&mut response, net.now).unwrap();
    assert_eq!(
        pair.server
            .handle_path_record(
                &mut server_validation,
                &received.authenticated_records()[0],
                &response,
                "new",
                true,
                net.now
            )
            .unwrap(),
        rrc::Action::Adopt { path: "new" }
    );

    let addr = SocketAddr::from(([127, 0, 0, 1], 1234));
    let mut paths =
        dtls::UdpPathValidation::new(&pair.server, addr, rrc::Selection::Basic).unwrap();
    assert_eq!(paths.active(), addr);
    assert_eq!(paths.pending(), None);
    assert_eq!(paths.next_timeout(), None);
    let mut sent = |_: &[u8], _: SocketAddr| {};
    paths.poll(&mut pair.server, net.now, &mut sent).unwrap();
    let mut ordinary = Vec::new();
    pair.client.send(b"bound path", &mut ordinary).unwrap();
    let received = pair.server.read_datagram(&mut ordinary, net.now).unwrap();
    let ranges = paths
        .input(
            &mut pair.server,
            &received,
            &ordinary,
            addr,
            net.now,
            &mut sent,
        )
        .unwrap();
    assert_eq!(&ordinary[ranges[0].clone()], b"bound path");
}
