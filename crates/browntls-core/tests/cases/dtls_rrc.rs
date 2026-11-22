// Normal API use with a deterministic clock and delivery schedule. Path
// labels are opaque validator identities; these cases never open a socket.

fn rrc_settings(len: u8, sending: bool) -> dtls::Settings {
    dtls::Settings::default()
        .with_return_routability_checks(dtls::ConnectionIdPolicy::new(len, sending).unwrap())
}

#[test]
fn rrc_negotiates_only_with_mutual_opt_in_and_cid() {
    for (client, server, expected) in [
        (rrc_settings(8, true), rrc_settings(16, true), true),
        (rrc_settings(0, true), rrc_settings(16, false), true),
        (rrc_settings(8, false), rrc_settings(0, true), true),
        (rrc_settings(0, false), rrc_settings(0, false), true),
        (rrc_settings(8, true), cid_settings(16, true), false),
        (cid_settings(8, true), rrc_settings(16, true), false),
        (rrc_settings(8, true), dtls::Settings::default(), false),
        (dtls::Settings::default(), rrc_settings(16, true), false),
        (rrc_settings(8, true), rrc_settings(16, false), false),
    ] {
        let mut pair = cid_pair(client, server);
        assert!(!pair.client.return_routability_checks_negotiated());
        assert!(pair.client.rrc_record_len().is_err());
        let message = dtls::rrc::Message {
            kind: dtls::rrc::MessageType::Challenge,
            cookie: [7; 8],
        };
        let mut early = Vec::new();
        assert_eq!(
            pair.client.send_rrc(&message, &mut early),
            Err(Error::HandshakeNotComplete)
        );
        assert!(early.is_empty());
        let mut sim = Sim::perfect();
        pair.handshake(&mut sim).unwrap();
        assert_eq!(pair.client.return_routability_checks_negotiated(), expected);
        assert_eq!(pair.server.return_routability_checks_negotiated(), expected);
        assert_eq!(pair.client.rrc_record_len().is_ok(), expected);
        assert_eq!(
            pair.client
                .new_path_validation(
                    "bound",
                    dtls::rrc::Selection::Basic,
                    dtls::rrc::DEFAULT_TIMEOUT,
                )
                .is_ok(),
            expected
        );
        pair.exchange(&mut sim, "ordinary data after RRC negotiation");
        if !expected {
            let message = dtls::rrc::Message {
                kind: dtls::rrc::MessageType::Challenge,
                cookie: [7; 8],
            };
            let mut out = Vec::new();
            assert!(pair.client.send_rrc(&message, &mut out).is_err());
            assert!(out.is_empty());
        }
    }
}

#[test]
fn rrc_protected_round_trip_drives_only_caller_owned_validation() {
    protected_path_validation(dtls::Versions::V1_3);
}

#[cfg(feature = "tls12")]
#[test]
fn dtls12_rrc_protected_control_and_path_validation() {
    protected_path_validation(dtls::Versions::V1_2);
}

fn protected_path_validation(versions: dtls::Versions) {
    use dtls::rrc::{Action, DEFAULT_TIMEOUT, Selection};
    let mut pair = cid_pair(
        rrc_settings(8, true).with_versions(versions),
        rrc_settings(16, true).with_versions(versions),
    );
    let mut sim = Sim::perfect();
    pair.handshake(&mut sim).unwrap();
    let ids: Vec<Vec<u8>> = pair
        .server
        .local_connection_ids()
        .map(<[u8]>::to_vec)
        .collect();
    let mut server_validation = pair
        .server
        .new_path_validation("old", Selection::Basic, DEFAULT_TIMEOUT)
        .unwrap();
    let mut client_validation = pair
        .client
        .new_path_validation("server", Selection::Basic, DEFAULT_TIMEOUT)
        .unwrap();

    let mut reordered = Vec::new();
    pair.client
        .send(b"valid reordered datagram", &mut reordered)
        .unwrap();
    let mut latest = Vec::new();
    pair.client
        .send(b"most recent datagram", &mut latest)
        .unwrap();
    pair.server.read_datagram(&mut latest, sim.now).unwrap();
    let old = pair.server.read_datagram(&mut reordered, sim.now).unwrap();
    assert_eq!(old.app_data().len(), 1);
    assert_eq!(
        pair.server
            .handle_path_record(
                &mut server_validation,
                &old.authenticated_records()[0],
                &reordered,
                "candidate",
                true,
                sim.now,
            )
            .unwrap(),
        Action::None
    );
    assert_eq!(server_validation.pending_path(), None);

    let mut app = Vec::new();
    pair.client
        .send(b"transparent application datagram", &mut app)
        .unwrap();
    let received = pair.server.read_datagram(&mut app, sim.now).unwrap();
    assert_eq!(received.app_data().len(), 1);
    assert_eq!(
        &app[received.app_data()[0].clone()],
        b"transparent application datagram"
    );
    let record = &received.authenticated_records()[0];
    assert!(record.rrc_payload_range().is_none());
    // Reading alone did not change validator state or any lookup identifier.
    assert_eq!(server_validation.pending_path(), None);
    assert_eq!(
        pair.server
            .handle_path_record(
                &mut server_validation,
                record,
                &app,
                "candidate",
                true,
                sim.now,
            )
            .unwrap(),
        Action::None
    );
    assert_eq!(server_validation.bound_path(), &"old");
    let Action::Send { path, message } = pair
        .server
        .poll_path_validation(&mut server_validation, sim.now)
        .unwrap()
    else {
        panic!("challenge expected")
    };
    assert_eq!(path, "candidate");
    let mut challenge = Vec::new();
    pair.server.send_rrc(&message, &mut challenge).unwrap();
    assert_eq!(challenge.len(), pair.server.rrc_record_len().unwrap());
    let received = pair.client.read_datagram(&mut challenge, sim.now).unwrap();
    assert!(received.app_data().is_empty());
    assert_eq!(received.authenticated_records().len(), 1);
    let record = &received.authenticated_records()[0];
    assert!(record.rrc_payload_range().is_some());
    let Action::Send { path, message } = pair
        .client
        .handle_path_record(
            &mut client_validation,
            record,
            &challenge,
            "server",
            true,
            sim.now,
        )
        .unwrap()
    else {
        panic!("response expected")
    };
    assert_eq!(path, "server");
    let mut response = Vec::new();
    pair.client.send_rrc(&message, &mut response).unwrap();
    assert_eq!(response.len(), pair.client.rrc_record_len().unwrap());
    let received = pair.server.read_datagram(&mut response, sim.now).unwrap();
    assert!(received.app_data().is_empty());
    assert_eq!(server_validation.bound_path(), &"old");
    assert_eq!(
        pair.server
            .handle_path_record(
                &mut server_validation,
                &received.authenticated_records()[0],
                &response,
                "candidate",
                true,
                sim.now,
            )
            .unwrap(),
        Action::Adopt { path: "candidate" }
    );
    assert_eq!(server_validation.bound_path(), &"candidate");
    assert_eq!(
        pair.server.local_connection_ids().collect::<Vec<_>>(),
        ids.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    pair.exchange(&mut sim, "application data after protected RRC");
    pair.client.send_close_notify();
    let mut closed = Vec::new();
    assert!(pair.client.send_rrc(&message, &mut closed).is_err());
    assert!(closed.is_empty());
}

#[cfg(feature = "std")]
#[test]
fn rrc_candidate_never_delivers_application_data_before_validation() {
    socket_path_validation(dtls::Versions::V1_3);
    #[cfg(feature = "tls12")]
    socket_path_validation(dtls::Versions::V1_2);
}

#[cfg(feature = "std")]
fn socket_path_validation(versions: dtls::Versions) {
    use dtls::rrc::{DEFAULT_TIMEOUT, Message, MessageType, Selection};
    use dtls::{ServerConnection, UdpPathValidation};
    use std::net::SocketAddr;

    fn input(
        server: &mut ServerConnection,
        paths: &mut UdpPathValidation,
        mut datagram: Vec<u8>,
        source: SocketAddr,
        now: Duration,
        output: &mut Vec<(SocketAddr, Vec<u8>)>,
    ) -> Vec<Vec<u8>> {
        let received = server.read_datagram(&mut datagram, now).unwrap();
        paths
            .input(
                server,
                &received,
                &datagram,
                source,
                now,
                &mut |data, peer| {
                    output.push((peer, data.to_vec()));
                },
            )
            .unwrap()
            .into_iter()
            .map(|range| datagram[range].to_vec())
            .collect()
    }

    fn decode_rrc(pair: &mut Pair, data: &mut [u8], now: Duration) -> Message {
        let received = pair.client.read_datagram(data, now).unwrap();
        let payload = received.authenticated_records()[0]
            .rrc_payload_range()
            .unwrap();
        Message::decode(&data[payload]).unwrap().unwrap()
    }

    fn probe(
        pair: &mut Pair,
        paths: &mut UdpPathValidation,
        now: Duration,
    ) -> (SocketAddr, Message) {
        let mut output = None;
        paths
            .poll(&mut pair.server, now, &mut |data, peer| {
                assert!(output.replace((peer, data.to_vec())).is_none());
            })
            .unwrap();
        let (path, mut data) = output.unwrap();
        let message = decode_rrc(pair, &mut data, now);
        assert_eq!(message.kind, MessageType::Challenge);
        (path, message)
    }

    let old = SocketAddr::from(([127, 0, 0, 1], 41000));
    let candidate = SocketAddr::from(([127, 0, 0, 1], 41001));
    let settings = || rrc_settings(8, true).with_versions(versions);
    for selection in [Selection::Basic, Selection::Enhanced] {
        let mut pair = cid_pair(settings(), settings());
        let mut sim = Sim::perfect();
        pair.handshake(&mut sim).unwrap();
        let mut paths = UdpPathValidation::new(&pair.server, old, selection).unwrap();
        let mut output = Vec::new();
        let mut trigger = Vec::new();
        pair.client
            .send_rrc(
                &Message {
                    kind: MessageType::Challenge,
                    cookie: [7; 8],
                },
                &mut trigger,
            )
            .unwrap();
        let credited = trigger.len();
        assert!(
            input(
                &mut pair.server,
                &mut paths,
                trigger,
                candidate,
                sim.now,
                &mut output
            )
            .is_empty()
        );
        assert_eq!(paths.active(), old);
        assert_eq!(paths.pending(), Some(candidate));
        let (reply_path, mut reply) = output.pop().unwrap();
        assert_eq!(reply_path, candidate);
        assert_eq!(reply.len(), credited);
        assert_eq!(
            decode_rrc(&mut pair, &mut reply, sim.now),
            Message {
                kind: MessageType::Response,
                cookie: [7; 8]
            }
        );

        let mut candidate_bytes = reply.len();
        let mut last_probe = None;
        let mut now = sim.now;
        for _ in 0..16 {
            let Some(due) = paths.next_timeout() else {
                break;
            };
            assert!(due >= now && due <= sim.now + DEFAULT_TIMEOUT * 3);
            now = due;
            paths
                .poll(&mut pair.server, now, &mut |data, peer| {
                    output.push((peer, data.to_vec()))
                })
                .unwrap();
            for (peer, mut data) in output.drain(..) {
                assert!(peer == candidate || (peer == old && selection == Selection::Enhanced));
                if peer == candidate {
                    candidate_bytes += data.len();
                }
                let probe = decode_rrc(&mut pair, &mut data, now);
                assert_eq!(probe.kind, MessageType::Challenge);
                if peer == candidate {
                    last_probe = Some(probe);
                }
            }
            assert_eq!(paths.active(), old);
        }
        assert_eq!(candidate_bytes, 3 * credited, "{versions:?} {selection:?}");
        assert_eq!(paths.pending(), None);
        assert_eq!(paths.next_timeout(), None);

        // A genuine but late reply cannot revive the expired validation.
        let mut late = Vec::new();
        pair.client
            .send_rrc(
                &Message {
                    kind: MessageType::Response,
                    ..last_probe.unwrap()
                },
                &mut late,
            )
            .unwrap();
        assert!(
            input(
                &mut pair.server,
                &mut paths,
                late,
                candidate,
                now,
                &mut output
            )
            .is_empty()
        );
        assert_eq!(paths.active(), old);
        assert_eq!(paths.next_timeout(), None);
        assert!(output.is_empty());

        let mut active_data = Vec::new();
        pair.client
            .send(b"old path after expiry", &mut active_data)
            .unwrap();
        assert_eq!(
            input(
                &mut pair.server,
                &mut paths,
                active_data,
                old,
                now,
                &mut output
            ),
            [b"old path after expiry".to_vec()]
        );

        // A new observation can succeed. Only data following the matching
        // response in wire order is released, even in the same datagram.
        let mut trigger = Vec::new();
        pair.client
            .send(b"start a fresh validation", &mut trigger)
            .unwrap();
        assert!(
            input(
                &mut pair.server,
                &mut paths,
                trigger,
                candidate,
                now,
                &mut output
            )
            .is_empty()
        );
        let (mut path, mut challenge) = probe(&mut pair, &mut paths, now);
        if selection == Selection::Enhanced {
            assert_eq!(path, old);
            let mut drop = Vec::new();
            pair.client
                .send_rrc(
                    &Message {
                        kind: MessageType::Drop,
                        ..challenge
                    },
                    &mut drop,
                )
                .unwrap();
            assert!(input(&mut pair.server, &mut paths, drop, old, now, &mut output).is_empty());
            now = paths.next_timeout().unwrap();
            (path, challenge) = probe(&mut pair, &mut paths, now);
        }
        assert_eq!(path, candidate);
        let response = Message {
            kind: MessageType::Response,
            ..challenge
        };
        let mut wrong_path = Vec::new();
        pair.client.send_rrc(&response, &mut wrong_path).unwrap();
        assert!(
            input(
                &mut pair.server,
                &mut paths,
                wrong_path,
                old,
                now,
                &mut output
            )
            .is_empty()
        );
        assert_eq!(paths.active(), old);
        assert_eq!(paths.pending(), Some(candidate));

        let mut coalesced = Vec::new();
        pair.client
            .send(b"before response", &mut coalesced)
            .unwrap();
        pair.client.send_rrc(&response, &mut coalesced).unwrap();
        pair.client.send(b"after response", &mut coalesced).unwrap();
        assert_eq!(
            input(
                &mut pair.server,
                &mut paths,
                coalesced,
                candidate,
                now,
                &mut output
            ),
            [b"after response".to_vec()]
        );
        assert_eq!(paths.active(), candidate);
        assert_eq!(paths.next_timeout(), None);
        assert!(output.is_empty());
    }
}
