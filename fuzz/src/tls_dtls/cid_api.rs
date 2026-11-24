//! Bounded public CID API programs on a simulated, fixed-address path.

use std::net::UdpSocket;

use browntls_core::{ProtocolVersion, dtls};

use super::{Net, PEER, START, accept, settled, setup};
use crate::input::Input;

pub(super) const PREFIX: &[u8] = b"\xffCID-API\0";

pub(super) fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for version in 0..2 {
        for provider in 0..2 {
            for mode in 0..3 {
                for (client, server) in [(1, 2), (0, 2), (1, 0)] {
                    let mut seed = PREFIX.to_vec();
                    seed.extend_from_slice(&[version, provider, mode, client, server, 2]);
                    seeds.push(seed);
                }
            }
        }
    }
    seeds
}

fn settings(version: dtls::Versions, len: u8) -> dtls::Settings {
    dtls::Settings::default()
        .with_versions(version)
        .with_connection_ids(dtls::ConnectionIdPolicy::new(len, true).unwrap())
}

pub(super) fn run(data: &[u8]) {
    let mut input = Input::new(data);
    let v12 = input.bool();
    let rustcrypto = input.bool();
    let mode = input.choose(3);
    let lengths = [0, 8, 16, 32];
    let client_len = lengths[input.choose(lengths.len())];
    let server_len = lengths[input.choose(lengths.len())];
    let count = 1 + input.byte() % 3;
    assert!(dtls::ConnectionIdPolicy::new(7, true).is_err());
    assert!(dtls::ConnectionIdPolicy::new(33, true).is_err());
    let version = if v12 {
        dtls::Versions::V1_2
    } else {
        dtls::Versions::V1_3
    };
    let side = setup::Side {
        rustcrypto,
        suites: 0xff,
        versions: if v12 { 2 } else { 0 },
    };
    let configs = setup::configs(&setup::Choice {
        client: side,
        server: side,
        key_type: 0,
        server_group: None,
        cookies: true,
        defer: false,
    });
    let (Some(client_config), Some(server_config)) = (configs.client, configs.server) else {
        return;
    };
    let client_settings = settings(version, client_len);
    let server_settings = settings(version, server_len);
    let mut client = dtls::ClientConnection::new_with_settings(
        client_config,
        setup::localhost(),
        client_settings,
    )
    .unwrap();
    assert!(client.request_connection_ids(1).is_err());
    let acceptor =
        dtls::Acceptor::new_with_settings(server_config.clone(), server_settings.clone()).unwrap();
    // Construct the blocking wrapper where loopback sockets are available.
    if let Ok(socket) = UdpSocket::bind("127.0.0.1:0") {
        dtls::UdpServer::new_with_settings(server_config.clone(), socket, server_settings.clone())
            .unwrap();
    }
    let mut server = match mode {
        0 => {
            dtls::ServerConnection::new_with_settings(server_config, PEER, server_settings).unwrap()
        }
        1 => dtls::ServerConnection::new_without_cookie_exchange_with_settings(
            server_config,
            PEER,
            server_settings,
        )
        .unwrap(),
        _ => match accept(&acceptor, &mut client, false, true, START) {
            Some(server) => server,
            None => return,
        },
    };
    let mut net = Net::new(START);
    net.run(&mut client, &mut server, settled)
        .expect("CID handshake");
    let expected_version = if v12 {
        ProtocolVersion::DTLSv1_2
    } else {
        ProtocolVersion::DTLSv1_3
    };
    assert_eq!(client.protocol_version(), Some(expected_version));
    assert_eq!(server.protocol_version(), Some(expected_version));
    if v12 {
        use browntls_core::SupportedCipherSuite;
        use browntls_core::crypto::cipher::Tls12RecordProtection;

        let Some(SupportedCipherSuite::Tls12(suite)) = client.negotiated_cipher_suite() else {
            panic!("DTLS 1.2 suite expected");
        };
        let Tls12RecordProtection::Aead(algorithm) = suite.record else {
            panic!("DTLS 1.2 AEAD expected");
        };
        assert_eq!(algorithm.dtls12_cid_support(), (true, true));
    }
    let client_id = client.local_connection_ids().next().map(<[u8]>::to_vec);
    let server_id = server.local_connection_ids().next().map(<[u8]>::to_vec);
    assert_eq!(client_id.is_some(), client_len != 0);
    assert_eq!(server_id.is_some(), server_len != 0);
    exchange(&mut client, &mut server, server_id.as_deref(), net.now);
    exchange(&mut server, &mut client, client_id.as_deref(), net.now);
    if v12 {
        assert!(client.request_connection_ids(count).is_err());
        assert!(
            server
                .issue_connection_ids(count, dtls::ConnectionIdUsage::Immediate)
                .is_err()
        );
    } else if client_len != 0 && server_len != 0 {
        client.request_connection_ids(count).unwrap();
        net.run(&mut client, &mut server, settled).unwrap();
        server
            .issue_connection_ids(1, dtls::ConnectionIdUsage::Immediate)
            .unwrap();
        net.run(&mut client, &mut server, settled).unwrap();
        let latest = server.local_connection_ids().last().unwrap().to_vec();
        exchange(&mut client, &mut server, Some(&latest), net.now);
        client
            .issue_connection_ids(1, dtls::ConnectionIdUsage::Spare)
            .unwrap();
        net.run(&mut client, &mut server, settled).unwrap();
    }
}

fn exchange<A: browntls_core::SideData, B: browntls_core::SideData>(
    sender: &mut dtls::ConnectionCommon<A>,
    receiver: &mut dtls::ConnectionCommon<B>,
    expected: Option<&[u8]>,
    now: std::time::Duration,
) {
    let mut packet = Vec::new();
    sender.send(b"CID data", &mut packet).unwrap();
    let received = receiver.read_datagram(&mut packet, now).unwrap();
    assert_eq!(received.app_data().len(), 1);
    assert_eq!(&packet[received.app_data()[0].clone()], b"CID data");
    let records = received.authenticated_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].connection_id(), expected);
    assert_eq!(records[0].range(), 0..packet.len());
    let _ = (records[0].epoch(), records[0].sequence_number());
}

#[cfg(test)]
mod tests {
    #[test]
    fn cid_api_seeds_replay() {
        let seeds = super::seeds();
        assert_eq!(seeds.len(), 36);
        for seed in seeds {
            super::super::run(&seed);
        }
    }
}
