//! Deterministic negotiation, wire validation and resource-bound cases.

use super::*;
use crate::common_state::Side;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ClientExtensions, ServerExtensions};
use crate::rand::GetRandomFailed;
use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug)]
struct Counter(AtomicU8);
impl SecureRandom for Counter {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        bytes.fill(self.0.fetch_add(1, Ordering::Relaxed));
        Ok(())
    }
}

#[derive(Debug)]
struct Repeats;
impl SecureRandom for Repeats {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        bytes.fill(7);
        Ok(())
    }
}

#[derive(Debug)]
struct Fails;
impl SecureRandom for Fails {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        Err(GetRandomFailed)
    }
}

fn cids(receive_len: u8, allow_sending: bool) -> Cids {
    // Each test gets its own deterministic source, including parallel runs.
    let random = alloc::boxed::Box::leak(alloc::boxed::Box::new(Counter(AtomicU8::new(1))));
    let mut cids = Cids::default();
    cids.initialize(
        Some(ConnectionIdPolicy::new(receive_len, allow_sending).unwrap()),
        random,
    )
    .unwrap();
    cids
}

fn negotiate(client: &mut Cids, server: &mut Cids) {
    server.select(client.offer().as_ref(), true).unwrap();
    client.select(server.response().as_ref(), false).unwrap();
}

fn update(ids: &[&[u8]], usage: u8) -> Vec<u8> {
    let mut list = Vec::new();
    for id in ids {
        PayloadU8::new(id.to_vec()).encode(&mut list);
    }
    let mut out = Vec::new();
    (list.len() as u16).encode(&mut out);
    out.extend_from_slice(&list);
    out.push(usage);
    out
}

#[test]
fn directional_policy_and_empty_receiving_ids() {
    for (client_len, client_sends, server_len, server_sends, selected) in [
        (8, true, 16, true, true),
        (0, true, 16, false, true),
        (8, false, 0, true, true),
        (0, false, 0, false, true),
        (8, true, 16, false, false),
    ] {
        let mut client = cids(client_len, client_sends);
        let mut server = cids(server_len, server_sends);
        negotiate(&mut client, &mut server);
        assert_eq!(client.negotiated, selected);
        assert_eq!(server.negotiated, selected);
        assert_eq!(
            client.receive_len(),
            if selected { usize::from(client_len) } else { 0 }
        );
        assert_eq!(
            client.outbound().len(),
            if selected { usize::from(server_len) } else { 0 }
        );
        assert_eq!(
            server.outbound().len(),
            if selected { usize::from(client_len) } else { 0 }
        );
    }
    let mut client = cids(8, false);
    assert!(
        client
            .select(Some(&PayloadU8::new(alloc::vec![9; 16])), false)
            .is_err()
    );
    assert!(!client.negotiated);
    assert!(
        Cids::default()
            .select(Some(&PayloadU8::empty()), false)
            .is_err()
    );
    let mut client = cids(8, true);
    let mut server = Cids::default();
    negotiate(&mut client, &mut server);
    assert!(!client.negotiated);
    assert!(!server.negotiated);
}

#[test]
fn extension_round_trip_and_bad_lengths() {
    for id in [&[][..], &[7; 8], &[9; 255]] {
        let extensions = ServerExtensions {
            connection_id: Some(PayloadU8::new(id.to_vec())),
            ..Default::default()
        };
        let bytes = extensions.get_encoding();
        assert_eq!(ServerExtensions::read_bytes(&bytes).unwrap(), extensions);
        assert_eq!(extensions.present_types(), [ExtensionType::ConnectionId]);
        let parsed = ClientExtensions::read_bytes(&bytes).unwrap();
        assert_eq!(parsed.connection_id.as_ref().unwrap().0, id);
        // The stream/QUIC ClientHello encoder never emits the indication.
        assert_eq!(parsed.get_encoding(), [0, 0]);
    }
    for malformed in [
        &[0, 4, 0, 54, 0, 0][..],                 // missing CID vector length
        &[0, 5, 0, 54, 0, 1, 1],                  // truncated CID
        &[0, 6, 0, 54, 0, 2, 0, 1],               // trailing byte
        &[0, 10, 0, 54, 0, 1, 0, 0, 54, 0, 1, 0], // duplicate
    ] {
        assert!(ClientExtensions::read_bytes(malformed).is_err());
        assert!(ServerExtensions::read_bytes(malformed).is_err());
    }
}

#[test]
fn fixed_local_length_lifetime_bound_and_no_reuse() {
    for len in [0, 8, 16, 32] {
        assert!(ConnectionIdPolicy::new(len, true).is_ok());
    }
    for len in [1, 7, 33, 255] {
        assert!(ConnectionIdPolicy::new(len, true).is_err());
    }
    let mut local = cids(8, true);
    let mut peer = cids(32, true);
    negotiate(&mut local, &mut peer);
    let initial = local.local[0].clone();
    let (count, body) = local.new_ids(255, ConnectionIdUsage::Immediate).unwrap();
    assert_eq!(count, MAX_CONNECTION_IDS - 1);
    assert_eq!(local.local.len(), MAX_CONNECTION_IDS);
    assert!(local.local.iter().all(|id| id.len() == 8));
    assert!(local.matches(Some(&initial)));
    assert!(!local.matches(None));
    assert!(!local.matches(Some(&[99; 8])));
    peer.receive_new(&body).unwrap();
    assert_eq!(peer.outbound(), local.local[1]);
    assert_eq!(local.local_ids().count(), MAX_CONNECTION_IDS);
    assert!(local.new_ids(1, ConnectionIdUsage::Immediate).is_err());
    let (count, body) = local.new_ids(1, ConnectionIdUsage::Spare).unwrap();
    assert_eq!(count, 0);
    assert_eq!(body, [0, 0, 1]);
    peer.receive_new(&body).unwrap();
    for (i, id) in local.local.iter().enumerate() {
        assert!(!local.local[..i].contains(id));
    }
}

#[test]
fn random_failure_and_collision_are_bounded_and_transactional() {
    let policy = Some(ConnectionIdPolicy::new(8, true).unwrap());
    assert_eq!(
        Cids::default().initialize(policy, &Fails),
        Err(Error::FailedToGetRandomBytes)
    );
    let mut local = Cids::default();
    local.initialize(policy, &Repeats).unwrap();
    let mut peer = cids(8, true);
    negotiate(&mut local, &mut peer);
    assert_eq!(
        local.new_ids(2, ConnectionIdUsage::Spare),
        Err(Error::FailedToGetRandomBytes)
    );
    assert_eq!(local.local.len(), 1);
}

#[test]
fn updates_validate_vectors_usage_direction_and_bounded_spares() {
    let mut local = cids(8, true);
    let mut peer = cids(16, true);
    negotiate(&mut local, &mut peer);
    let initial = local.outbound().to_vec();
    local
        .receive_new(&update(&[&[2; 255], &[3; 1], &[3; 1]], 1))
        .unwrap();
    assert_eq!(local.outbound(), initial);
    assert_eq!(local.peer.len(), 3);
    let ids: Vec<Vec<u8>> = (10..50).map(|i| alloc::vec![i; 20]).collect();
    let refs: Vec<&[u8]> = ids.iter().map(Vec::as_slice).collect();
    local.receive_new(&update(&refs, 1)).unwrap();
    assert_eq!(local.peer.len(), MAX_CONNECTION_IDS);
    local.receive_new(&update(&[&[4; 3]], 0)).unwrap();
    assert_eq!(local.outbound(), [4; 3]);
    local.receive_new(&update(&[&[]], 0)).unwrap();
    assert!(local.outbound().is_empty());
    for invalid in [
        &[][..],
        &[0],
        &[0, 2, 3, 1],
        &[0, 0, 0],
        &[0, 0, 2],
        &[0, 0, 1, 0],
    ] {
        assert!(local.receive_new(invalid).is_err());
    }
    assert_eq!(
        Cids::default().receive_new(&[0, 0, 1]).unwrap_err().0,
        AlertDescription::UnexpectedMessage
    );
    let mut empty = cids(0, true);
    let mut local = cids(8, true);
    negotiate(&mut local, &mut empty);
    assert_eq!(
        local.receive_new(&[0, 0, 1]).unwrap_err().0,
        AlertDescription::UnexpectedMessage
    );
    assert!(empty.new_ids(1, ConnectionIdUsage::Spare).is_err());
}

#[test]
fn cid_messages_require_application_epoch_and_complete_handshake() {
    let mut dtls = Dtls::new(Side::Client, Settings::default());
    let request = [9, 0, 0, 1, 1];
    for (epoch, handshaking) in [(0, false), (2, false), (3, true), (3, false)] {
        assert_eq!(
            dtls.handle_cid_message(epoch, &request, handshaking)
                .unwrap_err()
                .0,
            AlertDescription::UnexpectedMessage
        );
    }
    assert!(
        !dtls
            .handle_cid_message(3, &[24, 0, 0, 1, 0], false)
            .unwrap()
    );
}

#[test]
fn cid_extension_placement_excludes_stream_and_quic_responses() {
    use crate::tls13::extensions::{Tls13Message, allowed_in};
    for message in [
        Tls13Message::ServerHello,
        Tls13Message::HelloRetryRequest,
        Tls13Message::EncryptedExtensions,
        Tls13Message::CertificateRequest,
        Tls13Message::Certificate,
        Tls13Message::NewSessionTicket,
    ] {
        assert_eq!(
            allowed_in(ExtensionType::ConnectionId, message),
            Some(false)
        );
    }
    // Only the DTLS ServerHello validator has the explicit exception.
    assert_eq!(
        allowed_in(ExtensionType::ConnectionId, Tls13Message::ClientHello),
        Some(true)
    );
}

#[test]
fn cid_management_checks_empty_directions_and_request_flood_bound() {
    let mut local = cids(8, true);
    let mut peer = cids(0, true);
    negotiate(&mut local, &mut peer);
    let request = [9, 0, 0, 1, 255];
    let mut dtls = Dtls::new(Side::Server, Settings::default());
    dtls.cid = peer;
    assert_eq!(
        dtls.handle_cid_message(3, &request, false).unwrap_err().0,
        AlertDescription::UnexpectedMessage
    );
    dtls.cid = local;
    assert!(dtls.handle_cid_message(3, &[9, 0, 0, 0], false).is_err());
    assert!(dtls.handle_cid_message(3, &request, false).unwrap());
    assert_eq!(dtls.cid.requested, Some(255));
    assert_eq!(
        dtls.handle_cid_message(3, &request, false).unwrap_err().0,
        AlertDescription::TooManyCidsRequested
    );
}

#[cfg(any(feature = "native", feature = "rustcrypto"))]
mod protected {
    use super::*;
    use crate::crypto::tls13::OkmBlock;
    use crate::dtls::state::Incoming;
    use crate::enums::ContentType;
    use core::time::Duration;

    fn pair() -> (Dtls, Dtls) {
        #[cfg(feature = "native")]
        let suite = crate::crypto::native::cipher_suite::TLS13_AES_128_GCM_SHA256;
        #[cfg(all(not(feature = "native"), feature = "rustcrypto"))]
        let suite = crate::crypto::rustcrypto::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let suite = suite.tls13().unwrap();
        let secret = OkmBlock::new(&[0x42; 32]);
        let mut a = Dtls::new(Side::Client, Settings::default());
        let mut b = Dtls::new(Side::Server, Settings::default());
        a.cid = cids(8, true);
        b.cid = cids(16, true);
        negotiate(&mut a.cid, &mut b.cid);
        for dtls in [&mut a, &mut b] {
            // Fixed test traffic secrets install epochs 2 and 3.
            for _ in 0..2 {
                dtls.set_write_secret(suite, &secret);
                dtls.set_read_secret(suite, &secret);
            }
        }
        (a, b)
    }

    #[test]
    fn deterministic_protected_round_trip_and_header_authentication() {
        let (mut a, mut b) = pair();
        let (_, spare) = b.cid.new_ids(1, ConnectionIdUsage::Spare).unwrap();
        a.cid.receive_new(&spare).unwrap();
        let mut record = Vec::new();
        a.seal_record(&mut record, 3, ContentType::ApplicationData, b"round trip")
            .unwrap();
        let original = record.clone();
        let mut changed = record.clone();
        changed[1..17].copy_from_slice(&b.cid.local[1]);
        assert_eq!(
            b.read_record(&mut changed, &mut 0, false).unwrap(),
            Incoming::Handled
        );
        assert!(b.authenticated_record.is_none());
        let mut replay = record.clone();
        let Incoming::ApplicationData(range) = b.read_record(&mut record, &mut 0, false).unwrap()
        else {
            panic!("application data expected")
        };
        assert_eq!(&record[range], b"round trip");
        let metadata = b.authenticated_record.take().unwrap();
        assert_eq!(metadata.sequence_number(), 0);
        assert_eq!(metadata.connection_id(), Some(b.cid.local[0].as_slice()));
        assert_eq!(
            b.read_record(&mut replay, &mut 0, false).unwrap(),
            Incoming::Handled
        );
        assert!(b.authenticated_record.is_none());
        // The deterministic traffic keys and CIDs produce identical bytes
        // for the same initial state, independently of earlier reads.
        let (mut a2, _) = pair();
        let mut same = Vec::new();
        a2.seal_record(&mut same, 3, ContentType::ApplicationData, b"round trip")
            .unwrap();
        assert_eq!(same, original);
    }

    #[test]
    fn update_categories_gate_ack_and_fulfillment_independently() {
        let (mut a, mut b) = pair();
        a.issue_cids(1, ConnectionIdUsage::Immediate).unwrap();
        a.request_cids(1).unwrap();
        assert!(a.issue_cids(1, ConnectionIdUsage::Spare).is_err());
        assert!(a.request_cids(1).is_err());
        let mut out = Vec::new();
        a.write_datagram(&mut out, Duration::ZERO).unwrap();
        let mut at = 0;
        while at < out.len() {
            b.read_record(&mut out, &mut at, false).unwrap();
            while let Some((epoch, bytes)) = b.next_message() {
                assert!(b.handle_cid_message(epoch, &bytes, false).unwrap());
            }
        }
        // ACK for the update releases that category alone. The request
        // remains blocked after its ACK until a response arrives too.
        a.on_ack([RecordNumber { epoch: 3, seq: 0 }].into_iter());
        a.issue_cids(1, ConnectionIdUsage::Spare).unwrap();
        a.on_ack([RecordNumber { epoch: 3, seq: 1 }].into_iter());
        assert!(a.request_cids(1).is_err());
        a.cid.receive_new(&[0, 0, 1]).unwrap();
        a.request_cids(1).unwrap();
        assert_eq!(b.cid.local.len(), 1);
        b.answer_cid_request().unwrap();
        assert_eq!(b.cid.local.len(), 2);
        assert!(b.out.has_type(HandshakeType::NewConnectionId));
    }

    #[test]
    fn maximum_peer_id_length_and_small_mtu_fail_explicitly() {
        let (mut a, _) = pair();
        a.set_mtu(256).unwrap();
        a.cid.receive_new(&update(&[&[9; 255]], 0)).unwrap();
        assert!(a.write_datagram(&mut Vec::new(), Duration::ZERO).is_err());
        assert!(a.set_mtu(256).is_err());
        // 294 bytes would fit a fragment but not a one-record ACK.
        assert!(a.set_mtu(294).is_err());
        a.set_mtu(295).unwrap();
        a.set_mtu(512).unwrap();
        let mut record = Vec::new();
        a.seal_record(
            &mut record,
            3,
            ContentType::ApplicationData,
            b"long peer ID",
        )
        .unwrap();
        assert_eq!(&record[1..256], &[9; 255]);
        assert!(record.len() <= 512);
    }
}
