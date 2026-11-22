use alloc::vec::Vec;

use super::{Dtls, HandshakeHeader, HandshakeType, RecordNumber, Settings, Side};
use crate::dtls::reassembly::WINDOW;

#[test]
fn record_ack_requires_every_fragment_to_be_buffered() {
    let mut state = Dtls::new(Side::Client, Settings::default());
    let mut record = Vec::new();
    for message_seq in [0, WINDOW] {
        record.extend_from_slice(
            &HandshakeHeader {
                typ: u8::from(HandshakeType::Finished),
                length: 1,
                message_seq,
                fragment_offset: 0,
                fragment_length: 1,
            }
            .encode(),
        );
        record.push(1);
    }

    let mixed = RecordNumber { epoch: 2, seq: 0 };
    state
        .read_handshake_fragments(&record, mixed, true)
        .unwrap();
    assert!(state.acks.is_empty());

    let buffered = RecordNumber { epoch: 2, seq: 1 };
    state
        .read_handshake_fragments(&record[..13], buffered, true)
        .unwrap();
    assert_eq!(state.acks, [buffered]);
}

#[test]
fn record_size_limit_is_independent_of_mtu_and_rejects_values_below_64() {
    let settings = Settings::default()
        .with_record_size_limit(Some(64))
        .unwrap();
    let state = Dtls::new(Side::Client, settings);
    assert_eq!(state.mtu(), super::DEFAULT_MTU);
    assert_eq!(state.record_size_limit_offer(), Some(64));
    assert!(
        Settings::default()
            .with_record_size_limit(Some(63))
            .is_err()
    );
    assert_eq!(
        Settings::default()
            .with_record_size_limit(None)
            .unwrap()
            .record_size_limit,
        None
    );
}

#[test]
fn record_size_limit_observation_is_applied_only_after_acknowledgement() {
    let mut state = Dtls::new(
        Side::Client,
        Settings::default()
            .with_record_size_limit(Some(64))
            .unwrap(),
    );
    state.start_record_size_limit_observation();
    state.observed_record_size_limit_overflow = true;
    assert_eq!(
        state.set_record_size_limits(64, 80, true),
        Err(crate::error::Error::PeerSentOversizedRecord)
    );

    state.start_record_size_limit_observation();
    state.observed_record_size_limit_overflow = true;
    state.clear_record_size_limit_observation();
    assert!(!state.observed_record_size_limit_overflow);
    assert!(!state.has_negotiated_record_size_limits());
}

#[test]
fn negotiated_peer_limit_caps_outbound_content_and_tls13_type_byte() {
    let mut state = Dtls::new(Side::Client, Settings::default());
    state.set_record_size_limits(100, 64, true).unwrap();
    assert_eq!(state.outbound_content_limit(2), 63);
    assert!(state.record_room(0, super::DEFAULT_MTU).unwrap() > 63);

    state.set_record_size_limits(100, 64, false).unwrap();
    assert_eq!(state.outbound_content_limit(1), 64);
}

#[cfg(feature = "native")]
#[test]
fn authenticated_dtls13_overflow_fails_before_replay_or_application_dispatch() {
    use crate::crypto::native::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use crate::crypto::tls13::OkmBlock;
    use crate::dtls::keys::RecordKeys;
    use crate::dtls::wire::{Header, parse_record};
    use crate::enums::ContentType;

    let secret = OkmBlock::new(&[0x42; 32]);
    let suite = TLS13_AES_128_GCM_SHA256.tls13().unwrap();
    let mut state = Dtls::new(Side::Server, Settings::default());
    state.set_read_secret(suite, &secret);
    state.set_read_secret(suite, &secret);
    state.set_record_size_limits(64, 100, true).unwrap();

    let mut record = Vec::new();
    RecordKeys::derive(suite, &secret)
        .unwrap()
        .seal(
            &mut record,
            RecordNumber { epoch: 3, seq: 0 },
            ContentType::ApplicationData,
            &[0x5a; 64],
            &[],
        )
        .unwrap();
    let parsed = parse_record(&record, 0).unwrap();
    let Header::Unified {
        epoch_bits, seq, ..
    } = parsed.header
    else {
        panic!("expected unified DTLS record");
    };
    assert_eq!(
        state.read_protected(&mut record, epoch_bits, seq, parsed.body, 0, false,),
        Err(crate::error::Error::PeerSentOversizedRecord)
    );
    assert_eq!(state.read[1].window.highest(), None);
    assert!(state.authenticated_record.is_none());
}

#[cfg(feature = "native")]
#[test]
fn observed_dtls13_overflow_becomes_fatal_only_when_offer_is_acknowledged() {
    use crate::crypto::native::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use crate::crypto::tls13::OkmBlock;
    use crate::dtls::keys::RecordKeys;
    use crate::dtls::wire::{Header, parse_record};
    use crate::enums::ContentType;

    let secret = OkmBlock::new(&[0x34; 32]);
    let suite = TLS13_AES_128_GCM_SHA256.tls13().unwrap();
    let mut state = Dtls::new(
        Side::Client,
        Settings::default()
            .with_record_size_limit(Some(64))
            .unwrap(),
    );
    state.set_read_secret(suite, &secret);
    state.set_read_secret(suite, &secret);
    state.start_record_size_limit_observation();

    let mut record = Vec::new();
    RecordKeys::derive(suite, &secret)
        .unwrap()
        .seal(
            &mut record,
            RecordNumber { epoch: 3, seq: 0 },
            ContentType::ApplicationData,
            &[0x5a; 64],
            &[],
        )
        .unwrap();
    let parsed = parse_record(&record, 0).unwrap();
    let Header::Unified {
        epoch_bits, seq, ..
    } = parsed.header
    else {
        panic!("expected unified DTLS record");
    };
    assert!(matches!(
        state.read_protected(&mut record, epoch_bits, seq, parsed.body, 0, false),
        Ok(super::Incoming::ApplicationData(_))
    ));
    assert!(state.observed_record_size_limit_overflow);
    assert_eq!(
        state.set_record_size_limits(64, 100, true),
        Err(crate::error::Error::PeerSentOversizedRecord)
    );
}

#[cfg(feature = "native")]
#[test]
fn oversized_ciphertext_is_discarded_before_authentication() {
    use crate::crypto::native::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use crate::crypto::tls13::OkmBlock;
    use crate::dtls::wire::put_unified_header;

    let mut state = Dtls::new(Side::Client, Settings::default());
    state.set_read_secret(
        TLS13_AES_128_GCM_SHA256.tls13().unwrap(),
        &OkmBlock::new(&[0x42; 32]),
    );
    let read = &state.read[0];
    let len = read.keys.max_ciphertext_len() + 1;
    let mut datagram = Vec::new();
    put_unified_header(&mut datagram, read.epoch, 0, &[], len as u16);
    datagram.resize(datagram.len() + len, 0);

    let mut at = 0;
    assert_eq!(
        state.read_record(&mut datagram, &mut at, true).unwrap(),
        super::Incoming::Handled,
    );
    assert_eq!(at, datagram.len());
    assert_eq!(state.read[0].failures, 0);
    assert!(state.read[0].window.highest().is_none());
    assert!(!state.peer_authenticated);
}
