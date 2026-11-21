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
