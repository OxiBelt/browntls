//! Key operations of the `tls_quic` target: Initial keys, keys and secrets
//! from fuzzed traffic secrets with key updates, the Retry Integrity Tag and
//! CRYPTO_ERROR codes.

use browntls::crypto::cipher::{Iv, NONCE_LEN};
use browntls::crypto::tls13::OkmBlock;
use browntls::quic::{self, Keys, Secrets, Side, Version};
use browntls::{AlertDescription, CipherSuite};

use super::{check_keys, check_packet_keys, other, packet, provider, suite};
use crate::input::Input;

pub(super) fn initial(input: &mut Input) {
    let provider = provider(input);
    let (_, quic) = suite(input, &provider);
    let Some(quic) = quic else { return };
    let side = if input.bool() {
        Side::Client
    } else {
        Side::Server
    };
    let dcid = input.short_field();
    let packet = packet(input);

    let ours = quic.keys(dcid, side, Version::V1);
    let theirs = Keys::initial(Version::V1, quic.suite, quic.quic, dcid, other(side));
    check_keys(&ours.local, &theirs.remote, &packet, input);
    check_keys(&theirs.local, &ours.remote, &packet, input);

    // The two directions, and another connection ID, differ.
    let mut sealed = packet.payload.clone();
    let tag = ours
        .local
        .packet
        .encrypt_in_place(packet.packet_number, &packet.header, &mut sealed)
        .unwrap();
    sealed.extend_from_slice(tag.as_ref());
    let mut copy = sealed.clone();
    assert!(
        ours.remote
            .packet
            .decrypt_in_place(packet.packet_number, &packet.header, &mut copy)
            .is_err()
    );
    let mut dcid2 = dcid.to_vec();
    dcid2.push(input.byte());
    let elsewhere = quic.keys(&dcid2, other(side), Version::V1);
    assert!(
        elsewhere
            .remote
            .packet
            .decrypt_in_place(packet.packet_number, &packet.header, &mut sealed)
            .is_err()
    );

    // nonce_for: the IV XORed with the packet number, right-aligned.
    let iv_bytes = input.array::<NONCE_LEN>();
    let iv = Iv::new(iv_bytes);
    let pn = input.u64();
    let nonce = quic::nonce_for(&iv, pn);
    let mut expected = iv_bytes;
    for (byte, p) in expected[NONCE_LEN - 8..].iter_mut().zip(pn.to_be_bytes()) {
        *byte ^= p;
    }
    assert_eq!(nonce, expected);
}

pub(super) fn secrets(input: &mut Input) {
    let provider = provider(input);
    let (_, quic) = suite(input, &provider);
    let Some(quic) = quic else { return };
    let client = OkmBlock::new(input.short_field());
    let server = OkmBlock::new(input.short_field());
    let updates = 1 + input.choose(4);
    let packet = packet(input);

    // Both sides derive the same directional keys from one secret.
    let a = quic::DirectionalKeys::new(quic.suite, quic.quic, &client, Version::V1);
    let b = quic::DirectionalKeys::new(quic.suite, quic.quic, &client, Version::V1);
    check_keys(&a, &b, &packet, input);

    let mut at_client = Secrets::new(
        client.clone(),
        server.clone(),
        quic.suite,
        quic.quic,
        Side::Client,
        Version::V1,
    );
    let mut at_server = Secrets::new(
        client,
        server,
        quic.suite,
        quic.quic,
        Side::Server,
        Version::V1,
    );
    let mut previous: Option<Box<dyn quic::PacketKey>> = None;
    for _ in 0..updates {
        let c = at_client.next_packet_keys();
        let s = at_server.next_packet_keys();
        check_packet_keys(&*c.local, &*s.remote, &packet, input);
        check_packet_keys(&*s.local, &*c.remote, &packet, input);
        // A key update changes the keys.
        if let Some(old) = &previous {
            let mut sealed = packet.payload.clone();
            let tag = c
                .local
                .encrypt_in_place(packet.packet_number, &packet.header, &mut sealed)
                .unwrap();
            sealed.extend_from_slice(tag.as_ref());
            assert!(
                old.decrypt_in_place(packet.packet_number, &packet.header, &mut sealed)
                    .is_err()
            );
        }
        previous = Some(s.remote);
    }
}

pub(super) fn retry(input: &mut Input) {
    let provider = provider(input);
    let (_, quic) = suite(input, &provider);
    let Some(quic) = quic else { return };
    let odcid = input.short_field();
    let body = input.field();
    let tamper = input.byte();

    let aes_128_gcm = quic.suite.common.suite == CipherSuite::TLS13_AES_128_GCM_SHA256;
    let tag = quic::retry_integrity_tag(Version::V1, &quic, odcid, body);
    if !aes_128_gcm || odcid.len() > 20 {
        assert!(tag.is_err());
        let mut packet = body.to_vec();
        packet.extend_from_slice(&[0; quic::SAMPLE_LEN]);
        assert!(!quic::verify_retry_integrity(
            Version::V1,
            &quic,
            odcid,
            &packet
        ));
        return;
    }
    let tag = tag.unwrap();
    let mut packet = body.to_vec();
    packet.extend_from_slice(tag.as_ref());
    assert!(quic::verify_retry_integrity(
        Version::V1,
        &quic,
        odcid,
        &packet
    ));

    // Any changed byte, another connection ID or a truncated packet fails.
    let mut damaged = packet.clone();
    let at = usize::from(tamper) % damaged.len();
    damaged[at] ^= 0x01;
    assert!(!quic::verify_retry_integrity(
        Version::V1,
        &quic,
        odcid,
        &damaged
    ));
    let mut odcid2 = odcid.to_vec();
    if odcid2.is_empty() {
        odcid2.push(tamper);
    } else {
        odcid2.pop();
    }
    assert!(!quic::verify_retry_integrity(
        Version::V1,
        &quic,
        &odcid2,
        &packet
    ));
    assert!(!quic::verify_retry_integrity(
        Version::V1,
        &quic,
        odcid,
        &packet[..packet.len().min(quic::SAMPLE_LEN - 1)]
    ));
}

pub(super) fn codes(input: &mut Input) {
    let code = input.u64();
    match quic::alert_from_crypto_error(code) {
        Some(alert) => {
            assert!((0x0100..=0x01ff).contains(&code));
            assert_eq!(quic::crypto_error_code(alert), code);
        }
        None => assert!(!(0x0100..=0x01ff).contains(&code)),
    }
    let alert = AlertDescription::from(input.byte());
    let code = quic::crypto_error_code(alert);
    assert_eq!(quic::alert_from_crypto_error(code), Some(alert));
}
