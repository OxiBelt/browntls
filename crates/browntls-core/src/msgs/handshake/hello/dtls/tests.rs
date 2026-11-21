//! Tests of the DTLS 1.3 hello encodings.

use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::enums::CipherSuite;
use crate::msgs::base::{PayloadU8, PayloadU16};
use crate::msgs::enums::{Compression, ExtensionType, NamedGroup, PskKeyExchangeMode};
use crate::msgs::handshake::{
    ClientExtensions, HelloRetryRequest, HelloRetryRequestExtensions, KeyShareEntry,
    PresharedKeyIdentity, PresharedKeyOffer, Random, ServerExtensions, SessionId,
};
use crate::msgs::message::MessagePayload;

fn dtls_client_hello() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([1u8; 32]),
        session_id: SessionId::empty(),
        legacy_cookie: Some(PayloadU8::empty()),
        cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
        compression_methods: vec![Compression::Null],
        extensions: ClientExtensions {
            named_groups: Some(vec![NamedGroup::X25519]),
            supported_versions: Some(vec![
                ProtocolVersion::Unknown(0x1a1a),
                ProtocolVersion::TLSv1_3,
            ]),
            key_shares: Some(vec![KeyShareEntry::new(NamedGroup::X25519, &[9; 32])]),
            psk_modes: Some(vec![PskKeyExchangeMode::PSK_DHE_KE]),
            cookie: Some(PayloadU16::new(vec![7; 5])),
            grease_first: Some(0x0a0a),
            preshared_key: Some(PresharedKeyOffer::new(
                PresharedKeyIdentity::new(vec![1, 2, 3], 7),
                vec![0xab; 32],
            )),
            ..Default::default()
        },
    }
}

/// `ch` as it reads back: GREASE extensions are kept as unknown ones, and
/// are not encoded again.
fn as_read(mut ch: ClientHelloPayload) -> ClientHelloPayload {
    if let Some(grease) = ch.extensions.grease_first.take() {
        ch.extensions.unknown.push(ExtensionType::Unknown(grease));
    }
    ch
}

/// The extension types of an encoded extension block, in order.
fn extension_types(mut block: &[u8]) -> Vec<u16> {
    let mut types = Vec::new();
    block = &block[2..];
    while block.len() >= 4 {
        types.push(u16::from_be_bytes([block[0], block[1]]));
        let len = usize::from(u16::from_be_bytes([block[2], block[3]]));
        block = &block[4 + len..];
    }
    types
}

#[test]
fn version_mapping_is_an_involution() {
    for (tls, dtls) in [(0x0304, 0xfefc), (0x0303, 0xfefd), (0x0302, 0xfeff)] {
        let tls = ProtocolVersion::from(tls);
        let dtls = ProtocolVersion::from(dtls);
        assert_eq!(swap_version(tls), dtls);
        assert_eq!(swap_version(dtls), tls);
    }
    for v in [0u16, 0x0300, 0x0301, 0x0a0a, 0x7f1c, 0xfefe, 0xffff] {
        assert_eq!(
            swap_version(ProtocolVersion::from(v)),
            ProtocolVersion::from(v)
        );
    }
    for v in 0..=u16::MAX {
        let v = ProtocolVersion::from(v);
        assert_eq!(swap_version(swap_version(v)), v);
    }
}

#[test]
fn client_hello_round_trip() {
    let ch = dtls_client_hello();
    let msg = HandshakeMessagePayload(HandshakePayload::ClientHello(ch.clone()));
    let enc = msg.get_encoding();
    assert_eq!(enc[0], 1);
    // legacy_version 0xfefd, then random, an empty session ID and an empty
    // legacy_cookie.
    assert_eq!(enc[4..6], [0xfe, 0xfd]);
    assert_eq!(enc[38..40], [0, 0]);
    // The cookie extension comes first, GREASE after it.
    let extensions = &enc[40 + 2 + 2 + 2..];
    let types = extension_types(extensions);
    assert_eq!(types[..2], [u16::from(ExtensionType::Cookie), 0x0a0a]);
    assert_eq!(types.last(), Some(&u16::from(ExtensionType::PreSharedKey)));
    // supported_versions: the GREASE value as is, then DTLS 1.3.
    let versions = [4, 0x1a, 0x1a, 0xfe, 0xfc];
    assert!(enc.windows(versions.len()).any(|w| w == versions));

    let back =
        HandshakeMessagePayload::read_dtls(&mut Reader::init(&enc), ProtocolVersion::TLSv1_2)
            .unwrap();
    match &back.0 {
        HandshakePayload::ClientHello(parsed) => assert_eq!(*parsed, as_read(ch.clone())),
        other => panic!("wrong payload {other:?}"),
    }
    let mut no_grease = ch;
    no_grease.extensions.grease_first = None;
    assert_eq!(
        back.get_encoding(),
        HandshakeMessagePayload(HandshakePayload::ClientHello(no_grease)).get_encoding()
    );

    // The transcript takes the DTLS encoding, and so do the binders.
    match MessagePayload::handshake(msg) {
        MessagePayload::Handshake { parsed, encoded } => {
            assert_eq!(encoded.bytes(), enc);
            let truncated = parsed.encoding_for_binder_signing();
            assert_eq!(truncated.len(), enc.len() - (2 + 33));
            assert_eq!(truncated, enc[..truncated.len()]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn client_hello_legacy_cookie_is_read() {
    let mut ch = dtls_client_hello();
    ch.legacy_cookie = Some(PayloadU8::new(vec![5, 6, 7]));
    let enc = HandshakeMessagePayload(HandshakePayload::ClientHello(ch.clone())).get_encoding();
    assert_eq!(enc[38..43], [0, 3, 5, 6, 7]);
    match HandshakeMessagePayload::read_dtls(&mut Reader::init(&enc), ProtocolVersion::TLSv1_2)
        .unwrap()
        .0
    {
        HandshakePayload::ClientHello(parsed) => {
            assert_eq!(parsed.legacy_cookie, Some(PayloadU8::new(vec![5, 6, 7])));
            assert_eq!(parsed, as_read(ch));
        }
        other => panic!("wrong payload {other:?}"),
    }
    // Cut inside the legacy_cookie.
    let mut short = enc[..41].to_vec();
    short[3] = 37;
    assert!(
        HandshakeMessagePayload::read_dtls(&mut Reader::init(&short), ProtocolVersion::TLSv1_2)
            .is_err()
    );
}

#[test]
fn tls_client_hello_encoding_is_unchanged() {
    let mut ch = dtls_client_hello();
    ch.legacy_cookie = None;
    let enc = ch.get_encoding();
    assert_eq!(enc[..2], [0x03, 0x03]);
    let types = extension_types(&enc[2 + 32 + 1 + 4 + 2..]);
    assert_eq!(types[0], 0x0a0a);
    assert!(types[1..].contains(&u16::from(ExtensionType::Cookie)));
    assert_eq!(ClientHelloPayload::read_bytes(&enc).unwrap(), as_read(ch));
}

#[test]
fn server_hello_and_hello_retry_request_round_trip() {
    let sh = ServerHelloPayload {
        legacy_version: ProtocolVersion::TLSv1_2,
        random: Random::from([5u8; 32]),
        session_id: SessionId::empty(),
        cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        compression_method: Compression::Null,
        extensions: ServerExtensions {
            supported_versions: Some(ProtocolVersion::TLSv1_3),
            key_share: Some(KeyShareEntry::new(NamedGroup::X25519, &[1; 32])),
            ..Default::default()
        },
        dtls: true,
    };
    let enc = HandshakeMessagePayload(HandshakePayload::ServerHello(sh.clone())).get_encoding();
    assert_eq!(enc[4..6], [0xfe, 0xfd]);
    let versions = [0, 0x2b, 0, 2, 0xfe, 0xfc];
    assert!(enc.windows(versions.len()).any(|w| w == versions));
    let back =
        HandshakeMessagePayload::read_dtls(&mut Reader::init(&enc), ProtocolVersion::TLSv1_2)
            .unwrap();
    match &back.0 {
        HandshakePayload::ServerHello(parsed) => assert_eq!(*parsed, sh),
        other => panic!("{other:?}"),
    }
    assert_eq!(back.get_encoding(), enc);
    // Read as TLS, the versions are DTLS ones.
    match HandshakeMessagePayload::read_bytes(&enc).unwrap().0 {
        HandshakePayload::ServerHello(parsed) => {
            assert_eq!(parsed.legacy_version, ProtocolVersion::DTLSv1_2);
            assert_eq!(
                parsed.extensions.supported_versions,
                Some(ProtocolVersion::DTLSv1_3)
            );
        }
        other => panic!("{other:?}"),
    }

    for key_share in [Some(NamedGroup::secp256r1), None] {
        let hrr = HelloRetryRequest {
            legacy_version: ProtocolVersion::TLSv1_2,
            session_id: SessionId::empty(),
            cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            compression_method: Compression::Null,
            extensions: HelloRetryRequestExtensions {
                key_share,
                cookie: Some(PayloadU16::new(vec![1, 2])),
                supported_versions: Some(ProtocolVersion::TLSv1_3),
                ..Default::default()
            },
            dtls: true,
        };
        let enc = HandshakeMessagePayload(HandshakePayload::HelloRetryRequest(hrr.clone()))
            .get_encoding();
        assert_eq!(enc[4..6], [0xfe, 0xfd]);
        assert_eq!(enc[6..38], super::super::HELLO_RETRY_REQUEST_RANDOM.0);
        assert!(enc.windows(versions.len()).any(|w| w == versions));
        let back =
            HandshakeMessagePayload::read_dtls(&mut Reader::init(&enc), ProtocolVersion::TLSv1_2)
                .unwrap();
        match &back.0 {
            HandshakePayload::HelloRetryRequest(parsed) => assert_eq!(*parsed, hrr),
            other => panic!("{other:?}"),
        }
        assert_eq!(back.get_encoding(), enc);
    }
}

#[test]
fn dtls_less_messages_read_as_unknown() {
    for typ in [
        HandshakeType::EndOfEarlyData,
        HandshakeType::HelloVerifyRequest,
        HandshakeType::RequestConnectionId,
        HandshakeType::NewConnectionId,
    ] {
        for body in [&[][..], &[1, 2]] {
            let mut enc = vec![u8::from(typ), 0, 0, body.len() as u8];
            enc.extend_from_slice(body);
            let msg = HandshakeMessagePayload::read_dtls(
                &mut Reader::init(&enc),
                ProtocolVersion::TLSv1_3,
            )
            .unwrap();
            assert!(matches!(msg.0, HandshakePayload::Unknown((t, _)) if t == typ));
        }
    }
    // TLS knows EndOfEarlyData.
    let enc = [u8::from(HandshakeType::EndOfEarlyData), 0, 0, 0];
    let msg =
        HandshakeMessagePayload::read_version(&mut Reader::init(&enc), ProtocolVersion::TLSv1_3)
            .unwrap();
    assert!(matches!(msg.0, HandshakePayload::EndOfEarlyData));
}

#[test]
fn connection_id_round_trips_in_dtls_client_hello_only() {
    for id in [vec![], vec![9; 8], vec![3; 255]] {
        let mut hello = dtls_client_hello();
        hello.extensions.connection_id = Some(PayloadU8::new(id.clone()));
        let encoding =
            HandshakeMessagePayload(HandshakePayload::ClientHello(hello.clone())).get_encoding();
        let parsed = HandshakeMessagePayload::read_dtls(
            &mut Reader::init(&encoding),
            ProtocolVersion::TLSv1_3,
        )
        .unwrap();
        let HandshakePayload::ClientHello(parsed) = parsed.0 else {
            panic!("ClientHello expected")
        };
        assert_eq!(parsed.extensions.connection_id, Some(PayloadU8::new(id)));
        assert!(
            parsed
                .extensions
                .present_types()
                .contains(&ExtensionType::ConnectionId)
        );
        hello.legacy_cookie = None;
        let encoding = HandshakeMessagePayload(HandshakePayload::ClientHello(hello)).get_encoding();
        let parsed = HandshakeMessagePayload::read_version(
            &mut Reader::init(&encoding),
            ProtocolVersion::TLSv1_3,
        )
        .unwrap();
        let HandshakePayload::ClientHello(parsed) = parsed.0 else {
            panic!("ClientHello expected")
        };
        assert!(parsed.extensions.connection_id.is_none());
    }
}

#[test]
fn other_messages_read_as_in_tls() {
    let enc = [u8::from(HandshakeType::Finished), 0, 0, 2, 1, 2];
    let msg = HandshakeMessagePayload::read_dtls(&mut Reader::init(&enc), ProtocolVersion::TLSv1_3)
        .unwrap();
    assert!(matches!(msg.0, HandshakePayload::Finished(_)));
    assert_eq!(msg.get_encoding(), enc);
    // Trailing data inside a hello, and an oversized length, are refused.
    let mut ch =
        HandshakeMessagePayload(HandshakePayload::ClientHello(dtls_client_hello())).get_encoding();
    ch.push(0);
    ch[3] += 1;
    assert!(
        HandshakeMessagePayload::read_dtls(&mut Reader::init(&ch), ProtocolVersion::TLSv1_2)
            .is_err()
    );
    assert_eq!(
        HandshakeMessagePayload::read_dtls(
            &mut Reader::init(&[1, 1, 0, 0]),
            ProtocolVersion::TLSv1_2
        )
        .unwrap_err(),
        InvalidMessage::HandshakePayloadTooLarge
    );
}
