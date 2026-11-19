//! Tests of the hello message codecs.

use super::*;

fn sample_client_hello() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([1u8; 32]),
        session_id: SessionId::from_slice(&[2u8; 32]).unwrap(),
        cipher_suites: alloc::vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        ],
        compression_methods: alloc::vec![Compression::Null],
        extensions: ClientExtensions {
            server_name: Some(ServerNamePayload::SingleDnsName(
                browntls_pki::DnsName::try_from("example.com")
                    .unwrap()
                    .to_owned(),
            )),
            named_groups: Some(alloc::vec![NamedGroup::X25519]),
            signature_schemes: Some(alloc::vec![SignatureScheme::ED25519]),
            protocols: Some(alloc::vec![ProtocolName::from(b"h2".to_vec())]),
            supported_versions: Some(alloc::vec![ProtocolVersion::TLSv1_3]),
            key_shares: Some(alloc::vec![KeyShareEntry::new(
                NamedGroup::X25519,
                &[9; 32]
            )]),
            psk_modes: Some(alloc::vec![PskKeyExchangeMode::PSK_DHE_KE]),
            preshared_key: Some(PresharedKeyOffer::new(
                super::super::PresharedKeyIdentity::new(alloc::vec![1, 2, 3], 7),
                alloc::vec![0xab; 32],
            )),
            ..Default::default()
        },
    }
}

#[test]
fn client_hello_roundtrip() {
    let ch = sample_client_hello();
    let msg = HandshakeMessagePayload(HandshakePayload::ClientHello(ch.clone()));
    let enc = msg.get_encoding();
    assert_eq!(enc[0], 1);
    let back =
        HandshakeMessagePayload::read_version(&mut Reader::init(&enc), ProtocolVersion::TLSv1_3)
            .unwrap();
    match back.0 {
        HandshakePayload::ClientHello(parsed) => assert_eq!(parsed, ch),
        other => panic!("wrong payload {other:?}"),
    }
    // binder truncation removes exactly the binders list
    let truncated = msg.encoding_for_binder_signing();
    assert_eq!(truncated.len(), enc.len() - (2 + 33));
    assert_eq!(&enc[..truncated.len()], &truncated[..]);
}

#[test]
fn client_hello_with_later_rfc_extensions() {
    let mut ch = sample_client_hello();
    ch.extensions.record_size_limit = Some(16_385);
    ch.extensions.ticket_request = Some(ClientTicketRequest {
        new_session_count: 2,
        resumption_count: 1,
    });
    ch.extensions.grease_first = Some(0x1a1a);
    ch.extensions.grease_last = Some(0x2a2a);
    ch.extensions.padding = Some(7);
    let enc = ch.get_encoding();
    let back = ClientHelloPayload::read_bytes(&enc).unwrap();
    assert_eq!(back.extensions.record_size_limit, Some(16_385));
    assert_eq!(back.extensions.ticket_request, ch.extensions.ticket_request);
    assert_eq!(back.extensions.padding, Some(7));
    // GREASE extensions read back as unknown ones, in order.
    assert_eq!(
        back.extensions.unknown,
        [
            ExtensionType::Unknown(0x1a1a),
            ExtensionType::Unknown(0x2a2a)
        ]
    );
    assert_eq!(back.extensions.preshared_key, ch.extensions.preshared_key);
    // Neither GREASE nor padding counts as offered.
    let offered = ch.extensions.present_types();
    assert!(offered.contains(&ExtensionType::RecordSizeLimit));
    assert!(offered.contains(&ExtensionType::TicketRequest));
    assert!(!offered.contains(&ExtensionType::Padding));
    assert!(
        !offered
            .iter()
            .any(|t| matches!(t, ExtensionType::Unknown(_)))
    );
    // The padding body is zeros, followed only by pre_shared_key.
    let psk_len = 4 + ch
        .extensions
        .preshared_key
        .as_ref()
        .unwrap()
        .get_encoding()
        .len();
    let padding = &enc[enc.len() - psk_len - 11..enc.len() - psk_len];
    assert_eq!(padding, [0, 0x15, 0, 7, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn psk_must_be_last() {
    let mut ch = sample_client_hello();
    // Encode manually with PSK first by swapping extension order:
    let mut bytes = Vec::new();
    ch.client_version.encode(&mut bytes);
    ch.random.encode(&mut bytes);
    ch.session_id.encode(&mut bytes);
    encode_vec_u16(&mut bytes, &ch.cipher_suites);
    encode_vec_u8(&mut bytes, &ch.compression_methods);
    let psk = ch.extensions.preshared_key.take().unwrap();
    let mut exts = Vec::new();
    {
        let list = LengthPrefixedBuffer::new(ListLength::U16, &mut exts);
        encode_extension(ExtensionType::PreSharedKey, list.buf, |b| psk.encode(b));
        encode_extension(ExtensionType::SupportedVersions, list.buf, |b| {
            encode_vec_u8(b, &[ProtocolVersion::TLSv1_3]);
        });
    }
    bytes.extend(exts);
    assert_eq!(
        ClientHelloPayload::read_bytes(&bytes),
        Err(InvalidMessage::PreSharedKeyIsNotFinalExtension)
    );
}

#[test]
fn client_hello_rejects_empty_lists_and_duplicates() {
    let mut ch = sample_client_hello();
    ch.cipher_suites.clear();
    assert_eq!(
        ClientHelloPayload::read_bytes(&ch.get_encoding()),
        Err(InvalidMessage::IllegalEmptyList("CipherSuites"))
    );
    let ch = sample_client_hello();
    let mut enc = ch.get_encoding();
    // Build an extension block containing the same extension twice.
    let mut bytes = Vec::new();
    ch.client_version.encode(&mut bytes);
    ch.random.encode(&mut bytes);
    ch.session_id.encode(&mut bytes);
    encode_vec_u16(&mut bytes, &ch.cipher_suites);
    encode_vec_u8(&mut bytes, &ch.compression_methods);
    {
        let list = LengthPrefixedBuffer::new(ListLength::U16, &mut bytes);
        encode_extension(ExtensionType::EarlyData, list.buf, |_| {});
        encode_extension(ExtensionType::EarlyData, list.buf, |_| {});
    }
    assert_eq!(
        ClientHelloPayload::read_bytes(&bytes),
        Err(InvalidMessage::DuplicateExtension(0x2a))
    );
    enc.truncate(10);
    assert!(ClientHelloPayload::read_bytes(&enc).is_err());
}

#[test]
fn client_hello_without_extensions_block() {
    let ch = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: alloc::vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
        compression_methods: alloc::vec![Compression::Null],
        extensions: ClientExtensions::default(),
    };
    let mut enc = ch.get_encoding();
    // strip the (empty) extension block
    enc.truncate(enc.len() - 2);
    let back = ClientHelloPayload::read_bytes(&enc).unwrap();
    assert_eq!(back, ch);
    assert!(back.sni().is_none());
    assert!(!back.has_duplicate_key_share());
}

#[test]
fn server_hello_and_hrr() {
    let sh = ServerHelloPayload {
        legacy_version: ProtocolVersion::TLSv1_2,
        random: Random::from([5u8; 32]),
        session_id: SessionId::empty(),
        cipher_suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        compression_method: Compression::Null,
        extensions: ServerExtensions {
            supported_versions: Some(ProtocolVersion::TLSv1_3),
            key_share: Some(KeyShareEntry::new(NamedGroup::X25519, &[1; 32])),
            ..Default::default()
        },
    };
    let msg = HandshakeMessagePayload(HandshakePayload::ServerHello(sh.clone()));
    let enc = msg.get_encoding();
    match HandshakeMessagePayload::read_bytes(&enc).unwrap().0 {
        HandshakePayload::ServerHello(back) => assert_eq!(back, sh),
        other => panic!("{other:?}"),
    }
    assert!(!sh.has_downgrade_sentinel());

    let hrr = HelloRetryRequest {
        legacy_version: ProtocolVersion::TLSv1_2,
        session_id: SessionId::empty(),
        cipher_suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        compression_method: Compression::Null,
        extensions: HelloRetryRequestExtensions {
            key_share: Some(NamedGroup::secp256r1),
            supported_versions: Some(ProtocolVersion::TLSv1_3),
            cookie: Some(PayloadU16::new(alloc::vec![1, 2])),
            encrypted_client_hello: Some([7; 8]),
            unknown: Vec::new(),
        },
    };
    let msg = HandshakeMessagePayload(HandshakePayload::HelloRetryRequest(hrr.clone()));
    let enc = msg.get_encoding();
    assert_eq!(enc[0], u8::from(HandshakeType::ServerHello));
    match HandshakeMessagePayload::read_bytes(&enc).unwrap().0 {
        HandshakePayload::HelloRetryRequest(back) => assert_eq!(back, hrr),
        other => panic!("{other:?}"),
    }
}

#[test]
fn oversize_handshake_rejected() {
    let bytes = [1, 0x01, 0, 0];
    assert_eq!(
        HandshakeMessagePayload::read_bytes(&bytes).unwrap_err(),
        InvalidMessage::HandshakePayloadTooLarge
    );
    let bytes = [1, 0, 0, 5, 0];
    assert_eq!(
        HandshakeMessagePayload::read_bytes(&bytes).unwrap_err(),
        InvalidMessage::MessageTooShort
    );
}

#[test]
fn message_hash_cannot_come_from_wire() {
    let bytes = [0xfe, 0, 0, 1, 0];
    assert_eq!(
        HandshakeMessagePayload::read_bytes(&bytes).unwrap_err(),
        InvalidMessage::UnexpectedMessage("MessageHash")
    );
}

#[test]
fn unknown_handshake_type_is_opaque() {
    let bytes = [0x7f, 0, 0, 2, 1, 2];
    let msg = HandshakeMessagePayload::read_bytes(&bytes).unwrap();
    assert_eq!(msg.typ(), HandshakeType::Unknown(0x7f));
    assert_eq!(msg.get_encoding(), bytes);
}
