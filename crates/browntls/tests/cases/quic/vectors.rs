// RFC 9001 appendix A test vectors, header protection, AEAD limits and
// crypto error codes.
//
// Included by `cases/quic.rs`, which holds the imports and the handshake
// plumbing.

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn quic_suite(suite: &browntls::SupportedCipherSuite) -> bq::Suite {
    suite
        .tls13()
        .and_then(|s| s.quic_suite())
        .expect("QUIC-capable suite")
}

/// RFC 9001 Appendix A.1: the client's Destination Connection ID.
const DCID: &str = "8394c8f03e515708";

/// RFC 9001 Appendix A.2: the CRYPTO frame of the client's Initial packet.
const CLIENT_CRYPTO_FRAME: &[&str] = &[
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba",
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100",
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000",
    "75300901100f088394c8f03e51570806048000ffff",
];

/// RFC 9001 Appendix A.2: the protected client Initial packet.
const CLIENT_INITIAL_PACKET: &[&str] = &[
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
    "e221af44860018ab0856972e194cd934",
];

/// RFC 9001 Appendix A.3: the server Initial payload (ACK and CRYPTO frames).
const SERVER_PAYLOAD: &str = "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739\
    88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94\
    0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00\
    020304";

/// RFC 9001 Appendix A.3: the protected server Initial packet.
const SERVER_INITIAL_PACKET: &str = "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a\
    5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3\
    dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84\
    022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4\
    2158407dd074ee";

/// Protects a long-header packet whose unprotected header is `header`
/// (ending with a `pn_len`-byte packet number `pn`), as RFC 9001 §5.3 and
/// §5.4 describe.
fn protect(
    keys: &bq::DirectionalKeys,
    header: &[u8],
    pn: u64,
    pn_len: usize,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = payload.to_vec();
    let tag = keys.packet.encrypt_in_place(pn, header, &mut body).unwrap();
    body.extend_from_slice(tag.as_ref());
    let mut packet = header.to_vec();
    packet.extend_from_slice(&body);
    // The sample starts four bytes after the start of the packet number.
    let pn_offset = header.len() - pn_len;
    let sample = packet[pn_offset + 4..pn_offset + 4 + bq::SAMPLE_LEN].to_vec();
    let (first, rest) = packet.split_at_mut(1);
    keys.header
        .encrypt_in_place(
            &sample,
            &mut first[0],
            &mut rest[pn_offset - 1..pn_offset - 1 + pn_len],
        )
        .unwrap();
    packet
}

/// Removes protection from `packet`, whose packet number starts at
/// `pn_offset`, given the expected full packet number; returns the header
/// and the payload.
fn unprotect(
    keys: &bq::DirectionalKeys,
    packet: &[u8],
    pn_offset: usize,
    pn: u64,
) -> (Vec<u8>, Vec<u8>) {
    let mut packet = packet.to_vec();
    let sample = packet[pn_offset + 4..pn_offset + 4 + bq::SAMPLE_LEN].to_vec();
    {
        let (first, rest) = packet.split_at_mut(1);
        keys.header
            .decrypt_in_place(
                &sample,
                &mut first[0],
                &mut rest[pn_offset - 1..pn_offset + 3],
            )
            .unwrap();
    }
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    let (header, body) = packet.split_at_mut(pn_offset + pn_len);
    let plain = keys
        .packet
        .decrypt_in_place(pn, header, body)
        .unwrap()
        .to_vec();
    (header.to_vec(), plain)
}

#[test]
fn rfc9001_client_initial() {
    let suite = quic_suite(&prov::cipher_suite::TLS13_AES_128_GCM_SHA256);
    let client = suite.keys(&hex(DCID), bq::Side::Client, bq::Version::V1);
    let server = suite.keys(&hex(DCID), bq::Side::Server, bq::Version::V1);

    let header = hex("c300000001088394c8f03e5157080000449e00000002");
    let mut payload = hex(&CLIENT_CRYPTO_FRAME.concat());
    payload.resize(1162, 0); // PADDING frames
    let packet = protect(&client.local, &header, 2, 4, &payload);
    assert_eq!(packet, hex(&CLIENT_INITIAL_PACKET.concat()));

    // A.2's intermediate header protection values.
    let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");
    assert_eq!(
        client.local.header.mask(&sample).unwrap()[..],
        hex("437b9aec36")[..]
    );

    let (got_header, got_payload) = unprotect(&server.remote, &packet, header.len() - 4, 2);
    assert_eq!(got_header, header);
    assert_eq!(got_payload, payload);
}

#[test]
fn rfc9001_server_initial() {
    let suite = quic_suite(&prov::cipher_suite::TLS13_AES_128_GCM_SHA256);
    let client = suite.keys(&hex(DCID), bq::Side::Client, bq::Version::V1);
    let server = suite.keys(&hex(DCID), bq::Side::Server, bq::Version::V1);

    let header = hex("c1000000010008f067a5502a4262b50040750001");
    let payload = hex(SERVER_PAYLOAD);
    let packet = protect(&server.local, &header, 1, 2, &payload);
    assert_eq!(packet, hex(SERVER_INITIAL_PACKET));
    let sample = hex("2cd0991cd25b0aac406a5816b6394100");
    assert_eq!(
        server.local.header.mask(&sample).unwrap()[..],
        hex("2ec0d8356a")[..]
    );

    let (got_header, got_payload) = unprotect(&client.remote, &packet, header.len() - 2, 1);
    assert_eq!(got_header, header);
    assert_eq!(got_payload, payload);

    // A corrupted packet does not authenticate.
    let mut bad = packet.clone();
    *bad.last_mut().unwrap() ^= 1;
    let pn_offset = header.len() - 2;
    let mut body = bad[pn_offset + 2..].to_vec();
    assert_eq!(
        client
            .remote
            .packet
            .decrypt_in_place(1, &header, &mut body)
            .unwrap_err(),
        Error::DecryptError
    );
}

#[test]
fn rfc9001_retry_integrity_tag() {
    let quic = &quic_suite(&prov::cipher_suite::TLS13_AES_128_GCM_SHA256);
    let retry = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    let (body, tag) = retry.split_at(retry.len() - 16);
    let computed = bq::retry_integrity_tag(bq::Version::V1, quic, &hex(DCID), body).unwrap();
    assert_eq!(computed.as_ref(), tag);
    assert!(bq::verify_retry_integrity(
        bq::Version::V1,
        quic,
        &hex(DCID),
        &retry
    ));

    let mut tampered = retry.clone();
    tampered[10] ^= 1;
    assert!(!bq::verify_retry_integrity(
        bq::Version::V1,
        quic,
        &hex(DCID),
        &tampered
    ));
    assert!(!bq::verify_retry_integrity(
        bq::Version::V1,
        quic,
        &hex("00"),
        &retry
    ));
    assert!(bq::retry_integrity_tag(bq::Version::V1, quic, &[0; 21], body).is_err());
    // Only TLS_AES_128_GCM_SHA256's AEAD makes the tag.
    let aes256 = &quic_suite(&prov::cipher_suite::TLS13_AES_256_GCM_SHA384);
    assert!(bq::retry_integrity_tag(bq::Version::V1, aes256, &hex(DCID), body).is_err());
    assert!(!bq::verify_retry_integrity(
        bq::Version::V1,
        aes256,
        &hex(DCID),
        &retry
    ));
}

/// RFC 9001 Appendix A.5: a short header packet under ChaCha20-Poly1305,
/// and the "quic ku" key update secret.
#[test]
fn rfc9001_chacha20_short_header() {
    let suite = quic_suite(&prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256);
    let secret = browntls::crypto::tls13::OkmBlock::new(&hex(
        "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
    ));
    let keys = bq::DirectionalKeys::new(suite.suite, suite.quic, &secret, bq::Version::V1);

    let pn = 654_360_564;
    let header = hex("4200bff4");
    let mut payload = hex("01");
    let tag = keys
        .packet
        .encrypt_in_place(pn, &header, &mut payload)
        .unwrap();
    payload.extend_from_slice(tag.as_ref());
    assert_eq!(payload, hex("655e5cd55c41f69080575d7999c25a5bfb"));

    // One byte skipped: the sample starts 4 bytes after the 1-byte-offset
    // packet number.
    let sample = &payload[1..17];
    assert_eq!(sample, &hex("5e5cd55c41f69080575d7999c25a5bfb")[..]);
    assert_eq!(keys.header.mask(sample).unwrap()[..], hex("aefefe7d03")[..]);
    let mut first = header[0];
    let mut pn_bytes = header[1..].to_vec();
    keys.header
        .encrypt_in_place(sample, &mut first, &mut pn_bytes)
        .unwrap();
    let mut packet = vec![first];
    packet.extend_from_slice(&pn_bytes);
    packet.extend_from_slice(&payload);
    assert_eq!(packet, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

    // Removing protection reads the packet number length from the
    // unmasked first byte; the fourth byte (here the payload's) is left as
    // it is.
    let mut first = packet[0];
    let mut window = packet[1..5].to_vec();
    keys.header
        .decrypt_in_place(sample, &mut first, &mut window)
        .unwrap();
    assert_eq!(first, 0x42);
    assert_eq!(window, [0x00, 0xbf, 0xf4, packet[4]]);

    // The packet keys after a key update come from the "quic ku" secret.
    let ku = browntls::crypto::tls13::OkmBlock::new(&hex(
        "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
    ));
    let updated = bq::DirectionalKeys::new(suite.suite, suite.quic, &ku, bq::Version::V1);
    let mut secrets = bq::Secrets::new(
        secret.clone(),
        secret,
        suite.suite,
        suite.quic,
        bq::Side::Server,
        bq::Version::V1,
    );
    let phase0 = secrets.next_packet_keys();
    let phase1 = secrets.next_packet_keys();
    assert_eq!(
        seal(&*phase0.local, 7, b"hdr", b"x"),
        seal(&*keys.packet, 7, b"hdr", b"x")
    );
    assert_eq!(
        seal(&*phase1.local, 7, b"hdr", b"x"),
        seal(&*updated.packet, 7, b"hdr", b"x")
    );
    assert_ne!(
        seal(&*phase0.local, 7, b"hdr", b"x"),
        seal(&*phase1.local, 7, b"hdr", b"x")
    );
}

fn seal(key: &dyn bq::PacketKey, pn: u64, header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = payload.to_vec();
    let tag = key.encrypt_in_place(pn, header, &mut body).unwrap();
    body.extend_from_slice(tag.as_ref());
    body
}

#[test]
fn header_protection_rejects_bad_sample_and_short_packet_number() {
    let suite = quic_suite(&prov::cipher_suite::TLS13_AES_128_GCM_SHA256);
    let keys = suite.keys(&hex(DCID), bq::Side::Client, bq::Version::V1);
    let mut first = 0xc3;
    let mut pn = [0u8; 4];
    assert!(
        keys.local
            .header
            .encrypt_in_place(&[0; 15], &mut first, &mut pn)
            .is_err()
    );
    // The first byte announces a 4-byte packet number; 2 bytes are given.
    assert!(
        keys.local
            .header
            .encrypt_in_place(&[0; 16], &mut first, &mut pn[..2])
            .is_err()
    );
    assert_eq!(first, 0xc3);
    assert_eq!(keys.local.header.sample_len(), 16);
}

#[test]
fn aead_limits_and_suites() {
    let gcm = quic_suite(&prov::cipher_suite::TLS13_AES_128_GCM_SHA256);
    let keys = gcm.keys(&hex(DCID), bq::Side::Client, bq::Version::V1);
    assert_eq!(keys.local.packet.confidentiality_limit(), 1 << 23);
    assert_eq!(keys.local.packet.integrity_limit(), 1 << 52);
    assert_eq!(keys.local.packet.tag_len(), 16);

    let chacha = quic_suite(&prov::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256);
    let secret = browntls::crypto::tls13::OkmBlock::new(&[7; 32]);
    let keys = bq::DirectionalKeys::new(chacha.suite, chacha.quic, &secret, bq::Version::V1);
    assert_eq!(keys.packet.integrity_limit(), 1 << 36);

    assert!(prov::cipher_suite::TLS13_AES_256_GCM_SHA384.usable_for_quic());
}

#[test]
fn crypto_error_codes() {
    assert_eq!(
        bq::crypto_error_code(AlertDescription::HandshakeFailure),
        0x0128
    );
    assert_eq!(
        bq::crypto_error_code(AlertDescription::NoApplicationProtocol),
        0x0178
    );
    assert_eq!(
        bq::alert_from_crypto_error(0x016d),
        Some(AlertDescription::MissingExtension)
    );
    assert_eq!(bq::alert_from_crypto_error(0x0a), None);
    assert_eq!(bq::alert_from_crypto_error(0x0200), None);
}
