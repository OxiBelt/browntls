//! Tests of the inner ClientHello encoding (RFC 9849 §5.1) and of the
//! server's checks on what it decrypts.

use alloc::vec;
use alloc::vec::Vec;

use super::client::encode_inner;
use super::codec::{EchClientHello, raw_extensions};
use super::server::decode_inner;
use crate::enums::{CipherSuite, ProtocolVersion, SignatureScheme};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::codec::{Codec, encode_vec_u8, encode_vec_u16};
use crate::msgs::enums::{Compression, NamedGroup, PskKeyExchangeMode};
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, KeyShareEntry,
    ProtocolName, Random, ServerNamePayload, SessionId,
};
use crate::msgs::message::MessagePayload;

#[cfg(feature = "native")]
mod pem_config;

fn name(n: &str) -> ServerNamePayload<'static> {
    ServerNamePayload::SingleDnsName(browntls_pki::DnsName::try_from(n).unwrap().to_owned())
}

fn inner_hello() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([3; 32]),
        session_id: SessionId::from_slice(&[9; 32]).unwrap(),
        legacy_cookie: None,
        cipher_suites: vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ],
        compression_methods: vec![Compression::Null],
        extensions: ClientExtensions {
            server_name: Some(name("secret.example")),
            named_groups: Some(vec![NamedGroup::X25519, NamedGroup::secp256r1]),
            signature_schemes: Some(vec![SignatureScheme::ED25519]),
            protocols: Some(vec![ProtocolName::from(b"h2".to_vec())]),
            supported_versions: Some(vec![ProtocolVersion::TLSv1_3]),
            key_shares: Some(vec![KeyShareEntry::new(NamedGroup::X25519, &[7; 32])]),
            psk_modes: Some(vec![PskKeyExchangeMode::PSK_DHE_KE]),
            encrypted_client_hello: Some(EchClientHello::Inner),
            ..Default::default()
        },
    }
}

fn outer_extensions(inner: &ClientHelloPayload) -> ClientExtensions {
    let mut outer = inner.extensions.clone();
    outer.server_name = Some(name("public.example"));
    outer.protocols = None;
    outer.encrypted_client_hello = None;
    outer
}

/// An outer ClientHello body with `exts` and the given session ID.
fn outer_body(exts: &ClientExtensions, session_id: SessionId) -> Vec<u8> {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([4; 32]),
        session_id,
        legacy_cookie: None,
        cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
        compression_methods: vec![Compression::Null],
        extensions: exts.clone(),
    }
    .get_encoding()
}

/// An EncodedClientHelloInner with the given extension block entries.
fn encoded_with(block: &[u8], padding: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ProtocolVersion::TLSv1_2.encode(&mut out);
    Random::from([3; 32]).encode(&mut out);
    SessionId::empty().encode(&mut out);
    encode_vec_u16(&mut out, &[CipherSuite::TLS13_AES_128_GCM_SHA256]);
    encode_vec_u8(&mut out, &[Compression::Null]);
    out.extend_from_slice(&(block.len() as u16).to_be_bytes());
    out.extend_from_slice(block);
    out.extend_from_slice(padding);
    out
}

fn ext(typ: u16, body: &[u8]) -> Vec<u8> {
    let mut out = typ.to_be_bytes().to_vec();
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn decode(outer: &[u8], encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let session_id = SessionId::from_slice(&[9; 32]).unwrap();
    decode_inner(ProtocolVersion::TLSv1_0, outer, &session_id, encoded)
        .map(|m| match m.payload {
            MessagePayload::Handshake { encoded, .. } => encoded.bytes().to_vec(),
            _ => Vec::new(),
        })
        .map_err(|fatal| fatal.1)
}

#[test]
fn inner_round_trips_through_compression() {
    let inner = inner_hello();
    let outer_exts = outer_extensions(&inner);
    for max_name_len in [0, 14, 64, 255] {
        let encoded = encode_inner(&inner, &outer_exts, max_name_len);
        assert_eq!(encoded.len() % 32, 0);
        // The session ID is dropped, and outer extensions were referenced.
        assert_eq!(encoded[34], 0);
        let ext_start = 35 + 2 + 4 + 1 + 1;
        let ext_len = usize::from(u16::from_be_bytes([
            encoded[ext_start],
            encoded[ext_start + 1],
        ]));
        let exts = raw_extensions(&encoded[ext_start..ext_start + 2 + ext_len]).unwrap();
        assert!(exts.iter().any(|e| e.typ == 0xfd00));
        assert!(exts.iter().any(|e| e.typ == 0xfe0d));

        let outer = outer_body(&outer_exts, SessionId::from_slice(&[9; 32]).unwrap());
        let decoded = decode(&outer, &encoded).unwrap();
        let expected =
            HandshakeMessagePayload(HandshakePayload::ClientHello(inner.clone())).get_encoding();
        assert_eq!(decoded, expected);
    }
}

#[test]
fn inner_without_compressible_extensions() {
    let inner = inner_hello();
    // An outer hello sharing nothing with the inner one.
    let outer_exts = ClientExtensions {
        server_name: Some(name("public.example")),
        ..Default::default()
    };
    let encoded = encode_inner(&inner, &outer_exts, 0);
    let outer = outer_body(&outer_exts, SessionId::from_slice(&[9; 32]).unwrap());
    let expected =
        HandshakeMessagePayload(HandshakePayload::ClientHello(inner.clone())).get_encoding();
    assert_eq!(decode(&outer, &encoded).unwrap(), expected);
}

#[test]
fn inner_decoding_errors() {
    let misbehaved = |e: PeerMisbehaved| Err(Error::PeerMisbehaved(e));
    let versions = ext(43, &[2, 3, 4]);
    let ech_inner = ext(0xfe0d, &[1]);
    let sigalgs = ext(13, &[0, 2, 8, 7]);
    let groups = ext(10, &[0, 2, 0, 29]);
    let outer_exts = [groups.clone(), sigalgs.clone(), ext(0xfe0d, &[0])].concat();
    let mut outer = outer_body(&ClientExtensions::default(), SessionId::empty());
    outer.truncate(outer.len() - 2);
    outer.extend_from_slice(&(outer_exts.len() as u16).to_be_bytes());
    outer.extend_from_slice(&outer_exts);

    // A good one: groups and sigalgs from the outer hello, in order.
    let good = [
        ext(0xfd00, &[4, 0, 10, 0, 13]),
        versions.clone(),
        ech_inner.clone(),
    ]
    .concat();
    assert!(decode(&outer, &encoded_with(&good, &[0; 7])).is_ok());

    // Non-zero padding.
    assert_eq!(
        decode(&outer, &encoded_with(&good, &[0, 0, 1])),
        misbehaved(PeerMisbehaved::IllegalEchPadding)
    );
    for refs in [
        &[2u8, 0xfe, 0x0d][..], // references ECH
        &[2, 0, 16],            // not in the outer hello
        &[4, 0, 13, 0, 10],     // out of order
        &[4, 0, 10, 0, 10],     // twice
        &[3, 0, 10, 0],         // odd length
        &[0],                   // empty
        &[5, 0, 10],            // length mismatch
    ] {
        let block = [ext(0xfd00, refs), versions.clone(), ech_inner.clone()].concat();
        assert_eq!(
            decode(&outer, &encoded_with(&block, &[])),
            misbehaved(PeerMisbehaved::IllegalEchOuterExtensions),
            "{refs:?}"
        );
    }
    // No `inner` ECH extension; TLS 1.2 offered; no supported_versions.
    for block in [
        [groups.clone(), versions.clone()].concat(),
        [ext(43, &[4, 3, 4, 3, 3]), ech_inner.clone()].concat(),
        [groups.clone(), ech_inner.clone()].concat(),
        [
            versions.clone(),
            ext(0xfe0d, &[0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0]),
        ]
        .concat(),
    ] {
        assert_eq!(
            decode(&outer, &encoded_with(&block, &[])),
            misbehaved(PeerMisbehaved::IllegalEchInnerClientHello)
        );
    }
    // Truncated.
    assert!(decode(&outer, &encoded_with(&good, &[])[..40]).is_err());
}

/// The server's optional checks (RFC 9849 §7.1): candidates by
/// configuration identifier or by trial decryption, and the outer server
/// name against the public name.
#[cfg(feature = "native")]
#[test]
fn candidate_selection_and_public_name_check() {
    use super::codec::EchOuter;
    use super::server::{Opened, open_first};
    use super::{EchConfig, EchServerConfig, EchServerKey, hpke_info};
    use crate::crypto::hpke::HpkePublicKey;
    use crate::crypto::native::hpke::ALL_SUPPORTED_SUITES;
    use crate::enums::AlertDescription;
    use crate::msgs::base::PayloadU16;

    let key = EchServerKey::generate(7, "public.example", 0, ALL_SUPPORTED_SUITES).unwrap();
    let other = EchServerKey::generate(8, "public.example", 0, ALL_SUPPORTED_SUITES).unwrap();
    let list = EchServerConfig::new(vec![key.clone()])
        .unwrap()
        .ech_config_list()
        .to_vec();
    let client = EchConfig::new(&list, ALL_SUPPORTED_SUITES).unwrap();

    // An outer ClientHello naming `outer_name`, sealed to `key` but sent
    // with `config_id`.
    let seal = |outer_name: &str, config_id: u8| -> ClientHelloPayload {
        let inner = inner_hello();
        let mut exts = outer_extensions(&inner);
        exts.server_name = Some(name(outer_name));
        let encoded = encode_inner(&inner, &exts, 0);
        let public_key = HpkePublicKey(client.contents.key_config.public_key.0.clone());
        let (enc, mut sealer) = client
            .hpke
            .setup_sealer(&hpke_info(&client.encoded), &public_key)
            .unwrap();
        let tag_len = client.cipher_suite.aead_id.tag_len().unwrap();
        let mut ech = EchOuter {
            cipher_suite: client.cipher_suite,
            config_id,
            enc: PayloadU16::new(enc.0),
            payload: PayloadU16::new(vec![0; encoded.len() + tag_len]),
        };
        let mut outer = ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from([4; 32]),
            session_id: SessionId::from_slice(&[9; 32]).unwrap(),
            legacy_cookie: None,
            cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            compression_methods: vec![Compression::Null],
            extensions: exts,
        };
        outer.extensions.encrypted_client_hello = Some(EchClientHello::Outer(ech.clone()));
        let aad = outer.get_encoding();
        ech.payload = PayloadU16::new(sealer.seal(&aad, &encoded).unwrap());
        outer.extensions.encrypted_client_hello = Some(EchClientHello::Outer(ech));
        outer
    };
    let open = |config: &EchServerConfig, outer: &ClientHelloPayload| {
        open_first(
            config,
            outer,
            &outer.get_encoding(),
            ProtocolVersion::TLSv1_0,
        )
    };
    let accepted = |r: &Result<Opened, _>| matches!(r, Ok(Opened::Accepted(..)));
    let rejected = |r: &Result<Opened, _>| matches!(r, Ok(Opened::Rejected));

    let by_id = EchServerConfig::new(vec![other.clone(), key.clone()]).unwrap();
    let trial = EchServerConfig::new(vec![other.clone(), key.clone()])
        .unwrap()
        .with_trial_decryption();
    let checked = EchServerConfig::new(vec![key.clone()])
        .unwrap()
        .with_public_name_check();

    // The configuration's identifier.
    let good = seal("public.example", 7);
    assert!(accepted(&open(&by_id, &good)));
    assert!(accepted(&open(&trial, &good)));
    assert!(accepted(&open(&checked, &good)));
    // Another identifier: only trial decryption finds the key.
    for id in [8, 9] {
        let moved = seal("public.example", id);
        assert!(rejected(&open(&by_id, &moved)), "{id}");
        assert!(accepted(&open(&trial, &moved)), "{id}");
    }
    // The outer name differs from the public name: refused only when
    // checked, ignoring ASCII case.
    let renamed = seal("other.example", 7);
    assert!(accepted(&open(&by_id, &renamed)));
    assert!(matches!(
        open(&checked, &renamed),
        Err(super::server::Fatal(
            AlertDescription::IllegalParameter,
            Error::PeerMisbehaved(PeerMisbehaved::EchPublicNameMismatch)
        ))
    ));
    assert!(accepted(&open(&checked, &seal("Public.EXAMPLE", 7))));
}
