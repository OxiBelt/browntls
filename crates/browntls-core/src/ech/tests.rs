//! Tests of the inner ClientHello encoding (RFC 9849 §5.1) and of the
//! server's checks on what it decrypts.

#[cfg(feature = "native")]
use alloc::string::String;
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
    // Every decryption below runs with a key log that takes everything.
    // With the `key-log` feature, `expect_records` then checks what the
    // call wrote: one `ECH_SECRET` and one `ECH_CONFIG` under the outer
    // random for an accepted offer, naming the configuration of the key
    // that decrypted, and nothing otherwise.
    let sink = Records::default();
    let open = |config: &EchServerConfig, outer: &ClientHelloPayload| {
        sink.0.lock().unwrap().clear();
        open_first(
            config,
            outer,
            &outer.get_encoding(),
            ProtocolVersion::TLSv1_0,
            &sink,
        )
    };
    let expect_records = |config: Option<&EchServerKey>| {
        let records = core::mem::take(&mut *sink.0.lock().unwrap());
        let (Some(key), true) = (config, cfg!(feature = "key-log")) else {
            assert!(records.is_empty(), "{records:?}");
            return;
        };
        let [secret, logged_config] = &records[..] else {
            panic!("{records:?}");
        };
        assert_eq!(secret.0, "ECH_SECRET");
        assert_eq!(secret.1, [4; 32]);
        // X25519: `Nsecret` is 32 bytes.
        assert_eq!(secret.2.len(), 32);
        assert_eq!(
            *logged_config,
            (String::from("ECH_CONFIG"), vec![4; 32], key.encoded.clone())
        );
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
    expect_records(Some(&key));
    assert!(accepted(&open(&trial, &good)));
    // Trial decryption tried `other` first: its failed context left no
    // record, and the configuration logged is the second key's.
    expect_records(Some(&key));
    assert!(accepted(&open(&checked, &good)));
    expect_records(Some(&key));
    // Another identifier: only trial decryption finds the key.
    for id in [8, 9] {
        let moved = seal("public.example", id);
        // Identifier 8 selects `other`, which sets a context up from the
        // client's `enc` but cannot open the payload.
        assert!(rejected(&open(&by_id, &moved)), "{id}");
        expect_records(None);
        assert!(accepted(&open(&trial, &moved)), "{id}");
        expect_records(Some(&key));
    }
    // The outer name differs from the public name: refused only when
    // checked, ignoring ASCII case. The refusal comes after the payload
    // opened, and still writes nothing.
    let renamed = seal("other.example", 7);
    assert!(accepted(&open(&by_id, &renamed)));
    expect_records(Some(&key));
    assert!(matches!(
        open(&checked, &renamed),
        Err(super::server::Fatal(
            AlertDescription::IllegalParameter,
            Error::PeerMisbehaved(PeerMisbehaved::EchPublicNameMismatch)
        ))
    ));
    expect_records(None);
    assert!(accepted(&open(&checked, &seal("Public.EXAMPLE", 7))));
    expect_records(Some(&key));

    // No ECH extension, and one of type `inner`: nothing to log.
    let mut plain = good.clone();
    plain.extensions.encrypted_client_hello = None;
    assert!(matches!(open(&by_id, &plain), Ok(Opened::NotOffered)));
    expect_records(None);
    plain.extensions.encrypted_client_hello = Some(EchClientHello::Inner);
    assert!(open(&by_id, &plain).is_err());
    expect_records(None);
}

/// A key log that takes every label and keeps what it is given.
#[cfg(feature = "native")]
#[derive(Debug, Default)]
struct Records(std::sync::Mutex<Vec<Record>>);

/// A label, the random that identifies the connection, and the value.
#[cfg(feature = "native")]
type Record = (String, Vec<u8>, Vec<u8>);

#[cfg(feature = "native")]
impl crate::KeyLog for Records {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.into(), client_random.to_vec(), secret.to_vec()));
    }
}
