//! Unit tests of the RFC 7924 wire forms, objects, store and server choice.

#![cfg(any(feature = "native", feature = "rustcrypto"))]

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use browntls_pki::{CertificateDer, DnsName, ServerName};

use super::codec::{hash_form_message, read_hash_form};
use super::*;
use crate::enums::SignatureScheme;
use crate::error::InvalidMessage;
use crate::msgs::codec::Codec;
use crate::msgs::enums::ClientCertificateType;

const CERT: CachedInformationType = CachedInformationType::Cert;
const CERT_REQ: CachedInformationType = CachedInformationType::CertReq;

/// Every provider this build has.
fn providers() -> Vec<CryptoProvider> {
    vec![
        #[cfg(feature = "native")]
        crate::crypto::native::default_provider(),
        #[cfg(feature = "rustcrypto")]
        crate::crypto::rustcrypto::default_provider(),
    ]
}

fn provider() -> CryptoProvider {
    providers().remove(0)
}

fn certificate(certs: &[&[u8]]) -> HandshakeMessagePayload<'static> {
    let chain = certs
        .iter()
        .map(|c| CertificateDer::from(c.to_vec()))
        .collect();
    HandshakeMessagePayload(HandshakePayload::Certificate(CertificateChain(chain)))
}

fn certificate_request() -> HandshakeMessagePayload<'static> {
    HandshakeMessagePayload(HandshakePayload::CertificateRequest(
        CertificateRequestPayload {
            certtypes: vec![ClientCertificateType::ECDSASign],
            sigschemes: vec![SignatureScheme::ED25519],
            canames: Vec::new(),
        },
    ))
}

fn object(typ: CachedInformationType, message: &HandshakeMessagePayload<'_>) -> CachedObject {
    CachedObject::new(&provider(), typ, message.get_encoding()).unwrap()
}

fn name(n: &str) -> ServerName<'static> {
    ServerName::DnsName(DnsName::try_from(n.to_owned()).unwrap())
}

#[test]
fn fingerprint_is_sha256_of_the_message() {
    // FIPS 180-2 "abc".
    let abc = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    for p in providers() {
        assert_eq!(fingerprint(&p, b"abc").unwrap(), abc);
    }
    let mut none = provider();
    none.cipher_suites.clear();
    assert!(fingerprint(&none, b"abc").is_err());
}

#[test]
fn types_and_sets() {
    assert_eq!(CachedInformationType::from_code(1), Some(CERT));
    assert_eq!(CachedInformationType::from_code(2), Some(CERT_REQ));
    for code in [0, 3, 255] {
        assert_eq!(CachedInformationType::from_code(code), None);
    }
    let mut set = CachedInformationTypes::default();
    assert!(set.is_empty());
    set.insert(CERT_REQ);
    assert!(set.contains(CERT_REQ) && !set.contains(CERT));
    set.insert(CERT);
    assert_eq!(set.iter().collect::<Vec<_>>(), [CERT, CERT_REQ]);
    assert_eq!(format!("{set:?}"), "{Cert, CertReq}");
    set.remove(CERT_REQ);
    set.remove(CERT);
    assert!(set.is_empty());
}

#[test]
fn objects_hold_exactly_one_message_of_their_type() {
    let cert = certificate(&[b"leaf", b"ca"]);
    let req = certificate_request();
    for p in providers() {
        let o = CachedObject::new(&p, CERT, cert.get_encoding()).unwrap();
        assert_eq!(o.typ(), CERT);
        assert_eq!(o.message(), cert.get_encoding());
        assert_eq!(*o.fingerprint(), fingerprint(&p, o.message()).unwrap());
        assert_eq!(o.certificate_chain().unwrap().0.len(), 2);
        assert!(o.certificate_request().is_err());
        let o = CachedObject::new(&p, CERT_REQ, req.get_encoding()).unwrap();
        assert!(o.certificate_request().is_ok());
        assert!(o.certificate_chain().is_err());
        assert!(format!("{o:?}").contains("CertReq"));

        // Wrong type, empty chain, trailing data, truncated, empty.
        let mut trailing = cert.get_encoding();
        trailing.push(0);
        let mut truncated = cert.get_encoding();
        truncated.pop();
        for (typ, bad) in [
            (CERT_REQ, cert.get_encoding()),
            (CERT, req.get_encoding()),
            (CERT, certificate(&[]).get_encoding()),
            (CERT, trailing),
            (CERT, truncated),
            (CERT, Vec::new()),
        ] {
            assert!(CachedObject::new(&p, typ, bad).is_err());
        }
    }
}

#[test]
fn client_hello_form_round_trips() {
    let cert = object(CERT, &certificate(&[b"leaf"]));
    let req = object(CERT_REQ, &certificate_request());
    assert!(ClientHelloCachedInfo::from_objects([]).is_none());
    let ext = ClientHelloCachedInfo::from_objects([&cert, &req]).unwrap();
    let wire = ext.get_encoding();
    assert_eq!(wire.len(), 2 + 2 * 34);
    assert_eq!(&wire[..4], &[0, 68, 1, 32]);
    let read = ClientHelloCachedInfo::read_bytes(&wire).unwrap();
    assert_eq!(read, ext);
    let entries: Vec<_> = read.entries().collect();
    assert_eq!(entries[0], (1, cert.fingerprint().as_slice()));
    assert_eq!(entries[1], (2, req.fingerprint().as_slice()));

    // Unknown types and other lengths are kept, to be skipped later.
    let read = ClientHelloCachedInfo::read_bytes(&[0, 6, 9, 1, 0xaa, 1, 1, 0xbb]).unwrap();
    let entries: Vec<_> = read.entries().collect();
    assert_eq!(entries, [(9, &[0xaa][..]), (1, &[0xbb][..])]);
}

#[test]
fn client_hello_form_rejects_malformed_lists() {
    for bad in [
        &[][..],
        &[0, 0],
        &[0, 1, 1],
        &[0, 2, 1, 0],
        &[0, 3, 1, 2, 0xaa],
        &[0, 4, 1, 1, 0xaa],
        &[0, 2, 1, 1, 0xaa],
    ] {
        assert!(ClientHelloCachedInfo::read_bytes(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        ClientHelloCachedInfo::read_bytes(&[0, 0]),
        Err(InvalidMessage::IllegalEmptyList("CachedInformation"))
    );
    assert_eq!(
        ClientHelloCachedInfo::read_bytes(&[0, 2, 1, 0]),
        Err(InvalidMessage::IllegalEmptyValue)
    );
}

#[test]
fn server_hello_form_round_trips() {
    assert!(ServerHelloCachedInfo::from_types(CachedInformationTypes::default()).is_none());
    let mut both = CachedInformationTypes::default();
    both.insert(CERT_REQ);
    both.insert(CERT);
    let ext = ServerHelloCachedInfo::from_types(both).unwrap();
    assert_eq!(ext.get_encoding(), [0, 2, 1, 2]);
    let read = ServerHelloCachedInfo::read_bytes(&[0, 3, 2, 2, 7]).unwrap();
    assert_eq!(read.codes(), [2, 2, 7]);
    assert_eq!(
        ServerHelloCachedInfo::read_bytes(&[0, 0]),
        Err(InvalidMessage::IllegalEmptyList("CachedInformation"))
    );
    for bad in [&[][..], &[0], &[0, 2, 1]] {
        assert!(ServerHelloCachedInfo::read_bytes(bad).is_err());
    }
}

#[test]
fn hash_form() {
    let fp = [7u8; FINGERPRINT_LEN];
    let msg = hash_form_message(HandshakeType::Certificate, &fp);
    let wire = msg.get_encoding();
    assert_eq!(&wire[..5], &[11, 0, 0, 33, 32]);
    assert_eq!(read_hash_form(&wire[4..]), Ok(&fp[..]));
    assert_eq!(read_hash_form(&[1, 9]), Ok(&[9][..]));
    for bad in [&[][..], &[0], &[2, 9], &[1, 9, 9]] {
        assert!(read_hash_form(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn read_handshake_keeps_acknowledged_messages_opaque() {
    let tls12 = ProtocolVersion::TLSv1_2;
    let mut expect = CachedInformationTypes::default();
    let full = certificate(&[b"leaf"]).get_encoding();
    let short = hash_form_message(HandshakeType::Certificate, &[1; 32]).get_encoding();

    // Not expected: parsed as usual, so a hash form is malformed.
    assert!(matches!(
        read_handshake(&full, tls12, expect).unwrap().0,
        HandshakePayload::Certificate(_)
    ));
    assert!(read_handshake(&short, tls12, expect).is_err());

    // Expected: any body is kept as it is, for the state machine.
    expect.insert(CERT);
    for bytes in [&short, &full] {
        match read_handshake(bytes, tls12, expect).unwrap().0 {
            HandshakePayload::Unknown((HandshakeType::Certificate, body)) => {
                assert_eq!(body.bytes(), &bytes[4..]);
            }
            other => panic!("{other:?}"),
        }
    }
    // Other messages and other versions are unaffected.
    let req = certificate_request().get_encoding();
    assert!(matches!(
        read_handshake(&req, tls12, expect).unwrap().0,
        HandshakePayload::CertificateRequest(_)
    ));
    assert!(read_handshake(&short, ProtocolVersion::TLSv1_3, expect).is_err());

    // The header is still checked.
    let mut long = short.clone();
    long[3] += 1;
    assert!(read_handshake(&long, tls12, expect).is_err());
    let huge = [11, 0xff, 0xff, 0xff];
    assert!(matches!(
        read_handshake(&huge, tls12, expect),
        Err(InvalidMessage::HandshakePayloadTooLarge)
    ));
}

#[cfg(feature = "std")]
#[test]
fn memory_store_is_bounded_and_ordered() {
    use crate::sync::Arc;

    let store = ClientCachedInfoMemoryCache::new(2, 2);
    let objects: Vec<_> = (0u8..3)
        .map(|i| Arc::new(object(CERT, &certificate(&[&[i]]))))
        .collect();
    let (a, b) = (name("a.example"), name("b.example"));
    assert!(store.lookup(&a, CERT).is_empty());
    for o in &objects {
        store.insert(a.clone(), o.clone());
    }
    // At most two per type, most recent first.
    let fps = |v: Vec<Arc<CachedObject>>| v.iter().map(|o| *o.fingerprint()).collect::<Vec<_>>();
    assert_eq!(
        fps(store.lookup(&a, CERT)),
        [*objects[2].fingerprint(), *objects[1].fingerprint()]
    );
    assert!(store.lookup(&a, CERT_REQ).is_empty());
    // Storing again makes it the most recent, without a duplicate.
    store.insert(a.clone(), objects[1].clone());
    assert_eq!(
        fps(store.lookup(&a, CERT)),
        [*objects[1].fingerprint(), *objects[2].fingerprint()]
    );
    // Types are kept apart.
    let req = Arc::new(object(CERT_REQ, &certificate_request()));
    store.insert(a.clone(), req.clone());
    assert_eq!(fps(store.lookup(&a, CERT_REQ)), [*req.fingerprint()]);
    assert_eq!(store.lookup(&a, CERT).len(), 2);
    // At most two server names: the oldest goes.
    store.insert(b.clone(), objects[0].clone());
    store.insert(name("c.example"), objects[0].clone());
    assert!(store.lookup(&a, CERT).is_empty());
    assert_eq!(store.lookup(&b, CERT).len(), 1);
    // Zero bounds are raised to one.
    let tiny = ClientCachedInfoMemoryCache::new(0, 0);
    tiny.insert(a.clone(), objects[0].clone());
    tiny.insert(a.clone(), objects[1].clone());
    assert_eq!(fps(tiny.lookup(&a, CERT)), [*objects[1].fingerprint()]);
    assert!(format!("{tiny:?}").contains("per_server: 1"));
}

#[cfg(feature = "tls12")]
#[test]
fn server_replaces_only_exact_offered_fingerprints() {
    use super::server::ServerCachedInfo;

    let cert = || certificate(&[b"leaf", b"ca"]);
    let req = certificate_request;
    let p = provider();
    let cert_fp = fingerprint(&p, &cert().get_encoding()).unwrap();
    let req_fp = fingerprint(&p, &req().get_encoding()).unwrap();
    let both = ServerCachedInfoPolicy {
        cert: true,
        cert_req: true,
    };
    let offer = |entries: &[(u8, &[u8])]| {
        let mut wire = Vec::new();
        for (typ, hash) in entries {
            wire.push(*typ);
            wire.push(hash.len() as u8);
            wire.extend_from_slice(hash);
        }
        let len = (wire.len() as u16).to_be_bytes();
        ClientHelloCachedInfo::read_bytes(&[&len[..], &wire].concat()).unwrap()
    };
    let decide = |policy: &ServerCachedInfoPolicy, offer: Option<&ClientHelloCachedInfo>| {
        ServerCachedInfo::new(policy, &p, offer, cert(), Some(req()))
    };

    // An exact offer, among others, replaces both messages.
    let good = offer(&[(9, &[1]), (1, &[0; 32]), (1, &cert_fp), (2, &req_fp)]);
    let out = decide(&both, Some(&good));
    assert!(out.replaced().contains(CERT) && out.replaced().contains(CERT_REQ));
    assert_eq!(out.extension().unwrap().codes(), [1, 2]);
    assert_eq!(
        out.certificate.get_encoding(),
        hash_form_message(HandshakeType::Certificate, &cert_fp).get_encoding()
    );
    assert_eq!(
        out.certificate_request.unwrap().get_encoding(),
        hash_form_message(HandshakeType::CertificateRequest, &req_fp).get_encoding()
    );

    // Off by policy, not offered, stale (also in the last byte only),
    // truncated, of another type: full.
    let mut cert_last = cert_fp;
    cert_last[FINGERPRINT_LEN - 1] ^= 1;
    let mut req_last = req_fp;
    req_last[FINGERPRINT_LEN - 1] ^= 1;
    let cert_only = ServerCachedInfoPolicy {
        cert: true,
        cert_req: false,
    };
    let out = decide(&cert_only, Some(&good));
    assert_eq!(out.extension().unwrap().codes(), [1]);
    assert_eq!(
        out.certificate_request.unwrap().get_encoding(),
        req().get_encoding()
    );
    for o in [
        None,
        Some(offer(&[(1, &[0; 32])])),
        Some(offer(&[(1, &cert_fp[..31])])),
        Some(offer(&[(1, &cert_last), (2, &req_last)])),
        Some(offer(&[(2, &cert_fp), (1, &req_fp)])),
        Some(offer(&[(3, &cert_fp)])),
    ] {
        let out = decide(&both, o.as_ref());
        assert!(out.replaced().is_empty());
        assert!(out.extension().is_none());
        assert_eq!(out.certificate.get_encoding(), cert().get_encoding());
        assert_eq!(
            out.certificate_request.unwrap().get_encoding(),
            req().get_encoding()
        );
    }
    let out = decide(&ServerCachedInfoPolicy::default(), Some(&good));
    assert!(out.replaced().is_empty());

    // No CertificateRequest: never acknowledged.
    let out = ServerCachedInfo::new(&both, &p, Some(&good), cert(), None);
    assert_eq!(out.extension().unwrap().codes(), [1]);
}

/// A full Certificate or CertificateRequest of a type the server
/// acknowledged is refused even if it reached the state machine parsed in
/// full (parsing normally keeps it as a hash form): `decode_error`.
#[cfg(all(feature = "tls12", feature = "std"))]
#[test]
fn acknowledged_types_refuse_full_messages() {
    use super::client::{
        ClientCachedInfo, process_server_hello, restored_certificate_request, take_certificate,
    };
    use crate::common_state::Side;
    use crate::msgs::message::{Message, MessagePayload};
    use crate::sync::Arc;
    use crate::{ClientConfig, RootCertStore};

    let server = name("a.example");
    let store = Arc::new(ClientCachedInfoMemoryCache::new(1, 1));
    store.insert(
        server.clone(),
        Arc::new(object(CERT, &certificate(&[b"leaf"]))),
    );
    store.insert(
        server.clone(),
        Arc::new(object(CERT_REQ, &certificate_request())),
    );
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&crate::version::TLS12])
        .unwrap()
        .with_root_certificates(Arc::new(RootCertStore::empty()))
        .with_no_client_auth();
    config.cached_info = Some(store);
    let mut both = CachedInformationTypes::default();
    both.insert(CERT);
    both.insert(CERT_REQ);
    let ack = ServerHelloCachedInfo::from_types(both).unwrap();

    for (typ, acknowledged) in [
        (CERT, true),
        (CERT_REQ, true),
        (CERT, false),
        (CERT_REQ, false),
    ] {
        let mut common = CommonState::new(Side::Client);
        let mut offer = ClientCachedInfo::offer(&config, &server, true).unwrap();
        let answer = acknowledged.then_some(&ack);
        process_server_hello(&mut common, Some(&mut offer), answer).unwrap();
        let full = if typ == CERT {
            certificate(&[b"leaf"])
        } else {
            certificate_request()
        };
        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(full),
        };
        let result = if typ == CERT {
            take_certificate(&mut common, Some(&mut offer), &m).map(|_| ())
        } else {
            restored_certificate_request(&mut common, Some(&mut offer), &m).map(|_| ())
        };
        match result {
            Err(Error::InvalidMessage(InvalidMessage::UnexpectedMessage(_))) => {
                assert!(acknowledged, "{typ:?}")
            }
            Ok(()) => assert!(!acknowledged, "{typ:?}"),
            Err(other) => panic!("{typ:?}: {other:?}"),
        }
    }
}
