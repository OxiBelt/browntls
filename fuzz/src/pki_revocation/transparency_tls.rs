//! RFC 9162 §6.5 `transparency_info` in TLS: a server whose certified key
//! carries a `TransItemList` and a client whose WebPKI verifier enforces a
//! CT 2.0 policy, over TLS 1.2 and 1.3, buffered and unbuffered clients,
//! with arbitrary bytes as the server's list or spliced into a hello.
//!
//! Input: one flags byte, then bytes whose use the flags choose.
//!
//! - bit 0: TLS 1.3 (else TLS 1.2); bit 1: unbuffered client;
//! - bit 2: the server sends the fixture list (an SCT, its inclusion proof
//!   and a tree head); bit 3: the client enforces a policy (else it only
//!   asks for the items); bit 4: the policy wants an inclusion proof;
//! - bit 5: the rest is the body of a `transparency_info` extension added
//!   to the ClientHello; bit 6: to a TLS 1.2 ServerHello (buffered client);
//!   neither: the rest, when not empty, is offered to the server's
//!   certified key as its list.
//!
//! Properties: nothing panics; a completed handshake under a policy has a
//! status meeting it; the client reports the list the server sent.

use std::sync::{Arc, OnceLock};

use browntls_core::client::{UnbufferedClientConnection, WebPkiServerVerifier};
use browntls_core::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::revocation::RevocationDigests;
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::transparency::{CtV2LogConfig, CtV2Requirements, TransparencyStatus};
use browntls_core::unbuffered::ConnectionState;
use browntls_core::{
    ClientConfig, ClientConnection, ConnectionCommon, RootCertStore, ServerConfig,
    ServerConnection, SideData, SupportedProtocolVersion, version,
};
use browntls_pki::transparency::{
    ArtifactExtensions, InclusionProofDataV2, LogId, MerklePath, SignedTreeHeadDataV2, TransItem,
    TransItemList, TreeHeadDataV2, merkle,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData as _, SigningKey as _,
};

use super::fixtures::{Clock, NOW};
use super::transparency::{LOG_ID, SCT_TIME, entry_item, sct_item, sha256, tbs};
use crate::connection::provider;

struct Fixture {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: Vec<u8>,
    log_spki: Vec<u8>,
    /// An `x509_sct_v2` for `leaf`, its inclusion proof in a tree of one
    /// entry, and that tree's signed head.
    list: Vec<u8>,
}

impl Fixture {
    fn get() -> &'static Self {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(Self::new)
    }

    fn new() -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "transparency TLS fixture CA");
        let ca = ca_params.self_signed(&ca_key).unwrap().der().to_vec();
        let issuer_key_hash = sha256(&ca_key.subject_public_key_info());
        let issuer = Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params.signed_by(&key, &issuer).unwrap().der().to_vec();

        let log_key = KeyPair::generate().unwrap();
        let entry = entry_item(false, &issuer_key_hash, &tbs(&leaf));
        let sct = sct_item(false, LOG_ID, &log_key.sign(&entry).unwrap());
        let root = merkle::merkle_tree_hash(sha256, &[entry]);
        let inclusion = TransItem::InclusionProofV2(InclusionProofDataV2 {
            log_id: LogId::new(LOG_ID).unwrap(),
            tree_size: 1,
            leaf_index: 0,
            inclusion_path: MerklePath::from_nodes(&[]),
        });
        let tree_head = TreeHeadDataV2 {
            timestamp_ms: SCT_TIME + 1,
            tree_size: 1,
            root_hash: &root,
            sth_extensions: ArtifactExtensions::EMPTY,
        };
        let signature = log_key.sign(&tree_head.encode().unwrap()).unwrap();
        let sth = TransItem::SignedTreeHeadV2(SignedTreeHeadDataV2 {
            log_id: LogId::new(LOG_ID).unwrap(),
            tree_head,
            signature: &signature,
        });
        let list =
            TransItemList::encode(&[&sct, &inclusion.encode().unwrap(), &sth.encode().unwrap()])
                .unwrap();
        Self {
            ca: ca.into(),
            leaf: leaf.into(),
            key: key.serialize_der(),
            log_spki: log_key.subject_public_key_info(),
            list,
        }
    }
}

fn client_config(
    fixture: &Fixture,
    v: &'static SupportedProtocolVersion,
    policy: Option<bool>,
) -> ClientConfig {
    let provider = provider(false);
    let mut roots = RootCertStore::empty();
    roots.add(fixture.ca.clone()).unwrap();
    let mut builder =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone());
    if let Some(strict) = policy {
        let log = CtV2LogConfig::new(LOG_ID, fixture.log_spki.clone())
            .with_timestamp_window(0, (NOW + 3600) * 1000);
        assert_eq!(log.log_id(), LOG_ID);
        let mut requirements = CtV2Requirements::new(RevocationDigests::native(), vec![log]);
        requirements.require_inclusion = strict;
        builder = builder.with_certificate_transparency(requirements);
    }
    let mut config = ClientConfig::builder_with_details(provider, Arc::new(Clock))
        .with_protocol_versions(&[v])
        .unwrap()
        .with_webpki_verifier(builder.build().unwrap())
        .with_no_client_auth();
    config.request_transparency_info = policy.is_none();
    config
}

fn server_config(
    fixture: &Fixture,
    v: &'static SupportedProtocolVersion,
    list: Option<Vec<u8>>,
) -> (ServerConfig, Option<Vec<u8>>) {
    let provider = provider(false);
    let key = PrivatePkcs8KeyDer::from(fixture.key.clone());
    let mut certified = CertifiedKey::from_der(
        vec![fixture.leaf.clone(), fixture.ca.clone()],
        key.into(),
        &provider,
    )
    .unwrap();
    if certified.set_transparency_info(list).is_err() {
        assert_eq!(certified.transparency_info(), None);
    }
    let sent = certified.transparency_info().map(<[u8]>::to_vec);
    let config = ServerConfig::builder_with_details(provider, Arc::new(Clock))
        .with_protocol_versions(&[v])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    (config, sent)
}

/// `flight` with a `transparency_info` extension of body `body` added to
/// the hello that opens its first record, if it is one; lengths fixed up.
fn splice(flight: &[u8], client_hello: bool, body: &[u8]) -> Option<Vec<u8>> {
    let be16 = |b: &[u8]| Some(usize::from(u16::from_be_bytes([*b.first()?, *b.get(1)?])));
    if *flight.first()? != 22 {
        return None;
    }
    let record_len = be16(flight.get(3..)?)?;
    let record = flight.get(5..5 + record_len)?;
    if *record.first()? != if client_hello { 1 } else { 2 } {
        return None;
    }
    let msg_len = usize::from(*record.get(1)?) << 16 | be16(record.get(2..)?)?;
    let msg = record.get(4..4 + msg_len)?;
    let mut at = 35 + usize::from(*msg.get(34)?);
    if client_hello {
        at += 2 + be16(msg.get(at..)?)?;
        at += 1 + usize::from(*msg.get(at)?);
    } else {
        at += 3;
    }
    let mut ext = vec![0, 52];
    ext.extend(u16::try_from(body.len()).ok()?.to_be_bytes());
    ext.extend_from_slice(body);
    let exts_len = u16::try_from(be16(msg.get(at..)?)? + ext.len()).ok()?;
    let mut new_msg = msg.get(..at)?.to_vec();
    new_msg.extend(exts_len.to_be_bytes());
    new_msg.extend(ext);
    new_msg.extend_from_slice(msg.get(at + 2..)?);
    let mut new_record = vec![record[0]];
    new_record.extend(&u32::try_from(new_msg.len()).ok()?.to_be_bytes()[1..]);
    new_record.extend(new_msg);
    new_record.extend_from_slice(&record[4 + msg_len..]);
    let mut out = flight[..3].to_vec();
    out.extend(u16::try_from(new_record.len()).ok()?.to_be_bytes());
    out.extend(new_record);
    out.extend_from_slice(&flight[5 + record_len..]);
    Some(out)
}

fn take<D: SideData>(conn: &mut ConnectionCommon<D>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

/// Delivers `bytes`; false when the connection failed.
fn give<D: SideData>(conn: &mut ConnectionCommon<D>, bytes: &[u8]) -> bool {
    let mut rd = bytes;
    while !rd.is_empty() {
        match conn.read_tls(&mut rd) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    conn.process_new_packets().is_ok()
}

/// Runs an unbuffered client until it needs input; false when it failed.
fn run_unbuffered(
    conn: &mut UnbufferedClientConnection,
    incoming: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> bool {
    for _ in 0..64 {
        let status = conn.process_tls_records(incoming);
        let discard = status.discard;
        let stop = match status.state {
            Ok(ConnectionState::EncodeTlsData(mut e)) => {
                let mut buf = vec![0u8; 1 << 16];
                match e.encode(&mut buf) {
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                    Err(_) => return false,
                }
                false
            }
            Ok(ConnectionState::TransmitTlsData(t)) => {
                t.done();
                false
            }
            Ok(ConnectionState::ReadTraffic(_)) => false,
            Ok(_) => true,
            Err(_) => return false,
        };
        incoming.drain(..discard);
        if stop {
            return true;
        }
    }
    true
}

pub(super) fn run(bytes: &[u8]) {
    let Some((&flags, rest)) = bytes.split_first() else {
        return;
    };
    let fixture = Fixture::get();
    let v = if flags & 1 == 0 {
        &version::TLS12
    } else {
        &version::TLS13
    };
    let unbuffered = flags & 2 != 0;
    let policy = (flags & 8 != 0).then_some(flags & 16 != 0);
    let (into_ch, into_sh) = (flags & 32 != 0, flags & 64 != 0 && !unbuffered);
    let list = if flags & 4 != 0 {
        Some(fixture.list.clone())
    } else if !into_ch && !into_sh && !rest.is_empty() {
        Some(rest.to_vec())
    } else {
        None
    };
    let client = Arc::new(client_config(fixture, v, policy));
    let (server, sent) = server_config(fixture, v, list);
    let mut server = ServerConnection::new(Arc::new(server)).unwrap();
    let name = ServerName::try_from("localhost").unwrap();

    if unbuffered {
        let mut client = UnbufferedClientConnection::new(client, name).unwrap();
        let (mut incoming, mut first) = (Vec::new(), true);
        for _ in 0..8 {
            let mut out = Vec::new();
            let ok = run_unbuffered(&mut client, &mut incoming, &mut out);
            if into_ch && std::mem::take(&mut first) {
                out = splice(&out, true, rest).unwrap_or(out);
            }
            if !ok || !give(&mut server, &out) {
                return;
            }
            incoming.extend(take(&mut server));
        }
        check(
            policy,
            client.is_handshaking(),
            &sent,
            client.peer_transparency_info(),
            client.peer_transparency_status(),
        );
        return;
    }

    let mut client = ClientConnection::new(client, name).unwrap();
    for round in 0..8 {
        let mut out = take(&mut client);
        if into_ch && round == 0 {
            out = splice(&out, true, rest).unwrap_or(out);
        }
        if !give(&mut server, &out) {
            return;
        }
        let mut back = take(&mut server);
        if into_sh && round == 0 && v == &version::TLS12 {
            back = splice(&back, false, rest).unwrap_or(back);
        }
        if !give(&mut client, &back) {
            return;
        }
    }
    check(
        policy,
        client.is_handshaking(),
        &sent,
        client.peer_transparency_info(),
        client.peer_transparency_status(),
    );
}

fn check(
    policy: Option<bool>,
    handshaking: bool,
    sent: &Option<Vec<u8>>,
    info: Option<&[u8]>,
    status: Option<TransparencyStatus>,
) {
    if handshaking {
        return;
    }
    match policy {
        Some(strict) => {
            let status = status.expect("a policy reports a status");
            let floor = if strict {
                TransparencyStatus::new(1, 1, 1)
            } else {
                TransparencyStatus::new(1, 1, 0)
            };
            assert!(status.verified_scts >= floor.verified_scts);
            assert!(status.distinct_logs >= floor.distinct_logs);
            assert!(status.inclusion_proven >= floor.inclusion_proven);
        }
        None => assert_eq!(status, None),
    }
    // Without splicing the list arrives as sent; a spliced ServerHello
    // extension may stand in for an empty one.
    if let (Some(sent), Some(info)) = (sent, info) {
        assert_eq!(sent.as_slice(), info);
    }
}

pub(super) fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for flags in [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 28, 29] {
        seeds.push(vec![flags]);
    }
    let list = &Fixture::get().list;
    seeds.push([&[0][..], list].concat());
    seeds.push([&[1][..], list].concat());
    seeds.push([&[8][..], list].concat());
    seeds.push(vec![0, 0, 1, 7]);
    // A non-empty ClientHello extension, an unsolicited ServerHello one.
    seeds.push(vec![32, 0]);
    seeds.push(vec![33]);
    seeds.push(vec![34, 0, 0]);
    seeds.push([&[64][..], list].concat());
    seeds.push(vec![68 | 8, 0, 0]);
    seeds
}
