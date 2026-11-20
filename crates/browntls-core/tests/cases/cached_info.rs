// Shared cases, included by `tests/cached_info.rs` (RustCrypto provider) and
// `tests/cached_info_native.rs` (native provider): RFC 7924 `cached_info`
// in TLS 1.2, client and server, Certificate and CertificateRequest.

use std::sync::Arc;

use browntls_core::cached_info::{
    CachedInformationType, CachedObject, ClientCachedInfoMemoryCache, ClientCachedInfoStore,
    ServerCachedInfoPolicy, fingerprint,
};
use browntls_core::client::Resumption;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, ProtocolVersion,
    ServerConfig, ServerConnection, SupportedProtocolVersion, version,
};
use common::*;

const CERT: CachedInformationType = CachedInformationType::Cert;
const CERT_REQ: CachedInformationType = CachedInformationType::CertReq;
/// The `cached_info` extension code point (RFC 7924 §8.1).
const EXT: u16 = 25;

static TLS12: [&SupportedProtocolVersion; 1] = [&version::TLS12];
static BOTH: [&SupportedProtocolVersion; 2] = [&version::TLS13, &version::TLS12];

fn new_store() -> Arc<ClientCachedInfoMemoryCache> {
    Arc::new(ClientCachedInfoMemoryCache::new(8, 2))
}

fn policy(cert: bool, cert_req: bool) -> ServerCachedInfoPolicy {
    let mut policy = ServerCachedInfoPolicy::default();
    policy.cert = cert;
    policy.cert_req = cert_req;
    policy
}

/// A client pinning `server`'s certificate, without session resumption (so
/// every handshake is full), caching in `store`.
fn client(
    server: &Chain,
    store: &Arc<ClientCachedInfoMemoryCache>,
    auth: Option<&Chain>,
    versions: &[&'static SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(server));
    let mut config = match auth {
        Some(chain) => builder
            .with_client_auth_cert(chain.cert_chain(), chain.private_key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.resumption = Resumption::disabled();
    config.cached_info = Some(store.clone());
    Arc::new(config)
}

/// A server for `chain`, requiring `auth`'s certificate when given.
fn server(
    chain: &Chain,
    cached_info: ServerCachedInfoPolicy,
    auth: Option<&Chain>,
    versions: &[&'static SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let builder = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap();
    let builder = match auth {
        Some(chain) => builder.with_client_cert_verifier(PinnedClientVerifier::new(chain, true)),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.cached_info = cached_info;
    Arc::new(config)
}

fn connect(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(cc.clone(), server_name()).unwrap(),
        ServerConnection::new(sc.clone()).unwrap(),
    )
}

/// Completes the handshake; returns how many bytes the server sent.
fn run(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<usize, Error> {
    let mut from_server = 0;
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(from_server);
        }
        transfer(client, server);
        server.process_new_packets()?;
        from_server += transfer(server, client);
        client.process_new_packets()?;
    }
    panic!("handshake did not complete");
}

fn cached(store: &Arc<ClientCachedInfoMemoryCache>, typ: CachedInformationType) -> Vec<[u8; 32]> {
    store
        .lookup(&server_name(), typ)
        .iter()
        .map(|object| *object.fingerprint())
        .collect()
}

fn assert_data_flows(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(send_and_receive(client, server, b"ping"), b"ping");
    assert_eq!(send_and_receive(server, client, b"pong"), b"pong");
}

// ------------------------------------------------- record-level plumbing

/// Takes everything `conn` has to send.
fn output<D: browntls_core::SideData>(conn: &mut browntls_core::ConnectionCommon<D>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).unwrap();
    }
    out
}

/// The handshake messages (header included) of unprotected handshake
/// records.
fn messages(tls: &[u8]) -> Vec<Vec<u8>> {
    let mut joined = Vec::new();
    let mut rest = tls;
    while !rest.is_empty() {
        assert_eq!(rest[0], 22, "not a handshake record");
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        joined.extend_from_slice(&rest[5..5 + len]);
        rest = &rest[5 + len..];
    }
    let mut out = Vec::new();
    let mut rest = &joined[..];
    while !rest.is_empty() {
        let len = u32::from_be_bytes([0, rest[1], rest[2], rest[3]]) as usize;
        out.push(rest[..4 + len].to_vec());
        rest = &rest[4 + len..];
    }
    out
}

/// One unprotected handshake record per message.
fn flight(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in messages {
        out.extend_from_slice(&[22, 3, 3]);
        out.extend_from_slice(&(m.len() as u16).to_be_bytes());
        out.extend_from_slice(m);
    }
    out
}

/// A handshake message of type `typ` with `body`.
fn message(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![typ];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

/// A hash-form body: `opaque hash_value<1..255>`.
fn hash_form(hash: &[u8]) -> Vec<u8> {
    let mut body = vec![hash.len() as u8];
    body.extend_from_slice(hash);
    body
}

/// Where the extension block of a hello message starts.
fn extensions_offset(hello: &[u8], client: bool) -> usize {
    let mut off = 4 + 2 + 32;
    off += 1 + usize::from(hello[off]);
    if client {
        off += 2 + usize::from(u16::from_be_bytes([hello[off], hello[off + 1]]));
        off += 1 + usize::from(hello[off]);
    } else {
        off += 3;
    }
    off
}

/// The extensions of a hello message: type and body.
fn extensions(hello: &[u8], client: bool) -> Vec<(u16, Vec<u8>)> {
    let off = extensions_offset(hello, client);
    let mut rest = &hello[off + 2..];
    let mut out = Vec::new();
    while !rest.is_empty() {
        let typ = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        out.push((typ, rest[4..4 + len].to_vec()));
        rest = &rest[4 + len..];
    }
    out
}

/// `server_hello` with its `cached_info` extension replaced by `body` (or
/// removed).
fn with_cached_info(server_hello: &[u8], body: Option<&[u8]>) -> Vec<u8> {
    let off = extensions_offset(server_hello, false);
    let mut exts: Vec<(u16, Vec<u8>)> = extensions(server_hello, false)
        .into_iter()
        .filter(|(typ, _)| *typ != EXT)
        .collect();
    if let Some(body) = body {
        exts.push((EXT, body.to_vec()));
    }
    let mut block = Vec::new();
    for (typ, body) in exts {
        block.extend_from_slice(&typ.to_be_bytes());
        block.extend_from_slice(&(body.len() as u16).to_be_bytes());
        block.extend_from_slice(&body);
    }
    let mut out = server_hello[4..off].to_vec();
    out.extend_from_slice(&(block.len() as u16).to_be_bytes());
    out.extend_from_slice(&block);
    message(2, &out)
}

/// Feeds `tls` to `client`.
fn deliver(client: &mut ClientConnection, tls: &[u8]) -> Result<(), Error> {
    let mut rest = tls;
    while !rest.is_empty() {
        client.read_tls(&mut rest).unwrap();
        client.process_new_packets()?;
    }
    Ok(())
}

/// The description of the fatal alert `client` queued, if any.
fn alert(client: &mut ClientConnection) -> Option<AlertDescription> {
    let out = output(client);
    let mut rest = &out[..];
    while rest.len() >= 5 {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        if rest[0] == 21 && len == 2 {
            return Some(AlertDescription::from(rest[6]));
        }
        rest = &rest[5 + len..];
    }
    None
}

// ------------------------------------------------------------------- cases

/// RFC 7924 Appendix A: the Certificate message with the certificate of
/// Figure 6 (header `0b 00 02 36 00 02 33 00 02 30`; the prose of the RFC
/// prints two extra bytes in it, which the lengths contradict).
const APPENDIX_A_CERT: [&str; 18] = [
    "3082022c308201b2a00302010202010d300a06082a8648ce3d040302303e310b",
    "3009060355040613024e4c3111300f060355040a1308506f6c617253534c311c",
    "301a06035504031313506f6c617273736c2054657374204543204341301e170d",
    "3133303932343135353230345a170d3233303932323135353230345a3041310b",
    "3009060355040613024e4c3111300f060355040a1308506f6c617253534c311f",
    "301d06035504031316506f6c617253534c205465737420436c69656e74203230",
    "59301306072a8648ce3d020106082a8648ce3d0301070342000457e5aeb173df",
    "d3acbb93b881ff12aeeee653acce5553f6340ecc2ee363250bdf98e2f35c6036",
    "96c0d5181470e57f9fd54b4518e5b06cd55cf8968f8770a3e4c7a3819d30819a",
    "30090603551d1304023000301d0603551d0e041604147a005f8664fce05de511",
    "103bb2e63bc4263fcfe2306e0603551d230467306580149d6d202449013f2bcb",
    "78b519bc7e24c9dbfb367ca142a440303e310b3009060355040613024e4c3111",
    "300f060355040a1308506f6c617253534c311c301a06035504031313506f6c61",
    "7273736c2054657374204543204341820900c143e27e6243cce8300a06082a86",
    "48ce3d040302036800306502304a650d7b2083a299b9a80ffc8dee8f3dbb704c",
    "9603ac8e7870ddf20ea0b216cb658e1ac93f2c617ef83cefad1cee3620023100",
    "9df227a6d574b824aee16a3f31a1ca542f08d08dee4f0c61df77787db4fdfc42",
    "49eee5b26ac2cd2677628e287c9e5745",
];
const APPENDIX_A_FINGERPRINT: &str =
    "086eefb4859adfe977defac494fff6b73033b4ce1f86b8f2a9fc0c6bf98605af";

fn appendix_a_message() -> Vec<u8> {
    let cert = hex::decode(APPENDIX_A_CERT.concat()).unwrap();
    assert_eq!(cert.len(), 560);
    let mut msg = hex::decode("0b000236000233000230").unwrap();
    msg.extend_from_slice(&cert);
    msg
}

#[test]
fn appendix_a_fingerprint() {
    let msg = appendix_a_message();
    let expected = hex::decode(APPENDIX_A_FINGERPRINT).unwrap();
    assert_eq!(fingerprint(&provider(), &msg).unwrap().as_slice(), expected);
    let object = CachedObject::new(&provider(), CERT, msg.clone()).unwrap();
    assert_eq!(object.fingerprint().as_slice(), expected);
    assert_eq!(object.message(), msg);
    assert_eq!(object.typ(), CERT);
    // Not a CertificateRequest, and not with a byte more or less.
    assert!(CachedObject::new(&provider(), CERT_REQ, msg.clone()).is_err());
    let mut longer = msg.clone();
    longer.push(0);
    assert!(CachedObject::new(&provider(), CERT, longer).is_err());
    assert!(CachedObject::new(&provider(), CERT, msg[..msg.len() - 1].to_vec()).is_err());
}

#[test]
fn second_handshake_replaces_the_certificate() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let store = new_store();
    let cc = client(&chain, &store, None, &TLS12);
    let sc = server(&chain, policy(true, false), None, &TLS12);

    // Nothing cached yet: no extension in the ClientHello.
    let (mut c, mut s) = connect(&cc, &sc);
    let hello = output(&mut c);
    assert!(
        extensions(&messages(&hello)[0], true)
            .iter()
            .all(|(typ, _)| *typ != EXT)
    );
    s.read_tls(&mut &hello[..]).unwrap();
    let full = run(&mut c, &mut s).unwrap();
    assert!(c.cached_info_replaced().is_empty());
    assert!(s.cached_info_replaced().is_empty());
    let stored = store.lookup(&server_name(), CERT);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].message()[0], 11, "a Certificate message");
    assert_eq!(
        stored[0].fingerprint(),
        &fingerprint(&provider(), stored[0].message()).unwrap()
    );
    assert!(cached(&store, CERT_REQ).is_empty());

    let (mut c, mut s) = connect(&cc, &sc);
    let short = run(&mut c, &mut s).unwrap();
    for replaced in [c.cached_info_replaced(), s.cached_info_replaced()] {
        assert!(replaced.contains(CERT));
        assert!(!replaced.contains(CERT_REQ));
    }
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(c.peer_certificates().unwrap(), chain.cert_chain());
    // The Certificate shrank to its 37-byte hash form; the ServerHello grew
    // by the 7-byte extension. Both Finished messages verified.
    assert_eq!(full - short, stored[0].message().len() - 37 - 7);
    assert_data_flows(&mut c, &mut s);
    // A restored message is not stored again.
    assert_eq!(cached(&store, CERT), vec![*stored[0].fingerprint()]);
}

#[test]
fn certificate_request_with_client_authentication() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let store = new_store();
    let cc = client(&chain, &store, Some(&client_chain), &TLS12);
    let sc = server(&chain, policy(true, true), Some(&client_chain), &TLS12);

    let (mut c, mut s) = connect(&cc, &sc);
    run(&mut c, &mut s).unwrap();
    assert_eq!(cached(&store, CERT).len(), 1);
    assert_eq!(cached(&store, CERT_REQ).len(), 1);
    assert!(s.cached_info_replaced().is_empty());

    let (mut c, mut s) = connect(&cc, &sc);
    run(&mut c, &mut s).unwrap();
    for replaced in [c.cached_info_replaced(), s.cached_info_replaced()] {
        assert!(replaced.contains(CERT) && replaced.contains(CERT_REQ));
    }
    // The client's CertificateVerify, over the transcript with both hash
    // forms, verified on the server.
    assert_eq!(s.peer_certificates().unwrap(), client_chain.cert_chain());
    assert_eq!(c.peer_certificates().unwrap(), chain.cert_chain());
    assert_data_flows(&mut c, &mut s);
}

#[test]
fn one_type_only_or_none() {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::EcdsaP256);
    let store = new_store();
    let cc = client(&chain, &store, Some(&client_chain), &TLS12);
    let (mut c, mut s) = connect(
        &cc,
        &server(&chain, policy(true, true), Some(&client_chain), &TLS12),
    );
    run(&mut c, &mut s).unwrap();

    // CertificateRequest only.
    let sc = server(&chain, policy(false, true), Some(&client_chain), &TLS12);
    let (mut c, mut s) = connect(&cc, &sc);
    run(&mut c, &mut s).unwrap();
    for replaced in [c.cached_info_replaced(), s.cached_info_replaced()] {
        assert!(!replaced.contains(CERT) && replaced.contains(CERT_REQ));
    }

    // Off (the default): everything in full, no extension.
    let sc = server(
        &chain,
        ServerCachedInfoPolicy::default(),
        Some(&client_chain),
        &TLS12,
    );
    let (mut c, mut s) = connect(&cc, &sc);
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let flight = output(&mut s);
    let sh = &messages(&flight)[0];
    assert!(extensions(sh, false).iter().all(|(typ, _)| *typ != EXT));
    deliver(&mut c, &flight).unwrap();
    run(&mut c, &mut s).unwrap();
    assert!(c.cached_info_replaced().is_empty() && s.cached_info_replaced().is_empty());
    assert_data_flows(&mut c, &mut s);
}

#[test]
fn stale_cache_falls_back_and_is_updated() {
    let old = server_chain(KeyType::EcdsaP256);
    let new = server_chain(KeyType::EcdsaP256);
    let store = new_store();
    let (mut c, mut s) = connect(
        &client(&old, &store, None, &TLS12),
        &server(&old, policy(true, true), None, &TLS12),
    );
    run(&mut c, &mut s).unwrap();
    let old_fp = cached(&store, CERT);

    // The server's certificate changed: the client's fingerprint is stale.
    let cc = client(&new, &store, None, &TLS12);
    let sc = server(&new, policy(true, true), None, &TLS12);
    let (mut c, mut s) = connect(&cc, &sc);
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let flight = output(&mut s);
    let sh = &messages(&flight)[0];
    assert!(extensions(sh, false).iter().all(|(typ, _)| *typ != EXT));
    deliver(&mut c, &flight).unwrap();
    run(&mut c, &mut s).unwrap();
    assert!(c.cached_info_replaced().is_empty() && s.cached_info_replaced().is_empty());
    assert_eq!(c.peer_certificates().unwrap(), new.cert_chain());
    // The new certificate is stored, most recent first.
    let now = cached(&store, CERT);
    assert_eq!(now.len(), 2);
    assert_eq!(now[1], old_fp[0]);

    let (mut c, mut s) = connect(&cc, &sc);
    run(&mut c, &mut s).unwrap();
    assert!(c.cached_info_replaced().contains(CERT));
}

#[test]
fn restored_chain_is_verified_like_a_received_one() {
    let chain = server_chain(KeyType::EcdsaP256);
    let other = server_chain(KeyType::EcdsaP256);
    let store = new_store();
    let sc = server(&chain, policy(true, false), None, &TLS12);
    let (mut c, mut s) = connect(&client(&chain, &store, None, &TLS12), &sc);
    run(&mut c, &mut s).unwrap();

    // A client that trusts another certificate refuses the cached one.
    let (mut c, mut s) = connect(&client(&other, &store, None, &TLS12), &sc);
    let (client_res, _) = do_handshake_until_error(&mut c, &mut s);
    assert_eq!(
        client_res.unwrap_err(),
        Error::InvalidCertificate(browntls_core::CertificateError::UnknownIssuer)
    );
    assert!(c.cached_info_replaced().contains(CERT));
    assert_eq!(cached(&store, CERT).len(), 1);
}

#[derive(Debug)]
struct FixedTime(browntls_core::pki_types::UnixTime);

impl browntls_core::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<browntls_core::pki_types::UnixTime> {
        Some(self.0)
    }
}

#[test]
fn restored_chain_is_checked_at_the_current_time() {
    let chain = server_chain(KeyType::EcdsaP256);
    let store = new_store();
    let mut roots = browntls_core::RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    let roots = Arc::new(roots);
    let make = |time: Arc<dyn browntls_core::time_provider::TimeProvider>| {
        let mut config = ClientConfig::builder_with_details(provider(), time)
            .with_protocol_versions(&TLS12)
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.cached_info = Some(store.clone());
        Arc::new(config)
    };
    let sc = server(&chain, policy(true, false), None, &TLS12);
    let now = Arc::new(browntls_core::time_provider::DefaultTimeProvider);
    let (mut c, mut s) = connect(&make(now), &sc);
    run(&mut c, &mut s).unwrap();

    // The day after the epoch, before the chain's notBefore: the restored
    // chain is not valid at the current time.
    let early = browntls_core::pki_types::UnixTime::since_unix_epoch(
        std::time::Duration::from_secs(86_400),
    );
    let (mut c, mut s) = connect(&make(Arc::new(FixedTime(early))), &sc);
    let (client_res, _) = do_handshake_until_error(&mut c, &mut s);
    assert!(
        matches!(client_res, Err(Error::InvalidCertificate(_))),
        "{client_res:?}"
    );
    assert!(c.cached_info_replaced().contains(CERT));
}

#[test]
fn failed_handshake_does_not_populate_the_store() {
    let chain = server_chain(KeyType::EcdsaP256);
    let store = new_store();
    let cc = client(&chain, &store, None, &TLS12);
    let sc = server(&chain, policy(true, true), None, &TLS12);

    // The certificate arrived in full and verified, but the server's
    // Finished is damaged.
    let (mut c, mut s) = connect(&cc, &sc);
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut last = output(&mut s);
    let end = last.len() - 1;
    last[end] ^= 1;
    assert!(deliver(&mut c, &last).is_err());
    assert!(cached(&store, CERT).is_empty());

    // The server's Finished decrypts but its verify_data is wrong: an
    // attacker altered the NewSessionTicket, which travels unprotected after
    // the server checked the client's Finished, so only the transcripts
    // differ (the keys do not depend on it) and only the client's check of
    // the server's Finished catches it.
    let mut ticket_client = (*cc).clone();
    ticket_client.resumption = Resumption::in_memory_sessions(4);
    let mut ticket_server = (*sc).clone();
    ticket_server.ticketer = prov::Ticketer::new().unwrap();
    let (mut c, mut s) = connect(&Arc::new(ticket_client), &Arc::new(ticket_server));
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut last = output(&mut s);
    // A NewSessionTicket record first; flip a bit of its lifetime hint.
    assert_eq!((last[0], last[5]), (22, 4));
    last[5 + 4 + 3] ^= 1;
    let err = deliver(&mut c, &last).unwrap_err();
    assert!(matches!(err, Error::DecryptError), "{err:?}");
    assert!(cached(&store, CERT).is_empty());

    // The certificate failed verification.
    let other = server_chain(KeyType::EcdsaP256);
    let (mut c, mut s) = connect(&client(&other, &store, None, &TLS12), &sc);
    assert!(do_handshake_until_error(&mut c, &mut s).0.is_err());
    assert!(cached(&store, CERT).is_empty());

    // The same handshake undamaged does populate it.
    let (mut c, mut s) = connect(&cc, &sc);
    run(&mut c, &mut s).unwrap();
    assert_eq!(cached(&store, CERT).len(), 1);
}

#[test]
fn tls13_ignores_the_extension() {
    let chain = server_chain(KeyType::EcdsaP256);
    let store = new_store();
    let (mut c, mut s) = connect(
        &client(&chain, &store, None, &TLS12),
        &server(&chain, policy(true, true), None, &TLS12),
    );
    run(&mut c, &mut s).unwrap();

    let cc = client(&chain, &store, None, &BOTH);
    let sc = server(&chain, policy(true, true), None, &BOTH);
    let (mut c, mut s) = connect(&cc, &sc);
    let hello = output(&mut c);
    // Offered, since the client also offers TLS 1.2.
    let ch = &messages(&hello)[0];
    assert!(extensions(ch, true).iter().any(|(typ, _)| *typ == EXT));
    s.read_tls(&mut &hello[..]).unwrap();
    s.process_new_packets().unwrap();
    let reply = output(&mut s);
    let sh = &messages(&reply[..5 + usize::from(u16::from_be_bytes([reply[3], reply[4]]))])[0];
    assert!(extensions(sh, false).iter().all(|(typ, _)| *typ != EXT));
    deliver(&mut c, &reply).unwrap();
    run(&mut c, &mut s).unwrap();
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert!(c.cached_info_replaced().is_empty() && s.cached_info_replaced().is_empty());
    assert_data_flows(&mut c, &mut s);
    assert_eq!(cached(&store, CERT).len(), 1);

    // A TLS 1.3 ServerHello may not carry it (RFC 9846 §4.3).
    let (mut c, mut s) = connect(&cc, &sc);
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let reply = output(&mut s);
    let sh_len = 5 + usize::from(u16::from_be_bytes([reply[3], reply[4]]));
    let sh = with_cached_info(&messages(&reply[..sh_len])[0], Some(&[0, 1, 1]));
    let err = deliver(&mut c, &flight(&[sh])).unwrap_err();
    assert!(matches!(err, Error::PeerMisbehaved(_)), "{err:?}");
    assert_eq!(alert(&mut c), Some(AlertDescription::IllegalParameter));
}

#[test]
fn resumption_needs_no_certificate() {
    let chain = server_chain(KeyType::EcdsaP256);
    let store = new_store();
    let sc = server(&chain, policy(true, false), None, &TLS12);
    // Populate the store without a session.
    let (mut c, mut s) = connect(&client(&chain, &store, None, &TLS12), &sc);
    run(&mut c, &mut s).unwrap();

    let mut config = (*client(&chain, &store, None, &TLS12)).clone();
    config.resumption = Resumption::in_memory_sessions(8);
    let cc = Arc::new(config);
    // Full handshake with the hash form: the session stores the restored
    // chain.
    let (mut c, mut s) = connect(&cc, &sc);
    run(&mut c, &mut s).unwrap();
    assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
    assert!(c.cached_info_replaced().contains(CERT));
    // Resumed: no Certificate, nothing replaced, the session's chain.
    let (mut c, mut s) = connect(&cc, &sc);
    run(&mut c, &mut s).unwrap();
    assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed));
    assert!(c.cached_info_replaced().is_empty() && s.cached_info_replaced().is_empty());
    assert_eq!(c.peer_certificates().unwrap(), chain.cert_chain());
    assert_data_flows(&mut c, &mut s);
}

#[test]
fn raw_public_keys() {
    let chain = server_chain(KeyType::EcdsaP256);
    let store = new_store();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&TLS12)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::raw_public_key(&chain))
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.cached_info = Some(store.clone());
    let cc = Arc::new(config);
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&TLS12)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(RawKeyResolver::new(&chain));
    config.cached_info = policy(true, false);
    let sc = Arc::new(config);
    for round in 0..2 {
        let (mut c, mut s) = connect(&cc, &sc);
        run(&mut c, &mut s).unwrap();
        assert_eq!(c.cached_info_replaced().contains(CERT), round == 1);
        assert_eq!(
            c.peer_certificates().unwrap(),
            [browntls_core::pki_types::CertificateDer::from(
                chain.end_entity_spki.clone()
            )]
        );
    }
}

include!("cached_info/peers.rs");
include!("cached_info/unbuffered.rs");
