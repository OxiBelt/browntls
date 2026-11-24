//! External session and identity binding, RFC 8844
//! (`fuzz_targets/tls_binding.rs`).
//!
//! Reaches every public function of `browntls_core::external_binding`:
//! [`ExternalIdHash`] and [`ExternalSessionId`] decoding of fuzzed
//! `extension_data`, construction, encoding and accessors,
//! [`ExternalIdHash::for_assertion`] with both providers, the
//! [`ClientHello`](browntls_core::server::ClientHello) view through the
//! buffered [`Acceptor`], and the `CommonState` accessors after TLS 1.3 and
//! TLS 1.2 handshakes whose two bindings are fuzz-chosen.
//!
//! Checked properties: decoding accepts exactly what an independent parser
//! of RFC 8844 §3.2 and §4.3 accepts, and re-encodes byte for byte;
//! `ExternalSessionId::new` accepts exactly 20 to 255 bytes; the assertion
//! hash agrees between the native and the RustCrypto providers and with
//! the `sha2` crate; a handshake succeeds exactly when a model of the
//! checks (mismatch, required support, the empty hash a binding without an
//! assertion sends) says so, and then each side reports what the model
//! says the peer sent; the ClientHello view shows what the client's
//! binding sends.
//!
//! Input: up to 32 operations, each an operation byte followed by its
//! arguments (see [`run`]); at most four handshakes per input.

use std::sync::{Arc, OnceLock};

use browntls_core::external_binding::{ExternalBinding, ExternalIdHash, ExternalSessionId};
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::server::Acceptor;
use browntls_core::{
    ClientConfig, ClientConnection, Error, RootCertStore, ServerConfig, ServerConnection, version,
};
use sha2::Digest;

use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 32;

/// Handshakes per input.
const MAX_HANDSHAKES: usize = 4;

/// The `tls_binding` fuzz target.
///
/// Operations (first byte modulo 5):
///
/// 0. decode an `external_id_hash` body (8-bit-prefixed field);
/// 1. decode an `external_session_id` body (16-bit-prefixed field);
/// 2. construct a session identifier (16-bit-prefixed field);
/// 3. hash an identity assertion (16-bit-prefixed field);
/// 4. handshake: version, acceptor, then the client's and the server's
///    binding (see [`binding`]).
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut handshakes = 0;
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.choose(5) {
            0 => decode_id_hash(input.short_field()),
            1 => decode_session_id(input.field()),
            2 => construct_session_id(input.field()),
            3 => hash_assertion(input.field()),
            _ => {
                if handshakes < MAX_HANDSHAKES {
                    handshakes += 1;
                    let _ = handshake(&mut input);
                }
            }
        }
    }
}

/// An independent parser: a one-byte length, then exactly that many bytes,
/// the length within `lengths`.
fn model(data: &[u8], valid: impl Fn(usize) -> bool) -> Option<&[u8]> {
    let (len, body) = data.split_first()?;
    (valid(usize::from(*len)) && body.len() == usize::from(*len)).then_some(body)
}

fn decode_id_hash(data: &[u8]) {
    let expected = model(data, |n| n == 0 || n == ExternalIdHash::SHA256_LEN);
    match (ExternalIdHash::from_extension_data(data), expected) {
        (Ok(hash), Some(body)) => {
            assert_eq!(hash.as_bytes(), body);
            assert_eq!(hash.is_empty(), body.is_empty());
            assert_eq!(hash.to_extension_data(), data);
            if let Ok(digest) = <[u8; 32]>::try_from(body) {
                assert_eq!(ExternalIdHash::from_sha256(digest), hash);
            } else {
                assert_eq!(hash, ExternalIdHash::EMPTY);
            }
        }
        (Err(_), None) => {}
        (got, expected) => panic!("external_id_hash {data:?}: {got:?} vs {expected:?}"),
    }
}

fn decode_session_id(data: &[u8]) {
    let valid = |n| (ExternalSessionId::MIN_LEN..=ExternalSessionId::MAX_LEN).contains(&n);
    match (
        ExternalSessionId::from_extension_data(data),
        model(data, valid),
    ) {
        (Ok(id), Some(body)) => {
            assert_eq!(id.as_bytes(), body);
            assert_eq!(id.to_extension_data(), data);
            assert_eq!(ExternalSessionId::new(body).as_ref(), Ok(&id));
        }
        (Err(_), None) => {}
        (got, expected) => panic!("external_session_id {data:?}: {got:?} vs {expected:?}"),
    }
}

fn construct_session_id(bytes: &[u8]) {
    let valid = (ExternalSessionId::MIN_LEN..=ExternalSessionId::MAX_LEN).contains(&bytes.len());
    match ExternalSessionId::new(bytes) {
        Ok(id) => {
            assert!(valid);
            assert_eq!(id.as_bytes(), bytes);
            let _ = format!("{id:?}");
        }
        Err(err) => {
            assert!(!valid);
            assert_eq!(err, Error::BadExternalSessionIdLength);
        }
    }
}

fn hash_assertion(assertion: &[u8]) {
    let native = browntls_core::crypto::native::default_provider();
    let rustcrypto = browntls_core::crypto::rustcrypto::default_provider();
    let a = ExternalIdHash::for_assertion(&native, assertion).expect("native SHA-256");
    let b = ExternalIdHash::for_assertion(&rustcrypto, assertion).expect("RustCrypto SHA-256");
    assert_eq!(a, b);
    assert_eq!(a.as_bytes(), sha2::Sha256::digest(assertion).as_slice());
    assert!(!a.is_empty() && ExternalIdHash::EMPTY.is_empty());
    let _ = format!("{a:?}");
}

// --------------------------------------------------------------- handshake

/// A CA and a `localhost` certificate, made once per process.
struct Pki {
    roots: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &issuer).expect("certificate");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .expect("root");
        Pki {
            roots: Arc::new(roots),
            chain: vec![CertificateDer::from(cert.der().to_vec())],
            key: key.serialize_der(),
        }
    })
}

/// The values a binding draws from: a few hashes and identifiers, so that
/// both sides often agree.
fn hash_value(selector: u8) -> ExternalIdHash {
    match selector % 3 {
        0 => ExternalIdHash::EMPTY,
        n => ExternalIdHash::from_sha256([n; 32]),
    }
}

fn id_value(selector: u8) -> ExternalSessionId {
    let len = [20, 32, 255][usize::from(selector % 3)];
    ExternalSessionId::new(&vec![b'a' + selector % 2; len]).expect("a valid length")
}

/// A binding: a presence byte, then a mask of the fields set and one value
/// selector per field.
fn binding(input: &mut Input) -> Option<ExternalBinding> {
    if !input.bool() {
        return None;
    }
    let mask = input.byte();
    let mut field = |bit: u8| (mask & bit != 0).then(|| input.byte());
    Some(ExternalBinding {
        id_hash: field(1).map(hash_value),
        peer_id_hash: field(2).map(hash_value),
        session_id: field(4).map(id_value),
        peer_session_id: field(8).map(id_value),
        require_peer_support: mask & 16 != 0,
    })
}

/// What each side sends of the RFC 8844 extensions.
#[derive(Clone, Debug, Default, PartialEq)]
struct Sent {
    id_hash: Option<ExternalIdHash>,
    session_id: Option<ExternalSessionId>,
}

fn sends(b: &ExternalBinding) -> Sent {
    Sent {
        id_hash: Some(b.id_hash.unwrap_or(ExternalIdHash::EMPTY)),
        session_id: b.session_id.clone(),
    }
}

/// Whether `checker` accepts what its peer `sent`.
fn accepts(checker: &ExternalBinding, sent: &Sent) -> bool {
    let one = |expected: Option<&[u8]>, got: Option<&[u8]>| match (expected, got) {
        (Some(e), Some(g)) => e == g,
        (Some(_), None) => !checker.require_peer_support,
        (None, _) => true,
    };
    one(
        checker.peer_id_hash.as_ref().map(ExternalIdHash::as_bytes),
        sent.id_hash.as_ref().map(ExternalIdHash::as_bytes),
    ) && one(
        checker
            .peer_session_id
            .as_ref()
            .map(ExternalSessionId::as_bytes),
        sent.session_id.as_ref().map(ExternalSessionId::as_bytes),
    )
}

fn send<A: browntls_core::SideData, B: browntls_core::SideData>(
    from: &mut browntls_core::ConnectionCommon<A>,
    to: &mut browntls_core::ConnectionCommon<B>,
) {
    let mut buf = Vec::new();
    while from.wants_write() {
        if from.write_tls(&mut buf).is_err() {
            break;
        }
    }
    let mut rest = &buf[..];
    while !rest.is_empty() {
        match to.read_tls(&mut rest) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fn pump(client: &mut ClientConnection, server: &mut ServerConnection) -> (bool, bool) {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        send(client, server);
        if server.process_new_packets().is_err() {
            send(server, client);
            let client_ok = client.process_new_packets().is_ok();
            return (client_ok, false);
        }
        send(server, client);
        if client.process_new_packets().is_err() {
            send(client, server);
            let server_ok = server.process_new_packets().is_ok();
            return (false, server_ok);
        }
    }
    (true, true)
}

/// Runs one handshake; whether it completed.
fn handshake(input: &mut Input) -> bool {
    let pki = pki();
    let tls12 = input.bool();
    let use_acceptor = input.bool();
    let client_binding = binding(input);
    let server_binding = binding(input);
    let versions: &[&'static browntls_core::SupportedProtocolVersion] = if tls12 {
        &[&version::TLS12]
    } else {
        &[&version::TLS13]
    };

    let mut client_config = ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(pki.roots.clone())
        .with_no_client_auth();
    client_config.external_binding = client_binding.clone();
    let mut server_config = ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(
            pki.chain.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone())),
        )
        .expect("server certificate");
    server_config.external_binding = server_binding.clone();

    let name = ServerName::try_from("localhost").expect("name");
    let client = ClientConnection::new(Arc::new(client_config), name);
    let inconsistent = client_binding
        .as_ref()
        .is_some_and(|b| b.peer_session_id.is_some() && b.session_id.is_none());
    let mut client = match client {
        Ok(client) => {
            assert!(!inconsistent);
            client
        }
        Err(err) => {
            assert!(inconsistent);
            assert_eq!(err, Error::InconsistentExternalBinding);
            return false;
        }
    };

    let client_sent = client_binding.as_ref().map(sends).unwrap_or_default();
    let server_sent = match &server_binding {
        Some(b) => {
            let ours = sends(b);
            Sent {
                id_hash: client_sent.id_hash.and(ours.id_hash),
                session_id: client_sent.session_id.as_ref().and(ours.session_id),
            }
        }
        None => Sent::default(),
    };

    let server_config = Arc::new(server_config);
    let mut server = if use_acceptor {
        let mut hello = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut hello).expect("write");
        }
        let mut acceptor = Acceptor::default();
        acceptor.read_tls(&mut &hello[..]).expect("read");
        let accepted = acceptor
            .accept()
            .expect("a valid ClientHello")
            .expect("a complete ClientHello");
        let view = accepted.client_hello();
        assert!(!view.offers_cert_with_extern_psk());
        assert_eq!(view.external_id_hash(), client_sent.id_hash.as_ref());
        assert_eq!(view.external_session_id(), client_sent.session_id.as_ref());
        match accepted.into_connection(server_config) {
            Ok(server) => server,
            Err((_, _alert)) => {
                assert!(
                    !server_binding
                        .as_ref()
                        .is_none_or(|b| accepts(b, &client_sent))
                );
                return false;
            }
        }
    } else {
        ServerConnection::new(server_config).expect("server")
    };

    let server_ok = server_binding
        .as_ref()
        .is_none_or(|b| accepts(b, &client_sent));
    let client_ok = server_ok
        && client_binding
            .as_ref()
            .is_none_or(|b| accepts(b, &server_sent));
    let (client_res, server_res) = pump(&mut client, &mut server);
    assert_eq!(
        client_res && server_res,
        client_ok,
        "{client_binding:?} {server_binding:?}"
    );
    if client_ok {
        assert!(!client.is_handshaking() && !server.is_handshaking());
        let recorded = |b: &Option<ExternalBinding>, sent: &Sent| match b {
            Some(_) => sent.clone(),
            None => Sent::default(),
        };
        let at_server = recorded(&server_binding, &client_sent);
        assert_eq!(server.peer_external_id_hash(), at_server.id_hash.as_ref());
        assert_eq!(
            server.peer_external_session_id(),
            at_server.session_id.as_ref()
        );
        let at_client = recorded(&client_binding, &server_sent);
        assert_eq!(client.peer_external_id_hash(), at_client.id_hash.as_ref());
        assert_eq!(
            client.peer_external_session_id(),
            at_client.session_id.as_ref()
        );
    }
    client_ok
}

/// Starting inputs: every decoder bound, a hash, and handshakes with
/// matching, differing and missing values.
pub fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // external_id_hash bodies around the valid lengths.
    for len in [0usize, 1, 31, 32, 33] {
        let mut body = vec![len as u8];
        body.resize(1 + len, 7);
        let mut seed = vec![0];
        put_short_field(&mut seed, &body);
        seeds.push(seed);
    }
    // external_session_id bodies, a stray byte, constructions.
    for len in [19usize, 20, 255] {
        let mut body = vec![len as u8];
        body.resize(1 + len, b'x');
        let mut seed = vec![1];
        put_field(&mut seed, &body);
        body.push(0);
        seed.push(1);
        put_field(&mut seed, &body);
        seed.push(2);
        put_field(&mut seed, &body[1..1 + len]);
        seeds.push(seed);
    }
    let mut seed = vec![2];
    put_field(&mut seed, &[b'y'; 256]);
    seed.push(3);
    put_field(&mut seed, b"{\"idp\":{},\"assertion\":\"\"}");
    seeds.push(seed);

    // Handshakes: [4, tls12, acceptor, client binding, server binding],
    // a binding being [present, mask, selectors...].
    let full = |sel: [u8; 4], require: bool| {
        let mut b = vec![1, 0x0f | if require { 16 } else { 0 }];
        b.extend_from_slice(&sel);
        b
    };
    for tls12 in [0u8, 1] {
        for acceptor in [0u8, 1] {
            let cases: [(Vec<u8>, Vec<u8>); 6] = [
                // Matching.
                (full([1, 2, 0, 1], true), full([2, 1, 1, 0], true)),
                // The server expects another hash.
                (full([1, 2, 0, 1], false), full([2, 2, 1, 0], false)),
                // The client expects another session identifier.
                (full([1, 2, 0, 1], false), full([2, 1, 2, 0], false)),
                // An unconfigured server; the client requires support.
                (full([1, 2, 0, 1], true), vec![0]),
                // A silent client; the server requires support.
                (vec![0], full([2, 1, 1, 0], true)),
                // Expectations only, and an inconsistent client.
                (vec![1, 0x02, 1], vec![1, 0x08 | 0x01, 0, 1]),
            ];
            for (client, server) in cases {
                let mut seed = vec![4, tls12, acceptor];
                seed.extend_from_slice(&client);
                seed.extend_from_slice(&server);
                seeds.push(seed);
            }
            seeds.push(vec![4, tls12, acceptor, 1, 0x08, 0, 0]);
        }
    }
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds hold to the model, and each handshake seed decodes as one.
    #[test]
    fn seeds_hold_to_the_model() {
        let seeds = seeds();
        assert!(seeds.iter().filter(|s| s.first() == Some(&4)).count() >= 28);
        for seed in &seeds {
            run(seed);
        }
        // The matching handshake seeds complete, over both versions and
        // with and without the acceptor; a mismatch does not.
        let mut completed = 0;
        for seed in seeds.iter().filter(|s| s.first() == Some(&4)) {
            let ok = handshake(&mut Input::new(&seed[1..]));
            completed += usize::from(ok);
        }
        assert!(completed >= 4, "{completed}");
    }
}
