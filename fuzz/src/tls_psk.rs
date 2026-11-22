//! External pre-shared keys (`fuzz_targets/tls_psk.rs`).
//!
//! Reaches every public function of `browntls_core::psk`: [`ExternalPsk`]
//! construction with fuzzed identities, keys and hashes, its builder
//! methods (cipher suite, server name, ALPN, early data, RFC 9258 import
//! context) and accessors, [`ImportedIdentity`] encoding and decoding, and
//! TLS 1.3 handshakes between a client and a server in the same process
//! that hold a fuzz-chosen PSK, with the importer, a pinned suite, 0-RTT
//! and certificate authentication on top of the PSK (RFC 8773).
//!
//! Checked properties: `new` and `imported` accept exactly the documented
//! ranges; the accessors return what was set; `ImportedIdentity` decoding
//! matches an independent parser and re-encodes to the same bytes; a
//! handshake with the same PSK on both sides succeeds and reports its
//! identity on both sides; a handshake where the client's PSK differs
//! (key, identity, import context or hash) never completes with a PSK, and
//! against a server without a certificate it fails on both sides with an
//! error, not a panic.
//!
//! Input: up to 32 operations, each an operation byte followed by its
//! arguments (see [`run`]); at most four handshakes per input.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::pki_types::{
    CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use browntls_core::psk::{
    ExternalPsk, ExternalPskReplayDecision, ExternalPskReplayKey, ExternalPskReplayPolicy,
    ImportedIdentity, ResolvesExternalPsk,
};
use browntls_core::{
    CipherSuite, ClientConfig, ClientConnection, Error, HandshakeKind, ProtocolVersion,
    RootCertStore, ServerConfig, ServerConnection, version,
};

use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 32;

/// Handshakes per input.
const MAX_HANDSHAKES: usize = 4;

const HASHES: &[HashAlgorithm] = &[
    HashAlgorithm::SHA256,
    HashAlgorithm::SHA384,
    HashAlgorithm::SHA1,
    HashAlgorithm::SHA512,
    HashAlgorithm::NONE,
    HashAlgorithm::MD5,
    HashAlgorithm::SHA224,
];

const NAMES: &[&str] = &["localhost", "example.com", "a.b.c.example"];

/// The TLS 1.3 suites of the native provider and their hashes.
const SUITES: &[(CipherSuite, HashAlgorithm)] = &[
    (CipherSuite::TLS13_AES_128_GCM_SHA256, HashAlgorithm::SHA256),
    (CipherSuite::TLS13_AES_256_GCM_SHA384, HashAlgorithm::SHA384),
    (
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        HashAlgorithm::SHA256,
    ),
];

/// The `tls_psk` fuzz target.
///
/// Operations (first byte modulo 4):
///
/// 0. construct: identity, key and hash selectors, then up to 8 builder
///    calls (see [`construct`]);
/// 1. decode: a 16-bit-prefixed `ImportedIdentity` encoding;
/// 2. encode: external identity and context (8-bit-prefixed), target
///    protocol and KDF (16 bits each);
/// 3. handshake: the shared PSK, the client's deviation from it and the
///    server's configuration (see [`handshake`]).
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut handshakes = 0;
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.choose(4) {
            0 => construct(&mut input),
            1 => decode(&mut input),
            2 => encode(&mut input),
            _ => {
                if handshakes < MAX_HANDSHAKES {
                    handshakes += 1;
                    handshake(&mut input);
                }
            }
        }
    }
}

/// `n` bytes: the fuzzed `prefix` repeated (or zeros without one).
fn stretch(prefix: &[u8], n: usize) -> Vec<u8> {
    if prefix.is_empty() {
        vec![0; n]
    } else {
        prefix.iter().copied().cycle().take(n).collect()
    }
}

// ---------------------------------------------------------------- building

/// Identity, key and hash for [`ExternalPsk::new`], with lengths around
/// every bound.
fn raw_parts(input: &mut Input) -> (Vec<u8>, Vec<u8>, HashAlgorithm) {
    let identity = match input.choose(4) {
        0 => Vec::new(),
        1 => stretch(input.short_field(), 65_534 + usize::from(input.byte() % 4)),
        _ => input.short_field().to_vec(),
    };
    let key_len = match input.choose(4) {
        0 => 14 + usize::from(input.byte() % 4),
        1 => 1022 + usize::from(input.byte() % 4),
        _ => usize::from(input.u16()) % 1100,
    };
    let key = stretch(input.short_field(), key_len);
    let hash = *input.pick(HASHES);
    (identity, key, hash)
}

fn dns_name(input: &mut Input) -> DnsName<'static> {
    DnsName::try_from(*input.pick(NAMES))
        .expect("a valid name")
        .to_owned()
}

fn construct(input: &mut Input) {
    let (identity, key, hash) = raw_parts(input);
    let valid = !identity.is_empty()
        && identity.len() <= usize::from(u16::MAX)
        && (ExternalPsk::MIN_KEY_LEN..=ExternalPsk::MAX_KEY_LEN).contains(&key.len())
        && matches!(hash, HashAlgorithm::SHA256 | HashAlgorithm::SHA384);
    let mut psk = match ExternalPsk::new(identity.clone(), key, hash) {
        Ok(psk) => {
            assert!(valid, "accepted: {} {hash:?}", identity.len());
            psk
        }
        Err(_) => {
            assert!(!valid, "refused: {} {hash:?}", identity.len());
            return;
        }
    };
    assert_eq!(psk.identity(), &identity[..]);
    assert_eq!(psk.hash(), hash);
    assert_eq!(psk.cipher_suite(), None);
    assert!(psk.server_name().is_none());
    assert_eq!(psk.alpn_protocol(), None);
    assert_eq!(psk.max_early_data_size(), 0);
    assert_eq!(psk.import_context(), None);
    assert_eq!(psk.key_generation(), None);

    let mut suite = None;
    let mut name = None;
    let mut alpn = None;
    let mut early = 0;
    let mut context = None;
    let mut generation = None;
    for _ in 0..8 {
        if input.is_empty() {
            break;
        }
        match input.choose(6) {
            0 => {
                let s = CipherSuite::from(input.u16());
                suite = Some(s);
                psk = psk.with_cipher_suite(s);
            }
            1 => {
                let n = dns_name(input);
                name = Some(n.clone());
                psk = psk.with_server_name(n);
            }
            2 => {
                let p = input.short_field().to_vec();
                alpn = Some(p.clone());
                psk = psk.with_alpn_protocol(p);
            }
            3 => {
                early = input.u32();
                psk = psk.with_early_data(early);
            }
            4 => {
                let ctx = if input.bool() {
                    stretch(input.short_field(), 65_500 + usize::from(input.byte() % 64))
                } else {
                    input.short_field().to_vec()
                };
                let fits = identity.len() + ctx.len() + 8 <= usize::from(u16::MAX);
                match psk.imported(ctx.clone()) {
                    Ok(imported) => {
                        assert!(fits, "imported identity too long accepted");
                        context = Some(ctx);
                        psk = imported;
                    }
                    Err(_) => {
                        assert!(!fits, "imported identity refused");
                        return;
                    }
                }
            }
            _ => {
                let value = if input.bool() {
                    stretch(input.short_field(), 65_534 + usize::from(input.byte() % 4))
                } else {
                    input.short_field().to_vec()
                };
                let fits = !value.is_empty() && value.len() <= ExternalPsk::MAX_KEY_GENERATION_LEN;
                match psk.with_key_generation(value.clone()) {
                    Ok(with_generation) => {
                        assert!(fits, "invalid key generation accepted");
                        generation = Some(value);
                        psk = with_generation;
                    }
                    Err(_) => {
                        assert!(!fits, "valid key generation refused");
                        return;
                    }
                }
            }
        }
        assert_eq!(psk.identity(), &identity[..]);
        assert_eq!(psk.hash(), hash);
        assert_eq!(psk.cipher_suite(), suite);
        assert_eq!(psk.server_name(), name.as_ref());
        assert_eq!(psk.alpn_protocol(), alpn.as_deref());
        assert_eq!(psk.max_early_data_size(), early);
        assert_eq!(psk.import_context(), context.as_deref());
        assert_eq!(psk.key_generation(), generation.as_deref());
    }
    // The resolver finds keys by identity.
    let resolver = vec![Arc::new(psk)];
    assert!(resolver.resolve(&identity).is_some());
    let mut other = identity.clone();
    other.push(0);
    assert!(resolver.resolve(&other).is_none());
}

// ---------------------------------------------------------------- importer

/// An independent `ImportedIdentity` parser: two 16-bit-prefixed vectors,
/// two 16-bit values, nothing after, a non-empty external identity.
fn parse_imported(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u16, u16)> {
    let mut input = Input::new(bytes);
    let field = |input: &mut Input| -> Option<Vec<u8>> {
        let len = usize::from(u16::from_be_bytes(input.bytes(2).try_into().ok()?));
        let value = input.bytes(len);
        (value.len() == len).then(|| value.to_vec())
    };
    let identity = field(&mut input)?;
    let context = field(&mut input)?;
    let protocol = u16::from_be_bytes(input.bytes(2).try_into().ok()?);
    let kdf = u16::from_be_bytes(input.bytes(2).try_into().ok()?);
    (input.is_empty() && !identity.is_empty()).then_some((identity, context, protocol, kdf))
}

fn decode(input: &mut Input) {
    let bytes = input.field();
    let decoded = ImportedIdentity::decode(bytes);
    match (parse_imported(bytes), decoded) {
        (Some((identity, context, protocol, kdf)), Some(got)) => {
            assert_eq!(got.external_identity, identity);
            assert_eq!(got.context, context);
            assert_eq!(u16::from(got.target_protocol), protocol);
            assert_eq!(got.target_kdf, kdf);
            assert_eq!(got.encode(), bytes);
        }
        (None, None) => {}
        (expected, got) => panic!("ImportedIdentity {bytes:?}: {expected:?} vs {got:?}"),
    }
}

fn encode(input: &mut Input) {
    let external_identity = input.short_field().to_vec();
    let context = input.short_field().to_vec();
    let target_protocol = match input.choose(3) {
        0 => ProtocolVersion::TLSv1_3,
        1 => ProtocolVersion::TLSv1_2,
        _ => ProtocolVersion::from(input.u16()),
    };
    let target_kdf = match input.choose(3) {
        0 => ImportedIdentity::HKDF_SHA256,
        1 => ImportedIdentity::HKDF_SHA384,
        _ => input.u16(),
    };
    let identity = ImportedIdentity {
        external_identity,
        context,
        target_protocol,
        target_kdf,
    };
    let encoded = identity.encode();
    let mut expected = Vec::new();
    put_field(&mut expected, &identity.external_identity);
    put_field(&mut expected, &identity.context);
    expected.extend_from_slice(&u16::from(target_protocol).to_be_bytes());
    expected.extend_from_slice(&target_kdf.to_be_bytes());
    assert_eq!(encoded, expected);
    let decoded = ImportedIdentity::decode(&encoded);
    if identity.external_identity.is_empty() {
        assert!(decoded.is_none(), "empty external identity decoded");
    } else {
        assert_eq!(decoded, Some(identity));
    }
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

/// Moves everything `from` has to send into `to`.
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

/// Runs the handshake until it completes or a side fails (the other side
/// then gets the alert); returns each side's first error.
fn pump(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> (Result<(), Error>, Result<(), Error>) {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        send(client, server);
        if let Err(e) = server.process_new_packets() {
            send(server, client);
            let client_res = client.process_new_packets().map(|_| ());
            return (client_res, Err(e));
        }
        send(server, client);
        if let Err(e) = client.process_new_packets() {
            send(client, server);
            let server_res = server.process_new_packets().map(|_| ());
            return (Err(e), server_res);
        }
    }
    (Ok(()), Ok(()))
}

/// What a PSK is made of here (all valid for [`ExternalPsk::new`]).
#[derive(Clone, Debug)]
struct Spec {
    identity: Vec<u8>,
    key: Vec<u8>,
    hash: HashAlgorithm,
    context: Option<Vec<u8>>,
    suite: Option<CipherSuite>,
    early: u32,
    server_name: bool,
}

impl Spec {
    fn build(&self) -> Arc<ExternalPsk> {
        let mut psk = ExternalPsk::new(self.identity.clone(), self.key.clone(), self.hash)
            .expect("a valid PSK");
        if let Some(suite) = self.suite {
            psk = psk.with_cipher_suite(suite);
        }
        if self.early != 0 {
            psk = psk
                .with_early_data(self.early)
                .with_early_data_record_size_limit(64 + (self.early % 1024) as u16)
                .expect("record size limit in range")
                .with_early_data_expiry(UnixTime::since_unix_epoch(Duration::from_secs(u64::MAX)));
        }
        if self.server_name {
            psk = psk.with_server_name(DnsName::try_from("localhost").expect("name").to_owned());
        }
        if let Some(context) = &self.context {
            psk = psk.imported(context.clone()).expect("a short context");
        }
        Arc::new(psk)
    }
}

#[derive(Debug, Default)]
struct SingleReplayMark(Mutex<Option<Vec<u8>>>);

impl ExternalPskReplayPolicy for SingleReplayMark {
    fn check_and_mark(
        &self,
        key: &ExternalPskReplayKey,
        _expires_at: UnixTime,
    ) -> ExternalPskReplayDecision {
        use ExternalPskReplayDecision::*;
        let mut mark = self.0.lock().expect("fuzz fixture lock");
        match &*mark {
            Some(prior) if prior == key.as_ref() => Duplicate,
            Some(_) => Unavailable,
            None => {
                *mark = Some(key.as_ref().to_vec());
                FirstUse
            }
        }
    }
}

/// How the client's PSK differs from the server's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Deviation {
    Same,
    Key,
    Identity,
    Context,
    Hash,
}

/// How the server is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerMode {
    /// No certificate: a PSK is the only way in.
    PskOnly,
    /// A certificate and the PSK.
    Cert,
    /// Both, and certificate authentication on top of the PSK (RFC 8773)
    /// enabled on both sides.
    CertWithPsk,
}

/// Handshake input: hash selector, identity (8-bit-prefixed, `psk` if
/// empty), key length and an 8-bit-prefixed key prefix, import flag and
/// context, suite flag and selector, early data limit (16 bits, 0 for
/// none), server name flag, deviation selector and its argument byte,
/// server mode, 8-bit-prefixed early data, then omit-replay-policy flag.
fn handshake(input: &mut Input) {
    let hash = if input.bool() {
        HashAlgorithm::SHA384
    } else {
        HashAlgorithm::SHA256
    };
    let mut identity = input.short_field().to_vec();
    if identity.is_empty() {
        identity = b"psk".to_vec();
    }
    let key_len = 16 + usize::from(input.byte() % 49);
    let key = stretch(input.short_field(), key_len);
    let context = input.bool().then(|| input.short_field().to_vec());
    // A pinned suite uses the key's hash.
    let suite = input.bool().then(|| {
        let usable: Vec<CipherSuite> = SUITES
            .iter()
            .filter(|(_, h)| *h == hash)
            .map(|(s, _)| *s)
            .collect();
        *input.pick(&usable)
    });
    let early = u32::from(input.u16());
    let server_name = input.bool();
    let shared = Spec {
        identity,
        key,
        hash,
        context,
        suite,
        early,
        server_name,
    };

    let deviation = match input.choose(5) {
        0 => Deviation::Same,
        1 => Deviation::Key,
        2 => Deviation::Identity,
        3 => Deviation::Context,
        _ => Deviation::Hash,
    };
    let arg = input.byte();
    let mut theirs = shared.clone();
    match deviation {
        Deviation::Same => {}
        Deviation::Key => {
            let at = usize::from(arg) % theirs.key.len();
            theirs.key[at] ^= 1 << (arg % 8);
        }
        Deviation::Identity => theirs.identity.push(arg),
        Deviation::Context => {
            theirs.context = match theirs.context {
                None => Some(vec![arg]),
                Some(mut c) if arg & 1 == 0 => {
                    c.push(arg);
                    Some(c)
                }
                Some(_) => None,
            }
        }
        Deviation::Hash => {
            theirs.hash = if hash == HashAlgorithm::SHA256 {
                HashAlgorithm::SHA384
            } else {
                HashAlgorithm::SHA256
            };
            // Keep the pinned suite consistent with the client's hash.
            theirs.suite = theirs.suite.map(|_| {
                SUITES
                    .iter()
                    .find(|(_, h)| *h == theirs.hash)
                    .expect("suite")
                    .0
            });
        }
    }
    let mode = match input.choose(3) {
        0 => ServerMode::PskOnly,
        1 => ServerMode::Cert,
        _ => ServerMode::CertWithPsk,
    };
    let early_data = input.short_field();
    let replay_policy = !input.bool();

    let pki = pki();
    let provider = Arc::new(browntls_core::crypto::native::default_provider());
    let server_psk = shared.build();
    let server_builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&version::TLS13])
        .expect("server versions")
        .with_no_client_auth();
    let mut server_config = match mode {
        ServerMode::PskOnly => {
            server_builder.with_external_psks_only(Arc::new(vec![server_psk.clone()]))
        }
        ServerMode::Cert | ServerMode::CertWithPsk => {
            let mut config = server_builder
                .with_single_cert(
                    pki.chain.clone(),
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone())),
                )
                .expect("server certificate");
            config.external_psks = Some(Arc::new(vec![server_psk.clone()]));
            config.cert_with_extern_psk = mode == ServerMode::CertWithPsk;
            config
        }
    };
    server_config.max_early_data_size = shared.early;
    if replay_policy {
        server_config.external_psk_replay_policy = Some(Arc::new(SingleReplayMark::default()));
    }

    let client_psk = theirs.build();
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .expect("client versions")
        .with_root_certificates(pki.roots.clone())
        .with_no_client_auth();
    client_config.external_psks = vec![client_psk.clone()];
    client_config.cert_with_extern_psk = mode == ServerMode::CertWithPsk;
    client_config.enable_early_data = shared.early != 0;

    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(Arc::new(client_config), name).expect("client");
    let mut server = ServerConnection::new(Arc::new(server_config)).expect("server");
    assert!(!client.negotiated_cert_with_extern_psk());
    assert!(!server.negotiated_cert_with_extern_psk());
    let mut sent_early = Vec::new();
    if let Some(mut early) = client.early_data() {
        // 0-RTT is offered only under a pinned suite, with the PSK first.
        assert!(theirs.suite.is_some() && theirs.early != 0);
        assert_eq!(early.bytes_left(), theirs.early as usize);
        let n = early_data.len().min(early.bytes_left());
        early.write_all(&early_data[..n]).expect("early data fits");
        sent_early.extend_from_slice(&early_data[..n]);
    }
    let (client_res, server_res) = pump(&mut client, &mut server);
    let completed = client_res.is_ok()
        && server_res.is_ok()
        && !client.is_handshaking()
        && !server.is_handshaking();

    if deviation == Deviation::Same {
        assert!(
            completed,
            "same PSK on both sides: {client_res:?} {server_res:?} {shared:?} {mode:?}"
        );
        assert_eq!(client.external_psk_identity(), Some(&shared.identity[..]));
        assert_eq!(server.external_psk_identity(), Some(&shared.identity[..]));
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(
            client.negotiated_cert_with_extern_psk(),
            mode == ServerMode::CertWithPsk,
        );
        assert_eq!(
            server.negotiated_cert_with_extern_psk(),
            mode == ServerMode::CertWithPsk,
        );
        assert_eq!(
            client.peer_certificates().is_some(),
            mode == ServerMode::CertWithPsk
        );
        let negotiated = client.negotiated_cipher_suite().expect("suite");
        if let Some(suite) = shared.suite {
            assert_eq!(negotiated.suite(), suite);
        }
        if !replay_policy {
            assert!(
                !client.is_early_data_accepted() && server.early_data().is_none(),
                "external PSK accepted without a replay policy"
            );
        }
        if client.is_early_data_accepted() {
            let mut got = Vec::new();
            if let Some(mut early) = server.early_data() {
                early.read_to_end(&mut got).expect("early data");
            }
            assert_eq!(got, sent_early, "0-RTT data");
        }
        // Application data flows both ways.
        client.writer().write_all(b"ping").expect("write");
        send(&mut client, &mut server);
        server.process_new_packets().expect("server reads");
        let mut got = [0u8; 4];
        server.reader().read_exact(&mut got).expect("ping");
        assert_eq!(&got, b"ping");
        return;
    }

    // A PSK the two sides do not share is never used.
    if completed {
        assert!(!client.negotiated_cert_with_extern_psk());
        assert!(!server.negotiated_cert_with_extern_psk());
        assert!(client.external_psk_identity().is_none(), "{deviation:?}");
        assert!(server.external_psk_identity().is_none(), "{deviation:?}");
        assert!(client.peer_certificates().is_some());
    }
    match mode {
        ServerMode::PskOnly => {
            assert!(
                server_res.is_err(),
                "PSK-only server accepted {deviation:?}"
            );
            assert!(client_res.is_err(), "client missed the failure");
        }
        ServerMode::Cert | ServerMode::CertWithPsk => {
            // The server does not recognise the identity it was offered,
            // so it authenticates with its certificate instead.
            let unknown = deviation == Deviation::Identity
                || (deviation == Deviation::Context
                    && shared.context.is_some()
                    && theirs.context.is_some());
            if unknown {
                assert!(completed, "{deviation:?}: {client_res:?} {server_res:?}");
            }
            if deviation == Deviation::Key {
                // A wrong binder is fatal.
                assert!(server_res.is_err() && client_res.is_err());
            }
        }
    }
}

/// Starting inputs for `tls_psk`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let mut seeds = Vec::new();

    // 0: construct, valid and at every bound, then every builder call
    let mut seed = vec![0, 2];
    put_short_field(&mut seed, b"client-1");
    seed.extend_from_slice(&[2, 0, 32]);
    put_short_field(&mut seed, b"key material");
    seed.push(0); // SHA-256
    seed.extend_from_slice(&[0, 0x13, 0x01, 1, 0, 2]);
    put_short_field(&mut seed, b"h2");
    seed.extend_from_slice(&[3, 0, 0, 4, 0, 4, 0]);
    put_short_field(&mut seed, b"ctx");
    seed.extend_from_slice(&[5, 0]);
    put_short_field(&mut seed, b"generation");
    seeds.push(seed);
    for (id_sel, key_sel, key_arg, hash, ctx_len) in [
        (0u8, 2u8, 32u8, 0u8, 0u8),
        (1, 2, 32, 1, 0),
        (2, 0, 1, 0, 0),
        (2, 0, 2, 1, 19),
        (2, 1, 2, 0, 20),
        (2, 1, 3, 0, 0),
        (2, 2, 32, 3, 0),
    ] {
        let mut seed = vec![0, id_sel];
        if id_sel != 0 {
            put_short_field(&mut seed, b"identity");
        }
        if id_sel == 1 {
            seed.push(1);
        }
        seed.push(key_sel);
        if key_sel == 2 {
            seed.extend_from_slice(&[0, key_arg]);
        } else {
            seed.push(key_arg);
        }
        put_short_field(&mut seed, b"k");
        seed.push(hash);
        // a long import context, around the bound for an 8-byte identity
        seed.extend_from_slice(&[4, 1]);
        put_short_field(&mut seed, b"c");
        seed.push(ctx_len);
        seeds.push(seed);
    }
    // 1: decode a valid identity, then garbage
    let valid = ImportedIdentity {
        external_identity: b"epsk".to_vec(),
        context: b"app".to_vec(),
        target_protocol: ProtocolVersion::TLSv1_3,
        target_kdf: ImportedIdentity::HKDF_SHA256,
    }
    .encode();
    let mut seed = vec![1];
    put_field(&mut seed, &valid);
    seed.push(1);
    put_field(&mut seed, &valid[..valid.len() - 1]);
    seed.push(1);
    put_field(&mut seed, &[0, 0, 0, 0, 3, 4, 0, 1]);
    seeds.push(seed);
    // 2: encode
    let mut seed = vec![2];
    put_short_field(&mut seed, b"epsk");
    put_short_field(&mut seed, b"context");
    seed.extend_from_slice(&[0, 1]);
    seed.push(2);
    put_short_field(&mut seed, b"");
    put_short_field(&mut seed, b"");
    seed.extend_from_slice(&[2, 0x7f, 0x1c, 2, 0, 9]);
    seeds.push(seed);
    // 3: handshakes, each deviation against each server mode, plus the
    // importer, a pinned suite with 0-RTT, and SHA-384
    for deviation in 0..5u8 {
        for mode in 0..3u8 {
            let mut seed = vec![3, 0];
            put_short_field(&mut seed, b"client-1");
            seed.push(16);
            put_short_field(&mut seed, b"secret key bytes");
            seed.push(0); // not imported
            seed.push(0); // no suite
            seed.extend_from_slice(&[0, 0]); // no early data
            seed.push(0); // no server name
            seed.extend_from_slice(&[deviation, 5, mode]);
            put_short_field(&mut seed, b"");
            seeds.push(seed);
        }
    }
    for (hash, imported, deviation, mode) in [
        (0u8, 1u8, 0u8, 0u8),
        (1, 1, 0, 2),
        (0, 1, 3, 1),
        (0, 1, 3, 0),
        (1, 1, 4, 0),
        (1, 0, 0, 0),
    ] {
        let mut seed = vec![3, hash];
        put_short_field(&mut seed, b"epsk");
        seed.push(32);
        put_short_field(&mut seed, b"0123456789");
        seed.push(imported);
        if imported == 1 {
            put_short_field(&mut seed, b"app ctx");
        }
        seed.extend_from_slice(&[0, 0, 0, 1]);
        seed.extend_from_slice(&[deviation, 6, mode]);
        put_short_field(&mut seed, b"");
        seeds.push(seed);
    }
    // A pinned suite with 0-RTT data, with and without replay protection.
    let mut seed = vec![3, 0];
    put_short_field(&mut seed, b"early");
    seed.push(0);
    put_short_field(&mut seed, b"early key");
    seed.extend_from_slice(&[0, 1, 0, 4, 0, 0, 0, 0, 0]);
    put_short_field(&mut seed, b"GET /idempotent");
    seeds.push(seed.clone());
    seed.push(1); // omit replay policy
    seeds.push(seed);
    seeds
}
