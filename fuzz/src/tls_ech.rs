//! Encrypted Client Hello (`fuzz_targets/tls_ech.rs`).
//!
//! Reaches every public function of `browntls::ech` and `browntls::ech::svcb`:
//! `ECHConfigList` parsing of fuzzed bytes ([`EchConfig::new`]), server keys
//! from fuzz-chosen `ECHConfig` fields ([`EchServerKey::new`]) and generated
//! ones ([`EchServerKey::generate`]), [`EchServerConfig`] lists, GREASE
//! settings, the SVCB/HTTPS record helpers, and TLS 1.3 handshakes between a
//! client and a server in the same process: ECH accepted (optionally after a
//! HelloRetryRequest), rejected with retry configurations and retried,
//! rejected by a server without ECH, and GREASE, optionally with a byte of
//! the client's first flight altered.
//!
//! Checked properties: the configuration parsers agree with an independent
//! model of RFC 9849 §4 (version, mandatory extensions, public name rules of
//! §6.1.7, suite selection); a server key re-encodes its `ECHConfig`
//! byte for byte and a server configuration lists exactly its keys; a
//! generated key round-trips through its parts; the three SVCB helpers agree
//! with each other and with a model of RFC 9460 §2.2; the handshakes end in
//! the documented states (both sides `Accepted` with the inner server name,
//! `RejectedEch` with the server's retry configurations, which then
//! succeed, or none for a server without ECH; GREASE completes).
//!
//! Input: up to 32 operations, each an operation byte followed by its
//! arguments (see [`run`]); at most two handshake operations per input.

use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};

use browntls::crypto::hpke::{Hpke, HpkeKem, HpkePrivateKey, HpkePublicKey};
use browntls::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use browntls::ech::svcb::{
    ECH_SVC_PARAM_KEY, ech_config_list_from_presentation, ech_config_list_from_svc_params,
    ech_config_list_from_svcb_rdata,
};
use browntls::ech::{
    EchConfig, EchGreaseConfig, EchMode, EchServerConfig, EchServerKey, EchStatus,
};
use browntls::pki_types::{CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls::{
    ClientConfig, ClientConnection, Error, RootCertStore, ServerConfig, ServerConnection, version,
};

use crate::input::{Input, put_field, put_short_field};

/// Operations per input.
const MAX_OPS: usize = 32;

/// Handshake operations per input.
const MAX_HANDSHAKES: usize = 2;

/// Key generations per input.
const MAX_GENERATIONS: usize = 4;

/// Server keys kept between operations.
const MAX_KEYS: usize = 4;

/// The ECH version of RFC 9849.
const ECH_VERSION: u16 = 0xfe0d;

/// The KEMs of the native suites, in the order of `ALL_SUPPORTED_SUITES`
/// (nine suites each).
const KEMS: [HpkeKem; 5] = [
    HpkeKem::DHKEM_X25519_HKDF_SHA256,
    HpkeKem::DHKEM_P256_HKDF_SHA256,
    HpkeKem::DHKEM_P384_HKDF_SHA384,
    HpkeKem::DHKEM_P521_HKDF_SHA512,
    HpkeKem::DHKEM_X448_HKDF_SHA512,
];

const PUBLIC: &str = "public.example";
const SECRET: &str = "secret.example";

/// Public names, valid and not (RFC 9849 §6.1.7).
const NAMES: &[&str] = &[
    PUBLIC,
    SECRET,
    "example",
    "a-b.example",
    "EXAMPLE.COM",
    "xn--bcher-kva.example",
    "192.0.2.1",
    "example.0x1f",
    "example.0X",
    "example.0xg",
    "example.123",
    "-a.example",
    "a-.example",
    "",
    ".example",
    "example.",
    "exa mple.com",
    "a..b",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
];

// ----------------------------------------------------------------- fixture

/// Keys and certificates made once per process.
struct Fixture {
    /// One key pair per KEM (index as in [`KEMS`]).
    pairs: Vec<(HpkePublicKey, HpkePrivateKey)>,
    /// An X25519 public key whose private half no server holds.
    stale: HpkePublicKey,
    roots: Arc<RootCertStore>,
    /// A certificate for both [`PUBLIC`] and [`SECRET`].
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let pairs = (0..KEMS.len())
            .map(|k| {
                ALL_SUPPORTED_SUITES[k * 9]
                    .generate_key_pair()
                    .expect("HPKE key pair")
            })
            .collect();
        let (stale, _) = ALL_SUPPORTED_SUITES[0]
            .generate_key_pair()
            .expect("HPKE key pair");

        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params =
            rcgen::CertificateParams::new(vec![PUBLIC.to_string(), SECRET.to_string()])
                .expect("params");
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &issuer).expect("certificate");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .expect("root");
        Fixture {
            pairs,
            stale,
            roots: Arc::new(roots),
            chain: vec![CertificateDer::from(cert.der().to_vec())],
            key: key.serialize_der(),
        }
    })
}

// ------------------------------------------------------------------- model

/// The fields of one `ECHConfig`, as the harness writes it.
#[derive(Clone, Debug)]
struct Fields {
    version: u16,
    config_id: u8,
    kem: u16,
    public_key: Vec<u8>,
    /// `(kdf, aead)` pairs.
    suites: Vec<(u16, u16)>,
    maximum_name_length: u8,
    public_name: Vec<u8>,
    /// `(type, data)` pairs.
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Fields {
    /// `version || length || ECHConfigContents`.
    fn encode(&self) -> Vec<u8> {
        let mut contents = vec![self.config_id];
        contents.extend_from_slice(&self.kem.to_be_bytes());
        put_field(&mut contents, &self.public_key);
        let mut suites = Vec::new();
        for (kdf, aead) in &self.suites {
            suites.extend_from_slice(&kdf.to_be_bytes());
            suites.extend_from_slice(&aead.to_be_bytes());
        }
        put_field(&mut contents, &suites);
        contents.push(self.maximum_name_length);
        put_short_field(&mut contents, &self.public_name);
        let mut extensions = Vec::new();
        for (typ, data) in &self.extensions {
            extensions.extend_from_slice(&typ.to_be_bytes());
            put_field(&mut extensions, data);
        }
        put_field(&mut contents, &extensions);
        let mut out = self.version.to_be_bytes().to_vec();
        put_field(&mut out, &contents);
        out
    }

    /// Whether `ECHConfigContents` is well formed (§4), whatever the
    /// version says.
    fn well_formed(&self) -> bool {
        let mut types: Vec<u16> = self.extensions.iter().map(|(t, _)| *t).collect();
        types.sort_unstable();
        types.dedup();
        !self.public_key.is_empty()
            && !self.suites.is_empty()
            && !self.public_name.is_empty()
            && types.len() == self.extensions.len()
    }

    /// The suite a client using `offered` seals with: the first of the
    /// configuration's suites that one of `offered` implements.
    fn client_suite(&self, offered: &[&'static dyn Hpke]) -> Option<(u16, u16)> {
        self.suites.iter().copied().find(|(kdf, aead)| {
            offered.iter().any(|s| {
                let s = s.suite();
                s.kem.0 == self.kem && s.sym.kdf_id.0 == *kdf && s.sym.aead_id.0 == *aead
            })
        })
    }

    /// Whether a client accepts the configuration (§4.2, §6.1.7).
    fn usable_by_client(&self, offered: &[&'static dyn Hpke]) -> bool {
        self.version == ECH_VERSION
            && self.well_formed()
            && !self.extensions.iter().any(|(t, _)| t & 0x8000 != 0)
            && public_name_ok(&self.public_name)
            && self.client_suite(offered).is_some()
    }

    /// Whether a server accepts the configuration with `offered`.
    fn usable_by_server(&self, offered: &[&'static dyn Hpke]) -> bool {
        self.version == ECH_VERSION && self.well_formed() && self.client_suite(offered).is_some()
    }
}

/// RFC 9849 §6.1.7: a host name in preferred name syntax whose last label
/// cannot be read as an IPv4 address (all digits, or a `0x` hex literal).
fn public_name_ok(name: &[u8]) -> bool {
    let Ok(s) = core::str::from_utf8(name) else {
        return false;
    };
    if s.is_empty() || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    for label in s.split('.') {
        let b = label.as_bytes();
        if b.is_empty()
            || b.len() > 63
            || b[0] == b'-'
            || b[b.len() - 1] == b'-'
            || !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        {
            return false;
        }
    }
    let last = s.rsplit('.').next().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if let Some(hex) = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X"))
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return false;
    }
    DnsName::try_from(s).is_ok()
}

/// A length-prefixed `ECHConfigList` of `entries`.
fn config_list<'a>(entries: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let body: Vec<u8> = entries.into_iter().flatten().copied().collect();
    let mut out = Vec::new();
    put_field(&mut out, &body);
    out
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
        for j in 0..4 {
            if j <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * j)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

// --------------------------------------------------------- fuzzed choices

/// A subset of the native suites, never empty unless chosen so.
fn pick_suites(input: &mut Input) -> Vec<&'static dyn Hpke> {
    let all = ALL_SUPPORTED_SUITES;
    match input.choose(5) {
        0 => all.to_vec(),
        1 => {
            let k = input.choose(KEMS.len());
            all[k * 9..k * 9 + 9].to_vec()
        }
        2 => vec![all[input.choose(all.len())]],
        3 => {
            let mask = input.u64();
            let chosen: Vec<_> = (0..all.len())
                .filter(|i| mask >> i & 1 != 0)
                .map(|i| all[i])
                .collect();
            if chosen.is_empty() {
                all.to_vec()
            } else {
                chosen
            }
        }
        _ => Vec::new(),
    }
}

fn pick_name(input: &mut Input) -> Vec<u8> {
    if input.choose(4) == 0 {
        input.short_field().to_vec()
    } else {
        input.pick(NAMES).as_bytes().to_vec()
    }
}

/// `ECHConfig` fields from the input. Returns them and whether the public
/// key is the fixture's key for the KEM (so that a server can decrypt).
fn pick_fields(input: &mut Input) -> (Fields, Option<usize>) {
    let fixture = fixture();
    let version = if input.choose(8) == 0 {
        input.u16()
    } else {
        ECH_VERSION
    };
    let config_id = input.byte();
    let (kem_index, kem) = if input.choose(8) == 0 {
        (None, input.u16())
    } else {
        let k = input.choose(KEMS.len());
        (Some(k), KEMS[k].0)
    };
    let (sound, public_key) = match (kem_index, input.choose(6)) {
        (Some(k), 0..=4) => (Some(k), fixture.pairs[k].0.0.clone()),
        _ => (None, input.short_field().to_vec()),
    };
    let count = input.choose(5);
    let suites = (0..count)
        .map(|_| match input.choose(8) {
            0 => (input.u16(), input.u16()),
            1 => (1, 0xffff),
            _ => (1 + input.choose(3) as u16, 1 + input.choose(3) as u16),
        })
        .collect();
    let maximum_name_length = input.byte();
    let public_name = pick_name(input);
    let count = input.choose(4);
    let extensions = (0..count)
        .map(|_| (input.u16(), input.short_field().to_vec()))
        .collect();
    (
        Fields {
            version,
            config_id,
            kem,
            public_key,
            suites,
            maximum_name_length,
            public_name,
            extensions,
        },
        sound,
    )
}

// ---------------------------------------------------------------- state

/// A server key and whether its `ECHConfig` carries the public half of its
/// private key (so that a server can decrypt what clients seal to it).
struct Key {
    key: EchServerKey,
    sound: bool,
    public_name: Vec<u8>,
}

#[derive(Default)]
struct State {
    keys: Vec<Key>,
    /// GREASE settings, and whether the placeholder key is a real one.
    grease: Option<(EchGreaseConfig, bool)>,
    generations: usize,
    handshakes: usize,
}

impl State {
    fn push(&mut self, key: Key) {
        if self.keys.len() == MAX_KEYS {
            self.keys.remove(0);
        }
        self.keys.push(key);
    }
}

/// The `tls_ech` fuzz target.
///
/// Operations (first byte modulo 8):
///
/// 0. list: suite selector, then a 16-bit-prefixed `ECHConfigList` for
///    [`EchConfig::new`] and the SVCB helpers;
/// 1. config: `ECHConfig` fields (version, id, KEM, public key, suites,
///    maximum name length, public name, extensions) for the server and the
///    client, against the model;
/// 2. generate: id, public name, maximum name length, suites;
/// 3. serve: a mask of the kept keys for [`EchServerConfig::new`];
/// 4. SVCB: wire-format SvcParams or RDATA built from fuzzed parameters,
///    or raw bytes;
/// 5. presentation: 16-bit-prefixed text;
/// 6. GREASE: suite and placeholder key, or a generated one;
/// 7. handshake: scenario, HelloRetryRequest flag, stale configuration
///    fields, and an optional edit of the client's first flight.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut state = State::default();
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.choose(8) {
            0 => list(&mut input),
            1 => config(&mut input, &mut state),
            2 => generate(&mut input, &mut state),
            3 => serve(&mut input, &state),
            4 => svcb(&mut input),
            5 => presentation(&mut input),
            6 => grease(&mut input, &mut state),
            _ => {
                if state.handshakes < MAX_HANDSHAKES {
                    state.handshakes += 1;
                    handshake(&mut input, &mut state);
                }
            }
        }
    }
}

// ----------------------------------------------------------- configuration

/// Checks a configuration the client accepted against `offered`.
fn check_client_config(config: &EchConfig, offered: &[&'static dyn Hpke]) {
    assert!(public_name_ok(config.public_name().as_ref().as_bytes()));
    let suite = config.suite();
    assert!(
        offered.iter().any(|s| s.suite() == suite),
        "selected suite not offered"
    );
    let _ = format!("{config:?}");
}

/// The SVCB helpers must agree on `list`: as an `ech` SvcParam, in RDATA,
/// and in presentation format.
fn check_svcb_agree(list: &[u8]) {
    let presented = ech_config_list_from_presentation(&base64(list));
    if let Ok(decoded) = &presented {
        assert_eq!(decoded, list);
    }
    let quoted = ech_config_list_from_presentation(&format!("\"{}\"", base64(list)));
    assert_eq!(quoted.is_ok(), presented.is_ok());
    if list.len() + 8 > usize::from(u16::MAX) {
        return;
    }
    let mut params = Vec::new();
    params.extend_from_slice(&1u16.to_be_bytes());
    put_field(&mut params, b"\x02h2");
    params.extend_from_slice(&ECH_SVC_PARAM_KEY.to_be_bytes());
    put_field(&mut params, list);
    let from_params = ech_config_list_from_svc_params(&params);
    match (&presented, &from_params) {
        (Ok(_), Ok(Some(found))) => assert_eq!(found, list),
        (Err(_), Err(_)) => {}
        _ => panic!("SVCB helpers disagree: {presented:?} {from_params:?}"),
    }
    let mut rdata = vec![0, 1, 3, b's', b'v', b'c', 0];
    rdata.extend_from_slice(&params);
    let from_rdata = ech_config_list_from_svcb_rdata(&rdata);
    assert_eq!(from_rdata.is_ok(), from_params.is_ok());
    if let (Ok(a), Ok(b)) = (&from_rdata, &from_params) {
        assert_eq!(a, b);
    }
}

fn list(input: &mut Input) {
    let offered = pick_suites(input);
    let bytes = input.field();
    if let Ok(config) = EchConfig::new(bytes, &offered) {
        check_client_config(&config, &offered);
        assert!(
            ech_config_list_from_presentation(&base64(bytes)).is_ok(),
            "a list the client uses is not a well-formed list"
        );
    }
    if !bytes.is_empty() {
        check_svcb_agree(bytes);
    }
}

fn config(input: &mut Input, state: &mut State) {
    let (fields, sound) = pick_fields(input);
    let offered = pick_suites(input);
    let entry = fields.encode();
    let list = config_list([&entry[..]]);
    let fixture = fixture();
    let private_key = fixture.pairs[sound.unwrap_or(0)].1.clone();

    // The client side.
    match EchConfig::new(&list, &offered) {
        Ok(config) => {
            assert!(fields.usable_by_client(&offered), "{fields:?}");
            check_client_config(&config, &offered);
            assert_eq!(config.config_id(), fields.config_id);
            assert_eq!(
                config.public_name().as_ref().as_bytes(),
                &fields.public_name[..]
            );
            let (kdf, aead) = fields.client_suite(&offered).expect("model suite");
            let suite = config.suite();
            assert_eq!(
                (suite.kem.0, suite.sym.kdf_id.0, suite.sym.aead_id.0),
                (fields.kem, kdf, aead)
            );
        }
        Err(_) => assert!(!fields.usable_by_client(&offered), "{fields:?}"),
    }

    // The server side.
    match EchServerKey::new(&entry, private_key, &offered) {
        Ok(key) => {
            assert!(fields.usable_by_server(&offered), "{fields:?}");
            assert_eq!(key.ech_config(), &entry[..], "ECHConfig re-encoding");
            assert_eq!(key.config_id(), fields.config_id);
            assert_eq!(key.kem().0, fields.kem);
            let _ = format!("{key:?}");
            let server = EchServerConfig::new(vec![key.clone()]).expect("one key");
            assert_eq!(server.ech_config_list(), &list[..]);
            state.push(Key {
                key,
                sound: sound.is_some(),
                public_name: fields.public_name.clone(),
            });
        }
        Err(_) => assert!(!fields.usable_by_server(&offered), "{fields:?}"),
    }
    check_svcb_agree(&list);
}

fn generate(input: &mut Input, state: &mut State) {
    let config_id = input.byte();
    let name = pick_name(input);
    let maximum_name_length = input.byte();
    let offered = pick_suites(input);
    if state.generations == MAX_GENERATIONS {
        return;
    }
    state.generations += 1;
    let Ok(text) = String::from_utf8(name.clone()) else {
        return;
    };
    let expected = !offered.is_empty() && public_name_ok(&name);
    let key = match EchServerKey::generate(config_id, &text, maximum_name_length, &offered) {
        Ok(key) => {
            assert!(expected, "generated with {text:?}");
            key
        }
        Err(_) => {
            assert!(!expected, "refused {text:?}");
            return;
        }
    };
    let kem = offered[0].suite().kem;
    assert_eq!(key.config_id(), config_id);
    assert_eq!(key.kem(), kem);
    assert!(!key.private_key().secret_bytes().is_empty());

    // The configuration is the model's encoding of what was asked for.
    let entry = key.ech_config();
    let pk_len = usize::from(u16::from_be_bytes([entry[7], entry[8]]));
    let mut suites = Vec::new();
    for s in &offered {
        let s = s.suite();
        if s.kem == kem {
            suites.push((s.sym.kdf_id.0, s.sym.aead_id.0));
        }
    }
    let fields = Fields {
        version: ECH_VERSION,
        config_id,
        kem: kem.0,
        public_key: entry[9..9 + pk_len].to_vec(),
        suites,
        maximum_name_length,
        public_name: name.clone(),
        extensions: Vec::new(),
    };
    assert_eq!(entry, &fields.encode()[..]);

    // A stored key round-trips through its parts.
    let again = EchServerKey::new(entry, key.private_key().clone(), &offered)
        .expect("a generated key loads");
    assert_eq!(again.ech_config(), entry);
    let list = config_list([entry]);
    let client = EchConfig::new(&list, &offered).expect("a generated key's config is usable");
    assert_eq!(client.config_id(), config_id);
    assert_eq!(client.public_name().as_ref().as_bytes(), &name[..]);
    state.push(Key {
        key,
        sound: true,
        public_name: name,
    });
}

fn serve(input: &mut Input, state: &State) {
    let mask = input.byte();
    let keys: Vec<EchServerKey> = state
        .keys
        .iter()
        .enumerate()
        .filter(|(i, _)| mask >> i & 1 != 0)
        .map(|(_, k)| k.key.clone())
        .collect();
    let entries: Vec<Vec<u8>> = keys.iter().map(|k| k.ech_config().to_vec()).collect();
    let total: usize = entries.iter().map(Vec::len).sum();
    match EchServerConfig::new(keys) {
        Ok(server) => {
            assert!(!entries.is_empty() && total <= usize::from(u16::MAX));
            let expected = config_list(entries.iter().map(Vec::as_slice));
            assert_eq!(server.ech_config_list(), &expected[..]);
            // A client takes the first configuration it can use.
            if let Ok(config) = EchConfig::new(server.ech_config_list(), ALL_SUPPORTED_SUITES) {
                let first = state
                    .keys
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask >> i & 1 != 0)
                    .map(|(_, k)| k)
                    .find(|k| {
                        EchConfig::new(&config_list([k.key.ech_config()]), ALL_SUPPORTED_SUITES)
                            .is_ok()
                    })
                    .expect("a usable key");
                assert_eq!(config.config_id(), first.key.config_id());
            }
            check_svcb_agree(server.ech_config_list());
        }
        Err(_) => assert!(entries.is_empty() || total > usize::from(u16::MAX)),
    }
}

// -------------------------------------------------------------------- SVCB

/// RFC 9460 §2.2 SvcParams: strictly increasing keys, each with a 16-bit
/// length; the `ech` value must be a well-formed list.
fn model_svc_params(params: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    let mut at = 0;
    let mut last: Option<u16> = None;
    let mut found = None;
    while at < params.len() {
        let header = params.get(at..at + 4).ok_or(())?;
        let key = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let value = params.get(at + 4..at + 4 + len).ok_or(())?;
        if last.is_some_and(|prev| key <= prev) {
            return Err(());
        }
        last = Some(key);
        if key == ECH_SVC_PARAM_KEY {
            // Well-formedness of the list itself, decided by the
            // presentation decoder (checked against the other helpers in
            // `check_svcb_agree`).
            if value.is_empty() || ech_config_list_from_presentation(&base64(value)).is_err() {
                return Err(());
            }
            found = Some(value.to_vec());
        }
        at += 4 + len;
    }
    Ok(found)
}

fn svcb(input: &mut Input) {
    let raw = input.bool();
    if raw {
        let bytes = input.field();
        let params = ech_config_list_from_svc_params(bytes);
        assert_eq!(params.as_ref().ok(), model_svc_params(bytes).ok().as_ref());
        let rdata = ech_config_list_from_svcb_rdata(bytes);
        if let Ok(Some(list)) = rdata.as_ref().map(Option::as_deref) {
            assert!(ech_config_list_from_presentation(&base64(list)).is_ok());
        }
        return;
    }
    // Parameters from fuzzed keys, usually with a usable ech value.
    let fixture = fixture();
    let good = Fields {
        version: ECH_VERSION,
        config_id: 1,
        kem: KEMS[0].0,
        public_key: fixture.pairs[0].0.0.clone(),
        suites: vec![(1, 1)],
        maximum_name_length: 0,
        public_name: PUBLIC.as_bytes().to_vec(),
        extensions: Vec::new(),
    }
    .encode();
    let good = config_list([&good[..]]);
    let mut params = Vec::new();
    let count = input.choose(6);
    for _ in 0..count {
        let key = match input.choose(4) {
            0 => ECH_SVC_PARAM_KEY,
            _ => input.u16() & 0x0f,
        };
        let value = if key == ECH_SVC_PARAM_KEY && input.bool() {
            good.clone()
        } else {
            input.short_field().to_vec()
        };
        params.extend_from_slice(&key.to_be_bytes());
        // A declared length past the end, sometimes.
        let declared = if input.choose(8) == 0 {
            value.len() + 1
        } else {
            value.len()
        };
        params.extend_from_slice(&(declared as u16).to_be_bytes());
        params.extend_from_slice(&value);
    }
    let from_params = ech_config_list_from_svc_params(&params);
    assert_eq!(
        from_params.as_ref().ok(),
        model_svc_params(&params).ok().as_ref(),
        "{params:?}"
    );

    // RDATA: priority, target name labels, params.
    let priority = input.u16();
    let mut rdata = priority.to_be_bytes().to_vec();
    let labels = input.choose(4);
    let mut target_ok = true;
    for _ in 0..labels {
        let len = match input.choose(8) {
            0 => 64,
            _ => input.choose(10),
        };
        if len == 0 {
            break;
        }
        target_ok &= len <= 63;
        rdata.push(len as u8);
        rdata.extend(std::iter::repeat_n(b'a', len));
    }
    rdata.push(0);
    rdata.extend_from_slice(&params);
    let from_rdata = ech_config_list_from_svcb_rdata(&rdata);
    match (target_ok, priority, &from_rdata) {
        (false, _, result) => assert!(result.is_err()),
        (true, 0, result) => assert_eq!(result, &Ok(None)),
        (true, _, result) => assert_eq!(result.as_ref().ok(), from_params.as_ref().ok()),
    }
}

fn presentation(input: &mut Input) {
    let bytes = input.field();
    let Ok(text) = core::str::from_utf8(bytes) else {
        return;
    };
    if let Ok(list) = ech_config_list_from_presentation(text) {
        // Decoded lists are well formed and re-encode.
        assert_eq!(
            ech_config_list_from_presentation(&base64(&list)).as_ref(),
            Ok(&list)
        );
        let _ = EchConfig::new(&list, ALL_SUPPORTED_SUITES);
    }
}

fn grease(input: &mut Input, state: &mut State) {
    let suite = *input.pick(ALL_SUPPORTED_SUITES);
    let mut valid = true;
    let config = if input.bool() {
        EchGreaseConfig::generate(suite).expect("GREASE key generation")
    } else {
        let fixture = fixture();
        let kem = KEMS
            .iter()
            .position(|k| *k == suite.suite().kem)
            .unwrap_or(0);
        let placeholder = if input.bool() {
            fixture.pairs[kem].0.clone()
        } else {
            valid = false;
            HpkePublicKey(input.short_field().to_vec())
        };
        EchGreaseConfig::new(suite, placeholder)
    };
    let _ = format!("{config:?}");
    state.grease = Some((config, valid));
}

// --------------------------------------------------------------- handshake

/// Moves everything `from` has to send into `to`, through `edit`.
fn send<A: browntls::SideData, B: browntls::SideData>(
    from: &mut browntls::ConnectionCommon<A>,
    to: &mut browntls::ConnectionCommon<B>,
    edit: &mut Option<(usize, u8)>,
) {
    let mut buf = Vec::new();
    while from.wants_write() {
        if from.write_tls(&mut buf).is_err() {
            break;
        }
    }
    if let Some((at, x)) = edit.take()
        && !buf.is_empty()
    {
        let at = at % buf.len();
        buf[at] ^= x;
    }
    let mut rest = &buf[..];
    while !rest.is_empty() {
        match to.read_tls(&mut rest) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Runs the handshake, applying `edit` to the client's first flight;
/// returns each side's first error.
fn pump(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    mut edit: Option<(usize, u8)>,
) -> (Result<(), Error>, Result<(), Error>) {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        send(client, server, &mut edit);
        if let Err(e) = server.process_new_packets() {
            send(server, client, &mut None);
            let client_res = client.process_new_packets().map(|_| ());
            return (client_res, Err(e));
        }
        send(server, client, &mut None);
        if let Err(e) = client.process_new_packets() {
            send(client, server, &mut None);
            let server_res = server.process_new_packets().map(|_| ());
            return (Err(e), server_res);
        }
    }
    (Ok(()), Ok(()))
}

fn server_config(ech: Option<Arc<EchServerConfig>>, hrr: bool) -> Arc<ServerConfig> {
    let fixture = fixture();
    let mut provider = browntls::crypto::native::default_provider();
    if hrr {
        // The client's first key share is not P-256.
        provider.kx_groups = vec![browntls::crypto::native::kx_group::SECP256R1];
    }
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            fixture.chain.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture.key.clone())),
        )
        .expect("server certificate");
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ech = ech;
    Arc::new(config)
}

/// A client offering `mode` and a server. The client may fail to start
/// (sealing to an invalid public key) unless `must` says it may not.
fn connect(
    mode: EchMode,
    server: &Arc<ServerConfig>,
    must: bool,
) -> Option<(ClientConnection, ServerConnection)> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(browntls::crypto::native::default_provider()))
            .with_protocol_versions(&[&version::TLS13])
            .expect("versions")
            .with_root_certificates(fixture().roots.clone())
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.ech_mode = Some(mode);
    let name = ServerName::try_from(SECRET).expect("name");
    let client = match ClientConnection::new(Arc::new(config), name) {
        Ok(client) => client,
        Err(e) => {
            assert!(!must, "client: {e:?}");
            return None;
        }
    };
    let server = ServerConnection::new(server.clone()).expect("server");
    Some((client, server))
}

/// Both sides accepted ECH: the server saw the inner hello.
fn assert_accepted(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(server.ech_status(), EchStatus::Accepted);
    assert_eq!(server.server_name(), Some(SECRET));
    assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
    client.writer().write_all(b"hidden").expect("write");
    send(client, server, &mut None);
    server.process_new_packets().expect("server reads");
    let mut got = [0u8; 6];
    server.reader().read_exact(&mut got).expect("data");
    assert_eq!(&got, b"hidden");
}

/// The default sound key: X25519, `public.example`.
fn default_key(config_id: u8, maximum_name_length: u8) -> EchServerKey {
    let fixture = fixture();
    let fields = Fields {
        version: ECH_VERSION,
        config_id,
        kem: KEMS[0].0,
        public_key: fixture.pairs[0].0.0.clone(),
        suites: vec![(1, 1), (1, 3)],
        maximum_name_length,
        public_name: PUBLIC.as_bytes().to_vec(),
        extensions: Vec::new(),
    };
    EchServerKey::new(
        &fields.encode(),
        fixture.pairs[0].1.clone(),
        ALL_SUPPORTED_SUITES,
    )
    .expect("default key")
}

/// Handshake input: scenario (accepted, stale, no server ECH, GREASE),
/// HelloRetryRequest flag, config id and maximum name length for the
/// default and stale keys, whether to serve the kept keys, the flight edit
/// flag, offset (16 bits) and XOR byte.
fn handshake(input: &mut Input, state: &mut State) {
    let scenario = input.choose(4);
    let hrr = input.bool();
    let config_id = input.byte();
    let maximum_name_length = input.byte();
    let use_kept = input.bool();
    let edit = input
        .bool()
        .then(|| (usize::from(input.u16()), input.byte() | 1));
    let edited = edit.is_some();

    // The server's keys: the newest kept one, or the default.
    let (key, sound, public_name) = match state.keys.last() {
        Some(k) if use_kept => (k.key.clone(), k.sound, k.public_name.clone()),
        _ => (
            default_key(config_id, maximum_name_length),
            true,
            PUBLIC.as_bytes().to_vec(),
        ),
    };
    let current = Arc::new(EchServerConfig::new(vec![key]).expect("one key"));

    match scenario {
        0 => {
            // Accepted.
            let Ok(config) = EchConfig::new(current.ech_config_list(), ALL_SUPPORTED_SUITES) else {
                return;
            };
            let server = server_config(Some(current.clone()), hrr);
            let Some((mut client, mut server)) = connect(EchMode::Enable(config), &server, sound)
            else {
                return;
            };
            assert_eq!(client.ech_status(), EchStatus::Offered);
            let (client_res, server_res) = pump(&mut client, &mut server, edit);
            if sound && !edited {
                assert!(
                    client_res.is_ok() && server_res.is_ok(),
                    "{client_res:?} {server_res:?}"
                );
                assert_accepted(&mut client, &mut server);
            }
        }
        1 => {
            // Rejected: the client has a configuration whose key the
            // server lacks (with a fuzzed id, possibly the server's).
            let fixture = fixture();
            let stale = Fields {
                version: ECH_VERSION,
                config_id,
                kem: KEMS[0].0,
                public_key: fixture.stale.0.clone(),
                suites: vec![(1, 1)],
                maximum_name_length,
                public_name: PUBLIC.as_bytes().to_vec(),
                extensions: Vec::new(),
            };
            let list = config_list([&stale.encode()[..]]);
            let config = EchConfig::new(&list, ALL_SUPPORTED_SUITES).expect("stale config");
            let server = server_config(Some(current.clone()), hrr);
            let (mut client, mut server_conn) =
                connect(EchMode::Enable(config), &server, true).expect("stale client");
            let (client_res, server_res) = pump(&mut client, &mut server_conn, edit);
            if edited {
                return;
            }
            assert_eq!(client.ech_status(), EchStatus::Rejected);
            assert_eq!(server_conn.ech_status(), EchStatus::Rejected);
            assert!(server_res.is_err(), "the server learns of the rejection");
            let Err(Error::RejectedEch(rejected)) = client_res else {
                panic!("expected a rejection: {client_res:?}");
            };
            assert_eq!(rejected.retry_configs(), Some(current.ech_config_list()));
            let usable = EchConfig::new(current.ech_config_list(), ALL_SUPPORTED_SUITES);
            assert!(!usable.is_ok() || rejected.can_retry());
            // The retry with the server's configuration.
            let Ok(retry) = usable else {
                return;
            };
            let Some((mut client, mut server_conn)) =
                connect(EchMode::Enable(retry), &server, sound)
            else {
                return;
            };
            let (client_res, server_res) = pump(&mut client, &mut server_conn, None);
            if sound {
                assert!(
                    client_res.is_ok() && server_res.is_ok(),
                    "{client_res:?} {server_res:?}"
                );
                assert_accepted(&mut client, &mut server_conn);
            }
        }
        2 => {
            // Rejected by a server without ECH.
            let Ok(config) = EchConfig::new(current.ech_config_list(), ALL_SUPPORTED_SUITES) else {
                return;
            };
            let server = server_config(None, hrr);
            let Some((mut client, mut server_conn)) =
                connect(EchMode::Enable(config), &server, sound)
            else {
                return;
            };
            let (client_res, _) = pump(&mut client, &mut server_conn, edit);
            if edited {
                return;
            }
            assert_eq!(server_conn.ech_status(), EchStatus::NotOffered);
            if public_name == PUBLIC.as_bytes() || public_name == SECRET.as_bytes() {
                // The rejection authenticates with the public name.
                let Err(Error::RejectedEch(rejected)) = client_res else {
                    panic!("expected a rejection: {client_res:?}");
                };
                assert_eq!(rejected.retry_configs(), None);
                assert!(!rejected.can_retry());
            } else {
                // No certificate for that name: the client must not
                // complete.
                assert!(client_res.is_err());
            }
            assert_eq!(client.ech_status(), EchStatus::Rejected);
        }
        _ => {
            // GREASE, against a server with or without ECH.
            let (config, valid) = match &state.grease {
                Some((g, valid)) => (g.clone(), *valid),
                None => (
                    EchGreaseConfig::generate(ALL_SUPPORTED_SUITES[0]).expect("GREASE"),
                    true,
                ),
            };
            let with_ech = config_id & 1 != 0;
            let server = server_config(with_ech.then(|| current.clone()), hrr);
            let Some((mut client, mut server_conn)) =
                connect(EchMode::Grease(config), &server, valid)
            else {
                return;
            };
            let (client_res, server_res) = pump(&mut client, &mut server_conn, edit);
            if !edited {
                assert!(
                    client_res.is_ok() && server_res.is_ok(),
                    "{client_res:?} {server_res:?}"
                );
                assert_eq!(client.ech_status(), EchStatus::Grease);
                let expected = if with_ech {
                    EchStatus::Rejected
                } else {
                    EchStatus::NotOffered
                };
                assert_eq!(server_conn.ech_status(), expected);
                assert_eq!(server_conn.server_name(), Some(SECRET));
            }
        }
    }
}

// ------------------------------------------------------------------- seeds

/// How a seed asks [`pick_fields`] for a cipher suite.
#[derive(Clone, Copy)]
enum SuiteSeed {
    /// KDF and AEAD indices (0 to 2) of the native suites.
    Known(u8, u8),
    ExportOnly,
    Raw(u16, u16),
}

/// The input [`pick_fields`] reads for these fields. `kem` is an index of
/// [`KEMS`] (or a raw KEM id with `raw_kem`); `public_key` replaces the
/// fixture's key.
struct FieldsSeed<'a> {
    version: Option<u16>,
    config_id: u8,
    kem: u8,
    raw_kem: Option<u16>,
    public_key: Option<&'a [u8]>,
    suites: &'a [SuiteSeed],
    maximum_name_length: u8,
    /// An index of [`NAMES`], or raw bytes.
    name: Result<u8, &'a [u8]>,
    extensions: &'a [(u16, &'a [u8])],
}

impl FieldsSeed<'_> {
    const DEFAULT: FieldsSeed<'static> = FieldsSeed {
        version: None,
        config_id: 7,
        kem: 0,
        raw_kem: None,
        public_key: None,
        suites: &[SuiteSeed::Known(0, 0)],
        maximum_name_length: 32,
        name: Ok(0),
        extensions: &[],
    };

    fn write(&self, out: &mut Vec<u8>) {
        match self.version {
            Some(v) => {
                out.push(0);
                out.extend_from_slice(&v.to_be_bytes());
            }
            None => out.push(1),
        }
        out.push(self.config_id);
        match self.raw_kem {
            Some(kem) => {
                out.push(0);
                out.extend_from_slice(&kem.to_be_bytes());
            }
            None => out.extend_from_slice(&[1, self.kem]),
        }
        match (self.raw_kem, self.public_key) {
            (None, None) => out.push(0),
            (None, Some(pk)) => {
                out.push(5);
                put_short_field(out, pk);
            }
            (Some(_), pk) => {
                out.push(0);
                put_short_field(out, pk.unwrap_or(b"key"));
            }
        }
        out.push(self.suites.len() as u8);
        for suite in self.suites {
            match *suite {
                SuiteSeed::Known(kdf, aead) => out.extend_from_slice(&[2, kdf, aead]),
                SuiteSeed::ExportOnly => out.push(1),
                SuiteSeed::Raw(kdf, aead) => {
                    out.push(0);
                    out.extend_from_slice(&kdf.to_be_bytes());
                    out.extend_from_slice(&aead.to_be_bytes());
                }
            }
        }
        out.push(self.maximum_name_length);
        match self.name {
            Ok(index) => out.extend_from_slice(&[1, index]),
            Err(raw) => {
                out.push(0);
                put_short_field(out, raw);
            }
        }
        out.push(self.extensions.len() as u8);
        for (typ, data) in self.extensions {
            out.extend_from_slice(&typ.to_be_bytes());
            put_short_field(out, data);
        }
    }
}

/// A handshake operation: scenario, HelloRetryRequest, config id, maximum
/// name length, kept key, edit.
fn handshake_seed(scenario: u8, hrr: bool, config_id: u8, kept: bool, edit: bool) -> Vec<u8> {
    let mut seed = vec![
        7,
        scenario,
        u8::from(hrr),
        config_id,
        32,
        u8::from(kept),
        u8::from(edit),
    ];
    if edit {
        seed.extend_from_slice(&[0x01, 0x20, 0x40]);
    }
    seed
}

/// Starting inputs for `tls_ech`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let fixture = fixture();
    let mut seeds = Vec::new();

    let example = Fields {
        version: ECH_VERSION,
        config_id: 1,
        kem: KEMS[0].0,
        public_key: fixture.pairs[0].0.0.clone(),
        suites: vec![(1, 1)],
        maximum_name_length: 100,
        public_name: b"ech-sites.example.net".to_vec(),
        extensions: Vec::new(),
    };
    let list = config_list([&example.encode()[..]]);

    // 0: a list, for all suites, one KEM, one suite, a mask, and none
    for suites in [
        &[0u8][..],
        &[1, 0],
        &[2, 0],
        &[3, 0, 0, 0, 0, 0, 0, 0, 3],
        &[4],
    ] {
        let mut seed = vec![0];
        seed.extend_from_slice(suites);
        put_field(&mut seed, &list);
        seeds.push(seed);
    }

    // 1: configurations, all suites offered: each KEM with its key, then
    // variants the model must judge
    let base = FieldsSeed::DEFAULT;
    let mut configs: Vec<FieldsSeed<'_>> = (0..5u8)
        .map(|kem| FieldsSeed {
            kem,
            suites: &[SuiteSeed::Known(1, 2), SuiteSeed::Known(0, 0)],
            ..FieldsSeed::DEFAULT
        })
        .collect();
    configs.extend([
        FieldsSeed {
            public_key: Some(b"not a key"),
            ..base
        },
        FieldsSeed {
            version: Some(0xfe0c),
            ..base
        },
        FieldsSeed {
            raw_kem: Some(0x0099),
            ..base
        },
        FieldsSeed {
            extensions: &[(0x8001, b"x")],
            ..base
        },
        FieldsSeed {
            extensions: &[(0x0001, b"x"), (0x0001, b"")],
            ..base
        },
        FieldsSeed {
            extensions: &[(0x0001, b"x"), (0x0002, b"")],
            ..base
        },
        FieldsSeed {
            suites: &[],
            ..base
        },
        FieldsSeed {
            suites: &[SuiteSeed::ExportOnly, SuiteSeed::Raw(9, 9)],
            ..base
        },
        FieldsSeed {
            public_key: Some(b""),
            ..base
        },
        FieldsSeed {
            name: Err(b""),
            ..base
        },
        FieldsSeed {
            name: Err(b"\xff.example"),
            ..base
        },
    ]);
    for index in 2..NAMES.len() as u8 {
        configs.push(FieldsSeed {
            name: Ok(index),
            ..base
        });
    }
    for fields in &configs {
        let mut seed = vec![1];
        fields.write(&mut seed);
        seed.push(0);
        seeds.push(seed);
    }
    // a configuration served with a suite subset that does not match
    let mut seed = vec![1];
    base.write(&mut seed);
    seed.extend_from_slice(&[1, 2]);
    seeds.push(seed);

    // 2: generate for every KEM, with a bad name, with no suites; then
    // serve two kept keys
    for kem in 0..5u8 {
        seeds.push(vec![2, 3, 1, 0, 32, 1, kem]);
    }
    seeds.push(vec![2, 3, 1, 6, 0, 0]);
    seeds.push(vec![2, 3, 1, 0, 0, 4]);
    let mut seed = vec![2, 4, 0];
    put_short_field(&mut seed, b"ok.example");
    seed.extend_from_slice(&[0, 0, 2, 5, 1, 0, 0, 0, 3, 0b11, 3, 0]);
    seeds.push(seed);

    // 4: SVCB, raw and built
    let mut params = Vec::new();
    params.extend_from_slice(&1u16.to_be_bytes());
    put_field(&mut params, b"\x02h2");
    params.extend_from_slice(&ECH_SVC_PARAM_KEY.to_be_bytes());
    put_field(&mut params, &list);
    let mut seed = vec![4, 1];
    put_field(&mut seed, &params);
    seed.extend_from_slice(&[4, 1]);
    let mut rdata = vec![0, 1, 0];
    rdata.extend_from_slice(&params);
    put_field(&mut seed, &rdata);
    seeds.push(seed);
    // built: alpn-like key 1, then ech with the good list; priority 1; one
    // label
    let mut seed = vec![4, 0, 2];
    seed.extend_from_slice(&[1, 0, 1]);
    put_short_field(&mut seed, b"\x02h2");
    seed.extend_from_slice(&[1, 0, 1, 1, 0, 1, 1, 1, 3]);
    seeds.push(seed);
    // AliasMode; a label too long; out-of-order keys; a bad ech value
    seeds.push(vec![4, 0, 0, 0, 0, 0]);
    seeds.push(vec![4, 0, 0, 0, 1, 1, 0]);
    let mut seed = vec![4, 0, 2, 1, 0, 6];
    put_short_field(&mut seed, b"a");
    seed.extend_from_slice(&[1, 1, 0, 1]);
    put_short_field(&mut seed, b"b");
    seed.extend_from_slice(&[1, 0, 1, 0]);
    seeds.push(seed);
    let mut seed = vec![4, 0, 1, 0, 0];
    put_short_field(&mut seed, b"\x00\x01\x02");
    seed.extend_from_slice(&[1, 0, 1, 0]);
    seeds.push(seed);

    // 5: presentation
    for text in [
        base64(&list),
        format!("\"{}\"", base64(&list)),
        "AE j=".into(),
        "AAA=".into(),
    ] {
        let mut seed = vec![5];
        put_field(&mut seed, text.as_bytes());
        seeds.push(seed);
    }

    // 7: handshakes: accepted (with and without HelloRetryRequest), stale
    // (twice, one sharing the server's id), no server ECH, GREASE without
    // and with server ECH, and an edited flight
    for (scenario, hrr, id) in [
        (0u8, false, 7u8),
        (0, true, 7),
        (1, false, 7),
        (1, true, 8),
        (2, false, 7),
        (3, false, 0),
        (3, true, 1),
    ] {
        seeds.push(handshake_seed(scenario, hrr, id, false, false));
    }
    seeds.push(handshake_seed(0, false, 7, false, true));
    // GREASE settings (generated, fixture placeholder, fuzzed placeholder),
    // then a handshake using them
    for grease in [&[6u8, 9, 1][..], &[6, 18, 0, 1], &[6, 27, 0, 0, 1, 7]] {
        let mut seed = grease.to_vec();
        seed.extend_from_slice(&handshake_seed(3, false, 1, false, false));
        seeds.push(seed);
    }
    // a generated key (P-256), then each scenario with it; a configured
    // key with a name lacking a certificate, then no server ECH
    for scenario in 0..3u8 {
        let mut seed = vec![2, 3, 1, 0, 32, 1, 1];
        seed.extend_from_slice(&handshake_seed(scenario, false, 9, true, false));
        seeds.push(seed);
    }
    let mut seed = vec![1];
    FieldsSeed {
        name: Ok(2),
        ..base
    }
    .write(&mut seed);
    seed.push(0);
    seed.extend_from_slice(&handshake_seed(2, false, 9, true, false));
    seeds.push(seed);
    seeds
}
