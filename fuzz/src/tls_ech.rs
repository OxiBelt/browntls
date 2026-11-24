//! Encrypted Client Hello (`fuzz_targets/tls_ech.rs`).
//!
//! Reaches every public function of `browntls_core::ech` and
//! `browntls_core::ech::svcb`: `ECHConfigList` parsing of fuzzed bytes
//! ([`EchConfig::new`]), server keys from fuzz-chosen `ECHConfig` fields
//! ([`EchServerKey::new`]) and generated ones ([`EchServerKey::generate`]),
//! [`EchServerConfig`] lists, GREASE settings, the SVCB/HTTPS record helpers,
//! and TLS 1.3 handshakes between a client and a server in the same process:
//! ECH accepted (optionally after a HelloRetryRequest), rejected with retry
//! configurations and retried, rejected by a server without ECH, and GREASE,
//! optionally with a byte of the client's first flight altered; and the same
//! through split mode (RFC 9849 §3.1): a [`ClientFacing`] server forwarding to
//! a back-end server ([`ServerConfig::ech_backend`]) or completing the
//! handshake locally, fed in fuzz-chosen pieces, optionally with trial
//! decryption, random configuration identifiers and the public name check.
//!
//! Checked properties: the configuration parsers agree with an independent
//! model of RFC 9849 §4 (version, mandatory extensions, public name rules of
//! §6.1.7, suite selection); a server key re-encodes its `ECHConfig`
//! byte for byte and a server configuration lists exactly its keys; a
//! generated key round-trips through its parts; the three SVCB helpers agree
//! with each other and with a model of RFC 9460 §2.2; the handshakes end in
//! the documented states (both sides `Accepted` with the inner server name,
//! `RejectedEch` with the server's retry configurations, which then
//! succeed, or none for a server without ECH; GREASE completes); in split
//! mode the client-facing server forwards exactly the accepted offers,
//! names the inner server, relays application data unmodified, keeps every
//! byte it received for a local server, and reports a fatal error with a
//! plaintext alert.
//!
//! Input: up to 32 operations, each an operation byte followed by its
//! arguments (see [`run`]); at most two handshake operations per input.
//!
//! [`EchConfig::new`]: browntls_core::ech::EchConfig::new
//! [`EchServerConfig`]: browntls_core::ech::EchServerConfig
//! [`ClientFacing`]: browntls_core::ech::split::ClientFacing
//! [`ServerConfig::ech_backend`]: browntls_core::ServerConfig::ech_backend

use std::sync::{Arc, OnceLock};

use browntls_core::RootCertStore;
use browntls_core::crypto::hpke::{Hpke, HpkeKem, HpkePrivateKey, HpkePublicKey};
use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use browntls_core::ech::{EchGreaseConfig, EchServerKey};
use browntls_core::pki_types::{CertificateDer, DnsName};

use self::config::{config, generate, grease, list, presentation, serve, svcb};
use self::handshake::handshake;
use crate::input::{Input, put_field, put_short_field};

mod config;
mod handshake;
mod pem;
mod seeds;
mod split;

pub use self::seeds::seeds;

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
        .map(|_| match input.choose(9) {
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
/// Operations (first byte modulo 9):
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
/// 7. handshake: scenario (shared mode: accepted, stale, no server ECH,
///    GREASE; split mode: accepted, stale or GREASE, and accepted with
///    random identifiers), HelloRetryRequest flag, stale configuration
///    fields, an optional edit of the client's first flight, and for split
///    mode the variant and the size of the pieces;
/// 8. PEM: arbitrary RFC 9934 bytes or PKCS #8, or a fixture-key round trip.
///
/// [`EchConfig::new`]: browntls_core::ech::EchConfig::new
/// [`EchServerConfig::new`]: browntls_core::ech::EchServerConfig::new
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut state = State::default();
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.choose(9) {
            0 => list(&mut input),
            1 => config(&mut input, &mut state),
            2 => generate(&mut input, &mut state),
            3 => serve(&mut input, &state),
            4 => svcb(&mut input),
            5 => presentation(&mut input),
            6 => grease(&mut input, &mut state),
            8 => pem::run(&mut input),
            _ => {
                if state.handshakes < MAX_HANDSHAKES {
                    state.handshakes += 1;
                    handshake(&mut input, &mut state);
                }
            }
        }
    }
}
