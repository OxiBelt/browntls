//! Delegated credentials and exported authenticators
//! (`fuzz_targets/tls_auth.rs`).
//!
//! Reaches every public function of `browntls::delegated_credential`,
//! `browntls::crypto::native::delegated_credential` and
//! `browntls::exported_authenticator`:
//!
//! * [`DelegatedCredential`] decoding of fuzzed bytes and encoding of
//!   fuzzed fields, issuance ([`DelegatedCredential::issue`] and the native
//!   [`generate`]) with fuzz-chosen certificates, schemes, keys and
//!   validity, [`DelegatedCredentialKey`], [`valid_time_until`] and expiry;
//! * TLS 1.3 handshakes with a delegated credential whose validity, the
//!   peers' clocks and an optional tampering are fuzz-chosen, so that the
//!   expiry and seven-day boundaries of RFC 9345 §4.1.3 are crossed;
//! * RFC 9261 exported authenticators between a connected client and server
//!   (TLS 1.3 or TLS 1.2): requests with fuzzed contexts and extensions,
//!   answers with fuzz-chosen certificates or declined, spontaneous server
//!   authenticators, tampered and replayed authenticators, and fuzzed
//!   request and authenticator bytes.
//!
//! Checked properties: decoding matches an independent parser of RFC 9345
//! §4 and re-encodes byte for byte; issuance succeeds exactly when the
//! documented conditions hold, and its signature verifies over
//! `signed_message` (which matches an independent construction) while any
//! tampering makes verification fail; generated keys match their
//! credential; a peer accepts a credential exactly when it is within its
//! validity window and untampered; an authenticator validates once, for the
//! request it answers, with the expected chain (or none when declined);
//! any altered, replayed or fuzzed authenticator is rejected.
//!
//! Input: up to 32 operations, each an operation byte followed by its
//! arguments (see [`run`]).
//!
//! [`generate`]: browntls::crypto::native::delegated_credential::generate
//! [`DelegatedCredentialKey`]: browntls::delegated_credential::DelegatedCredentialKey
//! [`valid_time_until`]: browntls::delegated_credential::valid_time_until

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use browntls::crypto::{CryptoProvider, verify_tls13_signature};
use browntls::delegated_credential::{Credential, DelegatedCredential, MAX_VALIDITY};
use browntls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
};
use browntls::sign::{CertifiedKey, SigningKey};
use browntls::time_provider::TimeProvider;
use browntls::{DigitallySignedStruct, RootCertStore, Side, SignatureScheme};

use self::credential::{decode, encode, issue, native_generate, validity};
use self::exported::{Ea, exported};
use self::handshake::handshake;
use crate::input::Input;

mod credential;
mod exported;
mod handshake;
mod seeds;

pub use self::seeds::seeds;

/// Operations per input.
const MAX_OPS: usize = 32;

/// Delegated-credential handshakes per input.
const MAX_HANDSHAKES: usize = 2;

/// Native key generations per input.
const MAX_GENERATIONS: usize = 2;

/// Exported-authenticator operations per input.
const MAX_AUTHENTICATORS: usize = 8;

/// The local bound on a credential's public key (RFC 9345 allows 2^24-1).
const MAX_SPKI_LEN: usize = 0x4000;

const SERVER_CONTEXT: &[u8] = b"TLS, server delegated credentials";
const CLIENT_CONTEXT: &[u8] = b"TLS, client delegated credentials";

const SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED448,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::ML_DSA_44,
];

// ----------------------------------------------------------------- fixture

/// A fixed clock.
#[derive(Debug)]
struct FixedTime(UnixTime);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
}

fn unix(secs: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(secs))
}

/// A delegated-credential key the fixture holds.
struct DcKey {
    scheme: SignatureScheme,
    key: Arc<dyn SigningKey>,
    spki: SubjectPublicKeyInfoDer<'static>,
}

/// Certificates and keys made once per process.
struct Fixture {
    provider: Arc<CryptoProvider>,
    roots: Arc<RootCertStore>,
    /// A P-256 `localhost` certificate that permits delegation, valid from
    /// `not_before` to `not_after`.
    delegation: CertificateDer<'static>,
    delegation_pkcs8: Vec<u8>,
    delegation_key: Arc<dyn SigningKey>,
    /// A P-256 `localhost` certificate without `DelegationUsage`.
    plain: CertificateDer<'static>,
    plain_key: Arc<dyn SigningKey>,
    not_before: u64,
    not_after: u64,
    /// Credential keys: ECDSA P-256 and Ed25519.
    dc_keys: Vec<DcKey>,
    /// Exported-authenticator identities: a server certificate for
    /// `localhost` (P-256), one for another name, and a client certificate
    /// (Ed25519).
    ea_server: CertifiedKey,
    ea_other: CertifiedKey,
    ea_client: CertifiedKey,
}

struct Issuer {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    ca: CertificateDer<'static>,
}

fn leaf(
    issuer: &Issuer,
    key: &rcgen::KeyPair,
    name: &str,
    purpose: rcgen::ExtendedKeyUsagePurpose,
    customize: impl FnOnce(&mut rcgen::CertificateParams),
) -> CertificateDer<'static> {
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("params");
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![purpose];
    customize(&mut params);
    let cert = params.signed_by(key, &issuer.issuer).expect("certificate");
    CertificateDer::from(cert.der().to_vec())
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let provider = Arc::new(browntls::crypto::native::default_provider());
        let load = |pkcs8: &[u8]| {
            provider
                .key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    pkcs8.to_vec(),
                )))
                .expect("key loads")
        };

        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = Issuer {
            issuer: rcgen::Issuer::new(ca_params, ca_key),
            ca: CertificateDer::from(ca.der().to_vec()),
        };
        let mut roots = RootCertStore::empty();
        roots.add(issuer.ca.clone()).expect("root");

        let start = rcgen::date_time_ymd(2026, 1, 1);
        let end = rcgen::date_time_ymd(2027, 1, 1);
        let server = rcgen::ExtendedKeyUsagePurpose::ServerAuth;
        let delegation_key = rcgen::KeyPair::generate().expect("key");
        let delegation = leaf(&issuer, &delegation_key, "localhost", server.clone(), |p| {
            p.not_before = start;
            p.not_after = end;
            // DelegationUsage (RFC 9345 §4.2), with a NULL value.
            p.custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 44363, 44],
                    vec![0x05, 0x00],
                ));
        });
        let plain_key = rcgen::KeyPair::generate().expect("key");
        let plain = leaf(&issuer, &plain_key, "localhost", server.clone(), |p| {
            p.not_before = start;
            p.not_after = end;
        });

        let dc_keys = [
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &rcgen::PKCS_ECDSA_P256_SHA256,
            ),
            (SignatureScheme::ED25519, &rcgen::PKCS_ED25519),
        ]
        .into_iter()
        .map(|(scheme, alg)| {
            let pair = rcgen::KeyPair::generate_for(alg).expect("credential key");
            let key = load(&pair.serialize_der());
            let spki = SubjectPublicKeyInfoDer::from(
                key.public_key().expect("public key").as_ref().to_vec(),
            );
            DcKey { scheme, key, spki }
        })
        .collect();

        let certified = |key: &rcgen::KeyPair, name: &str, purpose| {
            let cert = leaf(&issuer, key, name, purpose, |_| {});
            CertifiedKey::new(vec![cert], load(&key.serialize_der()))
        };
        let ea_server = certified(
            &rcgen::KeyPair::generate().expect("key"),
            "localhost",
            server.clone(),
        );
        let ea_other = certified(
            &rcgen::KeyPair::generate().expect("key"),
            "other.example",
            server,
        );
        let ea_client = certified(
            &rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key"),
            "client.example",
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        );

        Fixture {
            roots: Arc::new(roots),
            delegation_pkcs8: delegation_key.serialize_der(),
            delegation_key: load(&delegation_key.serialize_der()),
            delegation,
            plain_key: load(&plain_key.serialize_der()),
            plain,
            not_before: start.unix_timestamp() as u64,
            not_after: end.unix_timestamp() as u64,
            dc_keys,
            ea_server,
            ea_other,
            ea_client,
            provider,
        }
    })
}

// ------------------------------------------------------------------- model

/// `SignatureScheme::supported_in_tls13`: no hash below SHA-256 and no
/// RSA PKCS#1, DSA or anonymous signature.
fn tls13_scheme(scheme: SignatureScheme) -> bool {
    let [hash, sign] = u16::from(scheme).to_be_bytes();
    !matches!(hash, 0..=3) && !matches!(sign, 0..=2)
}

/// RFC 9345 §4: a TLS 1.3 scheme that does not need an `rsaEncryption`
/// key.
fn credential_scheme_ok(scheme: SignatureScheme) -> bool {
    tls13_scheme(scheme)
        && !matches!(
            scheme,
            SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
        )
}

/// An independent parser of the RFC 9345 §4 wire form, with this crate's
/// bound on the key: `(valid_time, dc scheme, key, algorithm, signature)`.
type Parsed = (u32, u16, Vec<u8>, u16, Vec<u8>);

fn parse_dc(bytes: &[u8]) -> Option<Parsed> {
    let mut input = Input::new(bytes);
    let mut take = |n: usize| {
        let b = input.bytes(n);
        (b.len() == n).then(|| b.to_vec())
    };
    let valid_time = u32::from_be_bytes(take(4)?.try_into().ok()?);
    let scheme = u16::from_be_bytes(take(2)?.try_into().ok()?);
    let len = take(3)?;
    let len = usize::from(len[0]) << 16 | usize::from(len[1]) << 8 | usize::from(len[2]);
    if len == 0 || len > MAX_SPKI_LEN {
        return None;
    }
    let spki = take(len)?;
    let algorithm = u16::from_be_bytes(take(2)?.try_into().ok()?);
    let sig_len = u16::from_be_bytes(take(2)?.try_into().ok()?);
    let signature = take(usize::from(sig_len))?;
    if signature.is_empty() || !input.is_empty() {
        return None;
    }
    Some((valid_time, scheme, spki, algorithm, signature))
}

/// The `Credential` encoding.
fn credential_bytes(credential: &Credential) -> Vec<u8> {
    let mut out = credential.valid_time.to_be_bytes().to_vec();
    out.extend_from_slice(&u16::from(credential.dc_cert_verify_algorithm).to_be_bytes());
    let spki = credential.public_key.as_ref();
    out.extend_from_slice(&(spki.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(spki);
    out
}

/// The bytes the certificate key signs (RFC 9345 §4).
fn expected_signed_message(
    side: Side,
    end_entity: &[u8],
    credential: &Credential,
    algorithm: SignatureScheme,
) -> Vec<u8> {
    let mut out = vec![0x20; 64];
    out.extend_from_slice(match side {
        Side::Client => CLIENT_CONTEXT,
        Side::Server => SERVER_CONTEXT,
    });
    out.push(0);
    out.extend_from_slice(end_entity);
    out.extend_from_slice(&credential_bytes(credential));
    out.extend_from_slice(&u16::from(algorithm).to_be_bytes());
    out
}

/// Verifies `dc`'s signature with `end_entity`'s key.
fn signature_verifies(
    side: Side,
    end_entity: &CertificateDer<'_>,
    dc: &DelegatedCredential,
) -> bool {
    let message =
        DelegatedCredential::signed_message(side, end_entity, &dc.credential, dc.algorithm);
    let dss = DigitallySignedStruct::new(dc.algorithm, dc.signature.clone());
    verify_tls13_signature(
        &message,
        end_entity,
        &dss,
        &fixture().provider.signature_verification_algorithms,
    )
    .is_ok()
}

// --------------------------------------------------------- fuzzed choices

/// Which certificate an operation uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cert {
    Delegation,
    Plain,
    Garbage,
}

fn pick_cert(input: &mut Input) -> (Cert, CertificateDer<'static>) {
    let fixture = fixture();
    match input.choose(6) {
        0 => (Cert::Plain, fixture.plain.clone()),
        1 => (
            Cert::Garbage,
            CertificateDer::from(input.short_field().to_vec()),
        ),
        _ => (Cert::Delegation, fixture.delegation.clone()),
    }
}

fn pick_scheme(input: &mut Input) -> SignatureScheme {
    if input.choose(8) == 0 {
        SignatureScheme::from(input.u16())
    } else {
        *input.pick(SCHEMES)
    }
}

/// Up to four schemes for the certificate key to choose from; the
/// certificate key's own scheme first unless the input says otherwise.
fn pick_cert_schemes(input: &mut Input) -> Vec<SignatureScheme> {
    let mut schemes = Vec::new();
    if input.choose(4) != 0 {
        schemes.push(SignatureScheme::ECDSA_NISTP256_SHA256);
    }
    for _ in 0..input.choose(4) {
        schemes.push(pick_scheme(input));
    }
    schemes
}

fn pick_side(input: &mut Input) -> Side {
    if input.choose(4) == 0 {
        Side::Client
    } else {
        Side::Server
    }
}

fn other_side(side: Side) -> Side {
    match side {
        Side::Client => Side::Server,
        Side::Server => Side::Client,
    }
}

/// The valid time: around the certificate's start, around a week, or any.
fn pick_valid_time(input: &mut Input) -> u32 {
    match input.choose(4) {
        0 => u32::from(input.byte()),
        1 => (MAX_VALIDITY.as_secs() as u32)
            .wrapping_add(u32::from(input.u16()).wrapping_sub(0x8000)),
        _ => input.u32(),
    }
}

// --------------------------------------------------------------- operations

#[derive(Default)]
struct State {
    handshakes: usize,
    generations: usize,
    authenticators: usize,
    ea: Option<Ea>,
}

/// The `tls_auth` fuzz target.
///
/// Operations (first byte modulo 7):
///
/// 0. decode: a 16-bit-prefixed `DelegatedCredential`;
/// 1. encode: valid time, schemes, key and signature fields;
/// 2. issue: side, certificate, certificate schemes, valid time, credential
///    scheme, key, tampering, credential key for `DelegatedCredentialKey`;
/// 3. generate (native): side, certificate, certificate schemes,
///    credential scheme, valid time;
/// 4. validity: certificate and a 64-bit time for `valid_time_until`,
///    a valid time for `expiry`;
/// 5. handshake with a credential: clock offset, server clock skew, valid
///    time, credential key, tampering;
/// 6. exported authenticators: version (first use), then one exchange.
pub fn run(data: &[u8]) {
    crate::init();
    let mut input = Input::new(data);
    let mut state = State::default();
    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        match input.choose(7) {
            0 => decode(&mut input),
            1 => encode(&mut input),
            2 => issue(&mut input),
            3 => {
                if state.generations < MAX_GENERATIONS {
                    state.generations += 1;
                    native_generate(&mut input);
                }
            }
            4 => validity(&mut input),
            5 => {
                if state.handshakes < MAX_HANDSHAKES {
                    state.handshakes += 1;
                    handshake(&mut input);
                }
            }
            _ => {
                if state.authenticators < MAX_AUTHENTICATORS {
                    state.authenticators += 1;
                    exported(&mut input, &mut state);
                }
            }
        }
    }
}
