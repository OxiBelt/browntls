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

use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use browntls::crypto::native::delegated_credential::generate;
use browntls::crypto::{CryptoProvider, verify_tls13_signature};
use browntls::delegated_credential::{
    Credential, DelegatedCredential, DelegatedCredentialKey, MAX_VALIDITY, valid_time_until,
};
use browntls::exported_authenticator::{AuthenticatorRequestExtensions, authenticator_context};
use browntls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use browntls::server::WebPkiClientVerifier;
use browntls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use browntls::time_provider::TimeProvider;
use browntls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, Error,
    PeerMisbehaved, RootCertStore, ServerConfig, ServerConnection, Side, SignatureScheme,
    SupportedProtocolVersion, version,
};

use crate::input::{Input, put_field, put_short_field};

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

fn decode(input: &mut Input) {
    let bytes = input.field();
    match (parse_dc(bytes), DelegatedCredential::from_bytes(bytes)) {
        (Some((valid_time, scheme, spki, algorithm, signature)), Ok(dc)) => {
            assert_eq!(dc.credential.valid_time, valid_time);
            assert_eq!(u16::from(dc.credential.dc_cert_verify_algorithm), scheme);
            assert_eq!(dc.credential.public_key.as_ref(), &spki[..]);
            assert_eq!(u16::from(dc.algorithm), algorithm);
            assert_eq!(dc.signature, signature);
            assert_eq!(dc.to_bytes(), bytes, "re-encoding differs");
        }
        (None, Err(_)) => {}
        (expected, got) => panic!("decoding {bytes:?}: {expected:?} vs {got:?}"),
    }
}

/// `n` bytes: the fuzzed `prefix` repeated.
fn stretch(prefix: &[u8], n: usize) -> Vec<u8> {
    if prefix.is_empty() {
        vec![0x30; n]
    } else {
        prefix.iter().copied().cycle().take(n).collect()
    }
}

fn encode(input: &mut Input) {
    let valid_time = input.u32();
    let scheme = pick_scheme(input);
    let spki = if input.choose(4) == 0 {
        stretch(input.short_field(), MAX_SPKI_LEN - 1 + input.choose(3))
    } else {
        input.short_field().to_vec()
    };
    let algorithm = pick_scheme(input);
    let signature = input.field().to_vec();
    let dc = DelegatedCredential {
        credential: Credential {
            valid_time,
            dc_cert_verify_algorithm: scheme,
            public_key: SubjectPublicKeyInfoDer::from(spki.clone()),
        },
        algorithm,
        signature: signature.clone(),
    };
    let bytes = dc.to_bytes();
    let mut expected = credential_bytes(&dc.credential);
    expected.extend_from_slice(&u16::from(algorithm).to_be_bytes());
    put_field(&mut expected, &signature);
    assert_eq!(bytes, expected);
    let decodable = !spki.is_empty() && spki.len() <= MAX_SPKI_LEN && !signature.is_empty();
    match DelegatedCredential::from_bytes(&bytes) {
        Ok(again) => {
            assert!(decodable);
            assert_eq!(again, dc);
        }
        Err(_) => assert!(!decodable),
    }
}

fn issue(input: &mut Input) {
    let fixture = fixture();
    let side = pick_side(input);
    let (cert, end_entity) = pick_cert(input);
    let cert_schemes = pick_cert_schemes(input);
    let valid_time = pick_valid_time(input);
    let dc_key = &fixture.dc_keys[input.choose(fixture.dc_keys.len())];
    let scheme = if input.choose(4) == 0 {
        pick_scheme(input)
    } else {
        dc_key.scheme
    };
    let spki = match input.choose(8) {
        0 => input.short_field().to_vec(),
        1 => stretch(b"\x30", MAX_SPKI_LEN + input.choose(2)),
        _ => dc_key.spki.as_ref().to_vec(),
    };
    let tamper = input.choose(5);
    let credential = Credential {
        valid_time,
        dc_cert_verify_algorithm: scheme,
        public_key: SubjectPublicKeyInfoDer::from(spki.clone()),
    };
    let cert_key = match cert {
        Cert::Plain => &fixture.plain_key,
        _ => &fixture.delegation_key,
    };
    let signer_ok = cert_schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256);
    let expected = cert == Cert::Delegation
        && credential_scheme_ok(scheme)
        && !spki.is_empty()
        && spki.len() <= MAX_SPKI_LEN
        && signer_ok;
    let result = DelegatedCredential::issue(
        side,
        &end_entity,
        &**cert_key,
        &cert_schemes,
        credential.clone(),
    );
    let mut dc = match result {
        Ok(dc) => {
            assert!(expected, "issued: {cert:?} {scheme:?} {cert_schemes:?}");
            dc
        }
        Err(e) => {
            assert!(!expected, "refused: {e:?}");
            return;
        }
    };
    assert_eq!(dc.credential, credential);
    assert_eq!(dc.algorithm, SignatureScheme::ECDSA_NISTP256_SHA256);
    assert_eq!(
        DelegatedCredential::signed_message(side, &end_entity, &dc.credential, dc.algorithm),
        expected_signed_message(side, end_entity.as_ref(), &dc.credential, dc.algorithm)
    );
    assert!(
        signature_verifies(side, &end_entity, &dc),
        "issued signature"
    );
    assert_eq!(
        DelegatedCredential::from_bytes(&dc.to_bytes()),
        Ok(dc.clone())
    );
    let expiry = dc.expiry(&end_entity).expect("expiry");
    assert_eq!(expiry.as_secs(), fixture.not_before + u64::from(valid_time));

    // A credential key matching the credential.
    let matching = scheme == dc_key.scheme && spki == dc_key.spki.as_ref();
    match DelegatedCredentialKey::new(&end_entity, dc.clone(), dc_key.key.clone()) {
        Ok(key) => {
            assert!(matching, "a mismatched credential key accepted");
            assert_eq!(key.credential(), &dc);
            assert_eq!(key.expiry(), expiry);
            assert_eq!(
                key.key().public_key().map(|k| k.as_ref().to_vec()),
                Some(dc_key.spki.as_ref().to_vec())
            );
            let _ = format!("{key:?}");
        }
        Err(_) => assert!(!matching, "a matching credential key refused"),
    }

    // Any change breaks the signature.
    let signer_side = match tamper {
        0 => {
            let at = usize::from(input.u16()) % dc.signature.len();
            dc.signature[at] ^= 1 << (input.byte() % 8);
            side
        }
        1 => {
            dc.credential.valid_time ^= 1 << (input.byte() % 32);
            side
        }
        2 => other_side(side),
        3 => {
            dc.credential.dc_cert_verify_algorithm = if scheme == SignatureScheme::ED25519 {
                SignatureScheme::ECDSA_NISTP256_SHA256
            } else {
                SignatureScheme::ED25519
            };
            side
        }
        _ => return,
    };
    assert!(
        !signature_verifies(signer_side, &end_entity, &dc),
        "a tampered credential verifies ({tamper})"
    );
}

fn native_generate(input: &mut Input) {
    let fixture = fixture();
    let side = pick_side(input);
    let (cert, end_entity) = pick_cert(input);
    let cert_schemes = pick_cert_schemes(input);
    let scheme = pick_scheme(input);
    let valid_time = pick_valid_time(input);
    let cert_key = match cert {
        Cert::Plain => &fixture.plain_key,
        _ => &fixture.delegation_key,
    };
    let generatable = matches!(
        scheme,
        SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512
            | SignatureScheme::ED25519
            | SignatureScheme::ED448
    );
    let expected = cert == Cert::Delegation
        && generatable
        && cert_schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256);
    let issued = match generate(
        side,
        &end_entity,
        &**cert_key,
        &cert_schemes,
        scheme,
        valid_time,
    ) {
        Ok(issued) => {
            assert!(expected, "generated: {cert:?} {scheme:?} {cert_schemes:?}");
            issued
        }
        Err(e) => {
            assert!(!expected, "refused: {e:?}");
            return;
        }
    };
    let dc = &issued.credential;
    assert_eq!(dc.credential.valid_time, valid_time);
    assert_eq!(dc.credential.dc_cert_verify_algorithm, scheme);
    let spki = issued.signing_key.public_key().expect("public key");
    assert_eq!(dc.credential.public_key.as_ref(), spki.as_ref());
    // The private key as stored loads to the same key.
    let reloaded = fixture
        .provider
        .key_provider
        .load_private_key(issued.private_key.clone_key())
        .expect("the generated key loads");
    assert_eq!(
        reloaded.public_key().map(|k| k.as_ref().to_vec()),
        Some(spki.as_ref().to_vec())
    );
    assert!(reloaded.choose_scheme(&[scheme]).is_some());
    assert!(signature_verifies(side, &end_entity, dc));
    let key = DelegatedCredentialKey::new(&end_entity, dc.clone(), issued.signing_key.clone())
        .expect("a generated credential pairs with its key");
    assert_eq!(
        key.expiry().as_secs(),
        fixture.not_before + u64::from(valid_time)
    );
    let _ = format!("{issued:?}");
}

fn validity(input: &mut Input) {
    let fixture = fixture();
    let (cert, end_entity) = pick_cert(input);
    let nb = fixture.not_before;
    let at = match input.choose(4) {
        0 => nb.wrapping_add(u64::from(input.byte())).wrapping_sub(128),
        1 => nb + u64::from(u32::MAX) + u64::from(input.byte()) - 128,
        _ => input.u64() >> 16,
    };
    let result = valid_time_until(&end_entity, unix(at));
    match cert {
        Cert::Garbage => assert!(result.is_err() || parses_as_certificate(&end_entity)),
        _ => {
            let expected = at
                .checked_sub(nb)
                .filter(|d| *d > 0)
                .and_then(|d| u32::try_from(d).ok());
            assert_eq!(result.ok(), expected, "valid_time_until({at})");
        }
    }
    let dc = DelegatedCredential {
        credential: Credential {
            valid_time: input.u32(),
            dc_cert_verify_algorithm: SignatureScheme::ED25519,
            public_key: SubjectPublicKeyInfoDer::from(vec![0x30]),
        },
        algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
        signature: vec![1],
    };
    match (cert, dc.expiry(&end_entity)) {
        (Cert::Garbage, result) => {
            assert!(result.is_err() || parses_as_certificate(&end_entity));
        }
        (_, result) => assert_eq!(
            result.map(|t| t.as_secs()).ok(),
            Some(nb + u64::from(dc.credential.valid_time))
        ),
    }
}

/// Whether fuzzed bytes happen to be a certificate.
fn parses_as_certificate(der: &CertificateDer<'_>) -> bool {
    browntls::pki_types::EndEntityCert::try_from(der).is_ok()
}

// --------------------------------------------------------------- handshakes

/// Moves everything `from` has to send into `to`.
fn send<A: browntls::SideData, B: browntls::SideData>(
    from: &mut browntls::ConnectionCommon<A>,
    to: &mut browntls::ConnectionCommon<B>,
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

/// Runs the handshake; returns each side's first error.
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

/// Handshake input: the client's clock (offset into the certificate's
/// validity, 32 bits), the server's skew selector and value, the expiry
/// relative to the client's clock (selector and value), the credential
/// key, and the tampering selector.
fn handshake(input: &mut Input) {
    let fixture = fixture();
    let nb = fixture.not_before;
    let na = fixture.not_after;
    let week = MAX_VALIDITY.as_secs();
    let now = nb + u64::from(input.u32()) % (na - nb);
    let skew: i64 = match input.choose(4) {
        0 | 1 => 0,
        2 => i64::from(input.byte()) - 128,
        _ => i64::from(input.u32() as i32) % (2 * 86_400),
    };
    let server_now = now.saturating_add_signed(skew);
    // The expiry, around the boundaries the peers check.
    let delta: i64 = match input.choose(8) {
        0 => 0,
        1 => 1,
        2 => -1,
        3 => week as i64,
        4 => week as i64 + 1,
        5 => week as i64 - 1,
        _ => i64::from(input.u32() % (9 * 86_400)) - 86_400,
    };
    let expiry = now.saturating_add_signed(delta);
    let Some(valid_time) = expiry
        .checked_sub(nb)
        .filter(|d| *d > 0)
        .and_then(|d| u32::try_from(d).ok())
    else {
        return;
    };
    assert_eq!(
        valid_time_until(&fixture.delegation, unix(expiry)).ok(),
        Some(valid_time)
    );
    let dc_key = &fixture.dc_keys[input.choose(fixture.dc_keys.len())];
    let tamper = input.choose(6);

    let mut dc = DelegatedCredential::issue(
        Side::Server,
        &fixture.delegation,
        &*fixture.delegation_key,
        &[SignatureScheme::ECDSA_NISTP256_SHA256],
        Credential {
            valid_time,
            dc_cert_verify_algorithm: dc_key.scheme,
            public_key: dc_key.spki.clone(),
        },
    )
    .expect("issue");
    let tampered = match tamper {
        0 => {
            let at = usize::from(input.u16()) % dc.signature.len();
            dc.signature[at] ^= 1 << (input.byte() % 8);
            true
        }
        1 => {
            dc.credential.valid_time = dc.credential.valid_time.wrapping_add(1);
            true
        }
        2 => {
            dc.algorithm = SignatureScheme::ED25519;
            true
        }
        _ => false,
    };
    let certified = CertifiedKey::from_der(
        vec![fixture.delegation.clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture.delegation_pkcs8.clone())),
        &fixture.provider,
    )
    .expect("certified key")
    .with_delegated_credential(dc.clone(), dc_key.key.clone())
    .expect("credential attaches");
    assert_eq!(certified.delegated_credentials().len(), 1);

    let server_config = ServerConfig::builder_with_details(
        fixture.provider.clone(),
        Arc::new(FixedTime(unix(server_now))),
    )
    .with_protocol_versions(&[&version::TLS13])
    .expect("versions")
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    let mut client_config = ClientConfig::builder_with_details(
        fixture.provider.clone(),
        Arc::new(FixedTime(unix(now))),
    )
    .with_protocol_versions(&[&version::TLS13])
    .expect("versions")
    .with_root_certificates(fixture.roots.clone())
    .with_no_client_auth();
    client_config.enable_delegated_credentials = true;
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(Arc::new(client_config), name).expect("client");
    let mut server = ServerConnection::new(Arc::new(server_config)).expect("server");
    let (client_res, server_res) = pump(&mut client, &mut server);

    // The server sends the credential only inside its own window.
    let expiry = nb + u64::from(dc.credential.valid_time);
    let sent = server_now < expiry && expiry <= server_now + week;
    if !sent {
        assert!(
            client_res.is_ok() && server_res.is_ok(),
            "{client_res:?} {server_res:?}"
        );
        assert!(client.delegated_credential().is_none());
        return;
    }
    if tampered {
        assert!(client_res.is_err(), "a tampered credential was accepted");
        assert!(server_res.is_err());
        return;
    }
    let expected = if now >= expiry {
        Some(PeerMisbehaved::DelegatedCredentialExpired)
    } else if expiry > now + week || expiry > na {
        Some(PeerMisbehaved::DelegatedCredentialValidityTooLong)
    } else {
        None
    };
    match expected {
        Some(error) => {
            assert_eq!(client_res, Err(Error::PeerMisbehaved(error)));
            assert!(server_res.is_err());
        }
        None => {
            assert!(
                client_res.is_ok() && server_res.is_ok(),
                "{client_res:?} {server_res:?}"
            );
            assert_eq!(client.delegated_credential(), Some(&dc));
            client.writer().write_all(b"dc").expect("write");
            send(&mut client, &mut server);
            server.process_new_packets().expect("server reads");
            let mut got = [0u8; 2];
            server.reader().read_exact(&mut got).expect("data");
            assert_eq!(&got, b"dc");
        }
    }
}

// --------------------------------------------------- exported authenticators

/// A connected pair and what each side has used.
struct Ea {
    client: ClientConnection,
    server: ServerConnection,
    /// Contexts of requests each side made.
    client_requests: Vec<Vec<u8>>,
    server_requests: Vec<Vec<u8>>,
    /// Unanswered requests the client made, for fuzzed answers.
    pending: Vec<Vec<u8>>,
}

fn connect_ea(versions: &[&'static SupportedProtocolVersion]) -> Ea {
    let fixture = fixture();
    let client_config = ClientConfig::builder_with_provider(fixture.provider.clone())
        .with_protocol_versions(versions)
        .expect("versions")
        .with_root_certificates(fixture.roots.clone())
        .with_no_client_auth();
    let verifier = WebPkiClientVerifier::builder_with_provider(
        fixture.roots.clone(),
        fixture.provider.clone(),
    )
    .allow_unauthenticated()
    .build()
    .expect("client verifier");
    let server_config = ServerConfig::builder_with_provider(fixture.provider.clone())
        .with_protocol_versions(versions)
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(fixture.ea_server.clone())));
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(Arc::new(client_config), name).expect("client");
    let mut server = ServerConnection::new(Arc::new(server_config)).expect("server");
    let (client_res, server_res) = pump(&mut client, &mut server);
    assert!(
        client_res.is_ok() && server_res.is_ok(),
        "{client_res:?} {server_res:?}"
    );
    Ea {
        client,
        server,
        client_requests: Vec::new(),
        server_requests: Vec::new(),
        pending: Vec::new(),
    }
}

/// Request extensions from the input, and whether they leave a TLS 1.3
/// scheme (with `None` the verifier's defaults, which do).
fn pick_extensions(input: &mut Input) -> (AuthenticatorRequestExtensions, Vec<SignatureScheme>) {
    let schemes = (input.choose(3) != 0).then(|| {
        let mut schemes: Vec<SignatureScheme> =
            (0..input.choose(4)).map(|_| pick_scheme(input)).collect();
        if input.bool() {
            schemes.push(SignatureScheme::ECDSA_NISTP256_SHA256);
            schemes.push(SignatureScheme::ED25519);
        }
        schemes
    });
    // At least one authority: `request_authenticator` encodes an empty list
    // as an empty `certificate_authorities` extension, which the peer
    // rejects (a library finding, reported separately; not fuzzed here so
    // that the rest of the exchange stays reachable).
    let authorities = input.bool().then(|| {
        (0..1 + input.choose(3))
            .map(|_| DistinguishedName::in_sequence(input.short_field()))
            .collect()
    });
    let effective = match &schemes {
        Some(s) => s.iter().copied().filter(|s| tls13_scheme(*s)).collect(),
        None => vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ],
    };
    (
        AuthenticatorRequestExtensions {
            signature_schemes: schemes,
            certificate_authorities: authorities,
        },
        effective,
    )
}

/// The identity an answer uses: the server's, another name's, the
/// client's, or none (declining).
fn pick_identity(input: &mut Input) -> (usize, Option<&'static CertifiedKey>) {
    let fixture = fixture();
    let index = input.choose(4);
    let key = match index {
        0 => Some(&fixture.ea_server),
        1 => Some(&fixture.ea_other),
        2 => Some(&fixture.ea_client),
        _ => None,
    };
    (index, key)
}

/// The scheme each identity's key signs with.
fn identity_scheme(index: usize) -> Option<SignatureScheme> {
    match index {
        0 | 1 => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
        2 => Some(SignatureScheme::ED25519),
        _ => None,
    }
}

/// Flips a bit of `authenticator` where the input says.
fn tampered(input: &mut Input, authenticator: &[u8]) -> Vec<u8> {
    let mut out = authenticator.to_vec();
    let at = usize::from(input.u16()) % out.len();
    out[at] ^= 1 << (input.byte() % 8);
    out
}

/// Exchange input: on first use a version byte (bit 0: TLS 1.2), then the
/// exchange selector and its arguments.
fn exported(input: &mut Input, state: &mut State) {
    if state.ea.is_none() {
        static TLS13: &[&SupportedProtocolVersion] = &[&version::TLS13];
        static TLS12: &[&SupportedProtocolVersion] = &[&version::TLS12];
        state.ea = Some(connect_ea(if input.bool() { TLS12 } else { TLS13 }));
    }
    let Some(ea) = state.ea.as_mut() else {
        return;
    };
    let fixture = fixture();
    match input.choose(5) {
        0 => {
            // The client asks, the server answers.
            let context = input.short_field().to_vec();
            let (extensions, schemes) = pick_extensions(input);
            let (index, identity) = pick_identity(input);
            let tamper = input.bool();
            let request = ea.client.request_authenticator(&context, &extensions);
            let fresh = !context.is_empty() && !ea.client_requests.contains(&context);
            let Ok(request) = request else {
                assert!(!fresh || schemes.is_empty(), "request refused");
                return;
            };
            assert!(fresh && !schemes.is_empty(), "request made");
            assert_eq!(request[0], 17, "a ClientCertificateRequest");
            ea.client_requests.push(context.clone());
            let auth = ea
                .server
                .authenticator(Some(&request), identity)
                .expect("the server answers");
            let signs = identity_scheme(index).is_some_and(|s| schemes.contains(&s));
            assert_eq!(
                authenticator_context(&auth).ok(),
                signs.then(|| context.clone())
            );
            if tamper {
                let bad = tampered(input, &auth);
                assert!(
                    ea.client
                        .validate_authenticator(Some(&request), &bad)
                        .is_err(),
                    "a tampered authenticator validated"
                );
            }
            let result = ea.client.validate_authenticator(Some(&request), &auth);
            match (signs, index) {
                (false, _) => assert_eq!(result, Ok(None), "declined"),
                (true, 0) => {
                    assert_eq!(result, Ok(Some(fixture.ea_server.cert.clone())), "answered")
                }
                // Wrong name, or a client certificate.
                (true, _) => assert!(result.is_err(), "{index}: {result:?}"),
            }
            // Never twice.
            assert!(
                ea.client
                    .validate_authenticator(Some(&request), &auth)
                    .is_err(),
                "a replayed authenticator validated"
            );
            if result.is_err() && ea.pending.len() < 4 {
                ea.pending.push(request);
            }
        }
        1 => {
            // The server asks, the client answers.
            let context = input.short_field().to_vec();
            let (extensions, schemes) = pick_extensions(input);
            let (index, identity) = pick_identity(input);
            let tamper = input.bool();
            let request = ea.server.request_authenticator(&context, &extensions);
            let fresh = !context.is_empty() && !ea.server_requests.contains(&context);
            let Ok(request) = request else {
                assert!(!fresh || schemes.is_empty(), "request refused");
                return;
            };
            assert!(fresh && !schemes.is_empty(), "request made");
            assert_eq!(request[0], 13, "a CertificateRequest");
            ea.server_requests.push(context.clone());
            let auth = ea
                .client
                .authenticator(&request, identity)
                .expect("the client answers");
            let signs = identity_scheme(index).is_some_and(|s| schemes.contains(&s));
            if tamper {
                let bad = tampered(input, &auth);
                assert!(
                    ea.server.validate_authenticator(&request, &bad).is_err(),
                    "a tampered authenticator validated"
                );
            }
            let result = ea.server.validate_authenticator(&request, &auth);
            match (signs, index) {
                (false, _) => assert_eq!(result, Ok(None), "declined"),
                (true, 2) => {
                    assert_eq!(result, Ok(Some(fixture.ea_client.cert.clone())), "answered")
                }
                // Server certificates lack the clientAuth purpose.
                (true, _) => assert!(result.is_err(), "{index}: {result:?}"),
            }
            assert!(
                ea.server.validate_authenticator(&request, &auth).is_err(),
                "a replayed authenticator validated"
            );
        }
        2 => {
            // A spontaneous server authenticator.
            let (index, identity) = pick_identity(input);
            let tamper = input.bool();
            let auth = ea.server.authenticator(None, identity);
            let Ok(auth) = auth else {
                assert!(identity.is_none(), "spontaneous authenticator refused");
                return;
            };
            assert!(identity.is_some());
            let context = authenticator_context(&auth).expect("a context");
            assert_eq!(context.len(), 32);
            if tamper {
                let bad = tampered(input, &auth);
                assert!(ea.client.validate_authenticator(None, &bad).is_err());
            }
            let result = ea.client.validate_authenticator(None, &auth);
            if index == 0 {
                assert_eq!(result, Ok(Some(fixture.ea_server.cert.clone())));
            } else {
                assert!(result.is_err(), "{index}: {result:?}");
            }
            assert!(ea.client.validate_authenticator(None, &auth).is_err());
        }
        3 => {
            // Fuzzed authenticators never validate.
            let auth = input.field();
            let _ = authenticator_context(auth);
            let request = ea.pending.first().cloned();
            if let Some(request) = &request {
                assert!(
                    ea.client
                        .validate_authenticator(Some(request), auth)
                        .is_err()
                );
            }
            assert!(ea.client.validate_authenticator(None, auth).is_err());
            let fuzzed_request = input.field();
            assert!(
                ea.client
                    .validate_authenticator(Some(fuzzed_request), auth)
                    .is_err()
            );
            assert!(
                ea.server
                    .validate_authenticator(fuzzed_request, auth)
                    .is_err()
            );
        }
        _ => {
            // Fuzzed requests are answered or refused, without panicking;
            // nothing the peer did not ask for validates.
            let request = input.field();
            let (_, identity) = pick_identity(input);
            if let Ok(auth) = ea.server.authenticator(Some(request), identity) {
                assert!(
                    ea.client
                        .validate_authenticator(Some(request), &auth)
                        .is_err()
                );
                assert!(ea.client.validate_authenticator(None, &auth).is_err());
            }
            if let Ok(auth) = ea.client.authenticator(request, identity) {
                assert!(ea.server.validate_authenticator(request, &auth).is_err());
            }
        }
    }
}

// ------------------------------------------------------------------- seeds

/// An issue operation: side selector, certificate selector (and garbage),
/// whether the certificate schemes include P-256, credential key, scheme
/// selector bytes, key selector bytes, tampering (with its arguments).
fn issue_seed(
    side: u8,
    cert: &[u8],
    p256: bool,
    key: u8,
    scheme: &[u8],
    spki: &[u8],
    tamper: u8,
) -> Vec<u8> {
    let mut seed = vec![2, side];
    seed.extend_from_slice(cert);
    seed.extend_from_slice(&[u8::from(p256), u8::from(!p256)]);
    if !p256 {
        // one scheme the certificate key lacks: P-384
        seed.extend_from_slice(&[1, 2]);
    }
    // valid for an hour
    seed.extend_from_slice(&[2, 0, 0, 0x0e, 0x10, key]);
    seed.extend_from_slice(scheme);
    seed.extend_from_slice(spki);
    seed.push(tamper);
    match tamper {
        0 => seed.extend_from_slice(&[0, 3, 5]),
        1 => seed.push(5),
        _ => {}
    }
    seed
}

/// Starting inputs for `tls_auth`.
#[must_use]
pub fn seeds() -> Vec<Vec<u8>> {
    crate::init();
    let fixture = fixture();
    let mut seeds = Vec::new();

    // 0: decode a valid credential, then malformed ones
    let dc = DelegatedCredential::issue(
        Side::Server,
        &fixture.delegation,
        &*fixture.delegation_key,
        &[SignatureScheme::ECDSA_NISTP256_SHA256],
        Credential {
            valid_time: 3600,
            dc_cert_verify_algorithm: SignatureScheme::ED25519,
            public_key: fixture.dc_keys[1].spki.clone(),
        },
    )
    .expect("issue")
    .to_bytes();
    let mut seed = vec![0];
    put_field(&mut seed, &dc);
    seed.push(0);
    put_field(&mut seed, &dc[..dc.len() - 1]);
    seed.push(0);
    put_field(&mut seed, &[1, 2, 3, 4, 4, 3, 0, 0, 0, 8, 7, 0, 1, 1]);
    seed.push(0);
    put_field(&mut seed, &[1, 2, 3, 4, 4, 3, 0, 0x40, 1]);
    seeds.push(seed);

    // 1: encode, decodable and not
    for (spki_sel, sig) in [(1u8, &b"sig"[..]), (0, b"sig"), (1, b"")] {
        let mut seed = vec![1, 0, 0, 0x0e, 0x10, 1, 1, spki_sel];
        put_short_field(&mut seed, b"\x30\x01\x00");
        if spki_sel == 0 {
            seed.push(1);
        }
        seed.extend_from_slice(&[1, 0]);
        put_field(&mut seed, sig);
        seeds.push(seed);
    }

    // 2: issue for each credential key, then each tampering; then the
    // refusals (client side, plain and garbage certificates, no usable
    // scheme, a forbidden credential scheme, fuzzed and oversized keys)
    for tamper in 0..5u8 {
        for key in 0..2u8 {
            seeds.push(issue_seed(1, &[2], true, key, &[1], &[2], tamper));
        }
    }
    seeds.push(issue_seed(0, &[2], true, 0, &[1], &[2], 4));
    seeds.push(issue_seed(1, &[0], true, 0, &[1], &[2], 4));
    seeds.push(issue_seed(1, &[1, 3, 0x30, 0, 0], true, 0, &[1], &[2], 4));
    seeds.push(issue_seed(1, &[2], false, 0, &[1], &[2], 4));
    seeds.push(issue_seed(1, &[2], true, 0, &[0, 1, 5], &[2], 4));
    seeds.push(issue_seed(1, &[2], true, 0, &[0, 1, 1], &[2], 4));
    seeds.push(issue_seed(1, &[2], true, 0, &[1], &[0, 3, 0x30, 1, 0], 4));
    seeds.push(issue_seed(1, &[2], true, 0, &[1], &[1, 1], 4));

    // 3: generate every native scheme, then an unsupported one
    for scheme in 0..6u8 {
        seeds.push(vec![3, 1, 2, 1, 0, 1, scheme, 2, 0, 0, 0x0e, 0x10]);
    }

    // 4: validity at the start, past 32 bits, of a plain certificate and
    // of garbage
    seeds.push(vec![4, 2, 0, 200, 0, 0, 0, 10]);
    seeds.push(vec![4, 2, 1, 200, 0, 0, 0, 10]);
    seeds.push(vec![4, 0, 2, 0, 0, 0x69, 0x55, 0, 0, 0, 0, 0, 0, 0, 1]);
    seeds.push(vec![4, 1, 1, 0x30, 2, 0, 0, 0, 0, 0]);

    // 5: handshakes: inside the window (two keys), at each boundary, with a
    // skewed server, and each tampering
    for (delta, key, skew, tamper) in [
        (6u8, 0u8, 0u8, 5u8),
        (6, 1, 0, 5),
        (0, 0, 0, 5),
        (1, 0, 0, 5),
        (2, 0, 0, 5),
        (3, 0, 0, 5),
        (4, 0, 0, 5),
        (5, 0, 0, 5),
        (6, 0, 2, 5),
        (6, 0, 0, 0),
        (6, 0, 0, 1),
        (6, 0, 0, 2),
    ] {
        let mut seed = vec![5, 0, 0x10, 0, 0, skew];
        if skew == 2 {
            seed.push(0);
        }
        seed.push(delta);
        if delta >= 6 {
            // two days
            seed.extend_from_slice(&[0, 3, 0xf4, 0x80]);
        }
        seed.extend_from_slice(&[key, tamper]);
        if tamper == 0 {
            seed.extend_from_slice(&[0, 3, 1]);
        }
        seeds.push(seed);
    }
    // the server's skew puts the credential past the client's window, or
    // after its expiry
    seeds.push(vec![5, 0, 0x10, 0, 0, 3, 0, 1, 0x51, 0x80, 4, 0, 5]);
    seeds.push(vec![5, 0, 0x10, 0, 0, 2, 0, 2, 0, 5]);

    // 6: exported authenticators over TLS 1.3 and TLS 1.2: each exchange
    // with each identity, tampered and not, then fuzzed messages
    for version in 0..2u8 {
        let mut seed = Vec::new();
        for (exchange, identity) in [
            (0u8, 0u8),
            (0, 1),
            (0, 3),
            (1, 2),
            (1, 0),
            (1, 3),
            (2, 0),
            (2, 1),
            (2, 2),
            (2, 3),
        ] {
            seed.push(6);
            if seed.len() == 1 {
                seed.push(version);
            }
            seed.push(exchange);
            if exchange < 2 {
                put_short_field(&mut seed, &[b'c', exchange, identity]);
                // default schemes, no authorities
                seed.extend_from_slice(&[0, 0]);
            }
            seed.extend_from_slice(&[identity, 1, 0, 0x20, 3]);
        }
        seeds.push(seed);
    }
    let mut seed = vec![6, 0, 0];
    put_short_field(&mut seed, b"ctx");
    // P-384 only (nothing to sign with), two authorities
    seed.extend_from_slice(&[1, 1, 1, 2, 0, 1, 2]);
    put_short_field(&mut seed, b"\x31\x00");
    put_short_field(&mut seed, b"");
    seed.extend_from_slice(&[0, 0]);
    // the same context again, then an empty one
    seed.extend_from_slice(&[6, 0]);
    put_short_field(&mut seed, b"ctx");
    seed.extend_from_slice(&[0, 0, 0, 0]);
    seed.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0]);
    // fuzzed authenticator and request, then a fuzzed request answered
    seed.extend_from_slice(&[6, 3]);
    put_field(&mut seed, &[11, 0, 0, 1, 0]);
    put_field(&mut seed, &[17, 0, 0, 0]);
    seed.extend_from_slice(&[6, 4]);
    put_field(
        &mut seed,
        &[17, 0, 0, 9, 3, b'a', b'b', b'c', 0, 4, 0, 13, 0, 0],
    );
    seed.push(0);
    seeds.push(seed);
    seeds
}
