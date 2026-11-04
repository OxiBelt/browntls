//! In-memory handshakes with RSASSA-PSS public keys: certificates whose
//! `SubjectPublicKeyInfo` algorithm is `id-RSASSA-PSS` (RFC 4055 §1.2,
//! §3.1; RFC 5756), which sign with the TLS `rsa_pss_pss_*` schemes
//! (RFC 9846 §4.3.3) in TLS 1.3 and TLS 1.2.
//!
//! * Server and client authentication with every `rsa_pss_pss_*` scheme,
//!   with keys without parameters and keys restricted to one hash.
//! * Certificate chains whose CA (root or intermediate) has an RSASSA-PSS
//!   key, validated by the web-PKI verifiers; certificate signatures are
//!   RSASSA-PSS with parameters.
//! * Negative cases: an RSASSA-PSS key with only `rsa_pss_rsae_*` or
//!   PKCS #1 v1.5 schemes offered, an `rsaEncryption` key with only
//!   `rsa_pss_pss_*` schemes, a restricted key with only other hashes;
//!   peers that sign anyway (a signing key that ignores its algorithm), and
//!   a CA restricted to SHA-256 that signs with SHA-384 parameters.
//! * OpenSSL 3.0.13 signatures verified through the provider's tables.
//! * The encodings of `RSASSA-PSS-params` RFC 4055 treats as equal (absent
//!   hash parameters, §2.1; an omitted or short minimum salt length, §3.3;
//!   an explicit trailer field 1, §3.1) in keys, key files and certificate
//!   signatures, through the raw-key and the certificate verification
//!   paths; and the encodings that stay rejected.
//!
//! rcgen cannot make RSASSA-PSS certificates, so a small X.509 builder here
//! writes them with `browntls_crypto::der` and signs them with
//! `browntls_crypto::rsa`. Every key is generated at run time and lives only
//! in memory.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::sync::{Arc, OnceLock};

use browntls::client::WebPkiServerVerifier;
use browntls::client::danger::ServerCertVerifier;
use browntls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer,
};
use browntls::server::WebPkiClientVerifier;
use browntls::sign::{CertifiedKey, Signer, SigningKey};
use browntls::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct,
    Error, PeerIncompatible, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    SignatureAlgorithm, SignatureScheme, SupportedProtocolVersion, version,
};
use browntls_crypto::der::{Writer, header_len, tag};
use browntls_crypto::hash::HashAlgorithm;
use browntls_crypto::rand::{OsRng, SecureRandom};
use browntls_crypto::rsa::{
    MAX_ALGORITHM_IDENTIFIER_LEN, MAX_MODULUS_BYTES, MAX_PKCS1_PRIVATE_KEY_DER_LEN,
    MAX_PKCS8_PRIVATE_KEY_DER_LEN, RsaKeyAlgorithm, RsaPrivateKey,
};
use common::*;

use HashAlgorithm::{Sha256, Sha384, Sha512};
use SignatureScheme as S;

const PSS_PSS: [SignatureScheme; 3] = [
    S::RSA_PSS_PSS_SHA256,
    S::RSA_PSS_PSS_SHA384,
    S::RSA_PSS_PSS_SHA512,
];

/// The schemes of `rsaEncryption` keys.
const RSAE: [SignatureScheme; 6] = [
    S::RSA_PSS_SHA256,
    S::RSA_PSS_SHA384,
    S::RSA_PSS_SHA512,
    S::RSA_PKCS1_SHA256,
    S::RSA_PKCS1_SHA384,
    S::RSA_PKCS1_SHA512,
];

const UNRESTRICTED: RsaKeyAlgorithm = RsaKeyAlgorithm::RsassaPss(None);
const RSAE_KEY: RsaKeyAlgorithm = RsaKeyAlgorithm::RsaEncryption;

const fn restricted(hash: HashAlgorithm) -> RsaKeyAlgorithm {
    RsaKeyAlgorithm::RsassaPss(Some(hash))
}

fn pss_pss_scheme(hash: HashAlgorithm) -> SignatureScheme {
    match hash {
        Sha256 => S::RSA_PSS_PSS_SHA256,
        Sha384 => S::RSA_PSS_PSS_SHA384,
        Sha512 => S::RSA_PSS_PSS_SHA512,
        other => panic!("no rsa_pss_pss scheme for {other:?}"),
    }
}

#[cfg(feature = "tls12")]
const VERSIONS: [ProtocolVersion; 2] = [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
#[cfg(not(feature = "tls12"))]
const VERSIONS: [ProtocolVersion; 1] = [ProtocolVersion::TLSv1_3];

#[cfg(feature = "tls12")]
static TLS12_ONLY: [&SupportedProtocolVersion; 1] = [&version::TLS12];
static TLS13_ONLY: [&SupportedProtocolVersion; 1] = [&version::TLS13];

fn versions(v: ProtocolVersion) -> &'static [&'static SupportedProtocolVersion] {
    match v {
        #[cfg(feature = "tls12")]
        ProtocolVersion::TLSv1_2 => &TLS12_ONLY,
        _ => &TLS13_ONLY,
    }
}

// ---------------------------------------------------------------------------
// Keys and certificates

/// RSA-2048 keys from `browntls-crypto`, generated once per test binary:
/// root CA, intermediate CA, server, client.
fn rsa_keys() -> &'static [Arc<RsaPrivateKey>; 4] {
    static KEYS: OnceLock<[Arc<RsaPrivateKey>; 4]> = OnceLock::new();
    KEYS.get_or_init(|| {
        std::array::from_fn(|_| {
            Arc::new(RsaPrivateKey::generate(2048, &OsRng).expect("RSA key generation"))
        })
    })
}

/// An RSA key and the algorithm its SPKI and PKCS #8 encodings carry.
#[derive(Clone)]
struct TestKey {
    key: Arc<RsaPrivateKey>,
    algorithm: RsaKeyAlgorithm,
    /// The `AlgorithmIdentifier` contents of both encodings, when not the
    /// canonical encoding of `algorithm`.
    encoding: Option<Vec<u8>>,
}

impl TestKey {
    fn new(index: usize, algorithm: RsaKeyAlgorithm) -> Self {
        Self {
            key: rsa_keys()[index].clone(),
            algorithm,
            encoding: None,
        }
    }

    /// The same key identified by `params` instead.
    fn encoded(self, params: PssParams) -> Self {
        Self {
            algorithm: restricted(params.hash),
            encoding: Some(params.encode()),
            ..self
        }
    }

    /// The `AlgorithmIdentifier` contents.
    fn algorithm_identifier(&self) -> Vec<u8> {
        if let Some(encoding) = &self.encoding {
            return encoding.clone();
        }
        let mut alg = [0u8; MAX_ALGORITHM_IDENTIFIER_LEN];
        let len = self
            .algorithm
            .encode_algorithm_identifier(&mut alg)
            .unwrap();
        alg[..len].to_vec()
    }

    fn root(algorithm: RsaKeyAlgorithm) -> Self {
        Self::new(0, algorithm)
    }

    fn intermediate(algorithm: RsaKeyAlgorithm) -> Self {
        Self::new(1, algorithm)
    }

    fn server(algorithm: RsaKeyAlgorithm) -> Self {
        Self::new(2, algorithm)
    }

    fn client(algorithm: RsaKeyAlgorithm) -> Self {
        Self::new(3, algorithm)
    }

    /// The `SubjectPublicKeyInfo`.
    fn spki(&self) -> Vec<u8> {
        let mut pkcs1 = vec![0u8; MAX_MODULUS_BYTES + 32];
        let n = self.key.public_key().to_pkcs1_der(&mut pkcs1).unwrap();
        seq(&[
            &tlv(tag::SEQUENCE, &self.algorithm_identifier()),
            &tlv(tag::BIT_STRING, &[&[0u8][..], &pkcs1[..n]].concat()),
        ])
    }

    /// The PKCS #8 `PrivateKeyInfo` (secret; kept in memory only).
    fn private_key(&self) -> PrivateKeyDer<'static> {
        let Some(encoding) = &self.encoding else {
            let mut der = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
            let len = self
                .key
                .to_pkcs8_der_with_algorithm(self.algorithm, &mut der)
                .unwrap();
            der.truncate(len);
            return PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
        };
        let mut pkcs1 = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
        let n = self.key.to_pkcs1_der(&mut pkcs1).unwrap();
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(seq(&[
            &tlv(tag::INTEGER, &[0]),
            &tlv(tag::SEQUENCE, encoding),
            &tlv(tag::OCTET_STRING, &pkcs1[..n]),
        ])))
    }
}

/// How `saltLength` is written in [`PssParams`].
#[derive(Clone, Copy, Debug)]
enum Salt {
    /// Absent: the DEFAULT 20.
    Omitted,
    /// The digest length.
    Digest,
    /// Explicitly this many bytes.
    Explicit(u8),
}

/// `id-RSASSA-PSS` parameters for `hash` with MGF1 over `hash`, written in
/// one of the ways RFC 4055 allows: hash identifiers with NULL or absent
/// parameters (§2.1), a salt length, an optional explicit trailer field.
#[derive(Clone, Copy, Debug)]
struct PssParams {
    hash: HashAlgorithm,
    null: bool,
    salt: Salt,
    trailer: Option<u8>,
}

impl PssParams {
    /// The canonical form: NULL parameters, a salt of the digest length.
    const fn canonical(hash: HashAlgorithm) -> Self {
        Self {
            hash,
            null: true,
            salt: Salt::Digest,
            trailer: None,
        }
    }

    const fn absent_hash_params(self) -> Self {
        Self {
            null: false,
            ..self
        }
    }

    const fn salt(self, salt: Salt) -> Self {
        Self { salt, ..self }
    }

    const fn trailer(self, value: u8) -> Self {
        Self {
            trailer: Some(value),
            ..self
        }
    }

    /// The `AlgorithmIdentifier` contents.
    fn encode(self) -> Vec<u8> {
        const RSASSA_PSS: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
        const MGF1: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
        let last = match self.hash {
            Sha256 => 1,
            Sha384 => 2,
            Sha512 => 3,
            other => panic!("{other:?}"),
        };
        let oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last];
        let null: &[u8] = if self.null { &[tag::NULL, 0] } else { &[] };
        let hash = seq(&[&tlv(tag::OID, &oid), null]);
        let mut fields = vec![
            tlv(tag::context_constructed(0), &hash),
            tlv(
                tag::context_constructed(1),
                &seq(&[&tlv(tag::OID, &MGF1), &hash]),
            ),
        ];
        let salt = match self.salt {
            Salt::Omitted => None,
            Salt::Digest => Some(u8::try_from(self.hash.output_len()).unwrap()),
            Salt::Explicit(len) => Some(len),
        };
        if let Some(len) = salt {
            assert!(len < 0x80);
            fields.push(tlv(tag::context_constructed(2), &tlv(tag::INTEGER, &[len])));
        }
        if let Some(value) = self.trailer {
            fields.push(tlv(
                tag::context_constructed(3),
                &tlv(tag::INTEGER, &[value]),
            ));
        }
        let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        [tlv(tag::OID, &RSASSA_PSS), seq(&fields)].concat()
    }
}

/// Encodings of keys restricted to `hash` that are accepted, other than the
/// canonical one: absent hash parameters, the minimum salt left at its
/// DEFAULT 20 (OpenSSL's `rsa_pss_keygen_md` with `rsa_pss_keygen_mgf1_md`),
/// a minimum of 0, an explicit trailer field 1, and all at once.
fn equivalent_key_forms(hash: HashAlgorithm) -> [PssParams; 5] {
    let canonical = PssParams::canonical(hash);
    [
        canonical.absent_hash_params(),
        canonical.salt(Salt::Omitted),
        canonical.salt(Salt::Explicit(0)),
        canonical.trailer(1),
        canonical
            .absent_hash_params()
            .salt(Salt::Omitted)
            .trailer(1),
    ]
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; header_len(content.len()) + content.len()];
    Writer::new(&mut out).tlv(tag, content).unwrap();
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &parts.concat())
}

/// A `Name` with one common name.
fn name(cn: &str) -> Vec<u8> {
    const COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
    const UTF8_STRING: u8 = 0x0c;
    let atv = seq(&[
        &tlv(tag::OID, &COMMON_NAME),
        &tlv(UTF8_STRING, cn.as_bytes()),
    ]);
    seq(&[&tlv(0x31, &atv)])
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let critical = if critical {
        tlv(tag::BOOLEAN, &[0xff])
    } else {
        Vec::new()
    };
    seq(&[
        &tlv(tag::OID, oid),
        &critical,
        &tlv(tag::OCTET_STRING, value),
    ])
}

/// What a certificate is for.
#[derive(Clone, Copy, Debug)]
enum Role {
    Ca,
    Server,
    Client,
}

fn extensions(role: Role) -> Vec<u8> {
    const BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1d, 0x13];
    const KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x0f];
    const EXT_KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x25];
    const SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1d, 0x11];
    const SERVER_AUTH: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    const CLIENT_AUTH: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    let exts = match role {
        Role::Ca => vec![
            extension(
                &BASIC_CONSTRAINTS,
                true,
                &seq(&[&tlv(tag::BOOLEAN, &[0xff])]),
            ),
            // keyCertSign and cRLSign.
            extension(&KEY_USAGE, true, &tlv(tag::BIT_STRING, &[0x01, 0x06])),
        ],
        Role::Server | Role::Client => {
            let (purpose, dns): (&[u8], &[u8]) = match role {
                Role::Server => (&SERVER_AUTH, b"localhost"),
                _ => (&CLIENT_AUTH, b"client.example"),
            };
            vec![
                // digitalSignature (RFC 4055 §1.2 for RSASSA-PSS keys).
                extension(&KEY_USAGE, true, &tlv(tag::BIT_STRING, &[0x07, 0x80])),
                extension(&EXT_KEY_USAGE, false, &seq(&[&tlv(tag::OID, purpose)])),
                extension(
                    &SUBJECT_ALT_NAME,
                    false,
                    &seq(&[&tlv(tag::context_primitive(2), dns)]),
                ),
            ]
        }
    };
    let exts: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
    tlv(tag::context_constructed(3), &seq(&exts))
}

/// Issues a v3 certificate for `subject` signed by `issuer` with RSASSA-PSS
/// over `hash` (RFC 4055 §3: parameters always present in the signature
/// algorithm). The issuer key signs whatever it is asked to, whatever its
/// own algorithm allows, so that tests can make invalid certificates too.
fn issue(
    subject_cn: &str,
    subject: &TestKey,
    role: Role,
    issuer_cn: &str,
    issuer: &TestKey,
    hash: HashAlgorithm,
) -> CertificateDer<'static> {
    let sig_alg = PssParams::canonical(hash);
    issue_with(subject_cn, subject, role, issuer_cn, issuer, sig_alg)
}

/// [`issue`] with the signature `AlgorithmIdentifier` written as `sig_alg`
/// says. The signature itself always uses `sig_alg`'s hash with MGF1 over
/// it and a salt of the digest length, so the identifier describes it only
/// when it is equivalent to the canonical one.
fn issue_with(
    subject_cn: &str,
    subject: &TestKey,
    role: Role,
    issuer_cn: &str,
    issuer: &TestKey,
    sig_alg: PssParams,
) -> CertificateDer<'static> {
    let mut serial = [0u8; 8];
    OsRng.fill(&mut serial).unwrap();
    serial[0] = (serial[0] & 0x7f) | 0x01;
    const UTC_TIME: u8 = 0x17;
    let hash = sig_alg.hash;
    let sig_alg = tlv(tag::SEQUENCE, &sig_alg.encode());
    let tbs = seq(&[
        &tlv(tag::context_constructed(0), &tlv(tag::INTEGER, &[2])),
        &tlv(tag::INTEGER, &serial),
        &sig_alg,
        &name(issuer_cn),
        &seq(&[
            &tlv(UTC_TIME, b"240101000000Z"),
            &tlv(UTC_TIME, b"491231235959Z"),
        ]),
        &name(subject_cn),
        &subject.spki(),
        &extensions(role),
    ]);
    let mut sig = vec![0u8; issuer.key.modulus_len_bytes()];
    issuer.key.sign_pss(hash, &tbs, &OsRng, &mut sig).unwrap();
    CertificateDer::from(seq(&[
        &tbs,
        &sig_alg,
        &tlv(tag::BIT_STRING, &[&[0u8][..], &sig].concat()),
    ]))
}

/// A certificate chain with its end-entity key.
#[derive(Clone)]
struct PssChain {
    root: CertificateDer<'static>,
    /// End entity first, then any intermediate.
    chain: Vec<CertificateDer<'static>>,
    key: TestKey,
}

impl PssChain {
    fn private_key(&self) -> PrivateKeyDer<'static> {
        self.key.private_key()
    }

    fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        Arc::new(roots)
    }

    fn spki(&self) -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from(self.key.spki())
    }
}

/// How a chain is made: the root's key and the hash it signs with, an
/// optional intermediate, and the end entity's key.
#[derive(Clone, Copy, Debug)]
struct ChainSpec {
    root: RsaKeyAlgorithm,
    root_hash: HashAlgorithm,
    intermediate: Option<(RsaKeyAlgorithm, HashAlgorithm)>,
    end_entity: RsaKeyAlgorithm,
}

impl ChainSpec {
    /// A root signing the end entity directly.
    const fn direct(root: RsaKeyAlgorithm, hash: HashAlgorithm, ee: RsaKeyAlgorithm) -> Self {
        Self {
            root,
            root_hash: hash,
            intermediate: None,
            end_entity: ee,
        }
    }

    fn build(&self, role: Role) -> PssChain {
        let root = TestKey::root(self.root);
        let ee = match role {
            Role::Client => TestKey::client(self.end_entity),
            _ => TestKey::server(self.end_entity),
        };
        let root_cert = issue(
            "PSS root",
            &root,
            Role::Ca,
            "PSS root",
            &root,
            self.root_hash,
        );
        let (chain, ee_cert) = match self.intermediate {
            None => (
                Vec::new(),
                issue("end entity", &ee, role, "PSS root", &root, self.root_hash),
            ),
            Some((alg, hash)) => {
                let ica = TestKey::intermediate(alg);
                let ica_cert = issue("PSS CA", &ica, Role::Ca, "PSS root", &root, self.root_hash);
                let ee_cert = issue("end entity", &ee, role, "PSS CA", &ica, hash);
                (vec![ica_cert], ee_cert)
            }
        };
        PssChain {
            root: root_cert,
            chain: [vec![ee_cert], chain].concat(),
            key: ee,
        }
    }
}

/// A server chain for `localhost` whose root (an `rsaEncryption` key)
/// signs the end entity with SHA-256 parameters.
fn server_with_key(algorithm: RsaKeyAlgorithm) -> PssChain {
    ChainSpec::direct(RSAE_KEY, Sha256, algorithm).build(Role::Server)
}

fn client_with_key(algorithm: RsaKeyAlgorithm) -> PssChain {
    ChainSpec::direct(RSAE_KEY, Sha256, algorithm).build(Role::Client)
}

// ---------------------------------------------------------------------------
// Configurations

fn pinned_server_verifier(chain: &PssChain) -> Arc<PinnedServerVerifier> {
    Arc::new(PinnedServerVerifier {
        expected: chain.chain[0].clone(),
        spki: chain.spki(),
        algs: prov::SUPPORTED_SIG_ALGS,
        raw: false,
    })
}

fn pinned_client_verifier(chain: &PssChain) -> Arc<PinnedClientVerifier> {
    Arc::new(PinnedClientVerifier {
        expected: chain.chain[0].clone(),
        spki: chain.spki(),
        algs: prov::SUPPORTED_SIG_ALGS,
        mandatory: true,
        hints: Vec::new(),
        raw: false,
    })
}

fn client_with(v: ProtocolVersion, verifier: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(v))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

fn server_for(chain: &PssChain) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.chain.clone(), chain.private_key())
        .unwrap()
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

fn round_trip(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(send_and_receive(client, server, b"ping"), b"ping");
    assert_eq!(send_and_receive(server, client, b"pong"), b"pong");
}

/// The client's and the server's results of a failed handshake.
type Failure = (Result<(), Error>, Result<(), Error>);

/// Runs a handshake where the client offers only `offer`, and returns the
/// schemes of the server signatures the client checked.
fn server_signs(
    v: ProtocolVersion,
    chain: &PssChain,
    offer: &[SignatureScheme],
) -> Result<Vec<SignatureScheme>, Failure> {
    let verifier = SchemeRecordingServerVerifier::new(pinned_server_verifier(chain), offer);
    let (mut client, mut server) = connect(client_with(v, verifier.clone()), server_for(chain));
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    if client_res.is_err() || server_res.is_err() {
        return Err((client_res, server_res));
    }
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(v));
    round_trip(&mut client, &mut server);
    Ok(verifier.seen())
}

// ---------------------------------------------------------------------------
// Signing with RSASSA-PSS keys

#[test]
fn pss_server_signs_with_every_pss_pss_scheme() {
    init_logging();
    let chain = server_with_key(UNRESTRICTED);
    let mut handshakes = 0;
    for v in VERSIONS {
        for scheme in PSS_PSS {
            let seen = server_signs(v, &chain, &[scheme])
                .unwrap_or_else(|e| panic!("{v:?} {scheme:?}: {e:?}"));
            assert_eq!(seen, [scheme], "{v:?}");
            handshakes += 1;
        }
        // Offered everything, the key prefers the largest hash.
        let mut offer = RSAE.to_vec();
        offer.extend(PSS_PSS);
        assert_eq!(
            server_signs(v, &chain, &offer).unwrap(),
            [S::RSA_PSS_PSS_SHA512],
            "{v:?}"
        );
    }
    // Three schemes in each enabled version.
    assert_eq!(handshakes, 3 * VERSIONS.len());
}

#[cfg(feature = "tls12")]
#[cfg(feature = "tls12")]
#[test]
fn pss_server_signs_with_every_tls12_rsa_suite() {
    init_logging();
    let chain = server_with_key(UNRESTRICTED);
    let suites: Vec<_> = prov::ALL_CIPHER_SUITES
        .iter()
        .filter(|s| s.tls13().is_none() && format!("{:?}", s.suite()).contains("_RSA_"))
        .copied()
        .collect();
    // 3 AEAD and 4 CBC `ECDHE_RSA` suites.
    assert_eq!(suites.len(), 7);
    for suite in suites {
        let mut provider = prov::default_provider();
        provider.cipher_suites = vec![suite];
        let verifier = SchemeRecordingServerVerifier::new(
            pinned_server_verifier(&chain),
            &[S::RSA_PSS_PSS_SHA256],
        );
        let client = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&TLS12_ONLY)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let (mut client, mut server) = connect(client, server_for(&chain));
        do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{suite:?}: {e}"));
        assert_eq!(
            server.negotiated_cipher_suite().unwrap().suite(),
            suite.suite()
        );
        assert_eq!(verifier.seen(), [S::RSA_PSS_PSS_SHA256]);
        round_trip(&mut client, &mut server);
    }
}

#[test]
fn restricted_pss_server_signs_only_with_its_hash() {
    init_logging();
    for hash in [Sha256, Sha384, Sha512] {
        let chain = server_with_key(restricted(hash));
        for v in VERSIONS {
            // Everything RSA offered: only the key's own scheme is usable.
            let mut offer = RSAE.to_vec();
            offer.extend(PSS_PSS);
            assert_eq!(
                server_signs(v, &chain, &offer).unwrap(),
                [pss_pss_scheme(hash)],
                "{v:?} {hash:?}"
            );
            // Only the other hashes offered: no signature can be made.
            let others: Vec<_> = PSS_PSS
                .into_iter()
                .filter(|s| *s != pss_pss_scheme(hash))
                .collect();
            let (client_res, server_res) = server_signs(v, &chain, &others).unwrap_err();
            assert_no_common_scheme(v, client_res, server_res);
        }
    }
}

/// The server found no scheme its key can sign with.
fn assert_no_common_scheme(
    v: ProtocolVersion,
    client_res: Result<(), Error>,
    server_res: Result<(), Error>,
) {
    assert_eq!(
        server_res,
        Err(PeerIncompatible::NoSignatureSchemesInCommon.into()),
        "{v:?}"
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure)),
        "{v:?}"
    );
}

#[test]
fn pss_key_refuses_rsae_and_pkcs1_schemes() {
    init_logging();
    // RFC 9846 §4.3.3: rsa_pss_rsae_* (and PKCS #1 v1.5) need an
    // rsaEncryption key; an RSASSA-PSS key only signs RSASSA-PSS (RFC 4055
    // §1.2).
    for algorithm in [UNRESTRICTED, restricted(Sha256)] {
        let chain = server_with_key(algorithm);
        for v in VERSIONS {
            let (client_res, server_res) = server_signs(v, &chain, &RSAE).unwrap_err();
            assert_no_common_scheme(v, client_res, server_res);
        }
    }
}

#[test]
fn rsae_key_refuses_pss_pss_schemes() {
    init_logging();
    let chain = server_with_key(RSAE_KEY);
    for v in VERSIONS {
        let (client_res, server_res) = server_signs(v, &chain, &PSS_PSS).unwrap_err();
        assert_no_common_scheme(v, client_res, server_res);
        // With the rsae schemes offered too, it uses those.
        let mut offer = PSS_PSS.to_vec();
        offer.push(S::RSA_PSS_SHA256);
        assert_eq!(
            server_signs(v, &chain, &offer).unwrap(),
            [S::RSA_PSS_SHA256]
        );
    }
}

#[test]
fn pss_client_auth_with_every_scheme() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    for (algorithm, schemes) in [
        (UNRESTRICTED, &PSS_PSS[..]),
        (restricted(Sha384), &[S::RSA_PSS_PSS_SHA384][..]),
    ] {
        let client_chain = client_with_key(algorithm);
        for v in VERSIONS {
            for scheme in schemes {
                let verifier = SchemeRecordingClientVerifier::new(
                    pinned_client_verifier(&client_chain),
                    &[*scheme],
                );
                let client_config = ClientConfig::builder_with_provider(provider())
                    .with_protocol_versions(versions(v))
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
                    .with_client_auth_cert(client_chain.chain.clone(), client_chain.private_key())
                    .unwrap();
                let server_config = ServerConfig::builder_with_provider(provider())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_client_cert_verifier(verifier.clone())
                    .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
                    .unwrap();
                let (mut client, mut server) = connect(client_config, server_config);
                do_handshake(&mut client, &mut server)
                    .unwrap_or_else(|e| panic!("{algorithm:?} {v:?} {scheme:?}: {e}"));
                assert_eq!(client.protocol_version(), Some(v));
                assert_eq!(verifier.seen(), [*scheme], "{algorithm:?} {v:?}");
                assert_eq!(
                    server.peer_certificates().unwrap(),
                    client_chain.chain.as_slice()
                );
                round_trip(&mut client, &mut server);
            }
        }
    }
}

#[test]
fn restricted_pss_client_cannot_answer_other_hashes() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_with_key(restricted(Sha256));
    for v in VERSIONS {
        let verifier = SchemeRecordingClientVerifier::new(
            pinned_client_verifier(&client_chain),
            &[
                S::RSA_PSS_PSS_SHA384,
                S::RSA_PSS_PSS_SHA512,
                S::RSA_PSS_SHA256,
            ],
        );
        let client_config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions(v))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
            .with_client_auth_cert(client_chain.chain.clone(), client_chain.private_key())
            .unwrap();
        let server_config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
            .unwrap();
        let (mut client, mut server) = connect(client_config, server_config);
        let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
        // The client sends no certificate; client authentication is
        // mandatory.
        assert_eq!(server_res, Err(Error::NoCertificatesPresented), "{v:?}");
        assert!(verifier.seen().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Certificate path validation

/// Chains with RSASSA-PSS keys at every position.
const CHAINS: [ChainSpec; 5] = [
    ChainSpec::direct(UNRESTRICTED, Sha256, UNRESTRICTED),
    ChainSpec::direct(restricted(Sha384), Sha384, restricted(Sha512)),
    ChainSpec::direct(restricted(Sha512), Sha512, RSAE_KEY),
    ChainSpec {
        root: RSAE_KEY,
        root_hash: Sha512,
        intermediate: Some((restricted(Sha256), Sha256)),
        end_entity: RSAE_KEY,
    },
    ChainSpec {
        root: UNRESTRICTED,
        root_hash: Sha384,
        intermediate: Some((UNRESTRICTED, Sha512)),
        end_entity: restricted(Sha256),
    },
];

fn webpki_configs(
    v: ProtocolVersion,
    server: &PssChain,
    client: &PssChain,
) -> (ClientConfig, ServerConfig) {
    let server_verifier = WebPkiServerVerifier::builder_with_provider(server.roots(), provider())
        .build()
        .unwrap();
    let client_verifier = WebPkiClientVerifier::builder_with_provider(client.roots(), provider())
        .build()
        .unwrap();
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(v))
        .unwrap()
        .with_webpki_verifier(server_verifier)
        .with_client_auth_cert(client.chain.clone(), client.private_key())
        .unwrap();
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server.chain.clone(), server.private_key())
        .unwrap();
    (client_config, server_config)
}

#[test]
fn webpki_verifiers_validate_chains_with_pss_keys() {
    init_logging();
    for spec in CHAINS {
        let server_chain = spec.build(Role::Server);
        let client_chain = spec.build(Role::Client);
        for v in VERSIONS {
            let (client_config, server_config) = webpki_configs(v, &server_chain, &client_chain);
            let (mut client, mut server) = connect(client_config, server_config);
            do_handshake(&mut client, &mut server)
                .unwrap_or_else(|e| panic!("{spec:?} {v:?}: {e}"));
            assert_eq!(client.protocol_version(), Some(v));
            assert_eq!(
                client.peer_certificates().unwrap(),
                server_chain.chain.as_slice()
            );
            assert_eq!(
                server.peer_certificates().unwrap(),
                client_chain.chain.as_slice()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn webpki_verifier_rejects_a_restricted_ca_signing_with_another_hash() {
    init_logging();
    // The root's key is restricted to SHA-256; the end entity's certificate
    // carries SHA-384 parameters, which are not identical to the key's
    // (RFC 9846 §4.3.3, RFC 4055 §3.3).
    for (spec, ok) in [
        (
            ChainSpec::direct(restricted(Sha256), Sha384, UNRESTRICTED),
            false,
        ),
        (
            ChainSpec::direct(restricted(Sha256), Sha256, UNRESTRICTED),
            true,
        ),
        (
            ChainSpec {
                root: RSAE_KEY,
                root_hash: Sha256,
                intermediate: Some((restricted(Sha512), Sha256)),
                end_entity: RSAE_KEY,
            },
            false,
        ),
    ] {
        let server_chain = spec.build(Role::Server);
        let client_chain = ChainSpec::direct(RSAE_KEY, Sha256, RSAE_KEY).build(Role::Client);
        for v in VERSIONS {
            let (client_config, server_config) = webpki_configs(v, &server_chain, &client_chain);
            let (mut client, mut server) = connect(client_config, server_config);
            let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
            if ok {
                client_res.unwrap();
            } else {
                assert_eq!(
                    client_res,
                    Err(Error::InvalidCertificate(
                        CertificateError::UnsupportedSignatureAlgorithm
                    )),
                    "{spec:?} {v:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Peers that sign with schemes their key does not allow

/// A signing key that signs RSASSA-PSS with any hash and offers every RSA
/// scheme, whatever its certificate's key algorithm says.
#[derive(Debug)]
struct UnrestrictedSigner {
    key: Arc<RsaPrivateKey>,
    schemes: Vec<SignatureScheme>,
}

#[derive(Debug)]
struct UnrestrictedPss {
    key: Arc<RsaPrivateKey>,
    scheme: SignatureScheme,
}

fn scheme_hash(scheme: SignatureScheme) -> HashAlgorithm {
    match scheme {
        S::RSA_PSS_SHA256 | S::RSA_PSS_PSS_SHA256 => Sha256,
        S::RSA_PSS_SHA384 | S::RSA_PSS_PSS_SHA384 => Sha384,
        S::RSA_PSS_SHA512 | S::RSA_PSS_PSS_SHA512 => Sha512,
        other => panic!("not an RSASSA-PSS scheme: {other:?}"),
    }
}

impl SigningKey for UnrestrictedSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = *self.schemes.iter().find(|s| offered.contains(s))?;
        Some(Box::new(UnrestrictedPss {
            key: self.key.clone(),
            scheme,
        }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Signer for UnrestrictedPss {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0u8; self.key.modulus_len_bytes()];
        self.key
            .sign_pss(scheme_hash(self.scheme), message, &OsRng, &mut sig)
            .map_err(|_| Error::General("signing failed".into()))?;
        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl browntls::server::ResolvesServerCert for FixedCert {
    fn resolve(&self, _: browntls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl browntls::client::ResolvesClientCert for FixedCert {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// `chain`'s certificates with a signer that uses `scheme` regardless.
fn misbehaving(chain: &PssChain, scheme: SignatureScheme) -> Arc<FixedCert> {
    Arc::new(FixedCert(Arc::new(CertifiedKey::new(
        chain.chain.clone(),
        Arc::new(UnrestrictedSigner {
            key: chain.key.key.clone(),
            schemes: vec![scheme],
        }),
    ))))
}

/// (key algorithm, scheme it must not sign with).
const MISUSES: [(RsaKeyAlgorithm, SignatureScheme); 4] = [
    (UNRESTRICTED, S::RSA_PSS_SHA256),
    (restricted(Sha256), S::RSA_PSS_PSS_SHA384),
    (restricted(Sha512), S::RSA_PSS_SHA512),
    (RSAE_KEY, S::RSA_PSS_PSS_SHA256),
];

#[test]
fn client_rejects_a_server_signing_outside_its_key_algorithm() {
    init_logging();
    for (algorithm, scheme) in MISUSES {
        let chain = ChainSpec::direct(UNRESTRICTED, Sha256, algorithm).build(Role::Server);
        for v in VERSIONS {
            let verifier = WebPkiServerVerifier::builder_with_provider(chain.roots(), provider())
                .build()
                .unwrap();
            let client_config = ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(versions(v))
                .unwrap()
                .with_webpki_verifier(verifier)
                .with_no_client_auth();
            let server_config = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(misbehaving(&chain, scheme));
            let (mut client, mut server) = connect(client_config, server_config);
            let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                client_res,
                Err(Error::InvalidCertificate(
                    CertificateError::UnsupportedSignatureAlgorithm
                )),
                "{algorithm:?} {scheme:?} {v:?}"
            );
        }
    }
}

#[test]
fn server_rejects_a_client_signing_outside_its_key_algorithm() {
    init_logging();
    let server_chain = server_with_key(RSAE_KEY);
    for (algorithm, scheme) in MISUSES {
        let client_chain = ChainSpec::direct(UNRESTRICTED, Sha256, algorithm).build(Role::Client);
        for v in VERSIONS {
            let client_verifier =
                WebPkiClientVerifier::builder_with_provider(client_chain.roots(), provider())
                    .build()
                    .unwrap();
            let client_config = ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(versions(v))
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(pinned_server_verifier(&server_chain))
                .with_client_cert_resolver(misbehaving(&client_chain, scheme));
            let server_config = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(server_chain.chain.clone(), server_chain.private_key())
                .unwrap();
            let (mut client, mut server) = connect(client_config, server_config);
            let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                server_res,
                Err(Error::InvalidCertificate(
                    CertificateError::UnsupportedSignatureAlgorithm
                )),
                "{algorithm:?} {scheme:?} {v:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Verification through the provider's scheme table

fn verify_raw(spki: &[u8], scheme: SignatureScheme, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let dss = DigitallySignedStruct::new(scheme, sig.to_vec());
    let spki = SubjectPublicKeyInfoDer::from(spki.to_vec());
    let tls13 = browntls::crypto::verify_tls13_signature_with_raw_key(
        msg,
        &spki,
        &dss,
        &prov::SUPPORTED_SIG_ALGS,
    )
    .map(|_| ());
    let tls12 = browntls::crypto::verify_tls12_signature_with_raw_key(
        msg,
        &spki,
        &dss,
        &prov::SUPPORTED_SIG_ALGS,
    )
    .map(|_| ());
    assert_eq!(tls12, tls13, "{scheme:?}");
    tls13
}

#[test]
fn scheme_table_binds_key_algorithm_and_hash() {
    let key = TestKey::server(UNRESTRICTED);
    let mut sig = vec![0u8; 256];
    for (algorithm, valid) in [
        (RSAE_KEY, &RSAE[..3]),
        (UNRESTRICTED, &PSS_PSS[..]),
        (restricted(Sha256), &PSS_PSS[..1]),
        (restricted(Sha384), &PSS_PSS[1..2]),
        (restricted(Sha512), &PSS_PSS[2..]),
    ] {
        let spki = TestKey {
            algorithm,
            ..key.clone()
        }
        .spki();
        for scheme in RSAE[..3].iter().chain(&PSS_PSS) {
            key.key
                .sign_pss(scheme_hash(*scheme), b"msg", &OsRng, &mut sig)
                .unwrap();
            let res = verify_raw(&spki, *scheme, b"msg", &sig);
            if valid.contains(scheme) {
                res.unwrap();
                assert_eq!(
                    verify_raw(&spki, *scheme, b"msh", &sig),
                    Err(CertificateError::BadSignature.into())
                );
            } else {
                assert_eq!(
                    res,
                    Err(CertificateError::UnsupportedSignatureAlgorithm.into()),
                    "{algorithm:?} {scheme:?}"
                );
            }
        }
    }
}

// Public keys and signatures made by OpenSSL 3.0.13 (the same vectors as
// `crates/browntls-crypto/tests/rsa_sign.rs`, which records the commands;
// the private keys were discarded): an RSA-PSS key without parameters
// signing with SHA-512, and a key restricted to SHA-256.
const OPENSSL_MSG: &[u8] = b"browntls RSASSA-PSS test vector";
const OPENSSL_PSS_SPKI: &str = concat!(
    "30820120300b06092a864886f70d01010a0382010f003082010a0282010100af",
    "44706e28928bb898b9da6b657ca711e2edd287181904fe632899fab589edbb1c",
    "8cf30da93dec59859ab3d0fa1ef7cf26624cb35024607a1dcb15800949e091e8",
    "f6821e46a2deebe55de982adfe235fff0cd21a1b60c28d08dda7ff635045e9e2",
    "cabe0006720c1267fd8b747415d00a8d06a91eed75f5fb38deffed32154d4c15",
    "6363fb974787748eae2438fa4a549bbeab5dc366b9ca7801caaf618852d41ce5",
    "9d613a4750cd8186f68e18a9de1618cd613386f827326931ecf73a9fdfa3b713",
    "899d4e961ff931b4c542a3569dab2d6f77882d671d6b9f34868005585a632c87",
    "f4e1eceb193a56d842e3585f6ce3a7a44ea7283bbdd3863268d3eaf18fe66302",
    "03010001",
);
const OPENSSL_PSS_SHA512_SIG: &str = concat!(
    "3f90c4862183f6072d95b3bd076fd375622a7216bd17c2bd6d2c1f26deef9917",
    "59748af3dda4d066da226f025a1b76a602b2784ed310dc50e666f93e64153b5e",
    "a531ae8a9a513168d69edccb9e6767304b17d085c5e9a02307880ee239f68dd0",
    "2f637eaf5f1ddebbb1d88962864c66259728a364f330da985f53105c8561fbe0",
    "7bcb36aca0ebab1dbeba9ca96253d8df20a15fbc3f6cbdbd73a0062cc98f4326",
    "227a416e7949d80f4a3b326d6ba8854f22de9fb0e3e6a7b7127ecf313de960ff",
    "61fee2277df5b7f5dc176fa3044e3a2a160075c17f56202987c70e0efc6fce0a",
    "c6e8f6e7410503f89ab3f534f27cc0a305d28ee49924fcccdc87a17602d78e89",
);
const OPENSSL_PSS_SHA256_SPKI: &str = concat!(
    "30820156304106092a864886f70d01010a3034a00f300d060960864801650304",
    "02010500a11c301a06092a864886f70d010108300d0609608648016503040201",
    "0500a2030201200382010f003082010a0282010100a9cb3bd5a02e5eee5eb103",
    "a87e19eadedc9bd44c12bfc6fa189c1ff7f790ab8cd20bbf98f7d40b0c206e10",
    "1baaa398a1dc6cf7652ce86bef43215d2438fc65c09e4e767ef263c350d2b568",
    "b538dc1f6dc6af9585692587599a039b337e15964711236111c99131c0dce053",
    "367bafe29831ff44ec67a2d43c54dd310a260d7cdc73794e2e2792b91841091f",
    "4ece9f75435746a39c76fb45db30473be87cc507313e58fadde9f4a9ec56ea2f",
    "eb9d9d432b2d06aa0fc8b22db7280c00222a6f8829ee62d3e83bdd52c9aba5c6",
    "e360a01c1cbfee0048cf429ccb3c4f7f7b8d929d966326257101b395d3d9c231",
    "38f2566ae7a123b13cb683eb9abe362fa6749d3add0203010001",
);
const OPENSSL_PSS_SHA256_SIG: &str = concat!(
    "3b5c48fc32708b0875acfbab1f5bffc19e19af234ce6785b2e5baa8f45d04ba5",
    "d628b678ffef425e8199b43f516f02df2c00ef2d9d2962df46d931f086f5871c",
    "799895cee57aa53908687ecb41f1b0a219b481e022a1095ac01dda13479eeacc",
    "02cbc22754f8de487e093dbff2f77e8182e26d997d01187be3a989d6444c90cc",
    "024c009818115665425e96f576d537cd033cebcf5fcf6c2c0310115fe64ae61b",
    "b7d3fbbf8da0f4043aaffc7e0c02a49e8d7fbc843bc7f900bf2b470e0718fd2c",
    "1c8253e74f6ddfb62ab8fae0b823a12d649d004f9a559514271e012efb36258e",
    "730bcbc1a78ac5619bd511b4306b297ae48fc5f0ca366589ad138116664b2c08",
);

#[test]
fn openssl_signatures_verify_with_pss_pss_schemes() {
    let unrestricted = hex::decode(OPENSSL_PSS_SPKI).unwrap();
    let sig512 = hex::decode(OPENSSL_PSS_SHA512_SIG).unwrap();
    verify_raw(&unrestricted, S::RSA_PSS_PSS_SHA512, OPENSSL_MSG, &sig512).unwrap();
    // The same signature under the rsae scheme: the key is not rsaEncryption.
    assert_eq!(
        verify_raw(&unrestricted, S::RSA_PSS_SHA512, OPENSSL_MSG, &sig512),
        Err(CertificateError::UnsupportedSignatureAlgorithm.into())
    );
    assert_eq!(
        verify_raw(&unrestricted, S::RSA_PSS_PSS_SHA384, OPENSSL_MSG, &sig512),
        Err(CertificateError::BadSignature.into())
    );

    let sha256_only = hex::decode(OPENSSL_PSS_SHA256_SPKI).unwrap();
    let sig256 = hex::decode(OPENSSL_PSS_SHA256_SIG).unwrap();
    verify_raw(&sha256_only, S::RSA_PSS_PSS_SHA256, OPENSSL_MSG, &sig256).unwrap();
    for scheme in [
        S::RSA_PSS_PSS_SHA384,
        S::RSA_PSS_PSS_SHA512,
        S::RSA_PSS_SHA256,
    ] {
        assert_eq!(
            verify_raw(&sha256_only, scheme, OPENSSL_MSG, &sig256),
            Err(CertificateError::UnsupportedSignatureAlgorithm.into()),
            "{scheme:?}"
        );
    }

    // The native key loader computes the same SPKI form for its own keys.
    for algorithm in [UNRESTRICTED, restricted(Sha256)] {
        let key = TestKey::server(algorithm);
        let loaded = prov::KEY_PROVIDER
            .load_private_key(key.private_key())
            .unwrap();
        assert_eq!(loaded.public_key().unwrap().as_ref(), key.spki().as_slice());
        let reference = if algorithm == UNRESTRICTED {
            &unrestricted
        } else {
            &sha256_only
        };
        // Same AlgorithmIdentifier as OpenSSL's (offset of the BIT STRING
        // differs only by the modulus).
        let alg_len = 2 + usize::from(reference[5]);
        assert_eq!(key.spki()[4..4 + alg_len], reference[4..4 + alg_len]);
    }
}

// ---------------------------------------------------------------------------
// Equivalent and rejected encodings of RSASSA-PSS-params

/// A self-signed root with `root`'s key, and an end entity with `ee`'s key
/// whose certificate signature identifier is written as `sig_alg`.
fn direct_chain(root: &TestKey, ee: &TestKey, role: Role, sig_alg: PssParams) -> PssChain {
    // A trust anchor's own signature is not validated; it uses the root
    // key's hash, if restricted.
    let root_hash = match root.algorithm {
        RsaKeyAlgorithm::RsassaPss(Some(hash)) => hash,
        _ => sig_alg.hash,
    };
    let root_cert = issue("PSS root", root, Role::Ca, "PSS root", root, root_hash);
    PssChain {
        root: root_cert,
        chain: vec![issue_with(
            "end entity",
            ee,
            role,
            "PSS root",
            root,
            sig_alg,
        )],
        key: ee.clone(),
    }
}

/// Runs a handshake with web-PKI verifiers on both sides where the client
/// offers `offer`, and returns the schemes of the server signatures the
/// client checked.
fn webpki_server_signs(
    v: ProtocolVersion,
    server: &PssChain,
    client: &PssChain,
    offer: &[SignatureScheme],
) -> Result<Vec<SignatureScheme>, Failure> {
    let (_, server_config) = webpki_configs(v, server, client);
    let webpki = WebPkiServerVerifier::builder_with_provider(server.roots(), provider())
        .build()
        .unwrap();
    let verifier = SchemeRecordingServerVerifier::new(webpki, offer);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(v))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_client_auth_cert(client.chain.clone(), client.private_key())
        .unwrap();
    let (mut client_conn, mut server_conn) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client_conn, &mut server_conn);
    if client_res.is_err() || server_res.is_err() {
        return Err((client_res, server_res));
    }
    do_handshake(&mut client_conn, &mut server_conn).unwrap();
    assert_eq!(
        server_conn.peer_certificates().unwrap(),
        client.chain.as_slice()
    );
    round_trip(&mut client_conn, &mut server_conn);
    Ok(verifier.seen())
}

#[test]
fn equivalent_key_encodings_sign_only_their_scheme() {
    init_logging();
    // Keys restricted to one hash, identified in every accepted way in
    // their key files and certificates, sign and verify exactly as the
    // canonical form does: only `rsa_pss_pss_<hash>`, with a salt of the
    // digest length, which meets any minimum up to that length (RFC 4055
    // §3.3, RFC 9846 §4.3.3).
    let mut all = RSAE.to_vec();
    all.extend(PSS_PSS);
    for hash in [Sha256, Sha384, Sha512] {
        let own = pss_pss_scheme(hash);
        let others: Vec<_> = PSS_PSS.into_iter().filter(|s| *s != own).collect();
        for form in equivalent_key_forms(hash) {
            let server_key = TestKey::server(UNRESTRICTED).encoded(form);
            let client_key = TestKey::client(UNRESTRICTED).encoded(form);
            let root = TestKey::root(RSAE_KEY);
            let server = direct_chain(
                &root,
                &server_key,
                Role::Server,
                PssParams::canonical(Sha256),
            );
            let client = direct_chain(
                &root,
                &client_key,
                Role::Client,
                PssParams::canonical(Sha256),
            );
            // The loaded key keeps the identifier of its key file.
            let loaded = prov::KEY_PROVIDER
                .load_private_key(server_key.private_key())
                .unwrap();
            assert_eq!(
                loaded.public_key().unwrap().as_ref(),
                server.spki().as_ref()
            );
            for v in VERSIONS {
                // Pinned key (the raw-key verification path).
                assert_eq!(
                    server_signs(v, &server, &all).unwrap(),
                    [own],
                    "{form:?} {v:?}"
                );
                let (client_res, server_res) = server_signs(v, &server, &others).unwrap_err();
                assert_no_common_scheme(v, client_res, server_res);
                // Certificate paths and the certificate verification path,
                // with the client authenticating with the same form.
                assert_eq!(
                    webpki_server_signs(v, &server, &client, &all).unwrap(),
                    [own],
                    "{form:?} {v:?}"
                );
            }
        }
    }
}

#[test]
fn equivalent_identifiers_in_certificate_chains_validate() {
    init_logging();
    // CA keys and certificate signature identifiers in equivalent forms:
    // absent hash parameters and an explicit trailer field 1 in the
    // signature identifiers (whose salt stays the digest length), and CA
    // keys with short minimum salts.
    let sha256 = PssParams::canonical(Sha256);
    let sha384 = PssParams::canonical(Sha384);
    let root_forms = [
        sha256.salt(Salt::Omitted),
        sha256.salt(Salt::Explicit(0)).absent_hash_params(),
        sha256.trailer(1),
    ];
    let sig_forms = [
        sha256,
        sha256.absent_hash_params(),
        sha256.trailer(1),
        sha256.absent_hash_params().trailer(1),
    ];
    for root_form in root_forms {
        for sig_form in sig_forms {
            let root = TestKey::root(RSAE_KEY).encoded(root_form);
            let ica = TestKey::intermediate(RSAE_KEY).encoded(sha384.salt(Salt::Omitted));
            let ica_cert = issue_with("PSS CA", &ica, Role::Ca, "PSS root", &root, sig_form);
            let root_cert = issue("PSS root", &root, Role::Ca, "PSS root", &root, Sha256);
            let chain = |key: TestKey, role| PssChain {
                root: root_cert.clone(),
                chain: vec![
                    issue_with(
                        "end entity",
                        &key,
                        role,
                        "PSS CA",
                        &ica,
                        sha384.absent_hash_params().trailer(1),
                    ),
                    ica_cert.clone(),
                ],
                key,
            };
            let server = chain(TestKey::server(UNRESTRICTED), Role::Server);
            let client = chain(TestKey::client(restricted(Sha512)), Role::Client);
            for v in VERSIONS {
                let (client_config, server_config) = webpki_configs(v, &server, &client);
                let (mut client_conn, mut server_conn) = connect(client_config, server_config);
                do_handshake(&mut client_conn, &mut server_conn)
                    .unwrap_or_else(|e| panic!("{root_form:?} {sig_form:?} {v:?}: {e}"));
                assert_eq!(
                    client_conn.peer_certificates().unwrap(),
                    server.chain.as_slice()
                );
                round_trip(&mut client_conn, &mut server_conn);
            }
        }
    }
}

/// The client's result of a handshake against `server`, validated with
/// web-PKI verifiers.
fn webpki_client_result(v: ProtocolVersion, server: &PssChain) -> Result<(), Error> {
    let client = ChainSpec::direct(RSAE_KEY, Sha256, RSAE_KEY).build(Role::Client);
    let (client_config, server_config) = webpki_configs(v, server, &client);
    let (mut client_conn, mut server_conn) = connect(client_config, server_config);
    do_handshake_until_error(&mut client_conn, &mut server_conn).0
}

#[test]
fn certificate_signatures_need_a_digest_length_salt_and_the_key_hash() {
    init_logging();
    let unsupported = Err(Error::InvalidCertificate(
        CertificateError::UnsupportedSignatureAlgorithm,
    ));
    let sha256 = PssParams::canonical(Sha256);
    let server_key = TestKey::server(UNRESTRICTED);
    for (root_form, sig_alg, ok) in [
        // A key with a minimum salt of 20 or 0 bytes verifies signatures
        // with a salt of 32 bytes (RFC 4055 §3.3)...
        (sha256.salt(Salt::Omitted), sha256, true),
        (sha256.salt(Salt::Explicit(0)), sha256, true),
        // ...but signature identifiers stating another salt describe no
        // TLS scheme (RFC 9846 §4.3.3) and match no algorithm, whatever
        // the key allows; the signatures here use 32 bytes anyway.
        (
            sha256.salt(Salt::Omitted),
            sha256.salt(Salt::Omitted),
            false,
        ),
        (
            sha256.salt(Salt::Explicit(0)),
            sha256.salt(Salt::Explicit(0)),
            false,
        ),
        (sha256, sha256.salt(Salt::Explicit(31)), false),
        (sha256, sha256.salt(Salt::Explicit(33)), false),
        // A trailer field other than 1.
        (sha256, sha256.trailer(2), false),
        // A key with a short minimum salt is still restricted to its hash.
        (
            sha256.salt(Salt::Omitted).absent_hash_params(),
            PssParams::canonical(Sha384),
            false,
        ),
        (
            PssParams::canonical(Sha512).salt(Salt::Explicit(0)),
            PssParams::canonical(Sha512).absent_hash_params(),
            true,
        ),
    ] {
        let root = TestKey::root(RSAE_KEY).encoded(root_form);
        let server = direct_chain(&root, &server_key, Role::Server, sig_alg);
        let expected = if ok { Ok(()) } else { unsupported.clone() };
        for v in VERSIONS {
            assert_eq!(
                webpki_client_result(v, &server),
                expected,
                "{root_form:?} {sig_alg:?} {v:?}"
            );
        }
    }
}

#[test]
fn unsupported_and_non_der_key_parameters_stay_rejected() {
    init_logging();
    let sha256 = PssParams::canonical(Sha256);
    // (identifier, whether it is well formed but unsupported).
    let rejected = [
        (sha256.salt(Salt::Explicit(33)), true),
        (PssParams::canonical(Sha384).salt(Salt::Explicit(49)), true),
        (sha256.trailer(2), true),
        (sha256.trailer(0), true),
        // An explicit DEFAULT salt length is not DER (X.690 §11.5).
        (sha256.salt(Salt::Explicit(20)), false),
    ];
    let unsupported = Err(Error::InvalidCertificate(
        CertificateError::UnsupportedSignatureAlgorithm,
    ));
    for (form, well_formed) in rejected {
        // As a CA key: the chain does not validate.
        let root = TestKey::root(RSAE_KEY).encoded(form);
        let server = direct_chain(&root, &TestKey::server(UNRESTRICTED), Role::Server, sha256);
        for v in VERSIONS {
            assert_eq!(
                webpki_client_result(v, &server),
                unsupported,
                "{form:?} {v:?}"
            );
        }
        // As a key file: loading fails, saying why when the parameters are
        // merely unsupported.
        let err = prov::KEY_PROVIDER
            .load_private_key(TestKey::server(UNRESTRICTED).encoded(form).private_key())
            .unwrap_err()
            .to_string();
        assert_eq!(
            err.contains("unsupported RSASSA-PSS key parameters"),
            well_formed,
            "{form:?}: {err}"
        );
        // As a raw public key: no scheme verifies with it.
        let key = TestKey::server(UNRESTRICTED).encoded(form);
        let mut sig = vec![0u8; 256];
        key.key.sign_pss(Sha256, b"msg", &OsRng, &mut sig).unwrap();
        for scheme in PSS_PSS {
            assert_eq!(
                verify_raw(&key.spki(), scheme, b"msg", &sig),
                Err(CertificateError::UnsupportedSignatureAlgorithm.into()),
                "{form:?} {scheme:?}"
            );
        }
    }
    // OpenSSL's `rsa_pss_keygen_md:sha256` alone (MGF1 with SHA-1 by
    // default) is unsupported too.
    let mgf1_sha1 = TestKey {
        encoding: Some(
            hex::decode("06092a864886f70d01010a3011a00f300d06096086480165030402010500").unwrap(),
        ),
        ..TestKey::server(UNRESTRICTED)
    };
    let err = prov::KEY_PROVIDER
        .load_private_key(mgf1_sha1.private_key())
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("unsupported RSASSA-PSS key parameters"),
        "{err}"
    );
}

#[test]
fn key_file_and_certificate_must_encode_the_key_alike() {
    init_logging();
    // The loaded key's SPKI is its key file's, byte for byte, and the
    // certificate/key consistency check compares bytes: equivalent but
    // differently written identifiers are reported as a mismatch.
    let canonical = TestKey::server(restricted(Sha256));
    let omitted = canonical
        .clone()
        .encoded(PssParams::canonical(Sha256).salt(Salt::Omitted));
    let root = TestKey::root(RSAE_KEY);
    for (cert_key, file_key, ok) in [
        (&omitted, &omitted, true),
        (&canonical, &canonical, true),
        (&omitted, &canonical, false),
        (&canonical, &omitted, false),
    ] {
        let chain = direct_chain(&root, cert_key, Role::Server, PssParams::canonical(Sha256));
        let result = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.chain.clone(), file_key.private_key())
            .map(|_| ());
        if ok {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err(),
                Error::InconsistentKeys(browntls::InconsistentKeys::KeyMismatch)
            );
        }
    }
}

#[test]
fn scheme_table_canonicalises_equivalent_key_encodings() {
    // The raw-key path: each accepted form of a key restricted to one hash
    // verifies that hash's `rsa_pss_pss_*` scheme only.
    let mut sig = vec![0u8; 256];
    for hash in [Sha256, Sha384, Sha512] {
        for form in equivalent_key_forms(hash) {
            let key = TestKey::server(UNRESTRICTED).encoded(form);
            for scheme in RSAE[..3].iter().chain(&PSS_PSS) {
                key.key
                    .sign_pss(scheme_hash(*scheme), b"msg", &OsRng, &mut sig)
                    .unwrap();
                let res = verify_raw(&key.spki(), *scheme, b"msg", &sig);
                if *scheme == pss_pss_scheme(hash) {
                    res.unwrap();
                    assert_eq!(
                        verify_raw(&key.spki(), *scheme, b"msh", &sig),
                        Err(CertificateError::BadSignature.into())
                    );
                } else {
                    assert_eq!(
                        res,
                        Err(CertificateError::UnsupportedSignatureAlgorithm.into()),
                        "{form:?} {scheme:?}"
                    );
                }
            }
        }
    }
}
