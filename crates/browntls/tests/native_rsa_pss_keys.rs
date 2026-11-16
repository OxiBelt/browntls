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

#[path = "native_rsa_pss_keys/misbehaving_peers.rs"]
mod misbehaving_peers;
#[path = "native_rsa_pss_keys/params_encodings.rs"]
mod params_encodings;
#[path = "native_rsa_pss_keys/path_validation.rs"]
mod path_validation;
#[path = "native_rsa_pss_keys/scheme_table.rs"]
mod scheme_table;
#[path = "native_rsa_pss_keys/signing.rs"]
mod signing;

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

fn scheme_hash(scheme: SignatureScheme) -> HashAlgorithm {
    match scheme {
        S::RSA_PSS_SHA256 | S::RSA_PSS_PSS_SHA256 => Sha256,
        S::RSA_PSS_SHA384 | S::RSA_PSS_PSS_SHA384 => Sha384,
        S::RSA_PSS_SHA512 | S::RSA_PSS_PSS_SHA512 => Sha512,
        other => panic!("not an RSASSA-PSS scheme: {other:?}"),
    }
}

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
