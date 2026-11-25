// Shared cases: the legacy RSASSA-PKCS1-v1_5 signature schemes of RFC 9963
// (`rsa_pkcs1_sha256_legacy` 0x0420, `rsa_pkcs1_sha384_legacy` 0x0520,
// `rsa_pkcs1_sha512_legacy` 0x0620) in TLS 1.3 client authentication, over
// the in-memory record layer, between browntls peers and against rustls
// 0.23 (an independent implementation, driven in memory as in
// `cases/interop.rs`). Included by `tests/rsa_pkcs1_legacy_native.rs`
// (native provider) and `tests/rsa_pkcs1_legacy.rs` (RustCrypto provider).
//
// Contract with the including target, which declares at its root:
//
// * `mod prov` (provider-specific), with:
//   - `fn provider() -> CryptoProvider`: the provider as it comes, without
//     the opt-in;
//   - `fn provider_with_rsa_pkcs1_legacy() -> CryptoProvider`: the
//     provider's `SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY` as
//     `signature_verification_algorithms`, everything else as it comes;
//   - everything `tests/common/mod.rs` needs from `prov` (one of
//     `tests/providers/*.rs` re-exported: `default_provider`,
//     `SUPPORTED_SIG_ALGS`, `SIGNS_RSA`, `NAME`).
// * `mod common` (`tests/common/mod.rs`).
//
// The cases reach the provider only through these functions and
// constants, so that another provider's target can run every case by
// supplying its own `prov`. The client's legacy key is a test double, a
// stand-in for an RSA key in a hardware token that cannot make RSASSA-PSS
// signatures: a `SigningKey` on the `rsa` crate (an independent RSA
// implementation), which chooses a legacy scheme from the offered list,
// signs with RSASSA-PKCS1-v1_5 and records every list it is offered.
// Variants of it send malformed or mislabelled signatures. Cases that
// need a provider whose own keys sign with RSA are in
// `rsa_pkcs1_legacy/native_only.rs`.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};

use browntls_core::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use browntls_core::client::{ResolvesClientCert, WebPkiServerVerifier};
use browntls_core::crypto::CryptoProvider;
use browntls_core::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use browntls_core::server::danger::ClientCertVerifier;
use browntls_core::server::{PostHandshakeAuthStatus, WebPkiClientVerifier};
use browntls_core::sign::{CertifiedKey, Signer, SigningKey};
use browntls_core::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct,
    Error, PeerMisbehaved, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    SignatureAlgorithm, SignatureScheme, SupportedProtocolVersion, version,
};
use common::{
    Chain, KeyType, SchemeRecordingClientVerifier, SchemeRecordingServerVerifier,
    do_handshake_until_error, send_and_receive, transfer,
};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::{Digest, Sha256, Sha384, Sha512};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer as _};

use SignatureScheme as S;

/// The legacy schemes in code point order.
const LEGACY: [S; 3] = [
    S::RSA_PKCS1_SHA256_LEGACY,
    S::RSA_PKCS1_SHA384_LEGACY,
    S::RSA_PKCS1_SHA512_LEGACY,
];

/// The legacy schemes as the opt-in tables list them: larger hashes first.
const OPT_IN_ORDER: [S; 3] = [
    S::RSA_PKCS1_SHA512_LEGACY,
    S::RSA_PKCS1_SHA384_LEGACY,
    S::RSA_PKCS1_SHA256_LEGACY,
];

fn is_legacy(scheme: &S) -> bool {
    matches!(u16::from(*scheme), 0x0420 | 0x0520 | 0x0620)
}

const BAD_SIGNATURE: Error = Error::InvalidCertificate(CertificateError::BadSignature);
const UNSUPPORTED: Error =
    Error::InvalidCertificate(CertificateError::UnsupportedSignatureAlgorithm);
const UNADVERTISED: Error =
    Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme);

// ---------------------------------------------------------------------------
// Chains (generated once per target: RSA key generation is slow)
// ---------------------------------------------------------------------------

/// A client chain whose end entity has an `rsaEncryption` key.
fn rsa_client() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(|| common::client_chain(KeyType::Rsa2048))
}

/// The ECDSA P-256 server chain every browntls server here presents
/// (each provider signs with it).
fn server() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(|| common::server_chain(KeyType::EcdsaP256))
}

/// A server chain whose end entity has an `rsaEncryption` key.
fn rsa_server() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(|| common::server_chain(KeyType::Rsa2048))
}

/// The private key of an RSA chain, for the `rsa` crate.
fn rsa_key(chain: &Chain) -> Arc<rsa::PrivateKey> {
    assert_eq!(chain.key_type, KeyType::Rsa2048);
    Arc::new(rsa::PrivateKey::from_pkcs8_der(&chain.end_entity_key).unwrap())
}

fn roots(chain: &Chain) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    Arc::new(roots)
}

// ---------------------------------------------------------------------------
// RSASSA-PKCS1-v1_5 with the `rsa` crate
// ---------------------------------------------------------------------------

/// The hash of a scheme of the key doubles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// The hash of a legacy, `rsa_pkcs1_*` or `rsa_pss_rsae_*` scheme.
    fn of(scheme: S) -> Self {
        match u16::from(scheme) {
            0x0420 | 0x0401 | 0x0804 => Self::Sha256,
            0x0520 | 0x0501 | 0x0805 => Self::Sha384,
            0x0620 | 0x0601 | 0x0806 => Self::Sha512,
            other => panic!("no RSA hash for {other:#06x}"),
        }
    }

    /// Another hash, whose identifier and digest a mislabelled signature
    /// carries.
    fn other(self) -> Self {
        match self {
            Self::Sha256 => Self::Sha384,
            Self::Sha384 => Self::Sha512,
            Self::Sha512 => Self::Sha256,
        }
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha384 => Sha384::digest(message).to_vec(),
            Self::Sha512 => Sha512::digest(message).to_vec(),
        }
    }

    /// The DER contents of the hash's object identifier
    /// (2.16.840.1.101.3.4.2.1, .2 and .3).
    fn oid(self) -> [u8; 9] {
        let last = match self {
            Self::Sha256 => 1,
            Self::Sha384 => 2,
            Self::Sha512 => 3,
        };
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last]
    }

    /// RSASSA-PKCS1-v1_5 with this hash, as the `rsa` crate makes it.
    fn pkcs1(self, key: &rsa::PrivateKey, message: &[u8]) -> Vec<u8> {
        let key = key.clone();
        match self {
            Self::Sha256 => rsa::pkcs1v15::SigningKey::<Sha256>::new(key)
                .sign(message)
                .to_vec(),
            Self::Sha384 => rsa::pkcs1v15::SigningKey::<Sha384>::new(key)
                .sign(message)
                .to_vec(),
            Self::Sha512 => rsa::pkcs1v15::SigningKey::<Sha512>::new(key)
                .sign(message)
                .to_vec(),
        }
    }

    /// RSASSA-PSS with this hash (MGF1 with the same hash, a salt as long
    /// as the digest), as the `rsa` crate makes it.
    fn pss(self, key: &rsa::PrivateKey, message: &[u8]) -> Vec<u8> {
        let key = key.clone();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        match self {
            Self::Sha256 => rsa::pss::SigningKey::<Sha256>::new(key)
                .sign_with_rng(&mut rng, message)
                .to_vec(),
            Self::Sha384 => rsa::pss::SigningKey::<Sha384>::new(key)
                .sign_with_rng(&mut rng, message)
                .to_vec(),
            Self::Sha512 => rsa::pss::SigningKey::<Sha512>::new(key)
                .sign_with_rng(&mut rng, message)
                .to_vec(),
        }
    }
}

/// A DER TLV with a short-form length.
fn tlv(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let body = parts.concat();
    [&[tag, u8::try_from(body.len()).unwrap()][..], &body].concat()
}

/// `DigestInfo` (RFC 8017 §9.2) of `digest` under `hash`'s identifier, in
/// DER, with or without the NULL parameters.
fn digest_info(hash: Hash, digest: &[u8], null: bool) -> Vec<u8> {
    let oid = tlv(0x06, &[&hash.oid()]);
    let params: &[u8] = if null { &[0x05, 0x00] } else { &[] };
    let algorithm = tlv(0x30, &[&oid, params]);
    tlv(0x30, &[&algorithm, &tlv(0x04, &[digest])])
}

/// A signature whose encoded message is `00 01 FF.. 00 || t` (RFC 8017
/// §9.2 step 5 with `t` as given): RSASSA-PKCS1-v1_5 when `t` is the DER
/// `DigestInfo`, a malformed variant otherwise.
fn sign_raw(key: &rsa::PrivateKey, t: &[u8]) -> Vec<u8> {
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), t).unwrap()
}

/// How a [`TokenKey`]'s signer forms the signature it sends, under the
/// scheme it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sig {
    /// RSASSA-PKCS1-v1_5 with the scheme's hash: what RFC 9963 §3 asks.
    Pkcs1,
    /// The `DigestInfo` without the NULL parameters of its algorithm.
    NoNull,
    /// The `DigestInfo` with a long-form length where DER requires the
    /// short form.
    BerLength,
    /// The bare digest, with no `DigestInfo` around it.
    BareDigest,
    /// The identifier of another hash around the right digest.
    WrongOid,
    /// A well-formed RSASSA-PKCS1-v1_5 signature with another hash.
    WrongHash,
    /// A well-formed signature over another message.
    OtherMessage,
    /// A valid signature without its last byte.
    Short,
    /// A valid signature after a zero byte (the same integer, one byte
    /// longer than the modulus).
    Long,
    /// RSASSA-PSS with the scheme's hash.
    Pss,
}

impl Sig {
    fn sign(self, key: &rsa::PrivateKey, hash: Hash, message: &[u8]) -> Vec<u8> {
        let digest = hash.digest(message);
        match self {
            Self::Pkcs1 => hash.pkcs1(key, message),
            Self::NoNull => sign_raw(key, &digest_info(hash, &digest, false)),
            Self::BerLength => {
                let mut t = digest_info(hash, &digest, true);
                let len = t[1];
                t.splice(1..2, [0x81, len]);
                sign_raw(key, &t)
            }
            Self::BareDigest => sign_raw(key, &digest),
            Self::WrongOid => sign_raw(key, &digest_info(hash.other(), &digest, true)),
            Self::WrongHash => hash.other().pkcs1(key, message),
            Self::OtherMessage => hash.pkcs1(key, &[message, b"!"].concat()),
            Self::Short => {
                let mut signature = hash.pkcs1(key, message);
                signature.pop();
                signature
            }
            Self::Long => [&[0][..], &hash.pkcs1(key, message)].concat(),
            Self::Pss => hash.pss(key, message),
        }
    }
}

// ---------------------------------------------------------------------------
// Key doubles
// ---------------------------------------------------------------------------

/// Which scheme a [`TokenKey`] names.
#[derive(Debug)]
enum Choose {
    /// The first of these that is offered; none if none is.
    First(Vec<S>),
    /// This one, whatever is offered.
    Always(S),
}

/// An RSA key that signs as `sig` says with the `rsa` crate, choosing its
/// scheme as `choose` says, and records every list of schemes it is
/// offered: a stand-in for a hardware token whose RSA key signs with
/// RSASSA-PKCS1-v1_5 only.
#[derive(Debug)]
struct TokenKey {
    key: Arc<rsa::PrivateKey>,
    spki: SubjectPublicKeyInfoDer<'static>,
    choose: Choose,
    sig: Sig,
    offered: Mutex<Vec<Vec<S>>>,
}

impl TokenKey {
    /// The key of `chain` choosing the first of `schemes` that is offered.
    fn choosing(chain: &Chain, schemes: &[S], sig: Sig) -> Arc<Self> {
        Self::new(chain, Choose::First(schemes.to_vec()), sig)
    }

    /// The key of [`rsa_client`], preferring `prefer` and otherwise taking
    /// another legacy scheme, never anything else.
    fn legacy(prefer: S, sig: Sig) -> Arc<Self> {
        let mut schemes = vec![prefer];
        schemes.extend(OPT_IN_ORDER.into_iter().filter(|s| *s != prefer));
        Self::choosing(rsa_client(), &schemes, sig)
    }

    /// The key of [`rsa_client`] naming `scheme` whatever is offered.
    fn ignoring_offer(scheme: S, sig: Sig) -> Arc<Self> {
        Self::new(rsa_client(), Choose::Always(scheme), sig)
    }

    fn new(chain: &Chain, choose: Choose, sig: Sig) -> Arc<Self> {
        Arc::new(Self {
            key: rsa_key(chain),
            spki: chain.spki(),
            choose,
            sig,
            offered: Mutex::new(Vec::new()),
        })
    }

    /// Every list offered so far.
    fn offered(&self) -> Vec<Vec<S>> {
        self.offered.lock().unwrap().clone()
    }
}

impl SigningKey for TokenKey {
    fn choose_scheme(&self, offered: &[S]) -> Option<Box<dyn Signer>> {
        self.offered.lock().unwrap().push(offered.to_vec());
        let scheme = match &self.choose {
            Choose::First(schemes) => *schemes.iter().find(|s| offered.contains(s))?,
            Choose::Always(scheme) => *scheme,
        };
        Some(Box::new(TokenSigner {
            key: self.key.clone(),
            scheme,
            sig: self.sig,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct TokenSigner {
    key: Arc<rsa::PrivateKey>,
    scheme: S,
    sig: Sig,
}

impl Signer for TokenSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.sig.sign(&self.key, Hash::of(self.scheme), message))
    }

    fn scheme(&self) -> S {
        self.scheme
    }
}

/// A key that names `claims` when it is offered, and signs with `real`
/// under the real key's own scheme `real_scheme`: a non-RSA certificate
/// key passed off as a legacy one.
#[derive(Debug)]
struct ClaimingKey {
    claims: S,
    real: Arc<dyn SigningKey>,
    real_scheme: S,
}

impl SigningKey for ClaimingKey {
    fn choose_scheme(&self, offered: &[S]) -> Option<Box<dyn Signer>> {
        if !offered.contains(&self.claims) {
            return None;
        }
        Some(Box::new(ClaimingSigner {
            claims: self.claims,
            real: self.real.choose_scheme(&[self.real_scheme]).unwrap(),
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.real.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.real.algorithm()
    }
}

#[derive(Debug)]
struct ClaimingSigner {
    claims: S,
    real: Box<dyn Signer>,
}

impl Signer for ClaimingSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.real.sign(message)
    }

    fn scheme(&self) -> S {
        self.claims
    }
}

/// A client certificate resolver that answers with `key` and records the
/// `sigschemes` of every request.
#[derive(Debug)]
struct Recording {
    key: Option<Arc<CertifiedKey>>,
    seen: Mutex<Vec<Vec<S>>>,
}

impl Recording {
    fn new(key: Option<CertifiedKey>) -> Arc<Self> {
        Arc::new(Self {
            key: key.map(Arc::new),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Vec<S>> {
        self.seen.lock().unwrap().clone()
    }
}

impl ResolvesClientCert for Recording {
    fn resolve(&self, _hints: &[&[u8]], sigschemes: &[S]) -> Option<Arc<CertifiedKey>> {
        self.seen.lock().unwrap().push(sigschemes.to_vec());
        self.key.clone()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Configurations
// ---------------------------------------------------------------------------

static TLS13: [&SupportedProtocolVersion; 1] = [&version::TLS13];

/// The library's client verifier for `client`'s CA, built with `provider`,
/// wrapped to record the scheme of every client signature it checks. The
/// wrapper advertises exactly what the library's verifier does.
fn client_verifier(
    provider: CryptoProvider,
    client: &Chain,
    mandatory: bool,
) -> Arc<SchemeRecordingClientVerifier> {
    let builder = WebPkiClientVerifier::builder_with_provider(roots(client), Arc::new(provider));
    let inner = if mandatory {
        builder.build()
    } else {
        builder.allow_unauthenticated().build()
    }
    .unwrap();
    let offer = inner.supported_verify_schemes();
    SchemeRecordingClientVerifier::new(inner, &offer)
}

/// The library's server verifier for `server`'s CA, built with `provider`,
/// wrapped to record the scheme of every server signature it checks.
fn server_verifier(provider: CryptoProvider, server: &Chain) -> Arc<SchemeRecordingServerVerifier> {
    let inner = WebPkiServerVerifier::builder_with_provider(roots(server), Arc::new(provider))
        .build()
        .unwrap();
    let offer = inner.supported_verify_schemes();
    SchemeRecordingServerVerifier::new(inner, &offer)
}

/// A server presenting [`server`] with `provider` and `verifier`.
fn server_config_for(
    provider: CryptoProvider,
    versions: &[&'static SupportedProtocolVersion],
    verifier: Arc<dyn ClientCertVerifier>,
) -> ServerConfig {
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server().cert_chain(), server().private_key())
        .unwrap()
}

/// A client with `provider` everywhere (its configuration and its
/// verifier of [`server`]), answering CertificateRequests with `resolver`.
fn client_config_for(
    provider: CryptoProvider,
    versions: &[&'static SupportedProtocolVersion],
    resolver: Arc<dyn ResolvesClientCert>,
) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(provider, server()))
        .with_client_cert_resolver(resolver)
}

/// A TLS 1.3 handshake and everything the cases look at afterwards.
struct Outcome {
    client: ClientConnection,
    server: ServerConnection,
    client_res: Result<(), Error>,
    server_res: Result<(), Error>,
    /// The server's client verifier.
    verifier: Arc<SchemeRecordingClientVerifier>,
    /// The client's certificate resolver.
    resolver: Arc<Recording>,
}

impl Outcome {
    /// Both sides completed, and application data flows both ways.
    fn completed(&mut self) {
        assert_eq!(self.client_res, Ok(()), "client");
        assert_eq!(self.server_res, Ok(()), "server");
        assert!(!self.client.is_handshaking() && !self.server.is_handshaking());
        assert_eq!(
            send_and_receive(&mut self.client, &mut self.server, b"ping"),
            b"ping"
        );
        assert_eq!(
            send_and_receive(&mut self.server, &mut self.client, b"pong"),
            b"pong"
        );
    }

    /// The server refused the client with `error`, and the client
    /// received `alert`.
    fn refused(&self, error: Error, alert: AlertDescription, what: &str) {
        assert_eq!(self.server_res, Err(error), "server: {what}");
        assert_eq!(
            self.client_res,
            Err(Error::AlertReceived(alert)),
            "client: {what}"
        );
    }
}

/// A TLS 1.3 handshake of a default client presenting `chain` with `key`
/// against a server whose client verifier (for `chain`'s CA) and
/// configuration are built with `server_provider`.
fn authenticate(
    server_provider: CryptoProvider,
    mandatory: bool,
    chain: &Chain,
    key: Arc<dyn SigningKey>,
) -> Outcome {
    authenticate_with(prov::provider(), server_provider, mandatory, chain, key)
}

/// As [`authenticate`], with `client_provider` everywhere on the client.
fn authenticate_with(
    client_provider: CryptoProvider,
    server_provider: CryptoProvider,
    mandatory: bool,
    chain: &Chain,
    key: Arc<dyn SigningKey>,
) -> Outcome {
    let verifier = client_verifier(server_provider.clone(), chain, mandatory);
    let resolver = Recording::new(Some(CertifiedKey::new(chain.cert_chain(), key)));
    let mut client = ClientConnection::new(
        Arc::new(client_config_for(client_provider, &TLS13, resolver.clone())),
        common::server_name(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config_for(
        server_provider,
        &TLS13,
        verifier.clone(),
    )))
    .unwrap();
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    Outcome {
        client,
        server,
        client_res,
        server_res,
        verifier,
        resolver,
    }
}

/// The provider's default schemes that TLS 1.3 allows (RFC 9846 §4.2.3:
/// no RSASSA-PKCS1-v1_5, SHA-1 or DSA), in the provider's order: what a
/// default server's TLS 1.3 CertificateRequest lists.
fn default_tls13_schemes() -> Vec<S> {
    prov::SUPPORTED_SIG_ALGS
        .supported_schemes()
        .into_iter()
        .filter(|s| {
            let [hash, sign] = u16::from(*s).to_be_bytes();
            hash >= 4 && sign != 1 && sign != 2
        })
        .collect()
}

include!("rsa_pkcs1_legacy/auth.rs");
include!("rsa_pkcs1_legacy/encoding.rs");
include!("rsa_pkcs1_legacy/rustls_peers.rs");
#[cfg(feature = "tls12")]
include!("rsa_pkcs1_legacy/tls12.rs");
