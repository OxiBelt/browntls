// Shared cases: TLS 1.3 authentication with ML-DSA keys
// (`draft-ietf-tls-mldsa-06`) between a browntls client and server, over
// the in-memory record layer with `ClientConnection` and
// `ServerConnection`. Included by the target of each provider that has the
// opt-in (`tests/mldsa_tls13_native.rs` for the native provider).
//
// Contract with the including target, which declares at its root:
//
// * `mod prov` (provider-specific), with:
//   - `fn provider() -> CryptoProvider`: the provider as it comes, without
//     any ML-DSA opt-in;
//   - `fn provider_with_ml_dsa() -> CryptoProvider`: both ML-DSA opt-ins,
//     the TLS 1.3 handshake signature table as
//     `signature_verification_algorithms` and the ML-DSA key loader as
//     `key_provider`;
//   - `fn provider_with_ml_dsa_certificates() -> CryptoProvider`: the
//     X.509-only ML-DSA table (certificate paths only, no TLS scheme) and
//     the default key loader;
//   - everything `tests/common/mod.rs` needs from `prov` (one of
//     `tests/providers/*.rs` re-exported: `default_provider`,
//     `SUPPORTED_SIG_ALGS`, `SIGNS_RSA`, `NAME`).
// * `mod common` (`tests/common/mod.rs`), `mod ml_dsa` and `mod x509` (the
//   `browntls-pki/tests/common/{ml_dsa,x509_builder}.rs` support files) and
//   `mod support` (`tests/native_mldsa/support.rs`, which signs with
//   `browntls_crypto::mldsa`, so the target needs the `native` feature
//   whichever provider it tests).
//
// The cases reach the provider only through these three functions, so that
// another provider's target can run every case by supplying its own `prov`.

use std::sync::Arc;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::ServerCertVerifier;
use browntls_core::crypto::CryptoProvider;
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::server::danger::ClientCertVerifier;
use browntls_core::sign::{CertifiedKey, Signer, SigningKey};
use browntls_core::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, ConnectionCommon, Error,
    HandshakeKind, PeerIncompatible, PeerMisbehaved, ProtocolVersion, RootCertStore, ServerConfig,
    ServerConnection, SideData, SignatureAlgorithm, SignatureScheme, version,
};
use common::{
    SchemeRecordingClientVerifier, SchemeRecordingServerVerifier, do_handshake_until_error,
    send_and_receive, transfer,
};
use ml_dsa::{Key, Set};
use support::{Impl, Issuer, MlKey, Purpose};

#[cfg(any(feature = "zlib", feature = "brotli", feature = "zstd"))]
#[path = "../common/counting_decompressor.rs"]
mod counting_decompressor;
#[cfg(any(feature = "zlib", feature = "brotli", feature = "zstd"))]
use counting_decompressor::Counting;

/// The scheme of each parameter set (§3 of the draft).
fn scheme_of(set: Set) -> SignatureScheme {
    match set {
        Set::MlDsa44 => SignatureScheme::ML_DSA_44,
        Set::MlDsa65 => SignatureScheme::ML_DSA_65,
        Set::MlDsa87 => SignatureScheme::ML_DSA_87,
    }
}

const ML_DSA_SCHEMES: [SignatureScheme; 3] = [
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_87,
];

fn arc(provider: CryptoProvider) -> Arc<CryptoProvider> {
    Arc::new(provider)
}

/// The default provider with only the key loader opt-in: it signs with
/// ML-DSA keys but neither offers nor verifies ML-DSA signatures.
fn provider_with_ml_dsa_keys_only() -> CryptoProvider {
    let mut provider = prov::provider();
    provider.key_provider = prov::provider_with_ml_dsa().key_provider;
    provider
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// The algorithm of a certificate's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alg {
    Ml(Set),
    /// ECDSA P-256 (a fresh key each time).
    P256,
}

/// A key held for an issuer or an end entity.
enum Held {
    Ml(Arc<MlKey>),
    P256(Key),
}

impl Held {
    fn new(alg: Alg, label: &str) -> Self {
        match alg {
            Alg::Ml(set) => Self::Ml(Arc::new(MlKey::new(set, label))),
            Alg::P256 => Self::P256(Key::p256()),
        }
    }

    fn issuer(&self) -> Issuer<'_> {
        match self {
            Self::Ml(key) => Issuer::MlDsa(key, Impl::Native),
            Self::P256(key) => Issuer::Classical(key),
        }
    }

    fn oracle(&self) -> &Key {
        match self {
            Self::Ml(key) => &key.oracle,
            Self::P256(key) => key,
        }
    }

    fn pkcs8(&self) -> PrivateKeyDer<'static> {
        let der = match self {
            Self::Ml(key) => key.pkcs8_der(),
            Self::P256(Key::P256(pair)) => pair.serialize_der(),
            Self::P256(_) => unreachable!(),
        };
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
    }
}

/// An end entity with its chain and private key.
struct Identity {
    alg: Alg,
    root: CertificateDer<'static>,
    /// The end entity, then the intermediates: what a peer sends.
    chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    /// The ML-DSA end-entity key, for test doubles that sign with it.
    ml: Option<Arc<MlKey>>,
}

/// An end entity of `ee` for `purpose` under the CAs `cas` (the root
/// first). Keys come from `label`, so two identities with the same label
/// and ML-DSA CAs share their CA certificates.
fn identity(ee: Alg, cas: &[Alg], purpose: Purpose, label: &str) -> Identity {
    let ca_keys: Vec<Held> = cas
        .iter()
        .enumerate()
        .map(|(i, alg)| Held::new(*alg, &format!("{label} CA {i}")))
        .collect();
    let ee_key = Held::new(ee, &format!("{label} end entity {purpose:?}"));
    let intermediates: Vec<(Issuer<'_>, Option<&[u8]>)> = ca_keys[1..]
        .iter()
        .map(|key| (key.issuer(), None))
        .collect();
    let chain = support::build_chain(
        ca_keys[0].issuer(),
        &intermediates,
        ee_key.oracle(),
        purpose,
    );
    Identity {
        alg: ee,
        root: CertificateDer::from(chain.root),
        chain: std::iter::once(chain.ee)
            .chain(chain.intermediates)
            .map(CertificateDer::from)
            .collect(),
        private_key: ee_key.pkcs8(),
        ml: match &ee_key {
            Held::Ml(key) => Some(key.clone()),
            Held::P256(_) => None,
        },
    }
}

fn server_id(alg: Alg) -> Identity {
    identity(alg, &[alg], Purpose::Server, "server")
}

fn client_id(alg: Alg) -> Identity {
    identity(alg, &[alg], Purpose::Client, "client")
}

impl Identity {
    fn roots(&self) -> Arc<RootCertStore> {
        roots(&[self])
    }

    /// The end entity's key loaded by `provider`'s key loader.
    fn signing_key(&self, provider: &CryptoProvider) -> Arc<dyn SigningKey> {
        provider
            .key_provider
            .load_private_key(self.private_key.clone_key())
            .unwrap()
    }

    fn certified_key(&self, provider: &CryptoProvider) -> CertifiedKey {
        CertifiedKey::new(self.chain.clone(), self.signing_key(provider))
    }

    /// The scheme its key signs `CertificateVerify` with here.
    fn scheme(&self) -> SignatureScheme {
        match self.alg {
            Alg::Ml(set) => scheme_of(set),
            Alg::P256 => SignatureScheme::ECDSA_NISTP256_SHA256,
        }
    }
}

fn roots(ids: &[&Identity]) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for id in ids {
        roots.add(id.root.clone()).unwrap();
    }
    Arc::new(roots)
}

fn server_name() -> ServerName<'static> {
    ServerName::try_from("example.com").unwrap()
}

// ---------------------------------------------------------------------------
// Verifiers and configurations (TLS 1.3 only)
// ---------------------------------------------------------------------------

/// The library's server certificate verifier for `server`'s root, wrapped
/// to record the scheme of every handshake signature it checks.
fn server_verifier(
    provider: CryptoProvider,
    server: &Identity,
) -> Arc<SchemeRecordingServerVerifier> {
    let inner = WebPkiServerVerifier::builder_with_provider(server.roots(), arc(provider))
        .build()
        .unwrap();
    let offer = inner.supported_verify_schemes();
    SchemeRecordingServerVerifier::new(inner, &offer)
}

/// As [`server_verifier`], offering only `offer`.
fn server_verifier_offering(
    provider: CryptoProvider,
    server: &Identity,
    offer: &[SignatureScheme],
) -> Arc<SchemeRecordingServerVerifier> {
    let inner = WebPkiServerVerifier::builder_with_provider(server.roots(), arc(provider))
        .build()
        .unwrap();
    SchemeRecordingServerVerifier::new(inner, offer)
}

/// The library's client certificate verifier for `client`'s root, wrapped
/// to record the scheme of every client signature it checks.
fn client_verifier(
    provider: CryptoProvider,
    client: &Identity,
    mandatory: bool,
) -> Arc<SchemeRecordingClientVerifier> {
    let builder = WebPkiClientVerifier::builder_with_provider(client.roots(), arc(provider));
    let inner = if mandatory {
        builder.build()
    } else {
        builder.allow_unauthenticated().build()
    }
    .unwrap();
    let offer = inner.supported_verify_schemes();
    SchemeRecordingClientVerifier::new(inner, &offer)
}

fn client_config(
    provider: CryptoProvider,
    verifier: Arc<dyn ServerCertVerifier>,
    client: Option<&Identity>,
) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(arc(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    match client {
        Some(id) => builder
            .with_client_auth_cert(id.chain.clone(), id.private_key.clone_key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    }
}

fn server_config(
    provider: CryptoProvider,
    server: &Identity,
    verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> ServerConfig {
    let builder = ServerConfig::builder_with_provider(arc(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap();
    match verifier {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(server.chain.clone(), server.private_key.clone_key())
    .unwrap()
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

/// Application data flows both ways.
fn exchange(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(send_and_receive(client, server, b"ping"), b"ping");
    assert_eq!(send_and_receive(server, client, b"pong"), b"pong");
}

/// Moves everything `from` has to send into `to`, processing `to`'s
/// records whenever its receive buffer is full, then processes the rest.
/// Unlike `common::transfer`, it never leaves part of a flight behind when
/// the receiver has something to write first, which matters for flights
/// larger than the receive buffer (ML-DSA-87 chains). Returns the bytes
/// moved.
fn pump<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    to: &mut ConnectionCommon<B>,
) -> Result<usize, Error> {
    let flight = common::hello_wire::take_flight(from);
    feed(to, &flight)?;
    Ok(flight.len())
}

/// Gives `bytes` to `to` and processes them, processing as often as its
/// receive buffer fills up.
fn feed<B: SideData>(to: &mut ConnectionCommon<B>, mut bytes: &[u8]) -> Result<(), Error> {
    for _ in 0..1000 {
        if bytes.is_empty() {
            break;
        }
        match to.read_tls(&mut bytes) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Other => {
                to.process_new_packets()?;
            }
            Err(e) => panic!("read_tls failed: {e}"),
        }
    }
    assert!(bytes.is_empty(), "the receiver took no more data");
    to.process_new_packets()?;
    Ok(())
}

/// Completes a handshake with [`pump`].
fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
        pump(client, server)?;
        pump(server, client)?;
    }
    panic!("handshake did not complete")
}

/// A full TLS 1.3 handshake with `server` authenticating to an opt-in
/// client, and `client` (if any) to an opt-in server with mandatory client
/// authentication. Returns the connections and both recorders.
fn ml_dsa_handshake(
    server: &Identity,
    client: Option<&Identity>,
) -> (
    ClientConnection,
    ServerConnection,
    Arc<SchemeRecordingServerVerifier>,
    Option<Arc<SchemeRecordingClientVerifier>>,
) {
    let server_verifier = server_verifier(prov::provider_with_ml_dsa(), server);
    let client_verifier =
        client.map(|client| client_verifier(prov::provider_with_ml_dsa(), client, true));
    let (mut c, mut s) = connect(
        client_config(
            prov::provider_with_ml_dsa(),
            server_verifier.clone(),
            client,
        ),
        server_config(
            prov::provider_with_ml_dsa(),
            server,
            client_verifier
                .clone()
                .map(|v| v as Arc<dyn ClientCertVerifier>),
        ),
    );
    handshake(&mut c, &mut s).unwrap();
    (c, s, server_verifier, client_verifier)
}

include!("mldsa_tls13/auth.rs");
include!("mldsa_tls13/negotiation.rs");
include!("mldsa_tls13/misbehaving.rs");
include!("mldsa_tls13/features.rs");
include!("mldsa_tls13/side_mechanisms.rs");
include!("mldsa_tls13/scheme_order.rs");
include!("mldsa_tls13/cross_config.rs");
