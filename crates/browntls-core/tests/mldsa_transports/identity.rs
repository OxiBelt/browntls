//! ML-DSA identities (`root -> intermediate -> end entity`, every key of
//! one parameter set) and the TLS 1.3 configurations of both sides with the
//! native provider's ML-DSA opt-in (`draft-ietf-tls-mldsa-06`).
//!
//! Certificates come from `native_mldsa/support.rs`; the end entity's
//! private key is the RFC 9881 §6 PKCS #8 `seed` form of the same FIPS 204
//! seed, written by `browntls_crypto::mldsa`.

use std::sync::Arc;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::ServerCertVerifier as _;
use browntls_core::crypto::{CryptoProvider, native};
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::version::TLS13;
use browntls_core::{ClientConfig, ServerConfig, SignatureScheme, SupportedProtocolVersion};
use browntls_crypto::mldsa::{self, MlDsa44, MlDsa65, MlDsa87, ParameterSet, PrivateKeyFormat};
use sha2::Digest as _;

use crate::common::{SchemeRecordingClientVerifier, SchemeRecordingServerVerifier};
use crate::ml_dsa::Set;
use crate::support::{Chain, Impl, Issuer, MlKey, Purpose, build_chain};

/// The TLS 1.3 scheme of `set` (0x0904 to 0x0906).
pub(crate) fn scheme(set: Set) -> SignatureScheme {
    match set {
        Set::MlDsa44 => SignatureScheme::ML_DSA_44,
        Set::MlDsa65 => SignatureScheme::ML_DSA_65,
        Set::MlDsa87 => SignatureScheme::ML_DSA_87,
    }
}

/// The name in the server certificates (`support::Purpose::Server`).
pub(crate) fn server_name() -> ServerName<'static> {
    ServerName::try_from("example.com").unwrap()
}

/// The native provider with both halves of the opt-in: the TLS 1.3
/// verification table and the key provider that loads ML-DSA keys.
pub(crate) fn opt_in() -> Arc<CryptoProvider> {
    let mut provider = native::default_provider();
    provider.signature_verification_algorithms = native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13;
    provider.key_provider = native::KEY_PROVIDER_WITH_ML_DSA;
    Arc::new(provider)
}

/// The PKCS #8 `seed` form of the key `MlKey::new(set, label)` holds.
fn pkcs8(key: &MlKey, label: &str) -> Vec<u8> {
    fn write<P: ParameterSet>(seed: &[u8; 32], public_key: &[u8]) -> Vec<u8> {
        let key = mldsa::SigningKey::<P>::from_seed(seed);
        assert_eq!(key.verifying_key().as_bytes(), public_key);
        let mut der = vec![0; mldsa::SigningKey::<P>::PKCS8_MAX_LEN];
        let len = key.to_pkcs8_der(PrivateKeyFormat::Seed, &mut der).unwrap();
        der.truncate(len);
        der
    }
    // The derivation of `MlKey::new`; the public key check above fails if
    // the two drift apart.
    let seed: [u8; 32] =
        sha2::Sha256::digest(format!("browntls native ML-DSA test {:?} {label}", key.set)).into();
    let public_key = key.native_public_key();
    match key.set {
        Set::MlDsa44 => write::<MlDsa44>(&seed, &public_key),
        Set::MlDsa65 => write::<MlDsa65>(&seed, &public_key),
        Set::MlDsa87 => write::<MlDsa87>(&seed, &public_key),
    }
}

/// A chain whose three keys are of one parameter set, and the end
/// entity's private key.
#[derive(Debug)]
pub(crate) struct Identity {
    pub(crate) chain: Chain,
    key: Vec<u8>,
    /// Whether the peer is also sent the root (a three-certificate
    /// Certificate message, over 16 kB with ML-DSA-87).
    pub(crate) send_root: bool,
}

impl Identity {
    pub(crate) fn new(set: Set, purpose: Purpose) -> Self {
        let side = match purpose {
            Purpose::Server => "server",
            Purpose::Client => "client",
        };
        let root = MlKey::new(set, &format!("transports {side} root"));
        let int = MlKey::new(set, &format!("transports {side} intermediate"));
        let ee_label = format!("transports {side} end entity");
        let ee = MlKey::new(set, &ee_label);
        let chain = build_chain(
            Issuer::MlDsa(&root, Impl::Native),
            &[(Issuer::MlDsa(&int, Impl::Native), None)],
            &ee.oracle,
            purpose,
        );
        let key = pkcs8(&ee, &ee_label);
        Self {
            chain,
            key,
            send_root: false,
        }
    }

    /// End entity and intermediate (and root if `send_root`), as a peer
    /// sends them.
    pub(crate) fn served(&self) -> Vec<CertificateDer<'static>> {
        let root = self.send_root.then_some(&self.chain.root);
        std::iter::once(&self.chain.ee)
            .chain(&self.chain.intermediates)
            .chain(root)
            .map(|der| CertificateDer::from(der.clone()))
            .collect()
    }

    pub(crate) fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()))
    }

    /// The library's server verifier for this chain's root with the opt-in
    /// table, recording the scheme of every handshake signature.
    pub(crate) fn server_verifier(&self) -> Arc<SchemeRecordingServerVerifier> {
        let inner = WebPkiServerVerifier::builder_with_provider(self.chain.roots(), opt_in())
            .build()
            .unwrap();
        let offer = inner.supported_verify_schemes();
        assert_eq!(
            offer,
            native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.supported_schemes()
        );
        SchemeRecordingServerVerifier::new(inner, &offer)
    }

    /// The library's client verifier (client authentication mandatory),
    /// recording likewise.
    pub(crate) fn client_verifier(&self) -> Arc<SchemeRecordingClientVerifier> {
        let inner = WebPkiClientVerifier::builder_with_provider(self.chain.roots(), opt_in())
            .build()
            .unwrap();
        let offer = native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.supported_schemes();
        assert_eq!(inner.supported_verify_schemes(), offer);
        SchemeRecordingClientVerifier::new(inner, &offer)
    }
}

/// The TLS 1.3 versions both sides allow unless a test says otherwise.
pub(crate) const TLS13_ONLY: &[&SupportedProtocolVersion] = &[&TLS13];

/// A server with `server`'s identity, and client authentication against
/// `client`'s root when given.
pub(crate) fn server_config(
    server: &Identity,
    client: Option<&Arc<SchemeRecordingClientVerifier>>,
    versions: &[&'static SupportedProtocolVersion],
) -> ServerConfig {
    let builder = ServerConfig::builder_with_provider(opt_in())
        .with_protocol_versions(versions)
        .unwrap();
    let builder = match client {
        Some(verifier) => builder.with_client_cert_verifier(verifier.clone()),
        None => builder.with_no_client_auth(),
    };
    builder
        .with_single_cert(server.served(), server.private_key())
        .unwrap()
}

/// A client verifying through `verifier`, authenticating with `client`
/// when given.
pub(crate) fn client_config(
    verifier: &Arc<SchemeRecordingServerVerifier>,
    client: Option<&Identity>,
    versions: &[&'static SupportedProtocolVersion],
) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(opt_in())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone());
    match client {
        Some(id) => builder
            .with_client_auth_cert(id.served(), id.private_key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    }
}

/// The configurations of one handshake and their recorders.
pub(crate) struct Setup {
    pub(crate) client: Arc<ClientConfig>,
    pub(crate) server: Arc<ServerConfig>,
    /// The client's verifier: the server's `CertificateVerify` schemes.
    pub(crate) server_auth: Arc<SchemeRecordingServerVerifier>,
    /// The server's verifier: the client's `CertificateVerify` schemes.
    pub(crate) client_auth: Option<Arc<SchemeRecordingClientVerifier>>,
    pub(crate) server_id: Identity,
}

impl Setup {
    /// TLS 1.3 with an ML-DSA server of `set`, and an ML-DSA client of the
    /// same set if `mutual`.
    pub(crate) fn new(set: Set, mutual: bool) -> Self {
        Self::build(set, mutual, false, |_, _| {})
    }

    /// As [`Self::new`], each side also sending its root.
    pub(crate) fn sending_roots(set: Set, mutual: bool) -> Self {
        Self::build(set, mutual, true, |_, _| {})
    }

    /// As [`Self::new`], with the configurations adjusted by `tweak`
    /// before use.
    pub(crate) fn with(
        set: Set,
        mutual: bool,
        tweak: impl FnOnce(&mut ClientConfig, &mut ServerConfig),
    ) -> Self {
        Self::build(set, mutual, false, tweak)
    }

    fn build(
        set: Set,
        mutual: bool,
        send_root: bool,
        tweak: impl FnOnce(&mut ClientConfig, &mut ServerConfig),
    ) -> Self {
        let identity = |purpose| Identity {
            send_root,
            ..Identity::new(set, purpose)
        };
        let server_id = identity(Purpose::Server);
        let client_id = mutual.then(|| identity(Purpose::Client));
        let server_auth = server_id.server_verifier();
        let client_auth = client_id.as_ref().map(Identity::client_verifier);
        let mut client = client_config(&server_auth, client_id.as_ref(), TLS13_ONLY);
        let mut server = server_config(&server_id, client_auth.as_ref(), TLS13_ONLY);
        tweak(&mut client, &mut server);
        Self {
            client: Arc::new(client),
            server: Arc::new(server),
            server_auth,
            client_auth,
            server_id,
        }
    }

    /// Each side's verifier checked exactly one signature, of `set`'s
    /// scheme (none on the server unless `mutual`).
    pub(crate) fn assert_schemes(&self, set: Set) {
        assert_eq!(self.server_auth.seen(), [scheme(set)], "{set:?} server");
        if let Some(client_auth) = &self.client_auth {
            assert_eq!(client_auth.seen(), [scheme(set)], "{set:?} client");
        }
    }
}
