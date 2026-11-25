//! The identities and TLS 1.3 configurations of both sides: an RSA client
//! whose key is `native::sign::any_rsa_pkcs1_legacy_type`, and an ECDSA
//! P-256 server whose client verifier is built with or without the opt-in
//! table `native::SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY`.
//!
//! The chains come from `common` and are generated once per target: RSA
//! key generation is slow.

use std::sync::{Arc, OnceLock};

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::ServerCertVerifier as _;
use browntls_core::crypto::{CryptoProvider, native};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::server::danger::ClientCertVerifier as _;
use browntls_core::sign::{CertifiedKey, SigningKey};
use browntls_core::version::TLS13;
use browntls_core::{
    ClientConfig, RootCertStore, ServerConfig, SignatureScheme, SupportedProtocolVersion,
};

use crate::common::{
    self, Chain, KeyType, SchemeRecordingClientVerifier, SchemeRecordingServerVerifier,
};

/// The legacy schemes as an opted-in CertificateRequest lists them.
pub(crate) const OPT_IN_ORDER: [SignatureScheme; 3] = [
    SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
    SignatureScheme::RSA_PKCS1_SHA384_LEGACY,
    SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
];

pub(crate) fn is_legacy(scheme: &SignatureScheme) -> bool {
    matches!(u16::from(*scheme), 0x0420 | 0x0520 | 0x0620)
}

/// A client chain whose end entity has an `rsaEncryption` key.
pub(crate) fn rsa_client() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(|| common::client_chain(KeyType::Rsa2048))
}

/// The ECDSA P-256 server chain, for `common::server_name`.
pub(crate) fn server() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(|| common::server_chain(KeyType::EcdsaP256))
}

/// The native provider with the opt-in table as
/// `signature_verification_algorithms`.
pub(crate) fn opt_in() -> Arc<CryptoProvider> {
    let mut provider = native::default_provider();
    provider.signature_verification_algorithms = native::SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY;
    Arc::new(provider)
}

/// The native provider as it comes: no legacy scheme.
pub(crate) fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(native::default_provider())
}

/// [`rsa_client`]'s key, loaded so that it signs with RSASSA-PKCS1-v1_5
/// only.
pub(crate) fn legacy_key() -> Arc<dyn SigningKey> {
    native::sign::any_rsa_pkcs1_legacy_type(&rsa_client().private_key()).unwrap()
}

/// [`rsa_client`]'s chain with [`legacy_key`].
pub(crate) fn legacy_certified_key() -> CertifiedKey {
    CertifiedKey::new(rsa_client().cert_chain(), legacy_key())
}

fn roots(chain: &Chain) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    Arc::new(roots)
}

/// The library's client verifier for [`rsa_client`]'s CA (client
/// authentication mandatory), built with `provider` and recording the
/// scheme of every client signature. It advertises what the library's
/// verifier does.
pub(crate) fn client_verifier(provider: Arc<CryptoProvider>) -> Arc<SchemeRecordingClientVerifier> {
    let inner = WebPkiClientVerifier::builder_with_provider(roots(rsa_client()), provider)
        .build()
        .unwrap();
    let offer = inner.supported_verify_schemes();
    SchemeRecordingClientVerifier::new(inner, &offer)
}

/// The library's server verifier for [`server`]'s CA, built with
/// `provider` and recording the scheme of every server signature.
pub(crate) fn server_verifier(provider: Arc<CryptoProvider>) -> Arc<SchemeRecordingServerVerifier> {
    let inner = WebPkiServerVerifier::builder_with_provider(roots(server()), provider)
        .build()
        .unwrap();
    let offer = inner.supported_verify_schemes();
    SchemeRecordingServerVerifier::new(inner, &offer)
}

/// The TLS 1.3 versions both sides allow unless a test says otherwise.
pub(crate) const TLS13_ONLY: &[&SupportedProtocolVersion] = &[&TLS13];

/// A server presenting [`server`] with `provider`, authenticating clients
/// through `verifier`.
pub(crate) fn server_config(
    provider: Arc<CryptoProvider>,
    verifier: &Arc<SchemeRecordingClientVerifier>,
    versions: &[&'static SupportedProtocolVersion],
) -> ServerConfig {
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(server().cert_chain(), server().private_key())
        .unwrap()
}

/// A client with `provider` verifying the server through `verifier` and
/// authenticating with [`legacy_certified_key`].
pub(crate) fn client_config(
    provider: Arc<CryptoProvider>,
    verifier: &Arc<SchemeRecordingServerVerifier>,
    versions: &[&'static SupportedProtocolVersion],
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_client_auth_certified_key(legacy_certified_key())
}

/// The configurations of one handshake and their recorders.
pub(crate) struct Setup {
    pub(crate) client: Arc<ClientConfig>,
    pub(crate) server: Arc<ServerConfig>,
    /// The client's verifier: the server's `CertificateVerify` schemes.
    pub(crate) server_auth: Arc<SchemeRecordingServerVerifier>,
    /// The server's verifier: the client's `CertificateVerify` schemes.
    pub(crate) client_auth: Arc<SchemeRecordingClientVerifier>,
}

impl Setup {
    /// TLS 1.3 with mandatory client authentication: a default client with
    /// the legacy key, and a server whose client verifier (and
    /// configuration) has the opt-in if `opted_in`.
    pub(crate) fn new(opted_in: bool) -> Self {
        Self::with(opted_in, |_, _| {})
    }

    /// As [`Self::new`], with the configurations adjusted by `tweak`
    /// before use.
    pub(crate) fn with(
        opted_in: bool,
        tweak: impl FnOnce(&mut ClientConfig, &mut ServerConfig),
    ) -> Self {
        let server_provider = if opted_in {
            opt_in()
        } else {
            default_provider()
        };
        let server_auth = server_verifier(default_provider());
        let client_auth = client_verifier(server_provider.clone());
        let offer = client_auth.supported_verify_schemes();
        assert_eq!(
            OPT_IN_ORDER.iter().all(|s| offer.contains(s)),
            opted_in,
            "{offer:?}"
        );
        assert!(opted_in || offer.iter().all(|s| !is_legacy(s)));
        let mut client = client_config(default_provider(), &server_auth, TLS13_ONLY);
        let mut server = server_config(server_provider, &client_auth, TLS13_ONLY);
        tweak(&mut client, &mut server);
        Self {
            client: Arc::new(client),
            server: Arc::new(server),
            server_auth,
            client_auth,
        }
    }

    /// The client verified the server's ECDSA P-256 signature and the
    /// server the client's `rsa_pkcs1_sha512_legacy` signature (the legacy
    /// key's first choice, which an opted-in request lists), each exactly
    /// once.
    pub(crate) fn assert_schemes(&self) {
        assert_eq!(
            self.server_auth.seen(),
            [SignatureScheme::ECDSA_NISTP256_SHA256]
        );
        assert_eq!(
            self.client_auth.seen(),
            [SignatureScheme::RSA_PKCS1_SHA512_LEGACY]
        );
    }
}
