//! The client half of the configuration builder.

use alloc::vec::Vec;
use core::marker::PhantomData;

use browntls_pki::{CertificateDer, PrivateKeyDer};

use super::client_conn::Resumption;
use super::{ClientConfig, ResolvesClientCert, handy};
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;
use crate::webpki::{self, WebPkiServerVerifier};
use crate::{compress, verify, versions};

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Trusts the roots in `root_store`, using the provider's verification
    /// algorithms and no revocation checking.
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let algorithms = self.provider.signature_verification_algorithms;
        self.with_webpki_verifier(Arc::new(WebPkiServerVerifier::new_without_revocation(
            root_store, algorithms,
        )))
    }

    /// Uses a configured [`WebPkiServerVerifier`].
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<WebPkiServerVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                versions: self.state.versions,
                verifier,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Accesses the configuration options that bypass certificate verification.
    pub fn dangerous(self) -> danger::DangerousClientConfigBuilder {
        danger::DangerousClientConfigBuilder { cfg: self }
    }
}

/// Builder options that can disable server authentication.
pub(super) mod danger {
    use core::marker::PhantomData;

    use crate::client::WantsClientCert;
    use crate::sync::Arc;
    use crate::{ClientConfig, ConfigBuilder, WantsVerifier, verify};

    /// A builder that accepts any [`ServerCertVerifier`](verify::ServerCertVerifier).
    #[derive(Debug)]
    pub struct DangerousClientConfigBuilder {
        /// The wrapped builder.
        pub cfg: ConfigBuilder<ClientConfig, WantsVerifier>,
    }

    impl DangerousClientConfigBuilder {
        /// Uses `verifier` to decide whether servers are trusted.
        pub fn with_custom_certificate_verifier(
            self,
            verifier: Arc<dyn verify::ServerCertVerifier>,
        ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
            ConfigBuilder {
                state: WantsClientCert {
                    versions: self.cfg.state.versions,
                    verifier,
                },
                provider: self.cfg.provider,
                time_provider: self.cfg.time_provider,
                side: PhantomData,
            }
        }
    }
}

/// The builder is waiting for the client's own certificate, if any.
#[derive(Clone)]
pub struct WantsClientCert {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
}

impl core::fmt::Debug for WantsClientCert {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WantsClientCert")
            .field("versions", &self.versions)
            .finish_non_exhaustive()
    }
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Authenticates with `cert_chain` and `key_der` when the server asks.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, &self.provider)?;
        Ok(self.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
    }

    /// Never authenticates to servers.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Picks the client certificate per connection with `client_auth_cert_resolver`.
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        let require_ems = self.provider.fips();
        ClientConfig {
            provider: self.provider,
            alpn_protocols: Vec::new(),
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            require_ems,
            require_secure_renegotiation: true,
            allow_mac_then_encrypt: false,
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
        }
    }
}
