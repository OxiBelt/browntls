//! The server half of the configuration builder.

use alloc::vec::Vec;
use core::marker::PhantomData;

use browntls_pki::{CertificateDer, PrivateKeyDer};

use super::{ResolvesServerCert, ServerConfig, handy};
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::psk::ResolvesExternalPsk;
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;
use crate::verify::{ClientCertVerifier, NoClientAuth};
use crate::{compress, versions};

impl ConfigBuilder<ServerConfig, WantsVerifier> {
    /// Authenticates clients with `client_cert_verifier`.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ConfigBuilder {
            state: WantsServerCert {
                versions: self.state.versions,
                verifier: client_cert_verifier,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Does not ask clients for certificates.
    pub fn with_no_client_auth(self) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        self.with_client_cert_verifier(Arc::new(NoClientAuth))
    }
}

/// The builder is waiting for the server's certificate.
#[derive(Clone)]
pub struct WantsServerCert {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn ClientCertVerifier>,
}

impl core::fmt::Debug for WantsServerCert {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WantsServerCert")
            .field("versions", &self.versions)
            .finish_non_exhaustive()
    }
}

impl ConfigBuilder<ServerConfig, WantsServerCert> {
    /// Serves one certificate chain with `key_der`.
    pub fn with_single_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, self.crypto_provider())?;
        Ok(self.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
    }

    /// Like [`Self::with_single_cert`], stapling `ocsp` when clients ask.
    pub fn with_single_cert_with_ocsp(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
        ocsp: Vec<u8>,
    ) -> Result<ServerConfig, Error> {
        let mut certified_key =
            CertifiedKey::from_der(cert_chain, key_der, self.crypto_provider())?;
        if !ocsp.is_empty() {
            certified_key.ocsp = Some(ocsp);
        }
        Ok(self.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
    }

    /// Picks the certificate per connection with `cert_resolver`.
    pub fn with_cert_resolver(self, cert_resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
        let require_ems = self.provider.fips();
        ServerConfig {
            provider: self.provider,
            verifier: self.state.verifier,
            cert_resolver,
            ignore_client_order: false,
            max_fragment_size: None,
            #[cfg(feature = "std")]
            session_storage: handy::ServerSessionMemoryCache::new(256),
            #[cfg(not(feature = "std"))]
            session_storage: Arc::new(handy::NoServerSessionStorage {}),
            ticketer: Arc::new(handy::NeverProducesTickets {}),
            #[cfg(feature = "tls12")]
            dtls12_ticketer: Arc::new(handy::NeverProducesTickets {}),
            #[cfg(feature = "tls12")]
            dtls12_resumption_context: None,
            alpn_protocols: Vec::new(),
            versions: self.state.versions,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            max_early_data_size: 0,
            send_half_rtt_data: false,
            send_tls13_tickets: 2,
            request_client_auth_after_handshake: false,
            hello_retry_cookies: None,
            require_ems,
            allow_mac_then_encrypt: false,
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            cert_decompression_limit: compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE,
            external_psks: None,
            cert_with_extern_psk: false,
            require_cert_with_extern_psk: false,
            require_external_psk: false,
            client_certificate_url: None,
            enable_delegated_credentials: false,
            record_size_limit: Some(crate::common_state::max_record_size_limit(true)),
            external_binding: None,
            enable_grease: false,
            ech: None,
            ech_backend: false,
            cached_info: Default::default(),
        }
    }

    /// Serves only TLS 1.3 clients that offer one of the external PSKs
    /// `psks` finds (RFC 9846 §4.3.11); without a certificate, a client
    /// that offers none is refused with `handshake_failure`.
    pub fn with_external_psks_only(self, psks: Arc<dyn ResolvesExternalPsk>) -> ServerConfig {
        let mut config = self.with_cert_resolver(Arc::new(handy::NoServerCert));
        config.external_psks = Some(psks);
        config
    }
}
