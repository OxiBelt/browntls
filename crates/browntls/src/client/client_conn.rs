//! Client configuration and connections.

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use browntls_pki::{ServerName, UnixTime};

use super::handy::NoClientSessionStorage;
use super::hs;
use crate::builder::{ConfigBuilder, WantsVersions};
use crate::common_state::{CommonState, Side};
use crate::compress;
use crate::conn::{ConnectionCore, SideData};
use crate::crypto::{CryptoProvider, SupportedKxGroup};
use crate::enums::{CipherSuite, ProtocolVersion, SignatureScheme};
use crate::error::Error;
use crate::key_log::KeyLog;
#[cfg(feature = "tls12")]
use crate::msgs::enums::NamedGroup;
#[cfg(not(feature = "tls12"))]
use crate::msgs::enums::NamedGroup;
#[cfg(feature = "tls12")]
use crate::msgs::persist::Tls12ClientSessionValue;
use crate::msgs::persist::Tls13ClientSessionValue;
use crate::sign::CertifiedKey;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::time_provider::TimeProvider;
use crate::verify::ServerCertVerifier;
use crate::versions::EnabledVersions;

/// Stores session state for resumption, keyed by server name.
pub trait ClientSessionStore: fmt::Debug + Send + Sync {
    /// Remembers which key exchange group `server_name` accepted.
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup);

    /// The group `server_name` last accepted, if remembered.
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup>;

    /// Stores a TLS 1.2 session for `server_name`.
    #[cfg(feature = "tls12")]
    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue);

    /// The stored TLS 1.2 session for `server_name`, if any.
    #[cfg(feature = "tls12")]
    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue>;

    /// Forgets the TLS 1.2 session for `server_name`.
    #[cfg(feature = "tls12")]
    fn remove_tls12_session(&self, server_name: &ServerName<'static>);

    /// Stores a TLS 1.3 ticket for `server_name`.
    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue);

    /// Removes and returns a TLS 1.3 ticket for `server_name`.
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue>;
}

/// Chooses the client certificate to present.
pub trait ResolvesClientCert: fmt::Debug + Send + Sync {
    /// Picks a certificate acceptable to the given issuers and schemes, or `None`.
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>>;

    /// Whether the resolver only yields raw public keys (RFC 7250).
    fn only_raw_public_keys(&self) -> bool {
        false
    }

    /// Whether any certificate might be returned at all.
    fn has_certs(&self) -> bool;
}

/// Configuration shared by all connections a client makes.
///
/// Build one with [`ClientConfig::builder`] and share it in an `Arc`.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// ALPN protocols to offer, in preference order.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// How sessions are stored and resumed.
    pub resumption: Resumption,

    /// The maximum record size including header; `None` means the protocol maximum.
    pub max_fragment_size: Option<usize>,

    /// Chooses the client certificate when the server asks for one.
    pub client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,

    /// Whether to send the server name in the ClientHello.
    pub enable_sni: bool,

    /// Where session secrets are logged (debugging only).
    pub key_log: Arc<dyn KeyLog>,

    /// Whether `dangerous_extract_secrets` is allowed.
    pub enable_secret_extraction: bool,

    /// Whether to send 0-RTT data when a session allows it.
    pub enable_early_data: bool,

    /// Whether TLS 1.2 servers must support the extended master secret (RFC 7627).
    pub require_ems: bool,

    /// The clock.
    pub time_provider: Arc<dyn TimeProvider>,

    /// Compressors for our own certificate (RFC 8879), in preference order.
    pub cert_compressors: Vec<&'static dyn compress::CertCompressor>,

    /// Cache of compressed certificate messages.
    pub cert_compression_cache: Arc<compress::CompressionCache>,

    /// Decompressors to offer for the server's certificate (RFC 8879).
    pub cert_decompressors: Vec<&'static dyn compress::CertDecompressor>,

    pub(super) versions: EnabledVersions,
    pub(super) verifier: Arc<dyn ServerCertVerifier>,
    pub(super) provider: Arc<CryptoProvider>,
}

impl ClientConfig {
    /// Starts a builder with the process-default provider and all versions.
    #[cfg(feature = "std")]
    pub fn builder() -> ConfigBuilder<Self, crate::WantsVerifier> {
        Self::builder_with_protocol_versions(crate::versions::DEFAULT_VERSIONS)
    }

    /// Starts a builder with the process-default provider and `versions`.
    ///
    /// # Panics
    ///
    /// Panics if no default provider is available; use
    /// [`Self::builder_with_provider`] to avoid that.
    #[cfg(feature = "std")]
    #[allow(clippy::panic)] // documented: no fallible API exists for this constructor
    pub fn builder_with_protocol_versions(
        versions: &[&'static crate::versions::SupportedProtocolVersion],
    ) -> ConfigBuilder<Self, crate::WantsVerifier> {
        let provider = CryptoProvider::get_default_or_install_from_crate_features()
            .unwrap_or_else(|err| panic!("{err}"));
        // The default provider always has usable suites and groups.
        Self::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap_or_else(|err| panic!("{err}"))
    }

    /// Starts a builder with `provider`.
    pub fn builder_with_provider(
        provider: Arc<CryptoProvider>,
    ) -> ConfigBuilder<Self, WantsVersions> {
        #[cfg(feature = "std")]
        let time_provider = Arc::new(crate::time_provider::DefaultTimeProvider);
        #[cfg(not(feature = "std"))]
        let time_provider = Arc::new(NoTime);
        Self::builder_with_details(provider, time_provider)
    }

    /// Starts a builder with `provider` and `time_provider`.
    pub fn builder_with_details(
        provider: Arc<CryptoProvider>,
        time_provider: Arc<dyn TimeProvider>,
    ) -> ConfigBuilder<Self, WantsVersions> {
        ConfigBuilder {
            state: WantsVersions {},
            provider,
            time_provider,
            side: PhantomData,
        }
    }

    /// Whether the configuration only uses FIPS-validated components.
    pub fn fips(&self) -> bool {
        self.provider.fips() && self.require_ems
    }

    /// The provider.
    pub fn crypto_provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }

    /// Accesses settings that weaken security.
    pub fn dangerous(&mut self) -> danger::DangerousClientConfig<'_> {
        danger::DangerousClientConfig { cfg: self }
    }

    pub(super) fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.versions.contains(v)
    }

    pub(super) fn find_cipher_suite(&self, suite: CipherSuite) -> Option<SupportedCipherSuite> {
        self.provider
            .cipher_suites
            .iter()
            .copied()
            .find(|s| s.suite() == suite)
    }

    pub(super) fn find_kx_group(
        &self,
        group: NamedGroup,
        version: ProtocolVersion,
    ) -> Option<&'static dyn SupportedKxGroup> {
        self.provider
            .kx_groups
            .iter()
            .copied()
            .find(|g| g.name() == group && g.usable_for_version(version))
    }

    pub(super) fn current_time(&self) -> Result<UnixTime, Error> {
        self.time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)
    }

    pub(super) fn verifier(&self) -> &dyn ServerCertVerifier {
        &*self.verifier
    }
}

/// A clock for builds without `std`; configurations must replace it.
#[cfg(not(feature = "std"))]
#[derive(Debug)]
struct NoTime;

#[cfg(not(feature = "std"))]
impl TimeProvider for NoTime {
    fn current_time(&self) -> Option<UnixTime> {
        None
    }
}

/// Session resumption settings.
#[derive(Clone, Debug)]
pub struct Resumption {
    pub(super) store: Arc<dyn ClientSessionStore>,
    pub(super) tls12_resumption: Tls12Resumption,
}

impl Resumption {
    /// Stores up to `num` sessions in memory.
    #[cfg(feature = "std")]
    pub fn in_memory_sessions(num: usize) -> Self {
        Self {
            store: Arc::new(super::handy::ClientSessionMemoryCache::new(num)),
            tls12_resumption: Tls12Resumption::SessionIdOrTickets,
        }
    }

    /// Uses `store`.
    pub fn store(store: Arc<dyn ClientSessionStore>) -> Self {
        Self {
            store,
            tls12_resumption: Tls12Resumption::SessionIdOrTickets,
        }
    }

    /// Never resumes sessions.
    pub fn disabled() -> Self {
        Self {
            store: Arc::new(NoClientSessionStorage),
            tls12_resumption: Tls12Resumption::Disabled,
        }
    }

    /// Sets how TLS 1.2 sessions may be resumed.
    pub fn tls12_resumption(mut self, tls12: Tls12Resumption) -> Self {
        self.tls12_resumption = tls12;
        self
    }
}

impl Default for Resumption {
    /// 256 in-memory sessions with `std`; disabled otherwise.
    fn default() -> Self {
        #[cfg(feature = "std")]
        {
            Self::in_memory_sessions(256)
        }
        #[cfg(not(feature = "std"))]
        {
            Self::disabled()
        }
    }
}

/// How TLS 1.2 sessions may be resumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls12Resumption {
    /// Never resume TLS 1.2 sessions.
    Disabled,
    /// Resume only with session IDs (RFC 5246 §7.4.1.2).
    SessionIdOnly,
    /// Resume with session IDs or tickets (RFC 5077).
    SessionIdOrTickets,
}

/// Settings that weaken security.
pub(crate) mod danger {
    use super::ClientConfig;
    use crate::sync::Arc;
    use crate::verify::ServerCertVerifier;

    /// Access to the certificate verifier of a built configuration.
    #[derive(Debug)]
    pub struct DangerousClientConfig<'a> {
        /// The configuration.
        pub cfg: &'a mut ClientConfig,
    }

    impl DangerousClientConfig<'_> {
        /// Replaces the server certificate verifier.
        pub fn set_certificate_verifier(&mut self, verifier: Arc<dyn ServerCertVerifier>) {
            self.cfg.verifier = verifier;
        }
    }
}

/// Per-connection client data.
#[derive(Debug)]
pub struct ClientConnectionData {
    pub(super) tls13_tickets_received: u32,
}

impl ClientConnectionData {
    fn new() -> Self {
        Self {
            tls13_tickets_received: 0,
        }
    }
}

impl SideData for ClientConnectionData {}

impl ConnectionCore<ClientConnectionData> {
    pub(crate) fn for_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        let mut common_state = CommonState::new(Side::Client);
        common_state.set_max_fragment_size(config.max_fragment_size)?;
        common_state.enable_secret_extraction = config.enable_secret_extraction;
        common_state.fips = config.fips();
        let mut data = ClientConnectionData::new();
        let mut cx = crate::conn::Context {
            common: &mut common_state,
            data: &mut data,
        };
        let state = hs::start_handshake(name, alpn_protocols, config, &mut cx)?;
        Ok(Self::new(state, data, common_state))
    }
}

/// A client-side TLS connection.
#[cfg(feature = "std")]
pub struct ClientConnection {
    inner: crate::conn::ConnectionCommon<ClientConnectionData>,
}

#[cfg(feature = "std")]
impl ClientConnection {
    /// Starts a connection to `name` with `config`; the ClientHello is queued immediately.
    pub fn new(config: Arc<ClientConfig>, name: ServerName<'static>) -> Result<Self, Error> {
        let alpn = config.alpn_protocols.clone();
        Self::new_with_alpn(config, name, alpn)
    }

    /// Like [`Self::new`] with ALPN protocols overriding the configuration's.
    pub fn new_with_alpn(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: ConnectionCore::for_client(config, name, alpn_protocols)?.into(),
        })
    }

    /// How many TLS 1.3 tickets the server has sent so far.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.inner.core.data.tls13_tickets_received
    }

    /// Whether the connection only uses FIPS-validated components.
    pub fn fips(&self) -> bool {
        self.inner.core.common_state.fips()
    }

    /// See [`crate::ConnectionCommon::dangerous_extract_secrets`].
    pub fn dangerous_extract_secrets(self) -> Result<crate::suites::ExtractedSecrets, Error> {
        self.inner.dangerous_extract_secrets()
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConnection").finish_non_exhaustive()
    }
}

#[cfg(feature = "std")]
impl core::ops::Deref for ClientConnection {
    type Target = crate::conn::ConnectionCommon<ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(feature = "std")]
impl core::ops::DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(feature = "std")]
impl From<ClientConnection> for crate::conn::Connection {
    fn from(conn: ClientConnection) -> Self {
        Self::Client(conn)
    }
}
