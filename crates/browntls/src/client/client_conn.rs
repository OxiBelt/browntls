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
use crate::log::trace;
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

    /// Whether a TLS 1.2 server must acknowledge secure renegotiation
    /// (RFC 5746). On by default: RFC 9325 §3.5 requires a client to abort
    /// otherwise, since such a server is vulnerable to renegotiation attacks
    /// whether or not either side renegotiates. Turn off only for a legacy
    /// server known not to renegotiate.
    pub require_secure_renegotiation: bool,

    /// Whether a TLS 1.2 CBC cipher suite may be used without the
    /// `encrypt_then_mac` extension (RFC 7366). Off by default (RFC 9325
    /// §4.2): the MAC-then-encrypt construction of RFC 5246 is decrypted in
    /// constant time, but its padding oracle history is the reason for the
    /// extension. Irrelevant unless the provider offers a CBC suite.
    pub allow_mac_then_encrypt: bool,

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

/// Where 0-RTT stands on a client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyDataState {
    /// Not offered (no ticket allowing it, or disabled by configuration).
    Disabled,
    /// Offered in the ClientHello; the server has not answered yet.
    Ready,
    /// The server accepted it; EndOfEarlyData is still to be sent.
    Accepted,
    /// Accepted, and EndOfEarlyData has been sent.
    AcceptedFinished,
    /// The server declined it (or a HelloRetryRequest made it moot).
    Rejected,
}

/// The client's 0-RTT bookkeeping.
#[derive(Debug)]
pub(super) struct EarlyData {
    state: EarlyDataState,
    /// How many more bytes the server's `max_early_data_size` allows.
    left: usize,
}

impl EarlyData {
    fn new() -> Self {
        Self {
            state: EarlyDataState::Disabled,
            left: 0,
        }
    }

    /// Whether early data is being, or may still be, sent.
    pub(super) fn is_enabled(&self) -> bool {
        matches!(self.state, EarlyDataState::Ready | EarlyDataState::Accepted)
    }

    pub(super) fn is_accepted(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Accepted | EarlyDataState::AcceptedFinished
        )
    }

    pub(super) fn enable(&mut self, max_data: usize) {
        debug_assert_eq!(self.state, EarlyDataState::Disabled);
        self.state = EarlyDataState::Ready;
        self.left = max_data;
    }

    pub(super) fn rejected(&mut self) {
        trace!("EarlyData rejected");
        self.state = EarlyDataState::Rejected;
    }

    pub(super) fn accepted(&mut self) {
        trace!("EarlyData accepted");
        debug_assert_eq!(self.state, EarlyDataState::Ready);
        self.state = EarlyDataState::Accepted;
    }

    pub(super) fn finished(&mut self) {
        trace!("EarlyData finished");
        debug_assert_eq!(self.state, EarlyDataState::Accepted);
        self.state = EarlyDataState::AcceptedFinished;
    }

    /// How many of `sz` bytes may still be sent as early data, or `None`
    /// once no more may be sent at all.
    fn check_write(&mut self, sz: usize) -> Option<usize> {
        match self.state {
            EarlyDataState::Ready | EarlyDataState::Accepted => {
                let take = sz.min(self.left);
                self.left -= take;
                Some(take)
            }
            EarlyDataState::Disabled
            | EarlyDataState::Rejected
            | EarlyDataState::AcceptedFinished => None,
        }
    }
}

/// Per-connection client data.
#[derive(Debug)]
pub struct ClientConnectionData {
    pub(super) tls13_tickets_received: u32,
    pub(super) early_data: EarlyData,
    /// Where the TLS 1.2 session for `server_name` lives, so a fatal error
    /// can forget it.
    session_store: Arc<dyn ClientSessionStore>,
    server_name: ServerName<'static>,
}

impl ClientConnectionData {
    fn new(session_store: Arc<dyn ClientSessionStore>, server_name: ServerName<'static>) -> Self {
        Self {
            tls13_tickets_received: 0,
            early_data: EarlyData::new(),
            session_store,
            server_name,
        }
    }
}

impl SideData for ClientConnectionData {
    fn on_fatal_error(&mut self, negotiated_version: Option<ProtocolVersion>) {
        // RFC 5246 §7.2.2: the session of a connection that failed cannot be
        // resumed. Before the ServerHello no session belongs to this
        // connection yet; TLS 1.3 tickets are single-use anyway.
        #[cfg(feature = "tls12")]
        if negotiated_version == Some(ProtocolVersion::TLSv1_2) {
            self.session_store.remove_tls12_session(&self.server_name);
        }
        #[cfg(not(feature = "tls12"))]
        let _ = negotiated_version;
    }
}

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
        let mut data = ClientConnectionData::new(config.resumption.store.clone(), name.clone());
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

    /// A writer for TLS 1.3 0-RTT ("early") data, while that is possible.
    ///
    /// Returns `None` unless the configuration enables early data, the
    /// resumed session's ticket permits it, and the server has not yet
    /// declined it. Writes beyond the ticket's `max_early_data_size` are
    /// refused. Early data is **replayable** by an attacker and must only
    /// carry idempotent requests; the server may also silently discard it, so
    /// check [`Self::is_early_data_accepted`] after the handshake and resend
    /// if needed.
    pub fn early_data(&mut self) -> Option<WriteEarlyData<'_>> {
        if self.inner.core.data.early_data.is_enabled() {
            Some(WriteEarlyData { conn: self })
        } else {
            None
        }
    }

    /// Whether the server accepted the early data sent so far.
    ///
    /// Meaningful once the handshake has finished (and only if
    /// [`Self::early_data`] was used).
    pub fn is_early_data_accepted(&self) -> bool {
        self.inner.core.data.early_data.is_accepted()
    }

    fn write_early_data(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let Some(take) = self.inner.core.data.early_data.check_write(data.len()) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        Ok(self
            .inner
            .core
            .common_state
            .send_early_plaintext(&data[..take]))
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

/// An [`std::io::Write`] for early data; see [`ClientConnection::early_data`].
#[cfg(feature = "std")]
pub struct WriteEarlyData<'a> {
    conn: &'a mut ClientConnection,
}

#[cfg(feature = "std")]
impl WriteEarlyData<'_> {
    /// How many more bytes of early data the server allows.
    pub fn bytes_left(&self) -> usize {
        self.conn.inner.core.data.early_data.left
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for WriteEarlyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteEarlyData")
            .field("bytes_left", &self.bytes_left())
            .finish()
    }
}

#[cfg(feature = "std")]
impl std::io::Write for WriteEarlyData<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.conn.write_early_data(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
