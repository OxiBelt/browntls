//! Server configuration and connections.

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use browntls_pki::{DnsName, UnixTime};

use super::hs;
use crate::builder::{ConfigBuilder, WantsVersions};
use crate::common_state::{CommonState, Side};
use crate::compress;
use crate::conn::{ConnectionCore, SideData};
use crate::crypto::{CryptoProvider, SupportedKxGroup};
use crate::enums::{CertificateType, CipherSuite, ProtocolVersion, SignatureScheme};
use crate::error::Error;
use crate::key_log::KeyLog;
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::{ClientHelloPayload, DistinguishedName, ProtocolName};
use crate::sign::CertifiedKey;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::time_provider::TimeProvider;
use crate::vecbuf::ChunkVecBuffer;
use crate::verify::ClientCertVerifier;
use crate::versions::EnabledVersions;

/// Stores server-side session state, keyed by session ID or ticket identifier.
pub trait StoresServerSessions: fmt::Debug + Send + Sync {
    /// Stores `value` under `key`; returns whether it was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Fetches the value under `key`, leaving it in place.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Fetches and removes the value under `key`.
    fn take(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Whether `put` can ever succeed.
    fn can_cache(&self) -> bool;
}

/// Encrypts session state into tickets the client holds (RFC 5077, RFC 8446 §4.6.1).
pub trait ProducesTickets: fmt::Debug + Send + Sync {
    /// Whether tickets are issued at all.
    fn enabled(&self) -> bool;

    /// How long tickets are valid, in seconds.
    fn lifetime(&self) -> u32;

    /// Encrypts and authenticates `plain`.
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>>;

    /// Decrypts `cipher`, returning `None` if it is not authentic.
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>>;
}

/// Chooses the server certificate for a connection.
pub trait ResolvesServerCert: fmt::Debug + Send + Sync {
    /// Picks a certificate for `client_hello`, or `None` to abort.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>>;

    /// Whether the resolver only yields raw public keys (RFC 7250).
    fn only_raw_public_keys(&self) -> bool {
        false
    }
}

/// What a [`ResolvesServerCert`] sees of the ClientHello.
#[derive(Debug)]
pub struct ClientHello<'a> {
    pub(super) server_name: Option<&'a DnsName<'static>>,
    pub(super) signature_schemes: &'a [SignatureScheme],
    pub(super) alpn: Option<&'a [ProtocolName]>,
    pub(super) cipher_suites: &'a [CipherSuite],
    pub(super) certificate_authorities: Option<&'a [DistinguishedName]>,
    pub(super) named_groups: Option<&'a [NamedGroup]>,
    pub(super) client_cert_types: Option<&'a [CertificateType]>,
    pub(super) server_cert_types: Option<&'a [CertificateType]>,
}

impl<'a> ClientHello<'a> {
    pub(super) fn new(
        server_name: Option<&'a DnsName<'static>>,
        signature_schemes: &'a [SignatureScheme],
        payload: &'a ClientHelloPayload,
    ) -> Self {
        Self {
            server_name,
            signature_schemes,
            alpn: payload.alpn_protocols(),
            cipher_suites: &payload.cipher_suites,
            certificate_authorities: payload.extensions.certificate_authorities.as_deref(),
            named_groups: payload.named_groups(),
            client_cert_types: payload.extensions.client_certificate_types.as_deref(),
            server_cert_types: payload.extensions.server_certificate_types.as_deref(),
        }
    }

    /// The certificate types the client can present (RFC 7250), if it said.
    pub fn client_cert_types(&self) -> Option<&'a [CertificateType]> {
        self.client_cert_types
    }

    /// The certificate types the client accepts from us (RFC 7250), if it said.
    pub fn server_cert_types(&self) -> Option<&'a [CertificateType]> {
        self.server_cert_types
    }

    /// The server name indicated by the client, if any.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.map(|n| n.as_ref())
    }

    /// The signature schemes the client accepts.
    pub fn signature_schemes(&self) -> &[SignatureScheme] {
        self.signature_schemes
    }

    /// The ALPN protocols the client offered, if any.
    pub fn alpn(&self) -> Option<impl Iterator<Item = &'a [u8]>> {
        self.alpn
            .map(|protocols| protocols.iter().map(ProtocolName::as_ref))
    }

    /// The cipher suites the client offered.
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        self.cipher_suites
    }

    /// The certificate authorities the client trusts, if it said.
    pub fn certificate_authorities(&self) -> Option<&'a [DistinguishedName]> {
        self.certificate_authorities
    }

    /// The key exchange groups the client offered, if any.
    pub fn named_groups(&self) -> Option<&'a [NamedGroup]> {
        self.named_groups
    }
}

/// Configuration shared by all connections a server accepts.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Prefer the server's suite order over the client's.
    pub ignore_client_order: bool,

    /// The maximum record size including header; `None` means the protocol maximum.
    pub max_fragment_size: Option<usize>,

    /// Where session state is cached.
    pub session_storage: Arc<dyn StoresServerSessions>,

    /// How tickets are produced; disabled by default.
    pub ticketer: Arc<dyn ProducesTickets>,

    /// Chooses the server certificate.
    pub cert_resolver: Arc<dyn ResolvesServerCert>,

    /// ALPN protocols supported, in preference order.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// Where session secrets are logged (debugging only).
    pub key_log: Arc<dyn KeyLog>,

    /// Whether `dangerous_extract_secrets` is allowed.
    pub enable_secret_extraction: bool,

    /// How much 0-RTT data to accept; zero disables early data.
    pub max_early_data_size: u32,

    /// Whether to send application data before the client's Finished.
    pub send_half_rtt_data: bool,

    /// How many TLS 1.3 tickets to send after a handshake.
    pub send_tls13_tickets: usize,

    /// Whether TLS 1.2 clients must support the extended master secret (RFC 7627).
    pub require_ems: bool,

    /// Whether a TLS 1.2 CBC cipher suite may be selected for a client that
    /// did not offer the `encrypt_then_mac` extension (RFC 7366). Off by
    /// default (RFC 9325 §4.2); such a client then gets an AEAD suite or no
    /// connection. Irrelevant unless the provider offers a CBC suite.
    pub allow_mac_then_encrypt: bool,

    /// The clock.
    pub time_provider: Arc<dyn TimeProvider>,

    /// Compressors for our certificate (RFC 8879), in preference order.
    pub cert_compressors: Vec<&'static dyn compress::CertCompressor>,

    /// Cache of compressed certificate messages.
    pub cert_compression_cache: Arc<compress::CompressionCache>,

    /// Decompressors for client certificates (RFC 8879).
    pub cert_decompressors: Vec<&'static dyn compress::CertDecompressor>,

    pub(super) versions: EnabledVersions,
    pub(super) verifier: Arc<dyn ClientCertVerifier>,
    pub(super) provider: Arc<CryptoProvider>,
}

impl ServerConfig {
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

    pub(super) fn current_time(&self) -> Result<UnixTime, Error> {
        self.time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)
    }

    pub(super) fn kx_groups(&self) -> &[&'static dyn SupportedKxGroup] {
        &self.provider.kx_groups
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

/// Where 0-RTT stands on a server connection.
#[derive(Default)]
pub(super) enum EarlyDataState {
    /// No decision yet.
    #[default]
    New,
    /// Accepted: `received` holds the data, `left` what may still arrive.
    Accepted {
        received: ChunkVecBuffer,
        left: usize,
    },
    /// Declined (by configuration, policy, or the application).
    Rejected,
}

impl EarlyDataState {
    pub(super) fn reject(&mut self) {
        *self = Self::Rejected;
    }

    pub(super) fn accept(&mut self, max_size: usize) {
        *self = Self::Accepted {
            received: ChunkVecBuffer::new(Some(max_size)),
            left: max_size,
        };
    }

    pub(super) fn was_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub(super) fn was_rejected(&self) -> bool {
        matches!(self, Self::Rejected)
    }

    /// Stores early data; `false` if it exceeds what was announced.
    pub(super) fn take_received_plaintext(&mut self, bytes: &[u8]) -> bool {
        let Self::Accepted { received, left } = self else {
            return false;
        };
        let available = bytes.len();
        if received.apply_limit(available) != available || available > *left {
            return false;
        }
        received.append(bytes.to_vec());
        *left -= available;
        true
    }

    #[cfg(feature = "std")]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Accepted { received, .. } => Ok(received.read(buf)),
            _ => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        }
    }
}

impl fmt::Debug for EarlyDataState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => f.write_str("EarlyDataState::New"),
            Self::Accepted { received, left } => f
                .debug_struct("EarlyDataState::Accepted")
                .field("received", &received.len())
                .field("left", left)
                .finish(),
            Self::Rejected => f.write_str("EarlyDataState::Rejected"),
        }
    }
}

/// Per-connection server data.
#[derive(Debug, Default)]
pub struct ServerConnectionData {
    pub(super) sni: Option<DnsName<'static>>,
    pub(super) received_resumption_data: Option<Vec<u8>>,
    pub(super) resumption_data: Vec<u8>,
    pub(super) early_data: EarlyDataState,
    /// The session cache entry this TLS 1.2 connection resumed or created,
    /// so a fatal error can forget it (tickets are stateless and cannot be
    /// recalled).
    pub(super) tls12_session: Option<(Arc<dyn StoresServerSessions>, Vec<u8>)>,
}

impl SideData for ServerConnectionData {
    fn on_fatal_error(&mut self, _negotiated_version: Option<ProtocolVersion>) {
        // RFC 5246 §7.2.2: the session of a connection that failed cannot be
        // resumed.
        if let Some((store, id)) = self.tls12_session.take() {
            store.take(&id);
        }
    }
}

impl ConnectionCore<ServerConnectionData> {
    pub(crate) fn for_server(config: Arc<ServerConfig>) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server);
        common.set_max_fragment_size(config.max_fragment_size)?;
        common.enable_secret_extraction = config.enable_secret_extraction;
        common.fips = config.fips();
        Ok(Self::new(
            alloc::boxed::Box::new(hs::ExpectClientHello::new(config)),
            ServerConnectionData::default(),
            common,
        ))
    }
}

/// An [`std::io::Read`] for accepted early data; see [`ServerConnection::early_data`].
#[cfg(feature = "std")]
pub struct ReadEarlyData<'a> {
    early_data: &'a mut EarlyDataState,
}

#[cfg(feature = "std")]
impl fmt::Debug for ReadEarlyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadEarlyData")
            .field("state", self.early_data)
            .finish()
    }
}

#[cfg(feature = "std")]
impl std::io::Read for ReadEarlyData<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.early_data.read(buf)
    }
}

/// A server-side TLS connection.
#[cfg(feature = "std")]
pub struct ServerConnection {
    inner: crate::conn::ConnectionCommon<ServerConnectionData>,
}

#[cfg(feature = "std")]
impl ServerConnection {
    /// Prepares to accept a connection with `config`.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            inner: ConnectionCore::for_server(config)?.into(),
        })
    }

    /// The server name the client indicated, once its ClientHello was processed.
    pub fn server_name(&self) -> Option<&str> {
        self.inner.core.data.sni.as_ref().map(|n| n.as_ref())
    }

    /// Application data stored with a resumed session, once resumed.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        self.inner.core.data.received_resumption_data.as_deref()
    }

    /// Application data to store with the session for later resumption.
    ///
    /// Call before the handshake completes; it is written into the tickets.
    pub fn set_resumption_data(&mut self, data: &[u8]) {
        self.inner.core.data.resumption_data = data.to_vec();
    }

    /// Refuses any 0-RTT data on this connection.
    ///
    /// Must be called before the handshake has processed the ClientHello
    /// (right after [`Self::new`], or from a certificate resolver); a later
    /// call has no effect on data already accepted.
    pub fn reject_early_data(&mut self) {
        debug_assert!(
            self.inner.core.common_state.is_handshaking(),
            "cannot retroactively reject early data"
        );
        self.inner.core.data.early_data.reject();
    }

    /// A reader for the client's 0-RTT ("early") data, if any was accepted.
    ///
    /// Early data is enabled by a non-zero [`ServerConfig::max_early_data_size`]
    /// with stateful (non-ticket) resumption. It is **replayable** by an
    /// attacker: the application must only act on it when a replay is
    /// harmless, and the library offers no anti-replay store. Returns `None`
    /// until the ClientHello has been processed, or if early data was not
    /// offered or not accepted.
    pub fn early_data(&mut self) -> Option<ReadEarlyData<'_>> {
        let data = &mut self.inner.core.data;
        if data.early_data.was_accepted() {
            Some(ReadEarlyData {
                early_data: &mut data.early_data,
            })
        } else {
            None
        }
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
impl fmt::Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConnection").finish_non_exhaustive()
    }
}

#[cfg(feature = "std")]
impl core::ops::Deref for ServerConnection {
    type Target = crate::conn::ConnectionCommon<ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(feature = "std")]
impl core::ops::DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(feature = "std")]
impl From<ServerConnection> for crate::conn::Connection {
    fn from(conn: ServerConnection) -> Self {
        Self::Server(conn)
    }
}

/// Reads a ClientHello before choosing a [`ServerConfig`].
#[cfg(feature = "std")]
pub struct Acceptor {
    inner: Option<crate::conn::ConnectionCommon<ServerConnectionData>>,
}

#[cfg(feature = "std")]
impl Default for Acceptor {
    fn default() -> Self {
        Self {
            inner: Some(
                ConnectionCore::new(
                    alloc::boxed::Box::new(Accepting),
                    ServerConnectionData::default(),
                    CommonState::new(Side::Server),
                )
                .into(),
            ),
        }
    }
}

#[cfg(feature = "std")]
impl Acceptor {
    /// Reads TLS bytes from `rd`.
    pub fn read_tls(&mut self, rd: &mut dyn std::io::Read) -> Result<usize, std::io::Error> {
        match &mut self.inner {
            Some(conn) => conn.read_tls(rd),
            None => Err(std::io::Error::other(
                "acceptor cannot read after successful acceptance",
            )),
        }
    }

    /// Returns the ClientHello once it has been read in full.
    ///
    /// On error, the alert to send to the client is returned too.
    pub fn accept(&mut self) -> Result<Option<Accepted>, (Error, AcceptedAlert)> {
        let Some(mut connection) = self.inner.take() else {
            return Err((
                Error::general("Acceptor polled after completion"),
                AcceptedAlert::empty(),
            ));
        };

        let message = match connection
            .core
            .first_handshake_message(&mut connection.deframer_buffer)
        {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                self.inner = Some(connection);
                return Ok(None);
            }
            Err(err) => {
                // Every refusal comes with an alert the caller can send.
                let err = ConnectionCore::<ServerConnectionData>::ensure_alert_sent(
                    &mut connection.core.common_state,
                    err,
                );
                return Err((err, AcceptedAlert::from(connection)));
            }
        };

        let mut cx = crate::conn::Context {
            common: &mut connection.core.common_state,
            data: &mut connection.core.data,
        };
        let sig_schemes = match hs::process_client_hello(&message, false, &mut cx) {
            Ok((_, sig_schemes)) => sig_schemes,
            Err(err) => {
                let err = ConnectionCore::<ServerConnectionData>::ensure_alert_sent(
                    &mut connection.core.common_state,
                    err,
                );
                return Err((err, AcceptedAlert::from(connection)));
            }
        };

        Ok(Some(Accepted {
            connection,
            message,
            sig_schemes,
        }))
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acceptor").finish_non_exhaustive()
    }
}

/// The alert an [`Acceptor`] or [`Accepted`] wants to send after a failure.
#[cfg(feature = "std")]
pub struct AcceptedAlert(ChunkVecBuffer);

#[cfg(feature = "std")]
impl AcceptedAlert {
    fn empty() -> Self {
        Self(ChunkVecBuffer::new(None))
    }

    /// Writes as much of the alert as `wr` accepts.
    pub fn write(&mut self, wr: &mut dyn std::io::Write) -> Result<usize, std::io::Error> {
        self.0.write_to(wr)
    }

    /// Writes the whole alert.
    pub fn write_all(&mut self, wr: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        while self.write(wr)? != 0 {}
        Ok(())
    }
}

#[cfg(feature = "std")]
impl From<crate::conn::ConnectionCommon<ServerConnectionData>> for AcceptedAlert {
    fn from(conn: crate::conn::ConnectionCommon<ServerConnectionData>) -> Self {
        Self(conn.core.common_state.sendable_tls)
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for AcceptedAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptedAlert").finish_non_exhaustive()
    }
}

/// A ClientHello read by an [`Acceptor`], waiting for a configuration.
#[cfg(feature = "std")]
pub struct Accepted {
    connection: crate::conn::ConnectionCommon<ServerConnectionData>,
    message: crate::msgs::message::Message<'static>,
    sig_schemes: Vec<SignatureScheme>,
}

#[cfg(feature = "std")]
impl Accepted {
    /// The ClientHello.
    pub fn client_hello(&self) -> ClientHello<'_> {
        ClientHello::new(
            self.connection.core.data.sni.as_ref(),
            &self.sig_schemes,
            Self::client_hello_payload(&self.message),
        )
    }

    /// Continues the handshake with `config`.
    pub fn into_connection(
        mut self,
        config: Arc<ServerConfig>,
    ) -> Result<ServerConnection, (Error, AcceptedAlert)> {
        if let Err(err) = self
            .connection
            .set_max_fragment_size(config.max_fragment_size)
        {
            return Err((err, AcceptedAlert::from(self.connection)));
        }
        self.connection.enable_secret_extraction = config.enable_secret_extraction;
        self.connection.fips = config.fips();

        let state = hs::ExpectClientHello::new(config);
        let mut cx = crate::conn::Context {
            common: &mut self.connection.core.common_state,
            data: &mut self.connection.core.data,
        };
        let payload = Self::client_hello_payload(&self.message);
        let new = match state.with_certified_key(self.sig_schemes, payload, &self.message, &mut cx)
        {
            Ok(new) => new,
            Err(err) => return Err((err, AcceptedAlert::from(self.connection))),
        };
        self.connection.replace_state(new);
        Ok(ServerConnection {
            inner: self.connection,
        })
    }

    fn client_hello_payload<'a>(
        message: &'a crate::msgs::message::Message<'_>,
    ) -> &'a ClientHelloPayload {
        match &message.payload {
            crate::msgs::message::MessagePayload::Handshake {
                parsed:
                    crate::msgs::handshake::HandshakeMessagePayload(
                        crate::msgs::handshake::HandshakePayload::ClientHello(ch),
                    ),
                ..
            } => ch,
            // `Acceptor::accept` only constructs `Accepted` from a ClientHello.
            _ => unreachable_client_hello(),
        }
    }
}

#[cfg(feature = "std")]
#[cold]
fn unreachable_client_hello() -> &'static ClientHelloPayload {
    // `Accepted` is only built after `process_client_hello` accepted the
    // message as a ClientHello, so this cannot be reached. Returning a leaked
    // minimal payload keeps the function free of panics.
    static EMPTY: std::sync::OnceLock<ClientHelloPayload> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: crate::msgs::handshake::Random::from([0u8; 32]),
        session_id: crate::msgs::handshake::SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: Default::default(),
    })
}

#[cfg(feature = "std")]
impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted").finish_non_exhaustive()
    }
}

/// The state an [`Acceptor`] parks in: it never handles messages itself.
#[cfg(feature = "std")]
struct Accepting;

#[cfg(feature = "std")]
impl crate::conn::State<ServerConnectionData> for Accepting {
    fn handle(
        self: alloc::boxed::Box<Self>,
        _cx: &mut crate::conn::Context<'_, ServerConnectionData>,
        _message: crate::msgs::message::Message<'_>,
    ) -> Result<alloc::boxed::Box<dyn crate::conn::State<ServerConnectionData>>, Error> {
        Err(Error::general(
            "Acceptor connections cannot process messages",
        ))
    }
}
