//! Client configuration and connections.

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use browntls_pki::{ServerName, UnixTime};

#[cfg(feature = "std")]
mod buffered;

#[cfg(feature = "std")]
pub use buffered::{ClientConnection, WriteEarlyData};

use super::handy::NoClientSessionStorage;
use super::hs;
use crate::builder::{ConfigBuilder, WantsVersions};
use crate::common_state::{CommonState, Side};
use crate::compress;
use crate::conn::{ConnectionCore, SideData};
use crate::crypto::{CryptoProvider, SupportedKxGroup};
use crate::delegated_credential::DelegatedCredential;
use crate::enums::{CipherSuite, ProtocolVersion, SignatureScheme};
use crate::error::Error;
use crate::key_log::KeyLog;
use crate::log::trace;
use crate::msgs::enums::NamedGroup;
use crate::msgs::persist::ClientConfigBinding;
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
    /// Picks a certificate acceptable to the given issuers and schemes, or
    /// `None`.
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

    /// The maximum record size including header; `None` means the protocol
    /// maximum.
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

    /// Whether to offer TLS 1.3 post-handshake client authentication
    /// (RFC 9846 §4.7.2, the `post_handshake_auth` extension). Off by
    /// default. When on, and [`Self::client_auth_cert_resolver`] has
    /// certificates, the server may ask for a certificate at any time after
    /// the handshake; the connection answers at once from the resolver, with
    /// an empty Certificate when it has none suitable.
    ///
    /// RFC 8740 forbids post-handshake authentication over HTTP/2; an
    /// application speaking HTTP/2 should leave this off. The library does
    /// not tie the setting to the negotiated ALPN protocol.
    pub enable_post_handshake_auth: bool,

    /// Whether TLS 1.2 servers must support the extended master secret
    /// (RFC 7627).
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

    /// The `trusted_ca_keys` extension (RFC 6066 §6): the CA root keys we
    /// possess, so that a TLS 1.2 server may choose a certificate chain
    /// ending in one of them. `None` (the default) sends no extension;
    /// `Some(vec![])` sends an empty list, which claims a set of root keys
    /// agreed by other means. See [`TrustedAuthority`](crate::TrustedAuthority)
    /// for building identifiers from certificates or trust anchors.
    ///
    /// The extension exists in TLS 1.2 only: it is sent only when TLS 1.2
    /// is offered (never over QUIC, nor in the inner ClientHello of
    /// Encrypted Client Hello), and a TLS 1.3 server ignores it. Whether a
    /// server acknowledged it is
    /// [`ClientConnection::trusted_ca_keys_acknowledged`](crate::ClientConnection::trusted_ca_keys_acknowledged).
    /// A list of more than 1024 entries (more than a server built from this
    /// crate accepts), one that does not fit in a ClientHello, or one that
    /// holds an empty `x509_name`, makes connection creation fail.
    ///
    /// Privacy (RFC 6066 §11.4): the list is sent in the clear and tells
    /// anyone watching which root keys this client trusts, which can
    /// identify the client or its configuration.
    pub trusted_ca_keys: Option<Vec<crate::TrustedAuthority>>,

    /// The clock.
    pub time_provider: Arc<dyn TimeProvider>,

    /// Compressors for our own certificate (RFC 8879), in preference order.
    pub cert_compressors: Vec<&'static dyn compress::CertCompressor>,

    /// Cache of compressed certificate messages.
    pub cert_compression_cache: Arc<compress::CompressionCache>,

    /// Decompressors to offer for the server's certificate (RFC 8879).
    pub cert_decompressors: Vec<&'static dyn compress::CertDecompressor>,

    /// Encrypted Client Hello (RFC 9849); `None` (the default) sends no
    /// ECH extension. [`EchMode::Enable`](crate::ech::EchMode::Enable)
    /// needs TLS 1.3 enabled and limits connections to it.
    pub ech_mode: Option<crate::ech::EchMode>,
    /// The largest `uncompressed_length` accepted in a peer's
    /// `CompressedCertificate` (RFC 8879 §4), in bytes. Defaults to
    /// [`compress::MAX_DECOMPRESSED_CERTIFICATE_SIZE`] (64 KiB), which also
    /// applies to larger values: a message declaring more than 64 KiB does
    /// not parse and ends the connection with `decode_error`. A message
    /// declaring more than this limit is refused with `bad_certificate`
    /// before anything is decompressed. Zero turns reception off: the
    /// `compress_certificate` extension is then not sent, whatever
    /// `cert_decompressors` holds.
    pub cert_decompression_limit: usize,

    /// Whether to accept a TLS 1.3 server authenticating with a delegated
    /// credential (RFC 9345). When set, the ClientHello carries the
    /// `delegated_credential` extension listing the verifier's TLS 1.3
    /// schemes, and a credential the server sends is checked (certificate
    /// `DelegationUsage`, the signature by the certificate key, at most
    /// seven days of validity) before its key verifies CertificateVerify.
    /// The verifier must implement
    /// [`ServerCertVerifier::verify_tls13_signature_with_delegated_key`].
    /// Off by default.
    pub enable_delegated_credentials: bool,

    /// Whether to offer the `transparency_info` extension (RFC 9162 §6.5)
    /// even when the verifier does not ask for it
    /// ([`ServerCertVerifier::requests_transparency_info`]), to obtain the
    /// server's Certificate Transparency 2.0 items unverified
    /// ([`UnbufferedClientConnection::peer_transparency_info`]). Never
    /// offered when the verifier requires raw public keys. Off by default.
    /// See [`crate::transparency`].
    pub request_transparency_info: bool,

    /// The `record_size_limit` to announce (RFC 8449): the largest record
    /// plaintext we accept, counting the content type in TLS 1.3. `None`
    /// sends no extension, and then the server's limit is not learnt
    /// either. A value above the protocol maximum (2^14 + 1 when TLS 1.3 is
    /// offered, 2^14 otherwise) is lowered to it; a value below 64 makes
    /// connection creation fail with [`Error::BadRecordSizeLimit`].
    ///
    /// Defaults to `Some(16385)`: no restriction of our own, but a server
    /// that announces a smaller limit has its limit respected. Records we
    /// send are limited by the server's limit and by `max_fragment_size`,
    /// whichever is smaller.
    pub record_size_limit: Option<u16>,

    /// The `ticket_request` extension (RFC 9149) to send when TLS 1.3 is
    /// offered: how many NewSessionTicket messages we would like. `None`
    /// (the default) sends no extension, and the server sends its own
    /// number of tickets.
    pub tls13_ticket_request: Option<TicketRequest>,

    /// External session and identity binding (RFC 8844): our
    /// `external_id_hash` and `external_session_id` to send, and the
    /// server's values to expect. `None` (the default) sends neither
    /// extension. The values belong to one connection: clone the
    /// configuration per connection. Connection creation fails with
    /// [`Error::InconsistentExternalBinding`] if the server's session
    /// identifier is expected without one of ours.
    ///
    /// With a binding the connection neither resumes a session nor keeps
    /// one (RFC 8844 §5: nothing of one TLS connection is used in another,
    /// even of the same signaling session), and sends no early data, even
    /// with [`Self::enable_early_data`]: the server would read it before
    /// its answer is checked. [`Self::external_psks`] are still offered.
    /// See [`crate::external_binding`].
    pub external_binding: Option<crate::external_binding::ExternalBinding>,

    /// The most valid TLS 1.3 tickets accepted for storage on one
    /// connection, including after kernel handoff. Later tickets are
    /// ignored; zero accepts none. Defaults to 8, and values above 255
    /// make connection creation fail with [`Error::BadTls13TicketLimit`].
    pub max_tls13_tickets_per_connection: usize,

    /// Whether to send GREASE values (RFC 8701) in the ClientHello: in the
    /// cipher suites, `supported_groups`, `key_share` (with a one-byte
    /// share), `supported_versions`, `signature_algorithms` and
    /// `psk_key_exchange_modes` lists, and as two extensions (one empty,
    /// one not). The values are random per connection. Off by default
    /// until interoperability with the GnuTLS peers of the end-to-end
    /// matrix has been shown; rustls and OpenSSL 3 are tested.
    pub enable_grease: bool,

    /// How the ClientHello is padded with the `padding` extension (RFC 7685).
    pub client_hello_padding: ClientHelloPadding,

    /// Where TLS 1.2 server Certificate and CertificateRequest messages are
    /// kept for RFC 7924 `cached_info`; `None` (the default) sends no
    /// `cached_info` extension. With a store, a ClientHello that offers TLS
    /// 1.2 carries the fingerprints the store holds for the server name
    /// (in the clear: they let an observer link connections), and messages
    /// received in full in completed TLS 1.2 handshakes are stored. See
    /// [`crate::cached_info`].
    pub cached_info: Option<Arc<dyn crate::cached_info::ClientCachedInfoStore>>,

    pub(super) versions: EnabledVersions,
    pub(super) verifier: Arc<dyn ServerCertVerifier>,
    pub(super) provider: Arc<CryptoProvider>,

    /// External PSKs (RFC 9846 §4.3.11) to offer in TLS 1.3, in preference
    /// order, after any resumption ticket. Empty by default. See
    /// [`crate::psk`].
    ///
    /// A server that selects one authenticates through it and sends no
    /// certificate; a server that selects none is authenticated with its
    /// certificate as usual, through the configured verifier.
    pub external_psks: Vec<Arc<crate::psk::ExternalPsk>>,

    /// Whether to ask a server that selects an external PSK to authenticate
    /// with its certificate as well (`tls_cert_with_extern_psk`, RFC 8773).
    /// Off by default. The server may decline; set
    /// [`Self::require_cert_with_extern_psk`] to refuse a server that does.
    pub cert_with_extern_psk: bool,

    /// With [`Self::cert_with_extern_psk`], whether a server that selects an
    /// external PSK without also authenticating with its certificate is
    /// refused. Off by default.
    pub require_cert_with_extern_psk: bool,

    /// Whether to refuse a server that does not authenticate through one of
    /// [`Self::external_psks`]: the handshake fails unless the server selects
    /// one, or resumes a session that was itself established with one (its
    /// key still configured here). Only such tickets are offered, and a
    /// TLS 1.2 server is refused. Off by default.
    ///
    /// Without it, a server that selects no external PSK is authenticated
    /// with its certificate instead; an application that needs PSK
    /// authentication must then check
    /// [`CommonState::external_psk_identity`](crate::CommonState::external_psk_identity)
    /// once the handshake completes.
    pub require_external_psk: bool,

    /// Whether to offer a TLS 1.2 server certificate URLs in place of the
    /// client certificate chain (RFC 6066 §5, `client_certificate_url`). Off
    /// by default.
    ///
    /// The extension is sent only when TLS 1.2 is offered and the client
    /// certificate resolver has certificates; a CertificateURL message only
    /// when the server acknowledged it, asked for a certificate, and the
    /// resolved key carries URLs
    /// ([`CertifiedKey::set_certificate_url`](crate::sign::CertifiedKey::set_certificate_url)).
    /// The server, not this library, fetches them. See
    /// [`crate::certificate_url`].
    pub enable_client_certificate_url: bool,
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
    /// Panics if no default provider is available, or if the provider has no
    /// usable cipher suites or key exchange groups for `versions` (an empty
    /// `versions` included); use [`Self::builder_with_provider`] to avoid that.
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

    /// The objects a session saved by this configuration is bound to; see
    /// [`ClientConfigBinding`].
    pub(crate) fn session_binding(&self) -> ClientConfigBinding<'_> {
        ClientConfigBinding {
            server_cert_verifier: &self.verifier,
            client_creds: &self.client_auth_cert_resolver,
        }
    }

    pub(crate) fn verifier(&self) -> &dyn ServerCertVerifier {
        &*self.verifier
    }

    pub(crate) fn revocation_enabled(&self) -> bool {
        self.verifier.revocation_enabled() && !self.verifier.requires_raw_public_keys()
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

/// The client's `ticket_request` (RFC 9149 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TicketRequest {
    /// Tickets wanted when the server establishes a new session (a full
    /// handshake, or a resumption it declined).
    pub new_session_count: u8,
    /// Tickets wanted when the server resumes the session we offered.
    pub resumption_count: u8,
}

/// How the ClientHello is padded with the `padding` extension (RFC 7685).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientHelloPadding {
    /// Never pad.
    Disabled,
    /// Pad a ClientHello whose handshake message (header included) would
    /// be 256 to 511 bytes long to 512 bytes: some server implementations
    /// hang on such lengths (RFC 7685 §4). The default; a ClientHello with
    /// a post-quantum key share is longer anyway.
    #[default]
    AvoidProblematicLengths,
    /// Pad the ClientHello handshake message to at least this many bytes
    /// (header included), then apply [`Self::AvoidProblematicLengths`].
    /// The padding body is at most 65535 bytes.
    AtLeast(u16),
}

/// Session resumption settings.
///
/// Cloning shares the session store. A stored session is bound to the
/// server certificate verifier and client certificate resolver objects of
/// the configuration that established it, and only a configuration using
/// those same objects resumes it; another one makes a full handshake.
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
    pub(crate) tls13_tickets_received: u32,
    pub(super) early_data: EarlyData,
    /// Whether our ClientHello offered `post_handshake_auth`.
    pub(super) offered_post_handshake_auth: bool,
    /// How many post-handshake CertificateRequests we have answered.
    pub(super) post_handshake_auth_responses: u32,
    /// Where Encrypted Client Hello stands.
    pub(super) ech_status: crate::ech::EchStatus,
    /// Whether a TLS 1.2 server acknowledged our `trusted_ca_keys` in a
    /// full handshake (RFC 6066 §6).
    pub(super) trusted_ca_keys_acknowledged: bool,
    /// The server's ECH retry configurations, after a rejection.
    pub(super) ech_retry_configs: Option<Vec<u8>>,
    /// Where the TLS 1.2 session for `server_name` lives, so a fatal error
    /// can forget it.
    session_store: Arc<dyn ClientSessionStore>,
    pub(crate) server_name: ServerName<'static>,
    /// The delegated credential the server authenticated with (RFC 9345).
    pub(super) delegated_credential: Option<DelegatedCredential>,
    /// The absolute expiry of the delegated credential that authenticated
    /// this connection, including when it was restored from a TLS 1.3 ticket.
    pub(super) delegated_credential_expiry: Option<UnixTime>,
    /// The server's Certificate Transparency 2.0 items (RFC 9162).
    pub(super) transparency: super::transparency::PeerTransparency,
    /// The configuration, for exported authenticators (RFC 9261).
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) authenticators: crate::exported_authenticator::AuthenticatorState,
}

impl ClientConnectionData {
    fn new(config: Arc<ClientConfig>, server_name: ServerName<'static>) -> Self {
        Self {
            tls13_tickets_received: 0,
            early_data: EarlyData::new(),
            offered_post_handshake_auth: false,
            post_handshake_auth_responses: 0,
            ech_status: crate::ech::EchStatus::NotOffered,
            trusted_ca_keys_acknowledged: false,
            ech_retry_configs: None,
            session_store: config.resumption.store.clone(),
            server_name,
            delegated_credential: None,
            delegated_credential_expiry: None,
            transparency: Default::default(),
            config,
            authenticators: Default::default(),
        }
    }
}

impl ClientConnectionData {
    /// Whether 0-RTT data may still be written (unbuffered API).
    pub(crate) fn early_data_writable(&self) -> bool {
        self.early_data.is_enabled()
    }

    /// How many more bytes of 0-RTT data the ticket allows.
    pub(crate) fn early_data_left(&self) -> usize {
        self.early_data.left
    }

    /// Charges `len` bytes (at most [`Self::early_data_left`]) of sent 0-RTT
    /// data.
    pub(crate) fn charge_early_data(&mut self, len: usize) {
        self.early_data.left = self.early_data.left.saturating_sub(len);
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

impl ClientConnectionData {
    /// Whether the server accepted 0-RTT.
    pub(crate) fn early_data_accepted(&self) -> bool {
        self.early_data.is_accepted()
    }
}

impl ConnectionCore<ClientConnectionData> {
    pub(crate) fn for_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        Self::for_client_with(config, name, alpn_protocols, None, None)
    }

    /// A QUIC client (RFC 9001): TLS 1.3 only, with a QUIC-capable suite.
    pub(crate) fn for_quic_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Vec<Vec<u8>>,
        quic: crate::quic::Quic,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for QUIC".into(),
            ));
        }
        if !config
            .provider
            .cipher_suites
            .iter()
            .any(|cs| cs.usable_for_quic())
        {
            return Err(Error::General(
                "no cipher suite of the configuration is usable with QUIC".into(),
            ));
        }
        // ECH over QUIC is not supported yet: the outer ClientHello carries
        // no ALPN, so a QUIC server rejecting ECH could not complete the
        // handshake that delivers retry configurations (RFC 9001 §8.1).
        if config.ech_mode.is_some() {
            return Err(Error::General(
                "Encrypted Client Hello is not supported over QUIC".into(),
            ));
        }
        Self::for_client_with(config, name, alpn_protocols, Some(quic), None)
    }

    /// A DTLS 1.3 client (RFC 9147): TLS 1.3 only, with a DTLS-capable
    /// suite, and without Encrypted Client Hello. The first ClientHello is
    /// queued with `dtls` here.
    pub(crate) fn for_dtls_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        dtls: crate::dtls::Dtls,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for DTLS 1.3".into(),
            ));
        }
        if !config
            .provider
            .cipher_suites
            .iter()
            .any(|cs| cs.usable_for_dtls())
        {
            return Err(Error::General(
                "no cipher suite of the configuration is usable with DTLS 1.3".into(),
            ));
        }
        if config.ech_mode.is_some() {
            return Err(Error::General(
                "Encrypted Client Hello is not supported over DTLS".into(),
            ));
        }
        let alpn_protocols = config.alpn_protocols.clone();
        Self::for_client_with(config, name, alpn_protocols, None, Some(dtls))
    }

    fn for_client_with(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Vec<Vec<u8>>,
        quic: Option<crate::quic::Quic>,
        dtls: Option<crate::dtls::Dtls>,
    ) -> Result<Self, Error> {
        if config.max_tls13_tickets_per_connection > 255 {
            return Err(Error::BadTls13TicketLimit);
        }
        crate::external_binding::handshake::check_client_config(config.external_binding.as_ref())?;
        let mut common_state = CommonState::new(Side::Client);
        common_state.quic = quic.map(alloc::boxed::Box::new);
        common_state.dtls = dtls.map(alloc::boxed::Box::new);
        common_state.set_max_fragment_size(config.max_fragment_size)?;
        crate::common_state::check_record_size_limit_config(config.record_size_limit)?;
        crate::trusted_ca_keys::check_config(config.trusted_ca_keys.as_deref())?;
        common_state.enable_secret_extraction = config.enable_secret_extraction;
        common_state.fips = config.fips();
        let mut data = ClientConnectionData::new(config.clone(), name.clone());
        let mut cx = crate::conn::Context {
            common: &mut common_state,
            data: &mut data,
        };
        let state = hs::start_handshake(name, alpn_protocols, config, &mut cx)?;
        Ok(Self::new(state, data, common_state))
    }
}

/// A client-side TLS connection driven by the caller's buffers; see
/// [`crate::unbuffered`].
///
/// Available without `std`. The ClientHello is queued by [`Self::new`], so
/// the first `process_tls_records` (with no input) offers it for encoding.
pub struct UnbufferedClientConnection {
    inner: crate::unbuffered::UnbufferedConnectionCommon<ClientConnectionData>,
}

impl UnbufferedClientConnection {
    /// Starts a connection to `name` with `config`.
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
            inner: crate::unbuffered::UnbufferedConnectionCommon::new(ConnectionCore::for_client(
                config,
                name,
                alpn_protocols,
            )?),
        })
    }

    /// How many valid TLS 1.3 tickets this connection accepted for storage.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.inner.core.data.tls13_tickets_received
    }

    /// The `extension_data` of the server's `transparency_info` extension
    /// (RFC 9162 §6.5) from a full handshake: a `TransItemList`, or empty
    /// or an empty list, which §6.5 allows. It is well formed but **not
    /// verified**; see [`Self::peer_transparency_status`].
    pub fn peer_transparency_info(&self) -> Option<&[u8]> {
        self.inner.core.data.transparency.info.as_deref()
    }

    /// What the certificate verifier established about the server
    /// certificate's Certificate Transparency 2.0 evidence, once the
    /// certificate is verified; `None` when the verifier reports nothing,
    /// and after resumption. See [`crate::transparency`].
    pub fn peer_transparency_status(&self) -> Option<crate::transparency::TransparencyStatus> {
        self.inner.core.data.transparency.status
    }

    /// The delegated credential (RFC 9345) the server authenticated with,
    /// once its CertificateVerify has been verified with the credential's
    /// key; `None` when the server signed with its certificate key.
    pub fn delegated_credential(&self) -> Option<&DelegatedCredential> {
        self.inner.core.data.delegated_credential.as_ref()
    }

    /// How many post-handshake CertificateRequests (RFC 9846 §4.7.2) this
    /// connection has answered, with or without a certificate.
    ///
    /// The answers are queued while the request is processed and offered
    /// through
    /// [`ConnectionState::EncodeTlsData`](crate::unbuffered::ConnectionState::EncodeTlsData)
    /// like any other handshake message.
    pub fn post_handshake_auth_responses(&self) -> u32 {
        self.inner.core.data.post_handshake_auth_responses
    }

    /// Whether the server accepted the 0-RTT data offered.
    ///
    /// Meaningful once the handshake has finished.
    pub fn is_early_data_accepted(&self) -> bool {
        self.inner.core.data.early_data.is_accepted()
    }

    /// Whether the connection only uses FIPS-validated components.
    pub fn fips(&self) -> bool {
        self.inner.core.common_state.fips()
    }

    /// Where Encrypted Client Hello stands. A rejection also ends the
    /// handshake with [`Error::RejectedEch`].
    pub fn ech_status(&self) -> crate::ech::EchStatus {
        self.inner.core.data.ech_status
    }

    /// Whether the server acknowledged our `trusted_ca_keys` (RFC 6066 §6):
    /// it negotiated TLS 1.2 in a full handshake and says the list guided
    /// its choice of certificate chain. Always false in TLS 1.3, and after
    /// resuming a session. Meaningful once the ServerHello is processed.
    pub fn trusted_ca_keys_acknowledged(&self) -> bool {
        self.inner.core.data.trusted_ca_keys_acknowledged
    }

    /// See
    /// [`crate::unbuffered::UnbufferedConnectionCommon::dangerous_extract_secrets`].
    pub fn dangerous_extract_secrets(self) -> Result<crate::suites::ExtractedSecrets, Error> {
        self.inner.dangerous_extract_secrets()
    }

    /// See
    /// [`crate::unbuffered::UnbufferedConnectionCommon::dangerous_into_kernel_connection`].
    pub fn dangerous_into_kernel_connection(
        self,
    ) -> Result<
        (
            crate::suites::ExtractedSecrets,
            crate::kernel::KernelConnection<ClientConnectionData>,
        ),
        Error,
    > {
        self.inner.dangerous_into_kernel_connection()
    }
}

impl fmt::Debug for UnbufferedClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnbufferedClientConnection")
            .finish_non_exhaustive()
    }
}

impl core::ops::Deref for UnbufferedClientConnection {
    type Target = crate::unbuffered::UnbufferedConnectionCommon<ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl core::ops::DerefMut for UnbufferedClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
