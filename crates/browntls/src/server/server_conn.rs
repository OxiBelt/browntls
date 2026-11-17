//! Server configuration and connections.

mod accept;
#[cfg(feature = "std")]
mod buffered;
mod unbuffered_acceptor;

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use browntls_pki::{DnsName, UnixTime};

#[cfg(feature = "std")]
pub use buffered::{Accepted, AcceptedAlert, Acceptor, ReadEarlyData, ServerConnection};
pub use unbuffered_acceptor::{
    UnbufferedAcceptStatus, UnbufferedAccepted, UnbufferedAcceptedAlert, UnbufferedAcceptor,
};

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
    ///
    /// It also bounds the rejected 0-RTT records skipped during the
    /// handshake: their plaintext, and their number, since each costs at
    /// least one byte. With zero, early data that is offered anyway is
    /// skipped up to 16384 bytes. When the server decrypts with an external
    /// PSK's handshake key, that PSK's own limit applies if larger.
    pub max_early_data_size: u32,

    /// Whether to send application data before the client's Finished.
    pub send_half_rtt_data: bool,

    /// How many TLS 1.3 tickets to send after a handshake.
    pub send_tls13_tickets: usize,

    /// Whether TLS 1.3 client authentication is left out of the handshake
    /// when the client offered `post_handshake_auth`, for the application
    /// to request later with [`ServerConnection::request_client_auth`]
    /// (RFC 9846 §4.7.2). Off by default.
    ///
    /// A client that did not offer `post_handshake_auth`, and every TLS 1.2
    /// client, is still asked during the handshake when the client
    /// certificate verifier offers client authentication. With this on,
    /// such a handshake completes without a client certificate even if the
    /// verifier makes it mandatory: the application must request one and
    /// check [`ServerConnection::post_handshake_auth_status`] before it
    /// trusts the client. RFC 8740 forbids post-handshake authentication
    /// over HTTP/2; the library leaves that decision to the application.
    pub request_client_auth_after_handshake: bool,

    /// Seals the cookie sent in TLS 1.3 HelloRetryRequests (RFC 9846
    /// §4.3.2), which makes the retry stateless; `None` (the default) sends
    /// no cookie.
    ///
    /// The cookie carries, encrypted and authenticated, the hash of the
    /// first ClientHello and the parameters the HelloRetryRequest chose, so
    /// a fresh [`ServerConnection`] (or [`Acceptor`]) whose first message is
    /// the second ClientHello can complete the handshake without the state
    /// of the connection that sent the HelloRetryRequest. Use a dedicated
    /// sealer with its own key, never the [`Self::ticketer`] instance: the
    /// plaintext is domain-separated from tickets, but a separate key keeps
    /// the two kinds of token apart outright. Creating a connection with
    /// the very same `Arc` here and in [`Self::ticketer`] fails; a
    /// separate sealer that shares the ticketer's key cannot be detected.
    /// A cookie is accepted for 60 seconds and only while the sealer still
    /// holds its key.
    pub hello_retry_cookies: Option<Arc<dyn ProducesTickets>>,

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

    /// Encrypted Client Hello keys (RFC 9849); `None` (the default)
    /// ignores ECH. The certificate resolver must also hold a certificate
    /// for each key's public name, so clients can authenticate a rejection.
    pub ech: Option<Arc<crate::ech::EchServerConfig>>,
    /// Act as the back-end server of an ECH split-mode deployment
    /// (RFC 9849 §7.2): a client-facing server
    /// ([`ech::split::ClientFacing`](crate::ech::split::ClientFacing))
    /// decrypts the ClientHello and forwards the inner one, which carries
    /// an `inner` ECH extension; this server then confirms acceptance in
    /// its ServerHello (and HelloRetryRequest). An `outer` ECH extension is
    /// refused with `illegal_parameter` (§7), as is an inner ClientHello
    /// that offers TLS 1.2 or below. A ClientHello without ECH is served as
    /// usual. Defaults to `false`; cannot be combined with
    /// [`ech`](Self::ech), which makes the server decrypt itself (shared
    /// mode).
    pub ech_backend: bool,
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

    /// The `record_size_limit` to answer a client's with (RFC 8449): the
    /// largest record plaintext we accept, counting the content type in TLS
    /// 1.3. `None` ignores the client's extension, so its limit is not
    /// respected either. A value above the protocol maximum (2^14 + 1 for
    /// TLS 1.3, 2^14 for TLS 1.2) is lowered to it; a value below 64 makes
    /// connection creation fail with [`Error::BadRecordSizeLimit`].
    ///
    /// Defaults to `Some(16385)`: no restriction of our own, but a client
    /// that announces a smaller limit has its limit respected. Records we
    /// send are limited by the client's limit and by `max_fragment_size`,
    /// whichever is smaller.
    pub record_size_limit: Option<u16>,

    pub(super) versions: EnabledVersions,
    pub(crate) verifier: Arc<dyn ClientCertVerifier>,
    pub(super) provider: Arc<CryptoProvider>,

    /// Finds the external PSKs (RFC 9846 §4.3.11) clients may offer; `None`
    /// (the default) accepts none. See [`crate::psk`].
    ///
    /// A TLS 1.3 handshake that selects an external PSK authenticates
    /// through it and sends no certificate, so [`Self::cert_resolver`] may
    /// return nothing for a client that offers one.
    pub external_psks: Option<Arc<dyn crate::psk::ResolvesExternalPsk>>,

    /// Whether to authenticate with our certificate as well when the
    /// client asks for it with `tls_cert_with_extern_psk` (RFC 8773) and an
    /// external PSK is selected. Off by default.
    pub cert_with_extern_psk: bool,

    /// Whether to refuse a client that does not authenticate through one of
    /// [`Self::external_psks`]: the handshake fails unless an external PSK
    /// is selected, or a ticket issued on a connection that used one (and
    /// whose key [`Self::external_psks`] still resolves) is resumed. Other
    /// tickets are passed over, and TLS 1.2 is refused. Off by default.
    ///
    /// Useful for a server that has a certificate as well as external PSKs
    /// but must serve only clients holding a PSK; without it, check
    /// [`CommonState::external_psk_identity`](crate::CommonState::external_psk_identity)
    /// once the handshake completes.
    pub require_external_psk: bool,
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

    /// Refuses a configuration whose HelloRetryRequest cookie sealer is
    /// the ticketer itself: cookies need their own key (RFC 9846 §4.3.2
    /// leaves the cookie format to the server; the key split is ours).
    /// The part this configuration plays in ECH (RFC 9849 §7).
    pub(crate) fn ech_role(&self) -> crate::ech::server::Role<'_> {
        use crate::ech::server::Role;
        match (&self.ech, self.ech_backend) {
            (Some(ech), _) => Role::Shared(ech),
            (None, true) => Role::Backend,
            (None, false) => Role::Off,
        }
    }

    pub(super) fn check_ech_role(&self) -> Result<(), Error> {
        if self.ech.is_some() && self.ech_backend {
            return Err(Error::General(
                "ech (shared mode) and ech_backend (split mode) exclude each other".into(),
            ));
        }
        Ok(())
    }

    /// Checks this configuration and applies its per-connection settings to
    /// `common`: every server connection goes through here, whether created
    /// with the configuration or given it by an acceptor.
    pub(super) fn apply_to(&self, common: &mut CommonState) -> Result<(), Error> {
        self.check_cookie_sealer()?;
        self.check_ech_role()?;
        common.set_max_fragment_size(self.max_fragment_size)?;
        crate::common_state::check_record_size_limit_config(self.record_size_limit)?;
        common.enable_secret_extraction = self.enable_secret_extraction;
        common.fips = self.fips();
        Ok(())
    }

    pub(super) fn check_cookie_sealer(&self) -> Result<(), Error> {
        match &self.hello_retry_cookies {
            Some(sealer) if Arc::ptr_eq(sealer, &self.ticketer) => Err(Error::General(
                "hello_retry_cookies must not be the ticketer: give cookies their own key".into(),
            )),
            _ => Ok(()),
        }
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
enum EarlyDataKind {
    /// No decision yet.
    #[default]
    New,
    /// Accepted: `received` holds the data (buffered API only), `left` what
    /// may still arrive.
    Accepted {
        received: ChunkVecBuffer,
        left: usize,
    },
    /// Declined (by configuration, policy, or the application).
    Rejected,
}

/// The server's 0-RTT bookkeeping.
#[derive(Default)]
pub(super) struct EarlyDataState {
    kind: EarlyDataKind,
    /// Unbuffered API: accepted early data stays in the caller's buffer.
    in_place: bool,
    /// Unbuffered API: the record just processed was accepted early data.
    in_place_pending: bool,
}

impl EarlyDataState {
    pub(super) fn reject(&mut self) {
        self.kind = EarlyDataKind::Rejected;
    }

    pub(super) fn accept(&mut self, max_size: usize) {
        self.kind = EarlyDataKind::Accepted {
            received: ChunkVecBuffer::new(Some(max_size)),
            left: max_size,
        };
    }

    pub(super) fn was_accepted(&self) -> bool {
        matches!(self.kind, EarlyDataKind::Accepted { .. })
    }

    pub(super) fn was_rejected(&self) -> bool {
        matches!(self.kind, EarlyDataKind::Rejected)
    }

    /// Stores early data; `false` if it exceeds what was announced.
    ///
    /// With the unbuffered API nothing is copied: the record stays where it
    /// was decrypted and only the budget is charged.
    pub(super) fn take_received_plaintext(&mut self, bytes: &[u8]) -> bool {
        let EarlyDataKind::Accepted { received, left } = &mut self.kind else {
            return false;
        };
        let available = bytes.len();
        if self.in_place {
            if available > *left {
                return false;
            }
            *left -= available;
            self.in_place_pending = true;
            return true;
        }
        if received.apply_limit(available) != available || available > *left {
            return false;
        }
        received.append(bytes.to_vec());
        *left -= available;
        true
    }

    /// Unbuffered API: leave accepted early data in the caller's buffer.
    fn set_in_place(&mut self) {
        self.in_place = true;
    }

    #[cfg(feature = "std")]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.kind {
            EarlyDataKind::Accepted { received, .. } => Ok(received.read(buf)),
            _ => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        }
    }
}

impl fmt::Debug for EarlyDataState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            EarlyDataKind::New => f.write_str("EarlyDataState::New"),
            EarlyDataKind::Accepted { received, left } => f
                .debug_struct("EarlyDataState::Accepted")
                .field("received", &received.len())
                .field("left", left)
                .finish(),
            EarlyDataKind::Rejected => f.write_str("EarlyDataState::Rejected"),
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
    /// The absolute expiry of the server delegated credential that
    /// authenticated this TLS 1.3 connection or its resumed ancestor.
    pub(super) delegated_credential_expiry: Option<UnixTime>,
    /// The session cache entry this TLS 1.2 connection resumed or created,
    /// so a fatal error can forget it (tickets are stateless and cannot be
    /// recalled).
    pub(super) tls12_session: Option<(Arc<dyn StoresServerSessions>, Vec<u8>)>,
    /// What was decided about Encrypted Client Hello.
    pub(crate) ech: crate::ech::server::ServerEch,
    /// State for exported authenticators (RFC 9261).
    pub(crate) authenticators: crate::exported_authenticator::ServerAuthenticatorState,
    /// Whether the TLS 1.3 ClientHello offered `post_handshake_auth`.
    pub(super) post_handshake_auth_offered: bool,
    /// The most recent post-handshake client authentication, if any.
    pub(super) post_handshake_auth: Option<PostHandshakeAuthStatus>,
}

/// Where the most recent post-handshake client authentication (RFC 9846
/// §4.7.2) stands; see [`ServerConnection::request_client_auth`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostHandshakeAuthStatus {
    /// The CertificateRequest is sent; the client has not completed its
    /// answer yet.
    Requested,
    /// The client presented a certificate that the client certificate
    /// verifier accepted, proved possession of its key and sent a valid
    /// Finished; `peer_certificates` now returns this certificate.
    Authenticated,
    /// The client answered with an empty Certificate and the verifier does
    /// not make client authentication mandatory. `peer_certificates` is
    /// unchanged.
    Declined,
}

impl SideData for ServerConnectionData {
    fn on_fatal_error(&mut self, _negotiated_version: Option<ProtocolVersion>) {
        // RFC 5246 §7.2.2: the session of a connection that failed cannot be
        // resumed.
        if let Some((store, id)) = self.tls12_session.take() {
            store.take(&id);
        }
    }

    fn take_early_data_in_place(&mut self) -> bool {
        core::mem::take(&mut self.early_data.in_place_pending)
    }
}

impl ServerConnectionData {
    pub(crate) fn server_name(&self) -> Option<&str> {
        self.sni.as_ref().map(|n| n.as_ref())
    }

    pub(crate) fn received_resumption_data(&self) -> Option<&[u8]> {
        self.received_resumption_data.as_deref()
    }

    pub(crate) fn set_resumption_data(&mut self, data: &[u8]) {
        self.resumption_data = data.to_vec();
    }

    pub(crate) fn reject_early_data(&mut self) {
        self.early_data.reject();
    }

    pub(crate) fn early_data_accepted(&self) -> bool {
        self.early_data.was_accepted()
    }
}

impl ConnectionCore<ServerConnectionData> {
    pub(crate) fn for_server(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Self::for_server_with(config, None)
    }

    /// Queues a post-handshake CertificateRequest (RFC 9846 §4.7.2); the
    /// body of the buffered and unbuffered `request_client_auth`.
    pub(crate) fn request_client_auth(&mut self) -> Result<(), Error> {
        if self.common_state.is_handshaking() {
            return Err(Error::HandshakeNotComplete);
        }
        if !self.common_state.is_tls13() {
            return Err(Error::General(
                "post-handshake client authentication requires TLS 1.3".into(),
            ));
        }
        let state = match &mut self.state {
            Ok(state) => state,
            Err(err) => return Err(err.clone()),
        };
        // A record whose encryption failed has used up its sequence number;
        // nothing may follow it.
        if self.common_state.encrypt_failed {
            return Err(Error::EncryptError);
        }
        // RFC 9846 §6.1: the client sends nothing after its close_notify,
        // and we would process nothing it sent, so a request would never be
        // answered.
        if self.common_state.has_received_close_notify {
            return Err(Error::General(
                "cannot request client authentication after the client's close_notify".into(),
            ));
        }
        let mut cx = crate::conn::Context {
            common: &mut self.common_state,
            data: &mut self.data,
        };
        state.request_client_auth(&mut cx)
    }

    /// A QUIC server (RFC 9001): TLS 1.3 only, with a QUIC-capable suite,
    /// and 0-RTT announced only with the sentinel size (§4.6.1).
    pub(crate) fn for_quic_server(
        config: Arc<ServerConfig>,
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
        if config.max_early_data_size != 0 && config.max_early_data_size != u32::MAX {
            return Err(Error::General(
                "QUIC servers must set max_early_data_size to 0 or u32::MAX".into(),
            ));
        }
        if config.ech.is_some() || config.ech_backend {
            return Err(Error::General(
                "Encrypted Client Hello is not supported over QUIC".into(),
            ));
        }
        Self::for_server_with(config, Some(quic))
    }

    fn for_server_with(
        config: Arc<ServerConfig>,
        quic: Option<crate::quic::Quic>,
    ) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server);
        common.quic = quic.map(alloc::boxed::Box::new);
        config.apply_to(&mut common)?;
        Ok(Self::new(
            alloc::boxed::Box::new(hs::ExpectClientHello::new(config)),
            ServerConnectionData::default(),
            common,
        ))
    }
}

/// A server-side TLS connection driven by the caller's buffers; see
/// [`crate::unbuffered`].
///
/// Available without `std`. Accepted 0-RTT data is reported as
/// [`ConnectionState::ReadEarlyData`](crate::unbuffered::ConnectionState::ReadEarlyData)
/// records, in place, and is replayable by an attacker (see
/// [`ServerConfig::max_early_data_size`]).
pub struct UnbufferedServerConnection {
    inner: crate::unbuffered::UnbufferedConnectionCommon<ServerConnectionData>,
}

impl UnbufferedServerConnection {
    /// Prepares to accept a connection with `config`.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self::from_core(ConnectionCore::for_server(config)?))
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
    /// Effective only before the ClientHello has been processed; once early
    /// data was accepted this does nothing (the client is already sending
    /// it under the early traffic key, RFC 9846 §4.2.10).
    pub fn reject_early_data(&mut self) {
        let early_data = &mut self.inner.core.data.early_data;
        if !early_data.was_accepted() {
            early_data.reject();
        }
    }

    /// Whether the connection only uses FIPS-validated components.
    pub fn fips(&self) -> bool {
        self.inner.core.common_state.fips()
    }

    /// What was decided about Encrypted Client Hello. With
    /// [`EchStatus::Accepted`](crate::ech::EchStatus::Accepted), the
    /// handshake used the client's encrypted ClientHello, and
    /// [`Self::server_name`] is the name it carried.
    pub fn ech_status(&self) -> crate::ech::EchStatus {
        self.inner.core.data.ech.status()
    }

    /// Whether the client offered TLS 1.3 post-handshake authentication
    /// (`post_handshake_auth`, RFC 9846 §4.3.6), once its ClientHello has
    /// been processed.
    pub fn post_handshake_auth_offered(&self) -> bool {
        self.inner.core.data.post_handshake_auth_offered
    }

    /// Asks the client for a certificate after the handshake (RFC 9846
    /// §4.7.2): queues a CertificateRequest with a fresh, unpredictable
    /// `certificate_request_context`.
    ///
    /// The same rules as for the buffered `ServerConnection` apply: a
    /// completed TLS 1.3 handshake with a client that offered
    /// `post_handshake_auth`, a client certificate verifier that offers
    /// client authentication, no request still unanswered, and no
    /// `close_notify` sent or received (the client would never answer).
    /// Call it
    /// between calls of
    /// [`process_tls_records`](crate::unbuffered::UnbufferedConnectionCommon::process_tls_records),
    /// not while a state it returned is held. The next call then offers
    /// the CertificateRequest through
    /// [`ConnectionState::EncodeTlsData`](crate::unbuffered::ConnectionState::EncodeTlsData)
    /// before anything else; the client's answer arrives with the records
    /// `process_tls_records` processes and is checked with the configured
    /// verifier: follow it with [`Self::post_handshake_auth_status`]. A
    /// refused certificate, a bad signature or Finished, a missing
    /// certificate when the verifier makes it mandatory, or messages
    /// interleaved with the answer end the connection with the
    /// corresponding alert.
    pub fn request_client_auth(&mut self) -> Result<(), Error> {
        self.inner.core.request_client_auth()
    }

    /// The state of the most recent [`Self::request_client_auth`], or
    /// `None` if none was made.
    pub fn post_handshake_auth_status(&self) -> Option<PostHandshakeAuthStatus> {
        self.inner.core.data.post_handshake_auth
    }

    /// See [`crate::unbuffered::UnbufferedConnectionCommon::dangerous_extract_secrets`].
    pub fn dangerous_extract_secrets(self) -> Result<crate::suites::ExtractedSecrets, Error> {
        self.inner.dangerous_extract_secrets()
    }
}

impl fmt::Debug for UnbufferedServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnbufferedServerConnection")
            .finish_non_exhaustive()
    }
}

impl core::ops::Deref for UnbufferedServerConnection {
    type Target = crate::unbuffered::UnbufferedConnectionCommon<ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl core::ops::DerefMut for UnbufferedServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
