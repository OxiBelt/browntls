//! Certificates and per-input configurations shared by `tls_conn` and
//! `tls_unbuffered`.
//!
//! One CA, a server certificate for `localhost` and a client certificate
//! are generated once per process. Configurations are built for every input
//! from a few header bytes ([`Knobs`]), so that session caches start empty
//! and resumption within one input replays the same way.

use std::sync::{Arc, OnceLock};

use browntls_core::cached_info::{
    CachedInformationType, CachedInformationTypes, CachedObject, ClientCachedInfoMemoryCache,
    ServerCachedInfoPolicy, fingerprint,
};
use browntls_core::client::danger::ServerCertVerifier;
use browntls_core::client::{
    ClientSessionMemoryCache, Resumption, Tls12Resumption, WebPkiServerVerifier,
};
use browntls_core::compress::CompressionCache;
use browntls_core::crypto::{CryptoProvider, native, rustcrypto};
use browntls_core::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use browntls_core::server::{ServerSessionMemoryCache, WebPkiClientVerifier};
use browntls_core::time_provider::DefaultTimeProvider;
use browntls_core::{
    ClientConfig, ConnectionTrafficSecrets, NamedGroup, RootCertStore, ServerConfig,
    SupportedProtocolVersion, version,
};

use crate::input::Input;

/// The process's certificates and keys.
pub(crate) struct Pki {
    pub(crate) roots: Arc<RootCertStore>,
    pub(crate) server_chain: Vec<CertificateDer<'static>>,
    server_key: Vec<u8>,
    pub(crate) client_chain: Vec<CertificateDer<'static>>,
    client_key: Vec<u8>,
}

impl Pki {
    pub(crate) fn get() -> &'static Self {
        static PKI: OnceLock<Pki> = OnceLock::new();
        PKI.get_or_init(|| {
            let ca_key = rcgen::KeyPair::generate().expect("CA key");
            let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            ca_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "browntls fuzz conn CA");
            let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
            let issuer = rcgen::Issuer::new(ca_params, ca_key);

            let leaf = |name: &str, purpose| {
                let key = rcgen::KeyPair::generate().expect("end-entity key");
                let mut params =
                    rcgen::CertificateParams::new(vec![name.to_string()]).expect("params");
                params.is_ca = rcgen::IsCa::NoCa;
                params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![purpose];
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, name);
                let cert = params.signed_by(&key, &issuer).expect("certificate");
                (
                    vec![CertificateDer::from(cert.der().to_vec())],
                    key.serialize_der(),
                )
            };
            let (server_chain, server_key) =
                leaf("localhost", rcgen::ExtendedKeyUsagePurpose::ServerAuth);
            let (client_chain, client_key) =
                leaf("client.example", rcgen::ExtendedKeyUsagePurpose::ClientAuth);

            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(ca_cert.der().to_vec()))
                .expect("root");
            Self {
                roots: Arc::new(roots),
                server_chain,
                server_key,
                client_chain,
                client_key,
            }
        })
    }

    pub(crate) fn server_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.clone()))
    }

    fn client_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.client_key.clone()))
    }
}

/// One certificate compression cache for every configuration: the
/// certificates never change, and compressing them (Brotli at its
/// amortised level) for every input would cost more than the rest of the
/// handshake.
fn compression_cache() -> Arc<CompressionCache> {
    static CACHE: OnceLock<Arc<CompressionCache>> = OnceLock::new();
    CACHE.get_or_init(Arc::default).clone()
}

/// The server name every client connects to.
pub(crate) fn server_name() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("name")
}

/// ALPN protocol sets the knobs choose from.
pub(crate) const ALPN: [&[&[u8]]; 4] = [&[], &[b"fuzz"], &[b"h2", b"fuzz"], &[b"other"]];

/// The configuration choices an input header makes (5 bytes).
///
/// Byte 0: bits 0-1 versions (both, 1.3 only, 1.2 only, both), bit 2 client
/// uses the RustCrypto provider, bit 3 server does, bits 4-5 builder
/// entry point, bit 6 early data, bit 7 half-RTT data.
/// Byte 1: bits 0-1 client authentication (none, mandatory, optional,
/// post-handshake only), bit 2 secret extraction, bit 3 client verifier set
/// through `dangerous()`, bits 4-5 client resumption store, bits 6-7 ALPN
/// set of the client (the server always offers `fuzz` and `h2`). Without
/// resumption the client also caches the server's messages (RFC 7924
/// `cached_info`), which the server always answers.
/// Byte 2: client cipher suite (0: all, otherwise one, by index).
/// Byte 3: client key exchange groups (low nibble mask) and server groups
/// (high nibble mask); zero means all.
/// Byte 4: maximum fragment size (0: default, otherwise `byte * 4 + 16`,
/// which includes invalid values).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Knobs {
    pub(crate) flags: u8,
    pub(crate) auth: u8,
    pub(crate) suite: u8,
    pub(crate) groups: u8,
    pub(crate) fragment: u8,
}

/// The fast key exchange groups (no finite-field Diffie-Hellman, whose key
/// generation would dominate every input).
fn fast_groups(provider: &mut CryptoProvider, mask: u8) {
    provider.kx_groups.retain(|g| {
        !matches!(
            g.name(),
            NamedGroup::FFDHE2048
                | NamedGroup::FFDHE3072
                | NamedGroup::FFDHE4096
                | NamedGroup::FFDHE6144
                | NamedGroup::FFDHE8192
        )
    });
    if mask != 0 {
        let mut i = 0;
        let all = provider.kx_groups.clone();
        provider.kx_groups.retain(|_| {
            i += 1;
            mask & (1 << ((i - 1) % 4)) != 0
        });
        if provider.kx_groups.is_empty() {
            provider.kx_groups = all;
        }
    }
}

impl Knobs {
    pub(crate) fn read(input: &mut Input<'_>) -> Self {
        Self {
            flags: input.byte(),
            auth: input.byte(),
            suite: input.byte(),
            groups: input.byte(),
            fragment: input.byte(),
        }
    }

    fn versions(self) -> &'static [&'static SupportedProtocolVersion] {
        static TLS13: [&SupportedProtocolVersion; 1] = [&version::TLS13];
        static TLS12: [&SupportedProtocolVersion; 1] = [&version::TLS12];
        match self.flags & 3 {
            1 => &TLS13,
            2 => &TLS12,
            _ => browntls_core::ALL_VERSIONS,
        }
    }

    fn provider(rust: bool) -> CryptoProvider {
        if rust {
            rustcrypto::default_provider()
        } else {
            native::default_provider()
        }
    }

    pub(crate) fn early_data(self) -> bool {
        self.flags & 0x40 != 0
    }

    pub(crate) fn client_auth(self) -> u8 {
        self.auth & 3
    }

    pub(crate) fn extraction(self) -> bool {
        self.auth & 4 != 0
    }

    fn fragment(self) -> Option<usize> {
        (self.fragment != 0).then(|| usize::from(self.fragment) * 4 + 16)
    }

    /// The client configuration, or `None` when the builder refuses the
    /// combination.
    pub(crate) fn client_config(self) -> Option<ClientConfig> {
        let pki = Pki::get();
        let mut provider = Self::provider(self.flags & 4 != 0);
        if self.suite != 0 {
            let suites = &provider.cipher_suites;
            provider.cipher_suites = vec![suites[usize::from(self.suite - 1) % suites.len()]];
        }
        fast_groups(&mut provider, self.groups & 15);
        let provider = Arc::new(provider);
        let versions = self.versions();
        let builder = match (self.flags >> 4) & 3 {
            0 => ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(versions)
                .ok()?,
            1 => {
                ClientConfig::builder_with_details(provider.clone(), Arc::new(DefaultTimeProvider))
                    .with_protocol_versions(versions)
                    .ok()?
            }
            // The preset names the list it stands for.
            2 if versions == [&version::TLS13] => ClientConfig::builder_tls13_only(),
            2 => ClientConfig::builder_with_protocol_versions(versions),
            _ => ClientConfig::builder(),
        };
        let builder = builder.with_root_certificates(pki.roots.clone());
        // Mode 2 (optional client authentication) leaves the client without
        // a certificate, so that it answers a CertificateRequest with none.
        let mut config = if matches!(self.client_auth(), 0 | 2) {
            builder.with_no_client_auth()
        } else {
            builder
                .with_client_auth_cert(pki.client_chain.clone(), pki.client_key())
                .ok()?
        };
        if self.auth & 8 != 0 {
            let verifier: Arc<dyn ServerCertVerifier> =
                WebPkiServerVerifier::builder_with_provider(
                    pki.roots.clone(),
                    config.crypto_provider().clone(),
                )
                .build()
                .ok()?;
            config.dangerous().set_certificate_verifier(verifier);
        }
        config.resumption = match (self.auth >> 4) & 3 {
            0 => Resumption::in_memory_sessions(8),
            1 => Resumption::store(Arc::new(ClientSessionMemoryCache::new(2)))
                .tls12_resumption(Tls12Resumption::SessionIdOnly),
            2 => Resumption::disabled(),
            _ => Resumption::in_memory_sessions(1).tls12_resumption(Tls12Resumption::Disabled),
        };
        if (self.auth >> 4) & 3 == 2 {
            config.cached_info = Some(Arc::new(ClientCachedInfoMemoryCache::new(1, 2)));
        }
        config.alpn_protocols = ALPN[usize::from(self.auth >> 6)]
            .iter()
            .map(|p| p.to_vec())
            .collect();
        config.enable_early_data = self.early_data();
        config.enable_post_handshake_auth = self.client_auth() >= 2;
        config.enable_secret_extraction = self.extraction();
        config.max_fragment_size = self.fragment();
        config.cert_compression_cache = compression_cache();
        let _ = config.fips();
        Some(config)
    }

    /// The server configuration, or `None` when the builder refuses the
    /// combination.
    pub(crate) fn server_config(self) -> Option<ServerConfig> {
        let pki = Pki::get();
        let mut provider = Self::provider(self.flags & 8 != 0);
        fast_groups(&mut provider, self.groups >> 4);
        let provider = Arc::new(provider);
        let versions = self.versions();
        let builder = match ((self.flags >> 4) + 1) & 3 {
            0 => ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(versions)
                .ok()?,
            1 => {
                ServerConfig::builder_with_details(provider.clone(), Arc::new(DefaultTimeProvider))
                    .with_protocol_versions(versions)
                    .ok()?
            }
            // The preset names the list it stands for.
            2 if versions == [&version::TLS13] => ServerConfig::builder_tls13_only(),
            2 => ServerConfig::builder_with_protocol_versions(versions),
            _ => ServerConfig::builder(),
        };
        let verifier = WebPkiClientVerifier::builder_with_provider(
            pki.roots.clone(),
            builder.crypto_provider().clone(),
        );
        let builder = match self.client_auth() {
            0 => builder.with_no_client_auth(),
            2 => builder.with_client_cert_verifier(verifier.allow_unauthenticated().build().ok()?),
            _ => builder.with_client_cert_verifier(verifier.build().ok()?),
        };
        let mut config = builder
            .with_single_cert(pki.server_chain.clone(), pki.server_key())
            .ok()?;
        config.session_storage = ServerSessionMemoryCache::new(8);
        config.alpn_protocols = vec![b"fuzz".to_vec(), b"h2".to_vec()];
        config.max_early_data_size = if self.early_data() { 1024 } else { 0 };
        config.send_half_rtt_data = self.flags & 0x80 != 0;
        config.request_client_auth_after_handshake = self.client_auth() == 3;
        let mut cached_info = ServerCachedInfoPolicy::default();
        (cached_info.cert, cached_info.cert_req) = (true, true);
        config.cached_info = cached_info;
        config.enable_secret_extraction = self.extraction();
        config.max_fragment_size = self.fragment();
        config.cert_compression_cache = compression_cache();
        let _ = (config.fips(), config.crypto_provider());
        Some(config)
    }
}

/// Checks RFC 7924 `cached_info` once both sides completed a handshake
/// with nothing corrupted: they agree on the messages that travelled as
/// fingerprints, the client restored those from its store, and every stored
/// object's fingerprint is the SHA-256 of its message.
pub(crate) fn check_cached_info(
    client: &ClientConfig,
    c: CachedInformationTypes,
    s: CachedInformationTypes,
) {
    assert_eq!(c, s, "the peers disagree on the cached_info replacements");
    let Some(store) = &client.cached_info else {
        assert!(c.is_empty(), "replaced without a client store");
        return;
    };
    let provider = client.crypto_provider();
    for typ in [CachedInformationType::Cert, CachedInformationType::CertReq] {
        let objects = store.lookup(&server_name(), typ);
        assert!(
            !c.contains(typ) || !objects.is_empty(),
            "restored from nothing"
        );
        for object in objects {
            assert_eq!(object.typ(), typ);
            let again = CachedObject::new(provider, typ, object.message().to_vec())
                .expect("a stored object holds a valid message");
            assert_eq!(again.fingerprint(), object.fingerprint());
            let hash = fingerprint(provider, object.message()).expect("SHA-256");
            assert_eq!(&hash, object.fingerprint());
        }
    }
}

/// Asserts that the secrets one side sends with are the ones its peer
/// receives with.
pub(crate) fn assert_same_secrets(
    tx: &(u64, ConnectionTrafficSecrets),
    rx: &(u64, ConnectionTrafficSecrets),
) {
    fn parts(s: &ConnectionTrafficSecrets) -> (u8, &[u8], &[u8]) {
        match s {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (0, key.as_ref(), iv.as_ref()),
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (1, key.as_ref(), iv.as_ref()),
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                (2, key.as_ref(), iv.as_ref())
            }
            ConnectionTrafficSecrets::Aes128Ccm { key, iv } => (3, key.as_ref(), iv.as_ref()),
            _ => (4, &[], &[]),
        }
    }
    assert_eq!(tx.0, rx.0, "sequence numbers differ");
    assert!(parts(&tx.1) == parts(&rx.1), "traffic secrets differ");
}

/// Asserts that `got` is a prefix of `sent`: received application data is
/// authentic and in order whatever happened on the wire.
pub(crate) fn assert_prefix(got: &[u8], sent: &[u8], what: &str) {
    assert!(
        got.len() <= sent.len() && sent[..got.len()] == *got,
        "{what}: received {} bytes that are not a prefix of the {} sent",
        got.len(),
        sent.len()
    );
}
