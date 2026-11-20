//! Client and server configuration builders, connections made from the
//! configurations, and a handshake between them.

use std::io::{Read, Write};
use std::sync::Arc;

use browntls_core::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use browntls_core::client::{ClientSessionMemoryCache, Resumption, WebPkiServerVerifier};
use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::crypto::{CryptoProvider, KeyExchangeAlgorithm};
use browntls_core::pki_types::{CertificateDer, ServerName, UnixTime};
use browntls_core::psk::ExternalPsk;
use browntls_core::server::danger::{ClientCertVerified, ClientCertVerifier};
use browntls_core::server::{
    NoServerSessionStorage, ResolvesServerCertUsingSni, ServerSessionMemoryCache,
    WebPkiClientVerifier,
};
use browntls_core::sign::{CertifiedKey, SingleCertAndKey};
use browntls_core::ticketer::TicketRotator;
use browntls_core::{
    ClientConfig, ClientConnection, ConfigBuilder, DigitallySignedStruct, DistinguishedName, Error,
    KeyLogFile, RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
    SupportedCipherSuite, SupportedProtocolVersion, WantsVersions, version,
};

use super::crypto::{kx_groups, suites};
use super::fixtures::{self, ED25519, P256, P256_SEC1, P384, RSA, RSA_PKCS1};
use super::sign::{chain_identity, key_identity, load, loadable};
use super::{provider, provider_name};
use crate::input::Input;

/// A server certificate verifier that accepts everything (the dangerous
/// builder's purpose); it still verifies handshake signatures.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        browntls_core::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        browntls_core::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client certificate verifier that accepts any certificate, optionally
/// without requiring one.
#[derive(Debug)]
struct AcceptAnyClientCert(Arc<CryptoProvider>, bool);

impl ClientCertVerifier for AcceptAnyClientCert {
    fn client_auth_mandatory(&self) -> bool {
        self.1
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        browntls_core::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        browntls_core::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

// ------------------------------------------------------------- providers

/// A provider with fuzz-chosen subsets of one base provider's suites and
/// groups.
fn custom_provider(input: &mut Input<'_>) -> (usize, Arc<CryptoProvider>) {
    let p = input.choose(2);
    let mut provider = (*provider(p)).clone();
    match input.choose(4) {
        // the defaults
        0 => {}
        // everything
        1 => {
            provider.cipher_suites = suites(p).to_vec();
            provider.kx_groups = kx_groups(p).to_vec();
        }
        // subsets (possibly empty)
        _ => {
            let suite_mask = input.u32();
            let kx_mask = input.u16();
            provider.cipher_suites = suites(p)
                .iter()
                .enumerate()
                .filter(|(i, _)| suite_mask >> (i % 32) & 1 != 0)
                .map(|(_, s)| *s)
                .collect();
            provider.kx_groups = kx_groups(p)
                .iter()
                .enumerate()
                .filter(|(i, _)| kx_mask >> (i % 16) & 1 != 0)
                .map(|(_, g)| *g)
                .collect();
        }
    }
    (p, Arc::new(provider))
}

/// The protocol versions to ask for: `None` for the safe defaults.
fn versions(input: &mut Input<'_>) -> Option<&'static [&'static SupportedProtocolVersion]> {
    const BOTH: &[&SupportedProtocolVersion] = &[&version::TLS13, &version::TLS12];
    const TLS13: &[&SupportedProtocolVersion] = &[&version::TLS13];
    const TLS12: &[&SupportedProtocolVersion] = &[&version::TLS12];
    match input.choose(5) {
        0 => None,
        1 => Some(BOTH),
        2 => Some(TLS13),
        3 => Some(TLS12),
        _ => Some(&[]),
    }
}

/// Whether `with_protocol_versions` must succeed: some suite of an enabled
/// version, some group, and a usable group for every TLS 1.2 suite.
fn versions_ok(provider: &CryptoProvider, versions: &[&SupportedProtocolVersion]) -> bool {
    let enabled: Vec<&SupportedCipherSuite> = provider
        .cipher_suites
        .iter()
        .filter(|s| versions.contains(&s.version()))
        .collect();
    let kx: Vec<KeyExchangeAlgorithm> = provider
        .kx_groups
        .iter()
        .map(|g| g.name().key_exchange_algorithm())
        .collect();
    !enabled.is_empty()
        && !kx.is_empty()
        && enabled.iter().all(|s| match s {
            SupportedCipherSuite::Tls12(t) => kx.contains(&t.kx),
            SupportedCipherSuite::Tls13(_) => true,
        })
}

/// Applies the version choice to a builder and checks the outcome.
fn with_versions<S: browntls_core::ConfigSide>(
    builder: ConfigBuilder<S, WantsVersions>,
    provider: &Arc<CryptoProvider>,
    versions: Option<&'static [&'static SupportedProtocolVersion]>,
) -> Option<ConfigBuilder<S, browntls_core::WantsVerifier>> {
    assert!(Arc::ptr_eq(builder.crypto_provider(), provider));
    let expected = versions_ok(
        provider,
        versions.unwrap_or(browntls_core::DEFAULT_VERSIONS),
    );
    let result = match versions {
        None => builder.with_safe_default_protocol_versions(),
        Some(v) => builder.with_protocol_versions(v),
    };
    assert_eq!(
        result.is_ok(),
        expected,
        "{} suites {:?}, {} groups, versions {versions:?}: {result:?}",
        provider_name(provider),
        provider.cipher_suites,
        provider.kx_groups.len()
    );
    let builder = result.ok()?;
    assert!(Arc::ptr_eq(builder.crypto_provider(), provider));
    Some(builder)
}

fn root_store() -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(fixtures::get().ca.clone()).expect("root");
    Arc::new(roots)
}

/// Fragment and record size settings, and whether a connection accepts
/// them.
fn sizes(input: &mut Input<'_>) -> (Option<usize>, Option<u16>, bool) {
    let fragment = match input.choose(4) {
        0 => None,
        1 => Some(usize::from(input.u16())),
        2 => Some(32 + usize::from(input.u16()) % 16_358),
        _ => Some(*input.pick(&[0, 31, 32, 16_389, 16_390, usize::MAX])),
    };
    let record = match input.choose(3) {
        0 => None,
        1 => Some(input.u16()),
        _ => Some(*input.pick(&[0, 63, 64, 16_384, 16_385, u16::MAX])),
    };
    let fragment_ok = fragment.is_none_or(|f| (32..=16_389).contains(&f));
    let record_ok = record.is_none_or(|r| r >= 64);
    (fragment, record, fragment_ok && record_ok)
}

/// One of the fixed ALPN lists (none, or valid protocol names).
fn fixed_alpn(input: &mut Input<'_>) -> Vec<Vec<u8>> {
    match input.choose(4) {
        0 => Vec::new(),
        1 => vec![b"h2".to_vec()],
        2 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        _ => vec![b"http/1.1".to_vec()],
    }
}

/// A fixed ALPN list or a fuzzed one.
fn alpn(input: &mut Input<'_>) -> Vec<Vec<u8>> {
    match input.choose(5) {
        0 => Vec::new(),
        1 => vec![b"h2".to_vec()],
        2 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        3 => vec![b"http/1.1".to_vec()],
        _ => (0..input.choose(3))
            .map(|_| input.short_field().to_vec())
            .collect(),
    }
}

/// Whether provider `p` can load key `k` and the chain of key `j` is for
/// it.
fn pair_ok(p: usize, k: usize, j: usize) -> bool {
    loadable(p, k) && chain_identity(j) == Some(key_identity(k))
}

// ------------------------------------------------------------------ client

/// A client configuration with fuzz-chosen provider, versions, verifier,
/// client authentication and options; then a connection from it.
pub(super) fn client_config_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let (p, provider) = custom_provider(input);
    let versions = versions(input);
    let Some(builder) = with_versions(
        ClientConfig::builder_with_provider(provider.clone()),
        &provider,
        versions,
    ) else {
        return;
    };
    let builder = match input.choose(3) {
        0 => builder.with_root_certificates(root_store()),
        1 => {
            let verifier =
                WebPkiServerVerifier::builder_with_provider(root_store(), provider.clone())
                    .build()
                    .expect("verifier");
            builder.with_webpki_verifier(verifier)
        }
        _ => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider.clone()))),
    };
    let mut config = match input.choose(3) {
        0 => builder.with_no_client_auth(),
        1 => {
            let k = input.choose(fx.keys.len());
            let j = input.choose(fx.keys.len());
            match builder.with_client_auth_cert(fx.keys[j].chain.clone(), fx.keys[k].der()) {
                Ok(config) => {
                    assert!(
                        pair_ok(p, k, j),
                        "{} with chain {}",
                        fx.keys[k].name,
                        fx.keys[j].name
                    );
                    config
                }
                Err(e) => {
                    assert!(!pair_ok(p, k, j), "{}: {e:?}", fx.keys[k].name);
                    return;
                }
            }
        }
        _ => {
            let k = *input.pick(&[P256, P384, ED25519, RSA]);
            let Some(key) = load(p, k) else { return };
            let ck = CertifiedKey::new(fx.keys[k].chain.clone(), key);
            builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(ck)))
        }
    };
    assert!(Arc::ptr_eq(config.crypto_provider(), &provider));
    let (fragment, record, sizes_ok) = sizes(input);
    config.max_fragment_size = fragment;
    config.record_size_limit = record;
    config.alpn_protocols = alpn(input);
    config.enable_sni = input.bool();
    config.enable_early_data = input.bool();
    config.resumption = match input.choose(3) {
        0 => Resumption::in_memory_sessions(input.choose(64)),
        1 => Resumption::store(Arc::new(ClientSessionMemoryCache::new(input.choose(64)))),
        _ => Resumption::disabled(),
    };
    if input.bool() {
        config.key_log = Arc::new(KeyLogFile::new());
    }
    let name = super::verifiers::server_name(input)
        .map_or(ServerName::try_from("localhost").expect("name"), |n| {
            n.to_owned()
        });
    // `with_protocol_versions` accepts TLS 1.2 with only TLS 1.3 groups
    // (FFDHE, ML-KEM, hybrids); the ClientHello then cannot be built.
    let enabled = versions.unwrap_or(browntls_core::DEFAULT_VERSIONS);
    let groups_ok = provider
        .kx_groups
        .iter()
        .any(|g| enabled.iter().any(|v| g.usable_for_version(v.version)));
    let sizes_ok = sizes_ok && groups_ok;
    match ClientConnection::new(Arc::new(config), name) {
        Ok(mut conn) => {
            assert!(sizes_ok, "fragment {fragment:?} record {record:?} accepted");
            let mut hello = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut hello).expect("write to a Vec");
            }
            assert_eq!(hello.first(), Some(&0x16));
        }
        Err(e) => assert!(!sizes_ok, "{e:?}"),
    }
}

// ------------------------------------------------------------------ server

/// A server configuration with fuzz-chosen provider, versions, client
/// verifier, certificate source and options; then a connection from it.
pub(super) fn server_config_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let (p, provider) = custom_provider(input);
    let versions = versions(input);
    let Some(builder) = with_versions(
        ServerConfig::builder_with_provider(provider.clone()),
        &provider,
        versions,
    ) else {
        return;
    };
    let builder = match input.choose(4) {
        0 => builder.with_no_client_auth(),
        1 => builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(root_store(), provider.clone())
                .build()
                .expect("verifier"),
        ),
        2 => builder.with_client_cert_verifier(WebPkiClientVerifier::no_client_auth()),
        _ => builder.with_client_cert_verifier(Arc::new(AcceptAnyClientCert(
            provider.clone(),
            input.bool(),
        ))),
    };
    let k = input.choose(fx.keys.len());
    let j = input.choose(fx.keys.len());
    let mut config = match input.choose(5) {
        0 => match builder.with_single_cert(fx.keys[j].chain.clone(), fx.keys[k].der()) {
            Ok(c) => {
                assert!(
                    pair_ok(p, k, j),
                    "{} with chain {}",
                    fx.keys[k].name,
                    fx.keys[j].name
                );
                c
            }
            Err(e) => {
                assert!(!pair_ok(p, k, j), "{}: {e:?}", fx.keys[k].name);
                return;
            }
        },
        1 => {
            let ocsp = input.short_field().to_vec();
            match builder.with_single_cert_with_ocsp(
                fx.keys[j].chain.clone(),
                fx.keys[k].der(),
                ocsp,
            ) {
                Ok(c) => {
                    assert!(pair_ok(p, k, j));
                    c
                }
                Err(_) => {
                    assert!(!pair_ok(p, k, j));
                    return;
                }
            }
        }
        2 => {
            let mut sni = ResolvesServerCertUsingSni::new();
            if let Some(key) = load(p, k) {
                let _ = sni.add(
                    "localhost",
                    CertifiedKey::new(fx.keys[k].chain.clone(), key),
                );
            }
            builder.with_cert_resolver(Arc::new(sni))
        }
        3 => {
            let Some(key) = load(p, k) else { return };
            let ck = CertifiedKey::new(fx.keys[k].chain.clone(), key);
            builder.with_cert_resolver(Arc::new(SingleCertAndKey::from(ck)))
        }
        _ => {
            let mut psks: Vec<Arc<ExternalPsk>> = Vec::new();
            let identity = input.short_field().to_vec();
            let key = input.field().to_vec();
            let hash = if input.bool() {
                HashAlgorithm::SHA256
            } else {
                HashAlgorithm::from(input.byte())
            };
            if let Ok(psk) = ExternalPsk::new(identity, key, hash) {
                psks.push(Arc::new(psk));
            }
            let config = builder.with_external_psks_only(Arc::new(psks));
            assert!(config.external_psks.is_some());
            config
        }
    };
    let (fragment, record, sizes_ok) = sizes(input);
    config.max_fragment_size = fragment;
    config.record_size_limit = record;
    config.alpn_protocols = alpn(input);
    config.ignore_client_order = input.bool();
    config.send_tls13_tickets = input.choose(4);
    config.max_early_data_size = input.u32();
    if input.bool() {
        config.session_storage = ServerSessionMemoryCache::new(input.choose(64));
    } else {
        config.session_storage = Arc::new(NoServerSessionStorage {});
    }
    if input.bool() {
        config.ticketer = browntls_core::crypto::rustcrypto::Ticketer::new().expect("ticketer");
    }
    match ServerConnection::new(Arc::new(config)) {
        Ok(conn) => {
            assert!(sizes_ok, "fragment {fragment:?} record {record:?} accepted");
            assert!(conn.is_handshaking());
        }
        Err(e) => assert!(!sizes_ok, "{e:?}"),
    }
}

// --------------------------------------------------------------- handshake

/// Moves records between the two sides until neither has anything to say.
fn pump(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..40 {
        let mut progressed = false;
        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).expect("write to a Vec");
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            progressed = true;
            server.read_tls(&mut rd).expect("read from a slice");
            server.process_new_packets()?;
        }
        let mut buf = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut buf).expect("write to a Vec");
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            progressed = true;
            client.read_tls(&mut rd).expect("read from a slice");
            client.process_new_packets()?;
        }
        if !progressed {
            break;
        }
    }
    Ok(())
}

/// A handshake between fuzz-chosen client and server configurations of
/// either provider. When the configurations are compatible it must
/// complete, and the sides must agree on what was negotiated; then a second
/// connection resumes.
pub(super) fn handshake_op(input: &mut Input<'_>) {
    const VERSIONS: [&[&SupportedProtocolVersion]; 3] = [
        &[&version::TLS13, &version::TLS12],
        &[&version::TLS13],
        &[&version::TLS12],
    ];
    let fx = fixtures::get();
    let pc = input.choose(2);
    let ps = input.choose(2);
    let cv = *input.pick(&VERSIONS);
    let sv = *input.pick(&VERSIONS);
    let k = *input.pick(&[P256, P384, ED25519, RSA, RSA_PKCS1, P256_SEC1]);
    let Some(server_key) = load(ps, k) else {
        return;
    };
    let sni = input.bool();
    let client_auth = input.choose(3);
    let client_alpn = fixed_alpn(input);
    let server_alpn = fixed_alpn(input);
    let name_choice = input.choose(3);
    let tickets = input.choose(3);

    let server_builder = ServerConfig::builder_with_provider(provider(ps))
        .with_protocol_versions(sv)
        .expect("default provider supports every version");
    let server_builder = match client_auth {
        0 => server_builder.with_no_client_auth(),
        1 => server_builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(root_store(), provider(ps))
                .build()
                .expect("verifier"),
        ),
        _ => server_builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(root_store(), provider(ps))
                .allow_unauthenticated()
                .build()
                .expect("verifier"),
        ),
    };
    let ck = CertifiedKey::new(fx.keys[k].chain.clone(), server_key);
    let mut server_config = if sni {
        let mut resolver = ResolvesServerCertUsingSni::new();
        resolver.add("localhost", ck).expect("valid for localhost");
        server_builder.with_cert_resolver(Arc::new(resolver))
    } else {
        server_builder.with_cert_resolver(Arc::new(SingleCertAndKey::from(ck)))
    };
    server_config.alpn_protocols = server_alpn.clone();
    match tickets {
        0 => {}
        1 => {
            server_config.ticketer =
                browntls_core::crypto::rustcrypto::Ticketer::new().expect("ticketer")
        }
        _ => {
            server_config.ticketer = Arc::new(
                TicketRotator::new(3600, || {
                    Ok(Box::new(
                        browntls_core::crypto::native::ticketer::AeadTicketProducer::new()?,
                    ))
                })
                .expect("rotator"),
            )
        }
    }
    let server_config = Arc::new(server_config);

    let client_builder = ClientConfig::builder_with_provider(provider(pc))
        .with_protocol_versions(cv)
        .expect("default provider supports every version")
        .with_root_certificates(root_store());
    // The client presents a certificate when the server asks for one, with a
    // key it can load.
    let client_key = load(pc, P256).expect("P-256 loads everywhere");
    let mut client_config = if client_auth != 0 && input.bool() {
        client_builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(
            CertifiedKey::new(fx.keys[P256].chain.clone(), client_key),
        )))
    } else {
        client_builder.with_no_client_auth()
    };
    let presents_cert = client_config.client_auth_cert_resolver.has_certs();
    client_config.alpn_protocols = client_alpn.clone();
    client_config.resumption = Resumption::in_memory_sessions(8);
    let client_config = Arc::new(client_config);
    let name = ["localhost", "a.wild.example", "127.0.0.1"][name_choice];
    let name = ServerName::try_from(name).expect("name").to_owned();

    let versions_meet = cv.iter().any(|v| sv.contains(v));
    let alpn_meets = client_alpn.is_empty()
        || server_alpn.is_empty()
        || client_alpn.iter().any(|a| server_alpn.contains(a));
    let resolves = !sni || name_choice == 0;
    let authenticates = client_auth != 1 || presents_cert;
    let expected = versions_meet && alpn_meets && resolves && authenticates;

    for round in 0..2 {
        let mut client =
            ClientConnection::new(client_config.clone(), name.clone()).expect("client");
        let mut server = ServerConnection::new(server_config.clone()).expect("server");
        let result = pump(&mut client, &mut server);
        let done = result.is_ok() && !client.is_handshaking() && !server.is_handshaking();
        assert_eq!(
            done, expected,
            "round {round}: client {pc} {cv:?}, server {ps} {sv:?}, key {}, sni {sni}, \
             auth {client_auth}/{presents_cert}, alpn {client_alpn:?}/{server_alpn:?}, \
             name {name:?}: {result:?}",
            fx.keys[k].name
        );
        if !done {
            return;
        }
        let suite = client.negotiated_cipher_suite().expect("suite");
        assert_eq!(server.negotiated_cipher_suite(), Some(suite));
        assert!(
            suites(pc).contains(&suite) && suites(ps).iter().any(|s| s.suite() == suite.suite())
        );
        let version = client.protocol_version().expect("version");
        assert_eq!(server.protocol_version(), Some(version));
        assert!(cv.iter().chain(sv).any(|v| v.version == version));
        assert_eq!(client.alpn_protocol(), server.alpn_protocol());
        if let Some(proto) = client.alpn_protocol() {
            assert!(client_alpn.iter().any(|a| a == proto));
            assert!(server_alpn.iter().any(|a| a == proto));
        }
        // Application data both ways.
        client.writer().write_all(b"ping").expect("buffered");
        server.writer().write_all(b"pong").expect("buffered");
        pump(&mut client, &mut server).expect("data");
        let mut got = [0u8; 4];
        server.reader().read_exact(&mut got).expect("ping");
        assert_eq!(&got, b"ping");
        client.reader().read_exact(&mut got).expect("pong");
        assert_eq!(&got, b"pong");
    }
}
