//! In-memory handshakes that only the native provider can run.
//!
//! * RSA server and client authentication with keys the native provider
//!   signs with: every RSA-PSS scheme in TLS 1.3, every RSA-PSS and
//!   PKCS #1 v1.5 scheme in TLS 1.2, with every suite that can carry them.
//! * Certificate chains whose keys come from `browntls-crypto` and whose
//!   certificate signatures the native provider makes, validated by the
//!   web-PKI verifiers.
//! * ECDSA P-521 handshake signatures in both directions, with keys from
//!   `browntls-crypto` presented as raw public keys (rcgen with ring cannot
//!   make P-521 keys or certificates).
//! * The ML-KEM-1024 and SecP384r1MLKEM1024 groups, which neither the
//!   RustCrypto provider nor rustls/ring implements, so they are exercised
//!   native to native here.
//!
//! The shared suites (`tls13_native.rs`, `tls12_native.rs`, ...) already run
//! every suite and group, these groups included, with the native provider;
//! the tests here pin down the signature scheme and key exchange details.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls::client::WebPkiServerVerifier;
use browntls::client::danger::ServerCertVerifier;
use browntls::crypto::{CryptoProvider, SupportedKxGroup};
use browntls::server::WebPkiClientVerifier;
use browntls::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, NamedGroup,
    PeerIncompatible, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    SignatureScheme, SupportedCipherSuite, SupportedProtocolVersion, version,
};
use common::*;

const PSS: [SignatureScheme; 3] = [
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
];

const PKCS1: [SignatureScheme; 3] = [
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

const VERSIONS: [ProtocolVersion; 2] = [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];

static TLS12_ONLY: [&SupportedProtocolVersion; 1] = [&version::TLS12];
static TLS13_ONLY: [&SupportedProtocolVersion; 1] = [&version::TLS13];

fn versions(v: ProtocolVersion) -> &'static [&'static SupportedProtocolVersion] {
    match v {
        ProtocolVersion::TLSv1_2 => &TLS12_ONLY,
        _ => &TLS13_ONLY,
    }
}

/// The RSA signature schemes a handshake signature may use in `v`.
fn rsa_schemes(v: ProtocolVersion) -> Vec<SignatureScheme> {
    match v {
        ProtocolVersion::TLSv1_2 => PSS.iter().chain(PKCS1.iter()).copied().collect(),
        _ => PSS.to_vec(),
    }
}

/// The suites a default RSA-keyed server can negotiate in `v`.
fn rsa_suites(v: ProtocolVersion) -> Vec<SupportedCipherSuite> {
    prov::DEFAULT_CIPHER_SUITES
        .iter()
        .filter(|s| match v {
            ProtocolVersion::TLSv1_2 => {
                s.tls13().is_none() && format!("{:?}", s.suite()).contains("_RSA_")
            }
            _ => s.tls13().is_some(),
        })
        .copied()
        .collect()
}

fn provider_with(
    suites: Option<&[SupportedCipherSuite]>,
    groups: Option<&[&'static dyn SupportedKxGroup]>,
) -> Arc<CryptoProvider> {
    let mut provider = prov::default_provider();
    if let Some(suites) = suites {
        provider.cipher_suites = suites.to_vec();
    }
    if let Some(groups) = groups {
        provider.kx_groups = groups.to_vec();
    }
    Arc::new(provider)
}

fn client_with(
    v: ProtocolVersion,
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions(v))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

fn server_with(chain: &Chain, provider: Arc<CryptoProvider>) -> ServerConfig {
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

fn roots_for(chain: &Chain) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    Arc::new(roots)
}

fn round_trip(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(send_and_receive(client, server, b"ping"), b"ping");
    assert_eq!(send_and_receive(server, client, b"pong"), b"pong");
}

// ------------------------------------------------------- default provider

/// With `native` as the only provider feature (the default build), the
/// default builders use it as the process default provider.
#[cfg(not(feature = "rustcrypto"))]
#[test]
fn default_builders_use_the_native_provider() {
    init_logging();
    let chain = server_chain(KeyType::Rsa2048);
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    for config in [
        client_config.crypto_provider(),
        server_config.crypto_provider(),
    ] {
        assert_eq!(config.cipher_suites, prov::DEFAULT_CIPHER_SUITES);
        assert_eq!(
            config
                .kx_groups
                .iter()
                .map(|g| g.name())
                .collect::<Vec<_>>(),
            prov::DEFAULT_KX_GROUPS
                .iter()
                .map(|g| g.name())
                .collect::<Vec<_>>()
        );
    }
    let (mut client, mut server) = connect(client_config, server_config);
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        prov::DEFAULT_KX_GROUPS[0].name()
    );
    round_trip(&mut client, &mut server);
}

// ------------------------------------------------------- RSA authentication

#[test]
fn rsa_server_signs_with_every_scheme_and_suite() {
    init_logging();
    let chain = server_chain(KeyType::Rsa2048);
    let mut handshakes = 0;
    for v in VERSIONS {
        for suite in rsa_suites(v) {
            for scheme in rsa_schemes(v) {
                let verifier = SchemeRecordingServerVerifier::new(
                    PinnedServerVerifier::new(&chain),
                    &[scheme],
                );
                let (mut client, mut server) = connect(
                    client_with(v, provider_with(Some(&[suite]), None), verifier.clone()),
                    server_config(&chain),
                );
                do_handshake(&mut client, &mut server)
                    .unwrap_or_else(|e| panic!("{v:?} {suite:?} {scheme:?}: {e}"));
                assert_eq!(client.protocol_version(), Some(v));
                assert_eq!(
                    server.negotiated_cipher_suite().unwrap().suite(),
                    suite.suite()
                );
                assert_eq!(verifier.seen(), [scheme], "{v:?} {suite:?}");
                round_trip(&mut client, &mut server);
                handshakes += 1;
            }
        }
    }
    // 4 TLS 1.3 suites (AES-128-CCM-8 is not a default suite) x 3 PSS
    // schemes + 3 ECDHE_RSA suites x 6 schemes
    assert_eq!(handshakes, 30);
}

#[test]
fn rsa_server_prefers_pss_with_the_largest_hash() {
    init_logging();
    let chain = server_chain(KeyType::Rsa2048);
    for v in VERSIONS {
        // Offered in the opposite order to the key's preference.
        let mut offer = rsa_schemes(v);
        offer.reverse();
        let verifier =
            SchemeRecordingServerVerifier::new(PinnedServerVerifier::new(&chain), &offer);
        let (mut client, mut server) = connect(
            client_with(v, provider_with(None, None), verifier.clone()),
            server_config(&chain),
        );
        do_handshake(&mut client, &mut server).unwrap();
        assert_eq!(verifier.seen(), [SignatureScheme::RSA_PSS_SHA512], "{v:?}");
    }
}

#[test]
fn tls13_rsa_server_refuses_a_pkcs1_only_client() {
    init_logging();
    let chain = server_chain(KeyType::Rsa2048);
    // PKCS #1 v1.5 is not a TLS 1.3 handshake signature (RFC 8446 §4.2.3).
    let verifier = SchemeRecordingServerVerifier::new(PinnedServerVerifier::new(&chain), &PKCS1);
    let (mut client, mut server) = connect(
        client_with(
            ProtocolVersion::TLSv1_3,
            provider_with(None, None),
            verifier.clone(),
        ),
        server_config(&chain),
    );
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res,
        Err(PeerIncompatible::NoSignatureSchemesInCommon.into())
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );
    assert!(verifier.seen().is_empty());
}

#[test]
fn ecdsa_suites_refuse_an_rsa_certificate() {
    init_logging();
    let chain = server_chain(KeyType::Rsa2048);
    let ecdsa_suites: Vec<_> = prov::ALL_CIPHER_SUITES
        .iter()
        .filter(|s| format!("{:?}", s.suite()).contains("_ECDSA_"))
        .copied()
        .collect();
    let (mut client, mut server) = connect(
        client_with(
            ProtocolVersion::TLSv1_2,
            provider_with(Some(&ecdsa_suites), None),
            PinnedServerVerifier::new(&chain),
        ),
        server_config(&chain),
    );
    let (_, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        server_res,
        Err(PeerIncompatible::NoCipherSuitesInCommon.into())
    );
}

#[test]
fn rsa_client_auth_with_every_scheme() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Rsa2048);
    for v in VERSIONS {
        for scheme in rsa_schemes(v) {
            let verifier = SchemeRecordingClientVerifier::new(
                PinnedClientVerifier::new(&client_chain, true),
                &[scheme],
            );
            let client_config = ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(versions(v))
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
                .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
                .unwrap();
            let server_config = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(verifier.clone())
                .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
                .unwrap();
            let (mut client, mut server) = connect(client_config, server_config);
            do_handshake(&mut client, &mut server)
                .unwrap_or_else(|e| panic!("{v:?} {scheme:?}: {e}"));
            assert_eq!(client.protocol_version(), Some(v));
            assert_eq!(verifier.seen(), [scheme], "{v:?}");
            assert_eq!(
                server.peer_certificates().unwrap(),
                client_chain.cert_chain()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn tls13_rsa_client_without_a_usable_scheme_sends_no_certificate() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Rsa2048);
    // The CertificateRequest allows ECDSA and PKCS #1 v1.5, which TLS 1.3
    // forbids for CertificateVerify: the RSA client cannot authenticate.
    // (With PKCS #1 v1.5 alone the server refuses to build the request.)
    let verifier = SchemeRecordingClientVerifier::new(
        PinnedClientVerifier::new(&client_chain, true),
        &[
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ],
    );
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
        .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
        .unwrap();
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
        .unwrap();
    let (mut client, mut server) = connect(client_config, server_config);
    let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(server_res, Err(Error::NoCertificatesPresented));
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::CertificateRequired))
    );
    assert!(verifier.seen().is_empty());
}

#[test]
fn natively_signed_chains_validate_with_the_webpki_verifiers() {
    init_logging();
    for alg in native_keys::CERT_ALGS {
        let server_chain = native_keys::server_chain(alg);
        let client_chain = native_keys::client_chain(alg);
        for v in VERSIONS {
            let server_verifier =
                WebPkiServerVerifier::builder_with_provider(roots_for(&server_chain), provider())
                    .build()
                    .unwrap();
            let client_verifier =
                WebPkiClientVerifier::builder_with_provider(roots_for(&client_chain), provider())
                    .build()
                    .unwrap();
            let client_config = ClientConfig::builder_with_provider(provider())
                .with_protocol_versions(versions(v))
                .unwrap()
                .with_webpki_verifier(server_verifier)
                .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
                .unwrap();
            let server_config = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
                .unwrap();
            let (mut client, mut server) = connect(client_config, server_config);
            do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{alg:?} {v:?}: {e}"));
            assert_eq!(client.protocol_version(), Some(v));
            assert_eq!(
                client.peer_certificates().unwrap(),
                server_chain.cert_chain()
            );
            assert_eq!(
                server.peer_certificates().unwrap(),
                client_chain.cert_chain()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn webpki_verifier_rejects_a_natively_signed_chain_from_another_root() {
    init_logging();
    let chain = native_keys::server_chain(native_keys::CERT_ALGS[0]);
    let other = server_chain(KeyType::Rsa2048);
    let verifier = WebPkiServerVerifier::builder_with_provider(roots_for(&other), provider())
        .build()
        .unwrap();
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    let (mut client, mut server) = connect(client_config, server_config(&chain));
    let (client_res, _) = do_handshake_until_error(&mut client, &mut server);
    assert!(
        matches!(client_res, Err(Error::InvalidCertificate(_))),
        "{client_res:?}"
    );
}

// ---------------------------------------------------------- ECDSA P-521

#[test]
fn p521_raw_public_keys_sign_in_both_directions() {
    init_logging();
    let server_key = native_keys::P521RawKey::generate();
    let client_key = native_keys::P521RawKey::generate();
    let provider = prov::default_provider();
    let p521 = [SignatureScheme::ECDSA_NISTP521_SHA512];
    for v in VERSIONS {
        let server_verifier = SchemeRecordingServerVerifier::new(
            server_key.server_verifier(prov::SUPPORTED_SIG_ALGS),
            &p521,
        );
        let client_verifier = SchemeRecordingClientVerifier::new(
            client_key.client_verifier(prov::SUPPORTED_SIG_ALGS),
            &p521,
        );
        let client_config = ClientConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_protocol_versions(versions(v))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier.clone())
            .with_client_cert_resolver(client_key.resolver(&provider));
        let server_config = ServerConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_protocol_versions(versions(v))
            .unwrap()
            .with_client_cert_verifier(client_verifier.clone())
            .with_cert_resolver(server_key.resolver(&provider));
        let (mut client, mut server) = connect(client_config, server_config);
        do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{v:?}: {e}"));
        assert_eq!(client.protocol_version(), Some(v));
        assert_eq!(server_verifier.seen(), p521, "{v:?}");
        assert_eq!(client_verifier.seen(), p521, "{v:?}");
        assert_eq!(
            client.peer_certificates().unwrap(),
            [browntls::pki_types::CertificateDer::from(
                server_key.spki.clone()
            )]
        );
        round_trip(&mut client, &mut server);
    }
}

// ------------------------------------------------- ML-KEM-1024 key exchange

/// The groups only the native provider implements.
fn mlkem1024_groups() -> [&'static dyn SupportedKxGroup; 2] {
    [
        prov::kx_group::MLKEM1024,
        prov::kx_group::SECP384R1MLKEM1024,
    ]
}

#[test]
fn mlkem1024_group_code_points() {
    assert_eq!(prov::kx_group::MLKEM1024.name(), NamedGroup::MLKEM1024);
    assert_eq!(
        prov::kx_group::SECP384R1MLKEM1024.name(),
        NamedGroup::secp384r1MLKEM1024
    );
    assert_eq!(
        u16::from(NamedGroup::secp384r1MLKEM1024),
        prov::kx_group::SECP384R1MLKEM1024_CODEPOINT
    );
    assert!(
        prov::ALL_KX_GROUPS
            .iter()
            .any(|g| g.name() == NamedGroup::MLKEM1024)
    );
    // Neither is enabled by default.
    assert!(
        prov::DEFAULT_KX_GROUPS
            .iter()
            .all(|g| !mlkem1024_groups().iter().any(|m| m.name() == g.name()))
    );
}

#[test]
fn mlkem1024_groups_with_every_suite_then_resume() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP384);
    for group in mlkem1024_groups() {
        for suite in prov::ALL_CIPHER_SUITES
            .iter()
            .filter(|s| s.tls13().is_some())
        {
            let provider = provider_with(Some(&[*suite]), Some(&[group]));
            let client_config = Arc::new(client_with(
                ProtocolVersion::TLSv1_3,
                provider.clone(),
                PinnedServerVerifier::new(&chain),
            ));
            let server_config = Arc::new(server_with(&chain, provider));
            let mut client = ClientConnection::new(client_config.clone(), server_name()).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            do_handshake(&mut client, &mut server)
                .unwrap_or_else(|e| panic!("{group:?} {suite:?}: {e}"));
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
            assert_eq!(
                client.negotiated_key_exchange_group().unwrap().name(),
                group.name()
            );
            assert_eq!(
                server.negotiated_key_exchange_group().unwrap().name(),
                group.name()
            );
            round_trip(&mut client, &mut server);

            // The resumption is psk_dhe_ke: a fresh exchange in the same group.
            let mut client = ClientConnection::new(client_config, server_name()).unwrap();
            let mut server = ServerConnection::new(server_config).unwrap();
            do_handshake(&mut client, &mut server)
                .unwrap_or_else(|e| panic!("resumed {group:?} {suite:?}: {e}"));
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(
                server.negotiated_key_exchange_group().unwrap().name(),
                group.name()
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn hello_retry_request_into_each_mlkem1024_group() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for group in mlkem1024_groups() {
        // The client's single key share is X25519; the server only takes `group`.
        let (mut client, mut server) = connect(
            client_with(
                ProtocolVersion::TLSv1_3,
                provider_with(None, Some(&[prov::kx_group::X25519, group])),
                PinnedServerVerifier::new(&chain),
            ),
            server_with(&chain, provider_with(None, Some(&[group]))),
        );
        do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{group:?}: {e}"));
        assert_eq!(
            client.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(
            server.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(
            client.negotiated_key_exchange_group().unwrap().name(),
            group.name()
        );
        round_trip(&mut client, &mut server);
    }
}

#[test]
fn secp384r1mlkem1024_share_carries_its_classical_half() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let client_groups = [
        prov::kx_group::SECP384R1MLKEM1024,
        prov::kx_group::SECP384R1,
    ];
    // A server without the hybrid answers the P-384 share sent alongside it.
    let (mut client, mut server) = connect(
        client_with(
            ProtocolVersion::TLSv1_3,
            provider_with(None, Some(&client_groups)),
            PinnedServerVerifier::new(&chain),
        ),
        server_with(
            &chain,
            provider_with(None, Some(&[prov::kx_group::SECP384R1])),
        ),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp384r1
    );
    round_trip(&mut client, &mut server);

    // A server with both takes the hybrid.
    let (mut client, mut server) = connect(
        client_with(
            ProtocolVersion::TLSv1_3,
            provider_with(None, Some(&client_groups)),
            PinnedServerVerifier::new(&chain),
        ),
        server_with(&chain, provider_with(None, Some(&client_groups))),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp384r1MLKEM1024
    );
    round_trip(&mut client, &mut server);
}

#[test]
fn mlkem1024_groups_are_not_used_for_tls12() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client_groups = mlkem1024_groups().to_vec();
    client_groups.push(prov::kx_group::SECP384R1);
    let (mut client, mut server) = connect(
        client_with(
            ProtocolVersion::TLSv1_2,
            provider_with(None, Some(&client_groups)),
            PinnedServerVerifier::new(&chain),
        ),
        server_with(&chain, provider_with(None, Some(prov::ALL_KX_GROUPS))),
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp384r1
    );
    round_trip(&mut client, &mut server);
}

#[test]
fn client_hello_offers_the_mlkem1024_groups() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let mut client = ClientConnection::new(
        Arc::new(client_with(
            ProtocolVersion::TLSv1_3,
            provider_with(None, Some(prov::ALL_KX_GROUPS)),
            PinnedServerVerifier::new(&chain),
        )),
        server_name(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let mut acceptor = browntls::server::Acceptor::default();
    acceptor.read_tls(&mut &hello[..]).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    let offered = accepted.client_hello().named_groups().unwrap().to_vec();
    assert_eq!(
        offered,
        prov::ALL_KX_GROUPS
            .iter()
            .map(|g| g.name())
            .collect::<Vec<_>>()
    );
    assert!(offered.contains(&NamedGroup::MLKEM1024));
    assert!(offered.contains(&NamedGroup::secp384r1MLKEM1024));
}
