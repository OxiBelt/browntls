//! Handshakes between a native-provider peer and a RustCrypto-provider peer,
//! in both directions: every cipher suite with every key exchange group the
//! two providers share and every server key type, client authentication,
//! resumption, HelloRetryRequest, key updates and exporters.
//!
//! Each side's record protection, key schedule, key exchange, randomness and
//! signature verification come from its own provider. RustCrypto signs
//! nothing with RSA (RUSTSEC-2023-0071), so an RSA-keyed RustCrypto peer
//! loads its private key with the native key provider; everything else on
//! that side stays RustCrypto's.

#![cfg(all(feature = "native", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls::crypto::{
    CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms, native, rustcrypto,
};
use browntls::{
    CipherSuite, ClientConfig, ClientConnection, HandshakeKind, NamedGroup, ProtocolVersion,
    ServerConfig, ServerConnection, SupportedCipherSuite, SupportedProtocolVersion, version,
};
use common::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Native,
    RustCrypto,
}

/// The suites both providers implement: the native ones without the AES-CCM
/// suites, which the RustCrypto provider lacks.
fn common_suites() -> Vec<SupportedCipherSuite> {
    native::ALL_CIPHER_SUITES
        .iter()
        .filter(|s| {
            rustcrypto::ALL_CIPHER_SUITES
                .iter()
                .any(|r| r.suite() == s.suite())
        })
        .copied()
        .collect()
}

/// `(client, server)` provider pairs.
const DIRECTIONS: [(Side, Side); 2] = [
    (Side::Native, Side::RustCrypto),
    (Side::RustCrypto, Side::Native),
];

#[cfg(feature = "tls12")]
const VERSIONS: [ProtocolVersion; 2] = [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
#[cfg(not(feature = "tls12"))]
const VERSIONS: [ProtocolVersion; 1] = [ProtocolVersion::TLSv1_3];

#[cfg(feature = "tls12")]
static TLS12_ONLY: [&SupportedProtocolVersion; 1] = [&version::TLS12];
static TLS13_ONLY: [&SupportedProtocolVersion; 1] = [&version::TLS13];

fn versions(v: ProtocolVersion) -> &'static [&'static SupportedProtocolVersion] {
    match v {
        #[cfg(feature = "tls12")]
        ProtocolVersion::TLSv1_2 => &TLS12_ONLY,
        _ => &TLS13_ONLY,
    }
}

impl Side {
    fn default_provider(self) -> CryptoProvider {
        match self {
            Side::Native => native::default_provider(),
            Side::RustCrypto => rustcrypto::default_provider(),
        }
    }

    fn suites(self) -> &'static [SupportedCipherSuite] {
        match self {
            Side::Native => native::ALL_CIPHER_SUITES,
            Side::RustCrypto => rustcrypto::ALL_CIPHER_SUITES,
        }
    }

    fn groups(self) -> &'static [&'static dyn SupportedKxGroup] {
        match self {
            Side::Native => native::ALL_KX_GROUPS,
            Side::RustCrypto => rustcrypto::ALL_KX_GROUPS,
        }
    }

    fn sig_algs(self) -> WebPkiSupportedAlgorithms {
        match self {
            Side::Native => native::SUPPORTED_SIG_ALGS,
            Side::RustCrypto => rustcrypto::SUPPORTED_SIG_ALGS,
        }
    }

    /// This side's provider, restricted to `suite` and `group` when given,
    /// able to sign with `key` when given.
    fn provider(
        self,
        suite: Option<CipherSuite>,
        group: Option<NamedGroup>,
        key: Option<KeyType>,
    ) -> Arc<CryptoProvider> {
        let mut provider = self.default_provider();
        if let Some(suite) = suite {
            provider.cipher_suites = self
                .suites()
                .iter()
                .filter(|s| s.suite() == suite)
                .copied()
                .collect();
            assert_eq!(provider.cipher_suites.len(), 1, "{self:?} {suite:?}");
        }
        if let Some(group) = group {
            provider.kx_groups = self
                .groups()
                .iter()
                .filter(|g| g.name() == group)
                .copied()
                .collect();
            assert_eq!(provider.kx_groups.len(), 1, "{self:?} {group:?}");
        }
        if self == Side::RustCrypto && key == Some(KeyType::Rsa2048) {
            provider.key_provider = native::KEY_PROVIDER;
        }
        Arc::new(provider)
    }

    /// Pins `chain`'s end entity, checking signatures with this side's algorithms.
    fn server_verifier(self, chain: &Chain) -> Arc<PinnedServerVerifier> {
        Arc::new(PinnedServerVerifier {
            expected: chain.end_entity.clone(),
            spki: chain.spki(),
            algs: self.sig_algs(),
            raw: false,
        })
    }

    /// Requires `chain`'s end entity, checking signatures with this side's algorithms.
    fn client_verifier(self, chain: &Chain) -> Arc<PinnedClientVerifier> {
        Arc::new(PinnedClientVerifier {
            expected: chain.end_entity.clone(),
            spki: chain.spki(),
            algs: self.sig_algs(),
            mandatory: true,
            hints: Vec::new(),
            raw: false,
        })
    }

    fn ticketer(self) -> Arc<dyn browntls::server::ProducesTickets> {
        match self {
            Side::Native => prov::Ticketer::new().unwrap(),
            Side::RustCrypto => rustcrypto::Ticketer::new().unwrap(),
        }
    }
}

fn client_config(
    side: Side,
    v: ProtocolVersion,
    provider: Arc<CryptoProvider>,
    server_chain: &Chain,
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions(v))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(side.server_verifier(server_chain))
        .with_no_client_auth()
}

fn server_config(provider: Arc<CryptoProvider>, chain: &Chain) -> ServerConfig {
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

fn round_trip(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(
        send_and_receive(client, server, b"from the client"),
        b"from the client"
    );
    assert_eq!(
        send_and_receive(server, client, b"from the server"),
        b"from the server"
    );
}

/// The server key types that can authenticate `suite`.
fn key_types(suite: &SupportedCipherSuite) -> &'static [KeyType] {
    if suite.tls13().is_some() {
        &KeyType::ALL
    } else if format!("{:?}", suite.suite()).contains("_RSA_") {
        &[KeyType::Rsa2048]
    } else {
        &KeyType::NON_RSA
    }
}

/// The groups both providers implement that `v` can use.
fn common_groups(v: ProtocolVersion) -> Vec<NamedGroup> {
    native::ALL_KX_GROUPS
        .iter()
        .filter(|g| g.usable_for_version(v))
        .map(|g| g.name())
        .filter(|name| rustcrypto::ALL_KX_GROUPS.iter().any(|r| r.name() == *name))
        .collect()
}

#[test]
fn common_groups_cover_every_rustcrypto_group() {
    assert_eq!(
        common_groups(ProtocolVersion::TLSv1_3).len(),
        rustcrypto::ALL_KX_GROUPS.len()
    );
    assert_eq!(
        common_groups(ProtocolVersion::TLSv1_2),
        [
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
            NamedGroup::secp521r1
        ]
    );
    // The providers implement the same suites, except the native-only
    // AES-CCM suites.
    let names =
        |suites: &[SupportedCipherSuite]| suites.iter().map(|s| s.suite()).collect::<Vec<_>>();
    assert_eq!(names(&common_suites()), names(Side::RustCrypto.suites()));
    let native_only: Vec<_> = names(Side::Native.suites())
        .into_iter()
        .filter(|s| !names(&common_suites()).contains(s))
        .collect();
    assert_eq!(
        native_only,
        [
            CipherSuite::TLS13_AES_128_CCM_SHA256,
            CipherSuite::TLS13_AES_128_CCM_8_SHA256
        ]
    );
}

#[test]
fn every_suite_group_and_key_type_both_directions() {
    init_logging();
    let chains: Vec<Chain> = KeyType::ALL.iter().map(|k| server_chain(*k)).collect();
    let chain_for = |k: KeyType| chains.iter().find(|c| c.key_type == k).unwrap();
    let mut handshakes = 0;
    for (client_side, server_side) in DIRECTIONS {
        for suite in &common_suites() {
            let v = suite.version().version;
            for &key in key_types(suite) {
                let chain = chain_for(key);
                for group in common_groups(v) {
                    let what =
                        format!("{client_side:?}->{server_side:?} {suite:?} {group:?} {key:?}");
                    let client = client_config(
                        client_side,
                        v,
                        client_side.provider(Some(suite.suite()), Some(group), None),
                        chain,
                    );
                    let server = server_config(
                        server_side.provider(Some(suite.suite()), Some(group), Some(key)),
                        chain,
                    );
                    let mut client =
                        ClientConnection::new(Arc::new(client), server_name()).unwrap();
                    let mut server = ServerConnection::new(Arc::new(server)).unwrap();
                    do_handshake(&mut client, &mut server)
                        .unwrap_or_else(|e| panic!("{what}: {e}"));
                    assert_eq!(client.protocol_version(), Some(v), "{what}");
                    assert_eq!(server.protocol_version(), Some(v), "{what}");
                    assert_eq!(
                        client.negotiated_cipher_suite().unwrap().suite(),
                        suite.suite(),
                        "{what}"
                    );
                    assert_eq!(
                        server.negotiated_key_exchange_group().unwrap().name(),
                        group,
                        "{what}"
                    );
                    assert_eq!(
                        client.negotiated_key_exchange_group().unwrap().name(),
                        group,
                        "{what}"
                    );
                    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full), "{what}");
                    round_trip(&mut client, &mut server);
                    handshakes += 1;
                }
            }
        }
    }
    // Per direction: 3 TLS 1.3 suites x 4 key types x 7 groups, and with
    // TLS 1.2 3 ECDHE_ECDSA suites x 3 key types x 4 groups and 3 ECDHE_RSA
    // suites x 4 groups.
    let tls12 = if cfg!(feature = "tls12") {
        3 * 3 * 4 + 3 * 4
    } else {
        0
    };
    assert_eq!(handshakes, 2 * (3 * 4 * 7 + tls12));
}

#[test]
fn client_auth_every_key_type_both_directions() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    for (client_side, server_side) in DIRECTIONS {
        for v in VERSIONS {
            for key in KeyType::ALL {
                let what = format!("{client_side:?}->{server_side:?} {v:?} {key:?}");
                let client_chain = client_chain(key);
                let client = ClientConfig::builder_with_provider(client_side.provider(
                    None,
                    None,
                    Some(key),
                ))
                .with_protocol_versions(versions(v))
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(client_side.server_verifier(&server_chain))
                .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
                .unwrap();
                let server =
                    ServerConfig::builder_with_provider(server_side.provider(None, None, None))
                        .with_safe_default_protocol_versions()
                        .unwrap()
                        .with_client_cert_verifier(server_side.client_verifier(&client_chain))
                        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
                        .unwrap();
                let mut client = ClientConnection::new(Arc::new(client), server_name()).unwrap();
                let mut server = ServerConnection::new(Arc::new(server)).unwrap();
                do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{what}: {e}"));
                assert_eq!(client.protocol_version(), Some(v), "{what}");
                assert_eq!(
                    server.peer_certificates().unwrap(),
                    client_chain.cert_chain(),
                    "{what}"
                );
                round_trip(&mut client, &mut server);
            }
        }
    }
}

#[test]
fn resumption_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for (client_side, server_side) in DIRECTIONS {
        for v in VERSIONS {
            for stateless in [false, true] {
                let what = format!("{client_side:?}->{server_side:?} {v:?} stateless={stateless}");
                let client = Arc::new(client_config(
                    client_side,
                    v,
                    client_side.provider(None, None, None),
                    &chain,
                ));
                let mut server = server_config(server_side.provider(None, None, None), &chain);
                if stateless {
                    server.ticketer = server_side.ticketer();
                    server.session_storage = Arc::new(browntls::server::NoServerSessionStorage {});
                }
                let server = Arc::new(server);

                let mut c = ClientConnection::new(client.clone(), server_name()).unwrap();
                let mut s = ServerConnection::new(server.clone()).unwrap();
                do_handshake(&mut c, &mut s).unwrap_or_else(|e| panic!("{what}: {e}"));
                assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full), "{what}");
                round_trip(&mut c, &mut s);

                let mut c = ClientConnection::new(client, server_name()).unwrap();
                let mut s = ServerConnection::new(server).unwrap();
                do_handshake(&mut c, &mut s).unwrap_or_else(|e| panic!("resumed {what}: {e}"));
                assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed), "{what}");
                assert_eq!(s.handshake_kind(), Some(HandshakeKind::Resumed), "{what}");
                assert_eq!(c.peer_certificates().unwrap(), chain.cert_chain(), "{what}");
                round_trip(&mut c, &mut s);
            }
        }
    }
}

#[test]
fn hello_retry_request_and_hybrid_fallback_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    let named = |side: Side, names: &[NamedGroup]| {
        let mut provider = side.default_provider();
        provider.kx_groups = names
            .iter()
            .map(|n| *side.groups().iter().find(|g| g.name() == *n).unwrap())
            .collect();
        Arc::new(provider)
    };
    for (client_side, server_side) in DIRECTIONS {
        for (client_groups, server_groups, expected_kind, expected_group) in [
            (
                &[NamedGroup::X25519, NamedGroup::secp256r1][..],
                &[NamedGroup::secp256r1][..],
                HandshakeKind::FullWithHelloRetryRequest,
                NamedGroup::secp256r1,
            ),
            (
                &[NamedGroup::X25519, NamedGroup::X25519MLKEM768][..],
                &[NamedGroup::X25519MLKEM768][..],
                HandshakeKind::FullWithHelloRetryRequest,
                NamedGroup::X25519MLKEM768,
            ),
            (
                &[NamedGroup::X25519MLKEM768, NamedGroup::X25519][..],
                &[NamedGroup::X25519][..],
                HandshakeKind::Full,
                NamedGroup::X25519,
            ),
        ] {
            let what =
                format!("{client_side:?}->{server_side:?} {client_groups:?} {server_groups:?}");
            let client = client_config(
                client_side,
                ProtocolVersion::TLSv1_3,
                named(client_side, client_groups),
                &chain,
            );
            let server = server_config(named(server_side, server_groups), &chain);
            let mut client = ClientConnection::new(Arc::new(client), server_name()).unwrap();
            let mut server = ServerConnection::new(Arc::new(server)).unwrap();
            do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(client.handshake_kind(), Some(expected_kind), "{what}");
            assert_eq!(server.handshake_kind(), Some(expected_kind), "{what}");
            assert_eq!(
                client.negotiated_key_exchange_group().unwrap().name(),
                expected_group,
                "{what}"
            );
            round_trip(&mut client, &mut server);
        }
    }
}

/// P-521 keys (generated by `browntls-crypto`) as raw public keys on both
/// sides: each provider signs with its own P-521 implementation and verifies
/// the other's.
#[test]
fn p521_raw_public_keys_both_directions() {
    init_logging();
    let server_key = native_keys::P521RawKey::generate();
    let client_key = native_keys::P521RawKey::generate();
    for (client_side, server_side) in DIRECTIONS {
        for v in VERSIONS {
            let what = format!("{client_side:?}->{server_side:?} {v:?}");
            let client_provider = client_side.provider(None, None, None);
            let server_provider = server_side.provider(None, None, None);
            let client = ClientConfig::builder_with_provider(client_provider.clone())
                .with_protocol_versions(versions(v))
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(
                    server_key.server_verifier(client_side.sig_algs()),
                )
                .with_client_cert_resolver(client_key.resolver(&client_provider));
            let server = ServerConfig::builder_with_provider(server_provider.clone())
                .with_protocol_versions(versions(v))
                .unwrap()
                .with_client_cert_verifier(client_key.client_verifier(server_side.sig_algs()))
                .with_cert_resolver(server_key.resolver(&server_provider));
            let mut client = ClientConnection::new(Arc::new(client), server_name()).unwrap();
            let mut server = ServerConnection::new(Arc::new(server)).unwrap();
            do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(client.protocol_version(), Some(v), "{what}");
            assert_eq!(
                server.peer_certificates().unwrap(),
                [browntls::pki_types::CertificateDer::from(
                    client_key.spki.clone()
                )],
                "{what}"
            );
            round_trip(&mut client, &mut server);
        }
    }
}

#[test]
fn key_update_and_exporters_agree_both_directions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP384);
    for (client_side, server_side) in DIRECTIONS {
        for suite in common_suites()
            .iter()
            .filter(|s| !format!("{:?}", s.suite()).contains("_RSA_"))
        {
            let v = suite.version().version;
            let what = format!("{client_side:?}->{server_side:?} {suite:?}");
            let client = client_config(
                client_side,
                v,
                client_side.provider(Some(suite.suite()), None, None),
                &chain,
            );
            let server = server_config(
                server_side.provider(Some(suite.suite()), None, None),
                &chain,
            );
            let mut client = ClientConnection::new(Arc::new(client), server_name()).unwrap();
            let mut server = ServerConnection::new(Arc::new(server)).unwrap();
            do_handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{what}: {e}"));

            for context in [None, Some(&b"context"[..])] {
                let c = client
                    .export_keying_material([0u8; 64], b"EXPORTER-mixed", context)
                    .unwrap();
                let s = server
                    .export_keying_material([0u8; 64], b"EXPORTER-mixed", context)
                    .unwrap();
                assert_eq!(c, s, "{what} {context:?}");
            }

            if v == ProtocolVersion::TLSv1_3 {
                client.refresh_traffic_keys().unwrap();
                round_trip(&mut client, &mut server);
                server.refresh_traffic_keys().unwrap();
                round_trip(&mut client, &mut server);
            }
            // Large transfers cross many records under each side's AEAD.
            client.set_buffer_limit(None);
            server.set_buffer_limit(None);
            let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                send_and_receive(&mut client, &mut server, &data),
                data,
                "{what}"
            );
            assert_eq!(
                send_and_receive(&mut server, &mut client, &data),
                data,
                "{what}"
            );
        }
    }
}
