// Shared cases, included by `tests/tls13_only_policy.rs` (RustCrypto
// provider) and `tests/tls13_only_policy_native.rs` (native provider).
// Provider items are reached through the including target's `prov` module.
//
// What a configuration that enables TLS 1.3 only offers, negotiates and
// refuses (the policy RFC 9852 §4 asks of new protocols that use TLS), and
// that the configurations with TLS 1.2 go on working as before.

use std::sync::Arc;

#[cfg(feature = "tls12")]
use browntls_core::server::Acceptor;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, PeerIncompatible,
    ProtocolVersion, ServerConfig, ServerConnection, SupportedProtocolVersion, version,
};
use common::hello_wire::*;
use common::*;

/// `supported_versions` (RFC 9846 §4.2.1).
const EXT_SUPPORTED_VERSIONS: u16 = 43;
/// `pre_shared_key` (RFC 9846 §4.2.11).
#[cfg(feature = "tls12")]
const EXT_PRE_SHARED_KEY: u16 = 41;
/// TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746 §3.3).
const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;
/// The extensions only TLS 1.2 gives a meaning to: `ec_point_formats`,
/// `encrypt_then_mac`, `extended_master_secret`, `session_ticket` and
/// `renegotiation_info`, and the two of RFC 6066 this library can send.
const TLS12_ONLY_EXTENSIONS: [u16; 7] = [
    11,
    22,
    23,
    35,
    0xff01,
    EXT_CLIENT_CERTIFICATE_URL,
    EXT_TRUSTED_CA_KEYS,
];

/// The version lists an application can choose between.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Policy {
    /// Exactly TLS 1.3.
    Tls13Only,
    /// The library's default list.
    Default,
    /// Exactly TLS 1.2.
    #[cfg(feature = "tls12")]
    Tls12Only,
}

impl Policy {
    fn versions(self) -> &'static [&'static SupportedProtocolVersion] {
        static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&version::TLS13];
        #[cfg(feature = "tls12")]
        static TLS12_ONLY: &[&SupportedProtocolVersion] = &[&version::TLS12];
        match self {
            Self::Tls13Only => TLS13_ONLY,
            Self::Default => browntls_core::DEFAULT_VERSIONS,
            #[cfg(feature = "tls12")]
            Self::Tls12Only => TLS12_ONLY,
        }
    }
}

fn policy_client(chain: &Chain, policy: Policy) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(policy.versions())
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn policy_server(chain: &Chain, policy: Policy) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(policy.versions())
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.session_storage = browntls_core::server::ServerSessionMemoryCache::new(16);
    config
}

fn client_conn(config: ClientConfig) -> ClientConnection {
    ClientConnection::new(Arc::new(config), server_name()).unwrap()
}

fn server_conn(config: ServerConfig) -> ServerConnection {
    ServerConnection::new(Arc::new(config)).unwrap()
}

/// The ClientHello a client with `policy` sends.
fn client_hello(chain: &Chain, policy: Policy) -> Vec<u8> {
    take_flight(&mut client_conn(policy_client(chain, policy)))
}

/// What a server does with `hello`: its result and the fatal alert it
/// answers with, if any.
#[cfg(feature = "tls12")]
fn serve(config: ServerConfig, hello: &[u8]) -> (Result<(), Error>, Option<AlertDescription>) {
    let mut server = server_conn(config);
    give(&mut server, hello);
    let result = server.process_new_packets().map(|_| ());
    let alert = fatal_alert(&take_flight(&mut server)).map(AlertDescription::from);
    (result, alert)
}

/// What a client that has sent its ClientHello does with `flight`.
#[cfg(feature = "tls12")]
fn answer(config: ClientConfig, flight: &[u8]) -> (Result<(), Error>, Option<AlertDescription>) {
    let mut client = client_conn(config);
    take_flight(&mut client);
    give(&mut client, flight);
    let result = client.process_new_packets().map(|_| ());
    let alert = fatal_alert(&take_flight(&mut client)).map(AlertDescription::from);
    (result, alert)
}

/// The body of the hello's `supported_versions` extension.
fn supported_versions(hello: &[u8]) -> Option<Vec<u8>> {
    hello_extensions(hello, true)
        .into_iter()
        .find(|(typ, _)| *typ == EXT_SUPPORTED_VERSIONS)
        .map(|(_, body)| body)
}

// ------------------------------------------------------------ what is sent

#[test]
fn a_tls13_only_client_offers_nothing_of_tls12() {
    let chain = server_chain(KeyType::Ed25519);
    let hello = client_hello(&chain, Policy::Tls13Only);

    // RFC 9846 §4.1.2: legacy_version stays 0x0303; the offer is the
    // extension's, and it names TLS 1.3 alone.
    assert_eq!(hello_legacy_version(&hello), 0x0303);
    assert_eq!(supported_versions(&hello).unwrap(), [2, 0x03, 0x04]);

    // The provider's TLS 1.2 suites are left out, and so is the signalling
    // value of RFC 5746 §3.3, which is about renegotiation in TLS 1.2 and
    // below: the list is the provider's TLS 1.3 suites, in its order.
    let suites = client_hello_cipher_suites(&hello);
    let offered = provider()
        .cipher_suites
        .iter()
        .filter(|suite| suite.version() == &version::TLS13)
        .map(|suite| u16::from(suite.suite()))
        .collect::<Vec<_>>();
    assert!(!offered.is_empty());
    assert!(offered.iter().all(|suite| suite >> 8 == 0x13));
    assert_eq!(suites, offered);
    assert!(!suites.contains(&TLS_EMPTY_RENEGOTIATION_INFO_SCSV));

    let extensions = hello_extension_types(&hello, true);
    for typ in TLS12_ONLY_EXTENSIONS {
        assert!(
            !extensions.contains(&typ),
            "extension {typ} in {extensions:?}"
        );
    }
}

#[cfg(feature = "tls12")]
#[test]
fn the_default_client_still_offers_tls12_after_tls13() {
    let chain = server_chain(KeyType::Ed25519);
    let hello = client_hello(&chain, Policy::Default);
    // TLS 1.3 first: it is the version a server with both takes.
    assert_eq!(
        supported_versions(&hello).unwrap(),
        [4, 0x03, 0x04, 0x03, 0x03]
    );
    let suites = client_hello_cipher_suites(&hello);
    assert!(suites.iter().any(|suite| suite >> 8 == 0x13));
    assert!(
        suites.iter().any(|suite| suite >> 8 == 0xc0),
        "{suites:04x?}"
    );
    // What the TLS 1.3-only hello must not carry is something this one
    // does carry, so that check can fail.
    assert!(hello_extension_types(&hello, true).contains(&23));

    let hello = client_hello(&chain, Policy::Tls12Only);
    assert_eq!(supported_versions(&hello).unwrap(), [2, 0x03, 0x03]);
    let suites = client_hello_cipher_suites(&hello);
    assert!(
        suites.iter().all(|suite| suite >> 8 != 0x13),
        "{suites:04x?}"
    );
}

// -------------------------------------------------- what is negotiated

/// The version a client and a server with these policies agree on.
fn common_version(client: Policy, server: Policy) -> Option<ProtocolVersion> {
    let has = |policy: Policy, version: ProtocolVersion| {
        policy
            .versions()
            .iter()
            .any(|supported| supported.version == version)
    };
    [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
        .into_iter()
        .find(|version| has(client, *version) && has(server, *version))
}

#[test]
fn every_pair_of_policies_negotiates_its_highest_common_version_or_fails() {
    init_logging();
    let policies = [
        Policy::Tls13Only,
        Policy::Default,
        #[cfg(feature = "tls12")]
        Policy::Tls12Only,
    ];
    let chain = server_chain(KeyType::EcdsaP256);
    for client_policy in policies {
        for server_policy in policies {
            let case = format!("client {client_policy:?}, server {server_policy:?}");
            let mut client = client_conn(policy_client(&chain, client_policy));
            let mut server = server_conn(policy_server(&chain, server_policy));
            let Some(expected) = common_version(client_policy, server_policy) else {
                // No version in common. The server refuses the hello, in
                // either direction, and tells the client why.
                let (client_res, server_res) = do_handshake_until_error(&mut client, &mut server);
                assert_eq!(
                    server_res,
                    Err(PeerIncompatible::Tls12NotOfferedOrEnabled.into()),
                    "{case}"
                );
                assert_eq!(
                    client_res,
                    Err(Error::AlertReceived(AlertDescription::ProtocolVersion)),
                    "{case}"
                );
                assert_eq!(client.protocol_version(), None, "{case}");
                assert_eq!(server.protocol_version(), None, "{case}");
                continue;
            };

            do_handshake(&mut client, &mut server).unwrap();
            assert_eq!(client.protocol_version(), Some(expected), "{case}");
            assert_eq!(server.protocol_version(), Some(expected), "{case}");
            let suite = client.negotiated_cipher_suite().unwrap();
            assert_eq!(suite.version().version, expected, "{case}");
            assert_eq!(server.negotiated_cipher_suite(), Some(suite), "{case}");
            assert_eq!(
                send_and_receive(&mut client, &mut server, b"ping"),
                b"ping",
                "{case}"
            );
            assert_eq!(
                send_and_receive(&mut server, &mut client, b"pong"),
                b"pong",
                "{case}"
            );
        }
    }
}

#[test]
fn tls13_only_takes_the_first_suite_and_group_of_the_provider() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = client_conn(policy_client(&chain, Policy::Tls13Only));
    let mut server = server_conn(policy_server(&chain, Policy::Tls13Only));
    do_handshake(&mut client, &mut server).unwrap();

    let provider = provider();
    let first_suite = provider
        .cipher_suites
        .iter()
        .find(|suite| suite.version() == &version::TLS13)
        .unwrap();
    assert_eq!(client.negotiated_cipher_suite(), Some(*first_suite));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        provider.kx_groups[0].name()
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}

// ---------------------------------------------- what a server refuses

/// A ClientHello as a client older than TLS 1.3 sends it: TLS 1.2 in
/// `legacy_version` and no `supported_versions`.
#[cfg(feature = "tls12")]
fn hello_without_supported_versions(chain: &Chain) -> Vec<u8> {
    let mut hello = client_hello(chain, Policy::Tls12Only);
    assert!(remove_hello_extension(
        &mut hello,
        true,
        EXT_SUPPORTED_VERSIONS
    ));
    assert_eq!(supported_versions(&hello), None);
    hello
}

#[cfg(feature = "tls12")]
#[test]
fn a_tls13_only_server_refuses_a_hello_without_supported_versions() {
    let chain = server_chain(KeyType::Ed25519);
    let hello = hello_without_supported_versions(&chain);

    let (result, alert) = serve(policy_server(&chain, Policy::Tls13Only), &hello);
    assert_eq!(
        result,
        Err(PeerIncompatible::SupportedVersionsExtensionRequired.into())
    );
    assert_eq!(alert, Some(AlertDescription::ProtocolVersion));

    // The same hello is a TLS 1.2 offer to a server that has TLS 1.2.
    for policy in [Policy::Default, Policy::Tls12Only] {
        let (result, alert) = serve(policy_server(&chain, policy), &hello);
        assert_eq!(result, Ok(()), "{policy:?}");
        assert_eq!(alert, None, "{policy:?}");
    }
}

#[cfg(feature = "tls12")]
#[test]
fn no_server_accepts_a_version_below_tls12() {
    let chain = server_chain(KeyType::Ed25519);
    for legacy_version in [0x0302, 0x0301, 0x0300] {
        let mut hello = hello_without_supported_versions(&chain);
        set_hello_legacy_version(&mut hello, legacy_version);
        for policy in [Policy::Tls13Only, Policy::Default, Policy::Tls12Only] {
            let (result, alert) = serve(policy_server(&chain, policy), &hello);
            assert_eq!(
                result,
                Err(PeerIncompatible::Tls12NotOffered.into()),
                "{legacy_version:04x} {policy:?}"
            );
            assert_eq!(alert, Some(AlertDescription::ProtocolVersion));
        }
    }
}

/// TLS_FALLBACK_SCSV (RFC 7507 §3).
#[cfg(feature = "tls12")]
const TLS_FALLBACK_SCSV: u16 = 0x5600;

#[cfg(feature = "tls12")]
#[test]
fn a_tls13_only_server_answers_a_fallback_probe_with_protocol_version() {
    let chain = server_chain(KeyType::Ed25519);
    // A client that fell back to TLS 1.2 says so with the signalling suite.
    let mut hello = client_hello(&chain, Policy::Tls12Only);
    add_client_hello_cipher_suite(&mut hello, TLS_FALLBACK_SCSV);
    assert!(client_hello_cipher_suites(&hello).contains(&TLS_FALLBACK_SCSV));

    // A server with both versions can do better than the client asks for
    // and says so (RFC 7507 §3).
    let (result, alert) = serve(policy_server(&chain, Policy::Default), &hello);
    assert!(result.is_err());
    assert_eq!(alert, Some(AlertDescription::InappropriateFallback));

    // A TLS 1.3-only server has no TLS 1.2 to fall back to: the version
    // check comes first and the answer is the same as without the suite.
    let (result, alert) = serve(policy_server(&chain, Policy::Tls13Only), &hello);
    assert_eq!(
        result,
        Err(PeerIncompatible::Tls12NotOfferedOrEnabled.into())
    );
    assert_eq!(alert, Some(AlertDescription::ProtocolVersion));

    // A TLS 1.2-only server is at its highest version: no fallback.
    let (result, alert) = serve(policy_server(&chain, Policy::Tls12Only), &hello);
    assert_eq!(result, Ok(()));
    assert_eq!(alert, None);
}

#[cfg(feature = "tls12")]
#[test]
fn an_acceptor_applies_the_policy_of_the_configuration_it_is_given() {
    let chain = server_chain(KeyType::Ed25519);
    let hello = client_hello(&chain, Policy::Tls12Only);
    let accept = || {
        let mut acceptor = Acceptor::default();
        acceptor.read_tls(&mut &hello[..]).unwrap();
        acceptor.accept().unwrap().expect("ClientHello complete")
    };

    // The acceptor itself has no version policy: it hands out the hello.
    let (error, mut alert) = accept()
        .into_connection(Arc::new(policy_server(&chain, Policy::Tls13Only)))
        .unwrap_err();
    assert_eq!(error, PeerIncompatible::Tls12NotOfferedOrEnabled.into());
    let mut sent = Vec::new();
    alert.write_all(&mut sent).unwrap();
    assert_eq!(
        fatal_alert(&sent).map(AlertDescription::from),
        Some(AlertDescription::ProtocolVersion)
    );

    // Another configuration for the same hello has its own policy, so an
    // application that chooses per hello must give each one TLS 1.3 only.
    let server = accept()
        .into_connection(Arc::new(policy_server(&chain, Policy::Default)))
        .map_err(|(error, _)| error)
        .unwrap();
    assert!(server.wants_write());
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_2));
}

// ---------------------------------------------- what a client refuses

/// The ServerHello a server with `server` sends a TLS 1.2-only client, in a
/// record of its own.
#[cfg(feature = "tls12")]
fn tls12_server_hello(chain: &Chain, server: Policy) -> Vec<u8> {
    let mut server = server_conn(policy_server(chain, server));
    give(&mut server, &client_hello(chain, Policy::Tls12Only));
    server.process_new_packets().unwrap();
    let hello = first_handshake_message(&take_flight(&mut server));
    assert_eq!(hello[5], 2, "a ServerHello");
    assert_eq!(hello_legacy_version(&hello), 0x0303);
    assert!(!hello_extension_types(&hello, false).contains(&EXT_SUPPORTED_VERSIONS));
    hello
}

/// Whether the ServerHello's random ends with the TLS 1.2 downgrade
/// sentinel (RFC 9846 §4.1.3).
#[cfg(feature = "tls12")]
fn has_downgrade_sentinel(server_hello: &[u8]) -> bool {
    server_hello[11 + 24..11 + 32] == *b"DOWNGRD\x01"
}

#[cfg(feature = "tls12")]
#[test]
fn a_tls13_only_client_refuses_a_tls12_server_hello() {
    let chain = server_chain(KeyType::Ed25519);
    // A server that ignores the offer and answers in TLS 1.2 anyway: with
    // the sentinel (it has TLS 1.3 too) and without it.
    for server in [Policy::Tls12Only, Policy::Default] {
        let server_hello = tls12_server_hello(&chain, server);
        let (result, alert) = answer(policy_client(&chain, Policy::Tls13Only), &server_hello);
        assert_eq!(
            result,
            Err(PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig.into()),
            "{server:?}"
        );
        assert_eq!(alert, Some(AlertDescription::ProtocolVersion), "{server:?}");
    }
}

#[cfg(feature = "tls12")]
#[test]
fn a_client_with_both_versions_refuses_a_downgrade_to_tls12() {
    use browntls_core::PeerMisbehaved;

    let chain = server_chain(KeyType::Ed25519);
    // A server with both versions that negotiates TLS 1.2 marks its random.
    // A client that offered TLS 1.3 and sees the mark knows that somebody
    // took TLS 1.3 out of its hello (RFC 9846 §4.1.3).
    let marked = tls12_server_hello(&chain, Policy::Default);
    assert!(has_downgrade_sentinel(&marked));
    let (result, alert) = answer(policy_client(&chain, Policy::Default), &marked);
    assert_eq!(
        result,
        Err(PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported.into())
    );
    assert_eq!(alert, Some(AlertDescription::IllegalParameter));

    // A client that never offered TLS 1.3 was not downgraded.
    let (result, alert) = answer(policy_client(&chain, Policy::Tls12Only), &marked);
    assert_eq!(result, Ok(()));
    assert_eq!(alert, None);

    // A TLS 1.2-only server leaves the random alone, and the client with
    // both versions goes on in TLS 1.2: the compatibility that stays.
    let plain = tls12_server_hello(&chain, Policy::Tls12Only);
    assert!(!has_downgrade_sentinel(&plain));
    let (result, alert) = answer(policy_client(&chain, Policy::Default), &plain);
    assert_eq!(result, Ok(()));
    assert_eq!(alert, None);
}

// ------------------------------------------------------------- sessions

#[cfg(feature = "tls12")]
#[test]
fn a_tls13_only_client_does_not_resume_a_tls12_session_of_a_shared_store() {
    use browntls_core::client::{ClientSessionMemoryCache, Resumption};

    let chain = server_chain(KeyType::EcdsaP256);
    let store = Arc::new(ClientSessionMemoryCache::new(8));
    let with_store = |policy: Policy| {
        let mut config = policy_client(&chain, policy);
        config.resumption = Resumption::store(store.clone());
        Arc::new(config)
    };
    let server_config = Arc::new(policy_server(&chain, Policy::Default));
    let connect = |config: &Arc<ClientConfig>| {
        let mut client = ClientConnection::new(config.clone(), server_name()).unwrap();
        let hello = take_flight(&mut client);
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        give(&mut server, &hello);
        server.process_new_packets().unwrap();
        do_handshake(&mut client, &mut server).unwrap();
        // The TLS 1.3 tickets follow the handshake.
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        (client, hello)
    };

    // A TLS 1.2 session lands in the store, and a TLS 1.2 client resumes it.
    let tls12 = with_store(Policy::Tls12Only);
    let (first, _) = connect(&tls12);
    assert_eq!(first.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(first.handshake_kind(), Some(HandshakeKind::Full));
    let (resumed, resuming_hello) = connect(&tls12);
    assert_eq!(resumed.handshake_kind(), Some(HandshakeKind::Resumed));
    let session_id = hello_session_id(&resuming_hello).to_vec();
    assert!(!session_id.is_empty());

    // The TLS 1.3-only client of the same store leaves that session alone:
    // its hello carries neither the session's ID nor a ticket, and the
    // handshake is a full TLS 1.3 one.
    let tls13 = with_store(Policy::Tls13Only);
    let (client, hello) = connect(&tls13);
    assert_ne!(hello_session_id(&hello), session_id);
    let extensions = hello_extension_types(&hello, true);
    assert!(!extensions.contains(&35), "{extensions:?}");
    assert!(!extensions.contains(&EXT_PRE_SHARED_KEY), "{extensions:?}");
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));

    // Its own next connection resumes in TLS 1.3, with the ticket it got.
    let (client, hello) = connect(&tls13);
    assert!(hello_extension_types(&hello, true).contains(&EXT_PRE_SHARED_KEY));
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));

    // The TLS 1.2 session is still there for the client it belongs to.
    let (resumed, _) = connect(&tls12);
    assert_eq!(resumed.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(resumed.handshake_kind(), Some(HandshakeKind::Resumed));
}

// ----------------------------------------------------------- the builder

#[cfg(feature = "tls12")]
#[test]
fn tls13_only_needs_a_tls13_suite() {
    let mut tls12_suites = prov::default_provider();
    tls12_suites
        .cipher_suites
        .retain(|suite| suite.version() == &version::TLS12);
    assert!(!tls12_suites.cipher_suites.is_empty());
    let tls12_suites = Arc::new(tls12_suites);

    // TLS 1.3 only with nothing to speak it in is refused when the
    // configuration is built, on either side, rather than falling back.
    let error = ClientConfig::builder_with_provider(tls12_suites.clone())
        .with_protocol_versions(&[&version::TLS13])
        .map(|_| ())
        .unwrap_err();
    assert_eq!(
        error,
        Error::General("no usable cipher suites configured".into())
    );
    let error = ServerConfig::builder_with_provider(tls12_suites.clone())
        .with_protocol_versions(&[&version::TLS13])
        .map(|_| ())
        .unwrap_err();
    assert_eq!(
        error,
        Error::General("no usable cipher suites configured".into())
    );

    // The same provider serves a TLS 1.2 list.
    ClientConfig::builder_with_provider(tls12_suites)
        .with_protocol_versions(&[&version::TLS12])
        .unwrap();
}

include!("tls13_only_policy/preset.rs");
