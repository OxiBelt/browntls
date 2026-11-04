//! In-memory handshakes over the RFC 7919 finite-field groups (FFDHE2048 to
//! FFDHE8192), which only the native provider implements.
//!
//! * Every group in TLS 1.3, then a psk_dhe_ke resumption in the same group.
//! * A HelloRetryRequest from the client's preferred group to each FFDHE
//!   group, and the key-exchange hint that avoids it next time.
//! * The non-preferred tier: default configurations never pick FFDHE, while
//!   a server answers an FFDHE key share without a retry.
//! * Invalid shares from either peer (out of range, wrong length) fail with
//!   an `illegal_parameter` alert.
//! * TLS 1.2: FFDHE is neither offered in a TLS 1.2-only ClientHello nor
//!   selected by a TLS 1.2 server (RFC 10015 §3).
//!
//! The shared suites (`tls13_native.rs`) also run every TLS 1.3 suite with
//! every group of `ALL_KX_GROUPS`, these included.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls::client::danger::ServerCertVerifier;
use browntls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use browntls::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, NamedGroup,
    PeerIncompatible, PeerMisbehaved, ProtocolVersion, ServerConfig, ServerConnection,
    SupportedProtocolVersion, version,
};
use common::*;

fn ffdhe_groups() -> [&'static dyn SupportedKxGroup; 5] {
    [
        prov::kx_group::FFDHE2048,
        prov::kx_group::FFDHE3072,
        prov::kx_group::FFDHE4096,
        prov::kx_group::FFDHE6144,
        prov::kx_group::FFDHE8192,
    ]
}

fn is_ffdhe(name: NamedGroup) -> bool {
    ffdhe_groups().iter().any(|g| g.name() == name)
}

/// The prime of an FFDHE group, big-endian.
fn prime(group: &dyn SupportedKxGroup) -> &'static [u8] {
    use browntls_crypto::ffdhe::Group;
    let g = match group.name() {
        NamedGroup::FFDHE2048 => Group::Ffdhe2048,
        NamedGroup::FFDHE3072 => Group::Ffdhe3072,
        NamedGroup::FFDHE4096 => Group::Ffdhe4096,
        NamedGroup::FFDHE6144 => Group::Ffdhe6144,
        NamedGroup::FFDHE8192 => Group::Ffdhe8192,
        other => panic!("not an FFDHE group: {other:?}"),
    };
    g.prime_be()
}

/// The default provider with `groups`. Without a group TLS 1.2 can use, the
/// TLS 1.2 (ECDHE) suites are dropped too: the configuration builders refuse
/// a suite whose key exchange no group serves.
fn provider_with(groups: &[&'static dyn SupportedKxGroup]) -> Arc<CryptoProvider> {
    let mut provider = prov::default_provider();
    provider.kx_groups = groups.to_vec();
    if !groups
        .iter()
        .any(|g| g.usable_for_version(ProtocolVersion::TLSv1_2))
    {
        provider.cipher_suites.retain(|s| s.tls13().is_some());
    }
    Arc::new(provider)
}

fn client_with(
    versions: &[&'static SupportedProtocolVersion],
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

fn server_with(
    versions: &[&'static SupportedProtocolVersion],
    chain: &Chain,
    provider: Arc<CryptoProvider>,
) -> ServerConfig {
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap()
}

static TLS13: &[&SupportedProtocolVersion] = &[&version::TLS13];
/// Every version the build supports.
#[cfg(feature = "tls12")]
static BOTH: &[&SupportedProtocolVersion] = &[&version::TLS13, &version::TLS12];
#[cfg(not(feature = "tls12"))]
static BOTH: &[&SupportedProtocolVersion] = TLS13;
#[cfg(feature = "tls12")]
static TLS12: &[&SupportedProtocolVersion] = &[&version::TLS12];

fn connect(
    client: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(client.clone(), server_name()).unwrap(),
        ServerConnection::new(server.clone()).unwrap(),
    )
}

fn round_trip(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(send_and_receive(client, server, b"ping"), b"ping");
    assert_eq!(send_and_receive(server, client, b"pong"), b"pong");
}

fn assert_group(client: &ClientConnection, server: &ServerConnection, name: NamedGroup) {
    assert_eq!(client.negotiated_key_exchange_group().unwrap().name(), name);
    assert_eq!(server.negotiated_key_exchange_group().unwrap().name(), name);
}

/// The supported_groups a client configuration sends, read back with the
/// server's `Acceptor`.
fn offered_groups(config: ClientConfig) -> Vec<NamedGroup> {
    let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let mut acceptor = browntls::server::Acceptor::default();
    acceptor.read_tls(&mut &hello[..]).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    accepted.client_hello().named_groups().unwrap().to_vec()
}

#[test]
fn every_ffdhe_group_in_tls13_then_resumes() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for group in ffdhe_groups() {
        assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!group.usable_for_version(ProtocolVersion::TLSv1_2));
        let client = Arc::new(client_with(
            TLS13,
            provider_with(&[group]),
            PinnedServerVerifier::new(&chain),
        ));
        // The server has every group, FFDHE last (the defaults stop at
        // FFDHE4096).
        let server = Arc::new(server_with(
            BOTH,
            &chain,
            provider_with(prov::ALL_KX_GROUPS),
        ));
        let (mut c, mut s) = connect(&client, &server);
        do_handshake(&mut c, &mut s).unwrap_or_else(|e| panic!("{group:?}: {e}"));
        assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(s.handshake_kind(), Some(HandshakeKind::Full));
        assert_group(&c, &s, group.name());
        round_trip(&mut c, &mut s);

        // psk_dhe_ke resumption: a fresh exchange in the same group.
        let (mut c, mut s) = connect(&client, &server);
        do_handshake(&mut c, &mut s).unwrap_or_else(|e| panic!("resumed {group:?}: {e}"));
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(s.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_group(&c, &s, group.name());
        round_trip(&mut c, &mut s);
    }
}

#[test]
fn hello_retry_request_into_each_ffdhe_group() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for group in ffdhe_groups() {
        // A client with every group sends a share for its preferred group
        // only; the server takes nothing but `group`.
        let client = Arc::new(client_with(
            TLS13,
            provider_with(prov::ALL_KX_GROUPS),
            PinnedServerVerifier::new(&chain),
        ));
        let server = Arc::new(server_with(BOTH, &chain, provider_with(&[group])));
        let (mut c, mut s) = connect(&client, &server);
        do_handshake(&mut c, &mut s).unwrap_or_else(|e| panic!("{group:?}: {e}"));
        assert_eq!(
            c.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(
            s.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_group(&c, &s, group.name());
        round_trip(&mut c, &mut s);

        // The client remembers the group: against a server that cannot
        // resume its ticket, it now sends the FFDHE share first and needs no
        // retry.
        let other_server = Arc::new(server_with(BOTH, &chain, provider_with(&[group])));
        let (mut c, mut s) = connect(&client, &other_server);
        do_handshake(&mut c, &mut s).unwrap_or_else(|e| panic!("hinted {group:?}: {e}"));
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
        assert_group(&c, &s, group.name());
    }
}

#[test]
fn hello_retry_request_follows_server_preference_among_ffdhe_groups() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP384);
    let client = Arc::new(client_with(
        TLS13,
        provider_with(&[
            prov::kx_group::X25519,
            prov::kx_group::FFDHE2048,
            prov::kx_group::FFDHE8192,
        ]),
        PinnedServerVerifier::new(&chain),
    ));
    let server = Arc::new(server_with(
        TLS13,
        &chain,
        provider_with(&[prov::kx_group::FFDHE8192, prov::kx_group::FFDHE2048]),
    ));
    let (mut c, mut s) = connect(&client, &server);
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(
        c.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_group(&c, &s, NamedGroup::FFDHE8192);
    round_trip(&mut c, &mut s);
}

#[test]
fn ffdhe_is_the_non_preferred_tier() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let defaults: Vec<NamedGroup> = prov::DEFAULT_KX_GROUPS.iter().map(|g| g.name()).collect();
    let all: Vec<NamedGroup> = prov::ALL_KX_GROUPS.iter().map(|g| g.name()).collect();
    let ffdhe: Vec<NamedGroup> = ffdhe_groups().iter().map(|g| g.name()).collect();
    // Last, in increasing size, in both lists; the defaults stop at
    // FFDHE4096 (the larger groups cost too much server time to enable by
    // default).
    assert_eq!(defaults[defaults.len() - 3..], ffdhe[..3]);
    assert_eq!(all[all.len() - 5..], ffdhe[..]);

    // Default client and server: the preferred group, never FFDHE, although
    // the client offers the FFDHE groups in supported_groups.
    let client = Arc::new(client_with(
        BOTH,
        Arc::new(prov::default_provider()),
        PinnedServerVerifier::new(&chain),
    ));
    let server = Arc::new(server_with(
        BOTH,
        &chain,
        Arc::new(prov::default_provider()),
    ));
    let (mut c, mut s) = connect(&client, &server);
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
    assert_group(&c, &s, defaults[0]);
    let offered = offered_groups(client_with(
        BOTH,
        Arc::new(prov::default_provider()),
        PinnedServerVerifier::new(&chain),
    ));
    assert_eq!(offered, defaults);

    // A client whose only key share is FFDHE but which also supports X25519
    // is asked for X25519: the server does not accept a non-preferred share
    // while a preferred group is mutually supported.
    let client = Arc::new(client_with(
        TLS13,
        provider_with(&[prov::kx_group::FFDHE3072, prov::kx_group::X25519]),
        PinnedServerVerifier::new(&chain),
    ));
    let (mut c, mut s) = connect(&client, &server);
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(
        c.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_group(&c, &s, NamedGroup::X25519);
    round_trip(&mut c, &mut s);

    // A client that supports nothing preferred gets its FFDHE share accepted
    // without a retry.
    let client = Arc::new(client_with(
        TLS13,
        provider_with(&[prov::kx_group::FFDHE3072]),
        PinnedServerVerifier::new(&chain),
    ));
    let (mut c, mut s) = connect(&client, &server);
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
    assert_group(&c, &s, NamedGroup::FFDHE3072);
    round_trip(&mut c, &mut s);
}

// ------------------------------------------------------------ invalid shares

/// Wraps a real group but puts `share` on the wire instead of the real
/// public value, as a misbehaving peer would.
#[derive(Debug)]
struct WrongShare {
    inner: &'static dyn SupportedKxGroup,
    share: Vec<u8>,
}

struct WrongShareKx {
    inner: Box<dyn ActiveKeyExchange>,
    share: Vec<u8>,
}

impl SupportedKxGroup for WrongShare {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(WrongShareKx {
            inner: self.inner.start()?,
            share: self.share.clone(),
        }))
    }

    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let mut completed = self.inner.start_and_complete(peer_pub_key)?;
        completed.pub_key = self.share.clone();
        Ok(completed)
    }

    fn name(&self) -> NamedGroup {
        self.inner.name()
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        self.inner.usable_for_version(version)
    }
}

impl ActiveKeyExchange for WrongShareKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        self.inner.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        self.inner.group()
    }
}

/// Shares a peer must reject for `group`: 0, 1, p - 1, p, the largest value
/// of the right length, and values one byte too short or too long.
fn invalid_shares(group: &'static dyn SupportedKxGroup) -> Vec<(&'static str, Vec<u8>)> {
    let p = prime(group);
    let n = p.len();
    let mut one = vec![0u8; n];
    one[n - 1] = 1;
    let mut p_minus_one = p.to_vec();
    p_minus_one[n - 1] -= 1;
    let mut padded_two = vec![0u8; n + 1];
    padded_two[n] = 2;
    let mut short_two = vec![0u8; n - 1];
    short_two[n - 2] = 2;
    vec![
        ("0", vec![0u8; n]),
        ("1", one),
        ("p - 1", p_minus_one),
        ("p", p.to_vec()),
        ("2^(8n) - 1", vec![0xff; n]),
        ("n + 1 bytes", padded_two),
        ("n - 1 bytes", short_two),
    ]
}

fn leak(group: WrongShare) -> &'static dyn SupportedKxGroup {
    Box::leak(Box::new(group))
}

#[test]
fn invalid_client_shares_are_rejected() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for group in [prov::kx_group::FFDHE2048, prov::kx_group::FFDHE6144] {
        let server = Arc::new(server_with(BOTH, &chain, provider_with(&[group])));
        for (what, share) in invalid_shares(group) {
            let bad = leak(WrongShare {
                inner: group,
                share,
            });
            let client = Arc::new(client_with(
                TLS13,
                provider_with(&[bad]),
                PinnedServerVerifier::new(&chain),
            ));
            let (mut c, mut s) = connect(&client, &server);
            let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
            assert_eq!(
                server_res,
                Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)),
                "{group:?} server with a client share of {what}"
            );
            assert_eq!(
                client_res,
                Err(Error::AlertReceived(AlertDescription::IllegalParameter)),
                "{group:?} client after sending {what}"
            );
        }
    }
}

#[test]
fn invalid_server_shares_are_rejected() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for group in [prov::kx_group::FFDHE3072, prov::kx_group::FFDHE8192] {
        let client = Arc::new(client_with(
            TLS13,
            provider_with(&[group]),
            PinnedServerVerifier::new(&chain),
        ));
        for (what, share) in invalid_shares(group) {
            let bad = leak(WrongShare {
                inner: group,
                share,
            });
            let server = Arc::new(server_with(BOTH, &chain, provider_with(&[bad])));
            let (mut c, mut s) = connect(&client, &server);
            let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
            assert_eq!(
                client_res,
                Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)),
                "{group:?} client with a server share of {what}"
            );
            // The client's illegal_parameter alert goes out in plaintext (it
            // has no handshake keys), while the server already reads under
            // its handshake keys, so the server reports the record as
            // undecryptable; either way the handshake fails.
            assert!(
                server_res.is_err(),
                "{group:?} server after sending {what}: {server_res:?}"
            );
        }
    }
}

// ------------------------------------------------------------------- TLS 1.2

#[cfg(feature = "tls12")]
#[test]
fn tls12_client_hello_does_not_offer_ffdhe() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let all = Arc::new({
        let mut p = prov::default_provider();
        p.kx_groups = prov::ALL_KX_GROUPS.to_vec();
        p
    });
    // TLS 1.2 only: just the groups TLS 1.2 can use, FFDHE excluded.
    let tls12_offer = offered_groups(client_with(
        TLS12,
        all.clone(),
        PinnedServerVerifier::new(&chain),
    ));
    let expected: Vec<NamedGroup> = prov::ALL_KX_GROUPS
        .iter()
        .filter(|g| g.usable_for_version(ProtocolVersion::TLSv1_2))
        .map(|g| g.name())
        .collect();
    assert_eq!(tls12_offer, expected);
    assert!(!tls12_offer.iter().any(|g| is_ffdhe(*g)));
    assert!(!expected.is_empty());
    // With TLS 1.3 also offered, the FFDHE groups are listed for TLS 1.3.
    let both_offer = offered_groups(client_with(
        BOTH,
        all.clone(),
        PinnedServerVerifier::new(&chain),
    ));
    assert_eq!(
        both_offer,
        prov::ALL_KX_GROUPS
            .iter()
            .map(|g| g.name())
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_server_never_selects_ffdhe() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let all_groups = provider_with(prov::ALL_KX_GROUPS);
    // The client prefers FFDHE (its first key share is FFDHE2048), but the
    // server only speaks TLS 1.2: it must fall through to an ECDHE group.
    let client = Arc::new(client_with(
        BOTH,
        provider_with(&[
            prov::kx_group::FFDHE2048,
            prov::kx_group::FFDHE8192,
            prov::kx_group::SECP384R1,
        ]),
        PinnedServerVerifier::new(&chain),
    ));
    let server = Arc::new(server_with(TLS12, &chain, all_groups.clone()));
    let (mut c, mut s) = connect(&client, &server);
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(s.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_group(&c, &s, NamedGroup::secp384r1);
    round_trip(&mut c, &mut s);

    // Both peers support FFDHE2048, but it is the only group they share
    // and the server only speaks TLS 1.2: no group can be selected.
    let client = Arc::new(client_with(
        BOTH,
        provider_with(&[prov::kx_group::FFDHE2048, prov::kx_group::SECP256R1]),
        PinnedServerVerifier::new(&chain),
    ));
    let server = Arc::new(server_with(
        TLS12,
        &chain,
        provider_with(&[prov::kx_group::FFDHE2048, prov::kx_group::X25519]),
    ));
    let (mut c, mut s) = connect(&client, &server);
    let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
    assert_eq!(
        server_res,
        Err(Error::PeerIncompatible(
            PeerIncompatible::NoKxGroupsInCommon
        ))
    );
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );
    assert!(s.negotiated_key_exchange_group().is_none());
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_configurations_need_an_ecdhe_group() {
    // FFDHE groups serve no TLS 1.2 suite, so the builders refuse a TLS 1.2
    // configuration whose only groups are FFDHE: with the TLS 1.2 suites
    // (no group for their ECDHE key exchange) or without them (no usable
    // suite for TLS 1.2).
    let mut with_tls12_suites = prov::default_provider();
    with_tls12_suites.kx_groups = ffdhe_groups().to_vec();
    for provider in [Arc::new(with_tls12_suites), provider_with(&ffdhe_groups())] {
        assert!(
            ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(TLS12)
                .is_err()
        );
        assert!(
            ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(TLS12)
                .is_err()
        );
    }
}

/// A TLS 1.2-only client whose groups are all TLS 1.3-only has nothing to put
/// in supported_groups; it fails locally instead of sending an empty list
/// (RFC 9846 §4.3.7 requires at least one entry).
#[cfg(feature = "tls12")]
#[test]
fn tls12_client_without_usable_groups_fails_locally() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut provider = prov::default_provider();
    provider.kx_groups = vec![prov::kx_group::MLKEM768];
    // The builder accepts it: ML-KEM's code point maps to an ECDHE-style
    // key exchange that the TLS 1.2 suites name.
    let client = Arc::new(client_with(
        TLS12,
        Arc::new(provider),
        PinnedServerVerifier::new(&chain),
    ));
    let err = ClientConnection::new(client, server_name()).unwrap_err();
    assert!(
        matches!(&err, Error::General(msg) if msg.contains("no key exchange group")),
        "{err:?}"
    );
}
