//! TLS 1.3 handshakes over the AES-CCM suites of RFC 9846's non-preferred
//! tier, `TLS13_AES_128_CCM_SHA256` and `TLS13_AES_128_CCM_8_SHA256`
//! (RFC 9846 Appendix B.4), between a browntls client and server on the
//! native provider (neither the RustCrypto provider nor rustls/ring
//! implements them):
//!
//! * every signing key type and several groups with each suite, full-size
//!   records in both directions, key updates, client authentication and
//!   resumption; record lengths reflect each suite's tag length;
//! * tampered, truncated, short and oversized records are rejected with the
//!   right alerts, during and after the handshake;
//! * negotiation: default configurations never negotiate CCM_8, and CCM only
//!   when the peers share no AES-GCM or ChaCha20-Poly1305 suite;
//! * kernel TLS secret extraction: CCM keys extract, CCM_8 keys fail cleanly;
//! * the integrity limit (RFC 9147 Appendix B) on forged records that a
//!   server skips while rejecting 0-RTT data.

#![cfg(feature = "native")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::io::{Read, Write};
use std::sync::Arc;

use browntls::crypto::CryptoProvider;
use browntls::server::{ServerSessionMemoryCache, StoresServerSessions};
use browntls::{
    AlertDescription, CipherSuite, ClientConfig, ClientConnection, ConnectionCommon,
    ConnectionTrafficSecrets, Error, HandshakeKind, NamedGroup, PeerIncompatible, ProtocolVersion,
    ServerConfig, ServerConnection, SideData, SupportedCipherSuite, version,
};
use common::*;
use prov::cipher_suite as cs;

/// RFC 9846 §5.1 / §5.2: the largest plaintext fragment and the largest
/// permitted record expansion.
const MAX_FRAGMENT: usize = 1 << 14;
const MAX_EXPANSION: usize = 256;

/// The CCM suites with their tag lengths.
fn ccm_suites() -> [(SupportedCipherSuite, usize); 2] {
    [
        (cs::TLS13_AES_128_CCM_SHA256, 16),
        (cs::TLS13_AES_128_CCM_8_SHA256, 8),
    ]
}

fn provider_with(suites: &[SupportedCipherSuite]) -> Arc<CryptoProvider> {
    let mut provider = prov::default_provider();
    provider.cipher_suites = suites.to_vec();
    provider.kx_groups = prov::ALL_KX_GROUPS.to_vec();
    Arc::new(provider)
}

/// A TLS 1.3 client offering `suites`.
fn client(chain: &Chain, suites: &[SupportedCipherSuite]) -> ClientConfig {
    ClientConfig::builder_with_provider(provider_with(suites))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

/// A server accepting `suites`, TLS 1.2 and 1.3.
fn server(chain: &Chain, suites: &[SupportedCipherSuite]) -> ServerConfig {
    ServerConfig::builder_with_provider(provider_with(suites))
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

/// A connected pair that negotiated `suite`.
fn connected(suite: SupportedCipherSuite) -> (ClientConnection, ServerConnection) {
    let chain = server_chain(KeyType::EcdsaP256);
    let (mut c, mut s) = connect(client(&chain, &[suite]), server(&chain, &[suite]));
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(c.negotiated_cipher_suite(), Some(suite));
    // Deliver the session tickets so later records are application data.
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();
    (c, s)
}

/// `(content type, body length)` of every record in `bytes`.
fn records(mut bytes: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        assert!(bytes.len() >= 5, "partial header");
        let len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        assert_eq!(bytes[1..3], [3, 3], "legacy_record_version");
        out.push((bytes[0], len));
        bytes = &bytes[5 + len..];
    }
    out
}

/// Everything `conn` wants to send.
fn wire_of<D: SideData>(conn: &mut ConnectionCommon<D>) -> Vec<u8> {
    let mut wire = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut wire).unwrap();
    }
    wire
}

/// Hands `bytes` to `conn`, processing records as they arrive; returns the
/// plaintext read meanwhile (read as it arrives, so the received-plaintext
/// limit never stalls the transfer).
fn feed<D: SideData>(conn: &mut ConnectionCommon<D>, mut bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut plaintext = Vec::new();
    while !bytes.is_empty() {
        match conn.read_tls(&mut bytes) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Other => {}
            Err(e) => panic!("read_tls: {e}"),
        }
        conn.process_new_packets()?;
        match conn.reader().read_to_end(&mut plaintext) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("read: {e}"),
        }
    }
    Ok(plaintext)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// Sends `data` from `from` to `to` in full-size records, checks the record
/// lengths for a `tag_len`-byte tag and returns what `to` read.
fn send_full_size<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    to: &mut ConnectionCommon<B>,
    data: &[u8],
    tag_len: usize,
) -> Vec<u8> {
    from.writer().write_all(data).unwrap();
    let wire = wire_of(from);
    let recs = records(&wire);
    assert_eq!(recs.len(), data.len().div_ceil(MAX_FRAGMENT), "{recs:?}");
    for (i, &(typ, len)) in recs.iter().enumerate() {
        assert_eq!(typ, 0x17, "outer type is application_data");
        let fragment = (data.len() - i * MAX_FRAGMENT).min(MAX_FRAGMENT);
        // TLSInnerPlaintext (content || type) plus the tag.
        assert_eq!(len, fragment + 1 + tag_len, "record {i}");
        assert!(len <= MAX_FRAGMENT + MAX_EXPANSION);
    }
    feed(to, &wire).unwrap()
}

// ------------------------------------------------------- handshakes

#[test]
fn every_key_type_and_group_with_full_size_records() {
    init_logging();
    let groups = [
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::X25519MLKEM768,
    ];
    for (suite, tag_len) in ccm_suites() {
        for &key_type in KeyType::SIGNING {
            let chain = server_chain(key_type);
            for group in groups {
                let what = format!("{suite:?} {key_type:?} {group:?}");
                let mut provider = (*provider_with(&[suite])).clone();
                provider.kx_groups.retain(|g| g.name() == group);
                assert_eq!(provider.kx_groups.len(), 1, "{what}");
                let client_config = ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[&version::TLS13])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
                    .with_no_client_auth();
                // The server enables every suite; the client's single
                // offer decides.
                let (mut c, mut s) =
                    connect(client_config, server(&chain, prov::ALL_CIPHER_SUITES));
                do_handshake(&mut c, &mut s).unwrap_or_else(|e| panic!("{what}: {e}"));
                assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_3));
                assert_eq!(c.negotiated_cipher_suite(), Some(suite), "{what}");
                assert_eq!(s.negotiated_cipher_suite(), Some(suite), "{what}");
                assert_eq!(c.negotiated_key_exchange_group().unwrap().name(), group);
                transfer(&mut s, &mut c);
                c.process_new_packets().unwrap();

                let data = pattern(3 * MAX_FRAGMENT + 1000);
                assert_eq!(
                    send_full_size(&mut c, &mut s, &data, tag_len),
                    data,
                    "{what}"
                );
                assert_eq!(
                    send_full_size(&mut s, &mut c, &data, tag_len),
                    data,
                    "{what}"
                );

                // KeyUpdate in both directions keeps the suite working.
                c.refresh_traffic_keys().unwrap();
                assert_eq!(send_and_receive(&mut c, &mut s, b"after c"), b"after c");
                s.refresh_traffic_keys().unwrap();
                assert_eq!(send_and_receive(&mut s, &mut c, b"after s"), b"after s");
                // The client answers the server's update_requested with its
                // own KeyUpdate; deliver it before counting records.
                transfer(&mut c, &mut s);
                s.process_new_packets().unwrap();
                assert_eq!(
                    send_full_size(&mut c, &mut s, &data, tag_len),
                    data,
                    "{what}"
                );
            }
        }
    }
}

#[test]
fn client_auth_and_resumption() {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP384);
    let client_chain = client_chain(KeyType::Ed25519);
    for (suite, _) in ccm_suites() {
        let client_config = Arc::new(
            ClientConfig::builder_with_provider(provider_with(&[suite]))
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
                .with_client_auth_cert(client_chain.cert_chain(), client_chain.private_key())
                .unwrap(),
        );
        let server_config = Arc::new(
            ServerConfig::builder_with_provider(provider_with(&[suite]))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, true))
                .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
                .unwrap(),
        );
        let mut c = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut s = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(s.negotiated_cipher_suite(), Some(suite));
        assert_eq!(s.peer_certificates().unwrap(), client_chain.cert_chain());
        assert_eq!(send_and_receive(&mut c, &mut s, b"ping"), b"ping");
        transfer(&mut s, &mut c);
        c.process_new_packets().unwrap();
        assert!(c.tls13_tickets_received() > 0);

        let mut c = ClientConnection::new(client_config, server_name()).unwrap();
        let mut s = ServerConnection::new(server_config).unwrap();
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(
            c.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "{suite:?}"
        );
        assert_eq!(s.negotiated_cipher_suite(), Some(suite));
        assert_eq!(send_and_receive(&mut s, &mut c, b"pong"), b"pong");
    }
}

#[test]
fn max_fragment_size_accounts_for_the_tag() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for (suite, tag_len) in ccm_suites() {
        let mut client_config = client(&chain, &[suite]);
        client_config.max_fragment_size = Some(512);
        let (mut c, mut s) = connect(client_config, server(&chain, &[suite]));
        do_handshake(&mut c, &mut s).unwrap();
        let data = pattern(5000);
        c.writer().write_all(&data).unwrap();
        let wire = wire_of(&mut c);
        // max_fragment_size counts the header: 507-byte fragments.
        let recs = records(&wire);
        assert_eq!(recs.len(), 5000usize.div_ceil(507));
        assert!(
            recs.iter().all(|&(_, len)| len <= 507 + 1 + tag_len),
            "{suite:?} {recs:?}"
        );
        assert_eq!(recs[0].1, 507 + 1 + tag_len);
        assert_eq!(feed(&mut s, &wire).unwrap(), data);
    }
}

// ------------------------------------------------------- tampering

/// Delivers `wire` to the server, expects `err`, and checks that the client
/// receives the matching fatal alert.
fn expect_server_rejects(
    c: &mut ClientConnection,
    s: &mut ServerConnection,
    wire: &[u8],
    err: Error,
    alert: AlertDescription,
    what: &str,
) {
    assert_eq!(feed(s, wire).unwrap_err(), err, "{what}");
    let alert_wire = wire_of(s);
    assert_eq!(records(&alert_wire).len(), 1, "{what}: one alert record");
    assert_eq!(
        feed(c, &alert_wire).unwrap_err(),
        Error::AlertReceived(alert),
        "{what}"
    );
}

#[test]
fn tampered_records_are_rejected_with_bad_record_mac() {
    init_logging();
    for (suite, tag_len) in ccm_suites() {
        let body_len = 100 + 1 + tag_len;
        // Positions in the record body: first ciphertext byte, the content
        // type byte, the first and last tag bytes.
        for pos in [0, 100, body_len - tag_len, body_len - 1] {
            let (mut c, mut s) = connected(suite);
            c.writer().write_all(&[0x42; 100]).unwrap();
            let mut wire = wire_of(&mut c);
            assert_eq!(records(&wire), [(0x17, body_len)]);
            wire[5 + pos] ^= 0x01;
            expect_server_rejects(
                &mut c,
                &mut s,
                &wire,
                Error::DecryptError,
                AlertDescription::BadRecordMac,
                &format!("{suite:?} flipped body byte {pos}"),
            );
        }

        // Truncating the tag (and the length field with it) changes the
        // additional data and the tag: rejected.
        let (mut c, mut s) = connected(suite);
        c.writer().write_all(b"truncate me").unwrap();
        let mut wire = wire_of(&mut c);
        wire.pop();
        let len = u16::from_be_bytes([wire[3], wire[4]]) - 1;
        wire[3..5].copy_from_slice(&len.to_be_bytes());
        expect_server_rejects(
            &mut c,
            &mut s,
            &wire,
            Error::DecryptError,
            AlertDescription::BadRecordMac,
            &format!("{suite:?} truncated tag"),
        );

        // A record body shorter than the tag cannot be authenticated.
        let (mut c, mut s) = connected(suite);
        let mut short = vec![0x17, 3, 3, 0, (tag_len - 1) as u8];
        short.extend(vec![0u8; tag_len - 1]);
        expect_server_rejects(
            &mut c,
            &mut s,
            &short,
            Error::DecryptError,
            AlertDescription::BadRecordMac,
            &format!("{suite:?} short record"),
        );

        // The largest valid record is 2^14 + 1 + tag bytes (RFC 9846 §5.2);
        // one byte more is a record_overflow.
        let (mut c, mut s) = connected(suite);
        let len = MAX_FRAGMENT + 1 + tag_len + 1;
        let mut oversized = vec![0x17, 3, 3];
        oversized.extend((len as u16).to_be_bytes());
        oversized.extend(vec![0u8; len]);
        expect_server_rejects(
            &mut c,
            &mut s,
            &oversized,
            Error::PeerSentOversizedRecord,
            AlertDescription::RecordOverflow,
            &format!("{suite:?} oversized record"),
        );
    }
}

#[test]
fn tampered_handshake_records_are_rejected() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for (suite, _) in ccm_suites() {
        let (mut c, mut s) = connect(client(&chain, &[suite]), server(&chain, &[suite]));
        transfer(&mut c, &mut s);
        s.process_new_packets().unwrap();
        let mut wire = wire_of(&mut s);
        // ServerHello, ChangeCipherSpec, then the encrypted flight: flip the
        // last byte of the first encrypted record.
        let recs = records(&wire);
        let first_encrypted = recs.iter().position(|&(t, _)| t == 0x17).unwrap();
        let end: usize = recs[..=first_encrypted].iter().map(|&(_, l)| 5 + l).sum();
        wire[end - 1] ^= 0x80;
        assert_eq!(
            feed(&mut c, &wire).unwrap_err(),
            Error::DecryptError,
            "{suite:?}"
        );
        let alert = wire_of(&mut c);
        assert_eq!(
            feed(&mut s, &alert).unwrap_err(),
            Error::AlertReceived(AlertDescription::BadRecordMac)
        );
    }
}

// ------------------------------------------------------- negotiation

/// The negotiated suite between a client offering `client_suites` and a
/// server accepting `server_suites`, or the server's error.
fn negotiate(
    client_suites: &[SupportedCipherSuite],
    server_suites: &[SupportedCipherSuite],
    ignore_client_order: bool,
) -> Result<CipherSuite, Error> {
    let chain = server_chain(KeyType::EcdsaP256);
    let client_config = ClientConfig::builder_with_provider(provider_with(client_suites))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
        .with_no_client_auth();
    let mut server_config = server(&chain, server_suites);
    server_config.ignore_client_order = ignore_client_order;
    let (mut c, mut s) = connect(client_config, server_config);
    match do_handshake_until_error(&mut c, &mut s) {
        (Ok(()), Ok(())) => {
            let suite = s.negotiated_cipher_suite().unwrap().suite();
            assert_eq!(c.negotiated_cipher_suite().unwrap().suite(), suite);
            Ok(suite)
        }
        (_, Err(e)) => Err(e),
        (Err(e), Ok(())) => panic!("client failed alone: {e}"),
    }
}

#[test]
fn default_configurations_never_negotiate_ccm_8() {
    init_logging();
    let defaults = prov::DEFAULT_CIPHER_SUITES;
    assert!(defaults.contains(&cs::TLS13_AES_128_CCM_SHA256));
    assert!(!defaults.contains(&cs::TLS13_AES_128_CCM_8_SHA256));
    assert!(prov::ALL_CIPHER_SUITES.contains(&cs::TLS13_AES_128_CCM_8_SHA256));
    assert_eq!(prov::default_provider().cipher_suites, defaults);

    let ccm_8 = [cs::TLS13_AES_128_CCM_8_SHA256];
    let no_suite = Err(Error::PeerIncompatible(
        PeerIncompatible::NoCipherSuitesInCommon,
    ));
    // A default client does not offer CCM_8 ...
    assert_eq!(negotiate(defaults, &ccm_8, false), no_suite);
    assert_eq!(negotiate(defaults, &ccm_8, true), no_suite);
    // ... and a default server does not accept it.
    assert_eq!(negotiate(&ccm_8, defaults, false), no_suite);
    assert_eq!(negotiate(&ccm_8, defaults, true), no_suite);
    // Defaults on both sides agree on the most preferred suite.
    assert_eq!(
        negotiate(defaults, defaults, false),
        Ok(CipherSuite::TLS13_AES_256_GCM_SHA384)
    );
    // With CCM_8 enabled on both sides it still comes last.
    let all = prov::ALL_CIPHER_SUITES;
    assert_eq!(
        negotiate(all, all, true),
        Ok(CipherSuite::TLS13_AES_256_GCM_SHA384)
    );
    assert_eq!(
        negotiate(
            all,
            &[cs::TLS13_AES_128_CCM_SHA256, cs::TLS13_AES_128_CCM_8_SHA256],
            true
        ),
        Ok(CipherSuite::TLS13_AES_128_CCM_SHA256)
    );
    assert_eq!(
        negotiate(&ccm_8, all, false),
        Ok(CipherSuite::TLS13_AES_128_CCM_8_SHA256)
    );
}

#[test]
fn ccm_is_chosen_only_when_nothing_preferred_is_shared() {
    init_logging();
    let defaults = prov::DEFAULT_CIPHER_SUITES;
    let ccm = cs::TLS13_AES_128_CCM_SHA256;
    let preferred = [
        cs::TLS13_AES_256_GCM_SHA384,
        cs::TLS13_AES_128_GCM_SHA256,
        cs::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    // The default order puts CCM after every preferred TLS 1.3 suite.
    let tls13: Vec<_> = defaults
        .iter()
        .filter(|s| s.tls13().is_some())
        .copied()
        .collect();
    assert_eq!(tls13, [preferred[0], preferred[1], preferred[2], ccm]);

    // Nothing preferred is shared: CCM.
    for ignore_client_order in [false, true] {
        assert_eq!(
            negotiate(defaults, &[ccm], ignore_client_order),
            Ok(CipherSuite::TLS13_AES_128_CCM_SHA256)
        );
        assert_eq!(
            negotiate(&[ccm], defaults, ignore_client_order),
            Ok(CipherSuite::TLS13_AES_128_CCM_SHA256)
        );
    }
    for p in preferred {
        // A default client and a server that also has a preferred suite,
        // in either order of the server's list and either preference rule.
        for server_suites in [[ccm, p], [p, ccm]] {
            assert_eq!(negotiate(defaults, &server_suites, false), Ok(p.suite()));
        }
        assert_eq!(negotiate(defaults, &[p, ccm], true), Ok(p.suite()));
        // A default server preferring its own order picks the preferred
        // suite even when a client lists CCM first.
        assert_eq!(negotiate(&[ccm, p], defaults, true), Ok(p.suite()));
    }
}

// ------------------------------------------------------- kernel TLS secrets

#[test]
fn secret_extraction_maps_ccm_and_refuses_ccm_8() {
    init_logging();
    let chain = server_chain(KeyType::Ed25519);
    for (suite, _) in ccm_suites() {
        let mut client_config = client(&chain, &[suite]);
        client_config.enable_secret_extraction = true;
        let mut server_config = server(&chain, &[suite]);
        server_config.enable_secret_extraction = true;
        let (mut c, mut s) = connect(client_config, server_config);
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(send_and_receive(&mut c, &mut s, b"x"), b"x");
        let (c, s) = (c.dangerous_extract_secrets(), s.dangerous_extract_secrets());
        if suite == cs::TLS13_AES_128_CCM_SHA256 {
            let (c, s) = (c.unwrap(), s.unwrap());
            let bytes = |t: &ConnectionTrafficSecrets| match t {
                ConnectionTrafficSecrets::Aes128Ccm { key, iv } => {
                    (key.as_ref().to_vec(), iv.as_ref().to_vec())
                }
                other => panic!("unexpected {other:?}"),
            };
            assert_eq!(bytes(&c.tx.1), bytes(&s.rx.1));
            assert_eq!(bytes(&c.rx.1), bytes(&s.tx.1));
            assert_eq!(bytes(&c.tx.1).0.len(), 16);
            assert_eq!(bytes(&c.tx.1).1.len(), 12);
            assert_eq!(c.tx.0, s.rx.0);
        } else {
            // No kernel TLS cipher has an 8-byte tag.
            let unsupported = Error::General("operation not supported".into());
            assert_eq!(c.unwrap_err(), unsupported);
            assert_eq!(s.unwrap_err(), unsupported);
        }
    }
}

// ------------------------------------------------------- integrity limit

/// Resumes with 0-RTT data that the server no longer accepts, injecting
/// `forgeries` forged application-data records after the client's first
/// flight. The server skips them (RFC 9846 §4.2.10) while trying the client
/// handshake key on each, as it does on the client's one early-data record.
/// Returns whether the handshake completed.
fn rejected_early_data_with_forgeries(suite: SupportedCipherSuite, forgeries: usize) -> bool {
    let chain = server_chain(KeyType::EcdsaP256);
    let cache: Arc<dyn StoresServerSessions> = ServerSessionMemoryCache::new(8);
    let server_config = |max_early_data_size| {
        let mut config = server(&chain, &[suite]);
        config.max_early_data_size = max_early_data_size;
        config.session_storage = cache.clone();
        Arc::new(config)
    };
    let mut client_config = client(&chain, &[suite]);
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);

    // A ticket that allows early data.
    let mut c = ClientConnection::new(client_config.clone(), server_name()).unwrap();
    let mut s = ServerConnection::new(server_config(1024)).unwrap();
    do_handshake(&mut c, &mut s).unwrap();
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();

    // Early data is now off: the server skips undecryptable records.
    let mut c = ClientConnection::new(client_config, server_name()).unwrap();
    let mut s = ServerConnection::new(server_config(0)).unwrap();
    c.early_data().unwrap().write_all(b"replayable").unwrap();
    let mut wire = wire_of(&mut c);
    for i in 0..forgeries {
        wire.extend([0x17, 3, 3, 0, 24]);
        wire.extend((0..24).map(|j| (i * 31 + j) as u8));
    }
    feed(&mut s, &wire).unwrap();
    for _ in 0..4 {
        transfer(&mut s, &mut c);
        c.process_new_packets().unwrap();
        transfer(&mut c, &mut s);
        s.process_new_packets().unwrap();
    }
    assert!(!c.is_handshaking());
    assert!(!c.is_early_data_accepted());
    !s.is_handshaking()
}

#[test]
fn integrity_limit_bounds_forgeries_skipped_with_rejected_early_data() {
    init_logging();
    // AES-128-CCM-8 tolerates 2^7 failed authentications per key (RFC 9147
    // Appendix B.3). The rejected early-data record is the first; with 126
    // forgeries the genuine Finished is the 128th authentication and is
    // accepted. With 127 the limit is reached first: the client handshake
    // key accepts nothing more, so the handshake cannot complete.
    let ccm_8 = cs::TLS13_AES_128_CCM_8_SHA256;
    assert!(rejected_early_data_with_forgeries(ccm_8, 0));
    assert!(rejected_early_data_with_forgeries(ccm_8, 126));
    assert!(!rejected_early_data_with_forgeries(ccm_8, 127));
    assert!(!rejected_early_data_with_forgeries(ccm_8, 200));
    // AES-128-CCM's limit is 2^23.5 (RFC 9147 Appendix B.2).
    assert!(rejected_early_data_with_forgeries(
        cs::TLS13_AES_128_CCM_SHA256,
        200
    ));
}
