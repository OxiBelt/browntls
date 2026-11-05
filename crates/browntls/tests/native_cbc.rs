//! TLS 1.2 CBC cipher suites (RFC 5246 §6.2.3.2, RFC 5289, RFC 8422) and
//! the `encrypt_then_mac` extension (RFC 7366), native provider only.
//!
//! * Every CBC suite completes a handshake with Encrypt-then-MAC and with
//!   MAC-then-encrypt (when both sides allow it), for ECDSA, Ed25519 and RSA
//!   keys, and carries application data of every size up to the record
//!   limit in both directions.
//! * CBC suites are the non-preferred tier: a server prefers any shared AEAD
//!   suite whatever the client's order.
//!
//! A browntls client offers `encrypt_then_mac` whenever a CBC suite is
//! enabled and a browntls server always acknowledges it for a CBC suite, so
//! the refusals of RFC 9325 §4.2 (a server not selecting a CBC suite for a
//! client without the extension, a client refusing a CBC suite selected
//! without the acknowledgement) and the MAC-then-encrypt opt-in are
//! exercised against OpenSSL with Encrypt-then-MAC disabled, in
//! `openssl_interop.rs`.
//! * Session resumption (session IDs and tickets) with CBC suites.
//! * `dangerous_extract_secrets` has no kernel representation for CBC.

#![cfg(all(feature = "native", feature = "tls12"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/native.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls::client::{Resumption, Tls12Resumption};
use browntls::crypto::CryptoProvider;
use browntls::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, ServerConfig,
    ServerConnection, SupportedCipherSuite, version,
};
use common::*;

/// The CBC suites a `key_type` server can use, in provider order.
fn cbc_suites(key_type: KeyType) -> Vec<SupportedCipherSuite> {
    let marker = match key_type {
        KeyType::Rsa2048 => "_RSA_",
        _ => "_ECDSA_",
    };
    prov::ALL_CIPHER_SUITES
        .iter()
        .copied()
        .filter(|s| s.is_tls12_block_cipher())
        .filter(|s| format!("{:?}", s.suite()).contains(marker))
        .collect()
}

/// The AEAD TLS 1.2 suites a `key_type` server can use.
fn aead_suites(key_type: KeyType) -> Vec<SupportedCipherSuite> {
    let marker = match key_type {
        KeyType::Rsa2048 => "_RSA_",
        _ => "_ECDSA_",
    };
    prov::ALL_CIPHER_SUITES
        .iter()
        .copied()
        .filter(|s| s.tls13().is_none() && !s.is_tls12_block_cipher())
        .filter(|s| format!("{:?}", s.suite()).contains(marker))
        .collect()
}

fn provider_with(suites: &[SupportedCipherSuite]) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: suites.to_vec(),
        ..prov::default_provider()
    })
}

fn client(chain: &Chain, suites: &[SupportedCipherSuite], allow_mte: bool) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider_with(suites))
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth();
    config.allow_mac_then_encrypt = allow_mte;
    config
}

fn server(chain: &Chain, suites: &[SupportedCipherSuite], allow_mte: bool) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider_with(suites))
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.allow_mac_then_encrypt = allow_mte;
    config
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

/// Sends `len` bytes each way and checks they arrive intact.
fn exchange(client: &mut ClientConnection, server: &mut ServerConnection, len: usize) {
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    assert_eq!(send_and_receive(client, server, &data), data, "len {len}");
    assert_eq!(send_and_receive(server, client, &data), data, "len {len}");
}

#[test]
fn every_cbc_suite_handshakes_and_carries_data() {
    for key_type in KeyType::SIGNING {
        let chain = server_chain(*key_type);
        for suite in cbc_suites(*key_type) {
            for allow_mte in [false, true] {
                // `allow_mte` on both sides does not disable the extension:
                // the handshake still negotiates Encrypt-then-MAC.
                let (mut c, mut s) = connect(
                    client(&chain, &[suite], allow_mte),
                    server(&chain, &[suite], allow_mte),
                );
                do_handshake(&mut c, &mut s).unwrap_or_else(|e| {
                    panic!("{key_type:?} {:?} mte={allow_mte}: {e}", suite.suite())
                });
                assert_eq!(c.negotiated_cipher_suite(), Some(suite));
                assert_eq!(s.negotiated_cipher_suite(), Some(suite));
                assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
                for len in [0, 1, 15, 16, 17, 255, 256, 1024, 16_383, 16_384, 40_000] {
                    exchange(&mut c, &mut s, len);
                }
            }
        }
    }
}

#[test]
fn server_prefers_aead_over_cbc_whatever_the_client_order() {
    for key_type in [KeyType::EcdsaP256, KeyType::Rsa2048] {
        let chain = server_chain(key_type);
        let cbc = cbc_suites(key_type);
        let aead = aead_suites(key_type);
        let mut client_suites = cbc.clone();
        client_suites.extend(aead.iter().copied());
        let mut server_suites = cbc.clone();
        server_suites.extend(aead.iter().copied());
        let (mut c, mut s) = connect(
            client(&chain, &client_suites, false),
            server(&chain, &server_suites, false),
        );
        do_handshake(&mut c, &mut s).unwrap();
        let negotiated = s.negotiated_cipher_suite().unwrap();
        assert!(
            !negotiated.is_tls12_block_cipher(),
            "{key_type:?}: negotiated {negotiated:?}"
        );
        // The client's first AEAD suite wins within the preferred tier.
        assert_eq!(negotiated, aead[0]);
    }
}

#[test]
fn server_without_shared_aead_falls_back_to_cbc() {
    let chain = server_chain(KeyType::EcdsaP384);
    let cbc = cbc_suites(KeyType::EcdsaP384);
    let mut server_suites = aead_suites(KeyType::EcdsaP384);
    server_suites.extend(cbc.iter().copied());
    let (mut c, mut s) = connect(
        client(&chain, &cbc[1..2], false),
        server(&chain, &server_suites, false),
    );
    do_handshake(&mut c, &mut s).unwrap();
    assert_eq!(s.negotiated_cipher_suite(), Some(cbc[1]));
    exchange(&mut c, &mut s, 3000);
}

#[test]
fn cbc_sessions_resume_with_ids_and_tickets() {
    let chain = server_chain(KeyType::EcdsaP256);
    let suite = cbc_suites(KeyType::EcdsaP256)[0];
    for tickets in [false, true] {
        let mut client_config = client(&chain, &[suite], false);
        client_config.resumption =
            Resumption::in_memory_sessions(4).tls12_resumption(Tls12Resumption::SessionIdOrTickets);
        let client_config = Arc::new(client_config);
        let mut server_config = server(&chain, &[suite], false);
        if tickets {
            server_config.ticketer = prov::Ticketer::new().unwrap();
        }
        let server_config = Arc::new(server_config);

        let mut c = ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut s = ServerConnection::new(server_config.clone()).unwrap();
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
        exchange(&mut c, &mut s, 100);

        let mut c = ClientConnection::new(client_config, server_name()).unwrap();
        let mut s = ServerConnection::new(server_config).unwrap();
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(
            c.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "tickets={tickets}"
        );
        assert_eq!(s.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(c.negotiated_cipher_suite(), Some(suite));
        exchange(&mut c, &mut s, 5000);
    }
}

#[test]
fn cbc_secrets_cannot_be_extracted() {
    let chain = server_chain(KeyType::EcdsaP256);
    let suite = cbc_suites(KeyType::EcdsaP256)[0];
    let mut client_config = client(&chain, &[suite], false);
    client_config.enable_secret_extraction = true;
    let mut server_config = server(&chain, &[suite], false);
    server_config.enable_secret_extraction = true;
    let (mut c, mut s) = connect(client_config, server_config);
    do_handshake(&mut c, &mut s).unwrap();
    assert!(c.dangerous_extract_secrets().is_err());
    assert!(s.dangerous_extract_secrets().is_err());
}

#[test]
fn corrupted_cbc_record_is_fatal() {
    let chain = server_chain(KeyType::Rsa2048);
    let suite = cbc_suites(KeyType::Rsa2048)[0];
    let (mut c, mut s) = connect(
        client(&chain, &[suite], false),
        server(&chain, &[suite], false),
    );
    do_handshake(&mut c, &mut s).unwrap();

    use std::io::Write;
    c.writer().write_all(b"hello").unwrap();
    let mut wire = Vec::new();
    c.write_tls(&mut wire).unwrap();
    // Flip a bit in the ciphertext (after the 5-byte header and 16-byte IV).
    wire[5 + 16 + 1] ^= 0x01;
    s.read_tls(&mut &wire[..]).unwrap();
    let err = s.process_new_packets().unwrap_err();
    assert_eq!(err, Error::DecryptError);
    // The server sends bad_record_mac.
    let mut alert = Vec::new();
    s.write_tls(&mut alert).unwrap();
    c.read_tls(&mut &alert[..]).unwrap();
    assert_eq!(
        c.process_new_packets().unwrap_err(),
        Error::AlertReceived(AlertDescription::BadRecordMac)
    );
}
