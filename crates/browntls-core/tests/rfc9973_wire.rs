//! RFC 9973 §5 wire conformance for `tls_cert_with_extern_psk`.
//!
//! The tests alter ordinary TLS 1.3 ClientHello messages after browntls has
//! serialized them, then feed those bytes to a real browntls peer.

#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "providers/rustcrypto.rs"]
mod prov;

mod common;

use std::sync::Arc;

use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::psk::ExternalPsk;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, ServerConfig, ServerConnection,
    version,
};
use common::hello_wire::{add_hello_extension, fatal_alert, give, hello_extensions, take_flight};
use common::*;

const CERT_WITH_EXTERN_PSK: u16 = 0x0021;
const KEY: [u8; 32] = [0x42; 32];

fn key(id: &[u8]) -> ExternalPsk {
    ExternalPsk::new(id.to_vec(), KEY.to_vec(), HashAlgorithm::SHA256).unwrap()
}

fn client(chain: &Chain) -> ClientConfig {
    client_for(chain, prov::default_provider())
}

fn client_for(chain: &Chain, provider: browntls_core::crypto::CryptoProvider) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth();
    config.external_psks = vec![Arc::new(key(b"rfc9973"))];
    config.cert_with_extern_psk = true;
    config
}

fn server(chain: &Chain) -> ServerConfig {
    server_for(chain, prov::default_provider())
}

fn server_for(chain: &Chain, provider: browntls_core::crypto::CryptoProvider) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.cert_with_extern_psk = true;
    config.external_psks = Some(Arc::new(vec![Arc::new(key(b"rfc9973"))]));
    config
}

fn hello(chain: &Chain) -> (ClientConnection, ServerConnection, Vec<u8>) {
    let mut client = ClientConnection::new(Arc::new(client(chain)), server_name()).unwrap();
    let server = ServerConnection::new(Arc::new(server(chain))).unwrap();
    let flight = take_flight(&mut client);
    (client, server, flight)
}

fn hello_extensions_start(buf: &[u8]) -> usize {
    assert_eq!(buf[0], 22);
    assert_eq!(buf[5], 1);
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(buf[at]);
    at += 2 + usize::from(u16::from_be_bytes([buf[at], buf[at + 1]]));
    at += 1 + usize::from(buf[at]);
    at
}

/// Removes one extension from this single-record ClientHello and updates its
/// enclosing lengths. The parser under test receives an otherwise normal
/// message, including the original PSK binder bytes.
fn remove_extension(buf: &mut Vec<u8>, wanted: u16) {
    let block = hello_extensions_start(buf);
    let block_len = usize::from(u16::from_be_bytes([buf[block], buf[block + 1]]));
    let end = block + 2 + block_len;
    let mut at = block + 2;
    while at < end {
        let typ = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let len = usize::from(u16::from_be_bytes([buf[at + 2], buf[at + 3]]));
        if typ == wanted {
            let removed = 4 + len;
            buf.drain(at..at + removed);
            for length_at in [3, 7, block] {
                let old = usize::from(u16::from_be_bytes([buf[length_at], buf[length_at + 1]]));
                buf[length_at..length_at + 2]
                    .copy_from_slice(&u16::try_from(old - removed).unwrap().to_be_bytes());
            }
            return;
        }
        at += 4 + len;
    }
    panic!("extension {wanted:#06x} not present");
}

fn assert_server_alert(mut server: ServerConnection, flight: &[u8], expected: AlertDescription) {
    give(&mut server, flight);
    let err = server.process_new_packets().unwrap_err();
    assert!(matches!(err, Error::PeerMisbehaved(_)), "{err:?}");
    assert_eq!(
        fatal_alert(&take_flight(&mut server)),
        Some(u8::from(expected))
    );
}

#[test]
fn client_hello_extension_requires_each_companion() {
    let chain = server_chain(KeyType::EcdsaP256);
    // RFC 9973 §5.1: supported_groups, key_share, psk_key_exchange_modes,
    // and pre_shared_key must accompany the extension.
    for companion in [0x000a, 0x0033, 0x002d, 0x0029] {
        let (_client, server, mut flight) = hello(&chain);
        remove_extension(&mut flight, companion);
        assert_server_alert(server, &flight, AlertDescription::MissingExtension);
    }
}

#[test]
fn client_hello_extension_has_empty_data() {
    let chain = server_chain(KeyType::EcdsaP256);
    let (_client, mut server, mut flight) = hello(&chain);
    // Replace the empty body with one byte while preserving the encoded
    // ClientHello lengths.
    let start = hello_extensions_start(&flight);
    let mut at = start + 2;
    while u16::from_be_bytes([flight[at], flight[at + 1]]) != CERT_WITH_EXTERN_PSK {
        at += 4 + usize::from(u16::from_be_bytes([flight[at + 2], flight[at + 3]]));
    }
    flight[at + 2..at + 4].copy_from_slice(&1_u16.to_be_bytes());
    flight.splice(at + 4..at + 4, [0]);
    for length_at in [3, 7, start] {
        let old = usize::from(u16::from_be_bytes([
            flight[length_at],
            flight[length_at + 1],
        ]));
        flight[length_at..length_at + 2]
            .copy_from_slice(&u16::try_from(old + 1).unwrap().to_be_bytes());
    }
    give(&mut server, &flight);
    let err = server.process_new_packets().unwrap_err();
    assert!(matches!(err, Error::InvalidMessage(_)), "{err:?}");
    assert_eq!(
        fatal_alert(&take_flight(&mut server)),
        Some(u8::from(AlertDescription::DecodeError))
    );
}

#[test]
fn client_hello_extension_conflicts_with_early_data() {
    let chain = server_chain(KeyType::EcdsaP256);
    let (_client, mut server, mut flight) = hello(&chain);
    // The conflict is checked before PSK binder verification. An empty
    // early_data extension is sufficient to express the conflicting offer.
    let (_, psk) = hello_extensions(&flight, true).pop().unwrap();
    remove_extension(&mut flight, 0x0029);
    add_hello_extension(&mut flight, true, 0x002a, &[]);
    add_hello_extension(&mut flight, true, 0x0029, &psk);
    give(&mut server, &flight);
    let err = server.process_new_packets().unwrap_err();
    assert!(matches!(err, Error::PeerMisbehaved(_)), "{err:?}");
    assert_eq!(
        fatal_alert(&take_flight(&mut server)),
        Some(u8::from(AlertDescription::IllegalParameter))
    );
}

#[test]
fn certificate_with_external_psk_requires_psk_dhe_mode() {
    let chain = server_chain(KeyType::EcdsaP256);
    let (_client, mut server, mut flight) = hello(&chain);
    let start = hello_extensions_start(&flight);
    let mut at = start + 2;
    while u16::from_be_bytes([flight[at], flight[at + 1]]) != 0x002d {
        at += 4 + usize::from(u16::from_be_bytes([flight[at + 2], flight[at + 3]]));
    }
    // psk_ke only: the extension is incompatible with this certificate mode,
    // which requires the key agreement contribution as well.
    assert_eq!(&flight[at + 2..at + 6], &[0, 2, 1, 1]);
    flight[at + 5] = 0;
    give(&mut server, &flight);
    let err = server.process_new_packets().unwrap_err();
    assert!(matches!(err, Error::PeerMisbehaved(_)), "{err:?}");
    assert_eq!(
        fatal_alert(&take_flight(&mut server)),
        Some(u8::from(AlertDescription::IllegalParameter))
    );
}

#[test]
fn stateful_and_stateless_retry_preserve_the_extension() {
    let chain = server_chain(KeyType::EcdsaP256);
    for stateless in [false, true] {
        for remove_offer in [false, true] {
            let mut client_provider = prov::default_provider();
            client_provider.kx_groups = vec![prov::kx_group::X25519, prov::kx_group::SECP256R1];
            let mut server_provider = prov::default_provider();
            server_provider.kx_groups = vec![prov::kx_group::SECP256R1];
            let mut config = server_for(&chain, server_provider);
            if stateless {
                config.hello_retry_cookies = Some(prov::Ticketer::new().unwrap());
            }
            let config = Arc::new(config);
            let mut client =
                ClientConnection::new(Arc::new(client_for(&chain, client_provider)), server_name())
                    .unwrap();
            let mut server = ServerConnection::new(config.clone()).unwrap();
            let first = take_flight(&mut client);
            assert!(hello_extensions(&first, true).contains(&(CERT_WITH_EXTERN_PSK, vec![])));
            give(&mut server, &first);
            server.process_new_packets().unwrap();
            give(&mut client, &take_flight(&mut server));
            client.process_new_packets().unwrap();
            let mut second = take_flight(&mut client);
            let offset = if second[0] == 20 { 6 } else { 0 };
            assert!(
                hello_extensions(&second[offset..], true).contains(&(CERT_WITH_EXTERN_PSK, vec![]))
            );
            if stateless {
                server = ServerConnection::new(config).unwrap();
            }
            if remove_offer {
                let mut modified = second.split_off(offset);
                remove_extension(&mut modified, CERT_WITH_EXTERN_PSK);
                second.extend(modified);
                assert_server_alert(server, &second, AlertDescription::IllegalParameter);
            } else {
                give(&mut server, &second);
                server.process_new_packets().unwrap();
                do_handshake(&mut client, &mut server).unwrap();
                assert!(client.peer_certificates().is_some());
                assert_eq!(server.external_psk_identity(), Some(b"rfc9973".as_slice()));
            }
        }
    }
}
