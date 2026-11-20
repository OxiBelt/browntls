// Shared cases, included by `tests/external_psk.rs` (RustCrypto provider) and
// `tests/external_psk_native.rs` (native provider): TLS 1.3 external PSKs
// (RFC 9846 §4.3.11), the PSK importer (RFC 9258) and certificate
// authentication with an external PSK (RFC 8773). Provider items are reached
// through the including target's `prov` module.

use std::io::{Read, Write};
use std::sync::Arc;

use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::pki_types::DnsName;
use browntls_core::psk::{ExternalPsk, ImportedIdentity, ResolvesExternalPsk};
use browntls_core::{
    AlertDescription, CipherSuite, ClientConfig, ClientConnection, Error, HandshakeKind,
    NamedGroup, PeerIncompatible, PeerMisbehaved, ServerConfig, ServerConnection, version,
};
use common::*;

const KEY: [u8; 32] = [0x42; 32];

fn psk(identity: &[u8], hash: HashAlgorithm) -> ExternalPsk {
    ExternalPsk::new(identity.to_vec(), KEY.to_vec(), hash).unwrap()
}

fn tls13_provider(
    suites: Option<&[browntls_core::SupportedCipherSuite]>,
    groups: Option<&[&'static dyn browntls_core::crypto::SupportedKxGroup]>,
) -> Arc<browntls_core::crypto::CryptoProvider> {
    let mut provider = prov::default_provider();
    if let Some(suites) = suites {
        provider.cipher_suites = suites.to_vec();
    }
    if let Some(groups) = groups {
        provider.kx_groups = groups.to_vec();
    }
    Arc::new(provider)
}

/// A TLS 1.3 client offering `psks`; it trusts `chain` should the server
/// authenticate with a certificate instead.
fn client_with(chain: &Chain, psks: Vec<ExternalPsk>) -> ClientConfig {
    client_with_provider(chain, psks, tls13_provider(None, None))
}

fn client_with_provider(
    chain: &Chain,
    psks: Vec<ExternalPsk>,
    provider: Arc<browntls_core::crypto::CryptoProvider>,
) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth();
    config.external_psks = psks.into_iter().map(Arc::new).collect();
    config
}

/// A server with no certificate that accepts `psks`.
fn psk_only_server(psks: Vec<ExternalPsk>) -> ServerConfig {
    psk_only_server_with_provider(psks, tls13_provider(None, None))
}

fn psk_only_server_with_provider(
    psks: Vec<ExternalPsk>,
    provider: Arc<browntls_core::crypto::CryptoProvider>,
) -> ServerConfig {
    let resolver: Vec<Arc<ExternalPsk>> = psks.into_iter().map(Arc::new).collect();
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_external_psks_only(Arc::new(resolver))
}

/// A server with `chain`'s certificate that also accepts `psks`.
fn cert_and_psk_server(chain: &Chain, psks: Vec<ExternalPsk>) -> ServerConfig {
    let mut config = server_config(chain);
    let resolver: Vec<Arc<ExternalPsk>> = psks.into_iter().map(Arc::new).collect();
    config.external_psks = Some(Arc::new(resolver));
    config
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

fn exchange_data(client: &mut ClientConnection, server: &mut ServerConnection) {
    assert_eq!(send_and_receive(client, server, b"ping"), b"ping");
    assert_eq!(send_and_receive(server, client, b"pong"), b"pong");
}

fn suite_of(conn: &browntls_core::CommonState) -> CipherSuite {
    conn.negotiated_cipher_suite().unwrap().suite()
}

/// Hands the tickets `server` sent to `client`.
fn take_tickets(client: &mut ClientConnection, server: &mut ServerConnection) {
    transfer(server, client);
    client.process_new_packets().unwrap();
    assert!(client.tls13_tickets_received() > 0);
}

include!("external_psk/negotiation.rs");
include!("external_psk/importer_and_certificates.rs");
include!("external_psk/tickets_and_early_data.rs");
