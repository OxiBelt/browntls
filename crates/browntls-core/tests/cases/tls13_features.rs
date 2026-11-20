// Shared cases, included by `tests/tls13_features.rs` (RustCrypto provider)
// and `tests/tls13_features_native.rs` (native provider): the RFC 9846
// features beyond the basic handshake (post-handshake client
// authentication, stateless HelloRetryRequest cookies, the early exporter)
// and the RFC 9266 `tls-exporter` channel binding.

use std::io::Read;
use std::sync::Arc;

use browntls_core::client::ResolvesClientCert;
use browntls_core::crypto::cipher::{MessageEncrypter, OutboundChunks, OutboundPlainMessage};
use browntls_core::pki_types::UnixTime;
use browntls_core::server::{PostHandshakeAuthStatus, ProducesTickets};
use browntls_core::sign::CertifiedKey;
use browntls_core::time_provider::TimeProvider;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, ConnectionTrafficSecrets, ContentType, Error,
    HandshakeKind, NamedGroup, PeerMisbehaved, ProtocolVersion, ServerConfig, ServerConnection,
    SignatureScheme, version,
};
use common::*;

fn tls13_client(server: &Chain) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(server))
        .with_no_client_auth()
}

/// A TLS 1.3 client holding `client`'s certificate that offers
/// post-handshake authentication.
fn pha_client(server: &Chain, client: &Chain) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(server))
        .with_client_auth_cert(client.cert_chain(), client.private_key())
        .unwrap();
    config.enable_post_handshake_auth = true;
    config
}

/// A server verifying client certificates against `client`, deferring
/// client authentication to after the handshake when `defer`.
fn pha_server(server: &Chain, client: &Chain, mandatory: bool, defer: bool) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(client, mandatory))
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap();
    config.request_client_auth_after_handshake = defer;
    config
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

/// Completes the handshake and delivers the server's tickets.
fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    do_handshake(client, server).unwrap();
    transfer(server, client);
    client.process_new_packets().unwrap();
}

/// Requests client authentication and carries the exchange through.
fn post_handshake_auth(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), Error> {
    server.request_client_auth().unwrap();
    assert_eq!(
        server.post_handshake_auth_status(),
        Some(PostHandshakeAuthStatus::Requested)
    );
    transfer(server, client);
    client.process_new_packets()?;
    transfer(client, server);
    server.process_new_packets()?;
    Ok(())
}

fn last_alert(bytes: &[u8]) -> u8 {
    assert_eq!(bytes[0], 0x15, "an unprotected alert record");
    bytes[bytes.len() - 1]
}

fn take_tls<A: browntls_core::SideData>(conn: &mut browntls_core::ConnectionCommon<A>) -> Vec<u8> {
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf).unwrap();
    }
    buf
}

fn feed<A: browntls_core::SideData>(
    conn: &mut browntls_core::ConnectionCommon<A>,
    mut bytes: &[u8],
) {
    while !bytes.is_empty() {
        conn.read_tls(&mut bytes).unwrap();
    }
}

include!("tls13_features/post_handshake_auth.rs");
include!("tls13_features/cookies_and_exporters.rs");
include!("tls13_features/server_grease.rs");
