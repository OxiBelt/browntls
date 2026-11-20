// Shared cases, included by `tests/external_binding.rs` (RustCrypto
// provider) and `tests/external_binding_native.rs` (native provider): the
// RFC 8844 `external_id_hash` and `external_session_id` extensions between a
// browntls client and server, buffered and unbuffered, TLS 1.3 and TLS 1.2.
// Provider items are reached through the including target's `prov` module.
//
// Some cases change the hello messages on the wire: they are unprotected,
// so a changed ServerHello reaches the client's checks before any
// transcript does, and a changed second ClientHello the server's.

use std::sync::Arc;

use browntls_core::external_binding::{ExternalBinding, ExternalIdHash, ExternalSessionId};
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, NamedGroup,
    PeerIncompatible, PeerMisbehaved, ProtocolVersion, ServerConfig, ServerConnection, version,
};
use common::*;

const EXT_EXTERNAL_ID_HASH: u16 = 0x0037;
const EXT_EXTERNAL_SESSION_ID: u16 = 0x0038;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_EARLY_DATA: u16 = 0x002a;

// ------------------------------------------------------------- values

/// A `tls-id`-like session identifier: `tag` padded to 24 bytes.
fn tls_id(tag: &str) -> ExternalSessionId {
    ExternalSessionId::new(format!("{tag:-<24}").as_bytes()).unwrap()
}

fn hash(byte: u8) -> ExternalIdHash {
    ExternalIdHash::from_sha256([byte; 32])
}

/// The bindings of the two ends of one signaled session: each sends its
/// own `tls-id` and assertion hash and expects the other's.
fn pair() -> (ExternalBinding, ExternalBinding) {
    let client = ExternalBinding {
        id_hash: Some(hash(1)),
        peer_id_hash: Some(hash(2)),
        session_id: Some(tls_id("client")),
        peer_session_id: Some(tls_id("server")),
        require_peer_support: false,
    };
    let server = ExternalBinding {
        id_hash: client.peer_id_hash,
        peer_id_hash: client.id_hash,
        session_id: client.peer_session_id.clone(),
        peer_session_id: client.session_id.clone(),
        require_peer_support: false,
    };
    (client, server)
}

// ------------------------------------------------------- configurations

#[cfg(feature = "tls12")]
const VERSIONS: [ProtocolVersion; 2] = [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
#[cfg(not(feature = "tls12"))]
const VERSIONS: [ProtocolVersion; 1] = [ProtocolVersion::TLSv1_3];

#[cfg(feature = "tls12")]
static TLS12_ONLY: [&browntls_core::SupportedProtocolVersion; 1] = [&version::TLS12];
static TLS13_ONLY: [&browntls_core::SupportedProtocolVersion; 1] = [&version::TLS13];

fn supported(v: ProtocolVersion) -> &'static [&'static browntls_core::SupportedProtocolVersion] {
    match v {
        #[cfg(feature = "tls12")]
        ProtocolVersion::TLSv1_2 => &TLS12_ONLY,
        _ => &TLS13_ONLY,
    }
}

fn client_for(chain: &Chain, v: ProtocolVersion, binding: Option<ExternalBinding>) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(supported(v))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth();
    config.external_binding = binding;
    config
}

fn server_for(chain: &Chain, v: ProtocolVersion, binding: Option<ExternalBinding>) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(supported(v))
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.cert_chain(), chain.private_key())
        .unwrap();
    config.session_storage = browntls_core::server::ServerSessionMemoryCache::new(16);
    config.external_binding = binding;
    config
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    connect_arc(&Arc::new(client), &Arc::new(server))
}

fn connect_arc(
    client: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(client.clone(), server_name()).unwrap(),
        ServerConnection::new(server.clone()).unwrap(),
    )
}

/// The alert a peer sees for an error of ours.
fn alert_for(v: ProtocolVersion, missing: bool) -> Error {
    Error::AlertReceived(match (missing, v) {
        (false, _) => AlertDescription::IllegalParameter,
        (true, ProtocolVersion::TLSv1_3) => AlertDescription::MissingExtension,
        (true, _) => AlertDescription::HandshakeFailure,
    })
}

// --------------------------------------------------------- wire helpers

fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn flight(conn: &mut browntls_core::ConnectionCommon<impl browntls_core::SideData>) -> Vec<u8> {
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf).unwrap();
    }
    buf
}

fn feed(
    conn: &mut browntls_core::ConnectionCommon<impl browntls_core::SideData>,
    mut bytes: &[u8],
) {
    while !bytes.is_empty() {
        conn.read_tls(&mut bytes).unwrap();
    }
}

/// Where the extension block of the hello message that starts the first
/// record of `buf` begins (its two-byte length).
fn extensions_at(buf: &[u8]) -> usize {
    assert_eq!(buf[0], 22, "not a handshake record");
    let client = match buf[5] {
        1 => true,
        2 => false,
        other => panic!("not a hello: {other}"),
    };
    let mut at = 9 + 2 + 32;
    at += 1 + usize::from(buf[at]);
    if client {
        at += 2 + usize::from(u16_at(buf, at));
        at += 1 + usize::from(buf[at]);
    } else {
        at += 3;
    }
    at
}

/// The extensions of the hello message at the start of `buf`: type, where
/// the body starts, and the body.
fn hello_extensions(buf: &[u8]) -> Vec<(u16, usize, Vec<u8>)> {
    let mut at = extensions_at(buf);
    let end = at + 2 + usize::from(u16_at(buf, at));
    at += 2;
    let mut out = Vec::new();
    while at < end {
        let typ = u16_at(buf, at);
        let len = usize::from(u16_at(buf, at + 2));
        out.push((typ, at + 4, buf[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    out
}

fn extension(buf: &[u8], typ: u16) -> Option<Vec<u8>> {
    hello_extensions(buf)
        .into_iter()
        .find(|(t, _, _)| *t == typ)
        .map(|(_, _, body)| body)
}

/// Changes the type of the extension `from` of the hello at the start of
/// `buf` to `to`.
fn retype_extension(buf: &mut [u8], from: u16, to: u16) {
    let (_, at, _) = hello_extensions(buf)
        .into_iter()
        .find(|(t, _, _)| *t == from)
        .expect("extension present");
    buf[at - 4..at - 2].copy_from_slice(&to.to_be_bytes());
}

/// Appends an extension to the hello at the start of `buf`, fixing the
/// record, message and block lengths.
fn append_extension(buf: &mut Vec<u8>, typ: u16, body: &[u8]) {
    let ext_at = extensions_at(buf);
    let block_end = ext_at + 2 + usize::from(u16_at(buf, ext_at));
    let mut ext = typ.to_be_bytes().to_vec();
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(body);
    let grow = ext.len();
    buf.splice(block_end..block_end, ext);
    let add16 = |buf: &mut Vec<u8>, at: usize| {
        let v = u16_at(buf, at) as usize + grow;
        buf[at..at + 2].copy_from_slice(&(v as u16).to_be_bytes());
    };
    add16(buf, 3);
    add16(buf, ext_at);
    let len = (usize::from(buf[6]) << 16 | usize::from(u16_at(buf, 7))) + grow;
    buf[6] = (len >> 16) as u8;
    buf[7..9].copy_from_slice(&(len as u16).to_be_bytes());
}

// ---------------------------------------------------------------- cases

include!("external_binding/handshakes.rs");
include!("external_binding/wire.rs");
include!("external_binding/resumption.rs");
include!("external_binding/acceptor.rs");
include!("external_binding/unbuffered.rs");
#[cfg(feature = "native")]
include!("external_binding/ech.rs");
