// Shared cases, included by `tests/rfc6066_legacy.rs` (RustCrypto provider)
// and `tests/rfc6066_legacy_native.rs` (native provider): the RFC 6066
// extensions that only TLS 1.2 defines (`client_certificate_url`,
// `trusted_ca_keys` and `truncated_hmac`) as a peer that negotiates none of
// them sees them. Provider items are reached through the including
// target's `prov` module.
//
// The library sends none of these extensions with a default configuration,
// so the cases add them to the hello messages on the wire: those are
// unprotected, and both sides judge a hello before any transcript does.

use std::sync::Arc;

use browntls_core::{
    ClientConfig, ClientConnection, Error, InvalidMessage, PeerMisbehaved, ServerConfig,
    ServerConnection, SupportedProtocolVersion, version,
};
use common::hello_wire::*;
use common::*;

const ALERT_ILLEGAL_PARAMETER: u8 = 47;
const ALERT_DECODE_ERROR: u8 = 50;
const ALERT_UNSUPPORTED_EXTENSION: u8 = 110;

/// The three extensions, each with a well-formed ClientHello body.
fn legacy_client_extensions() -> Vec<(u16, Vec<u8>)> {
    // TrustedAuthorities: pre_agreed, then a key_sha1_hash.
    let mut authorities = vec![0, 22, 0, 1];
    authorities.extend([0x5a; 20]);
    vec![
        (EXT_CLIENT_CERTIFICATE_URL, Vec::new()),
        (EXT_TRUSTED_CA_KEYS, authorities),
        (EXT_TRUNCATED_HMAC, Vec::new()),
    ]
}

fn versions() -> Vec<&'static SupportedProtocolVersion> {
    let mut all = vec![&version::TLS13];
    #[cfg(feature = "tls12")]
    all.push(&version::TLS12);
    all
}

fn client_for(chain: &Chain, version: &'static SupportedProtocolVersion) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(chain))
        .with_no_client_auth()
}

fn server_for(chain: &Chain, version: &'static SupportedProtocolVersion) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
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

/// A default client sends none of the three, whatever versions it offers.
#[test]
fn a_default_client_sends_no_legacy_extension() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut configs = vec![client_config(&chain)];
    configs.extend(versions().into_iter().map(|v| client_for(&chain, v)));
    for config in configs {
        let mut client = ClientConnection::new(Arc::new(config), server_name()).unwrap();
        let types = hello_extension_types(&take_flight(&mut client), true);
        for (typ, _) in legacy_client_extensions() {
            assert!(!types.contains(&typ), "{typ:#06x} in {types:x?}");
        }
    }
}

/// A server with a default configuration parses the three extensions and
/// answers none of them, in TLS 1.3 (where they do not exist) and in
/// TLS 1.2 (where it negotiates none).
#[test]
fn a_default_server_acknowledges_no_legacy_extension() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for version in versions() {
        let (mut client, mut server) =
            connect(client_for(&chain, version), server_for(&chain, version));
        let mut hello = take_flight(&mut client);
        for (typ, body) in legacy_client_extensions() {
            add_hello_extension(&mut hello, true, typ, &body);
        }
        give(&mut server, &hello);
        server.process_new_packets().unwrap();

        let types = hello_extension_types(&take_flight(&mut server), false);
        for (typ, _) in legacy_client_extensions() {
            assert!(
                !types.contains(&typ),
                "{version:?}: {typ:#06x} in {types:x?}"
            );
        }
    }
}

/// A malformed body of an extension the server parses is a decode_error,
/// also when the server negotiates nothing with it.
#[test]
fn malformed_legacy_extensions_fail_to_decode() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    let mut cut_hash = vec![0, 20, 3];
    cut_hash.extend([0u8; 19]);
    let cases: [(u16, Vec<u8>, InvalidMessage); 6] = [
        // RFC 6066 §5 and §7: "extension_data" is empty.
        (
            EXT_CLIENT_CERTIFICATE_URL,
            vec![0],
            InvalidMessage::TrailingData("extension"),
        ),
        (
            EXT_TRUNCATED_HMAC,
            vec![0],
            InvalidMessage::TrailingData("extension"),
        ),
        // RFC 6066 §6: TrustedAuthorities is a list with a length prefix.
        (
            EXT_TRUSTED_CA_KEYS,
            Vec::new(),
            InvalidMessage::MissingData("u16"),
        ),
        // An IdentifierType the RFC does not define.
        (
            EXT_TRUSTED_CA_KEYS,
            vec![0, 1, 4],
            InvalidMessage::UnknownTrustedAuthorityType,
        ),
        // A cert_sha1_hash of 19 bytes.
        (
            EXT_TRUSTED_CA_KEYS,
            cut_hash,
            InvalidMessage::MissingData("SHA1Hash"),
        ),
        // Bytes after the list.
        (
            EXT_TRUSTED_CA_KEYS,
            vec![0, 1, 0, 0],
            InvalidMessage::TrailingData("extension"),
        ),
    ];
    for version in versions() {
        for (typ, body, expected) in &cases {
            let (mut client, mut server) =
                connect(client_for(&chain, version), server_for(&chain, version));
            let mut hello = take_flight(&mut client);
            add_hello_extension(&mut hello, true, *typ, body);
            give(&mut server, &hello);
            assert_eq!(
                server.process_new_packets().unwrap_err(),
                Error::InvalidMessage(*expected),
                "{version:?}: {typ:#06x} {body:x?}"
            );
            assert_eq!(
                fatal_alert(&take_flight(&mut server)),
                Some(ALERT_DECODE_ERROR)
            );
        }
    }
}

/// An empty `trusted_ca_keys` list is valid (RFC 6066 §6: the client then
/// claims root keys agreed by other means).
#[test]
fn an_empty_trusted_ca_keys_list_is_accepted() {
    let chain = server_chain(KeyType::EcdsaP256);
    for version in versions() {
        let (mut client, mut server) =
            connect(client_for(&chain, version), server_for(&chain, version));
        let mut hello = take_flight(&mut client);
        add_hello_extension(&mut hello, true, EXT_TRUSTED_CA_KEYS, &[0, 0]);
        give(&mut server, &hello);
        server.process_new_packets().unwrap();
    }
}

/// The client's error when the ServerHello carries an extra extension.
fn client_error_for_server_hello_extension(
    chain: &Chain,
    version: &'static SupportedProtocolVersion,
    typ: u16,
) -> (Error, Option<u8>) {
    let (mut client, mut server) = connect(client_for(chain, version), server_for(chain, version));
    let hello = take_flight(&mut client);
    give(&mut server, &hello);
    server.process_new_packets().unwrap();
    let mut flight = take_flight(&mut server);
    add_hello_extension(&mut flight, false, typ, &[]);
    give(&mut client, &flight);
    let err = client.process_new_packets().unwrap_err();
    (err, fatal_alert(&take_flight(&mut client)))
}

/// TLS 1.2: a client that offered none of the three refuses a server that
/// answers one (RFC 5246 §7.4.1.4, unsupported_extension). For
/// `truncated_hmac` that holds for every configuration: it is never
/// offered (RFC 9325 §4.6).
#[cfg(feature = "tls12")]
#[test]
fn a_tls12_client_refuses_unsolicited_legacy_extensions() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for (typ, _) in legacy_client_extensions() {
        assert_eq!(
            client_error_for_server_hello_extension(&chain, &version::TLS12, typ),
            (
                Error::PeerMisbehaved(PeerMisbehaved::UnsolicitedServerHelloExtension),
                Some(ALERT_UNSUPPORTED_EXTENSION)
            ),
            "{typ:#06x}"
        );
    }
}

/// TLS 1.3 defines none of the three: in a ServerHello each is a recognised
/// extension in a message it may not appear in (RFC 9846 §4.3,
/// illegal_parameter).
#[test]
fn a_tls13_client_refuses_legacy_extensions_in_server_hello() {
    init_logging();
    let chain = server_chain(KeyType::EcdsaP256);
    for (typ, _) in legacy_client_extensions() {
        assert_eq!(
            client_error_for_server_hello_extension(&chain, &version::TLS13, typ),
            (
                Error::PeerMisbehaved(PeerMisbehaved::UnexpectedCleartextExtension),
                Some(ALERT_ILLEGAL_PARAMETER)
            ),
            "{typ:#06x}"
        );
    }
}
