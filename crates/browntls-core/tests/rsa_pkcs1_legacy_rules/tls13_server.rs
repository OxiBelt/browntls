//! A TLS 1.3 server and the legacy schemes (RFC 9963 §3: a server never
//! signs with one). No browntls client lists them, so a peer that does is
//! either a browntls ClientHello altered on the wire (it is plaintext; the
//! altered transcript does not matter, since these handshakes fail before
//! Finished) or a rustls client whose verifier lists them, whose
//! transcript matches the server's, so that it can read the server's
//! encrypted alert.

use std::sync::Arc;

use browntls_core::sign::CertifiedKey;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, PeerIncompatible, ServerConfig,
    ServerConnection, SignatureAlgorithm, SignatureScheme, version,
};

use crate::common::hello_wire::{fatal_alert, give, take_flight};
use crate::common::{
    Chain, KeyType, do_handshake_until_error, provider, server_chain, server_name,
};
use crate::doubles::*;
use crate::legacy::*;

/// The legacy schemes, named and as `Unknown` values.
fn every_legacy_value() -> [SignatureScheme; 6] {
    [
        LEGACY[0],
        LEGACY[1],
        LEGACY[2],
        LEGACY_AS_UNKNOWN[0],
        LEGACY_AS_UNKNOWN[1],
        LEGACY_AS_UNKNOWN[2],
    ]
}

/// A TLS 1.3 client whose verifier advertises the legacy schemes.
fn tls13_client(server: &Chain) -> ClientConnection {
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(legacy_server_verifier(server))
        .with_no_client_auth();
    ClientConnection::new(Arc::new(config), server_name()).unwrap()
}

/// A TLS 1.3 server whose only certificate has `key`.
fn tls13_server(server: &Chain, key: Arc<ClaimingKey>) -> ServerConnection {
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_certified_key(CertifiedKey::new(server.cert_chain(), key));
    ServerConnection::new(Arc::new(config)).unwrap()
}

/// The browntls client's TLS 1.3 hello with the legacy schemes put in
/// front of its `signature_algorithms`, and the schemes it listed.
fn hello_with_legacy_added(server: &Chain) -> (Vec<u8>, Vec<SignatureScheme>) {
    let mut hello = take_flight(&mut tls13_client(server));
    let listed = hello_schemes(&hello, EXT_SIGNATURE_ALGORITHMS).unwrap();
    assert!(!has_any_legacy(&listed), "{listed:?}");
    set_hello_schemes(&mut hello, &[&LEGACY[..], &listed].concat());
    (hello, listed)
}

/// Asserts that `key` was offered one non-empty list, of schemes from
/// `listed` and without a legacy scheme.
fn assert_offered_without_legacy(key: &ClaimingKey, listed: &[SignatureScheme]) {
    let offered = key.offered();
    assert_eq!(offered.len(), 1, "{offered:?}");
    assert!(
        !offered[0].is_empty() && !has_any_legacy(&offered[0]),
        "{offered:?}"
    );
    assert!(
        offered[0].iter().all(|scheme| listed.contains(scheme)),
        "{offered:?}"
    );
}

/// A TLS 1.3 server whose only key claims a legacy scheme is never offered
/// it, though the ClientHello lists it: the key declines the other
/// schemes, and the server fails with `handshake_failure` (as it does for
/// any key with no scheme in common) without asking the key to sign. The
/// legacy code points as `Unknown` values fare the same.
#[test]
fn tls13_server_never_offers_legacy_to_its_key() {
    let server = server_chain(KeyType::Rsa2048);
    for claims in every_legacy_value() {
        // A browntls hello altered on the wire.
        let key = ClaimingKey::new(claims, SignatureAlgorithm::RSA);
        let mut s = tls13_server(&server, key.clone());
        let (hello, listed) = hello_with_legacy_added(&server);
        give(&mut s, &hello);
        assert_eq!(
            s.process_new_packets().map(|_| ()),
            Err(Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon
            )),
            "{claims:?}"
        );
        assert_offered_without_legacy(&key, &listed);

        // A rustls client listing the legacy schemes: it reads the alert.
        let key = ClaimingKey::new(claims, SignatureAlgorithm::RSA);
        let mut s = tls13_server(&server, key.clone());
        let mut c = rustls_client(&server);
        let hello = rustls_flight(&mut c);
        let listed = hello_schemes(&hello, EXT_SIGNATURE_ALGORITHMS).unwrap();
        assert!(
            LEGACY.iter().all(|scheme| listed.contains(scheme)),
            "{listed:?}"
        );
        give(&mut s, &hello);
        assert_eq!(
            s.process_new_packets().map(|_| ()),
            Err(Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon
            )),
            "{claims:?}"
        );
        assert_offered_without_legacy(&key, &listed);
        assert_eq!(
            rustls_receive(&mut c, &take_flight(&mut s)),
            rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure),
            "{claims:?}"
        );
    }
}

/// A TLS 1.3 ClientHello whose `signature_algorithms` names only legacy
/// schemes leaves the server no scheme to sign with: it refuses the hello
/// with `handshake_failure` before its ServerHello, and its key is never
/// consulted.
#[test]
fn tls13_hello_naming_only_legacy_is_refused() {
    let server = server_chain(KeyType::Rsa2048);
    let key = ClaimingKey::new(LEGACY[0], SignatureAlgorithm::RSA);
    let mut s = tls13_server(&server, key.clone());
    let mut hello = take_flight(&mut tls13_client(&server));
    set_hello_schemes(&mut hello, &LEGACY);
    give(&mut s, &hello);
    assert_eq!(
        s.process_new_packets().map(|_| ()),
        Err(Error::PeerIncompatible(
            PeerIncompatible::NoSignatureSchemesInCommon
        ))
    );
    assert_eq!(fatal_alert(&take_flight(&mut s)), Some(HANDSHAKE_FAILURE));
    assert!(key.offered().is_empty(), "{:?}", key.offered());
}

/// A TLS 1.3 server whose key ignores the (legacy-free) list it is offered
/// and returns a signer for a legacy scheme: the server refuses that signer
/// before it signs, with `internal_error`. The check goes by code point,
/// so a signer naming an `Unknown` legacy value is refused too.
#[test]
fn tls13_server_key_choosing_legacy_anyway() {
    let server = server_chain(KeyType::Rsa2048);
    for claims in every_legacy_value() {
        let key = ClaimingKey::ignoring_offer(claims, SignatureAlgorithm::RSA);
        let mut s = tls13_server(&server, key.clone());
        let mut c = tls13_client(&server);
        let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
        assert_eq!(
            server_res,
            Err(Error::General(CLIENT_AUTH_ONLY.into())),
            "{claims:?}"
        );
        assert_eq!(
            client_res,
            Err(Error::AlertReceived(AlertDescription::InternalError)),
            "{claims:?}"
        );
        let offered = key.offered();
        assert_eq!(offered.len(), 1, "{offered:?}");
        assert!(
            !offered[0].is_empty() && !has_any_legacy(&offered[0]),
            "{offered:?}"
        );
    }
}
