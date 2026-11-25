//! A server that negotiates TLS 1.2 and the legacy schemes, which are not
//! for TLS 1.2 (RFC 9963 §3). No browntls client lists them, so the
//! ClientHello is altered on the wire (it is plaintext; the altered
//! transcript does not matter for what is checked, which comes before
//! Finished).

use std::sync::Arc;

use browntls_core::sign::CertifiedKey;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, PeerIncompatible, ServerConfig,
    ServerConnection, SignatureAlgorithm, SignatureScheme, SupportedProtocolVersion, version,
};

use crate::common::hello_wire::{fatal_alert, give, take_flight};
use crate::common::{
    Chain, KeyType, do_handshake_until_error, provider, server_chain, server_name,
};
use crate::doubles::*;
use crate::legacy::*;

fn certified_key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

/// A client over `versions` whose verifier advertises the legacy schemes.
fn client_over(versions: &[&'static SupportedProtocolVersion], server: &Chain) -> ClientConnection {
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(legacy_server_verifier(server))
        .with_no_client_auth();
    ClientConnection::new(Arc::new(config), server_name()).unwrap()
}

/// A TLS 1.2-only server whose only certificate has `key`.
fn tls12_server_with_key(server: &Chain, key: Arc<ClaimingKey>) -> ServerConnection {
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_certified_key(CertifiedKey::new(server.cert_chain(), key));
    ServerConnection::new(Arc::new(config)).unwrap()
}

/// A server over `versions` that asks `resolver` for its certificate.
fn server_with_resolver(
    versions: &[&'static SupportedProtocolVersion],
    resolver: Arc<RecordingServerResolver>,
) -> ServerConnection {
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    ServerConnection::new(Arc::new(config)).unwrap()
}

/// The hello of `c` with `schemes` as its `signature_algorithms`, and the
/// schemes it listed before.
fn altered_hello(
    c: &mut ClientConnection,
    schemes: impl FnOnce(&[SignatureScheme]) -> Vec<SignatureScheme>,
) -> (Vec<u8>, Vec<SignatureScheme>) {
    let mut hello = take_flight(c);
    let listed = hello_schemes(&hello, EXT_SIGNATURE_ALGORITHMS).unwrap();
    assert!(!has_any_legacy(&listed), "{listed:?}");
    set_hello_schemes(&mut hello, &schemes(&listed));
    (hello, listed)
}

/// A TLS 1.2 server whose only key claims a legacy scheme fails the
/// handshake without asking the key to sign, though the ClientHello lists
/// the legacy schemes. With a TLS 1.2 family no suite has, the key is never
/// consulted; with the RSA family it is offered the hello's other schemes
/// only, none of which it claims, and the server fails with
/// `handshake_failure`.
#[test]
fn tls12_server_with_only_a_legacy_claiming_key_fails_cleanly() {
    let server = server_chain(KeyType::Rsa2048);
    for claims in LEGACY {
        for algorithm in [SignatureAlgorithm::Unknown(0xff), SignatureAlgorithm::RSA] {
            let key = ClaimingKey::new(claims, algorithm);
            let mut s = tls12_server_with_key(&server, key.clone());
            let mut c = client_over(&[&version::TLS13, &version::TLS12], &server);
            let (hello, listed) = altered_hello(&mut c, |listed| [&LEGACY[..], listed].concat());
            give(&mut s, &hello);
            let result = s.process_new_packets().map(|_| ());
            let flight = take_flight(&mut s);
            assert_eq!(plaintext_fatal_alert(&flight), Some(HANDSHAKE_FAILURE));
            let offered = key.offered();
            if algorithm == SignatureAlgorithm::RSA {
                // A suite matches; the key declines the schemes offered.
                assert_eq!(
                    result,
                    Err(Error::PeerIncompatible(
                        PeerIncompatible::NoSignatureSchemesInCommon
                    ))
                );
                assert_eq!(offered.len(), 1, "{offered:?}");
                assert!(
                    !offered[0].is_empty() && !has_any_legacy(&offered[0]),
                    "{offered:?}"
                );
                assert!(offered[0].iter().all(|scheme| listed.contains(scheme)));
                // The client reads the server's plaintext flight up to the
                // alert.
                give(&mut c, &flight);
                assert_eq!(
                    c.process_new_packets().map(|_| ()),
                    Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
                );
            } else {
                // The key's TLS 1.2 family matches no TLS 1.2 cipher suite.
                assert_eq!(
                    result,
                    Err(Error::PeerIncompatible(
                        PeerIncompatible::NoCipherSuitesInCommon
                    ))
                );
                assert!(offered.is_empty(), "{offered:?}");
            }
        }
    }
}

/// A TLS 1.2 server whose RSA-family key ignores the (legacy-free) list it
/// is offered for the ServerKeyExchange and returns a signer for a legacy
/// scheme: the server refuses that signer before it signs, with
/// `internal_error`. So does one whose signer names a legacy code point as
/// an `Unknown` value.
#[test]
fn tls12_server_key_choosing_legacy_anyway() {
    let server = server_chain(KeyType::Rsa2048);
    for claims in [&LEGACY[..], &LEGACY_AS_UNKNOWN[..]].concat() {
        let key = ClaimingKey::ignoring_offer(claims, SignatureAlgorithm::RSA);
        let mut s = tls12_server_with_key(&server, key.clone());
        let mut c = client_over(&[&version::TLS13, &version::TLS12], &server);
        let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
        assert_eq!(
            server_res,
            Err(Error::General(TLS13_ONLY.into())),
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

/// A TLS 1.2-only ClientHello whose `signature_algorithms` names only
/// legacy schemes: the server, which supports TLS 1.2, removes them, finds
/// nothing left and fails with `handshake_failure` before its certificate
/// resolver is consulted. With one classical scheme beside them, the
/// server goes on and the resolver sees only that scheme.
#[test]
fn tls12_hello_naming_only_legacy_is_refused() {
    let server = server_chain(KeyType::EcdsaP256);
    for (schemes, refused) in [
        (LEGACY.to_vec(), true),
        (LEGACY_AS_UNKNOWN.to_vec(), true),
        (
            vec![
                SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
            ],
            false,
        ),
    ] {
        let resolver = RecordingServerResolver::new(certified_key(&server));
        let mut s = server_with_resolver(&[&version::TLS12, &version::TLS13], resolver.clone());
        let mut c = client_over(&[&version::TLS12], &server);
        let (hello, _) = altered_hello(&mut c, |_| schemes.clone());
        give(&mut s, &hello);
        let result = s.process_new_packets().map(|_| ());
        if refused {
            assert_eq!(
                result,
                Err(Error::PeerIncompatible(
                    PeerIncompatible::NoSignatureSchemesInCommon
                )),
                "{schemes:?}"
            );
            assert_eq!(fatal_alert(&take_flight(&mut s)), Some(HANDSHAKE_FAILURE));
            assert!(resolver.seen().is_empty());
        } else {
            result.unwrap();
            assert_eq!(
                resolver.seen(),
                [vec![SignatureScheme::ECDSA_NISTP256_SHA256]]
            );
            // The server's flight: ServerHello onwards (TLS 1.2).
            let flight = take_flight(&mut s);
            assert!(find_message(&flight, 12).is_some(), "ServerKeyExchange");
        }
    }
}

/// A server that negotiates TLS 1.2 gives its certificate resolver none of
/// the legacy schemes an altered hello lists in front of its own, whether
/// the hello offers TLS 1.2 only or TLS 1.3 too: the resolver sees exactly
/// the hello's own schemes, and the server goes on to sign its
/// ServerKeyExchange with one of them.
#[test]
fn tls12_server_resolver_sees_no_legacy() {
    let server = server_chain(KeyType::EcdsaP256);
    for versions in [
        &[&version::TLS12][..],
        &[&version::TLS13, &version::TLS12][..],
    ] {
        let resolver = RecordingServerResolver::new(certified_key(&server));
        let mut s = server_with_resolver(&[&version::TLS12], resolver.clone());
        let mut c = client_over(versions, &server);
        let (hello, listed) = altered_hello(&mut c, |listed| [listed, &LEGACY[..]].concat());
        give(&mut s, &hello);
        s.process_new_packets().unwrap();
        assert_eq!(resolver.seen(), [listed], "{versions:?}");
        let flight = take_flight(&mut s);
        let (_, msg) = find_message(&flight, 12).expect("ServerKeyExchange");
        // ECDHE parameters (RFC 8422 §5.4): curve type, named curve, point.
        let body = msg + 4;
        let scheme_at = body + 3 + 1 + usize::from(flight[body + 3]);
        assert_eq!(
            u16_at(&flight, scheme_at),
            usize::from(u16::from(SignatureScheme::ECDSA_NISTP256_SHA256))
        );
    }
}
