//! The handshake rules: what a TLS 1.2 CertificateRequest, a TLS 1.2
//! client's resolver and key, a ClientHello and a TLS 1.2 server's resolver
//! see of the ML-DSA schemes a verifier advertises.

use std::sync::Arc;

use browntls_core::sign::CertifiedKey;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, PeerIncompatible, ProtocolVersion,
    ServerConfig, ServerConnection, SignatureAlgorithm, SignatureScheme, SupportedProtocolVersion,
    version,
};

use crate::common::hello_wire::{give, take_flight};
use crate::common::{
    Chain, KeyType, PinnedServerVerifier, client_chain, do_handshake, do_handshake_until_error,
    provider, server_chain, server_name, transfer,
};
use crate::doubles::*;

fn certified_key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

fn connect(client: ClientConfig, server: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(client), server_name()).unwrap(),
        ServerConnection::new(Arc::new(server)).unwrap(),
    )
}

/// A server over `versions` serving `server`, asking for a client
/// certificate with a verifier of `client` that advertises ML-DSA.
fn server_asking(
    versions: &[&'static SupportedProtocolVersion],
    server: &Chain,
    client: &Chain,
    mandatory: bool,
) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_client_cert_verifier(client_verifier(client, mandatory))
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap()
}

/// A client over `versions` whose verifier advertises ML-DSA.
fn client_over(versions: &[&'static SupportedProtocolVersion], server: &Chain) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(server))
        .with_no_client_auth()
}

/// A TLS 1.2 CertificateRequest lists none of the ML-DSA schemes its
/// verifier advertises, so the client's resolver never sees them; the
/// TLS 1.3 CertificateRequest of the same server lists them all.
#[test]
fn tls12_certificate_request_leaves_ml_dsa_out() {
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::Ed25519);
    for (versions, tls13) in [
        (&[&version::TLS12][..], false),
        (&[&version::TLS13][..], true),
    ] {
        let resolver = RecordingClientResolver::new(Some(certified_key(&client)));
        let client_config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&server))
            .with_client_cert_resolver(resolver.clone());
        let (mut c, mut s) = connect(
            client_config,
            server_asking(versions, &server, &client, true),
        );
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(s.peer_certificates().unwrap(), client.cert_chain());
        let seen = resolver.seen();
        assert_eq!(seen.len(), 1);
        if tls13 {
            assert!(has_all_ml_dsa(&seen[0]), "{seen:?}");
        } else {
            assert!(!has_any_ml_dsa(&seen[0]), "{seen:?}");
            assert_eq!(seen[0], default_schemes());
        }
    }

    // On the wire: the plaintext TLS 1.2 CertificateRequest.
    let mut c = ClientConnection::new(
        Arc::new(client_over(&[&version::TLS12], &server)),
        server_name(),
    )
    .unwrap();
    let mut s = ServerConnection::new(Arc::new(server_asking(
        &[&version::TLS12],
        &server,
        &client,
        true,
    )))
    .unwrap();
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut flight = take_flight(&mut s);
    let listed = add_to_tls12_certificate_request(&mut flight, &[]);
    assert_eq!(listed, default_schemes());
}

/// A TLS 1.2 client whose key claims an ML-DSA scheme (and reports a
/// TLS 1.2 family the server's `certificate_types` accept) is not offered
/// that scheme even when the server's CertificateRequest lists it: the
/// resolver and the key see the request's other schemes only. The request
/// is altered on the wire (the TLS 1.2 server flight is plaintext), so the
/// handshake then fails on the Finished transcripts.
#[test]
fn tls12_client_keeps_ml_dsa_from_its_resolver_and_key() {
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::EcdsaP256);
    let key = ClaimingKey::new(SignatureScheme::ML_DSA_65, SignatureAlgorithm::ECDSA);
    let resolver =
        RecordingClientResolver::new(Some(CertifiedKey::new(client.cert_chain(), key.clone())));
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server))
        .with_client_cert_resolver(resolver.clone());
    let (mut c, mut s) = connect(
        client_config,
        server_asking(&[&version::TLS12], &server, &client, false),
    );
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut flight = take_flight(&mut s);
    let listed = add_to_tls12_certificate_request(&mut flight, &ML_DSA);
    assert!(!listed.is_empty() && !has_any_ml_dsa(&listed));
    give(&mut c, &flight);
    c.process_new_packets().unwrap();

    assert_eq!(resolver.seen(), std::slice::from_ref(&listed));
    assert_eq!(key.offered(), [listed]);

    // The client answered with an empty Certificate; the server's
    // transcript differs from the client's. With the extended master
    // secret (RFC 7627), whose session hash covers the CertificateRequest,
    // the two sides derive different keys, so the client's encrypted
    // Finished record does not decrypt: bad_record_mac (20), sent in
    // plaintext since the server has not sent its ChangeCipherSpec yet.
    transfer(&mut c, &mut s);
    assert_eq!(
        s.process_new_packets().map(|_| ()),
        Err(Error::DecryptError)
    );
    assert_eq!(
        crate::common::hello_wire::fatal_alert(&take_flight(&mut s)),
        Some(20)
    );
}

/// The single `signature_algorithms` list of a ClientHello serves every
/// version it offers (RFC 9846 §4.3.3): with TLS 1.3 offered (alone or
/// with TLS 1.2) it has the ML-DSA schemes the verifier advertises, in a
/// TLS 1.2-only hello it has none of them.
#[test]
fn client_hello_lists_ml_dsa_only_when_offering_tls13() {
    let server = server_chain(KeyType::EcdsaP256);
    for (versions, tls13) in [
        (&[&version::TLS12][..], false),
        (&[&version::TLS13][..], true),
        (&[&version::TLS13, &version::TLS12][..], true),
    ] {
        let mut c =
            ClientConnection::new(Arc::new(client_over(versions, &server)), server_name()).unwrap();
        let hello = take_flight(&mut c);
        let schemes = hello_schemes(&hello, EXT_SIGNATURE_ALGORITHMS).unwrap();
        if tls13 {
            assert_eq!(schemes, with_ml_dsa(), "{versions:?}");
        } else {
            assert_eq!(schemes, default_schemes(), "{versions:?}");
        }
    }
}

/// A server that negotiates TLS 1.2 with a client offering both versions
/// (and the ML-DSA schemes) gives its certificate resolver no ML-DSA
/// scheme; one that negotiates TLS 1.3 gives it all of them.
#[test]
fn tls12_server_resolver_sees_no_ml_dsa() {
    let server = server_chain(KeyType::EcdsaP256);
    for (versions, negotiated) in [
        (&[&version::TLS12][..], ProtocolVersion::TLSv1_2),
        (&[&version::TLS13][..], ProtocolVersion::TLSv1_3),
    ] {
        let resolver = RecordingServerResolver::new(certified_key(&server));
        let server_config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        let (mut c, mut s) = connect(
            client_over(&[&version::TLS13, &version::TLS12], &server),
            server_config,
        );
        do_handshake(&mut c, &mut s).unwrap();
        assert_eq!(s.protocol_version(), Some(negotiated));
        let seen = resolver.seen();
        assert_eq!(seen.len(), 1);
        match negotiated {
            ProtocolVersion::TLSv1_3 => assert!(has_all_ml_dsa(&seen[0]), "{seen:?}"),
            _ => assert!(!has_any_ml_dsa(&seen[0]) && !seen[0].is_empty(), "{seen:?}"),
        }
    }
}

/// A TLS 1.2 server whose only key claims an ML-DSA scheme fails the
/// handshake without asking the key to sign, even though the client
/// offered ML-DSA (for TLS 1.3) in its hello. With a TLS 1.2 family no
/// suite has, the key is never consulted; with the ECDSA family it is
/// offered the client's ECDSA schemes only, none of which it claims.
#[test]
fn tls12_server_with_only_an_ml_dsa_claiming_key_fails_cleanly() {
    let server = server_chain(KeyType::EcdsaP256);
    for algorithm in [SignatureAlgorithm::Unknown(0xff), SignatureAlgorithm::ECDSA] {
        let key = ClaimingKey::new(SignatureScheme::ML_DSA_65, algorithm);
        let server_config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_certified_key(CertifiedKey::new(server.cert_chain(), key.clone()));
        let (mut c, mut s) = connect(
            client_over(&[&version::TLS13, &version::TLS12], &server),
            server_config,
        );
        let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
        assert_eq!(
            client_res,
            Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
        );
        let offered = key.offered();
        if algorithm == SignatureAlgorithm::ECDSA {
            // A suite matches; the key declines the ECDSA schemes offered.
            assert_eq!(
                server_res,
                Err(Error::PeerIncompatible(
                    PeerIncompatible::NoSignatureSchemesInCommon
                ))
            );
            // First the server probes the key's curve with one ECDSA scheme
            // at a time (none is claimed), then offers the client's list.
            let probes = [
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
            ]
            .map(|scheme| vec![scheme]);
            assert_eq!(offered.len(), 4, "{offered:?}");
            assert_eq!(offered[..3], probes);
            assert!(
                !offered[3].is_empty() && !has_any_ml_dsa(&offered[3]),
                "{offered:?}"
            );
        } else {
            // The key's TLS 1.2 family matches no TLS 1.2 cipher suite.
            assert_eq!(
                server_res,
                Err(Error::PeerIncompatible(
                    PeerIncompatible::NoCipherSuitesInCommon
                ))
            );
            assert!(offered.is_empty(), "{offered:?}");
        }
    }
}
