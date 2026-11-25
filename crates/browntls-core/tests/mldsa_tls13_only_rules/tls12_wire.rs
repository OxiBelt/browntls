//! TLS 1.2 peers that put an ML-DSA scheme where the protocol has no place
//! for one, by rewriting plaintext handshake messages on the wire: a
//! ClientHello whose `signature_algorithms` names ML-DSA, a
//! ServerKeyExchange and a client CertificateVerify signed "with" ML-DSA.
//! Also the ML-DSA code points as `SignatureScheme::Unknown` values, and a
//! DTLS 1.2-only ClientHello.

use std::sync::Arc;
use std::time::Duration;

use browntls_core::sign::CertifiedKey;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, PeerIncompatible, PeerMisbehaved,
    ProtocolVersion, ServerConfig, ServerConnection, SignatureScheme, dtls, version,
};

use crate::common::hello_wire::{fatal_alert, give, take_flight};
use crate::common::{
    Chain, KeyType, PinnedClientVerifier, PinnedServerVerifier, SchemeRecordingClientVerifier,
    SchemeRecordingServerVerifier, client_chain, do_handshake, provider, server_chain, server_name,
    transfer,
};
use crate::doubles::*;

fn tls12_client(verifier: Arc<SchemeRecordingServerVerifier>) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

fn tls12_server_with(resolver: Arc<RecordingServerResolver>) -> ServerConfig {
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12, &version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(resolver)
}

fn certified_key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

/// A TLS 1.2-only ClientHello (with SNI) whose `signature_algorithms`
/// names only ML-DSA schemes: the server, which supports TLS 1.2, removes
/// them, finds nothing left and fails with `handshake_failure` before its
/// certificate resolver is consulted. With one classical scheme beside them,
/// the server goes on and the resolver sees only that scheme.
#[test]
fn tls12_hello_naming_only_ml_dsa_is_refused() {
    let server = server_chain(KeyType::EcdsaP256);
    for (schemes, refused) in [
        (ML_DSA.to_vec(), true),
        (
            vec![
                SignatureScheme::ML_DSA_65,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ML_DSA_87,
            ],
            false,
        ),
    ] {
        let resolver = RecordingServerResolver::new(certified_key(&server));
        let mut c = ClientConnection::new(
            Arc::new(tls12_client(server_verifier(&server))),
            server_name(),
        )
        .unwrap();
        let mut s = ServerConnection::new(Arc::new(tls12_server_with(resolver.clone()))).unwrap();
        let mut hello = take_flight(&mut c);
        assert_eq!(
            crate::common::hello_wire::hello_extensions(&hello, true)
                .iter()
                .filter(|(typ, _)| *typ == 0)
                .count(),
            1,
            "the hello carries server_name"
        );
        set_hello_schemes(&mut hello, &schemes);
        give(&mut s, &hello);
        let result = s.process_new_packets().map(|_| ());
        if refused {
            assert_eq!(
                result,
                Err(Error::PeerIncompatible(
                    PeerIncompatible::NoSignatureSchemesInCommon
                ))
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

/// The same without tampering: a client offering TLS 1.3 and 1.2 whose
/// verifier advertises only ML-DSA schemes and one classical scheme
/// completes a TLS 1.2 handshake with a server that has only TLS 1.2, which
/// signs with the classical scheme; with ML-DSA alone it fails as above.
#[test]
fn dual_version_hello_to_a_tls12_server() {
    let server = server_chain(KeyType::EcdsaP256);
    for (offer, completes) in [
        (ML_DSA.to_vec(), false),
        (
            [&ML_DSA[..], &[SignatureScheme::ECDSA_NISTP256_SHA256]].concat(),
            true,
        ),
    ] {
        let resolver = RecordingServerResolver::new(certified_key(&server));
        let verifier =
            SchemeRecordingServerVerifier::new(PinnedServerVerifier::new(&server), &offer);
        let client = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let server_config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        let mut c = ClientConnection::new(Arc::new(client), server_name()).unwrap();
        let mut s = ServerConnection::new(Arc::new(server_config)).unwrap();
        if completes {
            do_handshake(&mut c, &mut s).unwrap();
            assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_2));
            assert_eq!(verifier.seen(), [SignatureScheme::ECDSA_NISTP256_SHA256]);
            assert_eq!(
                resolver.seen(),
                [vec![SignatureScheme::ECDSA_NISTP256_SHA256]]
            );
        } else {
            let (client_res, server_res) = crate::common::do_handshake_until_error(&mut c, &mut s);
            assert_eq!(
                server_res,
                Err(Error::PeerIncompatible(
                    PeerIncompatible::NoSignatureSchemesInCommon
                ))
            );
            assert_eq!(
                client_res,
                Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
            );
            assert!(resolver.seen().is_empty());
            assert!(verifier.seen().is_empty());
        }
    }
}

/// A TLS 1.2 ServerKeyExchange whose scheme is rewritten to `mldsa65`
/// (0x0905), which the client offered (for TLS 1.3): the client refuses it
/// with `illegal_parameter` before its verifier checks a signature.
#[test]
fn tls12_server_key_exchange_with_an_ml_dsa_scheme() {
    let server = server_chain(KeyType::EcdsaP256);
    let verifier = server_verifier(&server);
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap();
    let mut c = ClientConnection::new(Arc::new(client), server_name()).unwrap();
    let mut s = ServerConnection::new(Arc::new(server_config)).unwrap();
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut flight = take_flight(&mut s);
    let (_, msg) = find_message(&flight, 12).unwrap();
    // ECDHE parameters (RFC 8422 §5.4): curve type, named curve, point.
    let body = msg + 4;
    assert_eq!(flight[body], 3, "named_curve");
    let scheme_at = body + 3 + 1 + usize::from(flight[body + 3]);
    assert_eq!(
        u16_at(&flight, scheme_at),
        usize::from(u16::from(SignatureScheme::ECDSA_NISTP256_SHA256))
    );
    set_scheme(&mut flight, scheme_at, 0x0905);
    give(&mut c, &flight);
    assert_eq!(
        c.process_new_packets().map(|_| ()),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::SignedKxWithWrongAlgorithm
        ))
    );
    assert_eq!(fatal_alert(&take_flight(&mut c)), Some(ILLEGAL_PARAMETER));
    assert!(verifier.seen().is_empty());
}

/// A TLS 1.2 client CertificateVerify (plaintext, before
/// ChangeCipherSpec) whose scheme is rewritten to `mldsa65`, to a server
/// whose client verifier advertises ML-DSA: the TLS 1.2 CertificateRequest
/// did not list it, so the server refuses it with `illegal_parameter`
/// before its verifier checks a signature.
#[test]
fn tls12_client_certificate_verify_with_an_ml_dsa_scheme() {
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::EcdsaP256);
    let client_verifier = client_verifier(&client, true);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server))
        .with_client_auth_cert(client.cert_chain(), client.private_key())
        .unwrap();
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_client_cert_verifier(client_verifier.clone())
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap();
    let mut c = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut s = ServerConnection::new(Arc::new(server_config)).unwrap();
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    transfer(&mut s, &mut c);
    c.process_new_packets().unwrap();
    let mut flight = take_flight(&mut c);
    let (_, msg) = find_message(&flight, 15).expect("CertificateVerify");
    set_scheme(&mut flight, msg + 4, 0x0905);
    give(&mut s, &flight);
    assert_eq!(
        s.process_new_packets().map(|_| ()),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme
        ))
    );
    assert_eq!(fatal_alert(&take_flight(&mut s)), Some(ILLEGAL_PARAMETER));
    assert!(client_verifier.seen().is_empty());
}

/// The ML-DSA code points count as ML-DSA when a verifier names them as
/// `SignatureScheme::Unknown` values: a TLS 1.2-only ClientHello and a
/// TLS 1.2 CertificateRequest leave 0x0905 out, a hello offering TLS 1.3
/// keeps it.
#[test]
fn ml_dsa_code_points_as_unknown_values() {
    let unknown = SignatureScheme::Unknown(0x0905);
    let mut offer = default_schemes();
    offer.push(unknown);
    let has_0905 = |schemes: &[SignatureScheme]| schemes.iter().any(|s| u16::from(*s) == 0x0905);
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::EcdsaP256);
    for (versions, kept) in [
        (&[&version::TLS12][..], false),
        (&[&version::TLS13, &version::TLS12][..], true),
    ] {
        let verifier =
            SchemeRecordingServerVerifier::new(PinnedServerVerifier::new(&server), &offer);
        let config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let mut c = ClientConnection::new(Arc::new(config), server_name()).unwrap();
        let hello = take_flight(&mut c);
        let schemes = hello_schemes(&hello, EXT_SIGNATURE_ALGORITHMS).unwrap();
        assert_eq!(has_0905(&schemes), kept, "{versions:?}");
        assert_eq!(schemes.len(), default_schemes().len() + usize::from(kept));
    }

    let verifier =
        SchemeRecordingClientVerifier::new(PinnedClientVerifier::new(&client, true), &offer);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap();
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server))
        .with_no_client_auth();
    let mut c = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut s = ServerConnection::new(Arc::new(server_config)).unwrap();
    transfer(&mut c, &mut s);
    s.process_new_packets().unwrap();
    let mut flight = take_flight(&mut s);
    let listed = add_to_tls12_certificate_request(&mut flight, &[]);
    assert_eq!(listed, default_schemes());
}

/// A DTLS 1.2-only ClientHello lists no ML-DSA scheme its verifier
/// advertises; one that also offers DTLS 1.3 lists them all.
#[test]
fn dtls12_hello_lists_no_ml_dsa() {
    let server = server_chain(KeyType::EcdsaP256);
    for (versions, tls13) in [
        (dtls::Versions::V1_2, false),
        (dtls::Versions::V1_2And1_3, true),
        (dtls::Versions::V1_3, true),
    ] {
        let config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier(&server))
            .with_no_client_auth();
        let mut c =
            dtls::ClientConnection::new_with_versions(Arc::new(config), server_name(), versions)
                .unwrap();
        let mut datagram = Vec::new();
        assert!(c.write_datagram(&mut datagram, Duration::ZERO).unwrap());
        let schemes = dtls_hello_schemes(&datagram);
        if tls13 {
            assert_eq!(schemes, with_ml_dsa(), "{versions:?}");
        } else {
            assert_eq!(schemes, default_schemes(), "{versions:?}");
        }
    }
}
