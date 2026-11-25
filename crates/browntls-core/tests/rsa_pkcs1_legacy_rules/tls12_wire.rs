//! TLS 1.2 peers that sign "with" a legacy scheme, by rewriting the scheme
//! of a plaintext ServerKeyExchange or client CertificateVerify on the
//! wire. The legacy schemes are not for TLS 1.2 (RFC 9963 §3), so each is
//! refused before a verifier checks a signature, even when that verifier
//! advertises the scheme.

use std::sync::Arc;

use browntls_core::{
    ClientConfig, ClientConnection, Error, PeerMisbehaved, ServerConfig, ServerConnection,
    SignatureScheme, version,
};

use crate::common::hello_wire::{fatal_alert, give, take_flight};
use crate::common::{
    KeyType, PinnedServerVerifier, client_chain, provider, server_chain, server_name, transfer,
};
use crate::doubles::*;
use crate::legacy::*;

/// A TLS 1.2 ServerKeyExchange whose scheme is rewritten to a legacy code
/// point, to a client (offering TLS 1.3 and 1.2) whose verifier advertises
/// the legacy schemes: the hello did not list it, so the client refuses it
/// with `illegal_parameter` before its verifier checks a signature.
#[test]
fn tls12_server_key_exchange_with_a_legacy_scheme() {
    let server = server_chain(KeyType::EcdsaP256);
    for code in LEGACY_CODES {
        let verifier = legacy_server_verifier(&server);
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
        set_scheme(&mut flight, scheme_at, code);
        give(&mut c, &flight);
        assert_eq!(
            c.process_new_packets().map(|_| ()),
            Err(Error::PeerMisbehaved(
                PeerMisbehaved::SignedKxWithWrongAlgorithm
            )),
            "{code:#06x}"
        );
        assert_eq!(fatal_alert(&take_flight(&mut c)), Some(ILLEGAL_PARAMETER));
        assert!(verifier.seen().is_empty());
    }
}

/// A TLS 1.2 client CertificateVerify (plaintext, before
/// ChangeCipherSpec) whose scheme is rewritten to a legacy code point, to a
/// server whose client verifier advertises the legacy schemes: the TLS 1.2
/// CertificateRequest did not list it, so the server refuses it with
/// `illegal_parameter` before its verifier checks a signature.
#[test]
fn tls12_client_certificate_verify_with_a_legacy_scheme() {
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::EcdsaP256);
    for code in LEGACY_CODES {
        let client_verifier = legacy_client_verifier(&client, true);
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
        assert_eq!(
            u16_at(&flight, msg + 4),
            usize::from(u16::from(SignatureScheme::ECDSA_NISTP256_SHA256))
        );
        set_scheme(&mut flight, msg + 4, code);
        give(&mut s, &flight);
        assert_eq!(
            s.process_new_packets().map(|_| ()),
            Err(Error::PeerMisbehaved(
                PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme
            )),
            "{code:#06x}"
        );
        assert_eq!(fatal_alert(&take_flight(&mut s)), Some(ILLEGAL_PARAMETER));
        assert!(client_verifier.seen().is_empty());
    }
}
