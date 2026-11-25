//! TLS 1.2 signing and suite selection around the ML-DSA schemes: a
//! misbehaving key that returns an ML-DSA signer whatever it is offered, a
//! custom TLS 1.2 suite that lists an ML-DSA scheme, and the `Acceptor`
//! given a TLS 1.2-only ClientHello that names ML-DSA.

use std::sync::Arc;

use browntls_core::crypto::CipherSuiteCommon;
use browntls_core::server::Acceptor;
use browntls_core::sign::CertifiedKey;
use browntls_core::{
    AlertDescription, ClientConfig, ClientConnection, Error, PeerMisbehaved, ProtocolVersion,
    ServerConfig, ServerConnection, SignatureAlgorithm, SignatureScheme, SupportedCipherSuite,
    Tls12CipherSuite, version,
};

use crate::common::hello_wire::{fatal_alert, give, take_flight};
use crate::common::{
    Chain, KeyType, PinnedServerVerifier, client_chain, do_handshake_until_error, provider,
    server_chain, server_name,
};
use crate::doubles::*;
use crate::tls12_wire::{ILLEGAL_PARAMETER, find_message, set_hello_schemes, set_scheme};

const TLS13_ONLY: &str = "signing key chose a TLS 1.3-only signature scheme";

fn certified_key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

/// A TLS 1.2 server whose ECDSA-family key ignores the (ML-DSA-free) list
/// it is offered for the ServerKeyExchange and returns an `mldsa65`
/// signer: the server refuses that signer before it signs, with
/// `internal_error`.
#[test]
fn tls12_server_key_choosing_ml_dsa_anyway() {
    let server = server_chain(KeyType::EcdsaP256);
    let key = ClaimingKey::ignoring_offer(SignatureScheme::ML_DSA_65, SignatureAlgorithm::ECDSA);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_certified_key(CertifiedKey::new(server.cert_chain(), key.clone()));
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(&server))
        .with_no_client_auth();
    let mut c = ClientConnection::new(Arc::new(client), server_name()).unwrap();
    let mut s = ServerConnection::new(Arc::new(server_config)).unwrap();
    let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
    assert_eq!(server_res, Err(Error::General(TLS13_ONLY.into())));
    assert_eq!(
        client_res,
        Err(Error::AlertReceived(AlertDescription::InternalError))
    );
    // The server's probe of the key's curve (one ECDSA scheme), then the
    // ServerKeyExchange offer.
    let offered = key.offered();
    assert_eq!(offered.len(), 2, "{offered:?}");
    assert_eq!(offered[0], [SignatureScheme::ECDSA_NISTP256_SHA256]);
    assert!(
        !offered[1].is_empty() && !has_any_ml_dsa(&offered[1]),
        "{offered:?}"
    );
}

/// A TLS 1.2 client whose ECDSA-family key ignores the (ML-DSA-free) list
/// of a CertificateRequest and returns an `mldsa65` signer: the client
/// refuses that signer before it signs its CertificateVerify, with
/// `internal_error`.
#[test]
fn tls12_client_key_choosing_ml_dsa_anyway() {
    let server = server_chain(KeyType::EcdsaP256);
    let client = client_chain(KeyType::EcdsaP256);
    let key = ClaimingKey::ignoring_offer(SignatureScheme::ML_DSA_65, SignatureAlgorithm::ECDSA);
    let resolver =
        RecordingClientResolver::new(Some(CertifiedKey::new(client.cert_chain(), key.clone())));
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server))
        .with_client_cert_resolver(resolver.clone());
    let verifier = client_verifier(&client, true);
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(server.cert_chain(), server.private_key())
        .unwrap();
    let mut c = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut s = ServerConnection::new(Arc::new(server_config)).unwrap();
    let (client_res, server_res) = do_handshake_until_error(&mut c, &mut s);
    assert_eq!(client_res, Err(Error::General(TLS13_ONLY.into())));
    assert_eq!(
        server_res,
        Err(Error::AlertReceived(AlertDescription::InternalError))
    );
    let offered = key.offered();
    assert_eq!(offered.len(), 1);
    assert!(
        !offered[0].is_empty() && !has_any_ml_dsa(&offered[0]),
        "{offered:?}"
    );
    assert_eq!(resolver.seen(), offered);
    assert!(verifier.seen().is_empty());
}

/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` of the provider with `mldsa65`
/// added to the schemes it may be signed with. `Tls12CipherSuite` has only
/// public fields, so a provider (here, a test) can build such a suite.
fn suite_signing_with_ml_dsa() -> SupportedCipherSuite {
    let SupportedCipherSuite::Tls12(base) =
        crate::prov::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    else {
        panic!("a TLS 1.2 suite")
    };
    let sign: &'static [SignatureScheme] = Box::leak(Box::new([
        SignatureScheme::ML_DSA_65,
        SignatureScheme::ECDSA_NISTP256_SHA256,
    ]));
    SupportedCipherSuite::Tls12(Box::leak(Box::new(Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        prf_provider: base.prf_provider,
        kx: base.kx,
        sign,
        record: base.record,
    })))
}

/// A client whose TLS 1.2 suite lists `mldsa65` among its signature
/// schemes, and which offered `mldsa65` (for TLS 1.3) in its hello, still
/// refuses a TLS 1.2 ServerKeyExchange whose scheme is rewritten to
/// `mldsa65`, with `illegal_parameter`, before its verifier checks a
/// signature.
#[test]
fn tls12_suite_listing_ml_dsa_does_not_admit_it() {
    let server = server_chain(KeyType::EcdsaP256);
    let verifier = server_verifier(&server);
    let mut client_provider = Arc::unwrap_or_clone(provider());
    client_provider
        .cipher_suites
        .retain(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)));
    client_provider
        .cipher_suites
        .insert(0, suite_signing_with_ml_dsa());
    let client = ClientConfig::builder_with_provider(Arc::new(client_provider))
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
    let hello = take_flight(&mut c);
    assert_eq!(
        hello_schemes(&hello, EXT_SIGNATURE_ALGORITHMS).unwrap(),
        with_ml_dsa()
    );
    give(&mut s, &hello);
    s.process_new_packets().unwrap();
    let mut flight = take_flight(&mut s);
    let (_, msg) = find_message(&flight, 12).expect("ServerKeyExchange");
    // ECDHE parameters (RFC 8422 §5.4): curve type, named curve, point.
    let body = msg + 4;
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

/// The `Acceptor` shows a TLS 1.2-only ClientHello's raw
/// `signature_algorithms`, ML-DSA schemes included; once the connection is
/// configured for TLS 1.2 only, the certificate resolver sees the
/// classical schemes alone.
#[test]
fn acceptor_with_a_tls12_hello_naming_ml_dsa() {
    let server = server_chain(KeyType::EcdsaP256);
    let raw = [
        SignatureScheme::ML_DSA_65,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ML_DSA_44,
        SignatureScheme::ED25519,
        SignatureScheme::ML_DSA_87,
    ];
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(&server))
        .with_no_client_auth();
    let mut c = ClientConnection::new(Arc::new(client), server_name()).unwrap();
    let mut hello = take_flight(&mut c);
    set_hello_schemes(&mut hello, &raw);

    let mut acceptor = Acceptor::default();
    acceptor.read_tls(&mut &hello[..]).unwrap();
    let accepted = acceptor.accept().unwrap().expect("a whole ClientHello");
    assert_eq!(accepted.client_hello().signature_schemes(), raw);

    let resolver = RecordingServerResolver::new(certified_key(&server));
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    let mut s = accepted.into_connection(Arc::new(config)).unwrap();
    s.process_new_packets().unwrap();
    let seen = resolver.seen();
    assert_eq!(
        seen,
        [vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]]
    );
    let flight = take_flight(&mut s);
    assert!(find_message(&flight, 12).is_some(), "ServerKeyExchange");
    // The server signed with the classical scheme; the client (whose own
    // hello was altered, so the transcripts differ later) accepts it.
    give(&mut c, &flight);
    c.process_new_packets().unwrap();
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_2));
}
