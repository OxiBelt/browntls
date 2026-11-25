//! What a ClientHello lists of the legacy schemes its verifier advertises:
//! none of them, for any version it offers, over TLS and DTLS, whether the
//! verifier names them or gives their code points as `Unknown` values.

use std::sync::Arc;
use std::time::Duration;

use browntls_core::{
    ClientConfig, ClientConnection, SignatureScheme, SupportedProtocolVersion, dtls, version,
};

use crate::common::hello_wire::take_flight;
use crate::common::{
    KeyType, PinnedServerVerifier, SchemeRecordingServerVerifier, provider, server_chain,
    server_name,
};
use crate::doubles::*;
use crate::legacy::*;

const VERSIONS: [&[&SupportedProtocolVersion]; 3] = [
    &[&version::TLS12],
    &[&version::TLS13],
    &[&version::TLS13, &version::TLS12],
];

/// The `signature_algorithms` of the first hello of a client over
/// `versions` whose verifier lists `offer`.
fn hello_offering(
    versions: &[&'static SupportedProtocolVersion],
    offer: &[SignatureScheme],
) -> Vec<SignatureScheme> {
    let server = server_chain(KeyType::EcdsaP256);
    let verifier = SchemeRecordingServerVerifier::new(PinnedServerVerifier::new(&server), offer);
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut c = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    hello_schemes(&take_flight(&mut c), EXT_SIGNATURE_ALGORITHMS).unwrap()
}

/// RFC 9963 §3: a ClientHello never lists a legacy scheme, since that
/// would invite the server to sign with it. Whether the hello offers
/// TLS 1.2 only, TLS 1.3 only or both, its `signature_algorithms` is what
/// the default schemes alone give.
#[test]
fn client_hello_never_lists_legacy() {
    for versions in VERSIONS {
        let schemes = hello_offering(versions, &with_legacy());
        assert!(!has_any_legacy(&schemes), "{versions:?}: {schemes:?}");
        assert_eq!(schemes, default_schemes(), "{versions:?}");
        assert_eq!(
            schemes,
            hello_offering(versions, &default_schemes()),
            "{versions:?}"
        );
    }
}

/// The legacy schemes alone with one classical scheme: the hello lists the
/// classical scheme only, wherever the verifier puts the legacy ones.
#[test]
fn client_hello_drops_legacy_around_a_classical_scheme() {
    let offer = [
        SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PKCS1_SHA512_LEGACY,
        SignatureScheme::RSA_PKCS1_SHA384_LEGACY,
    ];
    for versions in VERSIONS {
        assert_eq!(
            hello_offering(versions, &offer),
            [SignatureScheme::ECDSA_NISTP256_SHA256],
            "{versions:?}"
        );
    }
}

/// A DTLS ClientHello lists no legacy scheme either, for DTLS 1.2 only,
/// DTLS 1.3 only and both.
#[test]
fn dtls_hello_never_lists_legacy() {
    let server = server_chain(KeyType::EcdsaP256);
    for versions in [
        dtls::Versions::V1_2,
        dtls::Versions::V1_2And1_3,
        dtls::Versions::V1_3,
    ] {
        let config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(legacy_server_verifier(&server))
            .with_no_client_auth();
        let mut c =
            dtls::ClientConnection::new_with_versions(Arc::new(config), server_name(), versions)
                .unwrap();
        let mut datagram = Vec::new();
        assert!(c.write_datagram(&mut datagram, Duration::ZERO).unwrap());
        let schemes = dtls_hello_schemes(&datagram);
        assert!(!has_any_legacy(&schemes), "{versions:?}: {schemes:?}");
        assert_eq!(schemes, default_schemes(), "{versions:?}");
    }
}

/// The code point decides: a verifier that gives the legacy code points as
/// `SignatureScheme::Unknown` values gets the same hello, for every
/// version, as one that names them.
#[test]
fn legacy_code_points_as_unknown_values_in_a_hello() {
    let mut offer = default_schemes();
    offer.extend(LEGACY_AS_UNKNOWN);
    for versions in VERSIONS {
        let schemes = hello_offering(versions, &offer);
        assert!(!has_any_legacy(&schemes), "{versions:?}: {schemes:?}");
        assert_eq!(schemes, default_schemes(), "{versions:?}");
    }
}
