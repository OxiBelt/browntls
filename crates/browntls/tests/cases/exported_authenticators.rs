// Shared cases, included by `tests/exported_authenticators.rs` (RustCrypto
// provider) and `tests/exported_authenticators_native.rs` (native
// provider): RFC 9261 exported authenticators between a browntls client and
// server (no other implementation the project tests against exposes them).

use std::sync::Arc;

use browntls::exported_authenticator::{AuthenticatorRequestExtensions, authenticator_context};
use browntls::sign::CertifiedKey;
use browntls::{
    ClientConfig, ClientConnection, Error, PeerMisbehaved, ProtocolVersion, ServerConfig,
    ServerConnection, SignatureScheme, SupportedProtocolVersion, version,
};
use common::*;

struct Setup {
    server_chain: Chain,
    client_chain: Chain,
    client: ClientConnection,
    server: ServerConnection,
}

/// A connection over `versions` whose server verifies `client_chain` (not
/// requested in the handshake) and whose client pins `server_chain`.
fn setup(versions: &[&'static SupportedProtocolVersion]) -> Setup {
    init_logging();
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(&server_chain))
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_client_cert_verifier(PinnedClientVerifier::new(&client_chain, false))
        .with_single_cert(server_chain.cert_chain(), server_chain.private_key())
        .unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    do_handshake(&mut client, &mut server).unwrap();
    Setup {
        server_chain,
        client_chain,
        client,
        server,
    }
}

fn key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

/// The protocol versions to run each round trip over: TLS 1.3, and TLS 1.2
/// (with extended master secret) when built.
fn versions() -> Vec<&'static [&'static SupportedProtocolVersion]> {
    static TLS13: &[&SupportedProtocolVersion] = &[&version::TLS13];
    #[cfg(feature = "tls12")]
    static TLS12: &[&SupportedProtocolVersion] = &[&version::TLS12];
    vec![
        TLS13,
        #[cfg(feature = "tls12")]
        TLS12,
    ]
}

fn tls13() -> Setup {
    setup(&[&version::TLS13])
}

#[test]
fn server_authenticates_on_client_request() {
    for versions in versions() {
        let mut s = setup(versions);
        let request = s
            .client
            .request_authenticator(
                b"client context 1",
                &AuthenticatorRequestExtensions::default(),
            )
            .unwrap();
        // A ClientCertificateRequest (handshake type 17).
        assert_eq!(request[0], 17);
        let auth = s
            .server
            .authenticator(Some(&request), Some(&key(&s.server_chain)))
            .unwrap();
        assert_eq!(authenticator_context(&auth).unwrap(), b"client context 1");
        let chain = s
            .client
            .validate_authenticator(Some(&request), &auth)
            .unwrap()
            .unwrap();
        assert_eq!(chain, s.server_chain.cert_chain(), "{versions:?}");
    }
}

#[test]
fn client_authenticates_on_server_request() {
    for versions in versions() {
        let mut s = setup(versions);
        let request = s
            .server
            .request_authenticator(
                b"server context",
                &AuthenticatorRequestExtensions {
                    signature_schemes: Some(vec![SignatureScheme::ED25519]),
                    certificate_authorities: None,
                },
            )
            .unwrap();
        // A TLS 1.3 CertificateRequest (handshake type 13).
        assert_eq!(request[0], 13);
        let auth = s
            .client
            .authenticator(&request, Some(&key(&s.client_chain)))
            .unwrap();
        let chain = s
            .server
            .validate_authenticator(&request, &auth)
            .unwrap()
            .unwrap();
        assert_eq!(chain, s.client_chain.cert_chain(), "{versions:?}");
    }
}

#[test]
fn spontaneous_server_authenticator() {
    let mut s = tls13();
    let auth = s
        .server
        .authenticator(None, Some(&key(&s.server_chain)))
        .unwrap();
    let context = authenticator_context(&auth).unwrap();
    assert_eq!(context.len(), 32);
    let chain = s
        .client
        .validate_authenticator(None, &auth)
        .unwrap()
        .unwrap();
    assert_eq!(chain, s.server_chain.cert_chain());
    // Accepted once only.
    assert_eq!(
        s.client.validate_authenticator(None, &auth),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::ReusedAuthenticatorContext
        ))
    );
    // A spontaneous authenticator needs a certificate.
    assert!(s.server.authenticator(None, None).is_err());
}

#[test]
fn declining_with_an_empty_authenticator() {
    let mut s = tls13();
    let request = s
        .server
        .request_authenticator(b"ctx", &AuthenticatorRequestExtensions::default())
        .unwrap();
    let auth = s.client.authenticator(&request, None).unwrap();
    // A lone Finished (handshake type 20).
    assert_eq!(auth[0], 20);
    assert!(authenticator_context(&auth).is_err());
    assert_eq!(s.server.validate_authenticator(&request, &auth), Ok(None));

    // A key that cannot sign with any requested scheme also declines.
    let mut s = tls13();
    let request = s
        .server
        .request_authenticator(
            b"ctx",
            &AuthenticatorRequestExtensions {
                signature_schemes: Some(vec![SignatureScheme::ECDSA_NISTP384_SHA384]),
                certificate_authorities: None,
            },
        )
        .unwrap();
    let auth = s
        .client
        .authenticator(&request, Some(&key(&s.client_chain)))
        .unwrap();
    assert_eq!(auth[0], 20);
    assert_eq!(s.server.validate_authenticator(&request, &auth), Ok(None));
}

#[test]
fn tampering_is_detected() {
    let s = tls13();
    let server_key = key(&s.server_chain);
    let mut s = s;
    let request = s
        .client
        .request_authenticator(b"tamper", &AuthenticatorRequestExtensions::default())
        .unwrap();
    let auth = s
        .server
        .authenticator(Some(&request), Some(&server_key))
        .unwrap();
    // Flip one bit at a time across the whole authenticator: every
    // variant is rejected, without consuming the context.
    for i in 0..auth.len() {
        let mut bad = auth.clone();
        bad[i] ^= 0x01;
        assert!(
            s.client
                .validate_authenticator(Some(&request), &bad)
                .is_err(),
            "byte {i}"
        );
    }
    // Truncated and extended.
    assert!(
        s.client
            .validate_authenticator(Some(&request), &auth[..auth.len() - 1])
            .is_err()
    );
    let mut long = auth.clone();
    long.push(0);
    assert!(
        s.client
            .validate_authenticator(Some(&request), &long)
            .is_err()
    );
    // The genuine one still validates.
    assert!(
        s.client
            .validate_authenticator(Some(&request), &auth)
            .unwrap()
            .is_some()
    );
}

#[test]
fn bound_to_request_and_connection() {
    let mut s = tls13();
    let server_key = key(&s.server_chain);
    let first = s
        .client
        .request_authenticator(b"first", &AuthenticatorRequestExtensions::default())
        .unwrap();
    let second = s
        .client
        .request_authenticator(b"second", &AuthenticatorRequestExtensions::default())
        .unwrap();
    let auth = s
        .server
        .authenticator(Some(&first), Some(&server_key))
        .unwrap();
    // Against another request: wrong context.
    assert_eq!(
        s.client.validate_authenticator(Some(&second), &auth),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalCertificateRequestContext
        ))
    );
    // On another connection with the same request bytes: the exporter
    // differs, so Finished does not verify.
    let mut other = tls13();
    let other_request = other
        .client
        .request_authenticator(b"first", &AuthenticatorRequestExtensions::default())
        .unwrap();
    assert_eq!(other_request, first);
    assert_eq!(
        other.client.validate_authenticator(Some(&first), &auth),
        Err(Error::DecryptError)
    );
    // A request is answered once, and a context is requested once.
    assert!(s.client.validate_authenticator(Some(&first), &auth).is_ok());
    assert!(
        s.server
            .authenticator(Some(&first), Some(&server_key))
            .is_err()
    );
    assert!(
        s.client
            .request_authenticator(b"first", &AuthenticatorRequestExtensions::default())
            .is_err()
    );
    // The client's request goes to the server, not to the client itself.
    assert!(
        s.client
            .authenticator(&second, Some(&key(&s.client_chain)))
            .is_err()
    );
}

#[test]
fn verified_by_configured_verifier() {
    let mut s = tls13();
    // A certificate the client's pinned verifier does not accept.
    let other = server_chain(KeyType::EcdsaP256);
    let request = s
        .client
        .request_authenticator(b"other", &AuthenticatorRequestExtensions::default())
        .unwrap();
    let auth = s
        .server
        .authenticator(Some(&request), Some(&key(&other)))
        .unwrap();
    assert_eq!(
        s.client.validate_authenticator(Some(&request), &auth),
        Err(Error::InvalidCertificate(
            browntls::CertificateError::UnknownIssuer
        ))
    );
}

#[test]
fn needs_an_established_connection() {
    let chain = server_chain(KeyType::EcdsaP256);
    let mut client = ClientConnection::new(Arc::new(client_config(&chain)), server_name()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(&chain))).unwrap();
    let request = client
        .request_authenticator(b"early", &AuthenticatorRequestExtensions::default())
        .unwrap();
    assert!(
        server
            .authenticator(Some(&request), Some(&key(&chain)))
            .is_err()
    );
    assert!(server.authenticator(None, Some(&key(&chain))).is_err());
    assert_eq!(
        client.authenticator(&request, None),
        Err(Error::HandshakeNotComplete)
    );
    do_handshake(&mut client, &mut server).unwrap();
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
}

#[test]
fn malformed_requests_are_rejected() {
    let mut s = tls13();
    let server_key = key(&s.server_chain);
    for bad in [
        &[][..],
        &[17, 0, 0][..],
        // Empty body.
        &[17, 0, 0, 0][..],
        // Empty context, empty extensions.
        &[17, 0, 0, 3, 0, 0, 0][..],
        // Context "x", no signature_algorithms.
        &[17, 0, 0, 4, 1, b'x', 0, 0][..],
        // Length beyond the input.
        &[17, 0, 0, 9, 1, b'x', 0, 0][..],
    ] {
        assert!(
            s.server
                .authenticator(Some(bad), Some(&server_key))
                .is_err(),
            "{bad:?}"
        );
    }
    assert!(
        s.client
            .request_authenticator(b"", &AuthenticatorRequestExtensions::default())
            .is_err()
    );
    assert!(
        s.client
            .request_authenticator(&[0; 256], &AuthenticatorRequestExtensions::default())
            .is_err()
    );
}
