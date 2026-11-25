//! Exported authenticators (RFC 9261) and delegated credentials (RFC 9345)
//! on a TLS 1.3 connection whose verifiers advertise the legacy schemes:
//! neither requests, offers nor signs with one (RFC 9963 §3 defines them
//! for the client's handshake CertificateVerify only).

use std::sync::Arc;

use browntls_core::delegated_credential::{
    AttachmentError, Credential, DelegatedCredential, credential_scheme_allowed,
};
use browntls_core::exported_authenticator::AuthenticatorRequestExtensions;
use browntls_core::sign::CertifiedKey;
use browntls_core::{
    ClientConfig, ClientConnection, Error, ServerConfig, ServerConnection, Side,
    SignatureAlgorithm, SignatureScheme, version,
};

use crate::common::hello_wire::take_flight;
use crate::common::{
    Chain, KeyType, client_chain, delegation_server_chain, do_handshake, provider, server_chain,
    server_name,
};
use crate::doubles::*;
use crate::legacy::*;

fn certified_key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

struct Setup {
    server_chain: Chain,
    client_chain: Chain,
    client: ClientConnection,
    server: ServerConnection,
}

/// A TLS 1.3 connection whose two verifiers advertise the legacy schemes;
/// the server does not ask for a client certificate in the handshake.
fn setup() -> Setup {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(legacy_server_verifier(&server_chain))
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_client_cert_verifier(legacy_client_verifier(&client_chain, false))
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

/// A key claiming `claims` whose TLS 1.2 family no suite has.
fn claiming(claims: SignatureScheme) -> Arc<ClaimingKey> {
    ClaimingKey::new(claims, SignatureAlgorithm::Unknown(0xff))
}

/// Requests built from the verifiers' schemes carry no legacy scheme, and
/// authenticators with classical keys still work both ways. Asked for
/// explicitly, the legacy schemes are dropped too: alone they leave
/// nothing to request.
#[test]
fn authenticator_requests_leave_legacy_out() {
    let mut s = setup();
    let default = AuthenticatorRequestExtensions::default();

    let request = s.client.request_authenticator(b"client", &default).unwrap();
    let schemes = request_schemes(&request);
    assert!(
        !schemes.is_empty() && !has_any_legacy(&schemes),
        "{schemes:?}"
    );
    let auth = s
        .server
        .authenticator(Some(&request), Some(&certified_key(&s.server_chain)))
        .unwrap();
    let chain = s
        .client
        .validate_authenticator(Some(&request), &auth)
        .unwrap()
        .unwrap();
    assert_eq!(chain, s.server_chain.cert_chain());

    let request = s.server.request_authenticator(b"server", &default).unwrap();
    let schemes = request_schemes(&request);
    assert!(
        !schemes.is_empty() && !has_any_legacy(&schemes),
        "{schemes:?}"
    );
    let auth = s
        .client
        .authenticator(&request, Some(&certified_key(&s.client_chain)))
        .unwrap();
    let chain = s
        .server
        .validate_authenticator(&request, &auth)
        .unwrap()
        .unwrap();
    assert_eq!(chain, s.client_chain.cert_chain());

    let explicit = |schemes: Vec<SignatureScheme>| AuthenticatorRequestExtensions {
        signature_schemes: Some(schemes),
        certificate_authorities: None,
    };
    for only in [LEGACY, LEGACY_AS_UNKNOWN] {
        assert!(matches!(
            s.client
                .request_authenticator(b"only legacy", &explicit(only.to_vec())),
            Err(Error::General(_))
        ));
        assert!(matches!(
            s.server
                .request_authenticator(b"only legacy", &explicit(only.to_vec())),
            Err(Error::General(_))
        ));
    }
    for requester in [true, false] {
        let mixed = explicit(vec![
            SignatureScheme::RSA_PKCS1_SHA256_LEGACY,
            SignatureScheme::ED25519,
            SignatureScheme::Unknown(0x0620),
        ]);
        let request = if requester {
            s.client.request_authenticator(b"mixed", &mixed)
        } else {
            s.server.request_authenticator(b"mixed", &mixed)
        }
        .unwrap();
        assert_eq!(request_schemes(&request), [SignatureScheme::ED25519]);
    }
}

/// A key that claims a legacy scheme is never offered one: not for a
/// spontaneous server authenticator (whose schemes come from the
/// ClientHello), and not when a peer's request lists the legacy schemes.
/// The key then declines, and nothing is signed. A raw request naming
/// only legacy schemes gets an empty authenticator.
#[test]
fn authenticators_never_offer_legacy_to_a_key() {
    let mut s = setup();
    let key = claiming(LEGACY[0]);
    let claimed = CertifiedKey::new(s.server_chain.cert_chain(), key.clone());
    assert_eq!(
        s.server.authenticator(None, Some(&claimed)),
        Err(Error::General(
            "a spontaneous authenticator needs a certificate whose key can sign with a \
             scheme the client offered"
                .into()
        ))
    );
    let offered = key.offered();
    assert_eq!(offered.len(), 1);
    assert!(
        !offered[0].is_empty() && !has_any_legacy(&offered[0]),
        "{offered:?}"
    );

    // A server request (a TLS 1.3 CertificateRequest, type 13) from a peer
    // that lists the legacy schemes: the client's key sees only the other
    // scheme and declines with an empty authenticator (a lone Finished,
    // type 20).
    let key = claiming(LEGACY[1]);
    let claimed = CertifiedKey::new(s.client_chain.cert_chain(), key.clone());
    let request = raw_request(
        13,
        b"peer",
        &[&LEGACY[..], &[SignatureScheme::ED25519]].concat(),
    );
    let auth = s.client.authenticator(&request, Some(&claimed)).unwrap();
    assert_eq!(auth[0], 20);
    assert_eq!(key.offered(), [vec![SignatureScheme::ED25519]]);

    // A client request (a ClientCertificateRequest, type 17) listing the
    // legacy schemes only leaves nothing to offer the key. Each request
    // has a context of its own (RFC 9261 §4).
    for (context, claims) in [(b"peer 1", LEGACY[2]), (b"peer 2", LEGACY_AS_UNKNOWN[2])] {
        let key = claiming(claims);
        let claimed = CertifiedKey::new(s.server_chain.cert_chain(), key.clone());
        let request = raw_request(17, context, &LEGACY);
        let auth = s
            .server
            .authenticator(Some(&request), Some(&claimed))
            .unwrap();
        assert_eq!(auth[0], 20, "declined");
        assert_eq!(key.offered(), [Vec::<SignatureScheme>::new()]);
    }
}

/// A key that returns a legacy signer whatever it is offered (its signer
/// panics if used) signs no authenticator: a spontaneous one fails, and
/// the answer to a request, from either side, is the empty authenticator.
/// The request each key saw listed no legacy scheme.
#[test]
fn authenticators_do_not_sign_with_an_unoffered_legacy_scheme() {
    let mut s = setup();
    for claims in [LEGACY[0], LEGACY_AS_UNKNOWN[1]] {
        let key = ClaimingKey::ignoring_offer(claims, SignatureAlgorithm::Unknown(0xff));
        let claimed = CertifiedKey::new(s.server_chain.cert_chain(), key.clone());
        assert_eq!(
            s.server.authenticator(None, Some(&claimed)),
            Err(Error::General(
                "a spontaneous authenticator needs a certificate whose key can sign with a \
                 scheme the client offered"
                    .into()
            )),
            "{claims:?}"
        );
        assert!(!has_any_legacy(&key.offered()[0]));
    }

    // A server's request (type 13) answered by the client, and a client's
    // (type 17) answered by the server: a lone Finished (type 20).
    let key = ClaimingKey::ignoring_offer(LEGACY[2], SignatureAlgorithm::Unknown(0xff));
    let claimed = CertifiedKey::new(s.client_chain.cert_chain(), key.clone());
    let request = raw_request(
        13,
        b"unoffered 1",
        &[&LEGACY[..], &[SignatureScheme::ED25519]].concat(),
    );
    let auth = s.client.authenticator(&request, Some(&claimed)).unwrap();
    assert_eq!(auth[0], 20, "declined");
    assert_eq!(key.offered(), [vec![SignatureScheme::ED25519]]);

    let key = ClaimingKey::ignoring_offer(LEGACY[0], SignatureAlgorithm::Unknown(0xff));
    let claimed = CertifiedKey::new(s.server_chain.cert_chain(), key.clone());
    let request = raw_request(17, b"unoffered 2", &[SignatureScheme::ED25519]);
    let auth = s
        .server
        .authenticator(Some(&request), Some(&claimed))
        .unwrap();
    assert_eq!(auth[0], 20, "declined");
    assert_eq!(key.offered(), [vec![SignatureScheme::ED25519]]);
}

/// The client's `delegated_credential` extension (RFC 9345 §4.1.1) lists
/// none of the legacy schemes its verifier advertises, nor does the
/// `signature_algorithms` of the same hello; and no legacy scheme, named
/// or `Unknown`, is one a credential may use.
#[test]
fn delegated_credential_extension_leaves_legacy_out() {
    let server = server_chain(KeyType::EcdsaP256);
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(legacy_server_verifier(&server))
        .with_no_client_auth();
    config.enable_delegated_credentials = true;
    let mut c = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    let hello = take_flight(&mut c);
    assert_eq!(
        hello_schemes(&hello, EXT_SIGNATURE_ALGORITHMS).unwrap(),
        default_schemes()
    );
    let dc = hello_schemes(&hello, EXT_DELEGATED_CREDENTIAL).unwrap();
    assert!(!dc.is_empty() && !has_any_legacy(&dc), "{dc:?}");
    for scheme in [LEGACY, LEGACY_AS_UNKNOWN].concat() {
        assert!(!credential_scheme_allowed(scheme), "{scheme:?}");
    }
}

/// No delegated credential is issued with a legacy credential scheme, nor
/// signed by a certificate key with a legacy scheme: such a key is not
/// even offered the scheme.
#[test]
fn delegated_credentials_are_not_issued_with_legacy() {
    let chain = delegation_server_chain(KeyType::EcdsaP256);
    let cert_key = provider()
        .key_provider
        .load_private_key(chain.private_key())
        .unwrap();
    let credential = |scheme| Credential {
        valid_time: 3600,
        dc_cert_verify_algorithm: scheme,
        public_key: chain.spki(),
    };
    for scheme in [LEGACY, LEGACY_AS_UNKNOWN].concat() {
        assert_eq!(
            DelegatedCredential::issue(
                Side::Server,
                &chain.end_entity,
                &*cert_key,
                KeyType::EcdsaP256.schemes(),
                credential(scheme),
            )
            .unwrap_err(),
            Error::from(AttachmentError::UnsupportedScheme),
            "{scheme:?}"
        );
    }

    let key = claiming(LEGACY[0]);
    assert!(matches!(
        DelegatedCredential::issue(
            Side::Server,
            &chain.end_entity,
            &*key,
            &LEGACY,
            credential(SignatureScheme::ED25519),
        ),
        Err(Error::General(_))
    ));
    assert_eq!(key.offered(), [Vec::<SignatureScheme>::new()]);
}
