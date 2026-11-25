//! Exported authenticators (RFC 9261) and delegated credentials (RFC 9345)
//! on a TLS 1.3 connection whose verifiers advertise ML-DSA: neither
//! requests, offers nor signs with an ML-DSA scheme.

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

fn certified_key(chain: &Chain) -> CertifiedKey {
    CertifiedKey::from_der(chain.cert_chain(), chain.private_key(), &provider()).unwrap()
}

struct Setup {
    server_chain: Chain,
    client_chain: Chain,
    client: ClientConnection,
    server: ServerConnection,
}

/// A TLS 1.3 connection whose two verifiers advertise ML-DSA; the server
/// does not ask for a client certificate in the handshake.
fn setup() -> Setup {
    let server_chain = server_chain(KeyType::EcdsaP256);
    let client_chain = client_chain(KeyType::Ed25519);
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(&server_chain))
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_client_cert_verifier(client_verifier(&client_chain, false))
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

/// Requests built from the verifiers' schemes carry no ML-DSA scheme, and
/// authenticators with classical keys still work both ways.
#[test]
fn authenticator_requests_leave_ml_dsa_out() {
    let mut s = setup();
    let default = AuthenticatorRequestExtensions::default();

    let request = s.client.request_authenticator(b"client", &default).unwrap();
    let schemes = request_schemes(&request);
    assert!(
        !schemes.is_empty() && !has_any_ml_dsa(&schemes),
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
        !schemes.is_empty() && !has_any_ml_dsa(&schemes),
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

    // Asked for explicitly, ML-DSA is dropped too: alone it leaves
    // nothing to request.
    let explicit = |schemes: Vec<SignatureScheme>| AuthenticatorRequestExtensions {
        signature_schemes: Some(schemes),
        certificate_authorities: None,
    };
    assert!(matches!(
        s.client
            .request_authenticator(b"only ml-dsa", &explicit(ML_DSA.to_vec())),
        Err(Error::General(_))
    ));
    assert!(matches!(
        s.server
            .request_authenticator(b"only ml-dsa", &explicit(ML_DSA.to_vec())),
        Err(Error::General(_))
    ));
    let request = s
        .server
        .request_authenticator(
            b"mixed",
            &explicit(vec![SignatureScheme::ML_DSA_65, SignatureScheme::ED25519]),
        )
        .unwrap();
    assert_eq!(request_schemes(&request), [SignatureScheme::ED25519]);
}

/// A key that claims an ML-DSA scheme is never offered one: not for a
/// spontaneous server authenticator (whose schemes come from the
/// ClientHello, which listed ML-DSA), and not when a peer's request lists
/// ML-DSA. The key then declines, and nothing is signed.
#[test]
fn authenticators_never_offer_ml_dsa_to_a_key() {
    let mut s = setup();
    let key = ClaimingKey::new(
        SignatureScheme::ML_DSA_65,
        SignatureAlgorithm::Unknown(0xff),
    );
    let claiming = CertifiedKey::new(s.server_chain.cert_chain(), key.clone());
    assert_eq!(
        s.server.authenticator(None, Some(&claiming)),
        Err(Error::General(
            "a spontaneous authenticator needs a certificate whose key can sign with a \
             scheme the client offered"
                .into()
        ))
    );
    let offered = key.offered();
    assert_eq!(offered.len(), 1);
    assert!(
        !offered[0].is_empty() && !has_any_ml_dsa(&offered[0]),
        "{offered:?}"
    );

    // A server request (a TLS 1.3 CertificateRequest, type 13) from a peer
    // that lists ML-DSA: the client's key sees only the other scheme and
    // declines with an empty authenticator (a lone Finished, type 20).
    let key = ClaimingKey::new(
        SignatureScheme::ML_DSA_65,
        SignatureAlgorithm::Unknown(0xff),
    );
    let claiming = CertifiedKey::new(s.client_chain.cert_chain(), key.clone());
    let request = raw_request(
        13,
        b"peer",
        &[SignatureScheme::ML_DSA_65, SignatureScheme::ED25519],
    );
    let auth = s.client.authenticator(&request, Some(&claiming)).unwrap();
    assert_eq!(auth[0], 20);
    assert_eq!(key.offered(), [vec![SignatureScheme::ED25519]]);

    // A request listing ML-DSA only leaves nothing to offer the key.
    let key = ClaimingKey::new(
        SignatureScheme::ML_DSA_65,
        SignatureAlgorithm::Unknown(0xff),
    );
    let claiming = CertifiedKey::new(s.server_chain.cert_chain(), key.clone());
    let request = raw_request(17, b"peer", &[SignatureScheme::ML_DSA_65]);
    let auth = s
        .server
        .authenticator(Some(&request), Some(&claiming))
        .unwrap();
    assert_eq!(auth[0], 20, "declined");
    assert_eq!(key.offered(), [Vec::<SignatureScheme>::new()]);
}

/// The client's `delegated_credential` extension (RFC 9345 §4.1.1) lists
/// none of the ML-DSA schemes its verifier advertises, while the
/// `signature_algorithms` of the same hello lists them all.
#[test]
fn delegated_credential_extension_leaves_ml_dsa_out() {
    let server = server_chain(KeyType::EcdsaP256);
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(&server))
        .with_no_client_auth();
    config.enable_delegated_credentials = true;
    let mut c = ClientConnection::new(Arc::new(config), server_name()).unwrap();
    let hello = take_flight(&mut c);
    assert_eq!(
        hello_schemes(&hello, EXT_SIGNATURE_ALGORITHMS).unwrap(),
        with_ml_dsa()
    );
    let dc = hello_schemes(&hello, EXT_DELEGATED_CREDENTIAL).unwrap();
    assert!(!dc.is_empty() && !has_any_ml_dsa(&dc), "{dc:?}");
    for scheme in ML_DSA {
        assert!(!credential_scheme_allowed(scheme), "{scheme:?}");
    }
}

/// No delegated credential is issued with an ML-DSA credential key, nor
/// signed by a certificate key with an ML-DSA scheme: such a key is not
/// even offered the scheme.
#[test]
fn delegated_credentials_are_not_issued_with_ml_dsa() {
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
    for scheme in ML_DSA {
        assert_eq!(
            DelegatedCredential::issue(
                Side::Server,
                &chain.end_entity,
                &*cert_key,
                KeyType::EcdsaP256.schemes(),
                credential(scheme),
            )
            .unwrap_err(),
            Error::from(AttachmentError::UnsupportedScheme)
        );
    }

    let key = ClaimingKey::new(
        SignatureScheme::ML_DSA_65,
        SignatureAlgorithm::Unknown(0xff),
    );
    assert!(matches!(
        DelegatedCredential::issue(
            Side::Server,
            &chain.end_entity,
            &*key,
            &ML_DSA,
            credential(SignatureScheme::ED25519),
        ),
        Err(Error::General(_))
    ));
    assert_eq!(key.offered(), [Vec::<SignatureScheme>::new()]);
}
