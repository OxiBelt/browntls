// Cases included by `cases/mldsa_tls13.rs`, which holds the imports and the
// shared helpers: delegated credentials (RFC 9345) and exported
// authenticators (RFC 9261), which no specification defines for ML-DSA and
// which therefore never use it, alongside ML-DSA handshakes.

use browntls_core::delegated_credential::{AttachmentError, Credential, DelegatedCredential};
use browntls_core::exported_authenticator::AuthenticatorRequestExtensions;

/// `DelegationUsage` (RFC 9345 §4.2): 1.3.6.1.4.1.44363.44, NULL.
fn delegation_usage() -> Vec<u8> {
    x509::extension(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2c],
        false,
        &[0x05, 0x00],
    )
}

/// A server end entity of `ee` with `DelegationUsage`, under an ML-DSA-65
/// root, and its key.
fn delegation_certificate(ee: Alg) -> (CertificateDer<'static>, Held) {
    let root = Held::new(Alg::Ml(Set::MlDsa65), "delegation root");
    let key = Held::new(ee, "delegation end entity");
    let mut spec = x509::CertSpec::ee("end entity", "root", key.oracle());
    spec.extensions.push(delegation_usage());
    (CertificateDer::from(root.issuer().sign_cert(&spec)), key)
}

fn credential(scheme: SignatureScheme, public_key: Vec<u8>) -> Credential {
    Credential {
        valid_time: 3600,
        dc_cert_verify_algorithm: scheme,
        public_key: public_key.into(),
    }
}

/// A delegation certificate with an ML-DSA key signs no credential (its
/// key is not offered an ML-DSA scheme for that), while the same
/// certificate with an ECDSA key does.
#[test]
fn ml_dsa_end_entity_cannot_issue_a_delegated_credential() {
    let opt_in = prov::provider_with_ml_dsa();
    let ed25519 = common::server_chain(common::KeyType::Ed25519);
    for (ee, issues) in [(Alg::Ml(Set::MlDsa65), false), (Alg::P256, true)] {
        let (cert, key) = delegation_certificate(ee);
        let cert_key = opt_in.key_provider.load_private_key(key.pkcs8()).unwrap();
        let mut schemes = ML_DSA_SCHEMES.to_vec();
        schemes.push(SignatureScheme::ECDSA_NISTP256_SHA256);
        let issued = DelegatedCredential::issue(
            browntls_core::Side::Server,
            &cert,
            &*cert_key,
            &schemes,
            credential(SignatureScheme::ED25519, ed25519.end_entity_spki.clone()),
        );
        match issues {
            true => assert_eq!(
                issued.unwrap().algorithm,
                SignatureScheme::ECDSA_NISTP256_SHA256
            ),
            false => assert!(matches!(issued, Err(Error::General(_))), "{issued:?}"),
        }
    }
}

/// A credential whose key is an ML-DSA key is neither issued nor, when a
/// peer builds and signs one anyway, attached to a certified key.
#[test]
fn ml_dsa_credential_keys_are_refused() {
    let opt_in = prov::provider_with_ml_dsa();
    let (cert, key) = delegation_certificate(Alg::P256);
    let cert_key = opt_in.key_provider.load_private_key(key.pkcs8()).unwrap();
    for set in ml_dsa::SETS {
        let dc_id = server_id(Alg::Ml(set));
        let dc_key = dc_id.signing_key(&opt_in);
        let spki = dc_key.public_key().unwrap().as_ref().to_vec();
        let scheme = scheme_of(set);
        assert_eq!(
            DelegatedCredential::issue(
                browntls_core::Side::Server,
                &cert,
                &*cert_key,
                &[SignatureScheme::ECDSA_NISTP256_SHA256],
                credential(scheme, spki.clone()),
            )
            .unwrap_err(),
            Error::from(AttachmentError::UnsupportedScheme)
        );

        let credential = credential(scheme, spki);
        let algorithm = SignatureScheme::ECDSA_NISTP256_SHA256;
        let message = DelegatedCredential::signed_message(
            browntls_core::Side::Server,
            &cert,
            &credential,
            algorithm,
        );
        let signature = cert_key
            .choose_scheme(&[algorithm])
            .unwrap()
            .sign(&message)
            .unwrap();
        let dc = DelegatedCredential {
            credential,
            algorithm,
            signature,
        };
        let certified = CertifiedKey::new(vec![cert.clone()], cert_key.clone());
        assert_eq!(
            certified
                .with_delegated_credential(dc, dc_key, &opt_in)
                .unwrap_err(),
            Error::from(AttachmentError::UnsupportedScheme),
            "{set:?}"
        );
    }
}

/// A client offering `delegated_credential` to a server whose end entity
/// is an ML-DSA key: the server has no credential, and its certificate key
/// signs `CertificateVerify`.
#[test]
fn delegated_credential_offer_to_an_ml_dsa_server() {
    let server = server_id(Alg::Ml(Set::MlDsa65));
    let verifier = server_verifier(prov::provider_with_ml_dsa(), &server);
    let mut client_config = client_config(prov::provider_with_ml_dsa(), verifier.clone(), None);
    client_config.enable_delegated_credentials = true;
    let mut server_config = server_config(prov::provider_with_ml_dsa(), &server, None);
    server_config.enable_delegated_credentials = true;
    let (mut c, mut s) = connect(client_config, server_config);
    handshake(&mut c, &mut s).unwrap();
    assert!(c.delegated_credential().is_none());
    assert_eq!(verifier.seen(), [SignatureScheme::ML_DSA_65]);
    exchange(&mut c, &mut s);
}

/// Exported authenticators on an ML-DSA-authenticated connection: an
/// ML-DSA certified key cannot make one (a spontaneous one fails, a
/// requested one is declined), a classical key under the same root can.
#[test]
fn exported_authenticators_on_an_ml_dsa_connection() {
    let ml = identity(Alg::Ml(Set::MlDsa65), &[Alg::Ml(Set::MlDsa65)], Purpose::Server, "ea");
    let classical = identity(Alg::P256, &[Alg::Ml(Set::MlDsa65)], Purpose::Server, "ea");
    assert_eq!(ml.root, classical.root);
    let (mut c, mut s, seen, _) = ml_dsa_handshake(&ml, None);
    assert_eq!(seen.seen(), [SignatureScheme::ML_DSA_65]);
    let opt_in = prov::provider_with_ml_dsa();
    let ml_key = ml.certified_key(&opt_in);
    let classical_key = classical.certified_key(&opt_in);

    // The key is offered the client's schemes without ML-DSA and declines.
    assert_eq!(
        s.authenticator(None, Some(&ml_key)),
        Err(Error::General(
            "a spontaneous authenticator needs a certificate whose key can sign with a \
             scheme the client offered"
                .into()
        ))
    );

    let default = AuthenticatorRequestExtensions::default();
    let request = c.request_authenticator(b"first", &default).unwrap();
    let auth = s.authenticator(Some(&request), Some(&ml_key)).unwrap();
    // A lone Finished: declined.
    assert_eq!(auth[0], 20);
    assert_eq!(c.validate_authenticator(Some(&request), &auth), Ok(None));

    let request = c.request_authenticator(b"second", &default).unwrap();
    let auth = s
        .authenticator(Some(&request), Some(&classical_key))
        .unwrap();
    assert_eq!(
        c.validate_authenticator(Some(&request), &auth).unwrap(),
        Some(classical.chain.clone())
    );
    // The spontaneous one works with the classical key too.
    let auth = s.authenticator(None, Some(&classical_key)).unwrap();
    assert_eq!(
        c.validate_authenticator(None, &auth).unwrap(),
        Some(classical.chain)
    );
    exchange(&mut c, &mut s);
}
