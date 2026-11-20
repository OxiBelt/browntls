//! Tests of credential validation and of what may be issued or attached.

use alloc::vec;

use super::*;
use crate::crypto::native::sign::any_supported_type;

const DC_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 44363, 44];

/// An Ed25519 end-entity certificate (self-signed), with or without the
/// `DelegationUsage` extension and the `digitalSignature` key usage.
fn cert(
    delegation: bool,
    digital_signature: bool,
) -> (CertificateDer<'static>, Arc<dyn SigningKey>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    // Within `valid_time`'s 32-bit reach of the default notBefore (1975).
    params.not_after = rcgen::date_time_ymd(2040, 1, 1);
    if delegation {
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                DC_OID,
                vec![0x05, 0x00],
            ));
    }
    if digital_signature {
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    }
    let cert = params.self_signed(&key).unwrap();
    let signing = any_supported_type(&browntls_pki::PrivateKeyDer::Pkcs8(
        browntls_pki::PrivatePkcs8KeyDer::from(key.serialize_der()),
    ))
    .unwrap();
    (CertificateDer::from(cert.der().to_vec()), signing)
}

fn credential(
    end_entity: &CertificateDer<'_>,
    key: &dyn SigningKey,
    expiry: u64,
) -> DelegatedCredential {
    let not_before = EndEntityCert::try_from(end_entity)
        .unwrap()
        .not_before()
        .as_secs();
    let dc_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cred = Credential {
        valid_time: u32::try_from(expiry - not_before).unwrap(),
        dc_cert_verify_algorithm: SignatureScheme::ECDSA_NISTP256_SHA256,
        public_key: SubjectPublicKeyInfoDer::from(rcgen::PublicKeyData::subject_public_key_info(
            &dc_key,
        )),
    };
    // Signed directly: `issue` refuses certificates without delegation.
    let algorithm = SignatureScheme::ED25519;
    let signer = key.choose_scheme(&[algorithm]).unwrap();
    let signature = signer
        .sign(&DelegatedCredential::signed_message(
            Side::Server,
            end_entity,
            &cred,
            algorithm,
        ))
        .unwrap();
    DelegatedCredential {
        credential: cred,
        algorithm,
        signature,
    }
}

fn check(
    dc: &DelegatedCredential,
    end_entity: &CertificateDer<'_>,
    dc_schemes: &[SignatureScheme],
    cv_scheme: SignatureScheme,
    now: u64,
) -> Result<UnixTime, Error> {
    let presented = Presented {
        side: Side::Server,
        end_entity,
        offered_dc_schemes: dc_schemes,
        offered_sig_schemes: &[
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ],
        cert_verify_scheme: cv_scheme,
        now: UnixTime::since_unix_epoch(Duration::from_secs(now)),
    };
    let spki = EndEntityCert::try_from(end_entity)
        .unwrap()
        .subject_public_key_info()
        .into_owned();
    validate(dc, &presented, |msg, dss| {
        crate::webpki::verify_tls13_signature_with_raw_key(
            msg,
            &spki,
            dss,
            &crate::crypto::native::SUPPORTED_SIG_ALGS,
        )
    })
}

#[test]
fn checks_in_rfc_order() {
    const P256: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
    let now = UnixTime::now().as_secs();
    let (ee, key) = cert(true, true);
    let dc = credential(&ee, &*key, now + 3600);
    assert_eq!(
        check(&dc, &ee, &[P256], P256, now).unwrap().as_secs(),
        now + 3600
    );

    let err = |e: PeerMisbehaved| Err(Error::PeerMisbehaved(e));
    // §4.1.1: the credential's scheme must be one we offered.
    assert_eq!(
        check(&dc, &ee, &[SignatureScheme::ED25519], P256, now).map(|_| ()),
        err(PeerMisbehaved::DelegatedCredentialWithUnofferedScheme)
    );
    // §4.1.3 1: expired.
    assert_eq!(
        check(&dc, &ee, &[P256], P256, now + 3600).map(|_| ()),
        err(PeerMisbehaved::DelegatedCredentialExpired)
    );
    // 2: more than seven days left.
    assert_eq!(
        check(&dc, &ee, &[P256], P256, now - MAX_VALIDITY.as_secs()).map(|_| ()),
        err(PeerMisbehaved::DelegatedCredentialValidityTooLong)
    );
    // 3: CertificateVerify with another scheme.
    assert_eq!(
        check(&dc, &ee, &[P256], SignatureScheme::ED25519, now).map(|_| ()),
        err(PeerMisbehaved::DelegatedCredentialSchemeMismatch)
    );
    // 4: the certificate must permit delegation.
    for (delegation, ku) in [(false, true), (true, false)] {
        let (ee, key) = cert(delegation, ku);
        let dc = credential(&ee, &*key, now + 3600);
        assert_eq!(
            check(&dc, &ee, &[P256], P256, now).map(|_| ()),
            err(PeerMisbehaved::DelegatedCredentialWithoutDelegationUsage)
        );
    }
    // 5: signed by the certificate key, over this certificate and
    // credential.
    let (other, _) = cert(true, true);
    let mut forged = credential(&other, &*key, now + 3600);
    forged.credential.valid_time = dc.credential.valid_time;
    assert_eq!(
        check(&forged, &ee, &[P256], P256, now).map(|_| ()),
        err(PeerMisbehaved::DelegatedCredentialBadSignature)
    );
    let mut client = dc.clone();
    client.signature = key
        .choose_scheme(&[SignatureScheme::ED25519])
        .unwrap()
        .sign(&DelegatedCredential::signed_message(
            Side::Client,
            &ee,
            &dc.credential,
            dc.algorithm,
        ))
        .unwrap();
    assert_eq!(
        check(&client, &ee, &[P256], P256, now).map(|_| ()),
        err(PeerMisbehaved::DelegatedCredentialBadSignature)
    );
}

#[test]
fn no_rsa_encryption_keys() {
    const RSAE: [SignatureScheme; 3] = [
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
    ];
    for scheme in RSAE {
        assert!(!credential_scheme_allowed(scheme), "{scheme:?}");
    }
    for scheme in [
        SignatureScheme::RSA_PSS_PSS_SHA256,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ED25519,
    ] {
        assert!(credential_scheme_allowed(scheme), "{scheme:?}");
    }

    let now = UnixTime::now().as_secs();
    let (ee, key) = cert(true, true);
    let mut dc = credential(&ee, &*key, now + 3600);
    // Rejected by a validator even when it offered the scheme
    // (illegal_parameter, like every validation failure).
    dc.credential.dc_cert_verify_algorithm = SignatureScheme::RSA_PSS_SHA256;
    assert_eq!(
        check(&dc, &ee, &RSAE, SignatureScheme::RSA_PSS_SHA256, now).map(|_| ()),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialWithUnofferedScheme
        ))
    );
    // Neither issued nor attached.
    let refused = |r: Result<(), Error>| matches!(r, Err(Error::General(msg)) if msg.contains("rsaEncryption"));
    assert!(refused(
        DelegatedCredential::issue(
            Side::Server,
            &ee,
            &*key,
            &[SignatureScheme::ED25519],
            dc.credential.clone(),
        )
        .map(|_| ())
    ));
    assert!(refused(
        DelegatedCredentialKey::new(&ee, dc, key).map(|_| ())
    ));
}

#[test]
fn not_beyond_the_certificate() {
    let (ee, key) = cert(true, true);
    let not_after = EndEntityCert::try_from(&ee).unwrap().not_after().as_secs();
    let dc = credential(&ee, &*key, not_after + 60);
    assert_eq!(
        check(
            &dc,
            &ee,
            &[SignatureScheme::ECDSA_NISTP256_SHA256],
            SignatureScheme::ECDSA_NISTP256_SHA256,
            not_after - 3600,
        )
        .map(|_| ()),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialValidityTooLong
        ))
    );
}

#[test]
fn a_credential_is_only_usable_by_its_side() {
    const P256: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
    let now = UnixTime::now();
    let (ee, cert_key) = cert(true, true);
    let dc_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let dc_key = any_supported_type(&browntls_pki::PrivateKeyDer::Pkcs8(
        browntls_pki::PrivatePkcs8KeyDer::from(dc_pair.serialize_der()),
    ))
    .unwrap();
    let issue = |side| {
        DelegatedCredential::issue(
            side,
            &ee,
            &*cert_key,
            &[SignatureScheme::ED25519],
            Credential {
                valid_time: valid_time_until(
                    &ee,
                    UnixTime::since_unix_epoch(Duration::from_secs(now.as_secs() + 3600)),
                )
                .unwrap(),
                dc_cert_verify_algorithm: P256,
                public_key: SubjectPublicKeyInfoDer::from(
                    rcgen::PublicKeyData::subject_public_key_info(&dc_pair),
                ),
            },
        )
        .unwrap()
    };
    let usable = |key: &DelegatedCredentialKey, side| {
        key.usable(side, &ee, &[P256], &[P256, SignatureScheme::ED25519], now)
    };

    // `new` is a server's credential.
    let server = DelegatedCredentialKey::new(&ee, issue(Side::Server), dc_key.clone()).unwrap();
    assert_eq!(server.side(), Side::Server);
    assert!(usable(&server, Side::Server));
    assert!(!usable(&server, Side::Client));

    let client =
        DelegatedCredentialKey::new_for(Side::Client, &ee, issue(Side::Client), dc_key).unwrap();
    assert_eq!(client.side(), Side::Client);
    assert!(usable(&client, Side::Client));
    assert!(!usable(&client, Side::Server));
    // The credential's own scheme must be in `signature_algorithms` too:
    // that list governs CertificateVerify (RFC 9846 §4.5.2).
    let all = [P256, SignatureScheme::ED25519];
    assert!(client.usable(Side::Client, &ee, &[P256], &all, now));
    assert!(!client.usable(Side::Client, &ee, &[P256], &[SignatureScheme::ED25519], now));

    // The signature covers the side: a client's credential validates as
    // one presented by a client only.
    let presented = |side| Presented {
        side,
        end_entity: &ee,
        offered_dc_schemes: &[P256],
        offered_sig_schemes: &[SignatureScheme::ED25519],
        cert_verify_scheme: P256,
        now,
    };
    let spki = EndEntityCert::try_from(&ee)
        .unwrap()
        .subject_public_key_info()
        .into_owned();
    let verify = |side| {
        validate(client.credential(), &presented(side), |msg, dss| {
            crate::webpki::verify_tls13_signature_with_raw_key(
                msg,
                &spki,
                dss,
                &crate::crypto::native::SUPPORTED_SIG_ALGS,
            )
        })
        .map(|_| ())
    };
    assert_eq!(verify(Side::Client), Ok(()));
    assert_eq!(
        verify(Side::Server),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DelegatedCredentialBadSignature
        ))
    );
}
