//! OCSP responses signed by delegated responders, and the certificate
//! extensions related to OCSP.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ocsp.rs"]
mod support;

use support::*;

// ---------------------------------------------------------------------------
// Delegated responders
// ---------------------------------------------------------------------------

/// A response signed by `delegate` and carrying its certificate.
fn delegated(fx: &Fixture, delegate: &Delegate, by_name_id: bool) -> Vec<u8> {
    let mut response = fx.response();
    response.responder_id = if by_name_id {
        by_name(&delegate.cert())
    } else {
        by_key(&delegate.key)
    };
    response.certs = vec![fx.chain.root_der().to_vec(), delegate.der.to_vec()];
    response.signed_by(&delegate.key)
}

#[test]
fn delegate_with_nocheck() {
    let fx = Fixture::new();
    let delegate = fx.delegate(|_| {});
    assert_eq!(has_ocsp_nocheck(&delegate.cert()), Ok(true));
    assert_eq!(has_ocsp_nocheck(&fx.ee()), Ok(false));
    let not_after = delegate.cert().not_after();
    for by_name_id in [false, true] {
        let der = delegated(&fx, &delegate, by_name_id);
        for policy in [stapled(), fetched()] {
            let verified = fx.verify(&der, &policy).unwrap();
            assert_eq!(verified.status, CertStatus::Good);
            assert_eq!(
                verified.signer,
                OcspSigner::Delegate {
                    not_after,
                    nocheck: true
                }
            );
            assert_eq!(verified.expires, secs(NEXT_UPDATE));
        }
    }

    // The certificate must be carried by the response.
    let mut response = fx.response();
    response.responder_id = by_key(&delegate.key);
    let der = response.signed_by(&delegate.key);
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::UnknownResponder)
    );

    // The delegate's certificate does not vouch for another key.
    let stranger = key_for(alg());
    let mut response = fx.response();
    response.responder_id = by_key(&delegate.key);
    response.certs = vec![delegate.der.to_vec()];
    let der = response.signed_by(&stranger);
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::BadSignature(Error::InvalidSignatureForPublicKey))
    );
}

#[test]
fn delegate_validity_bounds_the_status() {
    let fx = Fixture::new();
    let delegate = fx.delegate(|params| {
        params.not_before = at(NOW_SECS - DAY);
        params.not_after = at(NOW_SECS + DAY);
    });
    let der = delegated(&fx, &delegate, false);
    let verified = fx.verify(&der, &fetched()).unwrap();
    assert_eq!(verified.next_update, Some(secs(NEXT_UPDATE)));
    assert_eq!(verified.expires, secs(NOW_SECS + DAY));

    assert_eq!(
        fx.verify(&der, &at_time(fetched(), NOW_SECS + DAY + 1)),
        Err(OcspError::DelegateInvalid(Error::CertExpired {
            time: secs(NOW_SECS + DAY + 1),
            not_after: secs(NOW_SECS + DAY),
        }))
    );
    let mut response = fx.response();
    response.responder_id = by_key(&delegate.key);
    response.certs = vec![delegate.der.to_vec()];
    response.produced_at = NOW_SECS - 2 * DAY;
    response.singles[0].this_update = generalized_time(NOW_SECS - 2 * DAY);
    let der = response.signed_by(&delegate.key);
    assert_eq!(
        fx.verify(&der, &at_time(fetched(), NOW_SECS - DAY - 1)),
        Err(OcspError::DelegateInvalid(Error::CertNotValidYet {
            time: secs(NOW_SECS - DAY - 1),
            not_before: secs(NOW_SECS - DAY),
        }))
    );
}

#[test]
fn delegate_authorization() {
    let fx = Fixture::new();
    let check = |delegate: &Delegate| {
        fx.verify(&delegated(&fx, delegate, false), &stapled())
            .map(|verified| verified.status)
    };

    // No extended key usage, another usage, and anyExtendedKeyUsage.
    for usages in [
        vec![],
        vec![ExtendedKeyUsagePurpose::ServerAuth],
        vec![ExtendedKeyUsagePurpose::Any],
    ] {
        let delegate = fx.delegate(|params| params.extended_key_usages = usages);
        assert_eq!(check(&delegate), Err(OcspError::DelegateNotOcspSigner));
    }
    // OCSP signing among other usages.
    let delegate = fx.delegate(|params| {
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::OcspSigning,
        ];
    });
    assert!(check(&delegate).is_ok());

    // Key usage without digitalSignature; an absent key usage is accepted.
    let delegate = fx.delegate(|params| params.key_usages = vec![KeyUsagePurpose::KeyEncipherment]);
    assert_eq!(check(&delegate), Err(OcspError::DelegateKeyUsage));
    let delegate = fx.delegate(|params| params.key_usages = Vec::new());
    assert!(check(&delegate).is_ok());

    // A malformed nocheck extension.
    let delegate = fx.delegate(|params| {
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            NOCHECK_OID,
            vec![0x01, 0x01, 0xff],
        )];
    });
    assert_eq!(
        check(&delegate),
        Err(OcspError::DelegateInvalid(Error::ExtensionValueInvalid))
    );

    // Issued by the root instead of the end entity's issuer.
    let delegate = Delegate::issue(&fx.chain.root, |_| {});
    assert_eq!(check(&delegate), Err(OcspError::DelegateNotIssuedByCa));

    // Issued by an impostor with the issuer's name and another key.
    let impostor = CertifiedIssuer::self_signed(ca_params("issuing ca"), key_for(alg())).unwrap();
    let delegate = Delegate::issue(&impostor, |_| {});
    assert_eq!(
        check(&delegate),
        Err(OcspError::DelegateInvalid(
            Error::InvalidSignatureForPublicKey
        ))
    );

    // The end entity itself is not a responder.
    let mut response = fx.response();
    response.responder_id = by_key(&fx.chain.ee_key);
    response.certs = vec![fx.ee_der.to_vec()];
    let der = response.signed_by(&fx.chain.ee_key);
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::DelegateNotOcspSigner)
    );
}

fn crl(issuer: &Issuer<'_, KeyPair>, revoked: &[&[u8]], next_update: u64) -> Vec<u8> {
    CertificateRevocationListParams {
        this_update: at(THIS_UPDATE),
        next_update: at(next_update),
        crl_number: SerialNumber::from(7u64),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|serial| RevokedCertParams {
                serial_number: SerialNumber::from_slice(serial),
                revocation_time: at(THIS_UPDATE - HOUR),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .unwrap()
    .der()
    .to_vec()
}

fn borrowed(der: &[u8]) -> CertRevocationList<'_> {
    CertRevocationList::from(BorrowedCertRevocationList::from_der(der).unwrap())
}

#[test]
fn delegate_without_nocheck_needs_a_fresh_crl() {
    let fx = Fixture::new();
    let delegate = fx.delegate(|params| params.custom_extensions = Vec::new());
    assert_eq!(has_ocsp_nocheck(&delegate.cert()), Ok(false));
    let not_after = delegate.cert().not_after();
    let der = delegated(&fx, &delegate, false);
    let crl_next = NOW_SECS + DAY;

    // No CRL.
    assert_eq!(
        fx.verify(&der, &stapled()),
        Err(OcspError::DelegateRevocationUnknown)
    );

    // A current CRL of the issuer that does not list the delegate.
    let clean = crl(fx.ca_issuer(), &[OTHER_SERIAL], crl_next);
    let clean = borrowed(&clean);
    let crls = [&clean];
    let mut policy = stapled();
    policy.delegate_crls = &crls;
    let verified = fx.verify(&der, &policy).unwrap();
    assert_eq!(
        verified.signer,
        OcspSigner::Delegate {
            not_after,
            nocheck: false
        }
    );
    // The status is good for as long as the CRL is.
    assert_eq!(verified.expires, secs(crl_next));

    // The same CRL once it has expired, or before it is valid.
    for time in [crl_next, THIS_UPDATE - 1] {
        let mut policy = at_time(stapled(), time);
        policy.delegate_crls = &crls;
        assert_eq!(
            fx.verify(&der, &policy),
            Err(OcspError::DelegateRevocationUnknown)
        );
    }

    // A CRL listing the delegate; a clean one beside it does not help.
    let listing = crl(fx.ca_issuer(), &[DELEGATE_SERIAL], crl_next);
    let listing = borrowed(&listing);
    for crls in [&[&listing][..], &[&clean, &listing], &[&listing, &clean]] {
        let mut policy = stapled();
        policy.delegate_crls = crls;
        assert_eq!(fx.verify(&der, &policy), Err(OcspError::DelegateRevoked));
    }

    // A CRL of another issuer is not consulted.
    let root_crl = crl(&fx.chain.root, &[], crl_next);
    let root_crl = borrowed(&root_crl);
    let crls = [&root_crl];
    let mut policy = stapled();
    policy.delegate_crls = &crls;
    assert_eq!(
        fx.verify(&der, &policy),
        Err(OcspError::DelegateRevocationUnknown)
    );

    // A CRL under the issuer's name that the issuer did not sign.
    let impostor = CertifiedIssuer::self_signed(ca_params("issuing ca"), key_for(alg())).unwrap();
    let forged = crl(&impostor, &[], crl_next);
    let forged = borrowed(&forged);
    let crls = [&forged];
    let mut policy = stapled();
    policy.delegate_crls = &crls;
    assert_eq!(
        fx.verify(&der, &policy),
        Err(OcspError::DelegateCrl(
            Error::InvalidCrlSignatureForPublicKey
        ))
    );

    // CRLs are not needed for a response the CA signed itself.
    let der = fx.response().signed_by(fx.ca_key());
    let mut policy = stapled();
    policy.delegate_crls = &crls;
    assert!(fx.verify(&der, &policy).is_ok());
}

// ---------------------------------------------------------------------------
// Certificate extensions
// ---------------------------------------------------------------------------

fn ee_with_extensions(extensions: Vec<CustomExtension>) -> Fixture {
    let mut params = ee_params(&["example.com"]);
    params.custom_extensions = extensions;
    Fixture::with_ee(params)
}

#[test]
fn must_staple_extension() {
    let feature =
        |content: &[u8]| CustomExtension::from_oid_content(TLS_FEATURE_OID, content.to_vec());
    assert_eq!(must_staple(&Fixture::new().ee()), Ok(false));
    for (content, expected) in [
        (&[0x30, 0x03, 0x02, 0x01, 0x05][..], Ok(true)),
        // status_request_v2 and status_request.
        (&[0x30, 0x06, 0x02, 0x01, 0x11, 0x02, 0x01, 0x05], Ok(true)),
        (&[0x30, 0x03, 0x02, 0x01, 0x11], Ok(false)),
        (&[0x30, 0x00], Ok(false)),
        // 0x0105 is not feature 5.
        (&[0x30, 0x04, 0x02, 0x02, 0x01, 0x05], Ok(false)),
        (
            &[0x30, 0x03, 0x04, 0x01, 0x05],
            Err(Error::ExtensionValueInvalid),
        ),
        (&[0x02, 0x01, 0x05], Err(Error::ExtensionValueInvalid)),
        (
            &[0x30, 0x03, 0x02, 0x01, 0x85],
            Err(Error::ExtensionValueInvalid),
        ),
        (
            &[0x30, 0x03, 0x02, 0x01, 0x05, 0x00],
            Err(Error::ExtensionValueInvalid),
        ),
    ] {
        let fx = ee_with_extensions(vec![feature(content)]);
        assert_eq!(must_staple(&fx.ee()), expected, "{content:?}");
    }
}

#[test]
fn authority_information_access() {
    let access = |method: &[u8], location_tag: u8, location: &[u8]| {
        seq(&[&tlv(0x06, method), &tlv(location_tag, location)])
    };
    let fx = Fixture::new();
    assert_eq!(ocsp_responder_uris(&fx.ee()).unwrap().count(), 0);
    assert_eq!(ca_issuer_uris(&fx.ee()).unwrap().count(), 0);

    let value = seq(&[
        &access(oid::AD_OCSP, 0x86, b"http://ocsp.example.com"),
        &access(oid::AD_CA_ISSUERS, 0x86, b"http://ca.example.com/ca.crt"),
        // A dNSName location and a non-ASCII URI are skipped.
        &access(oid::AD_OCSP, 0x82, b"ocsp.example.net"),
        &access(oid::AD_OCSP, 0x86, b"http://\xff.example.com"),
        &access(oid::AD_OCSP, 0x86, b"http://ocsp2.example.com/path"),
    ]);
    let fx = ee_with_extensions(vec![CustomExtension::from_oid_content(AIA_OID, value)]);
    let ee = fx.ee();
    assert_eq!(
        ocsp_responder_uris(&ee).unwrap().collect::<Vec<_>>(),
        ["http://ocsp.example.com", "http://ocsp2.example.com/path"]
    );
    assert_eq!(
        ca_issuer_uris(&ee).unwrap().collect::<Vec<_>>(),
        ["http://ca.example.com/ca.crt"]
    );

    for bad in [
        seq(&[]),
        seq(&[&tlv(0x06, oid::AD_OCSP)]),
        seq(&[&seq(&[&tlv(0x06, oid::AD_OCSP)])]),
        seq(&[&seq(&[&tlv(0x04, oid::AD_OCSP), &tlv(0x86, b"http://x")])]),
        tlv(0x04, b"http://ocsp.example.com"),
    ] {
        let fx = ee_with_extensions(vec![CustomExtension::from_oid_content(AIA_OID, bad)]);
        assert_eq!(
            ocsp_responder_uris(&fx.ee()).err(),
            Some(Error::ExtensionValueInvalid)
        );
        assert_eq!(
            ca_issuer_uris(&fx.ee()).err(),
            Some(Error::ExtensionValueInvalid)
        );
    }
}
