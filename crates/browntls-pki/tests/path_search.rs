//! Path search behaviour: the caller's path check, depth and work limits,
//! loop prevention and candidate ordering.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browntls_pki::{
    CertificateDer, EndEntityCert, Error, KeyUsage, TrustAnchor, anchor_from_trusted_cert,
};
use common::*;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};

/// Recreates a key pair so that the same key can sign under two issuers.
fn clone_key(key: &KeyPair) -> KeyPair {
    let der = rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    KeyPair::from_pkcs8_der_and_sign_algo(&der, key.algorithm()).unwrap()
}

#[test]
fn verify_path_callback_steers_the_search() {
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let root_a = CertifiedIssuer::self_signed(ca_params("root a"), key_for(alg)).unwrap();
    let root_b = CertifiedIssuer::self_signed(ca_params("root b"), key_for(alg)).unwrap();
    let int_key = key_for(alg);
    let int_by_a =
        CertifiedIssuer::signed_by(ca_params("intermediate"), clone_key(&int_key), &root_a)
            .unwrap();
    let int_by_b = CertifiedIssuer::signed_by(ca_params("intermediate"), int_key, &root_b).unwrap();
    let ee_key = key_for(alg);
    let ee = ee_params(&["example.com"])
        .signed_by(&ee_key, &int_by_a)
        .unwrap();

    let ee_der: CertificateDer<'_> = ee.der().to_vec().into();
    let roots = [root_a.der().to_vec().into(), root_b.der().to_vec().into()];
    let anchors = anchors(&roots);
    let intermediates: Vec<CertificateDer<'_>> = vec![
        int_by_a.der().to_vec().into(),
        int_by_b.der().to_vec().into(),
    ];
    let ee = EndEntityCert::try_from(&ee_der).unwrap();

    let path = ee
        .verify_for_usage(
            ALGS,
            &anchors,
            &intermediates,
            NOW,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .unwrap();
    assert_eq!(path.anchor(), &anchors[0]);

    let reject_a = |path: &browntls_pki::VerifiedPath<'_>| {
        if path.anchor().subject == anchors[0].subject {
            Err(Error::UnknownIssuer)
        } else {
            Ok(())
        }
    };
    let path = ee
        .verify_for_usage(
            ALGS,
            &anchors,
            &intermediates,
            NOW,
            KeyUsage::server_auth(),
            None,
            Some(&reject_a),
        )
        .unwrap();
    assert_eq!(path.anchor(), &anchors[1]);
    assert_eq!(
        path.intermediate_certificates().next(),
        Some(&intermediates[1])
    );

    let reject_all = |_: &browntls_pki::VerifiedPath<'_>| Err(Error::CertRevoked);
    let result = ee.verify_for_usage(
        ALGS,
        &anchors,
        &intermediates,
        NOW,
        KeyUsage::server_auth(),
        None,
        Some(&reject_all),
    );
    assert_eq!(result.err(), Some(Error::CertRevoked));
}

#[test]
fn depth_limit() {
    assert_eq!(
        Chain::simple(&rcgen::PKCS_ECDSA_P256_SHA256, 6).verify_at(NOW),
        Ok(())
    );
    assert_eq!(
        Chain::simple(&rcgen::PKCS_ECDSA_P256_SHA256, 7).verify_at(NOW),
        Err(Error::MaximumPathDepthExceeded)
    );
}

#[test]
fn issuer_loops_terminate() {
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key_a = key_for(alg);
    let key_b = key_for(alg);
    let issuer_a = rcgen::Issuer::new(ca_params("a"), clone_key(&key_a));
    let issuer_b = rcgen::Issuer::new(ca_params("b"), clone_key(&key_b));
    let a_by_b = ca_params("a").signed_by(&key_a, &issuer_b).unwrap();
    let b_by_a = ca_params("b").signed_by(&key_b, &issuer_a).unwrap();
    let ee = ee_params(&["example.com"])
        .signed_by(&key_for(alg), &issuer_a)
        .unwrap();
    let unrelated = Chain::simple(alg, 0);
    let roots = [unrelated.root_der()];
    let intermediates: Vec<CertificateDer<'_>> =
        vec![a_by_b.der().to_vec().into(), b_by_a.der().to_vec().into()];
    assert_eq!(
        verify(
            &ee.der().to_vec().into(),
            &intermediates,
            &anchors(&roots),
            ALGS,
            NOW,
            KeyUsage::server_auth(),
            None,
            None,
        ),
        Err(Error::UnknownIssuer)
    );
}

#[test]
fn signature_budget_with_many_candidate_anchors() {
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let chain = Chain::simple(alg, 1);
    let real = chain.root_der();
    let decoys: Vec<CertificateDer<'_>> = (0..120)
        .map(|_| {
            CertifiedIssuer::self_signed(ca_params("root"), key_for(alg))
                .unwrap()
                .der()
                .to_vec()
                .into()
        })
        .collect();
    let mut anchors: Vec<TrustAnchor<'_>> = decoys
        .iter()
        .map(|d| anchor_from_trusted_cert(d).unwrap())
        .collect();
    anchors.push(anchor_from_trusted_cert(&real).unwrap());
    let ee = chain.ee_der();
    let intermediates = chain.intermediate_ders();
    assert_eq!(
        verify(
            &ee,
            &intermediates,
            &anchors,
            ALGS,
            NOW,
            KeyUsage::server_auth(),
            None,
            None
        ),
        Err(Error::MaximumSignatureChecksExceeded)
    );
    // Fewer decoys fit in the budget and the real anchor is found.
    let few = &anchors[70..];
    assert_eq!(
        verify(
            &ee,
            &intermediates,
            few,
            ALGS,
            NOW,
            KeyUsage::server_auth(),
            None,
            None
        ),
        Ok(())
    );
}

#[test]
fn key_identifier_hint_orders_intermediate_candidates() {
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let build = |with_aki: bool| {
        let mut ee = ee_params(&["example.com"]);
        ee.use_authority_key_identifier_extension = with_aki;
        Chain::build(alg, ca_params("root"), vec![ca_params("intermediate")], &ee)
    };
    // Decoy intermediates share the real one's subject and are signed by
    // CAs with the real root's subject but other keys: each one costs a
    // signature check against the real anchor before it is rejected.
    let decoys: Vec<CertificateDer<'_>> = (0..120)
        .map(|_| {
            let fake_root = CertifiedIssuer::self_signed(ca_params("root"), key_for(alg)).unwrap();
            CertifiedIssuer::signed_by(ca_params("intermediate"), key_for(alg), &fake_root)
                .unwrap()
                .der()
                .to_vec()
                .into()
        })
        .collect();
    for with_aki in [false, true] {
        let chain = build(with_aki);
        let mut intermediates = decoys.clone();
        intermediates.extend(chain.intermediate_ders());
        let roots = [chain.root_der()];
        let result = verify(
            &chain.ee_der(),
            &intermediates,
            &anchors(&roots),
            ALGS,
            NOW,
            KeyUsage::server_auth(),
            None,
            None,
        );
        if with_aki {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(Error::MaximumSignatureChecksExceeded));
        }
    }
}

#[test]
fn trust_anchor_without_subject_match_is_ignored() {
    // The default distinguished name differs between CA and EE helpers; a
    // CA whose subject happens to equal the EE's issuer but with different
    // DN attributes is not matched.
    let chain = Chain::simple(&rcgen::PKCS_ECDSA_P256_SHA256, 0);
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let other =
        CertifiedIssuer::self_signed(params, key_for(&rcgen::PKCS_ECDSA_P256_SHA256)).unwrap();
    let roots = [other.der().to_vec().into()];
    assert_eq!(
        verify(
            &chain.ee_der(),
            &[],
            &anchors(&roots),
            ALGS,
            NOW,
            KeyUsage::server_auth(),
            None,
            None,
        ),
        Err(Error::UnknownIssuer)
    );
}

#[test]
fn build_call_budget_with_alternating_decoys() {
    // Two families of CA certificates issue each other: every "x" is
    // issued by some "y" and vice versa, all with distinct keys, so loop
    // prevention never fires and no trust anchor matches. The search
    // explores 8^6 candidate paths before the depth limit stops each one,
    // which exhausts the build-call budget without a single signature check.
    let alg = &rcgen::PKCS_ED25519;
    let x_issuer = rcgen::Issuer::new(ca_params("x"), key_for(alg));
    let y_issuer = rcgen::Issuer::new(ca_params("y"), key_for(alg));
    let mut intermediates: Vec<CertificateDer<'_>> = Vec::new();
    for _ in 0..8 {
        let x = ca_params("x").signed_by(&key_for(alg), &y_issuer).unwrap();
        let y = ca_params("y").signed_by(&key_for(alg), &x_issuer).unwrap();
        intermediates.push(x.der().to_vec().into());
        intermediates.push(y.der().to_vec().into());
    }
    let ee = ee_params(&["example.com"])
        .signed_by(&key_for(alg), &x_issuer)
        .unwrap();
    let unrelated = Chain::simple(alg, 0);
    let roots = [unrelated.root_der()];
    assert_eq!(
        verify(
            &ee.der().to_vec().into(),
            &intermediates,
            &anchors(&roots),
            ALGS,
            NOW,
            KeyUsage::server_auth(),
            None,
            None,
        ),
        Err(Error::MaximumPathBuildCallsExceeded)
    );
}
