//! Path building and validation with chains generated at run time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browntls_pki::{
    CertificateDer, EndEntityCert, Error, KeyUsage, RawPublicKeyEntity, SubjectPublicKeyInfoDer,
    anchor_from_trusted_cert,
};
use common::*;
use rcgen::{
    BasicConstraints, CertifiedIssuer, CustomExtension, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose, PublicKeyData as _, SignatureAlgorithm,
};

const ALGORITHMS: &[&SignatureAlgorithm] = &[
    &rcgen::PKCS_ECDSA_P256_SHA256,
    &rcgen::PKCS_ECDSA_P384_SHA384,
    &rcgen::PKCS_ED25519,
    &rcgen::PKCS_RSA_SHA256,
];

#[test]
fn valid_chains_for_each_algorithm_and_depth() {
    for alg in ALGORITHMS {
        for depth in 0..=2 {
            let chain = Chain::simple(alg, depth);
            assert_eq!(chain.verify_at(NOW), Ok(()), "{alg:?} depth {depth}");
        }
    }
    for alg in [&rcgen::PKCS_RSA_SHA384, &rcgen::PKCS_RSA_SHA512] {
        assert_eq!(Chain::simple(alg, 1).verify_at(NOW), Ok(()), "{alg:?}");
    }
}

#[test]
fn verified_path_reports_intermediates_and_anchor() {
    let chain = Chain::simple(&rcgen::PKCS_ECDSA_P256_SHA256, 2);
    let ee_der = chain.ee_der();
    let intermediates = chain.intermediate_ders();
    let root = chain.root_der();
    let anchors = [anchor_from_trusted_cert(&root).unwrap()];
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
    let in_path: Vec<&CertificateDer<'_>> = path.intermediate_certificates().collect();
    assert_eq!(in_path, intermediates.iter().collect::<Vec<_>>());
    assert_eq!(path.anchor(), &anchors[0]);
    assert_eq!(path.end_entity().der(), ee_der);
    // Shuffled intermediates still build the same path.
    let shuffled = [intermediates[1].clone(), intermediates[0].clone()];
    let path = ee
        .verify_for_usage(
            ALGS,
            &anchors,
            &shuffled,
            NOW,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .unwrap();
    assert_eq!(path.intermediate_certificates().count(), 2);
    assert_eq!(
        path.intermediate_certificates().next(),
        Some(&intermediates[0])
    );
}

#[test]
fn accessors_expose_certificate_fields() {
    let chain = Chain::simple(&rcgen::PKCS_ED25519, 0);
    let ee_der = chain.ee_der();
    let ee = EndEntityCert::try_from(&ee_der).unwrap();
    assert_eq!(
        ee.subject_public_key_info().as_ref(),
        chain.ee_key.subject_public_key_info().as_slice()
    );
    let root = chain.root_der();
    let anchor = anchor_from_trusted_cert(&root).unwrap();
    assert_eq!(ee.issuer(), anchor.subject.as_ref());
    assert!(!ee.serial().is_empty());
    assert!(!ee.subject().is_empty());
    assert_eq!(anchor.to_owned(), anchor);
}

#[test]
fn extended_key_usage() {
    // The default end entity has serverAuth only.
    let chain = Chain::simple(&rcgen::PKCS_ECDSA_P256_SHA256, 1);
    assert_eq!(
        chain.verify_with(ALGS, NOW, KeyUsage::client_auth(), None),
        Err(Error::RequiredEkuNotFound)
    );
    const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    assert_eq!(
        chain.verify_with(ALGS, NOW, KeyUsage::required(CODE_SIGNING), None),
        Err(Error::RequiredEkuNotFound)
    );

    // No EKU extension: fine for "required if present", not for "required".
    let mut no_eku = ee_params(&["example.com"]);
    no_eku.extended_key_usages.clear();
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![ca_params("intermediate")],
        &no_eku,
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));
    assert_eq!(
        chain.verify_with(ALGS, NOW, KeyUsage::client_auth(), None),
        Ok(())
    );
    assert_eq!(
        chain.verify_with(ALGS, NOW, KeyUsage::required(CODE_SIGNING), None),
        Err(Error::RequiredEkuNotFound)
    );

    // Both TLS usages plus a custom one.
    let mut many = ee_params(&["example.com"]);
    many.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::CodeSigning,
    ];
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![],
        &many,
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));
    assert_eq!(
        chain.verify_with(ALGS, NOW, KeyUsage::client_auth(), None),
        Ok(())
    );
    assert_eq!(
        chain.verify_with(ALGS, NOW, KeyUsage::required(CODE_SIGNING), None),
        Ok(())
    );

    // anyExtendedKeyUsage does not stand in for a specific purpose.
    let mut any = ee_params(&["example.com"]);
    any.extended_key_usages = vec![ExtendedKeyUsagePurpose::Any];
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![],
        &any,
    );
    assert_eq!(chain.verify_at(NOW), Err(Error::RequiredEkuNotFound));

    // An intermediate with an EKU extension must also list the purpose.
    let mut constrained_ca = ca_params("intermediate");
    constrained_ca.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![constrained_ca],
        &ee_params(&["example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Err(Error::RequiredEkuNotFound));
}

#[test]
fn validity_period() {
    let not_before = 1_700_000_000;
    let not_after = 1_800_000_000;
    let mut ee = ee_params(&["example.com"]);
    ee.not_before = at(not_before);
    ee.not_after = at(not_after);
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![ca_params("intermediate")],
        &ee,
    );
    assert_eq!(chain.verify_at(secs(not_before)), Ok(()));
    assert_eq!(chain.verify_at(secs(not_after)), Ok(()));
    assert_eq!(
        chain.verify_at(secs(not_before - 1)),
        Err(Error::CertNotValidYet {
            time: secs(not_before - 1),
            not_before: secs(not_before),
        })
    );
    assert_eq!(
        chain.verify_at(secs(not_after + 1)),
        Err(Error::CertExpired {
            time: secs(not_after + 1),
            not_after: secs(not_after),
        })
    );

    // An expired intermediate fails the path; an expired root does not,
    // since trust anchors carry no validity.
    let mut expired_ca = ca_params("intermediate");
    expired_ca.not_after = at(not_before);
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![expired_ca],
        &ee_params(&["example.com"]),
    );
    assert!(matches!(
        chain.verify_at(NOW),
        Err(Error::CertExpired { .. })
    ));

    let mut expired_root = ca_params("root");
    expired_root.not_after = at(not_before);
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        expired_root,
        vec![],
        &ee_params(&["example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));
}

#[test]
fn basic_constraints_roles() {
    // A CA certificate presented as the end entity.
    let mut ca_as_ee = ee_params(&["example.com"]);
    ca_as_ee.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![],
        &ca_as_ee,
    );
    assert_eq!(chain.verify_at(NOW), Err(Error::CaUsedAsEndEntity));

    // An end entity (explicit or implicit non-CA) used as an issuer.
    for is_ca in [IsCa::NoCa, IsCa::ExplicitNoCa] {
        let mut ee_as_ca = ca_params("intermediate");
        ee_as_ca.is_ca = is_ca;
        let chain = Chain::build(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            ca_params("root"),
            vec![ee_as_ca],
            &ee_params(&["example.com"]),
        );
        assert_eq!(
            chain.verify_at(NOW),
            Err(Error::EndEntityUsedAsCa),
            "{is_ca:?}"
        );
    }
}

#[test]
fn path_length_constraints() {
    let constrained = |n: u8| {
        let mut params = ca_params("intermediate 0");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(n));
        params
    };
    // pathLen 0 allows no further CA below it.
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![constrained(0), ca_params("intermediate 1")],
        &ee_params(&["example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Err(Error::PathLenConstraintViolated));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![constrained(0)],
        &ee_params(&["example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![constrained(1), ca_params("intermediate 1")],
        &ee_params(&["example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));
    // The anchor's own pathLenConstraint is not enforced (anchors are
    // reduced to subject, key and name constraints).
    let mut root = ca_params("root");
    root.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        root,
        vec![ca_params("a"), ca_params("b")],
        &ee_params(&["example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));
}

#[test]
fn issuer_key_usage() {
    let mut no_cert_sign = ca_params("intermediate");
    no_cert_sign.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![no_cert_sign],
        &ee_params(&["example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Err(Error::IssuerNotCertSigner));

    // Absent KeyUsage permits everything; end-entity KeyUsage is ignored.
    let mut no_ku = ca_params("intermediate");
    no_ku.key_usages.clear();
    let mut ee = ee_params(&["example.com"]);
    ee.key_usages = vec![KeyUsagePurpose::KeyAgreement];
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![no_ku],
        &ee,
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));
}

#[test]
fn unknown_issuer_and_bad_signatures() {
    let chain = Chain::simple(&rcgen::PKCS_ECDSA_P256_SHA256, 1);
    let other = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("other root"),
        vec![],
        &ee_params(&["example.com"]),
    );
    let ee = chain.ee_der();
    let intermediates = chain.intermediate_ders();

    // Unrelated root, or a missing intermediate.
    let roots = [other.root_der()];
    let trust = anchors(&roots);
    let usage = KeyUsage::server_auth();
    assert_eq!(
        verify(&ee, &intermediates, &trust, ALGS, NOW, usage, None, None),
        Err(Error::UnknownIssuer)
    );
    let roots = [chain.root_der()];
    let trust = anchors(&roots);
    assert_eq!(
        verify(&ee, &[], &trust, ALGS, NOW, usage, None, None),
        Err(Error::UnknownIssuer)
    );

    // Same root subject, different key.
    let impostor =
        CertifiedIssuer::self_signed(ca_params("root"), key_for(&rcgen::PKCS_ECDSA_P256_SHA256))
            .unwrap();
    let impostor_der: CertificateDer<'_> = impostor.der().to_vec().into();
    let trust = [anchor_from_trusted_cert(&impostor_der).unwrap()];
    assert_eq!(
        verify(&ee, &intermediates, &trust, ALGS, NOW, usage, None, None),
        Err(Error::InvalidSignatureForPublicKey)
    );

    // Tampered end-entity signature.
    let mut tampered = ee.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let tampered = CertificateDer::from(tampered);
    let roots = [chain.root_der()];
    let trust = anchors(&roots);
    assert_eq!(
        verify(
            &tampered,
            &intermediates,
            &trust,
            ALGS,
            NOW,
            usage,
            None,
            None
        ),
        Err(Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn signature_algorithm_support() {
    let ed = Chain::simple(&rcgen::PKCS_ED25519, 1);
    assert_eq!(
        ed.verify_with(P256_ONLY, NOW, KeyUsage::server_auth(), None),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
    // ecdsa-with-SHA384 is supported, but only for P-256 keys here, so a
    // P-384 chain is rejected for its key type.
    let p384 = Chain::simple(&rcgen::PKCS_ECDSA_P384_SHA384, 1);
    assert_eq!(
        p384.verify_with(&[&ECDSA_P256_SHA384], NOW, KeyUsage::server_auth(), None),
        Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
    );
    assert_eq!(
        p384.verify_with(&[&ECDSA_P384_SHA384], NOW, KeyUsage::server_auth(), None),
        Ok(())
    );
    assert_eq!(
        p384.verify_with(&[], NOW, KeyUsage::server_auth(), None),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn signature_algorithm_mismatch_is_rejected_at_parse_time() {
    let chain = Chain::simple(&rcgen::PKCS_ECDSA_P256_SHA256, 0);
    let ee = chain.ee_der();
    // ecdsa-with-SHA256 is 1.2.840.10045.4.3.2; the outer signatureAlgorithm
    // follows the TBSCertificate. Rewrite its last arc to .3 (SHA-384).
    const ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let positions: Vec<usize> = (0..ee.len() - ECDSA_SHA256.len())
        .filter(|&i| &ee[i..i + ECDSA_SHA256.len()] == ECDSA_SHA256)
        .collect();
    assert_eq!(positions.len(), 2, "inner and outer algorithm identifiers");
    let mut mismatched = ee.to_vec();
    mismatched[positions[1] + ECDSA_SHA256.len() - 1] = 0x03;
    let mismatched = CertificateDer::from(mismatched);
    assert_eq!(
        EndEntityCert::try_from(&mismatched).err(),
        Some(Error::SignatureAlgorithmMismatch)
    );
}

#[test]
fn critical_and_duplicate_extensions() {
    let unknown = |critical: bool| {
        let mut ext =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], vec![0x05, 0x00]);
        ext.set_criticality(critical);
        ext
    };
    let mut ee = ee_params(&["example.com"]);
    ee.custom_extensions.push(unknown(true));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![],
        &ee,
    );
    assert_eq!(
        EndEntityCert::try_from(&chain.ee_der()).err(),
        Some(Error::UnsupportedCriticalExtension)
    );
    let mut ee = ee_params(&["example.com"]);
    ee.custom_extensions.push(unknown(false));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![],
        &ee,
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));

    // On an intermediate the failure surfaces from path building.
    let mut ca = ca_params("intermediate");
    ca.custom_extensions.push(unknown(true));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![ca],
        &ee_params(&["example.com"]),
    );
    assert_eq!(
        chain.verify_at(NOW),
        Err(Error::UnsupportedCriticalExtension)
    );

    // A trust anchor may carry unknown critical extensions.
    let mut root = ca_params("root");
    root.custom_extensions.push(unknown(true));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        root,
        vec![],
        &ee_params(&["example.com"]),
    );
    assert_eq!(chain.verify_at(NOW), Ok(()));

    // A second subjectAltName extension is a duplicate.
    let mut ee = ee_params(&["example.com"]);
    ee.custom_extensions.push(CustomExtension::from_oid_content(
        &[2, 5, 29, 17],
        b"\x30\x0d\x82\x0bexample.org".to_vec(),
    ));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![],
        &ee,
    );
    assert_eq!(
        EndEntityCert::try_from(&chain.ee_der()).err(),
        Some(Error::MalformedExtensions)
    );
}

#[test]
fn handshake_signatures() {
    const MSG: &[u8] = b"hello world!";
    let cases: &[(
        &SignatureAlgorithm,
        &dyn browntls_pki::SignatureVerificationAlgorithm,
    )] = &[
        (&rcgen::PKCS_ECDSA_P256_SHA256, &ECDSA_P256_SHA256),
        (&rcgen::PKCS_ECDSA_P384_SHA384, &ECDSA_P384_SHA384),
        (&rcgen::PKCS_ED25519, &ED25519),
        (&rcgen::PKCS_RSA_SHA256, &RSA_PKCS1_SHA256),
        (&rcgen::PKCS_RSA_SHA384, &RSA_PKCS1_SHA384),
    ];
    for (rcgen_alg, alg) in cases {
        let chain = Chain::simple(rcgen_alg, 0);
        let ee_der = chain.ee_der();
        let ee = EndEntityCert::try_from(&ee_der).unwrap();
        let good = sign(&chain.ee_key, MSG);
        let bad = sign(&chain.ee_key, b"other");
        assert_eq!(
            ee.verify_signature(*alg, MSG, &good),
            Ok(()),
            "{rcgen_alg:?}"
        );
        assert_eq!(
            ee.verify_signature(*alg, MSG, &bad),
            Err(Error::InvalidSignatureForPublicKey)
        );
        assert_eq!(
            ee.verify_signature(*alg, MSG, &[]),
            Err(Error::InvalidSignatureForPublicKey)
        );
        let spki = ee.subject_public_key_info();
        let rpk = RawPublicKeyEntity::try_from(&spki).unwrap();
        assert_eq!(rpk.verify_signature(*alg, MSG, &good), Ok(()));
        assert_eq!(
            rpk.verify_signature(*alg, MSG, &bad),
            Err(Error::InvalidSignatureForPublicKey)
        );
        // Every other key type is rejected before any verification.
        for other in ALGS {
            if other.public_key_alg_id() != alg.public_key_alg_id() {
                assert_eq!(
                    ee.verify_signature(*other, MSG, &good),
                    Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
                );
            }
        }
    }

    // RSA-PSS over a PKCS#1-signed certificate's key.
    let chain = Chain::simple(&rcgen::PKCS_RSA_SHA256, 0);
    let ee_der = chain.ee_der();
    let ee = EndEntityCert::try_from(&ee_der).unwrap();
    let pss = rsa_pss_sign(MSG);
    assert_eq!(ee.verify_signature(&RSA_PSS_SHA256, MSG, &pss), Ok(()));
    assert_eq!(
        ee.verify_signature(&RSA_PSS_SHA256, b"other", &pss),
        Err(Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        ee.verify_signature(&RSA_PKCS1_SHA256, MSG, &pss),
        Err(Error::InvalidSignatureForPublicKey)
    );

    // Raw public keys must be a complete SubjectPublicKeyInfo.
    let spki_contents = SubjectPublicKeyInfoDer::from(ee.subject_public_key_info()[2..].to_vec());
    assert!(RawPublicKeyEntity::try_from(&spki_contents).is_err());
    assert!(RawPublicKeyEntity::try_from(&SubjectPublicKeyInfoDer::from(ee_der.to_vec())).is_err());
}
