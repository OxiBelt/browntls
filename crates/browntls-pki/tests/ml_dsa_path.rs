//! ML-DSA (RFC 9881) certificate path validation: each parameter set in
//! each position, mixed and hybrid chains, the supported-algorithm list as
//! the only policy, and the signature budget. Signatures are made and
//! checked by the RustCrypto `ml-dsa` crate (`common/ml_dsa.rs`), and
//! certificates are built by `common/x509_builder.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ml_dsa.rs"]
mod ml_dsa;
#[path = "common/x509_builder.rs"]
mod x509;

use browntls_pki::{
    CertificateDer, EndEntityCert, Error, KeyUsage, SignatureVerificationAlgorithm, TrustAnchor,
    anchor_from_trusted_cert,
};
use common::{ALGS, ECDSA_P256_SHA256, NOW};
use ml_dsa::{Counted, Key, ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_DSA_ALGS, SETS, Set};
use x509::{CertSpec, authority_key_id, subject_key_id};

/// A chain built with `x509_builder`: a self-signed root (the trust
/// anchor), intermediates nearest the end entity first, and the end entity.
struct Chain {
    root: Vec<u8>,
    intermediates: Vec<Vec<u8>>,
    ee: Vec<u8>,
}

impl Chain {
    /// `root -> intermediates[0] -> ... -> ee`, with `intermediates` given
    /// nearest the root first.
    fn build(root: &Key, intermediates: &[&Key], ee: &Key) -> Self {
        let root_cert = CertSpec::ca("root", "root", root).sign(root);
        let mut issuer = ("root".to_string(), root);
        let mut ints = Vec::new();
        for (i, key) in intermediates.iter().enumerate() {
            let subject = format!("intermediate {i}");
            ints.push(CertSpec::ca(&subject, &issuer.0, key).sign(issuer.1));
            issuer = (subject, key);
        }
        let ee = CertSpec::ee("end entity", &issuer.0, ee).sign(issuer.1);
        ints.reverse();
        Self {
            root: root_cert,
            intermediates: ints,
            ee,
        }
    }

    fn verify(&self, algs: &[&dyn SignatureVerificationAlgorithm]) -> Result<(), Error> {
        verify(&self.ee, &self.intermediates, &self.root, algs)
    }
}

fn verify(
    ee: &[u8],
    intermediates: &[Vec<u8>],
    root: &[u8],
    algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    let root = CertificateDer::from(root);
    let anchors = [anchor_from_trusted_cert(&root).unwrap()];
    let ints: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|c| CertificateDer::from(&c[..]))
        .collect();
    common::verify(
        &CertificateDer::from(ee),
        &ints,
        &anchors,
        algs,
        NOW,
        KeyUsage::server_auth(),
        None,
        None,
    )
}

/// Every classical test algorithm followed by `extra`.
fn with_classical<'a>(
    extra: &[&'a dyn SignatureVerificationAlgorithm],
) -> Vec<&'a dyn SignatureVerificationAlgorithm> {
    ALGS.iter().copied().chain(extra.iter().copied()).collect()
}

#[test]
fn each_parameter_set_as_anchor_intermediate_and_end_entity() {
    for set in SETS {
        let root = Key::ml_dsa(set, "root");
        let int = Key::ml_dsa(set, "intermediate");
        let ee = Key::ml_dsa(set, "ee");
        let counted = Counted::new(set.alg());
        for (intermediates, signatures) in [(vec![], 1), (vec![&int], 2)] {
            counted.reset();
            let chain = Chain::build(&root, &intermediates, &ee);
            assert_eq!(
                chain.verify(&with_classical(&[&counted])),
                Ok(()),
                "{set:?}"
            );
            // Each certificate signature was checked by the ML-DSA oracle;
            // the end entity's own key is not used by path validation.
            assert_eq!(counted.counts(), (signatures, signatures), "{set:?}");
        }
        // The end-entity key verifies a handshake-style signature.
        let chain = Chain::build(&root, &[&int], &ee);
        let der = CertificateDer::from(&chain.ee[..]);
        let cert = EndEntityCert::try_from(&der).unwrap();
        counted.reset();
        assert_eq!(
            cert.verify_signature(&counted, b"message", &ee.sign(b"message")),
            Ok(())
        );
        assert_eq!(
            cert.verify_signature(&counted, b"other message", &ee.sign(b"message")),
            Err(Error::InvalidSignatureForPublicKey)
        );
        assert_eq!(counted.counts(), (2, 1));
    }
}

#[test]
fn mixed_parameter_sets() {
    let root = Key::ml_dsa(Set::MlDsa87, "root");
    let int = Key::ml_dsa(Set::MlDsa65, "intermediate");
    let ee = Key::ml_dsa(Set::MlDsa44, "ee");
    let chain = Chain::build(&root, &[&int], &ee);
    let c44 = Counted::new(&ML_DSA_44);
    let c65 = Counted::new(&ML_DSA_65);
    let c87 = Counted::new(&ML_DSA_87);
    assert_eq!(chain.verify(&with_classical(&[&c44, &c65, &c87])), Ok(()));
    // ML-DSA-87 signed the intermediate, ML-DSA-65 the end entity.
    assert_eq!(c87.counts(), (1, 1));
    assert_eq!(c65.counts(), (1, 1));
    assert_eq!(c44.counts(), (0, 0));
    // Each certificate's identifiers are those of its issuer's key.
    let ee_cert = browntls_pki::Cert::try_from(&CertificateDer::from(&chain.ee[..]))
        .unwrap()
        .signed_data()
        .algorithm()
        .to_vec();
    assert_eq!(ee_cert, browntls_pki::alg_id::ML_DSA_65.as_bytes());
}

#[test]
fn hybrid_chains_by_composition() {
    let ml_dsa_ca = Key::ml_dsa(Set::MlDsa65, "ca");
    let ecdsa_ca = Key::p256();
    let ecdsa_ee = Key::p256();
    let ml_dsa_ee = Key::ml_dsa(Set::MlDsa44, "ee");
    let ecdsa = Counted::new(&ECDSA_P256_SHA256);
    let ml = Counted::new(&ML_DSA_65);
    let ml44 = Counted::new(&ML_DSA_44);
    let algs: [&dyn SignatureVerificationAlgorithm; 3] = [&ecdsa, &ml, &ml44];

    // An ECDSA P-256 end entity under an ML-DSA CA.
    let chain = Chain::build(&ml_dsa_ca, &[], &ecdsa_ee);
    assert_eq!(chain.verify(&algs), Ok(()));
    assert_eq!((ecdsa.counts(), ml.counts()), ((0, 0), (1, 1)));
    let der = CertificateDer::from(&chain.ee[..]);
    let cert = EndEntityCert::try_from(&der).unwrap();
    assert_eq!(
        cert.verify_signature(&ecdsa, b"m", &ecdsa_ee.sign(b"m")),
        Ok(())
    );
    assert_eq!(ecdsa.counts(), (1, 1));

    // An ML-DSA end entity under an ECDSA CA, and an ML-DSA intermediate
    // between ECDSA certificates.
    for (intermediates, ecdsa_sigs, ml_sigs, ee) in [
        (vec![], 1, 0, &ml_dsa_ee),
        (vec![&ml_dsa_ca], 1, 1, &ecdsa_ee),
    ] {
        ecdsa.reset();
        ml.reset();
        let chain = Chain::build(&ecdsa_ca, &intermediates, ee);
        assert_eq!(chain.verify(&algs), Ok(()));
        assert_eq!(ecdsa.counts(), (ecdsa_sigs, ecdsa_sigs));
        assert_eq!(ml.counts(), (ml_sigs, ml_sigs));
    }
    let chain = Chain::build(&ecdsa_ca, &[], &ml_dsa_ee);
    let der = CertificateDer::from(&chain.ee[..]);
    let cert = EndEntityCert::try_from(&der).unwrap();
    assert_eq!(
        cert.verify_signature(&ml44, b"m", &ml_dsa_ee.sign(b"m")),
        Ok(())
    );
    assert_eq!(ml44.counts(), (1, 1));
    // The ECDSA algorithm never verifies with the ML-DSA key.
    assert_eq!(
        cert.verify_signature(&ecdsa, b"m", &ml_dsa_ee.sign(b"m")),
        Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
    );
}

#[test]
fn supported_algorithms_are_the_policy() {
    let keys: Vec<Key> = SETS.iter().map(|&set| Key::ml_dsa(set, "ca")).collect();
    let ecdsa = Key::p256();
    for key in &keys {
        // Only classical algorithms: every ML-DSA signature is unsupported.
        for chain in [
            Chain::build(key, &[], key),
            Chain::build(key, &[], &ecdsa),
            Chain::build(&ecdsa, &[key], &ecdsa),
        ] {
            assert_eq!(
                chain.verify(ALGS),
                Err(Error::UnsupportedSignatureAlgorithm),
                "{key:?}"
            );
        }
        // An ML-DSA end entity under an ECDSA CA validates: path validation
        // never uses the end entity's key. Using the key needs an ML-DSA
        // algorithm.
        let chain = Chain::build(&ecdsa, &[], key);
        assert_eq!(chain.verify(ALGS), Ok(()));
        let der = CertificateDer::from(&chain.ee[..]);
        let cert = EndEntityCert::try_from(&der).unwrap();
        assert_eq!(
            cert.verify_signature(&ECDSA_P256_SHA256, b"m", &key.sign(b"m")),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
        );
    }

    // Only ML-DSA-65: ML-DSA-44 and -87 signatures are unsupported, never
    // invalid, and the ML-DSA-65 oracle is not consulted for them.
    let only65 = Counted::new(&ML_DSA_65);
    for key in &keys {
        only65.reset();
        let chain = Chain::build(key, &[], key);
        let expected = if key.set() == Some(Set::MlDsa65) {
            Ok(())
        } else {
            Err(Error::UnsupportedSignatureAlgorithm)
        };
        assert_eq!(chain.verify(&[&only65]), expected, "{key:?}");
        let calls = usize::from(expected.is_ok());
        assert_eq!(only65.counts(), (calls, calls));
    }

    // A parameter-set mismatch: the issuer key is ML-DSA-44, the signature
    // claims ML-DSA-65.
    let k44 = &keys[0];
    let root = CertSpec::ca("root", "root", k44).sign(k44);
    let mut spec = CertSpec::ee("end entity", "root", &keys[2]);
    spec.inner_alg = Some(Set::MlDsa65.alg_id().to_vec());
    let mut signed = spec.signed(k44);
    signed.alg = Set::MlDsa65.alg_id().to_vec();
    let ee = signed.der();
    assert_eq!(
        verify(&ee, &[], &root, ML_DSA_ALGS),
        Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
    );
    assert_eq!(
        verify(&ee, &[], &root, &[&ML_DSA_65]),
        Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
    );
    assert_eq!(
        verify(&ee, &[], &root, &[&ML_DSA_44]),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn signature_budget_with_many_candidate_ml_dsa_anchors() {
    // As `path_search::signature_budget_with_many_candidate_anchors`: 120
    // anchors share the real root's subject but not its key, so each one
    // costs an ML-DSA verification before it is rejected.
    let root = Key::ml_dsa(Set::MlDsa44, "root");
    let decoy = Key::ml_dsa(Set::MlDsa44, "decoy root");
    let ee = Key::ml_dsa(Set::MlDsa44, "ee");
    let chain = Chain::build(&root, &[], &ee);
    let decoy_root = CertificateDer::from(CertSpec::ca("root", "root", &decoy).sign(&decoy));
    let real_root = CertificateDer::from(&chain.root[..]);
    let mut anchors: Vec<TrustAnchor<'_>> =
        vec![anchor_from_trusted_cert(&decoy_root).unwrap(); 120];
    anchors.push(anchor_from_trusted_cert(&real_root).unwrap());
    let ee_der = CertificateDer::from(&chain.ee[..]);
    let run = |anchors: &[TrustAnchor<'_>], counted: &Counted<'_>| {
        common::verify(
            &ee_der,
            &[],
            anchors,
            &[counted],
            NOW,
            KeyUsage::server_auth(),
            None,
            None,
        )
    };
    let counted = Counted::new(&ML_DSA_44);
    assert_eq!(
        run(&anchors, &counted),
        Err(Error::MaximumSignatureChecksExceeded)
    );
    // The budget allows 100 signature checks, all of them failures.
    assert_eq!(counted.counts(), (100, 0));
    // Fewer decoys fit in the budget and the real anchor is found.
    counted.reset();
    assert_eq!(run(&anchors[70..], &counted), Ok(()));
    assert_eq!(counted.counts(), (51, 1));
}

#[test]
fn signature_budget_with_many_candidate_ml_dsa_intermediates() {
    // As `path_search::key_identifier_hint_orders_intermediate_candidates`:
    // decoy intermediates share the real one's subject and are signed by a
    // CA with the real root's subject but another key, so each costs an
    // ML-DSA verification against the real anchor. With an authority key
    // identifier on the end entity, the real intermediate is tried first.
    let root = Key::ml_dsa(Set::MlDsa65, "root");
    let fake_root = Key::ml_dsa(Set::MlDsa65, "fake root");
    let int = Key::ml_dsa(Set::MlDsa44, "intermediate");
    let ee = Key::ml_dsa(Set::MlDsa44, "ee");
    let int_cert = |issuer: &Key, serial: u8| {
        let ski = subject_key_id(&[serial]);
        let mut spec = CertSpec::ca("intermediate", "root", &int).serial(&[1, serial]);
        spec.extensions.push(ski);
        spec.sign(issuer)
    };
    let decoys: Vec<Vec<u8>> = (2..122).map(|n| int_cert(&fake_root, n)).collect();
    let real = int_cert(&root, 1);
    let root_cert = CertSpec::ca("root", "root", &root).sign(&root);
    for with_aki in [false, true] {
        let mut spec = CertSpec::ee("end entity", "intermediate", &ee);
        if with_aki {
            spec.extensions.push(authority_key_id(&[1]));
        }
        let ee_cert = spec.sign(&int);
        let mut intermediates = decoys.clone();
        intermediates.push(real.clone());
        let c65 = Counted::new(&ML_DSA_65);
        let c44 = Counted::new(&ML_DSA_44);
        let result = verify(&ee_cert, &intermediates, &root_cert, &[&c65, &c44]);
        if with_aki {
            assert_eq!(result, Ok(()));
            assert_eq!((c65.counts(), c44.counts()), ((1, 1), (1, 1)));
        } else {
            assert_eq!(result, Err(Error::MaximumSignatureChecksExceeded));
            // Each decoy cost one failed ML-DSA-65 check against the root
            // (signatures are checked from the anchor down), until the
            // budget of 100 ran out.
            assert_eq!(c65.counts(), (100, 0));
            assert_eq!(c44.counts(), (0, 0));
        }
    }
}
