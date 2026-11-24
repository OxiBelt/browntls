//! Wrong ML-DSA encodings in certificates (RFC 9881 §§2-4): parameters
//! other than absent, disagreeing or crossed identifiers, foreign and
//! pre-standard OIDs, keys and signatures of the wrong length, `BIT STRING`
//! unused bits and flipped bits. Each case asserts the exact error.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ml_dsa.rs"]
mod ml_dsa;
#[path = "common/x509_builder.rs"]
mod x509;

use browntls_pki::{
    CertificateDer, Der, EndEntityCert, Error, KeyUsage, SignatureVerificationAlgorithm,
    TrustAnchor, alg_id, anchor_from_trusted_cert,
};
use common::{ALGS, NOW};
use ml_dsa::{Key, ML_DSA_ALGS, SETS, Set, foreign_alg_ids, with_null_params};
use x509::{CertSpec, find, flip, ku, name, seq, spki, tlv};

/// Every classical and ML-DSA test algorithm.
fn all_algs() -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    ALGS.iter().chain(ML_DSA_ALGS).copied().collect()
}

/// A trust anchor named `root` with the given `SubjectPublicKeyInfo`.
fn anchor(spki_der: &[u8]) -> TrustAnchor<'static> {
    let subject = name("root");
    TrustAnchor {
        subject: Der::from(subject[2..].to_vec()),
        subject_public_key_info: Der::from(spki_der[spki_contents_offset(spki_der)..].to_vec()),
        name_constraints: None,
    }
}

fn spki_contents_offset(spki: &[u8]) -> usize {
    match spki[1] {
        n if n < 0x80 => 2,
        0x81 => 3,
        _ => 4,
    }
}

fn verify_with(
    ee: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[TrustAnchor<'_>],
) -> Result<(), Error> {
    let ints: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|c| CertificateDer::from(&c[..]))
        .collect();
    common::verify(
        &CertificateDer::from(ee),
        &ints,
        anchors,
        &all_algs(),
        NOW,
        KeyUsage::server_auth(),
        None,
        None,
    )
}

/// Verifies `ee` against the anchor holding `root`'s key.
fn verify(ee: &[u8], root: &Key) -> Result<(), Error> {
    verify_with(ee, &[], &[anchor(&x509::spki_of(root))])
}

#[test]
fn parameters_must_be_absent_in_both_signature_fields() {
    for set in SETS {
        let root = Key::ml_dsa(set, "root");
        let ee = Key::ml_dsa(set, "ee");
        let spec = CertSpec::ee("end entity", "root", &ee);
        assert_eq!(verify(&spec.sign(&root), &root), Ok(()));
        let null = with_null_params(set.alg_id());

        // Outer NULL, inner absent: the two fields disagree.
        let mut signed = spec.signed(&root);
        signed.alg = null.clone();
        assert_eq!(
            verify(&signed.der(), &root),
            Err(Error::SignatureAlgorithmMismatch)
        );
        // Inner NULL, outer absent.
        let mut inner = spec.clone();
        inner.inner_alg = Some(null.clone());
        assert_eq!(
            verify(&inner.sign(&root), &root),
            Err(Error::SignatureAlgorithmMismatch)
        );
        // NULL in both: consistent, but no algorithm is declared with
        // parameters, so the signature is unsupported (never verified).
        let mut both = inner.signed(&root);
        both.alg = null.clone();
        assert_eq!(
            verify(&both.der(), &root),
            Err(Error::UnsupportedSignatureAlgorithm)
        );
        // Other parameters (an empty SEQUENCE) are no better.
        let seq_params = [set.alg_id().as_bytes(), &[0x30, 0x00]].concat();
        let mut other = spec.clone();
        other.inner_alg = Some(seq_params.clone());
        let mut other = other.signed(&root);
        other.alg = seq_params;
        assert_eq!(
            verify(&other.der(), &root),
            Err(Error::UnsupportedSignatureAlgorithm)
        );
    }
}

#[test]
fn inner_and_outer_identifiers_must_agree() {
    let root = Key::ml_dsa(Set::MlDsa65, "root");
    let ee = Key::ml_dsa(Set::MlDsa44, "ee");
    let spec = CertSpec::ee("end entity", "root", &ee);
    for outer in [
        alg_id::ML_DSA_44,
        alg_id::ML_DSA_87,
        alg_id::ECDSA_SHA256,
        alg_id::ED25519,
    ] {
        let mut signed = spec.signed(&root);
        signed.alg = outer.to_vec();
        assert_eq!(
            verify(&signed.der(), &root),
            Err(Error::SignatureAlgorithmMismatch),
            "{outer:?}"
        );
        let der = signed.der();
        assert_eq!(
            EndEntityCert::try_from(&CertificateDer::from(&der[..])).err(),
            Some(Error::SignatureAlgorithmMismatch)
        );
    }
}

#[test]
fn identifiers_must_match_the_issuer_key_type() {
    let ml_dsa = Key::ml_dsa(Set::MlDsa65, "root");
    let ecdsa = Key::p256();
    let ee = Key::ml_dsa(Set::MlDsa44, "ee");
    // An ML-DSA signature identifier with an ECDSA issuer key, and an
    // ECDSA identifier with an ML-DSA issuer key.
    for (issuer, claimed) in [(&ecdsa, alg_id::ML_DSA_65), (&ml_dsa, alg_id::ECDSA_SHA256)] {
        let mut spec = CertSpec::ee("end entity", "root", &ee);
        spec.inner_alg = Some(claimed.to_vec());
        let mut signed = spec.signed(issuer);
        signed.alg = claimed.to_vec();
        assert_eq!(
            verify(&signed.der(), issuer),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            "{issuer:?}"
        );
    }
}

#[test]
fn foreign_and_pre_standard_identifiers_are_unsupported() {
    let root = Key::ml_dsa(Set::MlDsa65, "root");
    let ee = Key::ml_dsa(Set::MlDsa44, "ee");
    for (label, foreign) in foreign_alg_ids() {
        // As the certificate signature algorithm (both fields).
        let mut spec = CertSpec::ee("end entity", "root", &ee);
        spec.inner_alg = Some(foreign.clone());
        let mut signed = spec.signed(&root);
        signed.alg = foreign.clone();
        assert_eq!(
            verify(&signed.der(), &root),
            Err(Error::UnsupportedSignatureAlgorithm),
            "{label}"
        );
        // As the issuer's key algorithm, with a genuine ML-DSA-65
        // signature by that key.
        let cert = CertSpec::ee("end entity", "root", &ee).sign(&root);
        let anchors = [anchor(&spki(&foreign, &root.public_key()))];
        assert_eq!(
            verify_with(&cert, &[], &anchors),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
            "{label}"
        );
        // As an end-entity key algorithm: the key matches no algorithm.
        let mut spec = CertSpec::ee("end entity", "root", &ee);
        spec.spki = spki(&foreign, &ee.public_key());
        let der = spec.sign(&root);
        assert_eq!(verify(&der, &root), Ok(()), "{label}");
        let der = CertificateDer::from(&der[..]);
        let cert = EndEntityCert::try_from(&der).unwrap();
        for alg in ML_DSA_ALGS {
            assert_eq!(
                cert.verify_signature(*alg, b"m", &ee.sign(b"m")),
                Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
                "{label}"
            );
        }
    }
}

#[test]
fn key_parameters_must_be_absent() {
    for set in SETS {
        let root = Key::ml_dsa(set, "root");
        let int = Key::ml_dsa(set, "intermediate");
        let ee = Key::ml_dsa(set, "ee");
        let null = with_null_params(set.alg_id());
        // The anchor's key with NULL parameters.
        let cert = CertSpec::ee("end entity", "root", &ee).sign(&root);
        let anchors = [anchor(&spki(&null, &root.public_key()))];
        assert_eq!(
            verify_with(&cert, &[], &anchors),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
        );
        // An intermediate's key with NULL parameters.
        let mut int_spec = CertSpec::ca("intermediate", "root", &int);
        int_spec.spki = spki(&null, &int.public_key());
        let int_cert = int_spec.sign(&root);
        let ee_cert = CertSpec::ee("end entity", "intermediate", &ee).sign(&int);
        let anchors = [anchor(&x509::spki_of(&root))];
        assert_eq!(
            verify_with(&ee_cert, &[int_cert], &anchors),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
        );
        // An end entity's key with NULL parameters: path validation does
        // not use it, but no algorithm verifies with it.
        let mut ee_spec = CertSpec::ee("end entity", "root", &ee);
        ee_spec.spki = spki(&null, &ee.public_key());
        let der = ee_spec.sign(&root);
        assert_eq!(verify(&der, &root), Ok(()));
        let der = CertificateDer::from(&der[..]);
        let cert = EndEntityCert::try_from(&der).unwrap();
        assert_eq!(
            cert.verify_signature(set.alg(), b"m", &ee.sign(b"m")),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
        );
        // RFC 9881 §5 still applies to such a key (it is identified by
        // its OID).
        let ee_spec = ee_spec.key_usage(Some(&[ku::KEY_AGREEMENT]));
        assert_eq!(
            verify(&ee_spec.sign(&root), &root),
            Err(Error::KeyUsageNotPermittedForPublicKey)
        );
    }
}

/// `key` resized to `len` octets (truncated, or extended with zeros).
fn resized(key: &[u8], len: usize) -> Vec<u8> {
    let mut key = key.to_vec();
    key.resize(len, 0);
    key
}

#[test]
fn keys_of_the_wrong_length_are_invalid() {
    for set in SETS {
        let root = Key::ml_dsa(set, "root");
        let int = Key::ml_dsa(set, "intermediate");
        let ee = Key::ml_dsa(set, "ee");
        let cert = CertSpec::ee("end entity", "root", &ee).sign(&root);
        let key = root.public_key();
        assert_eq!(key.len(), set.public_key_len());
        let mut lengths = vec![key.len() - 1, key.len() + 1, 0];
        lengths.extend(
            SETS.iter()
                .filter(|&&s| s != set)
                .map(|s| s.public_key_len()),
        );
        for len in lengths {
            let anchors = [anchor(&spki(set.alg_id().as_bytes(), &resized(&key, len)))];
            assert_eq!(
                verify_with(&cert, &[], &anchors),
                Err(Error::InvalidSignatureForPublicKey),
                "{set:?} {len}"
            );
        }
        // A truncated intermediate key.
        let mut int_spec = CertSpec::ca("intermediate", "root", &int);
        let int_key = int.public_key();
        int_spec.spki = spki(set.alg_id().as_bytes(), &int_key[..int_key.len() - 1]);
        let int_cert = int_spec.sign(&root);
        let ee_cert = CertSpec::ee("end entity", "intermediate", &ee).sign(&int);
        let anchors = [anchor(&x509::spki_of(&root))];
        assert_eq!(
            verify_with(&ee_cert, &[int_cert], &anchors),
            Err(Error::InvalidSignatureForPublicKey)
        );
    }
}

#[test]
fn signatures_of_the_wrong_length_are_invalid() {
    for set in SETS {
        let root = Key::ml_dsa(set, "root");
        let ee = Key::ml_dsa(set, "ee");
        let signed = CertSpec::ee("end entity", "root", &ee).signed(&root);
        let sig = signed.signature().to_vec();
        assert_eq!(sig.len(), set.signature_len());
        let mut lengths = vec![sig.len() - 1, sig.len() + 1, 0];
        lengths.extend(
            SETS.iter()
                .filter(|&&s| s != set)
                .map(|s| s.signature_len()),
        );
        for len in lengths {
            let mut bad = signed.clone();
            bad.set_signature(&resized(&sig, len));
            assert_eq!(
                verify(&bad.der(), &root),
                Err(Error::InvalidSignatureForPublicKey),
                "{set:?} {len}"
            );
        }
    }
}

#[test]
fn bit_strings_must_have_no_unused_bits() {
    let root = Key::ml_dsa(Set::MlDsa87, "root");
    let ee = Key::ml_dsa(Set::MlDsa87, "ee");
    let spec = CertSpec::ee("end entity", "root", &ee);
    // The signature BIT STRING (the last octet's low bit is zero, so only
    // the unused-bit count is wrong).
    let mut signed = spec.signed(&root);
    let mut sig = signed.signature().to_vec();
    *sig.last_mut().unwrap() &= 0xfe;
    signed.bits = [&[1u8][..], &sig].concat();
    assert_eq!(verify(&signed.der(), &root), Err(Error::BadDer));
    // The end entity's key.
    let mut key = ee.public_key();
    *key.last_mut().unwrap() &= 0xfe;
    let mut ee_spec = spec.clone();
    ee_spec.spki = seq(&[
        &x509::alg(alg_id::ML_DSA_87.as_bytes()),
        &tlv(0x03, &[&[1u8][..], &key].concat()),
    ]);
    assert_eq!(verify(&ee_spec.sign(&root), &root), Err(Error::BadDer));
    // A trust anchor's key, from a certificate or given directly.
    let mut root_key = root.public_key();
    *root_key.last_mut().unwrap() &= 0xfe;
    let bad_spki = seq(&[
        &x509::alg(alg_id::ML_DSA_87.as_bytes()),
        &tlv(0x03, &[&[1u8][..], &root_key].concat()),
    ]);
    let mut root_spec = CertSpec::ca("root", "root", &root);
    root_spec.spki = bad_spki.clone();
    let root_cert = root_spec.sign(&root);
    assert_eq!(
        anchor_from_trusted_cert(&CertificateDer::from(&root_cert[..])).err(),
        Some(Error::BadDer)
    );
    assert_eq!(
        verify_with(&spec.sign(&root), &[], &[anchor(&bad_spki)]),
        Err(Error::BadDer)
    );
}

#[test]
fn flipped_bits_are_invalid() {
    for set in SETS {
        let root = Key::ml_dsa(set, "root");
        let ee = Key::ml_dsa(set, "ee");
        let signed = CertSpec::ee("end entity", "root", &ee).signed(&root);
        assert_eq!(verify(&signed.der(), &root), Ok(()));
        // In the tbsCertificate: the serial number, the subject key, the
        // DNS name.
        let ee_key = ee.public_key();
        // (The serial's contents start at index 11, after `30 82 LL LL`,
        // the version `a0 03 02 01 02` and the INTEGER tag and length.)
        for index in [
            12,
            find(&signed.tbs, &ee_key) + ee_key.len() / 2,
            find(&signed.tbs, b"example.com"),
        ] {
            let mut bad = signed.clone();
            bad.tbs = flip(bad.tbs, index);
            assert_eq!(
                verify(&bad.der(), &root),
                Err(Error::InvalidSignatureForPublicKey),
                "{set:?} tbs {index}"
            );
        }
        // In the signature: first, middle and last octets.
        let sig_len = signed.bits.len();
        for index in [1, sig_len / 2, sig_len - 1] {
            let mut bad = signed.clone();
            bad.bits = flip(bad.bits, index);
            assert_eq!(
                verify(&bad.der(), &root),
                Err(Error::InvalidSignatureForPublicKey),
                "{set:?} signature {index}"
            );
        }
        // In the issuer's key.
        let key = root.public_key();
        for index in [0, 32, key.len() - 1] {
            let anchors = [anchor(&spki(
                set.alg_id().as_bytes(),
                &flip(key.clone(), index),
            ))];
            assert_eq!(
                verify_with(&signed.der(), &[], &anchors),
                Err(Error::InvalidSignatureForPublicKey),
                "{set:?} key {index}"
            );
        }
    }
}
