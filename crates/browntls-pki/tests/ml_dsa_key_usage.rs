//! RFC 9881 §5 key usage for ML-DSA certificates in path validation: a
//! present `keyUsage` must assert at least one of digitalSignature,
//! nonRepudiation, keyCertSign and cRLSign, and none of keyEncipherment,
//! dataEncipherment, keyAgreement, encipherOnly and decipherOnly. Checked
//! for the end entity and intermediates; the same bit sets on ECDSA
//! certificates keep the RFC 5280 behaviour (only an issuer's keyCertSign
//! is required, and an absent `keyUsage` permits everything).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ml_dsa.rs"]
mod ml_dsa;
#[path = "common/x509_builder.rs"]
mod x509;

use browntls_pki::{
    CertificateDer, Error, KeyUsage, SignatureVerificationAlgorithm, anchor_from_trusted_cert,
};
use common::{ALGS, NOW};
use ml_dsa::{Key, ML_DSA_ALGS, SETS, Set};
use x509::{CertSpec, ku};

const ALLOWED: [u8; 4] = [
    ku::DIGITAL_SIGNATURE,
    ku::NON_REPUDIATION,
    ku::KEY_CERT_SIGN,
    ku::CRL_SIGN,
];
const FORBIDDEN: [u8; 5] = [
    ku::KEY_ENCIPHERMENT,
    ku::DATA_ENCIPHERMENT,
    ku::KEY_AGREEMENT,
    ku::ENCIPHER_ONLY,
    ku::DECIPHER_ONLY,
];

/// Every single bit, no bit at all, combinations around the rule, all
/// bits, and an absent extension (`None`).
fn cases() -> Vec<Option<Vec<u8>>> {
    let mut cases: Vec<Option<Vec<u8>>> = (0..9).map(|bit| Some(vec![bit])).collect();
    cases.extend(
        [
            vec![],
            ALLOWED.to_vec(),
            vec![ku::KEY_CERT_SIGN, ku::CRL_SIGN],
            vec![ku::DIGITAL_SIGNATURE, ku::KEY_ENCIPHERMENT],
            vec![ku::DIGITAL_SIGNATURE, ku::KEY_AGREEMENT, ku::ENCIPHER_ONLY],
            vec![ku::KEY_CERT_SIGN, ku::CRL_SIGN, ku::KEY_AGREEMENT],
            vec![ku::KEY_CERT_SIGN, ku::DATA_ENCIPHERMENT],
            vec![ku::KEY_CERT_SIGN, ku::ENCIPHER_ONLY],
            vec![ku::KEY_CERT_SIGN, ku::DECIPHER_ONLY],
            vec![ku::NON_REPUDIATION, ku::DECIPHER_ONLY],
            (0..9).collect(),
        ]
        .into_iter()
        .map(Some),
    );
    cases.push(None);
    cases
}

/// RFC 9881 §5 for an ML-DSA key.
fn ml_dsa_permits(bits: &Option<Vec<u8>>) -> bool {
    bits.as_ref().is_none_or(|bits| {
        bits.iter().any(|b| ALLOWED.contains(b)) && !bits.iter().any(|b| FORBIDDEN.contains(b))
    })
}

/// RFC 5280 §6.1.4 (n): an issuer's `keyUsage`, when present, asserts
/// keyCertSign.
fn issuer_permits(bits: &Option<Vec<u8>>) -> bool {
    bits.as_ref()
        .is_none_or(|bits| bits.contains(&ku::KEY_CERT_SIGN))
}

fn algs() -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    ALGS.iter().chain(ML_DSA_ALGS).copied().collect()
}

fn verify(ee: &[u8], intermediates: &[Vec<u8>], root: &[u8]) -> Result<(), Error> {
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
        &algs(),
        NOW,
        KeyUsage::server_auth(),
        None,
        None,
    )
}

fn describe(bits: &Option<Vec<u8>>) -> String {
    match bits {
        None => "absent".into(),
        Some(bits) => format!(
            "{:?}",
            bits.iter()
                .map(|&b| ku::NAMES[usize::from(b)])
                .collect::<Vec<_>>()
        ),
    }
}

/// The subject keys under test: each ML-DSA parameter set and ECDSA P-256.
fn subject_keys(label: &str) -> Vec<Key> {
    let mut keys: Vec<Key> = SETS.iter().map(|&set| Key::ml_dsa(set, label)).collect();
    keys.push(Key::p256());
    keys
}

#[test]
fn end_entity_key_usage() {
    let root = Key::ml_dsa(Set::MlDsa65, "root");
    let root_cert = CertSpec::ca("root", "root", &root).sign(&root);
    for ee in subject_keys("ee") {
        for bits in cases() {
            let cert = CertSpec::ee("end entity", "root", &ee)
                .key_usage(bits.as_deref())
                .sign(&root);
            // An ECDSA end entity's key usage is left to the protocol layer,
            // as before.
            let expected = if ee.set().is_none() || ml_dsa_permits(&bits) {
                Ok(())
            } else {
                Err(Error::KeyUsageNotPermittedForPublicKey)
            };
            assert_eq!(
                verify(&cert, &[], &root_cert),
                expected,
                "{ee:?} {}",
                describe(&bits)
            );
        }
    }
}

#[test]
fn intermediate_key_usage() {
    let root = Key::ml_dsa(Set::MlDsa87, "root");
    let root_cert = CertSpec::ca("root", "root", &root).sign(&root);
    let ee = Key::ml_dsa(Set::MlDsa44, "ee");
    for int in subject_keys("intermediate") {
        for bits in cases() {
            let int_cert = CertSpec::ca("intermediate", "root", &int)
                .key_usage(bits.as_deref())
                .sign(&root);
            let ee_cert = CertSpec::ee("end entity", "intermediate", &ee).sign(&int);
            // The RFC 9881 rule is checked before the issuer's keyCertSign.
            let expected = if int.set().is_some() && !ml_dsa_permits(&bits) {
                Err(Error::KeyUsageNotPermittedForPublicKey)
            } else if !issuer_permits(&bits) {
                Err(Error::IssuerNotCertSigner)
            } else {
                Ok(())
            };
            assert_eq!(
                verify(&ee_cert, &[int_cert], &root_cert),
                expected,
                "{int:?} {}",
                describe(&bits)
            );
        }
    }
}

#[test]
fn trust_anchor_key_usage_is_not_consulted() {
    // A trust anchor is reduced to its subject, key and name constraints,
    // so its keyUsage, even one RFC 9881 forbids, plays no part.
    for set in SETS {
        let root = Key::ml_dsa(set, "root");
        let ee = Key::ml_dsa(set, "ee");
        let root_cert = CertSpec::ca("root", "root", &root)
            .key_usage(Some(&[ku::KEY_AGREEMENT]))
            .sign(&root);
        let ee_cert = CertSpec::ee("end entity", "root", &ee).sign(&root);
        assert_eq!(verify(&ee_cert, &[], &root_cert), Ok(()), "{set:?}");
    }
}

#[test]
fn key_usage_rule_applies_without_ml_dsa_algorithms() {
    // The rule depends on the certificate alone, so it is reported even
    // when no ML-DSA algorithm is supplied (and ranks above an
    // unsupported signature algorithm).
    let root = Key::ml_dsa(Set::MlDsa65, "root");
    let root_cert = CertSpec::ca("root", "root", &root).sign(&root);
    let ee = Key::ml_dsa(Set::MlDsa65, "ee");
    let cert = CertSpec::ee("end entity", "root", &ee)
        .key_usage(Some(&[ku::DIGITAL_SIGNATURE, ku::KEY_ENCIPHERMENT]))
        .sign(&root);
    let root = CertificateDer::from(&root_cert[..]);
    let anchors = [anchor_from_trusted_cert(&root).unwrap()];
    assert_eq!(
        common::verify(
            &CertificateDer::from(&cert[..]),
            &[],
            &anchors,
            ALGS,
            NOW,
            KeyUsage::server_auth(),
            None,
            None,
        ),
        Err(Error::KeyUsageNotPermittedForPublicKey)
    );
}

/// `keyUsage` (critical) with raw `BIT STRING` contents.
fn raw_key_usage(spec: CertSpec, bits: &[u8]) -> CertSpec {
    let mut spec = spec.key_usage(None);
    spec.extensions.push(x509::extension(
        &[0x55, 0x1d, 0x0f],
        true,
        &x509::tlv(0x03, bits),
    ));
    spec
}

#[test]
fn unusual_key_usage_encodings() {
    // (BIT STRING contents, accepted on an ML-DSA end entity, accepted on
    // an ML-DSA intermediate, accepted on an ECDSA intermediate). Parsing
    // only checks that padding bits are zero, so a trailing zero octet
    // (not minimal DER) and the undefined bit 9 are read as they are, and
    // only the nine RFC 5280 bits count.
    let cases: [(&[u8], bool, bool, bool); 7] = [
        // No bit at all.
        (&[0x00], false, false, false),
        // Only bit 9.
        (&[0x06, 0x00, 0x40], false, false, false),
        // digitalSignature with a trailing zero octet.
        (&[0x00, 0x80, 0x00], true, false, false),
        // digitalSignature and bit 9.
        (&[0x06, 0x80, 0x40], true, false, false),
        // keyCertSign with a trailing zero octet.
        (&[0x00, 0x04, 0x00], true, true, true),
        // keyCertSign and bit 9.
        (&[0x06, 0x04, 0x40], true, true, true),
        // keyCertSign and keyAgreement.
        (&[0x02, 0x0c], false, false, true),
    ];
    let root = Key::ml_dsa(Set::MlDsa65, "root");
    let root_cert = CertSpec::ca("root", "root", &root).sign(&root);
    let leaf = Key::ml_dsa(Set::MlDsa44, "leaf");
    for key in subject_keys("subject") {
        let ml_dsa = key.set().is_some();
        for (bits, ee_ok, int_ok, ecdsa_int_ok) in cases {
            // End entity: an ECDSA end entity's key usage is not checked.
            let ee = raw_key_usage(CertSpec::ee("end entity", "root", &key), bits).sign(&root);
            let expected = if ee_ok || !ml_dsa {
                Ok(())
            } else {
                Err(Error::KeyUsageNotPermittedForPublicKey)
            };
            assert_eq!(
                verify(&ee, &[], &root_cert),
                expected,
                "{key:?} ee {bits:02x?}"
            );

            // Intermediate.
            let int = raw_key_usage(CertSpec::ca("intermediate", "root", &key), bits).sign(&root);
            let ee = CertSpec::ee("end entity", "intermediate", &leaf).sign(&key);
            let expected = match (ml_dsa, int_ok, ecdsa_int_ok, ee_ok) {
                (true, true, _, _) | (false, _, true, _) => Ok(()),
                // RFC 9881 §5 is checked before the issuer's keyCertSign.
                (true, false, _, false) => Err(Error::KeyUsageNotPermittedForPublicKey),
                _ => Err(Error::IssuerNotCertSigner),
            };
            assert_eq!(
                verify(&ee, &[int], &root_cert),
                expected,
                "{key:?} intermediate {bits:02x?}"
            );
        }
    }
}
