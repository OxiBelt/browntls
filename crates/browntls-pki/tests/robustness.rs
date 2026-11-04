//! Malformed-input robustness: truncation at every position, random byte
//! mutation and pathological encodings must never panic, and no mutation of
//! a valid certificate may still verify.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browntls_pki::{
    BorrowedCertRevocationList, CertRevocationList, CertificateDer, Der, EndEntityCert, Error,
    KeyUsage, OwnedCertRevocationList, RawPublicKeyEntity, ServerName, SubjectPublicKeyInfoDer,
    TrustAnchor, anchor_from_trusted_cert,
};
use common::*;
use rcgen::{
    CertificateRevocationListParams, KeyIdMethod, PublicKeyData as _, RevocationReason,
    RevokedCertParams, SerialNumber,
};

/// xorshift64*: deterministic, so failures reproduce.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// Flips, replaces, inserts or deletes a few bytes.
    fn mutate(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        for _ in 0..=self.below(3) {
            if out.is_empty() {
                out.push(self.next() as u8);
                continue;
            }
            let i = self.below(out.len());
            match self.below(10) {
                0 => out[i] ^= 1 << self.below(8),
                1 => out.insert(i, self.next() as u8),
                2 => {
                    out.remove(i);
                }
                3 => out[i] = 0xff,
                4 => out[i] = 0x00,
                5 => out[i] = 0x80,
                _ => out[i] = self.next() as u8,
            }
        }
        out
    }
}

fn fixture() -> (Chain, Vec<u8>) {
    let mut ee = ee_params(&["example.com", "192.0.2.1"]);
    ee.use_authority_key_identifier_extension = true;
    ee.serial_number = Some(SerialNumber::from_slice(&[0x7a, 1, 2, 3]));
    let chain = Chain::build(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        ca_params("root"),
        vec![ca_params("intermediate")],
        &ee,
    );
    let crl = CertificateRevocationListParams {
        this_update: at(1_717_000_000),
        next_update: at(1_718_000_000),
        crl_number: SerialNumber::from(7u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from_slice(&[0x7b, 4, 5, 6]),
            revocation_time: at(1_716_000_000),
            reason_code: Some(RevocationReason::Superseded),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&chain.intermediates[0])
    .unwrap()
    .der()
    .to_vec();
    (chain, crl)
}

/// Runs every public operation on `cert` against `chain`, returning whether
/// the path verified.
fn exercise(cert: &[u8], chain: &Chain, crl: &CertRevocationList<'_>) -> bool {
    let der = CertificateDer::from(cert);
    let Ok(ee) = EndEntityCert::try_from(&der) else {
        return false;
    };
    let _ = ee.verify_is_valid_for_subject_name(&ServerName::try_from("example.com").unwrap());
    let _ = ee.verify_is_valid_for_subject_name(&ServerName::try_from("192.0.2.1").unwrap());
    let _ = ee.verify_signature(
        &ECDSA_P256_SHA256,
        b"msg",
        &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    );
    let _ = ee.subject_public_key_info();
    let roots = [chain.root_der()];
    let anchors = anchors(&roots);
    let intermediates = chain.intermediate_ders();
    let crls = [crl];
    let revocation = browntls_pki::RevocationOptionsBuilder::new(&crls)
        .unwrap()
        .build();
    let plain = ee.verify_for_usage(
        ALGS,
        &anchors,
        &intermediates,
        NOW,
        KeyUsage::server_auth(),
        None,
        None,
    );
    let _ = ee.verify_for_usage(
        ALGS,
        &anchors,
        &intermediates,
        NOW,
        KeyUsage::server_auth(),
        Some(revocation),
        None,
    );
    plain.is_ok()
}

#[test]
fn truncated_inputs_are_rejected_without_panicking() {
    let (chain, crl) = fixture();
    let ee = chain.ee_der();
    for len in 0..ee.len() {
        let der = CertificateDer::from(&ee[..len]);
        assert!(EndEntityCert::try_from(&der).is_err(), "prefix {len}");
        assert!(
            anchor_from_trusted_cert(&der).is_err(),
            "anchor prefix {len}"
        );
    }
    for len in 0..crl.len() {
        assert!(
            BorrowedCertRevocationList::from_der(&crl[..len]).is_err(),
            "crl prefix {len}"
        );
        assert!(OwnedCertRevocationList::from_der(&crl[..len]).is_err());
    }
    let spki = chain.ee_key.subject_public_key_info();
    for len in 0..spki.len() {
        let der = SubjectPublicKeyInfoDer::from(&spki[..len]);
        assert!(
            RawPublicKeyEntity::try_from(&der).is_err(),
            "spki prefix {len}"
        );
    }
    // Trailing bytes are also rejected.
    let mut extended = ee.to_vec();
    extended.push(0);
    assert_eq!(
        EndEntityCert::try_from(&CertificateDer::from(extended.as_slice())).err(),
        Some(Error::TrailingData)
    );
}

#[test]
fn mutated_certificates_never_verify_and_never_panic() {
    let (chain, crl_der) = fixture();
    let crl = CertRevocationList::from(BorrowedCertRevocationList::from_der(&crl_der).unwrap());
    let ee = chain.ee_der();
    assert!(exercise(&ee, &chain, &crl), "fixture must verify");
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut parsed = 0;
    for _ in 0..3000 {
        let mutated = rng.mutate(&ee);
        if mutated.as_slice() == ee.as_ref() {
            continue;
        }
        if EndEntityCert::try_from(&CertificateDer::from(mutated.as_slice())).is_ok() {
            parsed += 1;
        }
        assert!(
            !exercise(&mutated, &chain, &crl),
            "mutated certificate verified: {}",
            hex::encode(&mutated)
        );
    }
    // Some mutations (e.g. in the signature value) still parse, which keeps
    // the later stages exercised.
    assert!(parsed > 0);
}

#[test]
fn mutated_crls_never_panic() {
    let (chain, crl_der) = fixture();
    let int_der: CertificateDer<'_> = chain.intermediates[0].der().to_vec().into();
    let int_anchor = anchor_from_trusted_cert(&int_der).unwrap();
    let issuer_spki = int_anchor.subject_public_key_info.as_ref();
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..3000 {
        let mutated = rng.mutate(&crl_der);
        let changed = mutated.as_slice() != crl_der.as_slice();
        if let Ok(crl) = BorrowedCertRevocationList::from_der(&mutated) {
            let crl = CertRevocationList::from(crl);
            let _ = crl.find_serial(&[0x7b, 4, 5, 6]);
            let _ = crl.find_serial(&[0x7a, 1, 2, 3]);
            let _ = crl.issuing_distribution_point();
            let verified = crl.verify_signature(ALGS, issuer_spki);
            assert!(!changed || verified.is_err(), "mutated CRL verified");
        }
        let _ = OwnedCertRevocationList::from_der(&mutated);
    }
}

#[test]
fn mutated_keys_and_signatures_never_verify() {
    let (chain, _) = fixture();
    let spki = chain.ee_key.subject_public_key_info();
    let msg = b"handshake transcript";
    let sig = sign(&chain.ee_key, msg);
    let spki_der = SubjectPublicKeyInfoDer::from(spki.as_slice());
    let rpk = RawPublicKeyEntity::try_from(&spki_der).unwrap();
    assert_eq!(rpk.verify_signature(&ECDSA_P256_SHA256, msg, &sig), Ok(()));
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..2000 {
        let bad_sig = rng.mutate(&sig);
        if bad_sig != sig {
            assert!(
                rpk.verify_signature(&ECDSA_P256_SHA256, msg, &bad_sig)
                    .is_err()
            );
        }
        let bad_spki = rng.mutate(&spki);
        let bad_spki = SubjectPublicKeyInfoDer::from(bad_spki.as_slice());
        if let Ok(bad) = RawPublicKeyEntity::try_from(&bad_spki) {
            let _ = bad.verify_signature(&ECDSA_P256_SHA256, msg, &sig);
        }
    }
}

#[test]
fn pathological_encodings() {
    // Lengths beyond the input, maximal four-octet lengths, nested garbage.
    for bytes in [
        &[0x30u8, 0x84, 0xff, 0xff, 0xff, 0xff][..],
        &[0x30, 0x82, 0xff, 0xff, 0x30],
        &[0x30, 0x80, 0x00, 0x00],
        &[0x30, 0x00],
        &[0x30, 0x01],
        &[],
        &[0x30],
        &[0xff; 64],
        &[0x00; 64],
    ] {
        let der = CertificateDer::from(bytes);
        assert!(EndEntityCert::try_from(&der).is_err());
        assert!(anchor_from_trusted_cert(&der).is_err());
        assert!(BorrowedCertRevocationList::from_der(bytes).is_err());
        let spki = SubjectPublicKeyInfoDer::from(bytes);
        assert!(RawPublicKeyEntity::try_from(&spki).is_err());
    }
    // Deeply nested sequences with correct lengths.
    let mut nested = Vec::new();
    for depth in 0..2000u32 {
        let inner = nested;
        nested = Vec::with_capacity(inner.len() + 6);
        nested.push(0x30);
        let len = inner.len();
        if len < 0x80 {
            nested.push(len as u8);
        } else if len < 0x100 {
            nested.extend_from_slice(&[0x81, len as u8]);
        } else {
            nested.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        nested.extend_from_slice(&inner);
        if depth % 500 == 499 {
            let der = CertificateDer::from(nested.as_slice());
            assert!(EndEntityCert::try_from(&der).is_err());
            assert!(BorrowedCertRevocationList::from_der(&nested).is_err());
        }
    }
}

#[test]
fn garbage_anchor_fields_are_errors_not_panics() {
    let (chain, _) = fixture();
    let root = chain.root_der();
    let good = anchor_from_trusted_cert(&root).unwrap();
    let ee = chain.ee_der();
    let intermediates = chain.intermediate_ders();
    let usage = KeyUsage::server_auth();
    // Malformed name constraints on the anchor.
    let bad_nc = TrustAnchor {
        subject: good.subject.clone(),
        subject_public_key_info: good.subject_public_key_info.clone(),
        name_constraints: Some(Der::from_slice(&[0x30, 0x03, 0xa0, 0x01, 0x00])),
    };
    assert_eq!(
        verify(&ee, &intermediates, &[bad_nc], ALGS, NOW, usage, None, None),
        Err(Error::MalformedNameConstraint)
    );
    // Malformed SPKI on the anchor.
    let bad_spki = TrustAnchor {
        subject: good.subject.clone(),
        subject_public_key_info: Der::from_slice(&[0x30, 0x00]),
        name_constraints: None,
    };
    assert_eq!(
        verify(
            &ee,
            &intermediates,
            &[bad_spki],
            ALGS,
            NOW,
            usage,
            None,
            None
        ),
        Err(Error::BadDer)
    );
    // Garbage SPKI for CRL verification.
    let (_, crl) = fixture();
    let crl = CertRevocationList::from(BorrowedCertRevocationList::from_der(&crl).unwrap());
    assert!(
        crl.verify_signature(ALGS, &[0x30, 0x02, 0x05, 0x00])
            .is_err()
    );
    assert!(crl.verify_signature(ALGS, &[]).is_err());
}
