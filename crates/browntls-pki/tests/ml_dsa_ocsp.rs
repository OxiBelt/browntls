//! OCSP responses signed with ML-DSA (RFC 9881): by the issuing CA itself
//! and by a delegated responder, whose key usage must satisfy both RFC 6960
//! (digitalSignature, when keyUsage is present) and RFC 9881 §5 for an
//! ML-DSA key. Also checks that the largest ML-DSA response fits within
//! `ocsp::MAX_RESPONSE_LEN`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ml_dsa.rs"]
mod ml_dsa;
#[path = "common/ocsp.rs"]
mod support;
#[path = "common/x509_builder.rs"]
mod x509;

use browntls_pki::SignatureVerificationAlgorithm;
use browntls_pki::ocsp::MAX_RESPONSE_LEN;
use ml_dsa::{Key, ML_DSA_ALGS, SETS, Set};
use support::{
    ALGS, CertIdHash, CertStatus, CertificateDer, DELEGATE_SERIAL, EE_SERIAL, HASHERS,
    KeyUsagePurpose, NOW, OcspError, OcspIssuer, OcspPolicy, OcspSigner, Response, Single,
    VerifiedOcspStatus, sha1, successful, verify_response,
};
use x509::{CertSpec, ku};

/// `id-kp-OCSPSigning` and `id-pkix-ocsp-nocheck` (encoded arcs).
const KP_OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
const OCSP_NOCHECK: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05];

fn algs() -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    ALGS.iter().chain(ML_DSA_ALGS).copied().collect()
}

/// An issuing CA with an ML-DSA (or ECDSA) key and an end entity it
/// issued.
struct Fixture {
    ca_key: Key,
    ca: CertificateDer<'static>,
    ee: CertificateDer<'static>,
}

impl Fixture {
    fn new(ca_key: Key) -> Self {
        let ee_key = Key::ml_dsa(Set::MlDsa44, "ee");
        let ca = CertSpec::ca("issuing ca", "issuing ca", &ca_key).sign(&ca_key);
        let ee = CertSpec::ee("end entity", "issuing ca", &ee_key)
            .serial(EE_SERIAL)
            .sign(&ca_key);
        Self {
            ca_key,
            ca: ca.into(),
            ee: ee.into(),
        }
    }

    /// A responder certificate issued by the CA, with OCSPSigning, nocheck
    /// and the given keyUsage bits (`None`: no keyUsage).
    fn delegate(&self, key: &Key, key_usage: Option<&[u8]>) -> Vec<u8> {
        CertSpec::bare("ocsp responder", "issuing ca", key)
            .serial(DELEGATE_SERIAL)
            .with(vec![
                x509::basic_constraints(false, None),
                x509::ext_key_usage(&[KP_OCSP_SIGNING]),
                x509::extension(OCSP_NOCHECK, false, &[0x05, 0x00]),
            ])
            .key_usage(key_usage)
            .sign(&self.ca_key)
    }

    /// A `good` response for the end entity, identifying `responder` by
    /// key, carrying `certs` and signed by `responder`.
    fn response(&self, responder: &Key, certs: Vec<Vec<u8>>) -> Vec<u8> {
        let ee = support::Cert::try_from(&self.ee).unwrap();
        let ca = support::Cert::try_from(&self.ca).unwrap();
        let cert_id = support::CertId::new(
            CertIdHash::Sha1,
            &HASHERS,
            &ee,
            &ca.subject_public_key_info(),
        )
        .unwrap();
        let response = Response {
            version: None,
            responder_id: support::tlv(0xa2, &support::tlv(0x04, &sha1(&responder.public_key()))),
            produced_at: support::THIS_UPDATE,
            singles: vec![Single::good(&cert_id)],
            extensions: Vec::new(),
            certs,
        };
        let tbs = response.tbs();
        let mut basic = [
            &tbs[..],
            &x509::alg(responder.sig_alg().as_bytes()),
            &x509::bit_string(&responder.sign(&tbs)),
        ]
        .concat();
        if !response.certs.is_empty() {
            let certs = response.certs.concat();
            basic.extend_from_slice(&support::tlv(0xa0, &support::tlv(0x30, &certs)));
        }
        successful(&support::tlv(0x30, &basic))
    }

    fn verify<'r>(
        &self,
        response: &'r [u8],
        algs: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<VerifiedOcspStatus<'r>, OcspError> {
        let ee = support::Cert::try_from(&self.ee).unwrap();
        let ca = support::Cert::try_from(&self.ca).unwrap();
        let policy = OcspPolicy::stapled(algs, HASHERS, NOW);
        verify_response(response, &ee, &OcspIssuer::from_cert(&ca), &policy)
    }

    /// The status of a response signed by a delegate with `key_usage`.
    fn delegated(&self, key: &Key, key_usage: Option<&[u8]>) -> Result<CertStatus, OcspError> {
        let delegate = self.delegate(key, key_usage);
        let der = self.response(key, vec![delegate]);
        self.verify(&der, &algs()).map(|verified| {
            assert!(matches!(
                verified.signer,
                OcspSigner::Delegate { nocheck: true, .. }
            ));
            verified.status
        })
    }
}

#[test]
fn ml_dsa_issuer_signs_directly() {
    for set in SETS {
        let fx = Fixture::new(Key::ml_dsa(set, "issuing ca"));
        let der = fx.response(&fx.ca_key, Vec::new());
        let verified = fx.verify(&der, &algs()).unwrap();
        assert_eq!(verified.status, CertStatus::Good);
        assert_eq!(verified.signer, OcspSigner::Issuer);
        // Only the supplied algorithms are accepted.
        assert_eq!(
            fx.verify(&der, ALGS).err(),
            Some(OcspError::BadSignature(
                support::Error::UnsupportedSignatureAlgorithm
            ))
        );
    }
}

#[test]
fn ml_dsa_delegate_key_usage() {
    for set in SETS {
        let fx = Fixture::new(Key::ml_dsa(Set::MlDsa65, "issuing ca"));
        let delegate = Key::ml_dsa(set, "ocsp responder");
        let ds = ku::DIGITAL_SIGNATURE;
        // digitalSignature, or no keyUsage at all, delegates signing.
        assert_eq!(fx.delegated(&delegate, Some(&[ds])), Ok(CertStatus::Good));
        assert_eq!(fx.delegated(&delegate, None), Ok(CertStatus::Good));
        assert_eq!(
            fx.delegated(&delegate, Some(&[ds, ku::NON_REPUDIATION])),
            Ok(CertStatus::Good)
        );
        // RFC 9881 §5: no encipherment or agreement bit beside it.
        for forbidden in [
            ku::KEY_ENCIPHERMENT,
            ku::DATA_ENCIPHERMENT,
            ku::KEY_AGREEMENT,
            ku::ENCIPHER_ONLY,
            ku::DECIPHER_ONLY,
        ] {
            assert_eq!(
                fx.delegated(&delegate, Some(&[ds, forbidden])),
                Err(OcspError::DelegateKeyUsage),
                "{set:?} {}",
                ku::NAMES[usize::from(forbidden)]
            );
        }
        // RFC 6960: digitalSignature is still required.
        assert_eq!(
            fx.delegated(&delegate, Some(&[ku::NON_REPUDIATION])),
            Err(OcspError::DelegateKeyUsage)
        );
    }
}

#[test]
fn classical_delegate_key_usage_is_unchanged() {
    // An ECDSA delegate under an ECDSA CA: RFC 9881 does not apply, so
    // digitalSignature with keyEncipherment is accepted, as it was before
    // the RFC 9881 rule was added to delegate authentication.
    let fx = Fixture::new(Key::p256());
    let delegate = Key::p256();
    let ds = ku::DIGITAL_SIGNATURE;
    assert_eq!(fx.delegated(&delegate, Some(&[ds])), Ok(CertStatus::Good));
    for other in [
        ku::KEY_ENCIPHERMENT,
        ku::DATA_ENCIPHERMENT,
        ku::KEY_AGREEMENT,
        ku::ENCIPHER_ONLY,
        ku::DECIPHER_ONLY,
    ] {
        assert_eq!(
            fx.delegated(&delegate, Some(&[ds, other])),
            Ok(CertStatus::Good)
        );
    }
    assert_eq!(
        fx.delegated(&delegate, Some(&[ku::KEY_ENCIPHERMENT])),
        Err(OcspError::DelegateKeyUsage)
    );
    // The same through the rcgen-based OCSP harness.
    let fx = support::Fixture::new();
    let delegate = fx.delegate(|params| {
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
    });
    let mut response = fx.response();
    response.responder_id = support::by_key(&delegate.key);
    response.certs = vec![delegate.der.to_vec()];
    let der = response.signed_by(&delegate.key);
    assert_eq!(
        fx.verify(&der, &support::stapled()).map(|v| v.status),
        Ok(CertStatus::Good)
    );
}

#[test]
fn largest_ml_dsa_response_fits() {
    // An ML-DSA-87 delegate certificate (signed with ML-DSA-87) carried in
    // a response signed with ML-DSA-87: the largest single-delegate case.
    let fx = Fixture::new(Key::ml_dsa(Set::MlDsa87, "issuing ca"));
    let delegate = Key::ml_dsa(Set::MlDsa87, "ocsp responder");
    let cert = fx.delegate(&delegate, Some(&[ku::DIGITAL_SIGNATURE]));
    let der = fx.response(&delegate, vec![cert.clone()]);
    assert_eq!(fx.verify(&der, &algs()).unwrap().status, CertStatus::Good);
    // 2592-octet key, two 4627-octet signatures and the DER around them.
    assert_eq!(cert.len(), 7_447);
    assert_eq!(der.len(), 12_283);
    // Under a fifth of the cap: room for several more such certificates.
    assert!(5 * der.len() <= MAX_RESPONSE_LEN);
}
