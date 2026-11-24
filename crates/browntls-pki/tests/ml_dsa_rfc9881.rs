//! The RFC 9881 Appendix C examples as independent encodings: the three
//! example certificates (C.3) and public keys (C.2), decoded from the RFC
//! text (`tests/data/rfc9881/`, see `tests/data/README.md`).
//!
//! Each certificate is a self-signed v3 CA certificate for
//! "O=IETF, CN=LAMPS WG", valid from 2020-02-03T04:32:10Z to
//! 2040-01-29T04:32:10Z, with critical keyUsage (digitalSignature,
//! keyCertSign, cRLSign), critical basicConstraints cA TRUE and a subject
//! key identifier. Their keys' private halves (C.1) are not used here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ml_dsa.rs"]
mod ml_dsa;
#[path = "common/x509_builder.rs"]
mod x509;

use browntls_pki::extensions::KeyUsageBit;
use browntls_pki::{
    Cert, CertificateDer, EndEntityCert, Error, KeyUsage, SignedData, SubjectPublicKeyInfoDer,
    UnixTime, anchor_from_trusted_cert,
};
use common::{ALGS, secs};
use ml_dsa::{Counted, Key, ML_DSA_ALGS, SETS, Set};
use x509::{CertSpec, find, flip, tlv};

/// 2025-01-01T00:00:00Z, inside the examples' validity period.
const TIME: UnixTime = secs(1_735_689_600);
const NOT_BEFORE: u64 = 1_580_704_330;
const NOT_AFTER: u64 = 2_211_424_330;

struct Example {
    set: Set,
    cert: CertificateDer<'static>,
    public_key: SubjectPublicKeyInfoDer<'static>,
}

fn examples() -> Vec<Example> {
    let files: [(Set, &[u8], &[u8]); 3] = [
        (
            Set::MlDsa44,
            include_bytes!("data/rfc9881/ml-dsa-44-certificate.der"),
            include_bytes!("data/rfc9881/ml-dsa-44-public-key.der"),
        ),
        (
            Set::MlDsa65,
            include_bytes!("data/rfc9881/ml-dsa-65-certificate.der"),
            include_bytes!("data/rfc9881/ml-dsa-65-public-key.der"),
        ),
        (
            Set::MlDsa87,
            include_bytes!("data/rfc9881/ml-dsa-87-certificate.der"),
            include_bytes!("data/rfc9881/ml-dsa-87-public-key.der"),
        ),
    ];
    files
        .into_iter()
        .map(|(set, cert, key)| Example {
            set,
            cert: CertificateDer::from(cert.to_vec()),
            public_key: SubjectPublicKeyInfoDer::from(key.to_vec()),
        })
        .collect()
}

#[test]
fn certificates_parse_and_carry_the_example_public_keys() {
    for ex in examples() {
        let cert = Cert::try_from(&ex.cert).unwrap();
        // C.2: the SPKI is the RFC 9881 identifier and the raw key.
        assert_eq!(cert.subject_public_key_info(), ex.public_key);
        let alg = ex.set.alg_id();
        let key_len = ex.set.public_key_len();
        let spki_header = [&[0x30, 0x82][..], &((key_len + 18) as u16).to_be_bytes()].concat();
        assert!(ex.public_key.starts_with(&spki_header), "{:?}", ex.set);
        assert_eq!(&ex.public_key[4..17], &tlv(0x30, alg.as_bytes())[..]);
        assert_eq!(ex.public_key.len(), 4 + 13 + 5 + key_len);
        // The certificate signature uses the same identifier.
        assert_eq!(cert.signed_data().algorithm(), alg.as_bytes());
        assert_eq!(cert.signed_data().signature().len(), ex.set.signature_len());
        // Self-signed CA, as described above.
        assert_eq!(cert.issuer(), cert.subject());
        assert_eq!(cert.not_before(), secs(NOT_BEFORE));
        assert_eq!(cert.not_after(), secs(NOT_AFTER));
        assert!(cert.basic_constraints().unwrap().ca);
        let ku = cert.key_usage().unwrap();
        for bit in KeyUsageBit::ALL {
            let expected = matches!(
                bit,
                KeyUsageBit::DigitalSignature | KeyUsageBit::KeyCertSign | KeyUsageBit::CrlSign
            );
            assert_eq!(ku.contains(bit), expected, "{:?} {bit:?}", ex.set);
        }
        assert_eq!(cert.subject_key_identifier().map(<[u8]>::len), Some(20));
    }
}

#[test]
fn self_signatures_verify_with_the_oracle() {
    for ex in examples() {
        let counted = Counted::new(ex.set.alg());
        // Through the certificate's own signed data and through `from_der`.
        let cert = Cert::try_from(&ex.cert).unwrap();
        for signed in [cert.signed_data(), SignedData::from_der(&ex.cert).unwrap()] {
            assert_eq!(signed.verify_signature(&[&counted], &ex.public_key), Ok(()));
            assert_eq!(signed.verify_signature(ML_DSA_ALGS, &ex.public_key), Ok(()));
            // The supported algorithms decide: classical algorithms only, or
            // the other parameter sets only, leave it unsupported.
            assert_eq!(
                signed.verify_signature(ALGS, &ex.public_key),
                Err(Error::UnsupportedSignatureAlgorithm)
            );
            let others: Vec<_> = SETS
                .iter()
                .filter(|&&s| s != ex.set)
                .map(|s| s.alg() as &dyn browntls_pki::SignatureVerificationAlgorithm)
                .collect();
            assert_eq!(
                signed.verify_signature(&others, &ex.public_key),
                Err(Error::UnsupportedSignatureAlgorithm)
            );
        }
        assert_eq!(counted.counts(), (2, 2), "{:?}", ex.set);
        // The other examples' keys belong to other parameter sets, so no
        // algorithm pairs them with this signature.
        for other in examples().iter().filter(|o| o.set != ex.set) {
            assert_eq!(
                cert.signed_data()
                    .verify_signature(ML_DSA_ALGS, &other.public_key),
                Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
            );
        }
    }
}

#[test]
fn single_byte_changes_are_rejected() {
    for ex in examples() {
        let der = ex.cert.to_vec();
        let cert = Cert::try_from(&ex.cert).unwrap();
        let tbs = cert.signed_data().message();
        let tbs_at = find(&der, tbs);
        let sig = cert.signed_data().signature();
        let sig_at = find(&der, sig);
        let key = &ex.public_key[22..];
        let key_at = find(&der, key);
        let ski = cert.subject_key_identifier().unwrap();
        let ski_at = find(&der, ski);
        // The serial number, a byte of "IETF" in the issuer, the subject
        // key, the subject key identifier, and the signature's first,
        // middle and last octets: each change keeps the DER valid.
        let issuer_at = find(&der[tbs_at..], b"IETF") + tbs_at;
        for index in [
            tbs_at + 12,
            issuer_at,
            key_at,
            key_at + key.len() - 1,
            ski_at + 10,
            sig_at,
            sig_at + sig.len() / 2,
            sig_at + sig.len() - 1,
        ] {
            let changed = CertificateDer::from(flip(der.clone(), index));
            let parsed = Cert::try_from(&changed).unwrap();
            assert_eq!(
                parsed
                    .signed_data()
                    .verify_signature(ML_DSA_ALGS, &ex.public_key),
                Err(Error::InvalidSignatureForPublicKey),
                "{:?} {index}",
                ex.set
            );
        }
        // Changing the identifier's last OID octet makes it another
        // parameter set in one field only.
        let alg_at = find(&der[tbs_at..], ex.set.alg_id().as_bytes()) + tbs_at;
        let changed = flip(der.clone(), alg_at + 10);
        assert_eq!(
            Cert::try_from(&CertificateDer::from(&changed[..])).err(),
            Some(Error::SignatureAlgorithmMismatch)
        );
    }
}

#[test]
fn examples_with_the_path_api() {
    for ex in examples() {
        // As a trust anchor, the example key is used with the oracle: an
        // end entity naming the example as issuer but signed by another key
        // fails its signature check.
        let anchor = anchor_from_trusted_cert(&ex.cert).unwrap();
        assert_eq!(anchor.subject_public_key_info.as_ref(), &ex.public_key[4..]);
        let cert = Cert::try_from(&ex.cert).unwrap();
        let impostor = Key::ml_dsa(ex.set, "impostor");
        let mut spec = CertSpec::ee("end entity", "unused", &impostor);
        spec.issuer = tlv(0x30, cert.subject());
        spec.not_before = NOT_BEFORE;
        let ee = CertificateDer::from(spec.sign(&impostor));
        let counted = Counted::new(ex.set.alg());
        assert_eq!(
            common::verify(
                &ee,
                &[],
                core::slice::from_ref(&anchor),
                &[&counted],
                TIME,
                KeyUsage::server_auth(),
                None,
                None,
            ),
            Err(Error::InvalidSignatureForPublicKey)
        );
        assert_eq!(counted.counts(), (1, 0));
        // Presented as an end entity, the CA certificate is refused before
        // any signature is checked.
        counted.reset();
        assert_eq!(
            common::verify(
                &ex.cert,
                &[],
                core::slice::from_ref(&anchor),
                &[&counted],
                TIME,
                KeyUsage::server_auth(),
                None,
                None,
            ),
            Err(Error::CaUsedAsEndEntity)
        );
        assert_eq!(counted.counts(), (0, 0));
        // Its key verifies with `EndEntityCert::verify_signature` like any
        // certificate's: here, its own signature over its tbsCertificate.
        let as_ee = EndEntityCert::try_from(&ex.cert).unwrap();
        let signed = cert.signed_data();
        assert_eq!(
            as_ee.verify_signature(ex.set.alg(), signed.message(), signed.signature()),
            Ok(())
        );
    }
}
