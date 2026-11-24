//! ML-DSA (RFC 9881) signatures on CRLs, in path validation and through
//! `CertRevocationList::verify_signature`, and the standalone `SignedData`
//! and `subject_public_keys_match` APIs with ML-DSA inputs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/ml_dsa.rs"]
mod ml_dsa;
#[path = "common/x509_builder.rs"]
mod x509;

use browntls_pki::{
    BorrowedCertRevocationList, Cert, CertRevocationList, CertificateDer, Error, ExpirationPolicy,
    KeyUsage, OwnedCertRevocationList, RevocationCheckDepth, RevocationOptions,
    RevocationOptionsBuilder, SignatureVerificationAlgorithm, SignedData, UnknownStatusPolicy,
    alg_id, anchor_from_trusted_cert, subject_public_keys_match,
};
use common::{ALGS, NOW};
use ml_dsa::{Counted, Key, ML_DSA_ALGS, SETS, Set, with_null_params};
use x509::{CertSpec, CrlSpec, find, flip, ku, spki, spki_of};

const INT_SERIAL: &[u8] = &[0x7b, 0x04];
const EE_SERIAL: &[u8] = &[0x7a, 0x01];
const OTHER_SERIAL: &[u8] = &[0x7c, 0x07];
const THIS_UPDATE: u64 = 1_717_000_000;
const NEXT_UPDATE: u64 = 1_718_000_000;

/// `root -> intermediate -> end entity`, every key of parameter set `set`.
struct Chain {
    root_key: Key,
    int_key: Key,
    root: Vec<u8>,
    int: Vec<u8>,
    ee: Vec<u8>,
}

impl Chain {
    fn new(set: Set, int_key_usage: &[u8]) -> Self {
        let root_key = Key::ml_dsa(set, "root");
        let int_key = Key::ml_dsa(set, "intermediate");
        let ee_key = Key::ml_dsa(set, "ee");
        let root = CertSpec::ca("root", "root", &root_key).sign(&root_key);
        let int = CertSpec::ca("intermediate", "root", &int_key)
            .serial(INT_SERIAL)
            .key_usage(Some(int_key_usage))
            .sign(&root_key);
        let ee = CertSpec::ee("end entity", "intermediate", &ee_key)
            .serial(EE_SERIAL)
            .sign(&int_key);
        Self {
            root_key,
            int_key,
            root,
            int,
            ee,
        }
    }

    fn verify(
        &self,
        algs: &[&dyn SignatureVerificationAlgorithm],
        crls: &[&CertRevocationList<'_>],
        depth: RevocationCheckDepth,
    ) -> Result<(), Error> {
        let root = CertificateDer::from(&self.root[..]);
        let anchors = [anchor_from_trusted_cert(&root).unwrap()];
        common::verify(
            &CertificateDer::from(&self.ee[..]),
            &[CertificateDer::from(&self.int[..])],
            &anchors,
            algs,
            NOW,
            KeyUsage::server_auth(),
            Some(options(crls, depth)),
            None,
        )
    }

    fn int_spki(&self) -> Vec<u8> {
        spki_of(&self.int_key)
    }
}

/// Deny unknown status, enforce expiration.
fn options<'a>(
    crls: &'a [&'a CertRevocationList<'a>],
    depth: RevocationCheckDepth,
) -> RevocationOptions<'a> {
    RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(depth)
        .with_status_policy(UnknownStatusPolicy::Deny)
        .with_expiration_policy(ExpirationPolicy::Enforce)
        .build()
}

fn crl(issuer: &str, revoked: &[&[u8]]) -> CrlSpec {
    revoked
        .iter()
        .fold(CrlSpec::new(issuer, THIS_UPDATE, NEXT_UPDATE), |crl, s| {
            crl.revoke(s, THIS_UPDATE - 1000)
        })
}

fn borrowed(der: &[u8]) -> CertRevocationList<'_> {
    CertRevocationList::from(BorrowedCertRevocationList::from_der(der).unwrap())
}

fn owned(der: &[u8]) -> CertRevocationList<'static> {
    CertRevocationList::from(OwnedCertRevocationList::from_der(der).unwrap())
}

fn all_algs() -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    ALGS.iter().chain(ML_DSA_ALGS).copied().collect()
}

#[test]
fn crls_signed_with_each_parameter_set() {
    let usage = [ku::KEY_CERT_SIGN, ku::CRL_SIGN];
    for set in SETS {
        let chain = Chain::new(set, &usage);
        let good = crl("intermediate", &[OTHER_SERIAL]).sign(&chain.int_key);
        let revoked = crl("intermediate", &[OTHER_SERIAL, EE_SERIAL]).sign(&chain.int_key);
        let root_crl = crl("root", &[]).sign(&chain.root_key);
        let impostor = Key::ml_dsa(set, "impostor");
        let forged = crl("intermediate", &[]).sign(&impostor);
        let mut tampered = crl("intermediate", &[OTHER_SERIAL, EE_SERIAL]).signed(&chain.int_key);
        // Drop the end entity from the list by changing its serial.
        let at = find(&tampered.tbs, EE_SERIAL);
        tampered.tbs = flip(tampered.tbs, at + 1);
        let tampered = tampered.der();

        let counted = Counted::new(set.alg());
        let algs: Vec<&dyn SignatureVerificationAlgorithm> = vec![&counted];
        let ee_only = RevocationCheckDepth::EndEntity;
        let invalid = Err(Error::InvalidCrlSignatureForPublicKey);
        // (CRL, path validation result, standalone signature check result)
        for (der, expected, signature) in [
            (&good, Ok(()), Ok(())),
            (&revoked, Err(Error::CertRevoked), Ok(())),
            (&forged, invalid.clone(), invalid.clone()),
            (&tampered, invalid.clone(), invalid.clone()),
        ] {
            for list in [borrowed(der), owned(der)] {
                counted.reset();
                assert_eq!(chain.verify(&algs, &[&list], ee_only), expected, "{set:?}");
                // Two certificate signatures and the CRL's were checked.
                let accepted = if signature.is_ok() { 3 } else { 2 };
                assert_eq!(counted.counts(), (3, accepted), "{set:?}");
                // The standalone check, with either SPKI form.
                let spki = chain.int_spki();
                assert_eq!(list.verify_signature(&algs, &spki), signature);
                assert_eq!(list.verify_signature(&algs, &spki[4..]), signature);
            }
        }

        // At chain depth the root's CRL covers the intermediate.
        let (good, root_crl) = (borrowed(&good), borrowed(&root_crl));
        let chain_depth = RevocationCheckDepth::Chain;
        assert_eq!(
            chain.verify(&algs, &[&good, &root_crl], chain_depth),
            Ok(())
        );
        assert_eq!(
            chain.verify(&algs, &[&good], chain_depth),
            Err(Error::UnknownRevocationStatus)
        );
        let revoked_int = crl("root", &[INT_SERIAL]).sign(&chain.root_key);
        let revoked_int = borrowed(&revoked_int);
        assert_eq!(
            chain.verify(&algs, &[&good, &revoked_int], chain_depth),
            Err(Error::CertRevoked)
        );
    }
}

#[test]
fn crl_signature_algorithm_errors() {
    let chain = Chain::new(Set::MlDsa65, &[ku::KEY_CERT_SIGN, ku::CRL_SIGN]);
    let spki = chain.int_spki();
    let der = crl("intermediate", &[]).sign(&chain.int_key);
    let list = borrowed(&der);
    // Only classical algorithms, or only other ML-DSA parameter sets.
    assert_eq!(
        list.verify_signature(ALGS, &spki),
        Err(Error::UnsupportedCrlSignatureAlgorithm)
    );
    assert_eq!(
        list.verify_signature(&[Set::MlDsa44.alg(), Set::MlDsa87.alg()], &spki),
        Err(Error::UnsupportedCrlSignatureAlgorithm)
    );
    // The issuer's key is of another parameter set.
    let other = spki_of(&Key::ml_dsa(Set::MlDsa44, "intermediate"));
    assert_eq!(
        list.verify_signature(ML_DSA_ALGS, &other),
        Err(Error::UnsupportedCrlSignatureAlgorithmForPublicKey)
    );
    // ... or has NULL parameters.
    let null_key = x509::spki(
        &with_null_params(alg_id::ML_DSA_65),
        &chain.int_key.public_key(),
    );
    assert_eq!(
        list.verify_signature(ML_DSA_ALGS, &null_key),
        Err(Error::UnsupportedCrlSignatureAlgorithmForPublicKey)
    );

    // In path validation: a CRL claiming ML-DSA-44 from the ML-DSA-65
    // intermediate.
    let mut claimed = crl("intermediate", &[]);
    claimed.inner_alg = Some(alg_id::ML_DSA_44.to_vec());
    let mut claimed = claimed.signed(&chain.int_key);
    claimed.alg = alg_id::ML_DSA_44.to_vec();
    let claimed = claimed.der();
    let ee_only = RevocationCheckDepth::EndEntity;
    assert_eq!(
        chain.verify(&all_algs(), &[&borrowed(&claimed)], ee_only),
        Err(Error::UnsupportedCrlSignatureAlgorithmForPublicKey)
    );

    // NULL parameters in both fields parse but are unsupported; in one
    // field only they disagree.
    let null = with_null_params(alg_id::ML_DSA_65);
    let mut both = crl("intermediate", &[]);
    both.inner_alg = Some(null.clone());
    let mut both_signed = both.signed(&chain.int_key);
    both_signed.alg = null.clone();
    let both_der = both_signed.der();
    assert_eq!(
        borrowed(&both_der).verify_signature(&all_algs(), &spki),
        Err(Error::UnsupportedCrlSignatureAlgorithm)
    );
    assert_eq!(
        chain.verify(&all_algs(), &[&borrowed(&both_der)], ee_only),
        Err(Error::UnsupportedCrlSignatureAlgorithm)
    );
    let inner_only = both.sign(&chain.int_key);
    let mut outer_only = crl("intermediate", &[]).signed(&chain.int_key);
    outer_only.alg = null;
    for der in [inner_only, outer_only.der()] {
        assert_eq!(
            BorrowedCertRevocationList::from_der(&der).err(),
            Some(Error::SignatureAlgorithmMismatch)
        );
        assert_eq!(
            OwnedCertRevocationList::from_der(&der).err(),
            Some(Error::SignatureAlgorithmMismatch)
        );
    }

    // A signature one octet short or long.
    let signed = crl("intermediate", &[]).signed(&chain.int_key);
    let sig = signed.signature().to_vec();
    for len in [sig.len() - 1, sig.len() + 1] {
        let mut bad = signed.clone();
        let mut resized = sig.clone();
        resized.resize(len, 0);
        bad.set_signature(&resized);
        assert_eq!(
            borrowed(&bad.der()).verify_signature(ML_DSA_ALGS, &spki),
            Err(Error::InvalidCrlSignatureForPublicKey)
        );
    }
}

#[test]
fn crl_issuer_key_usage() {
    // cRLSign is still required of the CRL issuer; keyCertSign alone is a
    // key usage RFC 9881 allows for ML-DSA.
    let chain = Chain::new(Set::MlDsa44, &[ku::KEY_CERT_SIGN]);
    let der = crl("intermediate", &[EE_SERIAL]).sign(&chain.int_key);
    let list = borrowed(&der);
    assert_eq!(
        chain.verify(ML_DSA_ALGS, &[&list], RevocationCheckDepth::EndEntity),
        Err(Error::IssuerNotCrlSigner)
    );
}

#[test]
fn signed_data_with_ml_dsa() {
    for set in SETS {
        let chain = Chain::new(set, &[ku::KEY_CERT_SIGN, ku::CRL_SIGN]);
        let algs = all_algs();
        let int_spki = chain.int_spki();
        let ee_der = CertificateDer::from(&chain.ee[..]);
        let ee = Cert::try_from(&ee_der).unwrap();
        let ee_signed = ee.signed_data();
        // `from_der` on a certificate and on a CRL.
        let from_der = SignedData::from_der(&chain.ee).unwrap();
        assert_eq!(from_der.message(), ee_signed.message());
        assert_eq!(from_der.algorithm(), set.alg_id().as_bytes());
        assert_eq!(from_der.signature().len(), set.signature_len());
        assert_eq!(from_der.verify_signature(&algs, &int_spki), Ok(()));
        assert_eq!(from_der.verify_signature(&algs, &int_spki[4..]), Ok(()));
        let crl_der = crl("intermediate", &[EE_SERIAL]).sign(&chain.int_key);
        let crl_signed = SignedData::from_der(&crl_der).unwrap();
        assert_eq!(crl_signed.verify_signature(&algs, &int_spki), Ok(()));
        // The wrong key, an unsupported list, a key with NULL parameters.
        assert_eq!(
            from_der.verify_signature(&algs, &spki_of(&chain.root_key)),
            Err(Error::InvalidSignatureForPublicKey)
        );
        assert_eq!(
            from_der.verify_signature(ALGS, &int_spki),
            Err(Error::UnsupportedSignatureAlgorithm)
        );
        let null_key = spki(&with_null_params(set.alg_id()), &chain.int_key.public_key());
        assert_eq!(
            from_der.verify_signature(&algs, &null_key),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
        );

        // `from_parts` with a message signed directly.
        let msg = b"RFC 9881 signed message";
        let sig = chain.int_key.sign(msg);
        let parts = SignedData::from_parts(msg, set.alg_id().as_bytes(), &sig);
        assert_eq!(parts.verify_signature(&algs, &int_spki), Ok(()));
        let other_msg = SignedData::from_parts(b"other", set.alg_id().as_bytes(), &sig);
        assert_eq!(
            other_msg.verify_signature(&algs, &int_spki),
            Err(Error::InvalidSignatureForPublicKey)
        );
        let null_alg = with_null_params(set.alg_id());
        let null_parts = SignedData::from_parts(msg, &null_alg, &sig);
        assert_eq!(
            null_parts.verify_signature(&algs, &int_spki),
            Err(Error::UnsupportedSignatureAlgorithm)
        );
        let truncated = SignedData::from_parts(msg, set.alg_id().as_bytes(), &sig[1..]);
        assert_eq!(
            truncated.verify_signature(&algs, &int_spki),
            Err(Error::InvalidSignatureForPublicKey)
        );
    }
}

#[test]
fn subject_public_keys_match_without_canonicalisation() {
    let keys: Vec<Key> = SETS.iter().map(|&set| Key::ml_dsa(set, "k")).collect();
    for key in &keys {
        let spki = spki_of(key);
        assert_eq!(subject_public_keys_match(&spki, &spki), Ok(true));
        // The same key octets with NULL parameters, or labelled as another
        // parameter set, are a different key.
        let null = x509::spki(&with_null_params(key.key_alg()), &key.public_key());
        assert_eq!(subject_public_keys_match(&spki, &null), Ok(false));
        for other in SETS {
            let relabelled = x509::spki(other.alg_id().as_bytes(), &key.public_key());
            let same = Some(other) == key.set();
            assert_eq!(subject_public_keys_match(&spki, &relabelled), Ok(same));
        }
        // A different key of the same set.
        let set = key.set().unwrap();
        let other = spki_of(&Key::ml_dsa(set, "other"));
        assert_eq!(subject_public_keys_match(&spki, &other), Ok(false));
        // Contents instead of a complete SPKI are rejected.
        assert!(subject_public_keys_match(&spki[4..], &spki).is_err());
    }
}
