//! The native ML-DSA verification algorithms on their own, and on the
//! RFC 9881 Appendix C.3 certificates.

use browntls_core::crypto::native;
use browntls_pki::{
    Cert, CertificateDer, Error, InvalidSignature, SignatureVerificationAlgorithm, SignedData,
    SubjectPublicKeyInfoDer, alg_id,
};

use crate::ml_dsa::{SETS, Set};
use crate::x509::{find, flip};
use crate::{Impl, MlKey, native_alg};

fn rejects(set: Set, key: &[u8], msg: &[u8], sig: &[u8], what: &str) {
    assert_eq!(
        native_alg(set).verify_signature(key, msg, sig),
        Err(InvalidSignature),
        "{set:?}: {what}"
    );
}

#[test]
fn signatures_of_both_implementations_verify() {
    for set in SETS {
        let key = MlKey::new(set, "algorithm");
        let pk = key.native_public_key();
        let msg = b"RFC 9881 to-be-signed bytes";
        let native_sig = key.sign(Impl::Native, msg);
        let oracle_sig = key.sign(Impl::Oracle, msg);
        let hedged = key.sign_hedged(msg);
        assert_eq!(native_sig.len(), set.signature_len());
        // Deterministic signing (`rnd = 0^32`) is one computation, so the
        // implementations must agree byte for byte.
        assert_eq!(native_sig, oracle_sig, "{set:?}");
        assert_ne!(hedged, native_sig, "{set:?}");
        for sig in [&native_sig, &oracle_sig, &hedged] {
            assert_eq!(native_alg(set).verify_signature(&pk, msg, sig), Ok(()));
            // And the oracle accepts what the native signer made.
            assert_eq!(set.alg().verify_signature(&pk, msg, sig), Ok(()));
        }
    }
}

#[test]
fn every_malformed_or_foreign_input_is_invalid() {
    let keys: Vec<MlKey> = SETS.iter().map(|&s| MlKey::new(s, "reject")).collect();
    let msg = b"message";
    for key in &keys {
        let set = key.set;
        let pk = key.native_public_key();
        let sig = key.sign(Impl::Oracle, msg);
        assert_eq!(native_alg(set).verify_signature(&pk, msg, &sig), Ok(()));

        rejects(set, &pk, b"messagf", &sig, "wrong message");
        rejects(set, &pk, b"", &sig, "empty message");
        for at in [0, pk.len() / 2, pk.len() - 1] {
            rejects(set, &flip(pk.clone(), at), msg, &sig, "flipped key bit");
        }
        for at in [0, sig.len() / 2, sig.len() - 1] {
            rejects(
                set,
                &pk,
                msg,
                &flip(sig.clone(), at),
                "flipped signature bit",
            );
        }
        rejects(set, &pk[..pk.len() - 1], msg, &sig, "key one byte short");
        rejects(
            set,
            &[&pk[..], &[0]].concat(),
            msg,
            &sig,
            "key one byte long",
        );
        rejects(
            set,
            &pk,
            msg,
            &sig[..sig.len() - 1],
            "signature one byte short",
        );
        rejects(
            set,
            &pk,
            msg,
            &[&sig[..], &[0]].concat(),
            "signature one byte long",
        );
        rejects(set, &[], msg, &sig, "empty key");
        rejects(set, &pk, msg, &[], "empty signature");
        rejects(set, &[], b"", &[], "everything empty");
        rejects(
            set,
            &[0; 2592],
            msg,
            &[0; 4627],
            "zeros of the longest lengths",
        );
        // Another parameter set's key or signature, alone or together.
        for other in keys.iter().filter(|k| k.set != set) {
            let other_pk = other.native_public_key();
            let other_sig = other.sign(Impl::Oracle, msg);
            rejects(set, &other_pk, msg, &sig, "other set's key");
            rejects(set, &pk, msg, &other_sig, "other set's signature");
            rejects(
                set,
                &other_pk,
                msg,
                &other_sig,
                "other set's key and signature",
            );
        }
        // Another key of the same set.
        let stranger = MlKey::new(set, "stranger");
        rejects(set, &stranger.native_public_key(), msg, &sig, "another key");
    }
}

#[test]
fn identifiers_and_debug() {
    let expected = [
        (Set::MlDsa44, alg_id::ML_DSA_44, "ML-DSA-44"),
        (Set::MlDsa65, alg_id::ML_DSA_65, "ML-DSA-65"),
        (Set::MlDsa87, alg_id::ML_DSA_87, "ML-DSA-87"),
    ];
    for (set, id, name) in expected {
        let alg = native_alg(set);
        assert_eq!(alg.public_key_alg_id(), id);
        assert_eq!(alg.signature_alg_id(), id);
        assert_eq!(alg.public_key_alg_id(), set.alg_id());
        assert!(!alg.fips());
        assert_eq!(
            format!("{alg:?}"),
            format!("MlDsaVerify {{ parameter_set: {name:?} }}")
        );
    }
    let table: Vec<_> = native::ML_DSA_VERIFICATION_ALGS
        .iter()
        .map(|a| a.public_key_alg_id())
        .collect();
    assert_eq!(
        table,
        [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87]
    );
}

// ---------------------------------------------------------------------------
// RFC 9881 Appendix C.3: signatures made by neither implementation
// ---------------------------------------------------------------------------

struct Example {
    set: Set,
    cert: &'static [u8],
    spki: &'static [u8],
}

const EXAMPLES: [Example; 3] = [
    Example {
        set: Set::MlDsa44,
        cert: include_bytes!("../../../browntls-pki/tests/data/rfc9881/ml-dsa-44-certificate.der"),
        spki: include_bytes!("../../../browntls-pki/tests/data/rfc9881/ml-dsa-44-public-key.der"),
    },
    Example {
        set: Set::MlDsa65,
        cert: include_bytes!("../../../browntls-pki/tests/data/rfc9881/ml-dsa-65-certificate.der"),
        spki: include_bytes!("../../../browntls-pki/tests/data/rfc9881/ml-dsa-65-public-key.der"),
    },
    Example {
        set: Set::MlDsa87,
        cert: include_bytes!("../../../browntls-pki/tests/data/rfc9881/ml-dsa-87-certificate.der"),
        spki: include_bytes!("../../../browntls-pki/tests/data/rfc9881/ml-dsa-87-public-key.der"),
    },
];

#[test]
fn rfc9881_example_self_signatures_verify() {
    for ex in &EXAMPLES {
        let der = CertificateDer::from(ex.cert);
        let cert = Cert::try_from(&der).unwrap();
        assert_eq!(
            cert.subject_public_key_info(),
            SubjectPublicKeyInfoDer::from(ex.spki)
        );
        let signed = SignedData::from_der(ex.cert).unwrap();
        let native_only: [&dyn SignatureVerificationAlgorithm; 1] = [native_alg(ex.set)];
        for algs in [
            &native_only[..],
            native::ML_DSA_VERIFICATION_ALGS,
            native::ALL_VERIFICATION_ALGS_WITH_ML_DSA,
            native::SUPPORTED_SIG_ALGS_WITH_ML_DSA.all,
        ] {
            assert_eq!(
                signed.verify_signature(algs, ex.spki),
                Ok(()),
                "{:?}",
                ex.set
            );
            assert_eq!(
                cert.signed_data().verify_signature(algs, ex.spki),
                Ok(()),
                "{:?}",
                ex.set
            );
        }
        // The algorithm on its own, with the raw key (the BIT STRING
        // contents: after the 4-octet SPKI header, the 13-octet identifier
        // and the 5-octet BIT STRING header).
        let raw_key = &ex.spki[22..];
        assert_eq!(raw_key.len(), ex.set.public_key_len());
        assert_eq!(
            native_alg(ex.set).verify_signature(raw_key, signed.message(), signed.signature()),
            Ok(())
        );
        // The defaults do not know ML-DSA.
        for algs in [
            native::ALL_VERIFICATION_ALGS,
            native::SUPPORTED_SIG_ALGS.all,
        ] {
            assert_eq!(
                signed.verify_signature(algs, ex.spki),
                Err(Error::UnsupportedSignatureAlgorithm)
            );
        }
        // Another parameter set's key is not paired with this signature.
        for other in EXAMPLES.iter().filter(|o| o.set != ex.set) {
            assert_eq!(
                signed.verify_signature(native::ALL_VERIFICATION_ALGS_WITH_ML_DSA, other.spki),
                Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
            );
        }
    }
}

#[test]
fn rfc9881_examples_fail_after_a_single_byte_change() {
    for ex in &EXAMPLES {
        let signed = SignedData::from_der(ex.cert).unwrap();
        let tbs_at = find(ex.cert, signed.message());
        let sig = signed.signature();
        let sig_at = find(ex.cert, sig);
        let issuer_at = find(&ex.cert[tbs_at..], b"IETF") + tbs_at;
        // The serial number, a byte of the issuer name, and the signature's
        // first, middle and last octets: each change keeps the DER valid.
        for index in [
            tbs_at + 12,
            issuer_at,
            sig_at,
            sig_at + sig.len() / 2,
            sig_at + sig.len() - 1,
        ] {
            let changed = flip(ex.cert.to_vec(), index);
            let signed = SignedData::from_der(&changed).unwrap();
            assert_eq!(
                signed.verify_signature(native::ALL_VERIFICATION_ALGS_WITH_ML_DSA, ex.spki),
                Err(Error::InvalidSignatureForPublicKey),
                "{:?} at {index}",
                ex.set
            );
        }
        // A changed key does not verify the unchanged certificate.
        let key_at = ex.spki.len() - 1;
        let changed_key = flip(ex.spki.to_vec(), key_at);
        assert_eq!(
            signed.verify_signature(native::ALL_VERIFICATION_ALGS_WITH_ML_DSA, &changed_key),
            Err(Error::InvalidSignatureForPublicKey)
        );
    }
}
