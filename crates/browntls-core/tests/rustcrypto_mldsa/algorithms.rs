//! The RustCrypto ML-DSA verification algorithms on their own, and on the
//! RFC 9881 Appendix C.3 certificates.

use browntls_core::crypto::rustcrypto;
use browntls_crypto::mldsa;
use browntls_pki::{
    Cert, CertificateDer, Error, InvalidSignature, SignatureVerificationAlgorithm, SignedData,
    SubjectPublicKeyInfoDer, alg_id,
};

use crate::ml_dsa::{SETS, Set};
use crate::x509::{find, flip};
use crate::{Impl, MlKey, rc_alg};

fn rejects(set: Set, key: &[u8], msg: &[u8], sig: &[u8], what: &str) {
    assert_eq!(
        rc_alg(set).verify_signature(key, msg, sig),
        Err(InvalidSignature),
        "{set:?}: {what}"
    );
}

#[test]
fn signatures_of_both_implementations_verify() {
    for set in SETS {
        let key = MlKey::new(set, "rustcrypto algorithm");
        let pk = key.native_public_key();
        let msg = b"RFC 9881 to-be-signed bytes";
        let native_sig = key.sign(Impl::Native, msg);
        let oracle_sig = key.sign(Impl::Oracle, msg);
        let hedged = key.sign_hedged(msg);
        assert_eq!(native_sig, oracle_sig, "{set:?}");
        assert_ne!(hedged, native_sig, "{set:?}");
        for sig in [&native_sig, &oracle_sig, &hedged] {
            assert_eq!(rc_alg(set).verify_signature(&pk, msg, sig), Ok(()));
        }
    }
}

#[test]
fn every_malformed_or_foreign_input_is_invalid() {
    let keys: Vec<MlKey> = SETS
        .iter()
        .map(|&s| MlKey::new(s, "rustcrypto reject"))
        .collect();
    let msg = b"message";
    for key in &keys {
        let set = key.set;
        let pk = key.native_public_key();
        let sig = key.sign(Impl::Native, msg);
        assert_eq!(rc_alg(set).verify_signature(&pk, msg, &sig), Ok(()));

        rejects(set, &pk, b"messagf", &sig, "wrong message");
        rejects(set, &pk, b"", &sig, "empty message");
        for at in [0, pk.len() / 2, pk.len() - 1] {
            rejects(set, &flip(pk.clone(), at), msg, &sig, "flipped key bit");
        }
        for at in [0, sig.len() / 2, sig.len() - 1] {
            let bad = flip(sig.clone(), at);
            rejects(set, &pk, msg, &bad, "flipped signature bit");
        }
        rejects(set, &pk[..pk.len() - 1], msg, &sig, "key one byte short");
        let long_pk = [&pk[..], &[0]].concat();
        rejects(set, &long_pk, msg, &sig, "key one byte long");
        let short_sig = &sig[..sig.len() - 1];
        rejects(set, &pk, msg, short_sig, "signature one byte short");
        let long_sig = [&sig[..], &[0]].concat();
        rejects(set, &pk, msg, &long_sig, "signature one byte long");
        rejects(set, &[], msg, &sig, "empty key");
        rejects(set, &pk, msg, &[], "empty signature");
        rejects(set, &[], b"", &[], "everything empty");
        let (zero_pk, zero_sig) = ([0; 2592], [0; 4627]);
        rejects(
            set,
            &zero_pk,
            msg,
            &zero_sig,
            "zeros of the longest lengths",
        );
        for other in keys.iter().filter(|k| k.set != set) {
            let other_pk = other.native_public_key();
            let other_sig = other.sign(Impl::Native, msg);
            rejects(set, &other_pk, msg, &sig, "other set's key");
            rejects(set, &pk, msg, &other_sig, "other set's signature");
            rejects(set, &other_pk, msg, &other_sig, "other set's pair");
        }
        let stranger = MlKey::new(set, "rustcrypto stranger");
        rejects(set, &stranger.native_public_key(), msg, &sig, "another key");
    }
}

/// `(public key, empty-context signature, signatures with context `ctx` by
/// `browntls_crypto` and by the `ml-dsa` crate)`, all deterministic.
fn context_signatures(set: Set, msg: &[u8], ctx: &[u8]) -> [Vec<u8>; 4] {
    let seed = [0x5a; 32];
    let b32 = ::ml_dsa::B32::from(seed);
    macro_rules! sigs {
        ($native:ty, $oracle:ty) => {{
            let native = mldsa::SigningKey::<$native>::from_seed(&seed);
            let oracle = ::ml_dsa::SigningKey::<$oracle>::from_seed(&b32);
            let expanded = oracle.expanded_key();
            [
                native.verifying_key().as_bytes().to_vec(),
                native
                    .sign_deterministic(msg, b"")
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                native
                    .sign_deterministic(msg, ctx)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                expanded
                    .sign_deterministic(msg, ctx)
                    .unwrap()
                    .encode()
                    .to_vec(),
            ]
        }};
    }
    match set {
        Set::MlDsa44 => sigs!(mldsa::MlDsa44, ::ml_dsa::MlDsa44),
        Set::MlDsa65 => sigs!(mldsa::MlDsa65, ::ml_dsa::MlDsa65),
        Set::MlDsa87 => sigs!(mldsa::MlDsa87, ::ml_dsa::MlDsa87),
    }
}

#[test]
fn signatures_with_a_context_string_are_invalid() {
    let msg = b"tbs";
    for set in SETS {
        for ctx in [&b"ctx"[..], &[0u8], &[0xff; 255]] {
            let [pk, plain, native_ctx, oracle_ctx] = context_signatures(set, msg, ctx);
            assert_eq!(rc_alg(set).verify_signature(&pk, msg, &plain), Ok(()));
            // Deterministic signing is one computation in both.
            assert_eq!(native_ctx, oracle_ctx, "{set:?}");
            rejects(set, &pk, msg, &native_ctx, "non-empty context");
            assert_eq!(
                crate::native_alg(set).verify_signature(&pk, msg, &native_ctx),
                Err(InvalidSignature)
            );
        }
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
        let alg = rc_alg(set);
        assert_eq!(alg.public_key_alg_id(), id);
        assert_eq!(alg.signature_alg_id(), id);
        assert_eq!(
            alg.public_key_alg_id(),
            crate::native_alg(set).public_key_alg_id()
        );
        assert!(!alg.fips());
        assert_eq!(
            format!("{alg:?}"),
            format!("MlDsaVerify {{ parameter_set: {name:?} }}")
        );
    }
    let table: Vec<_> = rustcrypto::ML_DSA_VERIFICATION_ALGS
        .iter()
        .map(|a| a.public_key_alg_id())
        .collect();
    assert_eq!(
        table,
        [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87]
    );
}

#[test]
fn defaults_have_no_ml_dsa_and_no_scheme_maps_to_it() {
    let is_ml_dsa = |a: &&dyn SignatureVerificationAlgorithm| {
        SETS.iter()
            .any(|s| a.public_key_alg_id() == s.alg_id() || a.signature_alg_id() == s.alg_id())
    };
    assert!(!rustcrypto::SUPPORTED_SIG_ALGS.all.iter().any(is_ml_dsa));
    let provider = rustcrypto::default_provider();
    let algs = provider.signature_verification_algorithms;
    assert!(!algs.all.iter().any(is_ml_dsa));
    assert_eq!(
        rustcrypto::ALL_VERIFICATION_ALGS_WITH_ML_DSA
            .iter()
            .filter(|a| is_ml_dsa(a))
            .count(),
        3
    );
    for table in [
        &rustcrypto::SUPPORTED_SIG_ALGS,
        &rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA,
    ] {
        for (_, mapped) in table.mapping {
            assert!(!mapped.iter().any(is_ml_dsa));
        }
    }
    assert_eq!(
        rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA.supported_schemes(),
        rustcrypto::SUPPORTED_SIG_ALGS.supported_schemes()
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
        let rc_only: [&dyn SignatureVerificationAlgorithm; 1] = [rc_alg(ex.set)];
        for algs in [
            &rc_only[..],
            rustcrypto::ML_DSA_VERIFICATION_ALGS,
            rustcrypto::ALL_VERIFICATION_ALGS_WITH_ML_DSA,
            rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA.all,
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
        // The raw key: the BIT STRING contents after the 22-octet prefix.
        let raw_key = &ex.spki[22..];
        assert_eq!(raw_key.len(), ex.set.public_key_len());
        assert_eq!(
            rc_alg(ex.set).verify_signature(raw_key, signed.message(), signed.signature()),
            Ok(())
        );
        // The defaults do not know ML-DSA.
        assert_eq!(
            signed.verify_signature(rustcrypto::SUPPORTED_SIG_ALGS.all, ex.spki),
            Err(Error::UnsupportedSignatureAlgorithm)
        );
        for other in EXAMPLES.iter().filter(|o| o.set != ex.set) {
            assert_eq!(
                signed.verify_signature(rustcrypto::ALL_VERIFICATION_ALGS_WITH_ML_DSA, other.spki),
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
                signed.verify_signature(rustcrypto::ALL_VERIFICATION_ALGS_WITH_ML_DSA, ex.spki),
                Err(Error::InvalidSignatureForPublicKey),
                "{:?} at {index}",
                ex.set
            );
        }
        let changed_key = flip(ex.spki.to_vec(), ex.spki.len() - 1);
        assert_eq!(
            signed.verify_signature(rustcrypto::ALL_VERIFICATION_ALGS_WITH_ML_DSA, &changed_key),
            Err(Error::InvalidSignatureForPublicKey)
        );
    }
}
