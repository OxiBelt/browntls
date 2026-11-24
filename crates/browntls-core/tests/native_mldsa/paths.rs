//! Certificate path validation with ML-DSA certificates: through the
//! library's verifiers with the opt-in and the default tables, and through
//! `browntls_pki` with chains signed by each implementation.

use browntls_core::crypto::native;
use browntls_pki::{
    CertificateDer, EndEntityCert, Error as PkiError, KeyUsage, SignatureVerificationAlgorithm,
    anchor_from_trusted_cert,
};

use crate::ml_dsa::{Key, ML_DSA_ALGS, SETS, Set};
use crate::x509::{Signed, flip, ku};
use crate::{
    BAD_SIGNATURE, Chain, Impl, Issuer, MlKey, Purpose, UNSUPPORTED, build_chain, default_provider,
    now, opt_in_provider, other_pki_error,
};

/// Checks a chain with an ML-DSA signature somewhere: accepted with the
/// opt-in table, unsupported with the default one, for both verifiers.
fn check_opt_in_only(server: &Chain, client: &Chain, what: &str) {
    assert_eq!(
        server.verify_server(opt_in_provider(), &[]),
        Ok(()),
        "{what}"
    );
    assert_eq!(client.verify_client(opt_in_provider()), Ok(()), "{what}");
    assert_eq!(
        server.verify_server(default_provider(), &[]),
        Err(UNSUPPORTED),
        "{what}"
    );
    assert_eq!(
        client.verify_client(default_provider()),
        Err(UNSUPPORTED),
        "{what}"
    );
}

#[test]
fn ml_dsa_anchor_and_intermediates_with_a_classical_end_entity() {
    let ee = Key::p256();
    for set in SETS {
        let root = MlKey::new(set, "root");
        let int = MlKey::new(set, "intermediate");
        for by in [Impl::Native, Impl::Oracle] {
            let root = Issuer::MlDsa(&root, by);
            let int = Issuer::MlDsa(&int, by);
            for ints in [vec![], vec![(int, None)]] {
                let what = format!("{set:?} by {by:?}, {} intermediates", ints.len());
                check_opt_in_only(
                    &build_chain(root, &ints, &ee, Purpose::Server),
                    &build_chain(root, &ints, &ee, Purpose::Client),
                    &what,
                );
            }
        }
    }
}

#[test]
fn mixed_parameter_sets_and_a_classical_anchor() {
    let ee = Key::p256();
    let k87 = MlKey::new(Set::MlDsa87, "root");
    let k65 = MlKey::new(Set::MlDsa65, "intermediate");
    let k44 = MlKey::new(Set::MlDsa44, "intermediate");
    let ints = [
        (Issuer::MlDsa(&k65, Impl::Oracle), None),
        (Issuer::MlDsa(&k44, Impl::Native), None),
    ];
    let root = Issuer::MlDsa(&k87, Impl::Native);
    check_opt_in_only(
        &build_chain(root, &ints, &ee, Purpose::Server),
        &build_chain(root, &ints, &ee, Purpose::Client),
        "ML-DSA-87 -> ML-DSA-65 -> ML-DSA-44 -> P-256",
    );
    // A classical root over an ML-DSA intermediate.
    let p256_root = Key::p256();
    let root = Issuer::Classical(&p256_root);
    let ints = [(Issuer::MlDsa(&k65, Impl::Native), None)];
    check_opt_in_only(
        &build_chain(root, &ints, &ee, Purpose::Server),
        &build_chain(root, &ints, &ee, Purpose::Client),
        "P-256 -> ML-DSA-65 -> P-256",
    );
    // A fully classical chain is unaffected by the table.
    let p256_int = Key::p256();
    let chain = build_chain(
        root,
        &[(Issuer::Classical(&p256_int), None)],
        &ee,
        Purpose::Server,
    );
    assert_eq!(chain.verify_server(opt_in_provider(), &[]), Ok(()));
    assert_eq!(chain.verify_server(default_provider(), &[]), Ok(()));
}

/// Flips a bit of the signature of a certificate built by
/// `Issuer::sign_cert`, which ends with it: octet `from_end` counted from
/// the last.
fn tamper(der: &[u8], from_end: usize) -> Vec<u8> {
    flip(der.to_vec(), der.len() - 1 - from_end)
}

#[test]
fn tampered_ml_dsa_signatures_are_bad_signatures() {
    let ee = Key::p256();
    for set in SETS {
        let root = MlKey::new(set, "root");
        let int = MlKey::new(set, "intermediate");
        let chain = build_chain(
            Issuer::MlDsa(&root, Impl::Native),
            &[(Issuer::MlDsa(&int, Impl::Native), None)],
            &ee,
            Purpose::Server,
        );
        assert_eq!(chain.verify_server(opt_in_provider(), &[]), Ok(()));
        // The certificate ends with its signature BIT STRING.
        let n = set.signature_len();
        for from_end in [0, n / 2, n - 1] {
            let mut bad = Chain {
                root: chain.root.clone(),
                intermediates: chain.intermediates.clone(),
                ee: tamper(&chain.ee, from_end),
            };
            assert_eq!(
                bad.verify_server(opt_in_provider(), &[]),
                Err(BAD_SIGNATURE),
                "{set:?} end entity, {from_end}"
            );
            bad.ee = chain.ee.clone();
            bad.intermediates[0] = tamper(&chain.intermediates[0], from_end);
            assert_eq!(
                bad.verify_server(opt_in_provider(), &[]),
                Err(BAD_SIGNATURE),
                "{set:?} intermediate, {from_end}"
            );
        }
        // A signature of the wrong length for the set.
        let spec = crate::x509::CertSpec::ee("end entity", "intermediate 0", &ee);
        let mut short: Signed = Issuer::MlDsa(&int, Impl::Native).signed(spec.tbs(&int.oracle));
        let truncated = short.signature()[..n - 1].to_vec();
        short.set_signature(&truncated);
        let bad = Chain {
            root: chain.root.clone(),
            intermediates: chain.intermediates.clone(),
            ee: short.der(),
        };
        assert_eq!(
            bad.verify_server(opt_in_provider(), &[]),
            Err(BAD_SIGNATURE),
            "{set:?} short"
        );
    }
}

#[test]
fn rfc9881_key_usage_violation_on_an_intermediate() {
    let ee = Key::p256();
    let root = MlKey::new(Set::MlDsa65, "root");
    let int = MlKey::new(Set::MlDsa44, "intermediate");
    let forbidden: &[u8] = &[ku::KEY_CERT_SIGN, ku::CRL_SIGN, ku::KEY_ENCIPHERMENT];
    let chain = |bits| {
        build_chain(
            Issuer::MlDsa(&root, Impl::Native),
            &[(Issuer::MlDsa(&int, Impl::Native), Some(bits))],
            &ee,
            Purpose::Server,
        )
    };
    // keyCertSign alone is allowed (RFC 9881 §5).
    assert_eq!(
        chain(&[ku::KEY_CERT_SIGN]).verify_server(opt_in_provider(), &[]),
        Ok(())
    );
    // keyEncipherment is not, for an ML-DSA key: the path fails with
    // `browntls_pki::Error::KeyUsageNotPermittedForPublicKey`, reported as
    // `CertificateError::Other` (alert `certificate_unknown`).
    for provider in [opt_in_provider(), default_provider()] {
        assert_eq!(
            other_pki_error(chain(forbidden).verify_server(provider, &[])),
            PkiError::KeyUsageNotPermittedForPublicKey
        );
    }
    let client = build_chain(
        Issuer::MlDsa(&root, Impl::Oracle),
        &[(Issuer::MlDsa(&int, Impl::Oracle), Some(forbidden))],
        &ee,
        Purpose::Client,
    );
    assert_eq!(
        other_pki_error(client.verify_client(opt_in_provider())),
        PkiError::KeyUsageNotPermittedForPublicKey
    );
}

/// `EndEntityCert::verify_for_usage` for server authentication.
fn pki_verify(chain: &Chain, algs: &[&dyn SignatureVerificationAlgorithm]) -> Result<(), PkiError> {
    let root = CertificateDer::from(&chain.root[..]);
    let anchors = [anchor_from_trusted_cert(&root).unwrap()];
    let ee = CertificateDer::from(&chain.ee[..]);
    EndEntityCert::try_from(&ee)?
        .verify_for_usage(
            algs,
            &anchors,
            &chain.intermediates(),
            now(),
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
}

#[test]
fn all_ml_dsa_chains_across_implementations() {
    let oracle_algs: Vec<&dyn SignatureVerificationAlgorithm> = native::ALL_VERIFICATION_ALGS
        .iter()
        .chain(ML_DSA_ALGS)
        .copied()
        .collect();
    for set in SETS {
        let root = MlKey::new(set, "root");
        let int = MlKey::new(set, "intermediate");
        let ee = MlKey::new(set, "end entity");
        for by in [Impl::Native, Impl::Oracle] {
            let chain = build_chain(
                Issuer::MlDsa(&root, by),
                &[(Issuer::MlDsa(&int, by), None)],
                &ee.oracle,
                Purpose::Server,
            );
            // Native signatures verified by the oracle, oracle signatures by
            // the native algorithms, and each by its own.
            for (algs, name) in [
                (native::ALL_VERIFICATION_ALGS_WITH_ML_DSA, "native"),
                (&oracle_algs[..], "oracle"),
            ] {
                assert_eq!(
                    pki_verify(&chain, algs),
                    Ok(()),
                    "{set:?} by {by:?}, {name}"
                );
            }
            assert_eq!(
                pki_verify(&chain, native::ALL_VERIFICATION_ALGS),
                Err(PkiError::UnsupportedSignatureAlgorithm),
                "{set:?}"
            );
            // The same chain through the library's verifier.
            assert_eq!(chain.verify_server(opt_in_provider(), &[]), Ok(()));
            assert_eq!(
                chain.verify_server(default_provider(), &[]),
                Err(UNSUPPORTED)
            );
            // The end entity's key verifies a signature by either
            // implementation with the native algorithm.
            let der = CertificateDer::from(&chain.ee[..]);
            let cert = EndEntityCert::try_from(&der).unwrap();
            for signer in [Impl::Native, Impl::Oracle] {
                let sig = ee.sign(signer, b"message");
                assert_eq!(
                    cert.verify_signature(crate::native_alg(set), b"message", &sig),
                    Ok(())
                );
                assert_eq!(
                    cert.verify_signature(crate::native_alg(set), b"massage", &sig),
                    Err(PkiError::InvalidSignatureForPublicKey)
                );
            }
        }
    }
}

/// The default RustCrypto provider has no ML-DSA algorithm (its own opt-in
/// table is tested in `rustcrypto_mldsa.rs`).
#[cfg(feature = "rustcrypto")]
#[test]
fn rustcrypto_provider_rejects_ml_dsa_chains() {
    use std::sync::Arc;

    use browntls_core::crypto::rustcrypto;

    let ee = Key::p256();
    let root = MlKey::new(Set::MlDsa65, "root");
    let root = Issuer::MlDsa(&root, Impl::Native);
    let server = build_chain(root, &[], &ee, Purpose::Server);
    let client = build_chain(root, &[], &ee, Purpose::Client);
    let provider = || Arc::new(rustcrypto::default_provider());
    assert_eq!(server.verify_server(provider(), &[]), Err(UNSUPPORTED));
    assert_eq!(client.verify_client(provider()), Err(UNSUPPORTED));
    assert!(
        !rustcrypto::SUPPORTED_SIG_ALGS
            .all
            .iter()
            .any(|a| SETS.iter().any(|s| a.public_key_alg_id() == s.alg_id()))
    );
    // The native opt-in table in a RustCrypto-based provider.
    let mut mixed = rustcrypto::default_provider();
    mixed.signature_verification_algorithms = native::SUPPORTED_SIG_ALGS_WITH_ML_DSA;
    assert_eq!(server.verify_server(Arc::new(mixed), &[]), Ok(()));
}

/// A signature by a key of one parameter set, labelled (inner `signature`
/// and outer `signatureAlgorithm`) as another set: no algorithm pairs the
/// label with the issuer's key, so it is unsupported, not a bad signature.
#[test]
fn signature_labelled_with_another_parameter_set() {
    let ee = Key::p256();
    for (signer, label) in [
        (Set::MlDsa44, Set::MlDsa65),
        (Set::MlDsa65, Set::MlDsa44),
        (Set::MlDsa87, Set::MlDsa65),
        (Set::MlDsa65, Set::MlDsa87),
    ] {
        let root_key = MlKey::new(signer, "root");
        let root = Issuer::MlDsa(&root_key, Impl::Native);
        let honest = build_chain(root, &[], &ee, Purpose::Server);
        assert_eq!(honest.verify_server(opt_in_provider(), &[]), Ok(()));
        let label_id = label.alg_id().as_bytes().to_vec();
        let spec = crate::x509::CertSpec {
            inner_alg: Some(label_id.clone()),
            ..crate::x509::CertSpec::ee("end entity", "root", &ee)
        };
        let tbs = spec.tbs(&root_key.oracle);
        let sig = root.sign(&tbs);
        let relabelled = Chain {
            root: honest.root.clone(),
            intermediates: vec![],
            ee: Signed {
                tbs,
                alg: label_id,
                bits: [&[0u8][..], &sig].concat(),
            }
            .der(),
        };
        for provider in [opt_in_provider(), default_provider()] {
            assert_eq!(
                relabelled.verify_server(provider, &[]),
                Err(UNSUPPORTED),
                "{signer:?} labelled {label:?}"
            );
        }
        // And through `browntls_pki`: the label matches an algorithm, but
        // not for the issuer's key.
        assert_eq!(
            pki_verify(&relabelled, native::ALL_VERIFICATION_ALGS_WITH_ML_DSA),
            Err(PkiError::UnsupportedSignatureAlgorithmForPublicKey),
            "{signer:?} labelled {label:?}"
        );
    }
}
