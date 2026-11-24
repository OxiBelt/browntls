//! ML-DSA (RFC 9881): the Appendix C.3 certificates and signatures by the
//! Appendix C.1 keys, verified with the native provider's opt-in table
//! (`native::SUPPORTED_SIG_ALGS_WITH_ML_DSA`), the default tables and
//! fuzzed subsets of the opt-in table.

use std::sync::OnceLock;

use browntls_core::crypto::{native, rustcrypto};
use browntls_crypto::mldsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey};
use browntls_pki::{
    AlgorithmIdentifier, CertificateDer, EndEntityCert, Error, KeyUsage, RawPublicKeyEntity,
    SignatureVerificationAlgorithm, SignedData, SubjectPublicKeyInfoDer, alg_id,
    anchor_from_trusted_cert, subject_public_keys_match,
};

use super::chains::{MESSAGE, corrupt, covered, signature_algorithm, spki_algorithm};
use crate::input::Input;

macro_rules! data {
    ($crate_dir:literal, $file:literal) => {
        include_bytes!(concat!(
            "../../../crates/",
            $crate_dir,
            "/tests/data/rfc9881/",
            $file
        ))
    };
}

/// Appendix C.3: self-signed CA certificates (keyCertSign, cRLSign and
/// digitalSignature) of the Appendix C.1 keys.
const CERTS: [&[u8]; 3] = [
    data!("browntls-pki", "ml-dsa-44-certificate.der"),
    data!("browntls-pki", "ml-dsa-65-certificate.der"),
    data!("browntls-pki", "ml-dsa-87-certificate.der"),
];

/// Appendix C.2: the public keys of the Appendix C.1 keys.
const SPKIS: [&[u8]; 3] = [
    data!("browntls-pki", "ml-dsa-44-public-key.der"),
    data!("browntls-pki", "ml-dsa-65-public-key.der"),
    data!("browntls-pki", "ml-dsa-87-public-key.der"),
];

/// Appendix C.1, seed form (published examples, not secrets).
const KEYS: [&[u8]; 3] = [
    data!("browntls-crypto", "ml-dsa-44-seed.der"),
    data!("browntls-crypto", "ml-dsa-65-seed.der"),
    data!("browntls-crypto", "ml-dsa-87-seed.der"),
];

const IDS: [AlgorithmIdentifier; 3] = [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87];

/// The signatures of the Appendix C.1 keys over [`MESSAGE`] (pure ML-DSA,
/// empty context, deterministic), made once per process.
fn signatures() -> &'static [Vec<u8>; 3] {
    static SIGNED: OnceLock<[Vec<u8>; 3]> = OnceLock::new();
    SIGNED.get_or_init(|| {
        let sign44 = SigningKey::<MlDsa44>::from_pkcs8_der(KEYS[0]).expect("C.1 key");
        let sign65 = SigningKey::<MlDsa65>::from_pkcs8_der(KEYS[1]).expect("C.1 key");
        let sign87 = SigningKey::<MlDsa87>::from_pkcs8_der(KEYS[2]).expect("C.1 key");
        [
            sign44
                .sign_deterministic(MESSAGE, b"")
                .expect("signing")
                .as_ref()
                .to_vec(),
            sign65
                .sign_deterministic(MESSAGE, b"")
                .expect("signing")
                .as_ref()
                .to_vec(),
            sign87
                .sign_deterministic(MESSAGE, b"")
                .expect("signing")
                .as_ref()
                .to_vec(),
        ]
    })
}

/// An algorithm table: the native default, the native opt-in, the
/// RustCrypto default, or a fuzzed subset of the opt-in.
fn table(input: &mut Input<'_>) -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    match input.choose(4) {
        0 => native::SUPPORTED_SIG_ALGS.all.to_vec(),
        1 => native::SUPPORTED_SIG_ALGS_WITH_ML_DSA.all.to_vec(),
        2 => rustcrypto::SUPPORTED_SIG_ALGS.all.to_vec(),
        _ => {
            let mask = input.u32();
            native::ALL_VERIFICATION_ALGS_WITH_ML_DSA
                .iter()
                .enumerate()
                .filter(|(i, _)| *i < 32 && mask >> i & 1 != 0)
                .map(|(_, a)| *a)
                .collect()
        }
    }
}

/// Whether `algs` has the native algorithm of parameter set `set`.
fn has(algs: &[&dyn SignatureVerificationAlgorithm], set: usize) -> bool {
    covered(algs, IDS[set].as_bytes(), IDS[set].as_bytes())
}

/// One operation: a certificate or a raw signature of a fuzzed parameter
/// set under a fuzzed table.
pub(super) fn ml_dsa_op(input: &mut Input<'_>) {
    let set = input.choose(3);
    let algs = table(input);
    if input.bool() {
        certificate(input, set, &algs);
    } else {
        raw_signature(input, set, &algs);
    }
}

/// An Appendix C.3 certificate, possibly corrupted, verified with its own
/// key, another set's key or a fuzzed one, then as an end entity under
/// itself as trust anchor.
fn certificate(input: &mut Input<'_>, set: usize, algs: &[&dyn SignatureVerificationAlgorithm]) {
    let mut bytes = CERTS[set].to_vec();
    let corrupted = input.bool();
    if corrupted {
        corrupt(input, &mut bytes);
    }
    let key_choice = input.choose(3);
    let spki = match key_choice {
        0 => SPKIS[set].to_vec(),
        1 => SPKIS[(set + 1) % 3].to_vec(),
        _ => input.field().to_vec(),
    };
    let spki = SubjectPublicKeyInfoDer::from(spki);

    let Ok(signed) = SignedData::from_der(&bytes) else {
        assert!(corrupted);
        return;
    };
    let result = signed.verify_signature(algs, &spki);
    if corrupted {
        assert!(result.is_err(), "a corrupted certificate verified");
    } else {
        // RFC 9881: the same identifier for key and signature, absent
        // parameters, matched byte for byte.
        assert_eq!(signature_algorithm(&bytes), IDS[set].as_bytes());
        match key_choice {
            0 => {
                let expected = if has(algs, set) {
                    Ok(())
                } else if algs
                    .iter()
                    .any(|a| a.signature_alg_id().matches_signature(IDS[set].as_bytes()))
                {
                    Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
                } else {
                    Err(Error::UnsupportedSignatureAlgorithm)
                };
                assert_eq!(result, expected);
            }
            1 => assert!(result.is_err()),
            _ => assert!(result.is_err() || spki.as_ref() == SPKIS[set]),
        }
    }

    let der = CertificateDer::from(bytes.as_slice());
    let Ok(cert) = EndEntityCert::try_from(&der) else {
        assert!(corrupted);
        return;
    };
    let cert_spki = cert.subject_public_key_info();
    if !corrupted {
        // The certificate holds the Appendix C.2 key, and only that set's
        // key matches it.
        assert_eq!(cert_spki.as_ref(), SPKIS[set]);
        assert_eq!(spki_algorithm(cert_spki.as_ref()), IDS[set].as_bytes());
        for (other, other_spki) in SPKIS.iter().enumerate() {
            assert_eq!(
                subject_public_keys_match(cert_spki.as_ref(), other_spki),
                Ok(other == set)
            );
        }
    }
    let _ = subject_public_keys_match(cert_spki.as_ref(), spki.as_ref());

    // The certificate as an end entity under itself as trust anchor: a CA
    // certificate, so path validation refuses it, and it never accepts what
    // the signature check refuses.
    let anchor_der = CertificateDer::from(CERTS[set]);
    let anchors = [anchor_from_trusted_cert(&anchor_der).expect("C.3 anchor")];
    let path = cert.verify_for_usage(
        algs,
        &anchors,
        &[],
        crate::tls_config::NOW,
        KeyUsage::server_auth(),
        None,
        None,
    );
    assert!(path.is_err() || (has(algs, set) && !corrupted));
}

/// A signature by an Appendix C.1 key over [`MESSAGE`], possibly tampered
/// with, through `RawPublicKeyEntity` with every algorithm of the table and
/// through `SignedData` with the table.
fn raw_signature(input: &mut Input<'_>, set: usize, algs: &[&dyn SignatureVerificationAlgorithm]) {
    let mut message = MESSAGE.to_vec();
    let mut signature = signatures()[set].clone();
    let tamper = input.choose(4);
    match tamper {
        0 => {}
        1 => corrupt(input, &mut signature),
        2 => corrupt(input, &mut message),
        _ => signature.truncate(usize::from(input.u16()) % signature.len()),
    }
    let genuine = tamper == 0;
    let spki = SubjectPublicKeyInfoDer::from(SPKIS[set]);
    let raw = RawPublicKeyEntity::try_from(&spki).expect("an ML-DSA SPKI");
    for alg in algs {
        let result = raw.verify_signature(*alg, &message, &signature);
        let own = alg.public_key_alg_id() == IDS[set] && alg.signature_alg_id() == IDS[set];
        if own && genuine {
            assert_eq!(result, Ok(()));
        } else {
            assert!(result.is_err(), "{alg:?}");
        }
    }
    let result = SignedData::from_parts(&message, IDS[set].as_bytes(), &signature)
        .verify_signature(algs, &spki);
    assert_eq!(result.is_ok(), genuine && has(algs, set));
    // Another set's identifier never verifies.
    let other = IDS[(set + 1) % 3];
    let result = SignedData::from_parts(&message, other.as_bytes(), &signature)
        .verify_signature(algs, &spki);
    assert!(result.is_err());
}
