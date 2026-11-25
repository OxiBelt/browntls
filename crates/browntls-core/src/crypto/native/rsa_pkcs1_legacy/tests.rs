use alloc::format;

use browntls_crypto::rsa::{
    MAX_PKCS1_PRIVATE_KEY_DER_LEN, MAX_PKCS8_PRIVATE_KEY_DER_LEN, verify_pkcs1v15, verify_pss,
};
use browntls_pki::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, alg_id};

use super::*;
use crate::crypto::native::SUPPORTED_SIG_ALGS;
use crate::crypto::native::sign::any_rsa_type;
use crate::error::PeerMisbehaved;
use crate::verify::DigitallySignedStruct;
use crate::webpki::{
    verify_tls12_signature_with_raw_key, verify_tls13_client_signature_with_raw_key,
    verify_tls13_signature_with_raw_key,
};

use SignatureScheme as S;

const LEGACY: [(S, BcHash); 3] = [
    (S::RSA_PKCS1_SHA256_LEGACY, BcHash::Sha256),
    (S::RSA_PKCS1_SHA384_LEGACY, BcHash::Sha384),
    (S::RSA_PKCS1_SHA512_LEGACY, BcHash::Sha512),
];

/// A fresh 2048-bit key and its PKCS #1 encoding (test data).
fn generate() -> (RsaPrivateKey, PrivateKeyDer<'static>) {
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let mut der = vec![0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
    let len = key.to_pkcs1_der(&mut der).unwrap();
    der.truncate(len);
    (key, PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)))
}

#[test]
fn key_signs_with_pkcs1_only() {
    let (key, der) = generate();
    let loaded = any_rsa_pkcs1_legacy_type(&der).unwrap();
    assert_eq!(loaded.algorithm(), SignatureAlgorithm::RSA);
    // The same `rsaEncryption` key as the ordinary loader's.
    let ordinary = any_rsa_type(&der).unwrap();
    assert_eq!(
        loaded.public_key().unwrap().as_ref(),
        ordinary.public_key().unwrap().as_ref()
    );

    // Never RSASSA-PSS, nor anything that is not RSA.
    for offered in [
        &[S::RSA_PSS_SHA256, S::RSA_PSS_SHA384, S::RSA_PSS_SHA512][..],
        &[
            S::RSA_PSS_PSS_SHA256,
            S::RSA_PSS_PSS_SHA384,
            S::RSA_PSS_PSS_SHA512,
        ],
        &[S::ED25519, S::ECDSA_NISTP256_SHA256, S::ML_DSA_65],
        &[S::RSA_PKCS1_SHA1, S::Unknown(0x0720)],
        &[],
    ] {
        assert!(loaded.choose_scheme(offered).is_none(), "{offered:?}");
    }

    // Each legacy scheme and each TLS 1.2 scheme, when offered, also
    // among schemes the key does not sign with.
    let tls12 = [
        (S::RSA_PKCS1_SHA256, BcHash::Sha256),
        (S::RSA_PKCS1_SHA384, BcHash::Sha384),
        (S::RSA_PKCS1_SHA512, BcHash::Sha512),
    ];
    for (scheme, hash) in LEGACY.into_iter().chain(tls12) {
        let signer = loaded
            .choose_scheme(&[S::RSA_PSS_SHA512, S::ED25519, scheme])
            .unwrap();
        assert_eq!(signer.scheme(), scheme);
        let signature = signer.sign(b"message").unwrap();
        assert_eq!(signature.len(), 256);
        verify_pkcs1v15(key.public_key(), hash, b"message", &signature).unwrap();
        assert!(verify_pkcs1v15(key.public_key(), hash, b"other", &signature).is_err());
        assert!(verify_pss(key.public_key(), hash, b"message", &signature).is_err());
        for other in [BcHash::Sha256, BcHash::Sha384, BcHash::Sha512] {
            assert_eq!(
                verify_pkcs1v15(key.public_key(), other, b"message", &signature).is_ok(),
                other == hash
            );
        }
    }
    // The larger hash first, within each kind.
    let all: Vec<S> = LEGACY.iter().map(|(scheme, _)| *scheme).collect();
    let signer = loaded.choose_scheme(&all).unwrap();
    assert_eq!(signer.scheme(), S::RSA_PKCS1_SHA512_LEGACY);
    let signer = loaded
        .choose_scheme(&[S::RSA_PKCS1_SHA256, S::RSA_PKCS1_SHA384])
        .unwrap();
    assert_eq!(signer.scheme(), S::RSA_PKCS1_SHA384);

    // An ordinary key never chooses a legacy scheme.
    assert!(ordinary.choose_scheme(&all).is_none());

    // No secret in the debug output.
    let debug = format!("{loaded:?} {signer:?}");
    assert!(debug.contains("RsaPkcs1LegacySigningKey") && debug.contains("2048"));
    assert!(debug.len() < 120, "{debug}");
}

#[test]
fn only_rsa_encryption_keys_load() {
    let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
    let pkcs8 = |algorithm| {
        let mut der = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
        let len = key
            .to_pkcs8_der_with_algorithm(algorithm, &mut der)
            .unwrap();
        der.truncate(len);
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
    };
    let loaded = any_rsa_pkcs1_legacy_type(&pkcs8(RsaKeyAlgorithm::RsaEncryption)).unwrap();
    let spki = loaded.public_key().unwrap();
    let (alg, _) = crate::x509::split_spki(spki.as_ref()).unwrap();
    assert_eq!(alg, alg_id::RSA_ENCRYPTION.as_ref());
    for algorithm in [
        RsaKeyAlgorithm::RsassaPss(None),
        RsaKeyAlgorithm::RsassaPss(Some(BcHash::Sha256)),
    ] {
        let der = pkcs8(algorithm);
        any_rsa_type(&der).unwrap();
        assert!(any_rsa_pkcs1_legacy_type(&der).is_err(), "{algorithm:?}");
    }
    let garbage = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x30, 0x00]));
    assert!(any_rsa_pkcs1_legacy_type(&garbage).is_err());
}

#[test]
fn table_adds_the_legacy_schemes_after_the_defaults() {
    let table = &SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY;
    let defaults = SUPPORTED_SIG_ALGS.mapping.len();
    assert_eq!(table.mapping.len(), defaults + 3);
    for (default, opt_in) in SUPPORTED_SIG_ALGS.mapping.iter().zip(table.mapping) {
        assert_eq!(default.0, opt_in.0);
        assert_eq!(default.1.len(), opt_in.1.len());
    }
    let added: Vec<S> = table.mapping[defaults..].iter().map(|m| m.0).collect();
    assert_eq!(
        added,
        [
            S::RSA_PKCS1_SHA512_LEGACY,
            S::RSA_PKCS1_SHA384_LEGACY,
            S::RSA_PKCS1_SHA256_LEGACY
        ]
    );
    for (scheme, algs) in RSA_PKCS1_LEGACY_VERIFICATION_ALG_MAPPING {
        assert!(scheme.is_rsa_pkcs1_legacy());
        // RSASSA-PKCS1-v1_5 with an `rsaEncryption` key, and nothing else.
        assert_eq!(algs.len(), 1);
        assert_eq!(algs[0].public_key_alg_id(), alg_id::RSA_ENCRYPTION);
        assert!(!SUPPORTED_SIG_ALGS.supported_schemes().contains(scheme));
    }
    // The certificate path algorithms are the default ones.
    assert_eq!(table.all.len(), SUPPORTED_SIG_ALGS.all.len());
    for (default, opt_in) in SUPPORTED_SIG_ALGS.all.iter().zip(table.all) {
        assert_eq!(default.signature_alg_id(), opt_in.signature_alg_id());
        assert_eq!(default.public_key_alg_id(), opt_in.public_key_alg_id());
    }
    // No default scheme is a legacy one.
    assert!(
        !SUPPORTED_SIG_ALGS
            .supported_schemes()
            .iter()
            .any(S::is_rsa_pkcs1_legacy)
    );
}

/// The key's legacy signatures verify with the opt-in table as a client's
/// `CertificateVerify`, and with nothing else. (The role rules and the
/// exact encoding are tested with both providers' tables in
/// `webpki::verify`.)
#[test]
fn signatures_verify_with_the_opt_in_table_for_a_client_only() {
    let (_, der) = generate();
    let loaded = any_rsa_pkcs1_legacy_type(&der).unwrap();
    let spki = loaded.public_key().unwrap();
    let table = &SUPPORTED_SIG_ALGS_WITH_RSA_PKCS1_LEGACY;
    let unadvertised =
        Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme);
    let message = b"TLS 1.3, client CertificateVerify";
    for (scheme, _) in LEGACY {
        let signer = loaded.choose_scheme(&[scheme]).unwrap();
        let dss = DigitallySignedStruct::new(scheme, signer.sign(message).unwrap());
        verify_tls13_client_signature_with_raw_key(message, &spki, &dss, table).unwrap();
        assert!(
            verify_tls13_client_signature_with_raw_key(message, &spki, &dss, &SUPPORTED_SIG_ALGS)
                .is_err()
        );
        assert_eq!(
            verify_tls13_signature_with_raw_key(message, &spki, &dss, table).unwrap_err(),
            unadvertised
        );
        assert_eq!(
            verify_tls12_signature_with_raw_key(message, &spki, &dss, table).unwrap_err(),
            unadvertised
        );
    }
}
