//! RFC 9881 private-key association: the Appendix C.1 private keys, loaded
//! from PKCS #8 in all three forms with `browntls_crypto::mldsa`, belong to
//! the Appendix C.3 certificates (and to no other), sign data that the
//! native provider's ML-DSA algorithms verify with the certificate's key,
//! and issue certificates that validate under the Appendix C.3 certificate
//! as trust anchor with the opt-in algorithm table. The Appendix C.4 keys
//! are refused, and the provider's key loader does not take ML-DSA keys
//! (TLS signing with ML-DSA is not implemented).
//!
//! The RFC 9881 examples are published, not secrets (see
//! `browntls-crypto/tests/data/rfc9881/README.md`); every other key is
//! derived at run time from a fixed label.

#![cfg(all(feature = "native", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../browntls-pki/tests/common/ml_dsa.rs"]
mod ml_dsa;
#[path = "../../browntls-pki/tests/common/x509_builder.rs"]
mod x509;

use std::sync::Arc;
use std::time::Duration;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::ServerCertVerifier as _;
use browntls_core::crypto::native;
use browntls_core::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SignatureVerificationAlgorithm,
    UnixTime,
};
use browntls_core::{CertificateError, Error, RootCertStore};
use browntls_crypto::mldsa::{self, MlDsa44, MlDsa65, MlDsa87, ParameterSet, SigningKey};
use browntls_crypto::rand::OsRng;
use browntls_pki::extensions::KeyUsageBit;
use browntls_pki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert, subject_public_keys_match};

use crate::ml_dsa::{Key, SETS, Set};
use crate::x509::{CertSpec, Signed, tlv};

macro_rules! crypto_data {
    ($file:literal) => {
        include_bytes!(concat!("../../browntls-crypto/tests/data/rfc9881/", $file))
    };
}

macro_rules! pki_data {
    ($file:literal) => {
        include_bytes!(concat!("../../browntls-pki/tests/data/rfc9881/", $file))
    };
}

/// Appendix C.1: each set's private key in the seed, expanded and both
/// forms.
const PRIVATE_KEYS: [[&[u8]; 3]; 3] = [
    [
        crypto_data!("ml-dsa-44-seed.der"),
        crypto_data!("ml-dsa-44-expanded.der"),
        crypto_data!("ml-dsa-44-both.der"),
    ],
    [
        crypto_data!("ml-dsa-65-seed.der"),
        crypto_data!("ml-dsa-65-expanded.der"),
        crypto_data!("ml-dsa-65-both.der"),
    ],
    [
        crypto_data!("ml-dsa-87-seed.der"),
        crypto_data!("ml-dsa-87-expanded.der"),
        crypto_data!("ml-dsa-87-both.der"),
    ],
];

/// Appendix C.4: inconsistent ML-DSA-44 private keys.
const INCONSISTENT: [&[u8]; 3] = [
    crypto_data!("ml-dsa-44-inconsistent-1.der"),
    crypto_data!("ml-dsa-44-inconsistent-2.der"),
    crypto_data!("ml-dsa-44-inconsistent-3.der"),
];

/// Appendix C.3: the self-signed certificates.
const CERTS: [&[u8]; 3] = [
    pki_data!("ml-dsa-44-certificate.der"),
    pki_data!("ml-dsa-65-certificate.der"),
    pki_data!("ml-dsa-87-certificate.der"),
];

/// Appendix C.2: the public keys.
const PUBLIC_KEYS: [&[u8]; 3] = [
    pki_data!("ml-dsa-44-public-key.der"),
    pki_data!("ml-dsa-65-public-key.der"),
    pki_data!("ml-dsa-87-public-key.der"),
];

/// The Appendix C.1 seed `xi`: 00 01 02 ... 1f.
const SEED: [u8; mldsa::SEED_LEN] = {
    let mut seed = [0u8; mldsa::SEED_LEN];
    let mut i = 0;
    while i < seed.len() {
        seed[i] = i as u8;
        i += 1;
    }
    seed
};

/// 2025-06-15, inside the validity of the Appendix C.3 certificates
/// (2020-02-03 to 2040-01-29) and of `x509_builder` certificates.
fn now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_750_000_000))
}

fn native_alg(set: Set) -> &'static dyn SignatureVerificationAlgorithm {
    match set {
        Set::MlDsa44 => &native::verify::ML_DSA_44,
        Set::MlDsa65 => &native::verify::ML_DSA_65,
        Set::MlDsa87 => &native::verify::ML_DSA_87,
    }
}

/// Signs a message with the empty context, hedged (`true`) or
/// deterministic.
type Sign = Box<dyn Fn(&[u8], bool) -> Vec<u8>>;

/// An Appendix C.1 key, held by `browntls_crypto`, with what the tests
/// need of it independent of the parameter set.
struct Loaded {
    spki: Vec<u8>,
    expanded: Vec<u8>,
    seed: Option<[u8; mldsa::SEED_LEN]>,
    sign: Sign,
}

/// Loads `der` as a key of `P`; `Err` with the error otherwise.
fn load_as<P: ParameterSet>(der: &[u8]) -> Result<Loaded, browntls_crypto::Error> {
    let key = SigningKey::<P>::from_pkcs8_der(der)?;
    let mut spki = vec![0u8; mldsa::VerifyingKey::<P>::SPKI_LEN];
    let n = key.verifying_key().to_spki_der(&mut spki).unwrap();
    spki.truncate(n);
    Ok(Loaded {
        spki,
        expanded: key.to_expanded_bytes().as_ref().to_vec(),
        seed: key.seed().copied(),
        sign: Box::new(move |msg, hedged| {
            let sig = if hedged {
                key.sign(msg, b"", &OsRng)
            } else {
                key.sign_deterministic(msg, b"")
            };
            sig.unwrap().as_ref().to_vec()
        }),
    })
}

fn load(set: Set, der: &[u8]) -> Result<Loaded, browntls_crypto::Error> {
    match set {
        Set::MlDsa44 => load_as::<MlDsa44>(der),
        Set::MlDsa65 => load_as::<MlDsa65>(der),
        Set::MlDsa87 => load_as::<MlDsa87>(der),
    }
}

fn cert(der: &'static [u8]) -> EndEntityCert<'static> {
    // The certificate DER outlives the test, so the parsed form may too.
    let der: &'static CertificateDer<'static> = Box::leak(Box::new(CertificateDer::from(der)));
    EndEntityCert::try_from(der).expect("an Appendix C.3 certificate")
}

// ---------------------------------------------------------------------------
// (a) and (b): the key's SubjectPublicKeyInfo is the certificate's
// ---------------------------------------------------------------------------

#[test]
fn each_form_of_each_key_matches_its_certificate_only() {
    for (s, set) in SETS.into_iter().enumerate() {
        let forms: Vec<Loaded> = PRIVATE_KEYS[s]
            .iter()
            .map(|der| load(set, der).expect("an Appendix C.1 key"))
            .collect();
        // Seed and both keep the seed; the expanded form cannot have it.
        assert_eq!(forms[0].seed, Some(SEED), "{set:?}");
        assert_eq!(forms[1].seed, None, "{set:?}");
        assert_eq!(forms[2].seed, Some(SEED), "{set:?}");
        for key in &forms {
            assert_eq!(key.expanded, forms[0].expanded, "{set:?}");
            assert_eq!(key.spki, forms[0].spki, "{set:?}");
            assert_eq!(key.spki, PUBLIC_KEYS[s], "{set:?}: the Appendix C.2 key");

            for (c, &cert_der) in CERTS.iter().enumerate() {
                let cert = cert(cert_der);
                let cert_spki = cert.subject_public_key_info();
                let same_bytes = key.spki == cert_spki.as_ref();
                let matched = subject_public_keys_match(&key.spki, cert_spki.as_ref());
                // Byte equality and `subject_public_keys_match` agree: only
                // the key's own certificate matches.
                assert_eq!(same_bytes, c == s, "{set:?} against certificate {c}");
                assert_eq!(matched, Ok(c == s), "{set:?} against certificate {c}");
            }
        }
        // Another key of the same set matches no Appendix C.3 certificate.
        let other = Key::ml_dsa(set, "another key");
        let other_spki = x509::spki_of(&other);
        assert_ne!(other_spki, forms[0].spki);
        assert_eq!(
            subject_public_keys_match(
                &other_spki,
                cert(CERTS[s]).subject_public_key_info().as_ref()
            ),
            Ok(false)
        );
    }
}

#[test]
fn a_key_does_not_load_as_another_parameter_set() {
    for (s, set) in SETS.into_iter().enumerate() {
        for der in PRIVATE_KEYS[s] {
            for other in SETS.into_iter().filter(|&o| o != set) {
                assert_eq!(
                    load(other, der).err(),
                    Some(browntls_crypto::Error::InvalidKey),
                    "{set:?} as {other:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// (c): signatures and certificates made by the loaded keys
// ---------------------------------------------------------------------------

#[test]
fn signatures_by_the_loaded_key_verify_with_the_certificate_key() {
    let message = b"fresh data signed by an RFC 9881 Appendix C.1 key";
    for (s, set) in SETS.into_iter().enumerate() {
        let cert = cert(CERTS[s]);
        for der in PRIVATE_KEYS[s] {
            let key = load(set, der).unwrap();
            for hedged in [false, true] {
                let sig = (key.sign)(message, hedged);
                assert_eq!(sig.len(), set.signature_len());
                assert_eq!(
                    cert.verify_signature(native_alg(set), message, &sig),
                    Ok(()),
                    "{set:?}"
                );
                // The test oracle agrees.
                assert_eq!(cert.verify_signature(set.alg(), message, &sig), Ok(()));
                // Another parameter set's algorithm, another message, a
                // flipped bit: refused.
                for other in SETS.into_iter().filter(|&o| o != set) {
                    assert!(
                        cert.verify_signature(native_alg(other), message, &sig)
                            .is_err()
                    );
                }
                assert!(
                    cert.verify_signature(native_alg(set), b"other", &sig)
                        .is_err()
                );
                let mut bad = sig.clone();
                bad[sig.len() / 2] ^= 1;
                assert!(
                    cert.verify_signature(native_alg(set), message, &bad)
                        .is_err()
                );
            }
            // A certificate of another set does not verify the signature.
            let other = self::cert(CERTS[(s + 1) % 3]);
            let sig = (key.sign)(message, false);
            for alg in native::ALL_VERIFICATION_ALGS_WITH_ML_DSA {
                assert!(other.verify_signature(*alg, message, &sig).is_err());
            }
        }
    }
}

/// The Appendix C.3 certificates are CA certificates that may sign
/// certificates: keyUsage digitalSignature, keyCertSign and cRLSign,
/// basicConstraints cA, a validity around [`now`].
#[test]
fn the_appendix_c3_certificates_are_ca_certificates() {
    for (s, set) in SETS.into_iter().enumerate() {
        let cert = cert(CERTS[s]);
        let basic = cert.basic_constraints().expect("basicConstraints");
        assert!(basic.ca, "{set:?}");
        let ku = cert.key_usage().expect("keyUsage");
        for bit in [
            KeyUsageBit::DigitalSignature,
            KeyUsageBit::KeyCertSign,
            KeyUsageBit::CrlSign,
        ] {
            assert!(ku.contains(bit), "{set:?}: {bit:?}");
        }
        assert!(cert.not_before() <= now() && now() <= cert.not_after());
        assert_eq!(cert.subject(), cert.issuer(), "self-issued");
        // Self-signed with the Appendix C.1 key.
        let anchor_der = CertificateDer::from(CERTS[s]);
        assert!(anchor_from_trusted_cert(&anchor_der).is_ok());
    }
}

/// A certificate for a fresh end-entity key, issued under the Appendix C.3
/// certificate's name and signed by the Appendix C.1 key loaded from
/// `der`.
fn issue(set: Set, issuer_subject: &[u8], key: &Loaded, subject_key: &Key) -> Vec<u8> {
    let mut spec = CertSpec::ee("ML-DSA end entity", "replaced below", subject_key);
    spec.issuer = tlv(0x30, issuer_subject);
    // `tbs` takes the inner signature algorithm from this key, whose set is
    // the issuer's; the signature itself is the loaded key's.
    let identifiers = Key::ml_dsa(set, "identifiers only");
    let tbs = spec.tbs(&identifiers);
    let sig = (key.sign)(&tbs, false);
    Signed {
        tbs,
        alg: set.alg_id().as_bytes().to_vec(),
        bits: [&[0u8][..], &sig].concat(),
    }
    .der()
}

#[test]
fn a_certificate_issued_by_the_loaded_key_validates_under_the_c3_anchor() {
    for (s, set) in SETS.into_iter().enumerate() {
        let anchor_der = CertificateDer::from(CERTS[s]);
        let anchors = [anchor_from_trusted_cert(&anchor_der).unwrap()];
        let issuer = cert(CERTS[s]);
        // End entities with an ML-DSA key of the same set and with a P-256
        // key.
        for subject_key in [Key::ml_dsa(set, "end entity"), Key::p256()] {
            for der in PRIVATE_KEYS[s] {
                let key = load(set, der).unwrap();
                let leaf = issue(set, issuer.subject(), &key, &subject_key);
                let leaf_der = CertificateDer::from(leaf.as_slice());
                let ee = EndEntityCert::try_from(&leaf_der).unwrap();
                let verify = |algs: &[&dyn SignatureVerificationAlgorithm]| {
                    ee.verify_for_usage(
                        algs,
                        &anchors,
                        &[],
                        now(),
                        KeyUsage::server_auth(),
                        None,
                        None,
                    )
                    .map(|_| ())
                };
                assert_eq!(
                    verify(native::SUPPORTED_SIG_ALGS_WITH_ML_DSA.all),
                    Ok(()),
                    "{set:?}, {subject_key:?}"
                );
                // The default table has no ML-DSA algorithm.
                assert_eq!(
                    verify(native::SUPPORTED_SIG_ALGS.all),
                    Err(browntls_pki::Error::UnsupportedSignatureAlgorithm)
                );

                // The same through the verifier of a provider with the
                // opt-in table, and refused by the default provider.
                let mut roots = RootCertStore::empty();
                roots.add(anchor_der.clone()).unwrap();
                let roots = Arc::new(roots);
                let mut provider = native::default_provider();
                provider.signature_verification_algorithms = native::SUPPORTED_SIG_ALGS_WITH_ML_DSA;
                let name = ServerName::try_from("example.com").unwrap();
                for (provider, expected) in [
                    (Arc::new(provider), Ok(())),
                    (
                        Arc::new(native::default_provider()),
                        Err(Error::InvalidCertificate(
                            CertificateError::UnsupportedSignatureAlgorithm,
                        )),
                    ),
                ] {
                    let verifier =
                        WebPkiServerVerifier::builder_with_provider(roots.clone(), provider)
                            .build()
                            .unwrap();
                    let result = verifier
                        .verify_server_cert(&leaf_der, &[], &name, &[], now())
                        .map(|_| ());
                    assert_eq!(result, expected, "{set:?}");
                }
            }
        }

        // A certificate under the same name signed by another key, and one
        // signed by the loaded key of another set, do not validate.
        let key = load(set, PRIVATE_KEYS[s][0]).unwrap();
        let ee_key = Key::ml_dsa(set, "end entity");
        let impostor = Key::ml_dsa(set, "impostor");
        let mut spec = CertSpec::ee("ML-DSA end entity", "replaced below", &ee_key);
        spec.issuer = tlv(0x30, issuer.subject());
        for leaf in [
            spec.sign(&impostor),
            issue(
                SETS[(s + 1) % 3],
                issuer.subject(),
                &load(SETS[(s + 1) % 3], PRIVATE_KEYS[(s + 1) % 3][0]).unwrap(),
                &ee_key,
            ),
            // The loaded key's own certificate, with one bit of the
            // signature flipped.
            x509::flip(issue(set, issuer.subject(), &key, &ee_key), 0),
        ] {
            let leaf_der = CertificateDer::from(leaf.as_slice());
            let Ok(ee) = EndEntityCert::try_from(&leaf_der) else {
                continue;
            };
            let result = ee.verify_for_usage(
                native::SUPPORTED_SIG_ALGS_WITH_ML_DSA.all,
                &anchors,
                &[],
                now(),
                KeyUsage::server_auth(),
                None,
                None,
            );
            assert!(result.is_err(), "{set:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// (d): inconsistent keys, and the provider's key loader
// ---------------------------------------------------------------------------

#[test]
fn the_appendix_c4_keys_are_refused() {
    for der in INCONSISTENT {
        for set in SETS {
            assert_eq!(
                load(set, der).err(),
                Some(browntls_crypto::Error::InvalidKey),
                "{set:?}"
            );
        }
    }
}

/// ML-DSA private keys are not TLS signing keys yet: the native key
/// provider refuses each Appendix C.1 key, in every form, as a PKCS #8 key
/// it cannot parse.
#[test]
fn the_native_key_provider_does_not_load_ml_dsa_keys() {
    for der in PRIVATE_KEYS.iter().flatten().chain(&INCONSISTENT) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()));
        let result = native::KEY_PROVIDER.load_private_key(key).map(|_| ());
        assert_eq!(
            result,
            Err(Error::General(
                "failed to parse PKCS#8 private key as ECDSA, EdDSA or RSA".into()
            ))
        );
    }
}
