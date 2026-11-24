//! ML-DSA private keys in both providers (`draft-ietf-tls-mldsa-06`
//! opt-in): `rustcrypto::sign::any_ml_dsa_type` and
//! `native::sign::any_ml_dsa_type` load the same RFC 9881 PKCS #8
//! encodings into keys with the same `SubjectPublicKeyInfo`, refuse the
//! same malformed ones, and sign what the other provider's algorithm of the
//! same parameter set verifies. The one difference: the RustCrypto
//! provider refuses the `expandedKey` form alone (the `ml-dsa` crate has
//! no checked decoding of an expanded key), which the native one loads.

use std::sync::Arc;

use browntls_core::crypto::{KeyProvider as _, native, rustcrypto};
use browntls_core::pki_types::PrivatePkcs8KeyDer;
use browntls_core::sign::SigningKey;
use browntls_core::{Error, SignatureScheme};
use browntls_crypto::mldsa::{self, MlDsa44, MlDsa65, MlDsa87, ParameterSet, PrivateKeyFormat};
use sha2::Digest as _;

use crate::ml_dsa::{SETS, Set};
use crate::{native_alg, rc_alg};

/// The forms both providers load.
const FORMATS: [PrivateKeyFormat; 2] = [PrivateKeyFormat::Seed, PrivateKeyFormat::Both];

/// The RustCrypto loader's error (the same for every ML-DSA key it
/// refuses).
fn rc_error() -> Error {
    rustcrypto::sign::any_ml_dsa_type(&PrivatePkcs8KeyDer::from(Vec::new())).unwrap_err()
}

/// `der` is an `expandedKey`-only key: the native provider loads it, the
/// RustCrypto provider refuses it (loader and opt-in key provider, with
/// the ML-DSA error). Returns the native key's SPKI.
fn expanded_only(der: &[u8], what: &str) -> Vec<u8> {
    let (native, rc) = load_both(der);
    assert_eq!(rc.err(), Some(rc_error()), "{what}");
    let key = browntls_core::pki_types::PrivateKeyDer::Pkcs8(der.to_vec().into());
    assert_eq!(
        rustcrypto::KEY_PROVIDER_WITH_ML_DSA
            .load_private_key(key)
            .err(),
        Some(rc_error()),
        "{what}"
    );
    spki(&native).unwrap_or_else(|| panic!("{what}"))
}

/// A fixed seed for `(set, label)` (test data, derived at run time).
pub(crate) fn seed(set: Set, label: &str) -> [u8; 32] {
    sha2::Sha256::digest(format!(
        "browntls RustCrypto ML-DSA signing {set:?} {label}"
    ))
    .into()
}

fn encode<P: ParameterSet>(seed: &[u8; 32], format: PrivateKeyFormat) -> Vec<u8> {
    let key = mldsa::SigningKey::<P>::from_seed(seed);
    let mut der = vec![0; mldsa::SigningKey::<P>::PKCS8_MAX_LEN];
    let len = key.to_pkcs8_der(format, &mut der).unwrap();
    der.truncate(len);
    der
}

/// The RFC 9881 PKCS #8 encoding of the key of `seed` in `format`, written
/// by `browntls_crypto`.
pub(crate) fn pkcs8(set: Set, seed: &[u8; 32], format: PrivateKeyFormat) -> Vec<u8> {
    match set {
        Set::MlDsa44 => encode::<MlDsa44>(seed, format),
        Set::MlDsa65 => encode::<MlDsa65>(seed, format),
        Set::MlDsa87 => encode::<MlDsa87>(seed, format),
    }
}

pub(crate) fn scheme(set: Set) -> SignatureScheme {
    match set {
        Set::MlDsa44 => SignatureScheme::ML_DSA_44,
        Set::MlDsa65 => SignatureScheme::ML_DSA_65,
        Set::MlDsa87 => SignatureScheme::ML_DSA_87,
    }
}

type Loaded = Result<Arc<dyn SigningKey>, Error>;

/// `der` loaded by both providers' ML-DSA loaders (native, RustCrypto).
fn load_both(der: &[u8]) -> (Loaded, Loaded) {
    let der = PrivatePkcs8KeyDer::from(der.to_vec());
    (
        native::sign::any_ml_dsa_type(&der),
        rustcrypto::sign::any_ml_dsa_type(&der),
    )
}

fn spki(key: &Loaded) -> Option<Vec<u8>> {
    key.as_ref()
        .ok()
        .map(|key| key.public_key().unwrap().as_ref().to_vec())
}

/// Both providers accept `der` with the same public key, or both refuse
/// it.
fn same_outcome(der: &[u8], what: &str) -> bool {
    let (native, rc) = load_both(der);
    assert_eq!(native.is_ok(), rc.is_ok(), "{what}");
    assert_eq!(spki(&native), spki(&rc), "{what}");
    rc.is_ok()
}

fn flip(der: &[u8], i: usize, bit: u8) -> Vec<u8> {
    let mut der = der.to_vec();
    der[i] ^= 1 << bit;
    der
}

#[test]
fn every_form_loads_in_both_providers_with_the_same_spki() {
    for set in SETS {
        let seed = seed(set, "forms");
        let mut spkis = Vec::new();
        for format in FORMATS {
            let der = pkcs8(set, &seed, format);
            let (native, rc) = load_both(&der);
            let (native, rc) = (native.unwrap(), rc.unwrap());
            assert_eq!(native.algorithm(), rc.algorithm(), "{set:?} {format:?}");
            let spki = rc.public_key().unwrap().as_ref().to_vec();
            assert_eq!(native.public_key().unwrap().as_ref(), spki);
            spkis.push(spki);
            // The opt-in key providers agree.
            let key = || browntls_core::pki_types::PrivateKeyDer::Pkcs8(der.clone().into());
            let rc_loaded = rustcrypto::KEY_PROVIDER_WITH_ML_DSA
                .load_private_key(key())
                .unwrap();
            assert_eq!(rc_loaded.public_key().unwrap().as_ref(), spkis[0]);
            assert!(rustcrypto::RustCrypto.load_private_key(key()).is_err());
        }
        assert!(spkis.iter().all(|s| *s == spkis[0]), "{set:?}");
        // The `expandedKey` form: native only, the same key.
        let der = pkcs8(set, &seed, PrivateKeyFormat::Expanded);
        assert_eq!(expanded_only(&der, &format!("{set:?}")), spkis[0]);
    }
}

#[test]
fn signatures_verify_with_the_other_provider() {
    for set in SETS {
        let der = pkcs8(set, &seed(set, "cross"), PrivateKeyFormat::Both);
        let (native, rc) = load_both(&der);
        let (native, rc) = (native.unwrap(), rc.unwrap());
        let spki = rc.public_key().unwrap().as_ref().to_vec();
        let public_key = &spki[spki.len() - set.public_key_len()..];
        let message = b"TLS 1.3, server CertificateVerify\0transcript hash";
        for (signer, verifier, what) in [
            (&rc, native_alg(set), "RustCrypto key, native algorithm"),
            (&native, rc_alg(set), "native key, RustCrypto algorithm"),
            (&rc, rc_alg(set), "RustCrypto key, RustCrypto algorithm"),
        ] {
            let signer = signer.choose_scheme(&[scheme(set)]).unwrap();
            assert_eq!(signer.scheme(), scheme(set));
            let signature = signer.sign(message).unwrap();
            assert_eq!(signature.len(), set.signature_len(), "{set:?} {what}");
            verifier
                .verify_signature(public_key, message, &signature)
                .unwrap_or_else(|_| panic!("{set:?} {what}"));
            // A changed signature or message does not verify.
            for i in [0, signature.len() / 2, signature.len() - 1] {
                let bad = flip(&signature, i, 0);
                assert!(
                    verifier
                        .verify_signature(public_key, message, &bad)
                        .is_err(),
                    "{set:?} {what} {i}"
                );
            }
            assert!(
                verifier
                    .verify_signature(public_key, b"another message", &signature)
                    .is_err()
            );
            // Nor with another parameter set's algorithm.
            for other in SETS.into_iter().filter(|s| *s != set) {
                assert!(
                    rc_alg(other)
                        .verify_signature(public_key, message, &signature)
                        .is_err()
                );
            }
        }
    }
}

macro_rules! rfc_data {
    ($file:literal) => {
        include_bytes!(concat!(
            "../../../browntls-crypto/tests/data/rfc9881/",
            $file
        ))
    };
}

/// One RFC 9881 example: the private key in its three forms and the public
/// key.
type Example = (Set, [&'static [u8]; 3], &'static [u8]);

#[test]
fn rfc9881_examples_load_and_inconsistent_keys_are_refused() {
    // Appendix C.1 (the three forms) and C.2 (the public key).
    let examples: [Example; 3] = [
        (
            Set::MlDsa44,
            [
                rfc_data!("ml-dsa-44-seed.der"),
                rfc_data!("ml-dsa-44-expanded.der"),
                rfc_data!("ml-dsa-44-both.der"),
            ],
            rfc_data!("ml-dsa-44-public-key.der"),
        ),
        (
            Set::MlDsa65,
            [
                rfc_data!("ml-dsa-65-seed.der"),
                rfc_data!("ml-dsa-65-expanded.der"),
                rfc_data!("ml-dsa-65-both.der"),
            ],
            rfc_data!("ml-dsa-65-public-key.der"),
        ),
        (
            Set::MlDsa87,
            [
                rfc_data!("ml-dsa-87-seed.der"),
                rfc_data!("ml-dsa-87-expanded.der"),
                rfc_data!("ml-dsa-87-both.der"),
            ],
            rfc_data!("ml-dsa-87-public-key.der"),
        ),
    ];
    for (set, [seed_der, expanded_der, both_der], public_key) in examples {
        for der in [seed_der, both_der] {
            let (native, rc) = load_both(der);
            assert_eq!(spki(&rc).unwrap(), public_key, "{set:?}");
            assert_eq!(spki(&native).unwrap(), public_key, "{set:?}");
        }
        assert_eq!(expanded_only(expanded_der, "C.1"), public_key, "{set:?}");
    }
    // Appendix C.4: a `both` whose parts disagree (refused by both for
    // the RFC 9881 §8.2 check), and `expandedKey`-only keys one byte away
    // from the C.1 key in `tr` and in `t0` (refused by the native provider
    // for that, by the RustCrypto provider already for the form).
    for der in [
        &rfc_data!("ml-dsa-44-inconsistent-1.der")[..],
        rfc_data!("ml-dsa-44-inconsistent-2.der"),
        rfc_data!("ml-dsa-44-inconsistent-3.der"),
    ] {
        let (native, rc) = load_both(der);
        assert!(native.is_err());
        assert_eq!(rc.err(), Some(rc_error()));
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    crate::x509::tlv(tag, value)
}

fn alg_with(oid: &[u8], params: &[u8]) -> Vec<u8> {
    tlv(0x30, &[&tlv(0x06, oid)[..], params].concat())
}

/// `OneAsymmetricKey` from its parts.
fn assemble(version: u8, alg: &[u8], private_key: &[u8], tail: &[&[u8]]) -> Vec<u8> {
    let mut body = [&tlv(0x02, &[version])[..], alg, &tlv(0x04, private_key)].concat();
    for t in tail {
        body.extend_from_slice(t);
    }
    tlv(0x30, &body)
}

/// The encoded OID of `set` (the contents of its OBJECT IDENTIFIER).
fn oid(set: Set) -> Vec<u8> {
    let id = set.alg_id();
    id.as_ref()[2..].to_vec()
}

fn negative_matrix(set: Set, other: Set) {
    let seed = seed(set, "negative");
    let expanded_der = pkcs8(set, &seed, PrivateKeyFormat::Expanded);
    let sk = &expanded_der[expanded_der.len() - set_sk_len(set)..];
    let pk = {
        let (_, rc) = load_both(&pkcs8(set, &seed, PrivateKeyFormat::Seed));
        let spki = spki(&rc).unwrap();
        spki[spki.len() - set.public_key_len()..].to_vec()
    };
    let a = alg_with(&oid(set), &[]);
    let choices = [
        tlv(0x80, &seed),
        tlv(0x04, sk),
        tlv(0x30, &[tlv(0x04, &seed), tlv(0x04, sk)].concat()),
    ];
    let public_key = |pk: &[u8]| tlv(0x81, &[&[0][..], pk].concat());
    let attribute = tlv(
        0x30,
        &[
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14],
            ),
            tlv(0x31, &tlv(0x1e, &[0, 0x41])),
        ]
        .concat(),
    );

    // Accepted by both (the `expandedKey` form by the native provider
    // only): the forms, with version 1, attributes and the right public
    // key.
    for (i, choice) in choices.iter().enumerate() {
        for der in [
            assemble(0, &a, choice, &[]),
            assemble(1, &a, choice, &[]),
            assemble(1, &a, choice, &[&tlv(0xa0, &attribute), &public_key(&pk)]),
            assemble(0, &a, choice, &[&tlv(0xa0, &[])]),
        ] {
            if i == 1 {
                expanded_only(&der, "valid expandedKey");
            } else {
                assert!(same_outcome(&der, "valid"), "{set:?}");
            }
        }
    }

    let mut refused: Vec<(String, Vec<u8>)> = Vec::new();
    let other_sk = {
        let der = pkcs8(other, &seed, PrivateKeyFormat::Expanded);
        der[der.len() - set_sk_len(other)..].to_vec()
    };
    for (i, choice) in choices.iter().enumerate() {
        let mut case = |name: &str, der: Vec<u8>| refused.push((format!("{name} {i}"), der));
        case(
            "NULL parameters",
            assemble(0, &alg_with(&oid(set), &[0x05, 0x00]), choice, &[]),
        );
        case(
            "SEQUENCE parameters",
            assemble(0, &alg_with(&oid(set), &[0x30, 0x00]), choice, &[]),
        );
        let under_other = assemble(0, &alg_with(&oid(other), &[]), choice, &[]);
        if i == 0 {
            // A seed is a key of every parameter set.
            assert!(same_outcome(&under_other, "seed under the other OID"));
        } else {
            case("other set's OID", under_other);
        }
        let mut hash_ml_dsa = oid(set);
        *hash_ml_dsa.last_mut().unwrap() += 0x0f; // id-hash-ml-dsa-*
        case(
            "HashML-DSA OID",
            assemble(0, &alg_with(&hash_ml_dsa, &[]), choice, &[]),
        );
        case(
            "OID prefix",
            assemble(0, &alg_with(&oid(set)[..8], &[]), choice, &[]),
        );
        case("no OID", assemble(0, &[0x30, 0x00], choice, &[]));
        case("version 2", assemble(2, &a, choice, &[]));
        case(
            "publicKey with version 0",
            assemble(0, &a, choice, &[&public_key(&pk)]),
        );
        let mut wrong = pk.clone();
        wrong[7] ^= 0x10;
        case(
            "publicKey mismatch",
            assemble(1, &a, choice, &[&public_key(&wrong)]),
        );
        case(
            "publicKey short",
            assemble(1, &a, choice, &[&public_key(&pk[1..])]),
        );
        let unused = tlv(0x81, &[&[1][..], &pk].concat());
        case("publicKey unused bits", assemble(1, &a, choice, &[&unused]));
        let mut outer = assemble(0, &a, choice, &[]);
        outer.push(0);
        case("trailing outer", outer);
        case(
            "trailing element",
            assemble(0, &a, choice, &[&[0x02, 0x01, 0x00]]),
        );
        let inner = [&choice[..], &[0x04, 0x00]].concat();
        case("trailing in privateKey", assemble(0, &a, &inner, &[]));
        case(
            "attributes garbage",
            assemble(0, &a, choice, &[&[0xa0, 3, 0xff, 0xff, 0xff]]),
        );
    }
    let mut case = |name: &str, der: Vec<u8>| refused.push((name.to_string(), der));
    for n in [0, 31, 33] {
        case(
            &format!("seed {n}"),
            assemble(0, &a, &tlv(0x80, &vec![1; n]), &[]),
        );
    }
    case("expanded short", assemble(0, &a, &tlv(0x04, &sk[1..]), &[]));
    case(
        "expanded long",
        assemble(0, &a, &tlv(0x04, &[sk, &[0]].concat()), &[]),
    );
    case(
        "other set's expanded",
        assemble(0, &a, &tlv(0x04, &other_sk), &[]),
    );
    let both = |s: &[u8], k: &[u8]| tlv(0x30, &[tlv(0x04, s), tlv(0x04, k)].concat());
    case(
        "both short seed",
        assemble(0, &a, &both(&seed[1..], sk), &[]),
    );
    case(
        "both short expanded",
        assemble(0, &a, &both(&seed, &sk[1..]), &[]),
    );
    case("both swapped", assemble(0, &a, &both(sk, &seed), &[]));
    let mut other_seed = seed;
    other_seed[31] ^= 1;
    case(
        "both other seed",
        assemble(0, &a, &both(&other_seed, sk), &[]),
    );
    case("seed as [1]", assemble(0, &a, &tlv(0x81, &seed), &[]));
    case("empty input", Vec::new());

    // Encodings that BER allows and DER does not (X.690 §10.1 and §8.3.2),
    // and structures with one element too many, on the `seed` form.
    let version = [0x02, 0x01, 0x00];
    let private_key = tlv(0x04, &choices[0]);
    let body = [&version[..], &a, &private_key].concat();
    let len = u8::try_from(body.len()).unwrap();
    assert!(len < 0x80);
    let with_length = |length: &[u8], end: &[u8]| [&[0x30][..], length, &body, end].concat();
    case("long-form outer length", with_length(&[0x81, len], &[]));
    case(
        "leading-zero outer length",
        with_length(&[0x82, 0, len], &[]),
    );
    case(
        "five-octet outer length",
        with_length(&[0x85, 0, 0, 0, 0, len], &[]),
    );
    case("indefinite outer length", with_length(&[0x80], &[0, 0]));
    for version in [[0x02, 0x02, 0, 0], [0x02, 0x02, 0, 1]] {
        case(
            "non-minimal version",
            tlv(0x30, &[&version[..], &a, &private_key].concat()),
        );
    }
    let long_octets = [&[0x04, 0x81, 34][..], &choices[0]].concat();
    case(
        "long-form privateKey length",
        tlv(0x30, &[&version[..], &a, &long_octets].concat()),
    );
    let long_seed = [&[0x80, 0x81, 32][..], &seed].concat();
    case("long-form seed length", assemble(0, &a, &long_seed, &[]));
    let long_oid = tlv(0x30, &[&[0x06, 0x81, 9][..], &oid(set)].concat());
    case(
        "long-form OID length",
        assemble(0, &long_oid, &choices[0], &[]),
    );
    case(
        "high-tag-number element",
        assemble(0, &a, &choices[0], &[&[0xbf, 0x20, 0x00]]),
    );
    let three = [tlv(0x04, &seed), tlv(0x04, sk), tlv(0x04, &[])].concat();
    case(
        "both with a third element",
        assemble(0, &a, &tlv(0x30, &three), &[]),
    );
    let tagged = [tlv(0x80, &seed), tlv(0x04, sk)].concat();
    case(
        "both with a [0] seed",
        assemble(0, &a, &tlv(0x30, &tagged), &[]),
    );
    let constructed = tlv(0xa1, &[&[0][..], &pk].concat());
    case(
        "constructed publicKey",
        assemble(1, &a, &choices[0], &[&constructed]),
    );
    let empty = tlv(0xa0, &[]);
    case(
        "repeated attributes",
        assemble(0, &a, &choices[0], &[&empty, &empty]),
    );

    for (name, der) in &refused {
        let (native, rc) = load_both(der);
        assert!(native.is_err(), "{set:?} native {name}");
        assert!(rc.is_err(), "{set:?} RustCrypto {name}");
    }

    // Every proper prefix, and single-bit changes: the seed form's header,
    // and the parts of an `expandedKey`-only key (the native provider
    // loads one with a changed `K`, which it cannot detect; the RustCrypto
    // provider refuses the form).
    let seed_der = assemble(0, &a, &choices[0], &[]);
    for der in [&seed_der, &expanded_der] {
        for n in 0..der.len() {
            assert!(!same_outcome(&der[..n], "prefix"), "{set:?} {n}");
        }
    }
    for i in 0..seed_der.len() {
        for bit in 0..8 {
            same_outcome(&flip(&seed_der, i, bit), "seed form bit");
        }
    }
    let offset = expanded_der.len() - sk.len();
    for i in (0..sk.len()).step_by(41).chain([32, 63, sk.len() - 1]) {
        let changed = flip(&expanded_der, offset + i, (i % 8) as u8);
        let (native, rc) = load_both(&changed);
        assert_eq!(native.is_ok(), (32..64).contains(&i), "{set:?} byte {i}");
        assert!(rc.is_err(), "{set:?} byte {i}");
    }
}

fn set_sk_len(set: Set) -> usize {
    match set {
        Set::MlDsa44 => MlDsa44::SIGNING_KEY_LEN,
        Set::MlDsa65 => MlDsa65::SIGNING_KEY_LEN,
        Set::MlDsa87 => MlDsa87::SIGNING_KEY_LEN,
    }
}

#[test]
fn malformed_keys_are_refused_by_both_providers() {
    negative_matrix(Set::MlDsa44, Set::MlDsa65);
    negative_matrix(Set::MlDsa65, Set::MlDsa87);
    negative_matrix(Set::MlDsa87, Set::MlDsa44);
}
