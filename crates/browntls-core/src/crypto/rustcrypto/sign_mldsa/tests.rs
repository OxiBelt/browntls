use alloc::vec;

use browntls_pki::AlgorithmIdentifier;
use ml_dsa::{EncodedSignature, Signature, VerifyingKey};

use super::*;
use crate::crypto::rustcrypto::SUPPORTED_SIG_ALGS_WITH_ML_DSA;

const ALL_SCHEMES: [SignatureScheme; 3] = [
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_87,
];

#[derive(Clone, Copy, Debug)]
enum Form {
    Seed,
    Expanded,
    Both,
}

/// The forms this provider loads (`Form::Expanded` is refused).
const FORMS: [Form; 2] = [Form::Seed, Form::Both];

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = crate::x509::asn1_wrap(tag, value);
    // `asn1_wrap` writes a minimal length, as DER requires.
    out.shrink_to_fit();
    out
}

#[allow(deprecated)]
fn expanded_bytes<P: MlDsaParams>(seed: &[u8; 32]) -> Vec<u8> {
    ExpandedSigningKey::<P>::from_seed(&B32::from(*seed))
        .to_expanded()
        .to_vec()
}

/// A version 0 PKCS #8 key of parameter set `P` in `form` (test data).
fn pkcs8<P: MlDsaParams>(alg: AlgorithmIdentifier, seed: &[u8; 32], form: Form) -> Vec<u8> {
    let sk = expanded_bytes::<P>(seed);
    let choice = match form {
        Form::Seed => tlv(0x80, seed),
        Form::Expanded => tlv(0x04, &sk),
        Form::Both => tlv(0x30, &[tlv(0x04, seed), tlv(0x04, &sk)].concat()),
    };
    let body = [
        &[0x02, 0x01, 0x00][..],
        &tlv(0x30, alg.as_ref()),
        &tlv(0x04, &choice),
    ]
    .concat();
    tlv(0x30, &body)
}

fn verifying_key<P: MlDsaParams>(seed: &[u8; 32]) -> VerifyingKey<P> {
    ExpandedSigningKey::<P>::from_seed(&B32::from(*seed)).verifying_key()
}

fn check<P: MlDsaParams>(
    scheme: SignatureScheme,
    alg: &dyn SignatureVerificationAlgorithm,
    name: &str,
) {
    let seed = [0x5a; 32];
    let vk = verifying_key::<P>(&seed);
    let public_key = vk.encode();
    for form in FORMS {
        let der = PrivatePkcs8KeyDer::from(pkcs8::<P>(alg.public_key_alg_id(), &seed, form));
        let loaded = any_ml_dsa_type(&der).unwrap();
        assert_eq!(loaded.algorithm(), NO_TLS12_SIGNATURE_ALGORITHM);

        // The RFC 9881 SubjectPublicKeyInfo of the key.
        let spki = loaded.public_key().unwrap();
        let (alg_id, key) = crate::x509::split_spki(spki.as_ref()).unwrap();
        assert_eq!(alg_id, alg.public_key_alg_id().as_ref());
        assert_eq!(key, public_key.as_slice());

        // Only its own scheme, and only when offered.
        for other in ALL_SCHEMES.into_iter().filter(|s| *s != scheme) {
            assert!(loaded.choose_scheme(&[other]).is_none());
        }
        assert!(
            loaded
                .choose_scheme(&[
                    SignatureScheme::ED25519,
                    SignatureScheme::ECDSA_NISTP256_SHA256
                ])
                .is_none()
        );
        assert!(loaded.choose_scheme(&[]).is_none());
        let signer = loaded
            .choose_scheme(&[SignatureScheme::ED25519, scheme])
            .unwrap();
        assert_eq!(signer.scheme(), scheme);

        // Pure ML-DSA with the empty context, hedged.
        let first = signer.sign(b"message").unwrap();
        let second = signer.sign(b"message").unwrap();
        assert_ne!(first, second);
        for signature in [&first, &second] {
            let encoded = EncodedSignature::<P>::try_from(signature.as_slice()).unwrap();
            let decoded = Signature::<P>::decode(&encoded).unwrap();
            assert!(vk.verify_with_context(b"message", &[], &decoded));
            assert!(!vk.verify_with_context(b"message", b"tls", &decoded));
            assert!(!vk.verify_with_context(b"other", &[], &decoded));
            alg.verify_signature(key, b"message", signature).unwrap();
        }

        // No secret in the debug output.
        let debug = alloc::format!("{loaded:?} {signer:?}");
        assert!(debug.contains(name), "{debug}");
        assert!(debug.len() < 120, "{debug}");

        // The opt-in provider loads it, the default one does not.
        let der = PrivateKeyDer::Pkcs8(der.clone_key());
        assert!(RustCrypto.load_private_key(der.clone_key()).is_err());
        let loaded = KEY_PROVIDER_WITH_ML_DSA.load_private_key(der).unwrap();
        assert_eq!(loaded.public_key().unwrap().as_ref(), spki.as_ref());
    }
}

#[test]
fn keys_load_and_sign_with_their_own_scheme() {
    check::<MlDsa44>(SignatureScheme::ML_DSA_44, &verify::ML_DSA_44, "ML-DSA-44");
    check::<MlDsa65>(SignatureScheme::ML_DSA_65, &verify::ML_DSA_65, "ML-DSA-65");
    check::<MlDsa87>(SignatureScheme::ML_DSA_87, &verify::ML_DSA_87, "ML-DSA-87");
}

/// The `expandedKey` form alone is refused, whatever its contents, without
/// reaching `ml-dsa`'s unchecked decoder (which panics on out-of-range
/// coefficients); the same key as `seed` or `both` loads.
fn expanded_form_refused<P: MlDsaParams>(alg: AlgorithmIdentifier) {
    let seed = [3; 32];
    let sk = expanded_bytes::<P>(&seed);
    let load = |sk: &[u8]| {
        let body = [
            &[0x02, 0x01, 0x00][..],
            &tlv(0x30, alg.as_ref()),
            &tlv(0x04, &tlv(0x04, sk)),
        ]
        .concat();
        any_ml_dsa_type(&PrivatePkcs8KeyDer::from(tlv(0x30, &body)))
    };
    assert!(load(&sk).is_err());
    assert!(load(&vec![0xff; sk.len()]).is_err());
    assert!(load(&sk[1..]).is_err());
    // As the key provider sees it: the ML-DSA error, not the ECDSA one.
    let der = pkcs8::<P>(alg, &seed, Form::Expanded);
    let err = KEY_PROVIDER_WITH_ML_DSA
        .load_private_key(PrivateKeyDer::Pkcs8(der.into()))
        .unwrap_err();
    assert_eq!(err, ml_dsa_error());
    for form in FORMS {
        let der = pkcs8::<P>(alg, &seed, form);
        any_ml_dsa_type(&PrivatePkcs8KeyDer::from(der)).unwrap();
    }
}

fn ml_dsa_error() -> Error {
    any_ml_dsa_type(&PrivatePkcs8KeyDer::from(vec![])).unwrap_err()
}

#[test]
fn the_expanded_form_alone_is_refused() {
    expanded_form_refused::<MlDsa44>(alg_id::ML_DSA_44);
    expanded_form_refused::<MlDsa65>(alg_id::ML_DSA_65);
    expanded_form_refused::<MlDsa87>(alg_id::ML_DSA_87);
}

#[test]
fn both_must_be_consistent_and_public_key_must_match() {
    let seed = [9; 32];
    let alg = alg_id::ML_DSA_65;
    let sk = expanded_bytes::<MlDsa65>(&seed);
    let pk = verifying_key::<MlDsa65>(&seed).encode();
    let build = |version: u8, choice: &[u8], tail: &[u8]| {
        let body = [
            &[0x02, 0x01, version][..],
            &tlv(0x30, alg.as_ref()),
            &tlv(0x04, choice),
            tail,
        ]
        .concat();
        PrivatePkcs8KeyDer::from(tlv(0x30, &body))
    };
    let both = |seed: &[u8], sk: &[u8]| tlv(0x30, &[tlv(0x04, seed), tlv(0x04, sk)].concat());
    any_ml_dsa_type(&build(0, &both(&seed, &sk), &[])).unwrap();
    let other = expanded_bytes::<MlDsa65>(&[8; 32]);
    assert!(any_ml_dsa_type(&build(0, &both(&seed, &other), &[])).is_err());
    assert!(any_ml_dsa_type(&build(0, &both(&sk, &seed), &[])).is_err());
    let mut changed_k = sk.clone();
    changed_k[32] ^= 1;
    assert!(any_ml_dsa_type(&build(0, &both(&seed, &changed_k), &[])).is_err());

    // `publicKey` (version 1 only), whatever the form.
    let field = |pk: &[u8]| tlv(0x81, &[&[0][..], pk].concat());
    let mut wrong = pk.to_vec();
    wrong[100] ^= 1;
    let attributes = tlv(0xa0, &[]);
    for choice in [tlv(0x80, &seed), both(&seed, &sk)] {
        any_ml_dsa_type(&build(1, &choice, &field(&pk))).unwrap();
        any_ml_dsa_type(&build(1, &choice, &[])).unwrap();
        any_ml_dsa_type(&build(0, &choice, &attributes)).unwrap();
        for (version, tail) in [
            (0, field(&pk)),
            (1, field(&wrong)),
            (1, field(&pk[1..])),
            (1, tlv(0x81, &[&[1][..], &pk].concat())),
            (1, [field(&pk), attributes.clone()].concat()),
            (2, Vec::new()),
        ] {
            assert!(any_ml_dsa_type(&build(version, &choice, &tail)).is_err());
        }
    }
}

#[test]
fn opt_in_provider_loads_what_the_default_loads() {
    // An Ed25519 PKCS #8 key (RFC 8410 §10.3).
    let mut ed25519 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    ed25519.extend_from_slice(&[7; 32]);
    let der = || PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ed25519.clone()));
    let default = RustCrypto.load_private_key(der()).unwrap();
    let opt_in = KEY_PROVIDER_WITH_ML_DSA.load_private_key(der()).unwrap();
    assert_eq!(default.algorithm(), opt_in.algorithm());
    assert_eq!(
        default.public_key().unwrap().as_ref(),
        opt_in.public_key().unwrap().as_ref()
    );
}

#[test]
fn garbage_fails_with_the_default_loader_error() {
    for bytes in [&[][..], &[1, 2, 3], &[0x30, 0x00]] {
        let pkcs8 = PrivatePkcs8KeyDer::from(bytes.to_vec());
        assert!(any_ml_dsa_type(&pkcs8).is_err());
        let der = || PrivateKeyDer::Pkcs8(pkcs8.clone_key());
        assert_eq!(
            KEY_PROVIDER_WITH_ML_DSA
                .load_private_key(der())
                .unwrap_err(),
            RustCrypto.load_private_key(der()).unwrap_err()
        );
    }
    // Other encodings are never tried as ML-DSA.
    let der = pkcs8::<MlDsa44>(alg_id::ML_DSA_44, &[1; 32], Form::Seed);
    for key in [
        PrivateKeyDer::Pkcs1(browntls_pki::PrivatePkcs1KeyDer::from(der.clone())),
        PrivateKeyDer::Sec1(browntls_pki::PrivateSec1KeyDer::from(der)),
    ] {
        assert!(KEY_PROVIDER_WITH_ML_DSA.load_private_key(key).is_err());
    }
    // A key of one set under another set's identifier.
    for alg in [alg_id::ML_DSA_65, alg_id::ML_DSA_87] {
        let der = pkcs8::<MlDsa44>(alg, &[1; 32], Form::Both);
        assert!(any_ml_dsa_type(&PrivatePkcs8KeyDer::from(der)).is_err());
    }
}

/// A PKCS #8 key that names ML-DSA and is refused gets the ML-DSA loader's
/// error from the opt-in key provider, as in the native provider; anything
/// else the default loader's.
#[test]
fn a_refused_ml_dsa_key_gets_the_ml_dsa_error() {
    let mut der = pkcs8::<MlDsa65>(alg_id::ML_DSA_65, &[4; 32], Form::Both);
    *der.last_mut().unwrap() ^= 1;
    assert!(names_ml_dsa(&der));
    let key_der = PrivatePkcs8KeyDer::from(der);
    let ml_dsa_err = any_ml_dsa_type(&key_der).unwrap_err();
    let key = || PrivateKeyDer::Pkcs8(key_der.clone_key());
    let default_err = RustCrypto.load_private_key(key()).unwrap_err();
    assert_ne!(ml_dsa_err, default_err);
    assert_eq!(
        KEY_PROVIDER_WITH_ML_DSA
            .load_private_key(key())
            .unwrap_err(),
        ml_dsa_err
    );
    // NULL parameters still name ML-DSA (the OID is what counts).
    let mut with_null = pkcs8::<MlDsa44>(alg_id::ML_DSA_44, &[4; 32], Form::Seed);
    with_null.splice(
        5..18,
        tlv(0x30, &[alg_id::ML_DSA_44.as_ref(), &[0x05, 0x00]].concat()),
    );
    with_null[1] += 2;
    assert!(names_ml_dsa(&with_null));
    assert!(any_ml_dsa_type(&PrivatePkcs8KeyDer::from(with_null)).is_err());
    assert!(!names_ml_dsa(&[]));
    assert!(!names_ml_dsa(&[0x30, 0x00]));
}

/// A random source that always fails.
struct NoRandom;

impl TryRng for NoRandom {
    type Error = RandomFailed;

    fn try_next_u32(&mut self) -> Result<u32, RandomFailed> {
        Err(RandomFailed)
    }

    fn try_next_u64(&mut self) -> Result<u64, RandomFailed> {
        Err(RandomFailed)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RandomFailed> {
        Err(RandomFailed)
    }
}

impl TryCryptoRng for NoRandom {}

#[test]
fn signing_needs_randomness() {
    // The adapter reads the provider's random source.
    let mut rng = OsRandom::new();
    let mut bytes = [0u8; 32];
    rng.try_fill_bytes(&mut bytes).unwrap();
    assert_ne!(bytes, [0; 32]);
    assert_ne!(rng.try_next_u64().unwrap(), rng.try_next_u64().unwrap());
    rng.try_next_u32().unwrap();
    assert!(!rng.failed);
    assert_eq!(
        alloc::format!("{RandomFailed}"),
        "no randomness from the operating system"
    );
    // Without randomness `ml-dsa` fails rather than signing
    // deterministically, so `sign_with` returns an error.
    let key = ExpandedSigningKey::<MlDsa44>::from_seed(&B32::from([1; 32]));
    assert!(key.sign_randomized(b"m", &[], &mut NoRandom).is_err());
    assert!(sign_with(&key, b"m", &mut rng).is_ok());
    // A failure of the random source is reported as such.
    let mut failing = OsRandom {
        fill: |_| Err(GetRandomFailed),
        failed: false,
    };
    assert_eq!(
        sign_with(&key, b"m", &mut failing),
        Err(Error::FailedToGetRandomBytes)
    );
    assert!(failing.failed);
}

#[test]
fn mapping_extends_the_default_mapping() {
    let default = SUPPORTED_SIG_ALGS.supported_schemes();
    let opt_in = SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.supported_schemes();
    assert_eq!(opt_in[..default.len()], default[..]);
    assert_eq!(opt_in[default.len()..], ALL_SCHEMES);
    assert!(ALL_SCHEMES.iter().all(|scheme| !default.contains(scheme)));
    // The certificate path list is the one of the X.509-only opt-in.
    assert!(core::ptr::eq(
        SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.all,
        SUPPORTED_SIG_ALGS_WITH_ML_DSA.all
    ));
    // Each default entry is carried over unchanged.
    for (default, opt_in) in SUPPORTED_SIG_ALGS
        .mapping
        .iter()
        .zip(VERIFICATION_ALG_MAPPING_WITH_ML_DSA)
    {
        assert_eq!(default.0, opt_in.0);
        assert_eq!(default.1.len(), opt_in.1.len());
        for (a, b) in default.1.iter().zip(opt_in.1) {
            assert!(core::ptr::addr_eq(
                *a as *const dyn SignatureVerificationAlgorithm,
                *b as *const dyn SignatureVerificationAlgorithm,
            ));
        }
    }
    // One algorithm per ML-DSA scheme, with the scheme's identifier.
    for ((scheme, algs), expected) in ML_DSA_VERIFICATION_ALG_MAPPING.iter().zip([
        alg_id::ML_DSA_44,
        alg_id::ML_DSA_65,
        alg_id::ML_DSA_87,
    ]) {
        assert!(scheme.is_ml_dsa() && scheme.supported_in_tls13());
        assert_eq!(algs.len(), 1);
        assert_eq!(algs[0].public_key_alg_id(), expected);
        assert_eq!(algs[0].signature_alg_id(), expected);
    }
    assert!(!SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.fips());
}
