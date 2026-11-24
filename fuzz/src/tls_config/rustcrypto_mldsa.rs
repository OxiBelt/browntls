//! The RustCrypto provider's ML-DSA key loader
//! (`rustcrypto::sign::any_ml_dsa_type`, the `draft-ietf-tls-mldsa-06`
//! opt-in) against the native provider's, on valid RFC 9881 PKCS #8 keys,
//! their mutations and arbitrary bytes. The loaders agree except on the
//! `expandedKey` form alone, which only the native one loads (the `ml-dsa`
//! crate has no checked decoding of an expanded key). Library tests only.

#![cfg(test)]

use browntls_core::SignatureScheme;
use browntls_core::crypto::{native, rustcrypto};
use browntls_core::pki_types::PrivatePkcs8KeyDer;
use browntls_core::sign::SigningKey;
use browntls_crypto::mldsa::{
    MlDsa44, MlDsa65, MlDsa87, ParameterSet, PrivateKeyFormat, SigningKey as NativeKey,
};

/// The forms both providers load.
const FORMATS: [PrivateKeyFormat; 2] = [PrivateKeyFormat::Seed, PrivateKeyFormat::Both];

fn encode<P: ParameterSet>(seed: u8, format: PrivateKeyFormat) -> Vec<u8> {
    let key = NativeKey::<P>::from_seed(&[seed; 32]);
    let mut der = vec![0; NativeKey::<P>::PKCS8_MAX_LEN];
    let len = key.to_pkcs8_der(format, &mut der).unwrap();
    der.truncate(len);
    der
}

/// Every valid key: three parameter sets in `formats`, with the scheme and
/// the native verification algorithm of its set.
fn valid_keys(
    formats: &[PrivateKeyFormat],
) -> Vec<(
    Vec<u8>,
    SignatureScheme,
    &'static dyn browntls_core::pki_types::SignatureVerificationAlgorithm,
)> {
    let mut keys = Vec::new();
    for &format in formats {
        keys.push((
            encode::<MlDsa44>(1, format),
            SignatureScheme::ML_DSA_44,
            &native::verify::ML_DSA_44 as _,
        ));
        keys.push((
            encode::<MlDsa65>(2, format),
            SignatureScheme::ML_DSA_65,
            &native::verify::ML_DSA_65 as _,
        ));
        keys.push((
            encode::<MlDsa87>(3, format),
            SignatureScheme::ML_DSA_87,
            &native::verify::ML_DSA_87 as _,
        ));
    }
    keys
}

fn spki(key: &dyn SigningKey) -> Vec<u8> {
    key.public_key().unwrap().as_ref().to_vec()
}

/// Both loaders accept `der` with the same public key, or both refuse it.
fn agree(der: &[u8]) -> bool {
    let der = PrivatePkcs8KeyDer::from(der.to_vec());
    let rc = rustcrypto::sign::any_ml_dsa_type(&der);
    let native = native::sign::any_ml_dsa_type(&der);
    assert_eq!(rc.is_ok(), native.is_ok(), "{:02x?}", der.secret_der());
    if let (Ok(rc), Ok(native)) = (&rc, &native) {
        assert_eq!(spki(rc.as_ref()), spki(native.as_ref()));
    }
    rc.is_ok()
}

/// The RustCrypto loader refuses `der` (an `expandedKey`-only key or a
/// change of one) without panicking; returns whether the native one loads
/// it.
fn native_only(der: &[u8]) -> bool {
    let der = PrivatePkcs8KeyDer::from(der.to_vec());
    assert!(
        rustcrypto::sign::any_ml_dsa_type(&der).is_err(),
        "{:02x?}",
        der.secret_der()
    );
    native::sign::any_ml_dsa_type(&der).is_ok()
}

#[test]
fn valid_keys_load_and_sign_like_native() {
    for (der, _, _) in valid_keys(&[PrivateKeyFormat::Expanded]) {
        assert!(native_only(&der));
    }
    for (der, scheme, alg) in valid_keys(&FORMATS) {
        assert!(agree(&der));
        let key = rustcrypto::sign::any_ml_dsa_type(&PrivatePkcs8KeyDer::from(der)).unwrap();
        let spki = spki(key.as_ref());
        let public_key = &spki[spki.len() - alg_public_key_len(scheme)..];
        let signer = key.choose_scheme(&[scheme]).unwrap();
        let signature = signer.sign(b"fuzz").unwrap();
        alg.verify_signature(public_key, b"fuzz", &signature)
            .unwrap();
        assert!(key.choose_scheme(&[SignatureScheme::ED25519]).is_none());
    }
}

fn alg_public_key_len(scheme: SignatureScheme) -> usize {
    match scheme {
        SignatureScheme::ML_DSA_44 => MlDsa44::VERIFYING_KEY_LEN,
        SignatureScheme::ML_DSA_65 => MlDsa65::VERIFYING_KEY_LEN,
        _ => MlDsa87::VERIFYING_KEY_LEN,
    }
}

/// A fixed xorshift sequence (test data).
fn bytes(state: &mut u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as u8
        })
        .collect()
}

#[test]
fn mutated_and_arbitrary_inputs_agree_with_native() {
    let mut state = 0x9e37_79b9_7f4a_7c15;
    for len in [0, 1, 2, 54, 100, 2588, 4962] {
        assert!(!agree(&bytes(&mut state, len)));
    }
    // Truncations, and single-bit changes spread over the encoding (the
    // header, the private key and, for the `both` form, its parts). Those
    // of an `expandedKey`-only key the RustCrypto loader refuses (for the
    // form, or as malformed).
    let keys = valid_keys(&FORMATS).into_iter().map(|k| (k.0, false));
    let expanded = valid_keys(&[PrivateKeyFormat::Expanded]);
    for (der, expanded) in keys.chain(expanded.into_iter().map(|k| (k.0, true))) {
        let check = |der: &[u8]| match expanded {
            true => native_only(der),
            false => agree(der),
        };
        for n in [0, 1, der.len() / 2, der.len() - 1] {
            assert!(!check(&der[..n]));
        }
        let step = (der.len() / 37).max(1);
        for i in (0..der.len()).step_by(step) {
            let mut changed = der.clone();
            changed[i] ^= 1 << (i % 8);
            check(&changed);
            // Arbitrary bytes in place of the tail.
            let mut tail = der[..i].to_vec();
            tail.extend(bytes(&mut state, der.len() - i));
            check(&tail);
        }
    }
}
