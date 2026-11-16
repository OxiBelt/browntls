//! Signing keys of both providers, `CertifiedKey`, and the handshake
//! signature verification functions.

use std::sync::Arc;

use browntls::crypto::{
    WebPkiSupportedAlgorithms, native, rustcrypto, verify_tls12_signature,
    verify_tls12_signature_with_raw_key, verify_tls13_signature,
    verify_tls13_signature_with_raw_key,
};
use browntls::delegated_credential::{Credential, DelegatedCredential};
use browntls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    RawPublicKeyEntity, SubjectPublicKeyInfoDer, alg_id,
};
use browntls::sign::{CertifiedKey, SigningKey, public_key_to_spki};
use browntls::{
    DigitallySignedStruct, Error, InconsistentKeys, Side, SignatureAlgorithm, SignatureScheme,
};

use super::crypto::offered_schemes;
use super::fixtures::{
    self, ED448, ED25519, MISMATCHED, P256, P256_SEC1, P384, P521, RSA, RSA_PKCS1, RSA_PSS,
};
use super::{KNOWN_SCHEMES, provider};
use crate::input::Input;

/// The schemes key `k` can sign with.
pub(crate) fn key_schemes(k: usize) -> &'static [SignatureScheme] {
    match k {
        P256 | P256_SEC1 | MISMATCHED => &[SignatureScheme::ECDSA_NISTP256_SHA256],
        P384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
        P521 => &[SignatureScheme::ECDSA_NISTP521_SHA512],
        ED25519 => &[SignatureScheme::ED25519],
        ED448 => &[SignatureScheme::ED448],
        RSA | RSA_PKCS1 => &[
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ],
        RSA_PSS => &[SignatureScheme::RSA_PSS_PSS_SHA256],
        _ => unreachable!(),
    }
}

fn key_algorithm(k: usize) -> SignatureAlgorithm {
    match k {
        P256 | P256_SEC1 | MISMATCHED | P384 | P521 => SignatureAlgorithm::ECDSA,
        ED25519 => SignatureAlgorithm::ED25519,
        ED448 => SignatureAlgorithm::ED448,
        _ => SignatureAlgorithm::RSA,
    }
}

/// Which certificate key `k` is the key of (keys sharing a certificate
/// share an identity).
pub(super) fn key_identity(k: usize) -> usize {
    match k {
        P256_SEC1 => P256,
        RSA_PKCS1 => RSA,
        other => other,
    }
}

/// Which key the certificate of `fixtures().keys[j].chain` is for.
pub(super) fn chain_identity(j: usize) -> Option<usize> {
    match j {
        P256 | P256_SEC1 | MISMATCHED => Some(P256),
        RSA | RSA_PKCS1 => Some(RSA),
        P384 | ED25519 => Some(j),
        _ => None,
    }
}

/// Whether provider `p` can load key `k`.
pub(super) fn loadable(p: usize, k: usize) -> bool {
    p == 0 || fixtures::get().keys[k].rustcrypto
}

/// RFC 8446 §4.2.3: no SHA-1/SHA-224/MD5, no PKCS #1 v1.5, no DSA.
pub(super) fn tls13_scheme(scheme: SignatureScheme) -> bool {
    let [hash, sign] = u16::from(scheme).to_be_bytes();
    hash > 3 && sign > 2
}

fn algs(p: usize) -> WebPkiSupportedAlgorithms {
    provider(p).signature_verification_algorithms
}

/// Loads key `k` with provider `p` through the provider and through the
/// provider's public loader functions, which must agree.
pub(super) fn load(p: usize, k: usize) -> Option<Arc<dyn SigningKey>> {
    let key = &fixtures::get().keys[k];
    let der = key.der();
    let loaded = provider(p).key_provider.load_private_key(key.der());
    assert_eq!(
        loaded.is_ok(),
        loadable(p, k),
        "{} with provider {p}",
        key.name
    );
    let ecdsa = matches!(key_algorithm(k), SignatureAlgorithm::ECDSA);
    let eddsa = matches!(k, ED25519 | ED448);
    let rsa = key_algorithm(k) == SignatureAlgorithm::RSA;
    if p == 0 {
        assert!(
            native::sign::any_supported_type(&der).is_ok(),
            "{}",
            key.name
        );
        assert_eq!(
            native::sign::any_ecdsa_type(&der).is_ok(),
            ecdsa,
            "{}",
            key.name
        );
        assert_eq!(
            native::sign::any_rsa_type(&der).is_ok(),
            rsa,
            "{}",
            key.name
        );
        if let PrivateKeyDer::Pkcs8(pkcs8) = &der {
            assert_eq!(
                native::sign::any_eddsa_type(pkcs8).is_ok(),
                eddsa,
                "{}",
                key.name
            );
        }
    } else {
        assert_eq!(
            rustcrypto::sign::any_supported_type(&der).is_ok(),
            key.rustcrypto
        );
        assert_eq!(
            rustcrypto::sign::any_ecdsa_type(&der).is_ok(),
            ecdsa,
            "{}",
            key.name
        );
        if let PrivateKeyDer::Pkcs8(pkcs8) = &der {
            assert_eq!(
                rustcrypto::sign::any_eddsa_type(pkcs8).is_ok(),
                k == ED25519,
                "{}",
                key.name
            );
        }
    }
    let loaded = loaded.ok()?;
    assert_eq!(loaded.algorithm(), key_algorithm(k));
    Some(loaded)
}

/// Fuzzed private key encodings for every loader.
pub(super) fn fuzzed_key(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let mut bytes = if input.bool() {
        let key = &fx.keys[input.choose(fx.keys.len())];
        key.der().secret_der().to_vec()
    } else {
        Vec::new()
    };
    if bytes.is_empty() {
        bytes = input.field().to_vec();
    } else {
        // Corrupt one byte of a genuine key.
        let at = usize::from(input.u16()) % bytes.len();
        bytes[at] ^= input.byte() | 1;
    }
    let der = match input.choose(3) {
        0 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(bytes)),
        1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(bytes)),
        _ => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes)),
    };
    let _ = native::sign::any_supported_type(&der);
    let _ = native::sign::any_ecdsa_type(&der);
    let _ = native::sign::any_rsa_type(&der);
    let _ = rustcrypto::sign::any_supported_type(&der);
    let _ = rustcrypto::sign::any_ecdsa_type(&der);
    if let PrivateKeyDer::Pkcs8(pkcs8) = &der {
        let _ = native::sign::any_eddsa_type(pkcs8);
        let _ = rustcrypto::sign::any_eddsa_type(pkcs8);
    }
    for p in 0..2 {
        if let Ok(key) = provider(p).key_provider.load_private_key(der.clone_key())
            && let Some(signer) = key.choose_scheme(KNOWN_SCHEMES)
        {
            // Whatever loaded must sign verifiably.
            let sig = signer.sign(b"fuzzed key").expect("signing");
            let spki = key.public_key().expect("public key");
            let dss = DigitallySignedStruct::new(signer.scheme(), sig);
            assert!(
                verify_tls12_signature_with_raw_key(b"fuzzed key", &spki, &dss, &algs(0)).is_ok(),
                "{:?}",
                signer.scheme()
            );
        }
    }
}

/// One key, one provider, one message: scheme selection, then the signature
/// must verify with every provider supporting the scheme (raw key and
/// certificate), and must not verify once tampered.
pub(super) fn sign_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let k = input.choose(fx.keys.len());
    let p = input.choose(2);
    let key = &fx.keys[k];
    let Some(signing) = load(p, k) else { return };
    let spki = signing.public_key().expect("public key").as_ref().to_vec();
    if key.rustcrypto {
        // Both providers derive the same SubjectPublicKeyInfo.
        let other = load(1 - p, k).expect("loadable by both");
        assert_eq!(other.public_key().expect("public key").as_ref(), spki);
    }
    let spki = SubjectPublicKeyInfoDer::from(spki);
    check_spki_builder(k, &spki);

    let mut offered = offered_schemes(input);
    if input.bool() {
        offered.extend_from_slice(key_schemes(k));
    }
    let signer = signing.choose_scheme(&offered);
    assert_eq!(
        signer.is_some(),
        key_schemes(k).iter().any(|s| offered.contains(s)),
        "{}: {offered:?}",
        key.name
    );
    let Some(signer) = signer else { return };
    let scheme = signer.scheme();
    assert!(offered.contains(&scheme) && key_schemes(k).contains(&scheme));

    let msg = input.field();
    let sig = signer.sign(msg).expect("signing");
    let dss = DigitallySignedStruct::new(scheme, sig.clone());
    assert_eq!(dss.signature(), sig);
    let cert = key.chain.first().filter(|_| k != MISMATCHED);

    // Every provider verifies through the raw key with the TLS 1.2 rules,
    // and through one more path chosen by the input (raw key under the
    // TLS 1.3 rules, the certificate under either).
    let path = input.choose(3);
    for q in 0..2 {
        let algs = algs(q);
        let supported = algs.supported_schemes().contains(&scheme);
        let tls13 = supported && tls13_scheme(scheme);
        let ctx = format!("{} {scheme:?} signed by {p}, verified by {q}", key.name);
        assert_eq!(
            verify_tls12_signature_with_raw_key(msg, &spki, &dss, &algs).is_ok(),
            supported,
            "{ctx}"
        );
        match (path, cert) {
            (1, Some(cert)) => assert_eq!(
                verify_tls12_signature(msg, cert, &dss, &algs).is_ok(),
                supported,
                "{ctx}"
            ),
            (2, Some(cert)) => assert_eq!(
                verify_tls13_signature(msg, cert, &dss, &algs).is_ok(),
                tls13,
                "{ctx}"
            ),
            _ => assert_eq!(
                verify_tls13_signature_with_raw_key(msg, &spki, &dss, &algs).is_ok(),
                tls13,
                "{ctx}"
            ),
        }
        if !supported {
            continue;
        }
        // Tampered signature and message.
        let mut bad = sig.clone();
        let at = usize::from(input.u16()) % bad.len();
        bad[at] ^= 1 << input.choose(8);
        let bad = DigitallySignedStruct::new(scheme, bad);
        assert!(
            verify_tls12_signature_with_raw_key(msg, &spki, &bad, &algs).is_err(),
            "{ctx}: tampered signature"
        );
        let longer = [msg, b"!"].concat();
        assert!(
            verify_tls12_signature_with_raw_key(&longer, &spki, &dss, &algs).is_err(),
            "{ctx}: other message"
        );
    }

    // Ed25519 is deterministic: both providers agree.
    if k == ED25519 {
        let other = load(1 - p, k).expect("both load Ed25519");
        let other = other.choose_scheme(&[scheme]).expect("Ed25519");
        assert_eq!(other.sign(msg).expect("signing"), sig);
    }
}

/// `public_key_to_spki` rebuilds the key's own SubjectPublicKeyInfo from
/// the bare public key.
fn check_spki_builder(k: usize, spki: &SubjectPublicKeyInfoDer<'_>) {
    let (alg, len) = match k {
        P256 | P256_SEC1 | MISMATCHED => (alg_id::ECDSA_P256, 65),
        P384 => (alg_id::ECDSA_P384, 97),
        P521 => (alg_id::ECDSA_P521, 133),
        ED25519 => (alg_id::ED25519, 32),
        ED448 => (alg_id::ED448, 57),
        _ => return,
    };
    let raw = &spki.as_ref()[spki.as_ref().len() - len..];
    assert_eq!(public_key_to_spki(&alg, raw).as_ref(), spki.as_ref());
}

/// `public_key_to_spki` with fuzzed contents: always well-formed DER.
pub(super) fn spki_op(input: &mut Input<'_>) {
    let alg = *input.pick(&[
        alg_id::ECDSA_P256,
        alg_id::ECDSA_P384,
        alg_id::ECDSA_P521,
        alg_id::ED25519,
        alg_id::ED448,
        alg_id::RSA_ENCRYPTION,
        alg_id::RSA_PSS_SHA256,
    ]);
    let key = input.field();
    let spki = public_key_to_spki(&alg, key);
    assert!(
        RawPublicKeyEntity::try_from(&spki).is_ok(),
        "malformed SPKI for a {}-byte key",
        key.len()
    );
    let scheme = SignatureScheme::from(input.u16());
    let dss = DigitallySignedStruct::new(scheme, input.field().to_vec());
    for p in 0..2 {
        let algs = algs(p);
        let _ = verify_tls12_signature_with_raw_key(b"m", &spki, &dss, &algs);
        let _ = verify_tls13_signature_with_raw_key(b"m", &spki, &dss, &algs);
    }
    // A fuzzed certificate in place of a genuine one.
    let cert = CertificateDer::from(input.field());
    for p in 0..2 {
        let algs = algs(p);
        let _ = verify_tls12_signature(b"m", &cert, &dss, &algs);
        let _ = verify_tls13_signature(b"m", &cert, &dss, &algs);
    }
}

/// `CertifiedKey` from DER and from parts, key/certificate consistency,
/// and delegated credentials.
pub(super) fn certified_op(input: &mut Input<'_>) {
    let fx = fixtures::get();
    let k = input.choose(fx.keys.len());
    let j = input.choose(fx.keys.len());
    let p = input.choose(2);
    let chain = fx.keys[j].chain.clone();
    let matches = chain_identity(j) == Some(key_identity(k));
    let expected = loadable(p, k) && matches;
    let ctx = format!("key {} with chain of {}", fx.keys[k].name, fx.keys[j].name);
    match CertifiedKey::from_der(chain.clone(), fx.keys[k].der(), &provider(p)) {
        Ok(ck) => {
            assert!(expected, "{ctx}");
            assert!(ck.keys_match().is_ok());
        }
        Err(e) => {
            assert!(!expected, "{ctx}: {e:?}");
            if loadable(p, k) && !chain.is_empty() {
                assert_eq!(
                    e,
                    Error::InconsistentKeys(InconsistentKeys::KeyMismatch),
                    "{ctx}"
                );
            }
        }
    }

    let Some(signing) = load(p, k) else { return };
    let mut ck = CertifiedKey::new(chain.clone(), signing);
    assert_eq!(ck.end_entity_cert().is_ok(), !chain.is_empty());
    assert_eq!(ck.keys_match().is_ok(), matches, "{ctx}");
    assert!(ck.delegated_credentials().is_empty());
    if input.bool() {
        ck.ocsp = Some(input.short_field().to_vec());
    }

    // A delegated credential for a delegation certificate (P-256 and
    // Ed25519 chains) with a genuine or fuzzed credential key.
    let d = *input.pick(&[P256, P384, ED25519, P521, ED448, RSA_PSS]);
    let Some(dc_key) = load(p, d) else { return };
    let dc_spki = dc_key.public_key().expect("public key").into_owned();
    let genuine = input.bool();
    let credential = Credential {
        valid_time: input.u32(),
        dc_cert_verify_algorithm: if genuine {
            key_schemes(d)[0]
        } else {
            SignatureScheme::from(input.u16())
        },
        public_key: if genuine {
            dc_spki
        } else {
            SubjectPublicKeyInfoDer::from(input.short_field().to_vec())
        },
    };
    let side = if input.bool() {
        Side::Client
    } else {
        Side::Server
    };
    let Ok(cert) = ck.end_entity_cert().map(|c| c.clone().into_owned()) else {
        return;
    };
    let delegation = matches!(chain_identity(j), Some(P256 | ED25519));
    let issued = DelegatedCredential::issue(side, &cert, &*ck.key, KNOWN_SCHEMES, credential);
    let dc = match issued {
        Ok(dc) => dc,
        Err(_) => {
            assert!(!(genuine && delegation && matches), "{ctx}: issue failed");
            return;
        }
    };
    match ck.with_delegated_credential(dc, dc_key) {
        Ok(ck) => {
            assert!(delegation);
            assert_eq!(ck.delegated_credentials().len(), 1);
        }
        Err(e) => assert!(!(genuine && delegation), "{ctx}: {e:?}"),
    }
}
