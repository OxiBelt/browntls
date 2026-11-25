//! ML-DSA (FIPS 204) signing keys for TLS 1.3 authentication
//! (`draft-ietf-tls-mldsa-06`), and the opt-in key provider and algorithm
//! table that enable it.
//!
//! The key type and loader are re-exported from [`super::sign`], the
//! provider items from [`super`] (the `native` module), which documents what
//! opting in means.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug};

use browntls_crypto::mldsa::{self, MlDsa44, MlDsa65, MlDsa87, ParameterSet};
use browntls_crypto::rand::OsRng;
use browntls_pki::{
    PrivateKeyDer, PrivatePkcs8KeyDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer,
};

use super::verify_mldsa::ALL_VERIFICATION_ALGS_WITH_ML_DSA;
use super::{VERIFICATION_ALG_MAPPING, sign, verify};
use crate::crypto::KeyProvider;
use crate::crypto::signer::{NO_TLS12_SIGNATURE_ALGORITHM, Signer, SigningKey};
use crate::crypto::verify_list::concat;
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::Error;
use crate::sync::Arc;
use crate::webpki::WebPkiSupportedAlgorithms;

/// A key of one parameter set.
#[derive(Clone)]
enum Key {
    MlDsa44(Arc<mldsa::SigningKey<MlDsa44>>),
    MlDsa65(Arc<mldsa::SigningKey<MlDsa65>>),
    MlDsa87(Arc<mldsa::SigningKey<MlDsa87>>),
}

impl Key {
    fn scheme(&self) -> SignatureScheme {
        match self {
            Self::MlDsa44(_) => SignatureScheme::ML_DSA_44,
            Self::MlDsa65(_) => SignatureScheme::ML_DSA_65,
            Self::MlDsa87(_) => SignatureScheme::ML_DSA_87,
        }
    }

    fn parameter_set(&self) -> &'static str {
        match self {
            Self::MlDsa44(_) => MlDsa44::NAME,
            Self::MlDsa65(_) => MlDsa65::NAME,
            Self::MlDsa87(_) => MlDsa87::NAME,
        }
    }
}

/// The RFC 9881 §4 `SubjectPublicKeyInfo` of `key`.
fn spki<P: ParameterSet>(key: &mldsa::SigningKey<P>) -> SubjectPublicKeyInfoDer<'static> {
    let mut der = vec![0; mldsa::VerifyingKey::<P>::SPKI_LEN];
    let written = key.verifying_key().to_spki_der(&mut der);
    debug_assert_eq!(written, Ok(der.len()));
    SubjectPublicKeyInfoDer::from(der)
}

/// Hedged pure ML-DSA with the empty context string.
fn sign_with<P: ParameterSet>(
    key: &mldsa::SigningKey<P>,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    key.sign(message, b"", &OsRng)
        .map(|signature| signature.as_ref().to_vec())
        .map_err(|err| match err {
            browntls_crypto::Error::RandomFailure => Error::FailedToGetRandomBytes,
            _ => Error::general("ML-DSA signing failed"),
        })
}

/// An ML-DSA-44, ML-DSA-65 or ML-DSA-87 signing key for TLS 1.3
/// (`draft-ietf-tls-mldsa-06`, an Internet-Draft: experimental).
///
/// It signs only with the scheme of its parameter set (`mldsa44`,
/// `mldsa65` or `mldsa87`, code points 0x0904 to 0x0906), and only when the
/// peer offered that scheme: pure ML-DSA (FIPS 204 Algorithm 2,
/// ML-DSA.Sign) with the empty context string, as §3.2 of the draft
/// requires. Signing is hedged with 32 fresh random bytes from the
/// operating system; without them it fails with
/// [`Error::FailedToGetRandomBytes`] (there is no deterministic fallback).
/// HashML-DSA is not supported.
///
/// These schemes exist in TLS 1.3 only. [`SigningKey::algorithm`] is a
/// value outside the TLS 1.2 `SignatureAlgorithm` registry's assignments,
/// so a server holding only this key completes no TLS 1.2 handshake and a
/// client does not answer a TLS 1.2 CertificateRequest with it. The key is
/// not usable with delegated credentials (RFC 9345) or exported
/// authenticators (RFC 9261), which no specification defines for ML-DSA.
///
/// [`SigningKey::public_key`] is the RFC 9881 §4 `SubjectPublicKeyInfo`
/// (`id-ml-dsa-*` with absent parameters), so the key is matched against
/// its certificate like any other.
///
/// Signing needs about 42, 66 and 102 KiB of stack for ML-DSA-44, -65 and
/// -87 (a release build on x86-64, unoptimised builds need more; see
/// `browntls_crypto::mldsa`), on the thread that drives the handshake. The
/// private key is zeroised on drop.
///
/// Load one with [`any_ml_dsa_type`]; [`KEY_PROVIDER`](super::KEY_PROVIDER)
/// does not load ML-DSA keys,
/// [`KEY_PROVIDER_WITH_ML_DSA`](super::KEY_PROVIDER_WITH_ML_DSA) does.
pub struct MlDsaSigningKey {
    key: Key,
    spki: SubjectPublicKeyInfoDer<'static>,
}

impl SigningKey for MlDsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&self.key.scheme()).then(|| {
            Box::new(MlDsaSigner {
                key: self.key.clone(),
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from_slice(self.spki.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        NO_TLS12_SIGNATURE_ALGORITHM
    }
}

impl Debug for MlDsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSigningKey")
            .field("parameter_set", &self.key.parameter_set())
            .finish_non_exhaustive()
    }
}

struct MlDsaSigner {
    key: Key,
}

impl Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.key {
            Key::MlDsa44(key) => sign_with(key, message),
            Key::MlDsa65(key) => sign_with(key, message),
            Key::MlDsa87(key) => sign_with(key, message),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.key.scheme()
    }
}

impl Debug for MlDsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSigner")
            .field("parameter_set", &self.key.parameter_set())
            .finish_non_exhaustive()
    }
}

/// Loads an ML-DSA-44, ML-DSA-65 or ML-DSA-87 private key from an RFC 9881
/// §6 PKCS #8 `OneAsymmetricKey` in strict DER, in any of the `seed`,
/// `expandedKey` and `both` forms (see
/// `browntls_crypto::mldsa::SigningKey::from_pkcs8_der` for the checks,
/// including the §8.2 consistency check of the `both` form).
///
/// The key signs TLS 1.3 handshakes as [`MlDsaSigningKey`] describes
/// (`draft-ietf-tls-mldsa-06`, experimental).
/// [`any_supported_type`](sign::any_supported_type) does not call this.
///
/// Every failure is one generic error.
pub fn any_ml_dsa_type(der: &PrivatePkcs8KeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    let der = der.secret_der();
    let (key, spki) = if let Ok(key) = mldsa::SigningKey::<MlDsa44>::from_pkcs8_der(der) {
        let spki = spki(&key);
        (Key::MlDsa44(Arc::new(key)), spki)
    } else if let Ok(key) = mldsa::SigningKey::<MlDsa65>::from_pkcs8_der(der) {
        let spki = spki(&key);
        (Key::MlDsa65(Arc::new(key)), spki)
    } else if let Ok(key) = mldsa::SigningKey::<MlDsa87>::from_pkcs8_der(der) {
        let spki = spki(&key);
        (Key::MlDsa87(Arc::new(key)), spki)
    } else {
        return Err(Error::general(
            "failed to parse PKCS#8 private key as ML-DSA",
        ));
    };
    Ok(Arc::new(MlDsaSigningKey { key, spki }))
}

/// The key loader of [`KEY_PROVIDER_WITH_ML_DSA`].
#[derive(Debug)]
pub struct NativeWithMlDsa;

/// [`KEY_PROVIDER`](super::KEY_PROVIDER) that also loads ML-DSA-44, -65 and
/// -87 private keys (RFC 9881 PKCS #8) for TLS 1.3 authentication: an
/// explicit opt-in to `draft-ietf-tls-mldsa-06`, an Internet-Draft, not a
/// published RFC. See [`MlDsaSigningKey`] for what such a key does, and the
/// [module documentation](super#ml-dsa-in-tls-13-opt-in-experimental) for
/// the whole opt-in.
///
/// A key is first loaded as [`KEY_PROVIDER`](super::KEY_PROVIDER) loads it
/// ([`sign::any_supported_type`]); a PKCS #8 key that fails there is tried
/// as ML-DSA ([`any_ml_dsa_type`]). When both fail, a key whose
/// `privateKeyAlgorithm` names an ML-DSA parameter set gets the ML-DSA
/// loader's error (so that, for instance, an inconsistent `both` key is
/// not reported as a malformed ECDSA key), and any other key the first
/// error.
pub static KEY_PROVIDER_WITH_ML_DSA: &dyn KeyProvider = &NativeWithMlDsa;

impl KeyProvider for NativeWithMlDsa {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der).or_else(|err| match &key_der {
            PrivateKeyDer::Pkcs8(pkcs8) => any_ml_dsa_type(pkcs8).map_err(|ml_dsa_err| {
                if names_ml_dsa(pkcs8.secret_der()) {
                    ml_dsa_err
                } else {
                    err
                }
            }),
            _ => Err(err),
        })
    }
}

/// Whether the `privateKeyAlgorithm` of the PKCS #8 key `der` begins with an
/// `id-ml-dsa-*` object identifier (RFC 9881 §2). Only the choice of error
/// message depends on it.
fn names_ml_dsa(der: &[u8]) -> bool {
    const TAG_OID: u8 = 0x06;
    crate::x509::pkcs8_algorithm_identifier(der).is_some_and(|algorithm| {
        [MlDsa44::OID, MlDsa65::OID, MlDsa87::OID]
            .into_iter()
            .any(|oid| match algorithm {
                [TAG_OID, len, rest @ ..] => {
                    usize::from(*len) == oid.len() && rest.starts_with(oid)
                }
                _ => false,
            })
    })
}

/// The TLS 1.3 signature schemes of `draft-ietf-tls-mldsa-06` and the
/// algorithm that verifies each: `mldsa44`, `mldsa65`, `mldsa87` (0x0904,
/// 0x0905, 0x0906), in that order. Each scheme maps to the one algorithm of
/// its parameter set, whose key identifier is the matching `id-ml-dsa-*`,
/// so a signature under a scheme verifies only with a key of that
/// parameter set (§3.2 of the draft).
#[allow(clippy::type_complexity)]
pub static ML_DSA_VERIFICATION_ALG_MAPPING: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &[
    (SignatureScheme::ML_DSA_44, &[&verify::ML_DSA_44]),
    (SignatureScheme::ML_DSA_65, &[&verify::ML_DSA_65]),
    (SignatureScheme::ML_DSA_87, &[&verify::ML_DSA_87]),
];

#[allow(clippy::type_complexity)]
static MAPPING_WITH_ML_DSA: [(SignatureScheme, &[&dyn SignatureVerificationAlgorithm]);
    VERIFICATION_ALG_MAPPING.len() + ML_DSA_VERIFICATION_ALG_MAPPING.len()] =
    concat(VERIFICATION_ALG_MAPPING, ML_DSA_VERIFICATION_ALG_MAPPING);

/// [`VERIFICATION_ALG_MAPPING`] followed by
/// [`ML_DSA_VERIFICATION_ALG_MAPPING`]: the TLS scheme mapping of
/// [`SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13`], computed at compile time so
/// that every default scheme stays ahead of the ML-DSA ones, in the
/// default order.
#[allow(clippy::type_complexity)]
pub static VERIFICATION_ALG_MAPPING_WITH_ML_DSA: &[(
    SignatureScheme,
    &[&dyn SignatureVerificationAlgorithm],
)] = &MAPPING_WITH_ML_DSA;

/// [`SUPPORTED_SIG_ALGS`](super::SUPPORTED_SIG_ALGS) with ML-DSA for
/// certificate paths (RFC 9881) and for TLS 1.3 handshake signatures
/// (`draft-ietf-tls-mldsa-06`): `all` is
/// [`ALL_VERIFICATION_ALGS_WITH_ML_DSA`], `mapping` is
/// [`VERIFICATION_ALG_MAPPING_WITH_ML_DSA`].
///
/// This is an explicit, experimental opt-in: the draft is not a published
/// RFC (its code points are registered with "Recommended: N"), and the
/// provider's defaults do not include ML-DSA. On top of what
/// [`SUPPORTED_SIG_ALGS_WITH_ML_DSA`](super::SUPPORTED_SIG_ALGS_WITH_ML_DSA)
/// does for X.509 validation, a provider or verifier using this table:
///
/// * offers `mldsa44`, `mldsa65` and `mldsa87` after its other schemes in
///   the `signature_algorithms` of a ClientHello that offers TLS 1.3 and
///   of a TLS 1.3 CertificateRequest, which every peer and observer of
///   the handshake start can see;
/// * accepts a TLS 1.3 `CertificateVerify` signed with one of them, from a
///   peer whose end-entity key is an ML-DSA key of the same parameter set
///   (pure ML-DSA, empty context string).
///
/// TLS 1.2 handshake signatures are unaffected: these schemes are never
/// listed in a ClientHello that offers TLS 1.2 alone or in a TLS 1.2
/// CertificateRequest, and never accepted in a TLS 1.2 `ServerKeyExchange`
/// or `CertificateVerify`. (Certificate path signatures are another
/// matter: as with `SUPPORTED_SIG_ALGS_WITH_ML_DSA`, ML-DSA-signed
/// certificates validate in every protocol version.) Delegated credentials
/// (RFC 9345) and exported authenticators (RFC 9261) never use them.
/// Signing with an ML-DSA key is a separate choice:
/// [`KEY_PROVIDER_WITH_ML_DSA`].
pub static SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: ALL_VERIFICATION_ALGS_WITH_ML_DSA,
        mapping: VERIFICATION_ALG_MAPPING_WITH_ML_DSA,
    };

#[cfg(test)]
mod tests {
    use browntls_crypto::mldsa::PrivateKeyFormat;

    use super::*;
    use crate::crypto::native::{KEY_PROVIDER, SUPPORTED_SIG_ALGS, SUPPORTED_SIG_ALGS_WITH_ML_DSA};

    const ALL_SCHEMES: [SignatureScheme; 3] = [
        SignatureScheme::ML_DSA_44,
        SignatureScheme::ML_DSA_65,
        SignatureScheme::ML_DSA_87,
    ];

    /// A PKCS #8 key of parameter set `P` from a fixed seed (test data).
    fn pkcs8<P: ParameterSet>(format: PrivateKeyFormat) -> (mldsa::SigningKey<P>, Vec<u8>) {
        let key = mldsa::SigningKey::<P>::from_seed(&[0x5a; 32]);
        let mut der = vec![0; mldsa::SigningKey::<P>::PKCS8_MAX_LEN];
        let len = key.to_pkcs8_der(format, &mut der).unwrap();
        der.truncate(len);
        (key, der)
    }

    fn check<P: ParameterSet>(scheme: SignatureScheme, alg: &dyn SignatureVerificationAlgorithm) {
        for format in [
            PrivateKeyFormat::Seed,
            PrivateKeyFormat::Expanded,
            PrivateKeyFormat::Both,
        ] {
            let (key, der) = pkcs8::<P>(format);
            let der = PrivatePkcs8KeyDer::from(der);
            let loaded = any_ml_dsa_type(&der).unwrap();
            assert_eq!(loaded.algorithm(), NO_TLS12_SIGNATURE_ALGORITHM);

            // The RFC 9881 SubjectPublicKeyInfo of the key.
            let spki = loaded.public_key().unwrap();
            let (alg_id, public_key) = crate::x509::split_spki(spki.as_ref()).unwrap();
            assert_eq!(alg_id, alg.public_key_alg_id().as_ref());
            assert_eq!(public_key, key.verifying_key().as_bytes());

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
            assert_eq!(first.len(), P::SIGNATURE_LEN);
            assert_ne!(first, second);
            for signature in [&first, &second] {
                key.verifying_key().verify(b"message", signature).unwrap();
                alg.verify_signature(public_key, b"message", signature)
                    .unwrap();
                assert!(
                    key.verifying_key()
                        .verify_with_context(b"message", b"tls", signature)
                        .is_err()
                );
            }
            assert!(key.verifying_key().verify(b"other", &first).is_err());

            // No secret in the debug output.
            let debug = alloc::format!("{loaded:?} {signer:?}");
            assert!(debug.contains(P::NAME), "{debug}");
            assert!(debug.len() < 120, "{debug}");

            // The opt-in provider loads it, the default one does not.
            let der = PrivateKeyDer::Pkcs8(der.clone_key());
            assert!(KEY_PROVIDER.load_private_key(der.clone_key()).is_err());
            let loaded = KEY_PROVIDER_WITH_ML_DSA.load_private_key(der).unwrap();
            assert_eq!(loaded.public_key().unwrap().as_ref(), spki.as_ref());
        }
    }

    #[test]
    fn keys_load_and_sign_with_their_own_scheme() {
        check::<MlDsa44>(SignatureScheme::ML_DSA_44, &verify::ML_DSA_44);
        check::<MlDsa65>(SignatureScheme::ML_DSA_65, &verify::ML_DSA_65);
        check::<MlDsa87>(SignatureScheme::ML_DSA_87, &verify::ML_DSA_87);
    }

    #[test]
    fn opt_in_provider_loads_what_the_default_loads() {
        let ed25519 =
            browntls_crypto::curve25519::ed25519::SigningKey::from_seed(&[7; 32]).to_pkcs8_der();
        let der = || PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ed25519.to_vec()));
        let default = KEY_PROVIDER.load_private_key(der()).unwrap();
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
                KEY_PROVIDER.load_private_key(der()).unwrap_err()
            );
        }
        // Other encodings are never tried as ML-DSA.
        let (_, der) = pkcs8::<MlDsa44>(PrivateKeyFormat::Seed);
        for key in [
            PrivateKeyDer::Pkcs1(browntls_pki::PrivatePkcs1KeyDer::from(der.clone())),
            PrivateKeyDer::Sec1(browntls_pki::PrivateSec1KeyDer::from(der)),
        ] {
            assert!(KEY_PROVIDER_WITH_ML_DSA.load_private_key(key).is_err());
        }
    }

    /// A PKCS #8 key that names ML-DSA and is refused (here a `both` key
    /// whose expanded key is not the one its seed derives, RFC 9881 §8.2)
    /// is reported as an ML-DSA key, not as a malformed classical one.
    #[test]
    fn a_refused_ml_dsa_key_gets_the_ml_dsa_error() {
        fn check<P: ParameterSet>() {
            let (_, mut der) = pkcs8::<P>(PrivateKeyFormat::Both);
            assert!(names_ml_dsa(&der));
            *der.last_mut().unwrap() ^= 1;
            assert!(names_ml_dsa(&der));
            let pkcs8 = PrivatePkcs8KeyDer::from(der);
            let ml_dsa_err = any_ml_dsa_type(&pkcs8).unwrap_err();
            let der = || PrivateKeyDer::Pkcs8(pkcs8.clone_key());
            let default_err = KEY_PROVIDER.load_private_key(der()).unwrap_err();
            assert_ne!(ml_dsa_err, default_err);
            assert_eq!(
                KEY_PROVIDER_WITH_ML_DSA
                    .load_private_key(der())
                    .unwrap_err(),
                ml_dsa_err
            );
        }
        check::<MlDsa44>();
        check::<MlDsa65>();
        check::<MlDsa87>();
        // A classical key names no ML-DSA parameter set.
        let ed25519 = browntls_crypto::curve25519::ed25519::SigningKey::from_seed(&[7; 32]);
        assert!(!names_ml_dsa(ed25519.to_pkcs8_der().as_ref()));
        assert!(!names_ml_dsa(&[]));
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
        for (default, opt_in) in VERIFICATION_ALG_MAPPING
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
            browntls_pki::alg_id::ML_DSA_44,
            browntls_pki::alg_id::ML_DSA_65,
            browntls_pki::alg_id::ML_DSA_87,
        ]) {
            assert!(scheme.is_ml_dsa() && scheme.supported_in_tls13());
            assert_eq!(algs.len(), 1);
            assert_eq!(algs[0].public_key_alg_id(), expected);
            assert_eq!(algs[0].signature_alg_id(), expected);
        }
        assert!(!SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13.fips());
    }
}
