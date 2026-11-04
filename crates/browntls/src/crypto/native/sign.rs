//! Signing keys: ECDSA (P-256, P-384, P-521), Ed25519, Ed448 and RSA
//! (PKCS #1 v1.5 and PSS), loaded from PKCS #8, SEC 1 or PKCS #1 DER.
//!
//! An RSA key's PKCS #8 algorithm decides its TLS schemes (RFC 9846
//! §4.3.3): an `rsaEncryption` key (and every PKCS #1 key) signs with
//! `rsa_pss_rsae_*` and `rsa_pkcs1_*`, an `id-RSASSA-PSS` key (RFC 4055) only
//! with `rsa_pss_pss_*`, and only with the hash its parameters name, if
//! any.
//!
//! Secret key material is held in `browntls-crypto` key types, which zeroise
//! it on drop. ECDSA nonces are RFC 6979 deterministic nonces hedged with
//! fresh randomness; RSA signing uses CRT with blinding and a fault check.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug};

use browntls_crypto::curve448::ed448;
use browntls_crypto::curve25519::ed25519;
use browntls_crypto::hash::HashAlgorithm as BcHash;
use browntls_crypto::nist::{p256, p384, p521};
use browntls_crypto::rand::OsRng;
use browntls_crypto::rsa::{MAX_MODULUS_BYTES, RsaKeyAlgorithm, RsaPrivateKey};

use browntls_pki::{PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, alg_id};

use crate::crypto::signer::{Signer, SigningKey, public_key_to_spki};
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::Error;
use crate::sync::Arc;

/// Loads any private key this provider can sign with: ECDSA (PKCS #8 or
/// SEC 1), Ed25519 or Ed448 (PKCS #8) or RSA (PKCS #8 or PKCS #1).
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    match der {
        PrivateKeyDer::Sec1(_) => any_ecdsa_type(der),
        PrivateKeyDer::Pkcs1(_) => any_rsa_type(der),
        PrivateKeyDer::Pkcs8(pkcs8) => any_ecdsa_type(der)
            .or_else(|_| any_eddsa_type(pkcs8))
            .or_else(|_| any_rsa_type(der))
            .map_err(|_| {
                Error::general("failed to parse PKCS#8 private key as ECDSA, EdDSA or RSA")
            }),
        _ => Err(Error::general("unsupported private key encoding")),
    }
}

/// Loads an ECDSA key (P-256, P-384 or P-521) in PKCS #8 or SEC 1 form.
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(key) = EcdsaP256SigningKey::load(der) {
        return Ok(Arc::new(key));
    }
    if let Ok(key) = EcdsaP384SigningKey::load(der) {
        return Ok(Arc::new(key));
    }
    if let Ok(key) = EcdsaP521SigningKey::load(der) {
        return Ok(Arc::new(key));
    }
    Err(Error::general("failed to parse private key as ECDSA"))
}

/// Loads an Ed25519 or Ed448 key in PKCS #8 (RFC 8410) form.
pub fn any_eddsa_type(der: &PrivatePkcs8KeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(key) = Ed25519SigningKey::from_pkcs8(der.secret_der()) {
        return Ok(Arc::new(key));
    }
    Ed448SigningKey::from_pkcs8(der.secret_der()).map(|k| Arc::new(k) as Arc<dyn SigningKey>)
}

/// Loads an RSA key in PKCS #8 or PKCS #1 form (2048 to 8192 bits). A
/// PKCS #8 key may be an `rsaEncryption` or an `id-RSASSA-PSS` key (without
/// parameters, or restricted to SHA-256, SHA-384 or SHA-512 with MGF1 over
/// the same hash and a salt of the digest length; see
/// `browntls_crypto::rsa::RsaKeyAlgorithm`).
pub fn any_rsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    RsaSigningKey::load(der).map(|k| Arc::new(k) as Arc<dyn SigningKey>)
}

// ---------------------------------------------------------------------------
// ECDSA

macro_rules! ecdsa_key {
    ($name:ident, $signer:ident, $curve:ident, $scheme:expr, $alg_id:expr, $doc:literal) => {
        #[doc = concat!("An ECDSA ", $doc, " signing key.")]
        pub struct $name {
            key: Arc<$curve::SigningKey>,
            spki: SubjectPublicKeyInfoDer<'static>,
        }

        impl $name {
            fn load(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
                let secret = match der {
                    PrivateKeyDer::Pkcs8(pkcs8) => {
                        $curve::SecretKey::from_pkcs8_der(pkcs8.secret_der())
                    }
                    PrivateKeyDer::Sec1(sec1) => {
                        $curve::SecretKey::from_sec1_der(sec1.secret_der())
                    }
                    _ => return Err(Error::general("unsupported key encoding for ECDSA")),
                }
                .map_err(|_| Error::general(concat!("invalid ", $doc, " ECDSA key")))?;
                let key = $curve::SigningKey::new(secret);
                let spki = public_key_to_spki(&$alg_id, key.verifying_key().to_uncompressed());
                Ok(Self {
                    key: Arc::new(key),
                    spki,
                })
            }
        }

        impl SigningKey for $name {
            fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
                offered.contains(&$scheme).then(|| {
                    Box::new($signer {
                        key: self.key.clone(),
                    }) as Box<dyn Signer>
                })
            }

            fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
                Some(SubjectPublicKeyInfoDer::from_slice(self.spki.as_ref()))
            }

            fn algorithm(&self) -> SignatureAlgorithm {
                SignatureAlgorithm::ECDSA
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        struct $signer {
            key: Arc<$curve::SigningKey>,
        }

        impl Signer for $signer {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
                // RFC 6979 nonce hedged with fresh randomness (§3.6); if the
                // random source fails, the purely deterministic nonce is still
                // safe.
                let sig = match self.key.sign($curve::TLS_HASH, message, &OsRng) {
                    Ok(sig) => sig,
                    Err(_) => self
                        .key
                        .sign_deterministic($curve::TLS_HASH, message)
                        .map_err(|_| Error::general("ECDSA signing failed"))?,
                };
                Ok(sig.as_der().to_vec())
            }

            fn scheme(&self) -> SignatureScheme {
                $scheme
            }
        }

        impl Debug for $signer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($signer))
                    .field("scheme", &$scheme)
                    .finish_non_exhaustive()
            }
        }
    };
}

ecdsa_key!(
    EcdsaP256SigningKey,
    EcdsaP256Signer,
    p256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    alg_id::ECDSA_P256,
    "P-256"
);
ecdsa_key!(
    EcdsaP384SigningKey,
    EcdsaP384Signer,
    p384,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    alg_id::ECDSA_P384,
    "P-384"
);
ecdsa_key!(
    EcdsaP521SigningKey,
    EcdsaP521Signer,
    p521,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    alg_id::ECDSA_P521,
    "P-521"
);

// ---------------------------------------------------------------------------
// Ed25519

/// An Ed25519 signing key.
pub struct Ed25519SigningKey {
    key: Arc<ed25519::SigningKey>,
    spki: SubjectPublicKeyInfoDer<'static>,
}

impl Ed25519SigningKey {
    fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let key = ed25519::SigningKey::from_pkcs8_der(der)
            .map_err(|_| Error::general("invalid PKCS#8 Ed25519 key"))?;
        let spki = public_key_to_spki(&alg_id::ED25519, key.verifying_key().as_bytes());
        Ok(Self {
            key: Arc::new(key),
            spki,
        })
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SignatureScheme::ED25519).then(|| {
            Box::new(Ed25519Signer {
                key: self.key.clone(),
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from_slice(self.spki.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey").finish_non_exhaustive()
    }
}

struct Ed25519Signer {
    key: Arc<ed25519::SigningKey>,
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.sign(message).to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Ed448

/// An Ed448 signing key (RFC 8410 `id-Ed448` PKCS #8). It signs with the
/// `ed448` scheme: PureEdDSA with an empty context (RFC 9846 §4.2.3,
/// RFC 8422 §5.10).
pub struct Ed448SigningKey {
    key: Arc<ed448::SigningKey>,
    spki: SubjectPublicKeyInfoDer<'static>,
}

impl Ed448SigningKey {
    fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let key = ed448::SigningKey::from_pkcs8_der(der)
            .map_err(|_| Error::general("invalid PKCS#8 Ed448 key"))?;
        let spki = public_key_to_spki(&alg_id::ED448, key.verifying_key().as_bytes());
        Ok(Self {
            key: Arc::new(key),
            spki,
        })
    }
}

impl SigningKey for Ed448SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SignatureScheme::ED448).then(|| {
            Box::new(Ed448Signer {
                key: self.key.clone(),
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from_slice(self.spki.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED448
    }
}

impl Debug for Ed448SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed448SigningKey").finish_non_exhaustive()
    }
}

struct Ed448Signer {
    key: Arc<ed448::SigningKey>,
}

impl Signer for Ed448Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.sign(message).to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED448
    }
}

impl Debug for Ed448Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed448Signer").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// RSA

/// The schemes an `rsaEncryption` key offers, in preference order (PSS
/// first, larger hashes first), as rustls does.
static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// The schemes an `id-RSASSA-PSS` key offers (larger hashes first), before
/// its parameters' restriction is applied.
static RSA_PSS_PSS_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_PSS_SHA512,
    SignatureScheme::RSA_PSS_PSS_SHA384,
    SignatureScheme::RSA_PSS_PSS_SHA256,
];

/// Whether an RSA scheme is RSASSA-PSS (rather than PKCS #1 v1.5), whether
/// it is an `rsa_pss_pss_*` scheme, and its hash.
fn rsa_scheme(scheme: SignatureScheme) -> Option<(bool, bool, BcHash)> {
    Some(match scheme {
        SignatureScheme::RSA_PSS_SHA256 => (true, false, BcHash::Sha256),
        SignatureScheme::RSA_PSS_SHA384 => (true, false, BcHash::Sha384),
        SignatureScheme::RSA_PSS_SHA512 => (true, false, BcHash::Sha512),
        SignatureScheme::RSA_PSS_PSS_SHA256 => (true, true, BcHash::Sha256),
        SignatureScheme::RSA_PSS_PSS_SHA384 => (true, true, BcHash::Sha384),
        SignatureScheme::RSA_PSS_PSS_SHA512 => (true, true, BcHash::Sha512),
        SignatureScheme::RSA_PKCS1_SHA256 => (false, false, BcHash::Sha256),
        SignatureScheme::RSA_PKCS1_SHA384 => (false, false, BcHash::Sha384),
        SignatureScheme::RSA_PKCS1_SHA512 => (false, false, BcHash::Sha512),
        _ => return None,
    })
}

/// Whether a key identified by `algorithm` may sign with `scheme`
/// (RFC 9846 §4.3.3: `rsa_pss_rsae_*` and `rsa_pkcs1_*` need an
/// `rsaEncryption` key, `rsa_pss_pss_*` an `id-RSASSA-PSS` key whose
/// parameters, if present, are the scheme's; RFC 4055 §1.2).
fn rsa_key_permits(algorithm: RsaKeyAlgorithm, scheme: SignatureScheme) -> bool {
    match (algorithm, rsa_scheme(scheme)) {
        (RsaKeyAlgorithm::RsaEncryption, Some((_, pss_key, _))) => !pss_key,
        (RsaKeyAlgorithm::RsassaPss(_), Some((true, true, hash))) => algorithm.allows_pss(hash),
        _ => false,
    }
}

/// An RSA signing key (2048 to 8192 bits, two primes), identified by
/// `rsaEncryption` or `id-RSASSA-PSS`.
pub struct RsaSigningKey {
    key: Arc<RsaPrivateKey>,
    algorithm: RsaKeyAlgorithm,
    spki: SubjectPublicKeyInfoDer<'static>,
}

impl RsaSigningKey {
    fn load(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        // Loading validates the key's consistency and runs a sign/verify
        // self-test.
        let (key, algorithm) = match der {
            PrivateKeyDer::Pkcs1(pkcs1) => RsaPrivateKey::from_pkcs1_der(pkcs1.secret_der())
                .map(|key| (key, RsaKeyAlgorithm::RsaEncryption)),
            PrivateKeyDer::Pkcs8(pkcs8) => {
                RsaPrivateKey::from_pkcs8_der_with_algorithm(pkcs8.secret_der())
            }
            _ => return Err(Error::general("unsupported key encoding for RSA")),
        }
        .map_err(|_| Error::general("invalid RSA private key"))?;
        let spki_alg = match algorithm {
            RsaKeyAlgorithm::RsaEncryption => alg_id::RSA_ENCRYPTION,
            RsaKeyAlgorithm::RsassaPss(None) => alg_id::RSASSA_PSS,
            RsaKeyAlgorithm::RsassaPss(Some(BcHash::Sha256)) => alg_id::RSASSA_PSS_SHA256_KEY,
            RsaKeyAlgorithm::RsassaPss(Some(BcHash::Sha384)) => alg_id::RSASSA_PSS_SHA384_KEY,
            RsaKeyAlgorithm::RsassaPss(Some(BcHash::Sha512)) => alg_id::RSASSA_PSS_SHA512_KEY,
            RsaKeyAlgorithm::RsassaPss(Some(_)) => {
                return Err(Error::general("unsupported RSASSA-PSS key parameters"));
            }
        };
        let mut pkcs1 = vec![0u8; MAX_MODULUS_BYTES + 32];
        let len = key
            .public_key()
            .to_pkcs1_der(&mut pkcs1)
            .map_err(|_| Error::general("failed to encode RSA public key"))?;
        let spki = public_key_to_spki(&spki_alg, &pkcs1[..len]);
        Ok(Self {
            key: Arc::new(key),
            algorithm,
            spki,
        })
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let preference = match self.algorithm {
            RsaKeyAlgorithm::RsaEncryption => RSA_SCHEMES,
            RsaKeyAlgorithm::RsassaPss(_) => RSA_PSS_PSS_SCHEMES,
        };
        let scheme = preference
            .iter()
            .find(|scheme| offered.contains(scheme) && rsa_key_permits(self.algorithm, **scheme))
            .copied()?;
        Some(Box::new(RsaSigner {
            key: self.key.clone(),
            algorithm: self.algorithm,
            scheme,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from_slice(self.spki.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Debug for RsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigningKey")
            .field("bits", &self.key.modulus_bits())
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

struct RsaSigner {
    key: Arc<RsaPrivateKey>,
    algorithm: RsaKeyAlgorithm,
    scheme: SignatureScheme,
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // `choose_scheme` only creates permitted signers; check again so a
        // restricted key can never sign outside its restriction.
        let (pss, hash) = match rsa_scheme(self.scheme) {
            Some((pss, _, hash)) if rsa_key_permits(self.algorithm, self.scheme) => (pss, hash),
            _ => return Err(Error::general("unsupported RSA signature scheme")),
        };
        let mut out = vec![0u8; self.key.modulus_len_bytes()];
        let len = if pss {
            self.key.sign_pss(hash, message, &OsRng, &mut out)
        } else {
            self.key
                .sign_pkcs1v15_with_rng(hash, message, &OsRng, &mut out)
        }
        .map_err(|_| Error::general("RSA signing failed"))?;
        out.truncate(len);
        Ok(out)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for RsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browntls_pki::{PrivatePkcs1KeyDer, PrivateSec1KeyDer};

    #[test]
    fn rejects_garbage() {
        for der in [
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![1u8, 2, 3])),
            PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(vec![0x30u8, 0])),
            PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(vec![0x30u8, 0])),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(Vec::new())),
        ] {
            assert!(any_supported_type(&der).is_err());
        }
    }

    #[test]
    fn ed25519_key() {
        let key = ed25519::SigningKey::from_seed(&[7u8; 32]);
        let der = key.to_pkcs8_der();
        let loaded = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            der.to_vec(),
        )))
        .unwrap();
        assert_eq!(loaded.algorithm(), SignatureAlgorithm::ED25519);
        assert!(
            loaded
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        let signer = loaded.choose_scheme(&[SignatureScheme::ED25519]).unwrap();
        let sig = signer.sign(b"msg").unwrap();
        assert_eq!(sig, key.sign(b"msg"));
        let spki = loaded.public_key().unwrap();
        let (alg, pk) = crate::x509::split_spki(spki.as_ref()).unwrap();
        assert_eq!(alg, alg_id::ED25519.as_bytes());
        assert_eq!(pk, key.verifying_key().as_bytes());
    }

    #[test]
    fn ed448_key() {
        let key = ed448::SigningKey::from_seed(&[7u8; 57]);
        let der = key.to_pkcs8_der();
        let loaded = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            der.to_vec(),
        )))
        .unwrap();
        assert_eq!(loaded.algorithm(), SignatureAlgorithm::ED448);
        assert!(loaded.choose_scheme(&[SignatureScheme::ED25519]).is_none());
        let signer = loaded
            .choose_scheme(&[SignatureScheme::ED25519, SignatureScheme::ED448])
            .unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ED448);
        let sig = signer.sign(b"msg").unwrap();
        assert_eq!(sig, key.sign(b"msg"));
        let spki = loaded.public_key().unwrap();
        let (alg, pk) = crate::x509::split_spki(spki.as_ref()).unwrap();
        assert_eq!(alg, alg_id::ED448.as_bytes());
        assert_eq!(pk, key.verifying_key().as_bytes());
        // Also through the EdDSA loader; a truncated key fails.
        let pkcs8 = PrivatePkcs8KeyDer::from(der.to_vec());
        assert_eq!(
            any_eddsa_type(&pkcs8).unwrap().algorithm(),
            SignatureAlgorithm::ED448
        );
        let truncated = PrivatePkcs8KeyDer::from(der[..der.len() - 1].to_vec());
        assert!(any_eddsa_type(&truncated).is_err());
    }

    #[test]
    fn ecdsa_pkcs8_and_sec1_agree() {
        let secret = p384::SecretKey::from_bytes(&[5u8; 48]).unwrap();
        let mut sec1 = [0u8; p384::SEC1_PRIVATE_MAX_LEN];
        let len = secret.to_sec1_der(&mut sec1).unwrap();
        let loaded = any_supported_type(&PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
            sec1[..len].to_vec(),
        )))
        .unwrap();
        assert_eq!(loaded.algorithm(), SignatureAlgorithm::ECDSA);
        assert!(
            loaded
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        let signer = loaded
            .choose_scheme(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP384_SHA384,
            ])
            .unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP384_SHA384);
        let sig = signer.sign(b"msg").unwrap();
        p384::verify(&secret.public_key(), p384::TLS_HASH, b"msg", &sig).unwrap();

        let spki = loaded.public_key().unwrap();
        let mut expected = [0u8; p384::SPKI_MAX_LEN];
        let len = secret.public_key().to_spki_der(&mut expected).unwrap();
        assert_eq!(spki.as_ref(), &expected[..len]);
    }

    #[test]
    fn rsa_chooses_scheme_by_preference() {
        let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
        let mut der = vec![0u8; browntls_crypto::rsa::MAX_PKCS1_PRIVATE_KEY_DER_LEN];
        let len = key.to_pkcs1_der(&mut der).unwrap();
        der.truncate(len);
        let loaded =
            any_supported_type(&PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der))).unwrap();
        assert_eq!(loaded.algorithm(), SignatureAlgorithm::RSA);
        assert!(loaded.choose_scheme(&[SignatureScheme::ED25519]).is_none());
        let signer = loaded
            .choose_scheme(&[
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
            ])
            .unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::RSA_PSS_SHA384);
        let sig = signer.sign(b"msg").unwrap();
        assert_eq!(sig.len(), 256);
        browntls_crypto::rsa::verify_pss(key.public_key(), BcHash::Sha384, b"msg", &sig).unwrap();
        let signer = loaded
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
            .unwrap();
        let sig = signer.sign(b"msg").unwrap();
        browntls_crypto::rsa::verify_pkcs1v15(key.public_key(), BcHash::Sha256, b"msg", &sig)
            .unwrap();
        // A PKCS #1 key is an rsaEncryption key: no rsa_pss_pss_* schemes.
        assert!(
            loaded
                .choose_scheme(&[SignatureScheme::RSA_PSS_PSS_SHA256])
                .is_none()
        );
    }

    #[test]
    fn rsa_key_algorithm_restricts_schemes() {
        use SignatureScheme as S;
        use browntls_crypto::rsa::{MAX_PKCS8_PRIVATE_KEY_DER_LEN, verify_pkcs1v15, verify_pss};
        let key = RsaPrivateKey::generate(2048, &OsRng).unwrap();
        let all = [
            S::RSA_PSS_SHA512,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA256,
            S::RSA_PKCS1_SHA512,
            S::RSA_PKCS1_SHA384,
            S::RSA_PKCS1_SHA256,
            S::RSA_PSS_PSS_SHA512,
            S::RSA_PSS_PSS_SHA384,
            S::RSA_PSS_PSS_SHA256,
        ];
        let cases: [(RsaKeyAlgorithm, _, &[S]); 5] = [
            (
                RsaKeyAlgorithm::RsaEncryption,
                alg_id::RSA_ENCRYPTION,
                &all[..6],
            ),
            (
                RsaKeyAlgorithm::RsassaPss(None),
                alg_id::RSASSA_PSS,
                &all[6..],
            ),
            (
                RsaKeyAlgorithm::RsassaPss(Some(BcHash::Sha256)),
                alg_id::RSASSA_PSS_SHA256_KEY,
                &[S::RSA_PSS_PSS_SHA256],
            ),
            (
                RsaKeyAlgorithm::RsassaPss(Some(BcHash::Sha384)),
                alg_id::RSASSA_PSS_SHA384_KEY,
                &[S::RSA_PSS_PSS_SHA384],
            ),
            (
                RsaKeyAlgorithm::RsassaPss(Some(BcHash::Sha512)),
                alg_id::RSASSA_PSS_SHA512_KEY,
                &[S::RSA_PSS_PSS_SHA512],
            ),
        ];
        for (algorithm, spki_alg, allowed) in cases {
            let mut der = vec![0u8; MAX_PKCS8_PRIVATE_KEY_DER_LEN];
            let len = key
                .to_pkcs8_der_with_algorithm(algorithm, &mut der)
                .unwrap();
            der.truncate(len);
            let loaded =
                any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))).unwrap();
            assert_eq!(loaded.algorithm(), SignatureAlgorithm::RSA);
            let spki = loaded.public_key().unwrap();
            let (alg, _) = crate::x509::split_spki(spki.as_ref()).unwrap();
            assert_eq!(alg, spki_alg.as_bytes(), "{algorithm:?}");
            // Offered everything, the key picks its most preferred scheme.
            assert_eq!(loaded.choose_scheme(&all).unwrap().scheme(), allowed[0]);
            for scheme in all {
                let signer = loaded.choose_scheme(&[scheme]);
                assert_eq!(
                    signer.is_some(),
                    allowed.contains(&scheme),
                    "{algorithm:?} {scheme:?}"
                );
                let Some(signer) = signer else { continue };
                assert_eq!(signer.scheme(), scheme);
                let sig = signer.sign(b"msg").unwrap();
                let (pss, _, hash) = rsa_scheme(scheme).unwrap();
                if pss {
                    verify_pss(key.public_key(), hash, b"msg", &sig).unwrap();
                } else {
                    verify_pkcs1v15(key.public_key(), hash, b"msg", &sig).unwrap();
                }
            }
        }

        // A signer outside its key's restriction refuses to sign.
        let key = Arc::new(key);
        for (algorithm, scheme) in [
            (
                RsaKeyAlgorithm::RsassaPss(Some(BcHash::Sha256)),
                S::RSA_PSS_PSS_SHA384,
            ),
            (RsaKeyAlgorithm::RsassaPss(None), S::RSA_PSS_SHA256),
            (RsaKeyAlgorithm::RsassaPss(None), S::RSA_PKCS1_SHA256),
            (RsaKeyAlgorithm::RsaEncryption, S::RSA_PSS_PSS_SHA256),
            (RsaKeyAlgorithm::RsaEncryption, S::ED25519),
        ] {
            let signer = RsaSigner {
                key: key.clone(),
                algorithm,
                scheme,
            };
            assert!(signer.sign(b"msg").is_err(), "{algorithm:?} {scheme:?}");
        }
    }
}
