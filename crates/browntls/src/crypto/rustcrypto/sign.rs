//! Signing keys: ECDSA (P-256, P-384, P-521) and Ed25519.
//!
//! RSA private keys are rejected: see the module documentation of
//! [`super`] for the advisory that motivates this.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug};

use browntls_pki::{PrivateKeyDer, SubjectPublicKeyInfoDer, alg_id};
use signature::Signer as _;

use crate::crypto::signer::{Signer, SigningKey, public_key_to_spki};
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::Error;
use crate::sync::Arc;

/// Loads any private key this provider can sign with.
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(key) = any_ecdsa_type(der) {
        return Ok(key);
    }
    if let PrivateKeyDer::Pkcs8(pkcs8) = der
        && let Ok(key) = Ed25519SigningKey::new(pkcs8.secret_der())
    {
        return Ok(Arc::new(key));
    }
    if matches!(der, PrivateKeyDer::Pkcs1(_)) || looks_like_rsa_pkcs8(der.secret_der()) {
        return Err(Error::general(
            "RSA signing is not supported by the rustcrypto provider \
             (RUSTSEC-2023-0071: Marvin attack on private-key operations)",
        ));
    }
    Err(Error::general(
        "failed to parse private key as ECDSA or Ed25519",
    ))
}

/// Loads an ECDSA key in PKCS#8 or SEC 1 form.
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(key) = EcdsaP256::load(der) {
        return Ok(Arc::new(key));
    }
    if let Ok(key) = EcdsaP384::load(der) {
        return Ok(Arc::new(key));
    }
    if let Ok(key) = EcdsaP521::load(der) {
        return Ok(Arc::new(key));
    }
    Err(Error::general("failed to parse private key as ECDSA"))
}

/// Loads an Ed25519 key in PKCS#8 form.
pub fn any_eddsa_type(
    der: &browntls_pki::PrivatePkcs8KeyDer<'_>,
) -> Result<Arc<dyn SigningKey>, Error> {
    Ed25519SigningKey::new(der.secret_der()).map(|k| Arc::new(k) as Arc<dyn SigningKey>)
}

/// Whether a PKCS#8 blob names `rsaEncryption`, so the failure can be explained.
fn looks_like_rsa_pkcs8(der: &[u8]) -> bool {
    const RSA_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    der.windows(RSA_OID.len()).any(|w| w == RSA_OID)
}

macro_rules! ecdsa_key {
    ($name:ident, $signer:ident, $krate:ident, $scheme:expr, $alg_id:expr) => {
        /// An ECDSA signing key.
        pub struct $name {
            key: $krate::ecdsa::SigningKey,
            spki: SubjectPublicKeyInfoDer<'static>,
        }

        impl $name {
            fn load(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
                use $krate::pkcs8::DecodePrivateKey;
                let key = match der {
                    PrivateKeyDer::Pkcs8(pkcs8) => {
                        $krate::ecdsa::SigningKey::from_pkcs8_der(pkcs8.secret_der())
                            .map_err(|_| Error::general("invalid PKCS#8 ECDSA key"))?
                    }
                    PrivateKeyDer::Sec1(sec1) => {
                        $krate::SecretKey::from_sec1_der(sec1.secret_der())
                            .map(Into::into)
                            .map_err(|_| Error::general("invalid SEC 1 ECDSA key"))?
                    }
                    _ => return Err(Error::general("unsupported key encoding for ECDSA")),
                };
                let point = key.verifying_key().to_sec1_point(false);
                let spki = public_key_to_spki(&$alg_id, point.as_bytes());
                Ok(Self { key, spki })
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
            key: $krate::ecdsa::SigningKey,
        }

        impl Signer for $signer {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
                // RFC 6979 deterministic nonces: no randomness is consumed here.
                let sig: $krate::ecdsa::Signature = self.key.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }

            fn scheme(&self) -> SignatureScheme {
                $scheme
            }
        }

        impl Debug for $signer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($signer)).finish_non_exhaustive()
            }
        }
    };
}

ecdsa_key!(
    EcdsaP256,
    EcdsaP256Signer,
    p256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    alg_id::ECDSA_P256
);
ecdsa_key!(
    EcdsaP384,
    EcdsaP384Signer,
    p384,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    alg_id::ECDSA_P384
);
ecdsa_key!(
    EcdsaP521,
    EcdsaP521Signer,
    p521,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    alg_id::ECDSA_P521
);

/// An Ed25519 signing key.
pub struct Ed25519SigningKey {
    key: ed25519_dalek::SigningKey,
    spki: SubjectPublicKeyInfoDer<'static>,
}

impl Ed25519SigningKey {
    fn new(pkcs8: &[u8]) -> Result<Self, Error> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let key = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8)
            .map_err(|_| Error::general("invalid PKCS#8 Ed25519 key"))?;
        let spki = public_key_to_spki(&alg_id::ED25519, key.verifying_key().as_bytes());
        Ok(Self { key, spki })
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
    key: ed25519_dalek::SigningKey,
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.sign(message).to_bytes().to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;
    use browntls_pki::PrivatePkcs8KeyDer;

    #[test]
    fn rejects_garbage_and_rsa() {
        let garbage = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(alloc::vec![1u8, 2, 3]));
        assert!(any_supported_type(&garbage).is_err());
        let pkcs1 = PrivateKeyDer::Pkcs1(browntls_pki::PrivatePkcs1KeyDer::from(alloc::vec![
            0x30u8, 0
        ]));
        let err = any_supported_type(&pkcs1).unwrap_err();
        assert!(alloc::format!("{err}").contains("RSA"));
    }

    #[test]
    fn ed25519_pkcs8_roundtrip() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let der = key.to_pkcs8_der().unwrap();
        let loaded = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            der.as_bytes().to_vec(),
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
        assert_eq!(sig.len(), 64);
        let spki = loaded.public_key().unwrap();
        let (alg, pk) = crate::x509::split_spki(spki.as_ref()).unwrap();
        assert_eq!(alg, alg_id::ED25519.as_bytes());
        assert_eq!(pk, key.verifying_key().as_bytes());
    }

    #[test]
    fn ecdsa_p256_pkcs8_and_sec1() {
        use p256::pkcs8::EncodePrivateKey;
        let secret = p256::SecretKey::from_slice(&[5u8; 32]).unwrap();
        let pkcs8 = secret.to_pkcs8_der().unwrap();
        let loaded = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pkcs8.as_bytes().to_vec(),
        )))
        .unwrap();
        assert_eq!(loaded.algorithm(), SignatureAlgorithm::ECDSA);
        let signer = loaded
            .choose_scheme(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ])
            .unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
        let sig = signer.sign(b"msg").unwrap();
        assert_eq!(sig[0], 0x30);

        let sec1 = secret.to_sec1_der().unwrap();
        let loaded2 = any_supported_type(&PrivateKeyDer::Sec1(
            browntls_pki::PrivateSec1KeyDer::from(sec1.to_vec()),
        ))
        .unwrap();
        assert_eq!(loaded.public_key().unwrap(), loaded2.public_key().unwrap());
    }
}
