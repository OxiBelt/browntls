//! Signature verification algorithms for certificate paths (via
//! `browntls-pki`) and handshake signatures.
//!
//! Each algorithm pairs a `SubjectPublicKeyInfo` algorithm identifier with a
//! signature algorithm identifier, as webpki does. Public keys are the content
//! of the `subjectPublicKey` BIT STRING: an uncompressed SEC 1 point for ECDSA,
//! 32 bytes for Ed25519 and a PKCS #1 `RSAPublicKey` for RSA. Every failure,
//! including a malformed key, is reported as [`InvalidSignature`].

use core::fmt;

use browntls_crypto::curve25519::ed25519;
use browntls_crypto::hash::HashAlgorithm as BcHash;
use browntls_crypto::nist::{p256, p384, p521};
use browntls_crypto::rsa::{self, RsaPublicKey};
use browntls_pki::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};

/// The curves ECDSA verification supports.
#[derive(Clone, Copy, Debug)]
enum Curve {
    P256,
    P384,
    P521,
}

/// ECDSA with a DER `Ecdsa-Sig-Value` (RFC 5480, RFC 8446 §4.2.3).
pub struct EcdsaVerify {
    curve: Curve,
    hash: BcHash,
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for EcdsaVerify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // Only the uncompressed point form is accepted, as in webpki.
        if public_key.first() != Some(&0x04) {
            return Err(InvalidSignature);
        }
        let ok = match self.curve {
            Curve::P256 => p256::PublicKey::from_sec1_bytes(public_key)
                .and_then(|pk| p256::verify(&pk, self.hash, message, signature)),
            Curve::P384 => p384::PublicKey::from_sec1_bytes(public_key)
                .and_then(|pk| p384::verify(&pk, self.hash, message, signature)),
            Curve::P521 => p521::PublicKey::from_sec1_bytes(public_key)
                .and_then(|pk| p521::verify(&pk, self.hash, message, signature)),
        };
        ok.map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

impl fmt::Debug for EcdsaVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaVerify")
            .field("curve", &self.curve)
            .field("hash", &self.hash)
            .finish()
    }
}

macro_rules! ecdsa_alg {
    ($(#[$m:meta])* $name:ident, $curve:ident, $hash:ident, $pk:ident, $sig:ident) => {
        $(#[$m])*
        pub static $name: EcdsaVerify = EcdsaVerify {
            curve: Curve::$curve,
            hash: BcHash::$hash,
            public_key_alg_id: alg_id::$pk,
            signature_alg_id: alg_id::$sig,
        };
    };
}

ecdsa_alg!(
    /// ECDSA on P-256 with SHA-256.
    ECDSA_P256_SHA256, P256, Sha256, ECDSA_P256, ECDSA_SHA256
);
ecdsa_alg!(
    /// ECDSA on P-256 with SHA-384.
    ECDSA_P256_SHA384, P256, Sha384, ECDSA_P256, ECDSA_SHA384
);
ecdsa_alg!(
    /// ECDSA on P-256 with SHA-512.
    ECDSA_P256_SHA512, P256, Sha512, ECDSA_P256, ECDSA_SHA512
);
ecdsa_alg!(
    /// ECDSA on P-384 with SHA-256.
    ECDSA_P384_SHA256, P384, Sha256, ECDSA_P384, ECDSA_SHA256
);
ecdsa_alg!(
    /// ECDSA on P-384 with SHA-384.
    ECDSA_P384_SHA384, P384, Sha384, ECDSA_P384, ECDSA_SHA384
);
ecdsa_alg!(
    /// ECDSA on P-384 with SHA-512.
    ECDSA_P384_SHA512, P384, Sha512, ECDSA_P384, ECDSA_SHA512
);
ecdsa_alg!(
    /// ECDSA on P-521 with SHA-256.
    ECDSA_P521_SHA256, P521, Sha256, ECDSA_P521, ECDSA_SHA256
);
ecdsa_alg!(
    /// ECDSA on P-521 with SHA-384.
    ECDSA_P521_SHA384, P521, Sha384, ECDSA_P521, ECDSA_SHA384
);
ecdsa_alg!(
    /// ECDSA on P-521 with SHA-512.
    ECDSA_P521_SHA512, P521, Sha512, ECDSA_P521, ECDSA_SHA512
);

/// Ed25519 (RFC 8032, RFC 8410).
pub struct Ed25519Verify;

/// Ed25519.
pub static ED25519: Ed25519Verify = Ed25519Verify;

impl SignatureVerificationAlgorithm for Ed25519Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = ed25519::VerifyingKey::from_slice(public_key).map_err(|_| InvalidSignature)?;
        let sig: &[u8; ed25519::SIGNATURE_LEN] =
            signature.try_into().map_err(|_| InvalidSignature)?;
        key.verify(message, sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

impl fmt::Debug for Ed25519Verify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Verify")
    }
}

/// The RSA signature padding.
#[derive(Clone, Copy, Debug)]
enum RsaPadding {
    Pkcs1v15,
    Pss,
}

/// RSA with 2048- to 8192-bit moduli: RSASSA-PKCS1-v1_5, or RSASSA-PSS with
/// MGF1 over the same hash and a salt as long as the digest (RFC 8446
/// §4.2.3).
pub struct RsaVerify {
    padding: RsaPadding,
    hash: BcHash,
    signature_alg_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for RsaVerify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;
        match self.padding {
            RsaPadding::Pkcs1v15 => rsa::verify_pkcs1v15(&key, self.hash, message, signature),
            RsaPadding::Pss => rsa::verify_pss(&key, self.hash, message, signature),
        }
        .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

impl fmt::Debug for RsaVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaVerify")
            .field("padding", &self.padding)
            .field("hash", &self.hash)
            .finish()
    }
}

macro_rules! rsa_alg {
    ($(#[$m:meta])* $name:ident, $padding:ident, $hash:ident, $sig:ident) => {
        $(#[$m])*
        pub static $name: RsaVerify = RsaVerify {
            padding: RsaPadding::$padding,
            hash: BcHash::$hash,
            signature_alg_id: alg_id::$sig,
        };
    };
}

rsa_alg!(
    /// RSASSA-PKCS1-v1_5 with SHA-256 (2048 to 8192 bits).
    RSA_PKCS1_2048_8192_SHA256, Pkcs1v15, Sha256, RSA_PKCS1_SHA256
);
rsa_alg!(
    /// RSASSA-PKCS1-v1_5 with SHA-384 (2048 to 8192 bits).
    RSA_PKCS1_2048_8192_SHA384, Pkcs1v15, Sha384, RSA_PKCS1_SHA384
);
rsa_alg!(
    /// RSASSA-PKCS1-v1_5 with SHA-512 (2048 to 8192 bits).
    RSA_PKCS1_2048_8192_SHA512, Pkcs1v15, Sha512, RSA_PKCS1_SHA512
);
rsa_alg!(
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt (2048 to
    /// 8192 bits; the key's SPKI is `rsaEncryption`).
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY, Pss, Sha256, RSA_PSS_SHA256
);
rsa_alg!(
    /// RSASSA-PSS with SHA-384, MGF1-SHA-384 and a 48-byte salt (2048 to
    /// 8192 bits; the key's SPKI is `rsaEncryption`).
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY, Pss, Sha384, RSA_PSS_SHA384
);
rsa_alg!(
    /// RSASSA-PSS with SHA-512, MGF1-SHA-512 and a 64-byte salt (2048 to
    /// 8192 bits; the key's SPKI is `rsaEncryption`).
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY, Pss, Sha512, RSA_PSS_SHA512
);

#[cfg(test)]
mod tests {
    use super::*;
    use browntls_crypto::rand::OsRng;

    #[test]
    fn ed25519_verifies_and_rejects() {
        let key = ed25519::SigningKey::from_seed(&[3u8; 32]);
        let sig = key.sign(b"hello");
        let pk = *key.verifying_key().as_bytes();
        assert!(ED25519.verify_signature(&pk, b"hello", &sig).is_ok());
        assert!(ED25519.verify_signature(&pk, b"hellp", &sig).is_err());
        assert!(ED25519.verify_signature(&pk[..31], b"hello", &sig).is_err());
        assert!(ED25519.verify_signature(&pk, b"hello", &sig[..63]).is_err());
        assert!(
            ED25519
                .verify_signature(&[0u8; 32], b"hello", &sig)
                .is_err()
        );
        assert_eq!(ED25519.public_key_alg_id(), alg_id::ED25519);
    }

    #[test]
    fn ecdsa_checks_curve_and_hash() {
        let key = p256::SigningKey::generate(&OsRng).unwrap();
        let pk = key.verifying_key().to_uncompressed();
        let sig = key.sign(BcHash::Sha256, b"data", &OsRng).unwrap();
        let der = sig.as_der();
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(&pk, b"data", der)
                .is_ok()
        );
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(&pk, b"datb", der)
                .is_err()
        );
        assert!(
            ECDSA_P256_SHA384
                .verify_signature(&pk, b"data", der)
                .is_err()
        );
        assert!(
            ECDSA_P384_SHA256
                .verify_signature(&pk, b"data", der)
                .is_err()
        );
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(&pk, b"data", sig.fixed())
                .is_err()
        );
        // compressed keys are not accepted
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02 | (pk[64] & 1);
        compressed[1..].copy_from_slice(&pk[1..33]);
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(&compressed, b"data", der)
                .is_err()
        );
        let sig512 = key.sign(BcHash::Sha512, b"data", &OsRng).unwrap();
        assert!(
            ECDSA_P256_SHA512
                .verify_signature(&pk, b"data", sig512.as_der())
                .is_ok()
        );
        assert_eq!(ECDSA_P256_SHA384.signature_alg_id(), alg_id::ECDSA_SHA384);
        assert_eq!(ECDSA_P521_SHA512.public_key_alg_id(), alg_id::ECDSA_P521);
    }

    #[test]
    fn rsa_rejects_malformed_input() {
        for alg in [
            &RSA_PKCS1_2048_8192_SHA256 as &dyn SignatureVerificationAlgorithm,
            &RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        ] {
            assert!(alg.verify_signature(&[0x30, 0], b"m", &[0; 256]).is_err());
            assert!(alg.verify_signature(&[], b"m", &[]).is_err());
            assert_eq!(alg.public_key_alg_id(), alg_id::RSA_ENCRYPTION);
        }
        assert_eq!(
            RSA_PKCS1_2048_8192_SHA384.signature_alg_id(),
            alg_id::RSA_PKCS1_SHA384
        );
    }
}
