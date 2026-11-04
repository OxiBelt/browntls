//! Signature verification algorithms for certificates and handshake signatures.

use core::fmt;
use core::marker::PhantomData;

use browntls_pki::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use sha2::Digest;
use signature::Verifier;
use signature::hazmat::PrehashVerifier;

/// ECDSA over curve `$krate` with hash `D`.
pub(crate) struct Ecdsa<C, D> {
    _curve: PhantomData<C>,
    _digest: PhantomData<D>,
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
}

impl<C, D> fmt::Debug for Ecdsa<C, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ecdsa")
            .field("public_key_alg_id", &self.public_key_alg_id)
            .field("signature_alg_id", &self.signature_alg_id)
            .finish()
    }
}

/// Marker types naming the curve an [`Ecdsa`] instance verifies over.
pub(crate) struct P256;
pub(crate) struct P384;
pub(crate) struct P521;

macro_rules! ecdsa_curve {
    ($marker:ident, $krate:ident) => {
        impl<D> SignatureVerificationAlgorithm for Ecdsa<$marker, D>
        where
            D: Digest + Send + Sync + 'static,
        {
            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let key = $krate::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let sig =
                    $krate::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                let digest = D::digest(message);
                key.verify_prehash(&digest, &sig)
                    .map_err(|_| InvalidSignature)
            }

            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                self.public_key_alg_id
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                self.signature_alg_id
            }
        }
    };
}

ecdsa_curve!(P256, p256);
ecdsa_curve!(P384, p384);
ecdsa_curve!(P521, p521);

macro_rules! ecdsa_alg {
    ($name:ident, $curve:ident, $digest:ty, $pk:expr, $sig:expr) => {
        pub(crate) static $name: Ecdsa<$curve, $digest> = Ecdsa {
            _curve: PhantomData,
            _digest: PhantomData,
            public_key_alg_id: $pk,
            signature_alg_id: $sig,
        };
    };
}

ecdsa_alg!(
    ECDSA_P256_SHA256,
    P256,
    sha2::Sha256,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA256
);
ecdsa_alg!(
    ECDSA_P256_SHA384,
    P256,
    sha2::Sha384,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA384
);
ecdsa_alg!(
    ECDSA_P384_SHA256,
    P384,
    sha2::Sha256,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA256
);
ecdsa_alg!(
    ECDSA_P384_SHA384,
    P384,
    sha2::Sha384,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA384
);
ecdsa_alg!(
    ECDSA_P521_SHA512,
    P521,
    sha2::Sha512,
    alg_id::ECDSA_P521,
    alg_id::ECDSA_SHA512
);

/// Ed25519 (RFC 8032).
#[derive(Debug)]
pub(crate) struct Ed25519;

pub(crate) static ED25519: Ed25519 = Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let pk: [u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

/// Accepted RSA modulus sizes in bytes (2048..=8192 bits).
const RSA_MIN_BYTES: usize = 256;
const RSA_MAX_BYTES: usize = 1024;

fn rsa_public_key(der: &[u8]) -> Result<rsa::RsaPublicKey, InvalidSignature> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPublicKey::from_pkcs1_der(der).map_err(|_| InvalidSignature)?;
    if !(RSA_MIN_BYTES..=RSA_MAX_BYTES).contains(&key.size()) {
        return Err(InvalidSignature);
    }
    Ok(key)
}

/// RSASSA-PKCS1-v1_5 with hash `D`.
pub(crate) struct RsaPkcs1<D> {
    _digest: PhantomData<D>,
    signature_alg_id: AlgorithmIdentifier,
}

impl<D> fmt::Debug for RsaPkcs1<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPkcs1")
            .field("signature_alg_id", &self.signature_alg_id)
            .finish()
    }
}

pub(crate) static RSA_PKCS1_SHA256: RsaPkcs1<sha2::Sha256> = RsaPkcs1 {
    _digest: PhantomData,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
};
pub(crate) static RSA_PKCS1_SHA384: RsaPkcs1<sha2::Sha384> = RsaPkcs1 {
    _digest: PhantomData,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
};
pub(crate) static RSA_PKCS1_SHA512: RsaPkcs1<sha2::Sha512> = RsaPkcs1 {
    _digest: PhantomData,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
};

impl<D> SignatureVerificationAlgorithm for RsaPkcs1<D>
where
    D: Digest + rsa::pkcs8::AssociatedOid + Send + Sync + 'static,
{
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = rsa::pkcs1v15::VerifyingKey::<D>::new(rsa_public_key(public_key)?);
        let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

/// RSASSA-PSS with hash `D`, MGF1 with `D`, and a salt as long as the digest.
pub(crate) struct RsaPss<D> {
    _digest: PhantomData<D>,
    signature_alg_id: AlgorithmIdentifier,
}

impl<D> fmt::Debug for RsaPss<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPss")
            .field("signature_alg_id", &self.signature_alg_id)
            .finish()
    }
}

pub(crate) static RSA_PSS_SHA256: RsaPss<sha2::Sha256> = RsaPss {
    _digest: PhantomData,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
};
pub(crate) static RSA_PSS_SHA384: RsaPss<sha2::Sha384> = RsaPss {
    _digest: PhantomData,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
};
pub(crate) static RSA_PSS_SHA512: RsaPss<sha2::Sha512> = RsaPss {
    _digest: PhantomData,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
};

impl<D> SignatureVerificationAlgorithm for RsaPss<D>
where
    D: Digest + rsa::pkcs8::AssociatedOid + sha2::digest::FixedOutputReset + Send + Sync + 'static,
{
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // RFC 8446 §4.2.3: the salt length equals the digest length, which is
        // what `VerifyingKey::new` configures.
        let key = rsa::pss::VerifyingKey::<D>::new(rsa_public_key(public_key)?);
        let sig = rsa::pss::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;

    #[test]
    fn ed25519_verifies_and_rejects() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let sig = key.sign(b"hello").to_bytes();
        let pk = key.verifying_key().to_bytes();
        assert!(ED25519.verify_signature(&pk, b"hello", &sig).is_ok());
        assert!(ED25519.verify_signature(&pk, b"hellp", &sig).is_err());
        assert!(ED25519.verify_signature(&pk[..31], b"hello", &sig).is_err());
        assert!(ED25519.verify_signature(&pk, b"hello", &sig[..63]).is_err());
        assert_eq!(ED25519.public_key_alg_id(), alg_id::ED25519);
    }

    #[test]
    fn ecdsa_verifies_with_each_hash() {
        let key = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let pk = key.verifying_key().to_sec1_point(false);
        // SHA-256 signature
        let sig: p256::ecdsa::Signature = key.sign(b"data");
        let der = sig.to_der();
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(pk.as_bytes(), b"data", der.as_bytes())
                .is_ok()
        );
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(pk.as_bytes(), b"datb", der.as_bytes())
                .is_err()
        );
        assert!(
            ECDSA_P256_SHA384
                .verify_signature(pk.as_bytes(), b"data", der.as_bytes())
                .is_err()
        );
        assert!(
            ECDSA_P384_SHA256
                .verify_signature(pk.as_bytes(), b"data", der.as_bytes())
                .is_err()
        );
        // SHA-384 signature over a P-256 key
        use signature::hazmat::PrehashSigner;
        let digest = sha2::Sha384::digest(b"data");
        let sig384: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        assert!(
            ECDSA_P256_SHA384
                .verify_signature(pk.as_bytes(), b"data", sig384.to_der().as_bytes())
                .is_ok()
        );
        assert_eq!(ECDSA_P256_SHA384.signature_alg_id(), alg_id::ECDSA_SHA384);
    }

    #[test]
    fn rsa_rejects_malformed_input() {
        assert!(
            RSA_PKCS1_SHA256
                .verify_signature(&[0x30, 0], b"m", &[0; 256])
                .is_err()
        );
        assert!(
            RSA_PSS_SHA256
                .verify_signature(&[0x30, 0], b"m", &[0; 256])
                .is_err()
        );
        assert_eq!(RSA_PSS_SHA256.public_key_alg_id(), alg_id::RSA_ENCRYPTION);
        assert_eq!(
            RSA_PKCS1_SHA384.signature_alg_id(),
            alg_id::RSA_PKCS1_SHA384
        );
    }
}
