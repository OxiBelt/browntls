//! PKIX `AlgorithmIdentifier` values (RFC 5280 §4.1.1.2).
//!
//! Each constant holds the DER encoding of the *contents* of the
//! `AlgorithmIdentifier` SEQUENCE (the OID followed by any parameters), which
//! is how certificates are compared against verification algorithms.

use core::fmt;

/// The contents of a DER-encoded `AlgorithmIdentifier` (without the outer
/// SEQUENCE tag and length).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlgorithmIdentifier(&'static [u8]);

impl AlgorithmIdentifier {
    /// Wraps the contents of an `AlgorithmIdentifier`.
    #[must_use]
    pub const fn from_slice(bytes: &'static [u8]) -> Self {
        Self(bytes)
    }

    /// Returns the encoded contents.
    #[must_use]
    pub const fn as_bytes(&self) -> &'static [u8] {
        self.0
    }
}

impl AsRef<[u8]> for AlgorithmIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl core::ops::Deref for AlgorithmIdentifier {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl fmt::Debug for AlgorithmIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AlgorithmIdentifier(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// AlgorithmIdentifier for `id-ecPublicKey` with named curve `secp256r1`.
pub const ECDSA_P256: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07,
]);

/// AlgorithmIdentifier for `id-ecPublicKey` with named curve `secp384r1`.
pub const ECDSA_P384: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
]);

/// AlgorithmIdentifier for `id-ecPublicKey` with named curve `secp521r1`.
pub const ECDSA_P521: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
]);

/// AlgorithmIdentifier for `ecdsa-with-SHA256`.
pub const ECDSA_SHA256: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);

/// AlgorithmIdentifier for `ecdsa-with-SHA384`.
pub const ECDSA_SHA384: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);

/// AlgorithmIdentifier for `ecdsa-with-SHA512`.
pub const ECDSA_SHA512: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]);

/// AlgorithmIdentifier for `rsaEncryption` with NULL parameters.
pub const RSA_ENCRYPTION: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
]);

/// AlgorithmIdentifier for `sha256WithRSAEncryption` with NULL parameters.
pub const RSA_PKCS1_SHA256: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
]);

/// AlgorithmIdentifier for `sha384WithRSAEncryption` with NULL parameters.
pub const RSA_PKCS1_SHA384: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00,
]);

/// AlgorithmIdentifier for `sha512WithRSAEncryption` with NULL parameters.
pub const RSA_PKCS1_SHA512: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00,
]);

/// AlgorithmIdentifier for `rsassa-pss` with SHA-256, MGF1(SHA-256) and a 32-byte salt.
pub const RSA_PSS_SHA256: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c,
    0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01,
    0x20,
]);

/// AlgorithmIdentifier for `rsassa-pss` with SHA-384, MGF1(SHA-384) and a 48-byte salt.
pub const RSA_PSS_SHA384: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xa1, 0x1c,
    0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01,
    0x30,
]);

/// AlgorithmIdentifier for `rsassa-pss` with SHA-512, MGF1(SHA-512) and a 64-byte salt.
pub const RSA_PSS_SHA512: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xa1, 0x1c,
    0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01,
    0x40,
]);

/// AlgorithmIdentifier for `id-RSASSA-PSS` with absent parameters: the
/// `SubjectPublicKeyInfo` algorithm of an RSA key restricted to RSASSA-PSS
/// with any hash (RFC 4055 §1.2 and §3.1, RFC 5756 §2; TLS
/// `rsa_pss_pss_*`, RFC 9846 §4.3.3).
pub const RSASSA_PSS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
]);

/// AlgorithmIdentifier of an `id-RSASSA-PSS` public key whose parameters
/// restrict it to SHA-256, MGF1(SHA-256) and a 32-byte salt (RFC 4055 §3.1).
///
/// The encoding is that of [`RSA_PSS_SHA256`]: RFC 9846 §4.3.3 requires a
/// certificate signature made with such a key to carry parameters identical
/// to the key's.
pub const RSASSA_PSS_SHA256_KEY: AlgorithmIdentifier = RSA_PSS_SHA256;

/// AlgorithmIdentifier of an `id-RSASSA-PSS` public key restricted to
/// SHA-384, MGF1(SHA-384) and a 48-byte salt; the encoding of
/// [`RSA_PSS_SHA384`].
pub const RSASSA_PSS_SHA384_KEY: AlgorithmIdentifier = RSA_PSS_SHA384;

/// AlgorithmIdentifier of an `id-RSASSA-PSS` public key restricted to
/// SHA-512, MGF1(SHA-512) and a 64-byte salt; the encoding of
/// [`RSA_PSS_SHA512`].
pub const RSASSA_PSS_SHA512_KEY: AlgorithmIdentifier = RSA_PSS_SHA512;

/// AlgorithmIdentifier for `id-Ed25519`.
pub const ED25519: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]);

/// AlgorithmIdentifier for `id-Ed448`.
pub const ED448: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x71]);

/// AlgorithmIdentifier for `id-ml-dsa-44`.
pub const ML_DSA_44: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
]);

/// AlgorithmIdentifier for `id-ml-dsa-65`.
pub const ML_DSA_65: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
]);

/// AlgorithmIdentifier for `id-ml-dsa-87`.
pub const ML_DSA_87: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
]);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::path::Budget;
    use crate::signed_data::{SignedData, Spki, verify_signed_data};
    use crate::types::{InvalidSignature, SignatureVerificationAlgorithm};

    #[test]
    fn rsassa_pss_key_identifiers() {
        // `openssl genpkey -algorithm RSA-PSS` (OpenSSL 3.0.13) public keys,
        // without parameters and with `rsa_pss_keygen_md:sha256`,
        // `rsa_pss_keygen_mgf1_md:sha256` and `rsa_pss_keygen_saltlen:32`.
        assert_eq!(hex::encode(RSASSA_PSS), "06092a864886f70d01010a");
        assert_eq!(
            hex::encode(RSASSA_PSS_SHA256_KEY),
            "06092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a\
             864886f70d010108300d06096086480165030402010500a203020120"
        );
        for (key, sig, oid) in [
            (RSASSA_PSS_SHA256_KEY, RSA_PSS_SHA256, 1u8),
            (RSASSA_PSS_SHA384_KEY, RSA_PSS_SHA384, 2),
            (RSASSA_PSS_SHA512_KEY, RSA_PSS_SHA512, 3),
        ] {
            assert_eq!(key, sig);
            assert!(key.starts_with(&RSASSA_PSS));
            // Both hash identifiers (message and MGF1) name the same hash.
            let hash_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, oid];
            assert_eq!(key.windows(9).filter(|w| *w == hash_oid).count(), 2);
        }
    }

    /// Accepts every signature; only the identifiers matter here.
    #[derive(Debug)]
    struct AcceptAll {
        public_key: AlgorithmIdentifier,
        signature: AlgorithmIdentifier,
    }

    impl SignatureVerificationAlgorithm for AcceptAll {
        fn verify_signature(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), InvalidSignature> {
            Ok(())
        }
        fn public_key_alg_id(&self) -> AlgorithmIdentifier {
            self.public_key
        }
        fn signature_alg_id(&self) -> AlgorithmIdentifier {
            self.signature
        }
    }

    #[test]
    fn restricted_pss_keys_only_match_their_own_parameters() {
        // An issuer key restricted to one hash verifies only signatures whose
        // parameters are identical to its own (RFC 9846 §4.3.3).
        static ALGS: [&dyn SignatureVerificationAlgorithm; 4] = [
            &AcceptAll {
                public_key: RSA_ENCRYPTION,
                signature: RSA_PSS_SHA256,
            },
            &AcceptAll {
                public_key: RSASSA_PSS,
                signature: RSA_PSS_SHA256,
            },
            &AcceptAll {
                public_key: RSASSA_PSS_SHA256_KEY,
                signature: RSA_PSS_SHA256,
            },
            &AcceptAll {
                public_key: RSASSA_PSS_SHA384_KEY,
                signature: RSA_PSS_SHA384,
            },
        ];
        let check = |key: AlgorithmIdentifier, sig: AlgorithmIdentifier| {
            let spki = Spki {
                algorithm: key.as_bytes(),
                key: &[],
            };
            let signed = SignedData {
                data: &[],
                algorithm: sig.as_bytes(),
                signature: &[],
            };
            verify_signed_data(&ALGS, &spki, &signed, &mut Budget::default())
        };
        assert_eq!(check(RSASSA_PSS, RSA_PSS_SHA256), Ok(()));
        assert_eq!(check(RSASSA_PSS_SHA256_KEY, RSA_PSS_SHA256), Ok(()));
        assert_eq!(check(RSA_ENCRYPTION, RSA_PSS_SHA256), Ok(()));
        assert_eq!(check(RSASSA_PSS_SHA384_KEY, RSA_PSS_SHA384), Ok(()));
        assert_eq!(
            check(RSASSA_PSS_SHA384_KEY, RSA_PSS_SHA256),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
        );
        assert_eq!(
            check(RSASSA_PSS_SHA256_KEY, RSA_PSS_SHA384),
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
        );
        // An RSASSA-PSS key never verifies PKCS #1 v1.5 signatures.
        assert_eq!(
            check(RSASSA_PSS, RSA_PKCS1_SHA256),
            Err(Error::UnsupportedSignatureAlgorithm)
        );
    }
}
