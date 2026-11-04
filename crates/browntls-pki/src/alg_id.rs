//! PKIX `AlgorithmIdentifier` values (RFC 5280 §4.1.1.2).
//!
//! Each constant holds the DER encoding of the *contents* of the
//! `AlgorithmIdentifier` SEQUENCE (the OID followed by any parameters), which
//! is how certificates are compared against verification algorithms.
//!
//! The comparison is byte for byte, except for `id-RSASSA-PSS`: its
//! parameters have several encodings RFC 4055 treats as equal, so
//! [`AlgorithmIdentifier::matches_public_key`] and
//! [`AlgorithmIdentifier::matches_signature`] first map them to a canonical
//! constant ([`canonical_public_key_alg_id`], [`canonical_signature_alg_id`]).
//! Certificate path validation and handshake signature verification
//! (including `browntls`' raw public keys) all match through these two
//! functions.

use core::fmt;

use crate::rsassa_pss;

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

    /// Whether this identifier, the [`public_key_alg_id`] of a verification
    /// algorithm, matches the contents of a `SubjectPublicKeyInfo`
    /// `algorithm`: they are equal byte for byte, or the input is an
    /// `id-RSASSA-PSS` identifier whose [`canonical_public_key_alg_id`] is
    /// this identifier.
    ///
    /// Only the input is canonicalised: a verification algorithm's
    /// identifier must itself be canonical (such as [`RSASSA_PSS`] or
    /// [`RSASSA_PSS_SHA256_KEY`]) to match equivalent encodings, and a
    /// non-canonical one matches only its own bytes.
    ///
    /// [`public_key_alg_id`]: crate::SignatureVerificationAlgorithm::public_key_alg_id
    #[must_use]
    pub fn matches_public_key(&self, spki_algorithm: &[u8]) -> bool {
        self.0 == spki_algorithm
            || canonical_public_key_alg_id(spki_algorithm).is_some_and(|key| key == *self)
    }

    /// Whether this identifier, the [`signature_alg_id`] of a verification
    /// algorithm, matches the contents of a certificate's or CRL's
    /// `signatureAlgorithm`: they are equal byte for byte, or the input is an
    /// `id-RSASSA-PSS` identifier whose [`canonical_signature_alg_id`] is
    /// this identifier. As for [`Self::matches_public_key`], only the input
    /// is canonicalised.
    ///
    /// [`signature_alg_id`]: crate::SignatureVerificationAlgorithm::signature_alg_id
    #[must_use]
    pub fn matches_signature(&self, signature_algorithm: &[u8]) -> bool {
        self.0 == signature_algorithm
            || canonical_signature_alg_id(signature_algorithm).is_some_and(|sig| sig == *self)
    }

    /// [`Self::matches_public_key`] or [`Self::matches_signature`] with the
    /// input's canonical form computed once by the caller.
    pub(crate) fn matches_given(&self, input: &[u8], canonical: Option<Self>) -> bool {
        self.0 == input || canonical.is_some_and(|c| c == *self)
    }
}

/// The canonical identifier of an `id-RSASSA-PSS` `SubjectPublicKeyInfo`
/// algorithm (the `AlgorithmIdentifier` contents), or `None` for any other
/// algorithm and for parameters outside the supported set.
///
/// * Absent parameters: [`RSASSA_PSS`] (RFC 4055 §3.3, case 2: any hash).
/// * Parameters with hash `H` (SHA-256, SHA-384 or SHA-512), MGF1 over `H`
///   (both hash identifiers with NULL or absent parameters, RFC 4055
///   §2.1), a `saltLength` absent (DEFAULT 20) or at most the digest length
///   (a minimum, RFC 4055 §3.3, case 3, which the digest-length salts of
///   TLS meet) and a `trailerField` absent or 1 (RFC 4055 §3.1):
///   [`RSASSA_PSS_SHA256_KEY`], [`RSASSA_PSS_SHA384_KEY`] or
///   [`RSASSA_PSS_SHA512_KEY`].
///
/// Malformed or non-DER parameters (X.690 §11.5; the explicit trailer field
/// 1, which RFC 4055 §3.1 requires validators to recognise, excepted) and
/// other hashes, mask generation functions, longer minimum salts or trailer
/// fields give `None`. `browntls_crypto::rsa::RsaKeyAlgorithm` accepts the
/// same set when it loads keys.
#[must_use]
pub fn canonical_public_key_alg_id(contents: &[u8]) -> Option<AlgorithmIdentifier> {
    rsassa_pss::public_key(contents).ok()
}

/// The canonical identifier of an `id-RSASSA-PSS` signature algorithm (the
/// `AlgorithmIdentifier` contents), or `None` for any other algorithm and
/// for parameters outside the supported set.
///
/// The parameters must be present (RFC 4055 §3.1) and are read as for
/// [`canonical_public_key_alg_id`], except that `saltLength` must be the
/// digest length: the only salt a TLS signature scheme describes (RFC 9846
/// §4.3.3). The result is [`RSA_PSS_SHA256`], [`RSA_PSS_SHA384`] or
/// [`RSA_PSS_SHA512`].
#[must_use]
pub fn canonical_signature_alg_id(contents: &[u8]) -> Option<AlgorithmIdentifier> {
    rsassa_pss::signature(contents).ok()
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
/// restrict it to SHA-256 and MGF1(SHA-256) (RFC 4055 §3.1): the canonical
/// form ([`canonical_public_key_alg_id`]) of every such key, whatever its
/// minimum salt length (up to 32 bytes) and other equivalent encodings.
///
/// The encoding is that of [`RSA_PSS_SHA256`], with a 32-byte salt: the
/// parameters of the signatures such a key makes in TLS (RFC 9846 §4.3.3),
/// and OpenSSL's encoding for `rsa_pss_keygen_saltlen:32`.
pub const RSASSA_PSS_SHA256_KEY: AlgorithmIdentifier = RSA_PSS_SHA256;

/// AlgorithmIdentifier of an `id-RSASSA-PSS` public key restricted to
/// SHA-384 and MGF1(SHA-384), with a minimum salt of up to 48 bytes, in
/// canonical form; the encoding of [`RSA_PSS_SHA384`].
pub const RSASSA_PSS_SHA384_KEY: AlgorithmIdentifier = RSA_PSS_SHA384;

/// AlgorithmIdentifier of an `id-RSASSA-PSS` public key restricted to
/// SHA-512 and MGF1(SHA-512), with a minimum salt of up to 64 bytes, in
/// canonical form; the encoding of [`RSA_PSS_SHA512`].
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

    #[test]
    fn only_the_input_is_canonicalised() {
        use crate::rsassa_pss::testing::{S256, restricted};
        // A non-canonical algorithm identifier (minimum salt 0) matches only
        // its own bytes, not a key whose minimum is the digest length.
        let salt0 = restricted(S256, false, false, Some(0), false);
        let alg = AlgorithmIdentifier::from_slice(alloc::boxed::Box::leak(
            salt0.clone().into_boxed_slice(),
        ));
        assert!(alg.matches_public_key(&salt0));
        assert!(!alg.matches_public_key(RSASSA_PSS_SHA256_KEY.as_bytes()));
        // The canonical constant matches every equivalent encoding.
        assert!(RSASSA_PSS_SHA256_KEY.matches_public_key(&salt0));
        assert!(RSASSA_PSS_SHA256_KEY.matches_public_key(RSASSA_PSS_SHA256_KEY.as_bytes()));
    }

    #[test]
    fn equivalent_pss_encodings_match_the_canonical_algorithms() {
        use crate::rsassa_pss::testing::{
            S256, S384, hash_field, mgf_field, pss, restricted, salt, trailer,
        };
        use crate::signed_data::verify_signature;
        static ALGS: [&dyn SignatureVerificationAlgorithm; 3] = [
            &AcceptAll {
                public_key: RSASSA_PSS,
                signature: RSA_PSS_SHA384,
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
        let check = |key: &[u8], sig: &[u8]| {
            let spki = Spki {
                algorithm: key,
                key: &[],
            };
            let signed = SignedData {
                data: &[],
                algorithm: sig,
                signature: &[],
            };
            verify_signed_data(&ALGS, &spki, &signed, &mut Budget::default())
        };
        // Keys restricted to SHA-256: absent hash parameters, the DEFAULT
        // (20) and 0 as minimum salt lengths, an explicit trailer field 1.
        let keys256 = [
            restricted(S256, false, false, Some(32), false),
            restricted(S256, true, false, None, false),
            restricted(S256, false, true, Some(0), true),
            restricted(S256, true, true, Some(31), true),
        ];
        // SHA-256 signature identifiers (salt 32) written differently.
        let sigs256 = [
            RSA_PSS_SHA256.as_bytes().to_vec(),
            restricted(S256, false, false, Some(32), false),
            restricted(S256, true, true, Some(32), true),
        ];
        let sig384 = restricted(S384, false, true, Some(48), true);
        for key in &keys256 {
            assert_eq!(
                canonical_public_key_alg_id(key),
                Some(RSASSA_PSS_SHA256_KEY)
            );
            assert!(RSASSA_PSS_SHA256_KEY.matches_public_key(key));
            assert!(!RSASSA_PSS_SHA384_KEY.matches_public_key(key));
            assert!(!RSASSA_PSS.matches_public_key(key));
            for sig in &sigs256 {
                assert_eq!(check(key, sig), Ok(()), "{}", hex::encode(key));
            }
            // Still only its own hash.
            assert_eq!(
                check(key, &sig384),
                Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
            );
            for alg in ALGS {
                let spki = Spki {
                    algorithm: key,
                    key: &[],
                };
                let matched = alg.public_key_alg_id() == RSASSA_PSS_SHA256_KEY;
                assert_eq!(
                    verify_signature(alg, &spki, &[], &[]).is_ok(),
                    matched,
                    "{alg:?}"
                );
            }
        }
        for sig in &sigs256 {
            assert_eq!(canonical_signature_alg_id(sig), Some(RSA_PSS_SHA256));
            assert!(RSA_PSS_SHA256.matches_signature(sig));
            assert!(!RSA_PSS_SHA384.matches_signature(sig));
        }
        // The unrestricted key and the SHA-384 signature in another form.
        assert_eq!(check(RSASSA_PSS.as_bytes(), &sig384), Ok(()));
        assert_eq!(
            check(&restricted(S384, true, true, Some(0), false), &sig384),
            Ok(())
        );
        // Signature salts other than the digest length match nothing, even
        // where the key's minimum allows them (no TLS scheme has them).
        for sig in [
            restricted(S256, true, true, None, false),
            restricted(S256, true, true, Some(0), false),
            restricted(S256, true, true, Some(31), false),
            restricted(S256, true, true, Some(64), false),
        ] {
            assert_eq!(canonical_signature_alg_id(&sig), None);
            assert_eq!(
                check(&keys256[1], &sig),
                Err(Error::UnsupportedSignatureAlgorithm)
            );
        }
        // Keys outside the supported set match nothing.
        for key in [
            pss(&[hash_field(S256, true), salt(&[32])]),
            restricted(S256, true, true, Some(33), false),
            pss(&[hash_field(S256, true), mgf_field(S256, true), salt(&[20])]),
            pss(&[hash_field(S256, true), mgf_field(S256, true), trailer(&[2])]),
            [RSASSA_PSS.as_bytes(), &[0x05, 0x00]].concat(),
        ] {
            assert_eq!(canonical_public_key_alg_id(&key), None);
            assert!(!RSASSA_PSS_SHA256_KEY.matches_public_key(&key));
            assert_eq!(
                check(&key, RSA_PSS_SHA256.as_bytes()),
                Err(Error::UnsupportedSignatureAlgorithmForPublicKey),
                "{}",
                hex::encode(&key)
            );
        }
        // Other algorithms keep byte-for-byte matching.
        assert!(RSA_ENCRYPTION.matches_public_key(RSA_ENCRYPTION.as_bytes()));
        assert!(!RSA_ENCRYPTION.matches_public_key(RSASSA_PSS.as_bytes()));
        assert!(!RSASSA_PSS.matches_public_key(RSA_ENCRYPTION.as_bytes()));
        assert!(!ECDSA_P256.matches_public_key(&ECDSA_P256.as_bytes()[..18]));
        assert_eq!(canonical_public_key_alg_id(ED25519.as_bytes()), None);
        assert_eq!(
            canonical_signature_alg_id(RSA_PKCS1_SHA256.as_bytes()),
            None
        );
    }
}
