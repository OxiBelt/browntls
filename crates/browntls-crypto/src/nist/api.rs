//! The public per-curve API, instantiated by [`curve_module!`] in `p256`,
//! `p384` and `p521`.
//!
//! Each module wraps the generic implementation for one parameter set. Point
//! multiplications go through `$fast` when `$accel()` reports the required CPU
//! features and through the portable `$soft` otherwise; both share constants.

macro_rules! curve_module {
    (
        name = $doc_name:literal,
        soft = $soft:ty,
        fast = $fast:ty,
        accel = $accel:expr,
        limbs = $n:literal,
        field_len = $field_len:literal,
        tls_hash = $tls_hash:ident
    ) => {
        use crate::Error;
        use crate::hash::{DynHash, HashAlgorithm};
        use crate::nist::curve::{Affine, Curve};
        use crate::nist::{ecdsa, keys};
        use crate::rand::SecureRandom;
        use crate::zeroize::Zeroizing;

        /// Length of a field element and of a scalar, in bytes.
        pub const FIELD_LEN: usize = $field_len;
        /// Length of an uncompressed SEC 1 point (`04 || X || Y`).
        pub const UNCOMPRESSED_LEN: usize = 1 + 2 * $field_len;
        /// Length of the fixed-size `r || s` signature form.
        pub const SIGNATURE_FIXED_LEN: usize = 2 * $field_len;
        /// Maximum length of a DER-encoded signature.
        pub const SIGNATURE_DER_MAX_LEN: usize = ecdsa::der_max_len($field_len);
        /// Maximum length of a `SubjectPublicKeyInfo` written by [`PublicKey::to_spki_der`].
        pub const SPKI_MAX_LEN: usize = 32 + UNCOMPRESSED_LEN;
        /// Maximum length of an RFC 5915 `ECPrivateKey` written by [`SecretKey::to_sec1_der`].
        pub const SEC1_PRIVATE_MAX_LEN: usize = 24 + FIELD_LEN + UNCOMPRESSED_LEN;
        /// DER contents of the curve's `namedCurve` OBJECT IDENTIFIER.
        pub const OID: &[u8] = <$soft as Curve<$n>>::OID;
        /// The hash TLS pairs with this curve in its ECDSA signature schemes.
        pub const TLS_HASH: HashAlgorithm = HashAlgorithm::$tls_hash;

        fn public_point(d: &keys::SecretScalar<$n>) -> Result<Affine<$n>, Error> {
            if $accel {
                keys::public_key::<$fast, $n>(d)
            } else {
                keys::public_key::<$soft, $n>(d)
            }
        }

        #[doc = concat!("A ", $doc_name, " private key: a scalar in `[1, n - 1]`, zeroised on drop.")]
        #[derive(Clone)]
        pub struct SecretKey {
            d: keys::SecretScalar<$n>,
            public: Affine<$n>,
        }

        impl core::fmt::Debug for SecretKey {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("SecretKey(..)")
            }
        }

        impl SecretKey {
            fn from_scalar(
                d: keys::SecretScalar<$n>,
                expected_public: Option<Affine<$n>>,
            ) -> Result<Self, Error> {
                let public = public_point(&d)?;
                if expected_public.is_some_and(|p| p != public) {
                    return Err(Error::InvalidKey);
                }
                Ok(Self { d, public })
            }

            /// Generates a random key.
            ///
            /// # Errors
            ///
            /// Returns [`Error::RandomFailure`] if `rng` fails.
            pub fn generate(rng: &dyn SecureRandom) -> Result<Self, Error> {
                Self::from_scalar(keys::generate::<$soft, $n>(rng)?, None)
            }

            /// Loads a big-endian scalar of exactly [`FIELD_LEN`] bytes.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidKey`] unless `1 <= d < n`.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Self::from_scalar(keys::scalar_from_bytes::<$soft, $n>(bytes, true)?, None)
            }

            /// Parses an RFC 5915 `ECPrivateKey`. A curve OID, if present, must
            /// name this curve; an embedded public key must match `d * G`.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidEncoding`] or [`Error::InvalidKey`].
            pub fn from_sec1_der(der: &[u8]) -> Result<Self, Error> {
                let (d, public) = keys::decode_sec1_private::<$soft, $n>(der)?;
                Self::from_scalar(d, public)
            }

            /// Parses a PKCS#8 `PrivateKeyInfo` / `OneAsymmetricKey` carrying an
            /// `id-ecPublicKey` key on this curve.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidEncoding`] or [`Error::InvalidKey`].
            pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
                let (d, public) = keys::decode_pkcs8::<$soft, $n>(der)?;
                Self::from_scalar(d, public)
            }

            /// The scalar as [`FIELD_LEN`] big-endian bytes.
            #[must_use]
            pub fn to_bytes(&self) -> Zeroizing<[u8; FIELD_LEN]> {
                let mut out = Zeroizing([0u8; FIELD_LEN]);
                keys::scalar_to_bytes(&self.d, &mut out[..]);
                out
            }

            /// Writes an RFC 5915 `ECPrivateKey` (with curve OID and public key)
            /// into `out` and returns its length.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidLength`] if `out` is shorter than
            /// [`SEC1_PRIVATE_MAX_LEN`].
            pub fn to_sec1_der(&self, out: &mut [u8]) -> Result<usize, Error> {
                keys::encode_sec1_private::<$soft, $n>(&self.d, &self.public, out)
            }

            /// The corresponding public key.
            #[must_use]
            pub fn public_key(&self) -> PublicKey {
                PublicKey { point: self.public }
            }

            /// ECDH: the x-coordinate of `d * peer` (constant time in `d`).
            ///
            /// # Errors
            ///
            /// Returns [`Error::KeyAgreementFailed`] if the product is the identity,
            /// which cannot happen for a validated `peer`.
            pub fn diffie_hellman(&self, peer: &PublicKey) -> Result<[u8; FIELD_LEN], Error> {
                let mut out = [0u8; FIELD_LEN];
                if $accel {
                    keys::ecdh::<$fast, $n>(&self.d, &peer.point, &mut out)?;
                } else {
                    keys::ecdh::<$soft, $n>(&self.d, &peer.point, &mut out)?;
                }
                Ok(out)
            }
        }

        #[doc = concat!("A validated ", $doc_name, " public key (a point of prime order).")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct PublicKey {
            point: Affine<$n>,
        }

        impl PublicKey {
            /// Parses a SEC 1 point: uncompressed `04 || X || Y` or compressed
            /// `02/03 || X`. The identity and hybrid forms are rejected.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidEncoding`] for malformed input and
            /// [`Error::InvalidKey`] for coordinates `>= p` or points off the curve.
            pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(Self {
                    point: keys::decode_point::<$soft, $n>(bytes)?,
                })
            }

            /// Parses a `SubjectPublicKeyInfo` with `id-ecPublicKey` and this
            /// curve's `namedCurve` OID.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidEncoding`] or [`Error::InvalidKey`].
            pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
                Ok(Self {
                    point: keys::decode_spki::<$soft, $n>(der)?,
                })
            }

            /// The uncompressed SEC 1 encoding.
            #[must_use]
            pub fn to_uncompressed(&self) -> [u8; UNCOMPRESSED_LEN] {
                let mut out = [0u8; UNCOMPRESSED_LEN];
                keys::encode_uncompressed::<$soft, $n>(&self.point, &mut out);
                out
            }

            /// Writes a `SubjectPublicKeyInfo` into `out` and returns its length.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidLength`] if `out` is shorter than [`SPKI_MAX_LEN`].
            pub fn to_spki_der(&self, out: &mut [u8]) -> Result<usize, Error> {
                keys::encode_spki::<$soft, $n>(&self.point, out)
            }
        }

        #[doc = concat!("An ECDSA signing key on ", $doc_name, ".")]
        #[derive(Clone, Debug)]
        pub struct SigningKey {
            secret: SecretKey,
        }

        impl SigningKey {
            /// Wraps a private key.
            #[must_use]
            pub fn new(secret: SecretKey) -> Self {
                Self { secret }
            }

            /// Generates a random signing key.
            ///
            /// # Errors
            ///
            /// Returns [`Error::RandomFailure`] if `rng` fails.
            pub fn generate(rng: &dyn SecureRandom) -> Result<Self, Error> {
                Ok(Self::new(SecretKey::generate(rng)?))
            }

            /// The wrapped private key.
            #[must_use]
            pub fn secret_key(&self) -> &SecretKey {
                &self.secret
            }

            /// The public key that verifies this key's signatures.
            #[must_use]
            pub fn verifying_key(&self) -> PublicKey {
                self.secret.public_key()
            }

            /// Signs `msg` hashed with `hash`, using an RFC 6979 nonce hedged
            /// with 32 bytes from `rng` (RFC 6979 section 3.6). TLS uses
            /// [`TLS_HASH`]; any supported hash is accepted.
            ///
            /// # Errors
            ///
            /// Returns [`Error::RandomFailure`] if `rng` fails.
            pub fn sign(
                &self,
                hash: HashAlgorithm,
                msg: &[u8],
                rng: &dyn SecureRandom,
            ) -> Result<Signature, Error> {
                let digest = DynHash::digest(hash, msg);
                self.sign_prehashed(hash, digest.as_ref(), Some(rng))
            }

            /// Signs `msg` with a purely deterministic RFC 6979 nonce.
            ///
            /// # Errors
            ///
            /// Returns [`Error::RandomFailure`] in the (practically impossible)
            /// event that no valid nonce is found.
            pub fn sign_deterministic(
                &self,
                hash: HashAlgorithm,
                msg: &[u8],
            ) -> Result<Signature, Error> {
                let digest = DynHash::digest(hash, msg);
                self.sign_prehashed(hash, digest.as_ref(), None)
            }

            /// Signs a precomputed `digest` of `hash` (its length must match the
            /// hash's output length); `rng`, if given, hedges the nonce.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidLength`] on a digest length mismatch and
            /// [`Error::RandomFailure`] if `rng` fails.
            pub fn sign_prehashed(
                &self,
                hash: HashAlgorithm,
                digest: &[u8],
                rng: Option<&dyn SecureRandom>,
            ) -> Result<Signature, Error> {
                if digest.len() != hash.output_len() {
                    return Err(Error::InvalidLength);
                }
                let mut extra = Zeroizing([0u8; 32]);
                let extra = match rng {
                    Some(rng) => {
                        rng.fill(&mut extra[..])?;
                        Some(&extra[..])
                    }
                    None => None,
                };
                let (r, s) = if $accel {
                    ecdsa::sign::<$fast, $n>(&self.secret.d, hash, digest, extra)?
                } else {
                    ecdsa::sign::<$soft, $n>(&self.secret.d, hash, digest, extra)?
                };
                Signature::from_scalars(&r, &s)
            }
        }

        #[doc = concat!("An ECDSA signature on ", $doc_name, " in DER and fixed (`r || s`) form.")]
        #[derive(Clone, Copy)]
        pub struct Signature {
            der: [u8; SIGNATURE_DER_MAX_LEN],
            der_len: usize,
            fixed: [u8; SIGNATURE_FIXED_LEN],
        }

        impl core::fmt::Debug for Signature {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("Signature").field("der", &self.as_der()).finish()
            }
        }

        impl PartialEq for Signature {
            fn eq(&self, other: &Self) -> bool {
                self.fixed == other.fixed
            }
        }

        impl Eq for Signature {}

        impl Signature {
            fn from_scalars(r: &[u64; $n], s: &[u64; $n]) -> Result<Self, Error> {
                let mut sig = Self {
                    der: [0; SIGNATURE_DER_MAX_LEN],
                    der_len: 0,
                    fixed: [0; SIGNATURE_FIXED_LEN],
                };
                sig.der_len = ecdsa::encode_der::<$soft, $n>(r, s, &mut sig.der)?;
                ecdsa::encode_fixed::<$soft, $n>(r, s, &mut sig.fixed);
                Ok(sig)
            }

            /// Parses a strict DER `Ecdsa-Sig-Value` with `1 <= r, s < n`.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidEncoding`].
            pub fn from_der(der: &[u8]) -> Result<Self, Error> {
                let (r, s) = ecdsa::decode_der::<$soft, $n>(der)?;
                Self::from_scalars(&r, &s)
            }

            /// Parses the fixed-size `r || s` form with `1 <= r, s < n`.
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidEncoding`].
            pub fn from_fixed(bytes: &[u8]) -> Result<Self, Error> {
                let (r, s) = ecdsa::decode_fixed::<$soft, $n>(bytes)?;
                Self::from_scalars(&r, &s)
            }

            /// The DER encoding (the form used by TLS and X.509).
            #[must_use]
            pub fn as_der(&self) -> &[u8] {
                &self.der[..self.der_len]
            }

            /// The fixed-size `r || s` encoding.
            #[must_use]
            pub fn fixed(&self) -> &[u8; SIGNATURE_FIXED_LEN] {
                &self.fixed
            }
        }

        fn verify_scalars(
            public: &PublicKey,
            digest: &[u8],
            r: &[u64; $n],
            s: &[u64; $n],
        ) -> Result<(), Error> {
            if $accel {
                ecdsa::verify::<$fast, $n>(&public.point, digest, r, s)
            } else {
                ecdsa::verify::<$soft, $n>(&public.point, digest, r, s)
            }
        }

        /// Verifies a DER signature over `msg` hashed with `hash`. Any supported
        /// hash is accepted (X.509 allows, for example, P-256 with SHA-384).
        /// Variable time: all inputs are public.
        ///
        /// # Errors
        ///
        /// Returns [`Error::InvalidSignature`] for any malformed or non-verifying
        /// signature.
        pub fn verify(
            public: &PublicKey,
            hash: HashAlgorithm,
            msg: &[u8],
            sig_der: &[u8],
        ) -> Result<(), Error> {
            let digest = DynHash::digest(hash, msg);
            verify_prehashed(public, digest.as_ref(), sig_der)
        }

        /// Verifies a fixed-size `r || s` signature over `msg` hashed with `hash`.
        ///
        /// # Errors
        ///
        /// Returns [`Error::InvalidSignature`].
        pub fn verify_fixed(
            public: &PublicKey,
            hash: HashAlgorithm,
            msg: &[u8],
            sig: &[u8],
        ) -> Result<(), Error> {
            let digest = DynHash::digest(hash, msg);
            let (r, s) =
                ecdsa::decode_fixed::<$soft, $n>(sig).map_err(|_| Error::InvalidSignature)?;
            verify_scalars(public, digest.as_ref(), &r, &s)
        }

        /// Verifies a DER signature over a precomputed `digest`.
        ///
        /// # Errors
        ///
        /// Returns [`Error::InvalidSignature`].
        pub fn verify_prehashed(
            public: &PublicKey,
            digest: &[u8],
            sig_der: &[u8],
        ) -> Result<(), Error> {
            let (r, s) =
                ecdsa::decode_der::<$soft, $n>(sig_der).map_err(|_| Error::InvalidSignature)?;
            verify_scalars(public, digest, &r, &s)
        }
    };
}

pub(crate) use curve_module;
