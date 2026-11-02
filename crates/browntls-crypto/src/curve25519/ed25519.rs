//! Ed25519 signatures (RFC 8032 §5.1, "pure" Ed25519 without context).
//!
//! # Verification policy
//!
//! [`VerifyingKey::verify`] accepts a signature `(R, S)` on `M` under `A` iff
//!
//! 1. `S < L` (canonical scalar; rejects the classic malleability `S + L`);
//! 2. `A` decodes canonically (`y < p`, no "negative zero" `x`), lies on the
//!    curve and is **not of small order** (checked once in
//!    [`VerifyingKey::from_bytes`]; a small-order key would make one
//!    signature valid for every message);
//! 3. the cofactorless equation `[S]B = R + [k]A` holds with
//!    `k = SHA-512(R || A || M) mod L`, checked as
//!    `encode([S]B - [k]A) == R` byte for byte. Because the left side is a
//!    canonical encoding, this also rejects any non-canonical or off-curve
//!    `R`, so `R` needs no separate decoding.
//!
//! This is RFC 8032's sufficient check plus canonicity, the same equation as
//! BoringSSL and ring and as ed25519-dalek's `verify_strict` for `A`.
//! Unlike `verify_strict` it does not reject small-order `R`: an honest
//! signer produces such an `R` with negligible probability, and the
//! cofactorless byte comparison already determines a unique valid `R`.
//! Against Wycheproof `ed25519_test.json` every "valid" vector verifies and
//! every "invalid" vector is rejected; "acceptable" small-order keys are
//! rejected, and "acceptable" mixed-order keys are judged by the equation.
//!
//! Signing is constant time (fixed-base comb, constant-time scalar
//! arithmetic); verification is variable time over public data only.

use super::edwards::{self, EdwardsPoint};
use super::scalar::{self, Scalar};
use crate::Error;
use crate::der;
use crate::hash::{HashFunction, Sha512};
use crate::rand::SecureRandom;
use crate::zeroize::Zeroize;

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of an encoded public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a private-key seed.
pub const SEED_LEN: usize = 32;
/// The `id-Ed25519` object identifier (1.3.101.112), DER contents.
pub const OID_ED25519: [u8; 3] = [0x2b, 0x65, 0x70];
/// Length of the PKCS#8 v1 encoding produced by [`SigningKey::to_pkcs8_der`].
pub const PKCS8_V1_LEN: usize = 48;

/// An Ed25519 public key (validated, decompressed).
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    bytes: [u8; 32],
    /// `-A`, so that verification computes `[S]B + [k](-A)`.
    minus_a: EdwardsPoint,
}

impl VerifyingKey {
    /// Parses and validates an encoded public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for non-canonical encodings, points not
    /// on the curve and small-order points.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let a = EdwardsPoint::decompress(bytes).ok_or(Error::InvalidKey)?;
        if a.is_small_order() {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            bytes: *bytes,
            minus_a: a.neg(),
        })
    }

    /// Parses a public key from a slice.
    ///
    /// # Errors
    ///
    /// As [`Self::from_bytes`], plus [`Error::InvalidKey`] for a wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let b: &[u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Self::from_bytes(b)
    }

    /// The 32-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Verifies `sig` on `msg` (see the module documentation for the policy).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if the signature does not verify.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        if !scalar::is_canonical(&s) {
            return Err(Error::InvalidSignature);
        }
        let mut h = Sha512::new();
        h.update(&r);
        h.update(&self.bytes);
        h.update(msg);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize()).to_bytes();
        let check = edwards::vartime_double_scalar_mul_base(&k, &self.minus_a, &s);
        if check == r {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifyingKey").field(&self.bytes).finish()
    }
}

/// An Ed25519 private key. Secret material is zeroised on drop.
pub struct SigningKey {
    seed: [u8; 32],
    /// Clamped secret scalar `s` (RFC 8032 §5.1.5) reduced mod L.
    s: Scalar,
    prefix: [u8; 32],
    public: VerifyingKey,
}

impl SigningKey {
    /// Expands a 32-byte seed (the RFC 8032 private key).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = Sha512::digest(seed);
        let mut s_bytes = [0u8; 32];
        let mut prefix = [0u8; 32];
        s_bytes.copy_from_slice(&h[..32]);
        prefix.copy_from_slice(&h[32..]);
        h.zeroize();
        s_bytes[0] &= 248;
        s_bytes[31] &= 127;
        s_bytes[31] |= 64;
        let a = EdwardsPoint::mul_base(&s_bytes);
        let s = Scalar::from_bytes_mod_order(&s_bytes);
        s_bytes.zeroize();
        Self {
            seed: *seed,
            s,
            prefix,
            // The public key of an honest key is never small order (its
            // scalar is a non-zero multiple of 8 below 8L times B).
            public: VerifyingKey {
                bytes: a.compress(),
                minus_a: a.neg(),
            },
        }
    }

    /// Generates a key from `rng`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomFailure`] if the random source fails.
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        let res = rng.fill(&mut seed).map(|()| Self::from_seed(&seed));
        seed.zeroize();
        res
    }

    /// Parses an RFC 8410 PKCS#8 `OneAsymmetricKey` (RFC 5958 v1 or v2).
    ///
    /// The algorithm must be `id-Ed25519` without parameters and the private
    /// key a 32-byte `CurvePrivateKey`. Attributes are ignored. A v2 public
    /// key, if present, must equal the key derived from the seed; v1
    /// encodings must not carry one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for malformed DER and
    /// [`Error::InvalidKey`] for a wrong algorithm, key length or mismatched
    /// public key.
    pub fn from_pkcs8_der(der_bytes: &[u8]) -> Result<Self, Error> {
        let (seed, public) = der::parse_sequence(der_bytes, |r| {
            let version = r.read_small_integer()?;
            if version > 1 {
                return Err(Error::InvalidEncoding);
            }
            let mut alg = r.read_sequence()?;
            if alg.read_oid()? != OID_ED25519 {
                return Err(Error::InvalidKey);
            }
            alg.finish().map_err(|_| Error::InvalidKey)?;
            let mut inner = der::Reader::new(r.read_octet_string()?);
            let seed = inner.read_octet_string()?;
            inner.finish()?;
            let seed: [u8; 32] = seed.try_into().map_err(|_| Error::InvalidKey)?;
            let _attributes = r.read_optional(der::tag::context_constructed(0))?;
            let public = r.read_optional(der::tag::context_primitive(1))?;
            let public = match (version, public) {
                (_, None) => None,
                (0, Some(_)) => return Err(Error::InvalidEncoding),
                (_, Some([0, rest @ ..])) => {
                    Some(<[u8; 32]>::try_from(rest).map_err(|_| Error::InvalidKey)?)
                }
                (_, Some(_)) => return Err(Error::InvalidEncoding),
            };
            Ok((seed, public))
        })?;
        let key = Self::from_seed(&seed);
        let mut seed = seed;
        seed.zeroize();
        match public {
            Some(p) if p != key.public.bytes => Err(Error::InvalidKey),
            _ => Ok(key),
        }
    }

    /// Encodes the key as an RFC 8410 PKCS#8 v1 `OneAsymmetricKey`.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> crate::zeroize::Zeroizing<[u8; PKCS8_V1_LEN]> {
        let mut out = crate::zeroize::Zeroizing([0u8; PKCS8_V1_LEN]);
        out[..16].copy_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        out[16..].copy_from_slice(&self.seed);
        out
    }

    /// The 32-byte seed.
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The corresponding public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.public
    }

    /// Signs `msg` (deterministic, RFC 8032 §5.1.6).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(&self.prefix);
        h.update(msg);
        let mut r_wide = h.finalize();
        let mut r = Scalar::from_bytes_mod_order_wide(&r_wide);
        let mut r_bytes = r.to_bytes();
        let big_r = EdwardsPoint::mul_base(&r_bytes).compress();

        let mut h = Sha512::new();
        h.update(&big_r);
        h.update(&self.public.bytes);
        h.update(msg);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize());
        let s = Scalar::mul_add(&k, &self.s, &r);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&s.to_bytes());
        r_wide.zeroize();
        r_bytes.zeroize();
        r.zeroize();
        sig
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.s.zeroize();
        self.prefix.zeroize();
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
