//! Ed448 signatures (RFC 8032 §5.2, PureEdDSA with `dom4(0, context)`).
//!
//! TLS uses Ed448 with an empty context (RFC 9846 §4.2.3, RFC 8422 §5.10):
//! [`SigningKey::sign`] and [`VerifyingKey::verify`]. The `*_with_context`
//! variants take a context of at most 255 octets (RFC 8032 §5.2). The
//! prehashed variant Ed448ph is not implemented.
//!
//! # Verification policy
//!
//! [`VerifyingKey::verify`] accepts a signature `ENC(R) || ENC(S)` on `M`
//! under `A` iff
//!
//! 1. the signature is exactly 114 bytes and `S < L` (RFC 8032 §5.2.7
//!    step 1; rejects the malleability `S + L` and any `S >= 2^448`);
//! 2. `A` and `R` decode strictly per RFC 8032 §5.2.3: `y < p` (so the
//!    unused bits 448..454 are zero), the point is on the curve, and `x = 0`
//!    with the sign bit set is rejected;
//! 3. `A` is **not of small order** (checked once in
//!    [`VerifyingKey::from_bytes`]): with `[4]A = O` one signature would be
//!    valid for every message;
//! 4. the **cofactored** group equation of RFC 8032 §5.2.7 step 3 holds,
//!    `[4]([S]B - R - [k]A) = O` with
//!    `k = SHAKE256(dom4(0, C) || ENC(R) || ENC(A) || M, 114) mod L`.
//!
//! The cofactored equation is the one RFC 8032 §5.2.7 states; the
//! cofactorless `[S]B = R + [k]A` is only "sufficient, but not required".
//! The two differ only for adversarially constructed signatures whose
//! `[S]B - R - [k]A` is a non-zero point of order 2 or 4, which no honest
//! signer produces. The cofactored check is the one batch verification can
//! reproduce, and it agrees with implementations that follow the main text
//! (OpenSSL's Ed448 also clears the cofactor). Against Wycheproof
//! `ed448_test.json` (all vectors are "valid" or "invalid") every valid
//! vector verifies and every invalid vector is rejected.
//!
//! Key generation and signing are constant time (fixed-window scalar
//! multiplication, constant-time scalar arithmetic); verification is
//! variable time over public data only.

use super::edwards::{self, EdwardsPoint};
use super::scalar::{self, Scalar};
use crate::Error;
use crate::der;
use crate::hash::Shake256;
use crate::rand::SecureRandom;
use crate::zeroize::Zeroize;

/// Length of an Ed448 signature.
pub const SIGNATURE_LEN: usize = 114;
/// Length of an encoded public key.
pub const PUBLIC_KEY_LEN: usize = 57;
/// Length of a private key (the RFC 8032 §5.2.5 57-octet seed).
pub const SEED_LEN: usize = 57;
/// Maximum context length (RFC 8032 §5.2).
pub const MAX_CONTEXT_LEN: usize = 255;
/// The `id-Ed448` object identifier (1.3.101.113, RFC 8410 §3), DER contents.
pub const OID_ED448: [u8; 3] = [0x2b, 0x65, 0x71];
/// Length of the PKCS#8 v1 encoding produced by [`SigningKey::to_pkcs8_der`].
pub const PKCS8_V1_LEN: usize = 73;

/// `SHAKE256(dom4(0, context) || parts..., 114)` (RFC 8032 §5.2: `H(x)`).
fn hash_dom4(context: &[u8], parts: &[&[u8]]) -> [u8; 114] {
    debug_assert!(context.len() <= MAX_CONTEXT_LEN);
    let mut h = Shake256::new();
    h.update(b"SigEd448");
    // phflag = 0 (PureEdDSA); the context length is at most 255.
    h.update(&[0, context.len() as u8]);
    h.update(context);
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 114];
    h.finalize_xof().read(&mut out);
    out
}

/// An Ed448 public key (validated, decompressed).
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    bytes: [u8; 57],
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
    pub fn from_bytes(bytes: &[u8; 57]) -> Result<Self, Error> {
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
        let b: &[u8; 57] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Self::from_bytes(b)
    }

    /// The 57-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 57] {
        &self.bytes
    }

    /// Verifies `sig` on `msg` with an empty context (Ed448 as used by TLS).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if the signature does not verify.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 114]) -> Result<(), Error> {
        self.verify_with_context(&[], msg, sig)
    }

    /// Verifies `sig` on `msg` under `context` (see the module documentation
    /// for the policy).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if the signature does not verify
    /// or `context` is longer than 255 bytes.
    pub fn verify_with_context(
        &self,
        context: &[u8],
        msg: &[u8],
        sig: &[u8; 114],
    ) -> Result<(), Error> {
        if context.len() > MAX_CONTEXT_LEN {
            return Err(Error::InvalidSignature);
        }
        let mut r_bytes = [0u8; 57];
        let mut s_bytes = [0u8; 57];
        r_bytes.copy_from_slice(&sig[..57]);
        s_bytes.copy_from_slice(&sig[57..]);
        if !scalar::is_canonical(&s_bytes) {
            return Err(Error::InvalidSignature);
        }
        let r = EdwardsPoint::decompress(&r_bytes).ok_or(Error::InvalidSignature)?;
        let s = Scalar::from_bytes_mod_order(&s_bytes);
        let k =
            Scalar::from_bytes_mod_order_wide(&hash_dom4(context, &[&r_bytes, &self.bytes, msg]));
        // [4]([S]B + [k](-A) - R) must be the identity.
        let check = edwards::vartime_double_scalar_mul_base(&k, &self.minus_a, &s)
            .add(&r.neg())
            .double()
            .double();
        if check.is_identity() {
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

/// An Ed448 private key. Secret material is zeroised on drop.
pub struct SigningKey {
    seed: [u8; 57],
    /// The pruned secret scalar `s` (RFC 8032 §5.2.5 steps 2-3) reduced mod L.
    s: Scalar,
    /// `h[57..114]` (RFC 8032 §5.2.6 step 1).
    prefix: [u8; 57],
    public: VerifyingKey,
}

impl SigningKey {
    /// Expands a 57-byte seed (the RFC 8032 §5.2.5 private key).
    #[must_use]
    pub fn from_seed(seed: &[u8; 57]) -> Self {
        let mut h = [0u8; 114];
        Shake256::digest_into(seed, &mut h);
        let mut s_bytes = [0u8; 57];
        let mut prefix = [0u8; 57];
        s_bytes.copy_from_slice(&h[..57]);
        prefix.copy_from_slice(&h[57..]);
        h.zeroize();
        // Prune: clear the two low bits of the first octet, all bits of the
        // last octet, and set the high bit of the second-to-last octet.
        s_bytes[0] &= 0xfc;
        s_bytes[56] = 0;
        s_bytes[55] |= 0x80;
        // [s]B = [s mod L]B because B has order L.
        let s = Scalar::from_bytes_mod_order(&s_bytes);
        s_bytes.zeroize();
        let a = EdwardsPoint::mul_base(&s);
        Self {
            seed: *seed,
            s,
            prefix,
            // An honest key is of small order only if s mod L = 0: among the
            // pruned scalars (2^447 <= s < 2^448, s = 0 mod 4) the only
            // multiple of L is 4L, which a uniform seed hits with probability
            // about 2^-445; otherwise A has order L.
            public: VerifyingKey {
                bytes: a.compress(),
                minus_a: a.neg(),
            },
        }
    }

    /// Generates a key from `rng` (57 random bytes, RFC 8032 §5.2.5).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomFailure`] if the random source fails.
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self, Error> {
        let mut seed = [0u8; 57];
        let res = rng.fill(&mut seed).map(|()| Self::from_seed(&seed));
        seed.zeroize();
        res
    }

    /// Parses an RFC 8410 PKCS#8 `OneAsymmetricKey` (RFC 5958 v1 or v2).
    ///
    /// The algorithm must be `id-Ed448` without parameters (RFC 8410 §3) and
    /// the private key a 57-byte `CurvePrivateKey` (RFC 8410 §7). Attributes
    /// are ignored. A v2 public key, if present, must equal the key derived
    /// from the seed; v1 encodings must not carry one.
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
            if alg.read_oid()? != OID_ED448 {
                return Err(Error::InvalidKey);
            }
            alg.finish().map_err(|_| Error::InvalidKey)?;
            let mut inner = der::Reader::new(r.read_octet_string()?);
            let seed = inner.read_octet_string()?;
            inner.finish()?;
            let seed: [u8; 57] = seed.try_into().map_err(|_| Error::InvalidKey)?;
            let _attributes = r.read_optional(der::tag::context_constructed(0))?;
            let public = r.read_optional(der::tag::context_primitive(1))?;
            let public = match (version, public) {
                (_, None) => None,
                (0, Some(_)) => return Err(Error::InvalidEncoding),
                (_, Some([0, rest @ ..])) => {
                    Some(<[u8; 57]>::try_from(rest).map_err(|_| Error::InvalidKey)?)
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
            0x30, 0x47, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x04, 0x3b,
            0x04, 0x39,
        ]);
        out[16..].copy_from_slice(&self.seed);
        out
    }

    /// The 57-byte seed.
    #[must_use]
    pub fn seed(&self) -> &[u8; 57] {
        &self.seed
    }

    /// The corresponding public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.public
    }

    /// Signs `msg` with an empty context (deterministic, RFC 8032 §5.2.6).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 114] {
        self.sign_inner(&[], msg)
    }

    /// Signs `msg` under `context` (at most 255 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `context` is longer than 255 bytes.
    pub fn sign_with_context(&self, context: &[u8], msg: &[u8]) -> Result<[u8; 114], Error> {
        if context.len() > MAX_CONTEXT_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(self.sign_inner(context, msg))
    }

    fn sign_inner(&self, context: &[u8], msg: &[u8]) -> [u8; 114] {
        // Step 2: r = SHAKE256(dom4(0, C) || prefix || M, 114) mod L.
        let mut r_wide = hash_dom4(context, &[&self.prefix, msg]);
        let mut r = Scalar::from_bytes_mod_order_wide(&r_wide);
        // Step 3: R = [r]B.
        let big_r = EdwardsPoint::mul_base(&r).compress();
        // Steps 4-5: k = SHAKE256(dom4(0, C) || R || A || M, 114);
        // S = (r + k s) mod L.
        let k = Scalar::from_bytes_mod_order_wide(&hash_dom4(
            context,
            &[&big_r, &self.public.bytes, msg],
        ));
        let s = Scalar::mul_add(&k, &self.s, &r);
        // Step 6.
        let mut sig = [0u8; 114];
        sig[..57].copy_from_slice(&big_r);
        sig[57..].copy_from_slice(&s.to_bytes());
        r_wide.zeroize();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A point of order 4: `y = 0`, `x = +-1`.
    fn order4() -> EdwardsPoint {
        let p = EdwardsPoint::decompress(&[0u8; 57]).unwrap();
        assert!(p.is_small_order() && !p.double().is_identity());
        p
    }

    /// Signs with `R = [r]B + T` for a point `T` of order 4: the cofactored
    /// equation of RFC 8032 §5.2.7 accepts the result, the cofactorless one
    /// (`[S]B = R + [k]A`) does not. This pins down which equation is used.
    #[test]
    fn cofactored_equation_accepts_torsion_in_r() {
        let key = SigningKey::from_seed(&[0x42; 57]);
        let msg = b"torsion";
        let r = Scalar::from_bytes_mod_order(&[7u8; 57]);
        let big_r = EdwardsPoint::mul_base(&r).add(&order4()).compress();
        let k =
            Scalar::from_bytes_mod_order_wide(&hash_dom4(&[], &[&big_r, &key.public.bytes, msg]));
        let s = Scalar::mul_add(&k, &key.s, &r);
        let mut sig = [0u8; 114];
        sig[..57].copy_from_slice(&big_r);
        sig[57..].copy_from_slice(&s.to_bytes());
        assert_eq!(key.public.verify(msg, &sig), Ok(()));
        let cofactorless =
            edwards::vartime_double_scalar_mul_base(&k, &key.public.minus_a, &s).compress();
        assert_ne!(cofactorless, big_r);
        // An honest signature satisfies both.
        let honest = key.sign(msg);
        let mut hr = [0u8; 57];
        let mut hs = [0u8; 57];
        hr.copy_from_slice(&honest[..57]);
        hs.copy_from_slice(&honest[57..]);
        let hk = Scalar::from_bytes_mod_order_wide(&hash_dom4(&[], &[&hr, &key.public.bytes, msg]));
        let check = edwards::vartime_double_scalar_mul_base(
            &hk,
            &key.public.minus_a,
            &Scalar::from_bytes_mod_order(&hs),
        );
        assert_eq!(check.compress(), hr);
    }

    #[test]
    fn small_order_keys_are_rejected() {
        let mut minus_one = [0xffu8; 57];
        minus_one[0] = 0xfe;
        minus_one[28] = 0xfe;
        minus_one[56] = 0;
        let mut identity = [0u8; 57];
        identity[0] = 1;
        let order4_pos = [0u8; 57];
        let mut order4_neg = order4_pos;
        order4_neg[56] = 0x80;
        for pk in [identity, minus_one, order4_pos, order4_neg] {
            assert_eq!(VerifyingKey::from_bytes(&pk), Err(Error::InvalidKey));
        }
        // A mixed-order key (A + T) decodes but no honest signature by the
        // key's owner verifies under it (k differs, and so does [k]T).
        let key = SigningKey::from_seed(&[1; 57]);
        let a = EdwardsPoint::decompress(&key.public.bytes).unwrap();
        let mixed = a.add(&order4()).compress();
        let vk = VerifyingKey::from_bytes(&mixed).unwrap();
        assert!(vk.verify(b"m", &key.sign(b"m")).is_err());
    }

    #[test]
    fn context_length_limits() {
        let key = SigningKey::from_seed(&[9; 57]);
        let ctx = [0x55u8; 256];
        assert_eq!(key.sign_with_context(&ctx, b"m"), Err(Error::InvalidLength));
        let sig = key.sign_with_context(&ctx[..255], b"m").unwrap();
        let vk = key.verifying_key();
        assert_eq!(vk.verify_with_context(&ctx[..255], b"m", &sig), Ok(()));
        assert!(vk.verify_with_context(&ctx, b"m", &sig).is_err());
        assert!(vk.verify_with_context(&ctx[..254], b"m", &sig).is_err());
        assert!(vk.verify(b"m", &sig).is_err());
        // An empty context is Ed448 as used by TLS.
        assert_eq!(key.sign_with_context(&[], b"m").unwrap(), key.sign(b"m"));
    }
}
