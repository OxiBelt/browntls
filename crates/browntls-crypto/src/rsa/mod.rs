//! RSA signatures: PKCS #1 v1.5 and PSS (RFC 8017) over constant-time
//! Montgomery arithmetic.
//!
//! # Scope
//!
//! * [`RsaPublicKey`] with [`verify_pkcs1v15`] and [`verify_pss`] for
//!   2048- to 8192-bit moduli (a lower bound of 1024 bits can be opted into
//!   for legacy material through the `*_with_min_bits` constructors) and odd
//!   public exponents `3 <= e < 2^33`, matching the Web PKI profile.
//! * [`RsaPrivateKey`] loaded from PKCS #1 `RSAPrivateKey` or PKCS #8
//!   `PrivateKeyInfo`, or generated with `e = 65537`, signing with the Chinese
//!   remainder theorem.
//! * PSS always uses MGF1 with the message hash and a salt as long as the
//!   digest, as TLS 1.3 requires.
//!
//! # Timing model
//!
//! Private-key operations are constant time with respect to the key and the
//! message: Montgomery multiplication (CIOS) has fixed loop counts, secret
//! exponents are processed with a fixed 4-bit window and constant-time table
//! selection, and every conditional is a mask. In addition, CRT signing
//! blinds the base with a random `r^e` (unblinding by `r^-1` modulo each
//! prime, computed with the constant-time Bernstein–Yang "safegcd"
//! inversion, which has a fixed number of branch-free divsteps for the key
//! size), and the result is checked
//! against the public key before it is released, defeating Bellcore-style
//! fault attacks. Public-key operations (verification, the fault check) are
//! variable time in the public exponent only.
//!
//! # Memory
//!
//! Nothing is heap allocated: values live in fixed-capacity limb arrays
//! (128 × u64 for the modulus, 64 × u64 per CRT half) with the active length
//! tracked. Key structures are therefore large (`RsaPublicKey` ≈ 3 KiB,
//! `RsaPrivateKey` ≈ 8.5 KiB) and callers may want to box them.
//!
//! Peak stack use, measured on x86-64 in a release build with a thread-size
//! binary search (4 KiB granularity, thread start-up subtracted; see the
//! `stack_usage_probe` test): about 12 KiB for verification, 24 KiB for
//! signing (the 8 KiB fixed-window table plus the CRT temporaries), 64 KiB
//! for loading a private key (nested `Result<RsaPrivateKey>` returns plus the
//! sign/verify self-test) and 72 KiB for key generation. Loading and
//! generation are one-time operations; signing and verification are the
//! per-handshake paths.
//!
//! # Blinding entropy
//!
//! The blinding factor is derived with SHAKE256 from `p`, `q`, the encoded
//! message and fresh entropy (from the caller's RNG for PSS and
//! [`RsaPrivateKey::sign_pkcs1v15_with_rng`], from the operating system for
//! [`RsaPrivateKey::sign_pkcs1v15`] when available). Without fresh entropy the
//! factor is still unpredictable to anyone who does not know the private key,
//! so a failing or absent entropy source degrades to deterministic blinding
//! rather than to no blinding. Unblinding costs two half-size inversions,
//! each about 3% of a half-size exponentiation.
//!
//! # Backends
//!
//! | Architecture | Kernel |
//! |---|---|
//! | x86-64 with BMI2 + ADX | `mulx`/`adcx`/`adox` assembly |
//! | all | portable `u128` |
//!
//! Secret material is zeroised on drop.

mod bigint;
mod keygen;

/// Whether the CPU offers the accelerated Montgomery kernel.
pub(crate) fn hardware_kernel_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        bigint::x86_64::MulxAdx::detect().is_some()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// RSA Montgomery kernels (for the acceleration policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RsaBackend {
    /// BMI2 `mulx` + ADX `adcx`/`adox` (x86-64).
    MulxAdx,
    /// Portable u128 CIOS.
    Soft,
}

impl crate::accel::Backends for RsaBackend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::Rsa;
    const PREFERENCE: &'static [Self] = &[Self::MulxAdx, Self::Soft];

    fn available(self) -> bool {
        match self {
            Self::MulxAdx => hardware_kernel_available(),
            Self::Soft => true,
        }
    }

    fn uses(self) -> crate::accel::Uses {
        match self {
            Self::MulxAdx => crate::accel::Uses::DEDICATED,
            Self::Soft => crate::accel::Uses::PORTABLE,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::MulxAdx => "BMI2/ADX",
            Self::Soft => "portable",
        }
    }
}
mod pkcs1;
mod private;
mod pss;

use crate::Error;
use crate::der::{self, tag};
use crate::hash::{DynHash, HashAlgorithm};
use bigint::MAX_LIMBS;
use bigint::mont::{Kernel, Mont};

pub use keygen::PUBLIC_EXPONENT as GENERATED_PUBLIC_EXPONENT;
pub use private::{MAX_PKCS1_PRIVATE_KEY_DER_LEN, MAX_PKCS8_PRIVATE_KEY_DER_LEN, RsaPrivateKey};

/// Default minimum modulus size in bits.
pub const MIN_MODULUS_BITS: usize = 2048;
/// Smallest modulus size that may be opted into for legacy verification.
pub const LEGACY_MIN_MODULUS_BITS: usize = 1024;
/// Largest supported modulus size in bits.
pub const MAX_MODULUS_BITS: usize = 8192;
/// Largest supported modulus size in bytes.
pub const MAX_MODULUS_BYTES: usize = MAX_MODULUS_BITS / 8;
/// Exclusive upper bound on the public exponent.
pub const MAX_PUBLIC_EXPONENT: u64 = 1 << 33;

/// `rsaEncryption` OBJECT IDENTIFIER contents (1.2.840.113549.1.1.1).
const OID_RSA_ENCRYPTION: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// An RSA public key `(n, e)`.
#[derive(Clone)]
pub struct RsaPublicKey {
    n: Mont<MAX_LIMBS>,
    e: u64,
    n_bytes: [u8; MAX_MODULUS_BYTES],
    n_len: usize,
    e_bytes: [u8; 5],
    e_len: usize,
    bits: usize,
}

impl core::fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("bits", &self.bits)
            .field("e", &self.e)
            .finish_non_exhaustive()
    }
}

/// Strips leading zero bytes.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    &bytes[skip..]
}

/// Parses the public exponent, enforcing `3 <= e < 2^33` and `e` odd.
fn parse_exponent(e_be: &[u8]) -> Result<u64, Error> {
    let e_be = strip_leading_zeros(e_be);
    if e_be.is_empty() || e_be.len() > 5 {
        return Err(Error::InvalidKey);
    }
    let e = e_be.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    if !(3..MAX_PUBLIC_EXPONENT).contains(&e) || e & 1 == 0 {
        return Err(Error::InvalidKey);
    }
    Ok(e)
}

impl RsaPublicKey {
    /// Builds a key from the big-endian modulus and exponent, requiring a
    /// modulus of at least [`MIN_MODULUS_BITS`] bits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for an even, too small or too large
    /// modulus, or an exponent outside `3 <= e < 2^33` or even.
    pub fn from_components(n_be: &[u8], e_be: &[u8]) -> Result<Self, Error> {
        Self::from_components_with_min_bits(n_be, e_be, MIN_MODULUS_BITS)
    }

    /// [`Self::from_components`] with a caller-chosen minimum modulus size
    /// (`LEGACY_MIN_MODULUS_BITS..=MAX_MODULUS_BITS`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] for a `min_bits` outside the allowed
    /// range, otherwise as [`Self::from_components`].
    pub fn from_components_with_min_bits(
        n_be: &[u8],
        e_be: &[u8],
        min_bits: usize,
    ) -> Result<Self, Error> {
        if !(LEGACY_MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&min_bits) {
            return Err(Error::Unsupported);
        }
        let n_be = strip_leading_zeros(n_be);
        if n_be.is_empty() || n_be.len() > MAX_MODULUS_BYTES {
            return Err(Error::InvalidKey);
        }
        let bits = (n_be.len() - 1) * 8 + (8 - n_be[0].leading_zeros() as usize);
        if bits < min_bits || bits > MAX_MODULUS_BITS || n_be[n_be.len() - 1] & 1 == 0 {
            return Err(Error::InvalidKey);
        }
        let e = parse_exponent(e_be)?;
        let e_stripped = strip_leading_zeros(e_be);

        let mut limbs = [0u64; MAX_LIMBS];
        let len = bigint::limbs_for_bits(bits);
        bigint::from_be_bytes(&mut limbs[..len], n_be)?;
        let n = Mont::new(&limbs[..len], Kernel::detect())?;

        let mut n_bytes = [0u8; MAX_MODULUS_BYTES];
        n_bytes[..n_be.len()].copy_from_slice(n_be);
        let mut e_bytes = [0u8; 5];
        e_bytes[..e_stripped.len()].copy_from_slice(e_stripped);
        Ok(Self {
            n,
            e,
            n_bytes,
            n_len: n_be.len(),
            e_bytes,
            e_len: e_stripped.len(),
            bits,
        })
    }

    /// Parses a PKCS #1 `RSAPublicKey` (RFC 8017, appendix A.1.1).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for malformed DER and the errors
    /// of [`Self::from_components`] for unacceptable parameters.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        Self::from_pkcs1_der_with_min_bits(der, MIN_MODULUS_BITS)
    }

    /// [`Self::from_pkcs1_der`] with a caller-chosen minimum modulus size.
    ///
    /// # Errors
    ///
    /// As [`Self::from_components_with_min_bits`] plus
    /// [`Error::InvalidEncoding`] for malformed DER.
    pub fn from_pkcs1_der_with_min_bits(der: &[u8], min_bits: usize) -> Result<Self, Error> {
        let (n, e) = der::parse_sequence(der, |r| {
            let n = r.read_positive_integer()?;
            let e = r.read_positive_integer()?;
            Ok((n, e))
        })?;
        Self::from_components_with_min_bits(n, e, min_bits)
    }

    /// Parses an X.509 `SubjectPublicKeyInfo` with the `rsaEncryption`
    /// algorithm (RFC 3279, section 2.3.1; parameters must be `NULL`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for malformed DER or a different
    /// algorithm, and the errors of [`Self::from_components`] otherwise.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        Self::from_spki_der_with_min_bits(der, MIN_MODULUS_BITS)
    }

    /// [`Self::from_spki_der`] with a caller-chosen minimum modulus size.
    ///
    /// # Errors
    ///
    /// As [`Self::from_spki_der`] and [`Self::from_components_with_min_bits`].
    pub fn from_spki_der_with_min_bits(der: &[u8], min_bits: usize) -> Result<Self, Error> {
        let key = der::parse_sequence(der, |r| {
            let mut alg = r.read_sequence()?;
            if alg.read_oid()? != OID_RSA_ENCRYPTION || !alg.read(tag::NULL)?.is_empty() {
                return Err(Error::InvalidEncoding);
            }
            alg.finish()?;
            r.read_bit_string_octets()
        })?;
        Self::from_pkcs1_der_with_min_bits(key, min_bits)
    }

    /// Modulus length in bytes (the signature length).
    #[must_use]
    pub fn modulus_len_bytes(&self) -> usize {
        self.n_len
    }

    /// Modulus length in bits.
    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        self.bits
    }

    /// The modulus, big-endian without leading zeros.
    #[must_use]
    pub fn n_be(&self) -> &[u8] {
        &self.n_bytes[..self.n_len]
    }

    /// The public exponent, big-endian without leading zeros.
    #[must_use]
    pub fn e_be(&self) -> &[u8] {
        &self.e_bytes[..self.e_len]
    }

    /// The public exponent as an integer.
    #[must_use]
    pub fn e(&self) -> u64 {
        self.e
    }

    /// Writes the PKCS #1 `RSAPublicKey` encoding to `out` and returns its
    /// length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out` is too small
    /// ([`MAX_MODULUS_BYTES`] + 16 bytes always suffice).
    pub fn to_pkcs1_der(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n_len = der::Writer::positive_integer_len(self.n_be());
        let e_len = der::Writer::positive_integer_len(self.e_be());
        let mut w = der::Writer::new(out);
        w.header(tag::SEQUENCE, n_len + e_len)?;
        w.positive_integer(self.n_be())?;
        w.positive_integer(self.e_be())?;
        Ok(w.len())
    }

    /// Number of limbs of the modulus.
    fn limbs(&self) -> usize {
        self.n.len()
    }

    /// RSAVP1: checks `sig` is exactly `k` bytes encoding `s < n` and writes
    /// `s^e mod n` as `k` bytes into `em`.
    ///
    /// Variable time; signatures are public.
    fn rsavp1(&self, sig: &[u8], em: &mut [u8]) -> Result<(), Error> {
        let k = self.modulus_len_bytes();
        if sig.len() != k || em.len() != k {
            return Err(Error::InvalidSignature);
        }
        let len = self.limbs();
        let mut s = [0u64; MAX_LIMBS];
        bigint::from_be_bytes(&mut s[..len], sig).map_err(|_| Error::InvalidSignature)?;
        if !bigint::ct_lt(&s[..len], self.n.modulus()).declassify() {
            return Err(Error::InvalidSignature);
        }
        let mut m = [0u64; MAX_LIMBS];
        self.n.to_mont(&mut m[..len], &s[..len]);
        self.n.exp_pub_vartime(&mut s[..len], &m[..len], self.e);
        self.n.demont(&mut m[..len], &s[..len]);
        bigint::to_be_bytes(&m[..len], em);
        Ok(())
    }
}

/// Verifies an RSASSA-PKCS1-v1_5 signature over `msg` with the given hash.
///
/// The expected `EM` is reconstructed and compared in full with `s^e mod n`;
/// no parsing of the decrypted signature takes place.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] if the signature does not verify,
/// including when its length differs from the modulus length or the
/// signature integer is not below the modulus. Returns
/// [`Error::InvalidLength`] when the modulus is too short for `hash`.
pub fn verify_pkcs1v15(
    key: &RsaPublicKey,
    hash: HashAlgorithm,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    let k = key.modulus_len_bytes();
    let mut expected = [0u8; MAX_MODULUS_BYTES];
    let expected = &mut expected[..k];
    pkcs1::encode(hash, msg, expected)?;
    let mut em = [0u8; MAX_MODULUS_BYTES];
    let em = &mut em[..k];
    key.rsavp1(sig, em)?;
    if crate::ct::eq(expected, em) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// Verifies an RSASSA-PSS signature over `msg` with the given hash, MGF1
/// with the same hash and a salt of the digest length.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] if the signature does not verify
/// (wrong length, integer not below the modulus, or inconsistent encoding).
pub fn verify_pss(
    key: &RsaPublicKey,
    hash: HashAlgorithm,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    let k = key.modulus_len_bytes();
    let em_bits = key.modulus_bits() - 1;
    let em_len = em_bits.div_ceil(8);
    let mut em = [0u8; MAX_MODULUS_BYTES];
    let em = &mut em[..k];
    key.rsavp1(sig, em)?;
    // I2OSP(m, emLen) must succeed: any byte above emLen must be zero.
    let skip = k - em_len;
    if em[..skip].iter().any(|&b| b != 0) {
        return Err(Error::InvalidSignature);
    }
    let m_hash = DynHash::digest(hash, msg);
    pss::verify(hash, m_hash.as_ref(), &em[skip..], em_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponent_rules() {
        assert_eq!(parse_exponent(&[1, 0, 1]).unwrap(), 65537);
        assert_eq!(parse_exponent(&[0, 0, 3]).unwrap(), 3);
        assert!(parse_exponent(&[1]).is_err());
        assert!(parse_exponent(&[2]).is_err());
        assert!(parse_exponent(&[0x10, 0, 0, 0, 0]).is_err()); // 2^36
        assert!(parse_exponent(&[1, 0xff, 0xff, 0xff, 0xff]).is_ok()); // 2^32 + 2^32 - 1
        assert!(parse_exponent(&[2, 0, 0, 0, 1]).is_err()); // 2^33 + 1
        assert!(parse_exponent(&[]).is_err());
    }

    #[test]
    fn modulus_rules() {
        let mut n = [0u8; 256];
        n[0] = 0x80;
        n[255] = 1;
        assert!(RsaPublicKey::from_components(&n, &[1, 0, 1]).is_ok());
        n[255] = 2;
        assert!(RsaPublicKey::from_components(&n, &[1, 0, 1]).is_err());
        n[255] = 1;
        n[0] = 0x40; // 2047 bits
        assert!(RsaPublicKey::from_components(&n, &[1, 0, 1]).is_err());
        assert!(RsaPublicKey::from_components_with_min_bits(&n, &[1, 0, 1], 1024).is_ok());
        assert!(RsaPublicKey::from_components_with_min_bits(&n, &[1, 0, 1], 512).is_err());
        let mut big = [0xffu8; 1025];
        big[0] = 0;
        assert!(RsaPublicKey::from_components(&big, &[1, 0, 1]).is_ok());
        let huge = [0xffu8; 1025];
        assert!(RsaPublicKey::from_components(&huge, &[1, 0, 1]).is_err());
    }
}
