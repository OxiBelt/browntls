//! X448 Diffie-Hellman (RFC 7748 §5, §6.2).
//!
//! * [`x448`] is the RFC 7748 function: `decodeScalar448` clamping, then a
//!   constant-time Montgomery ladder over all 448 scalar bits with a
//!   constant-time conditional swap. u-coordinates are 56 bytes with no
//!   masked bit (RFC 7748 §5: only X25519 masks the top bit); non-canonical
//!   values (`p` through `2^448 - 1`) are accepted and processed as if
//!   reduced. Low-order inputs are not rejected here; they yield an all-zero
//!   output, which [`is_all_zero`] detects.
//! * [`x448_base`] is `x448(k, 5)` (the base point u-coordinate 5).
//! * [`PrivateKey::diffie_hellman`] additionally rejects an all-zero shared
//!   secret with [`Error::KeyAgreementFailed`] (RFC 7748 §6.2, RFC 9846
//!   §7.4.2, RFC 8422 §5.11).
//!
//! There is a single portable backend (eight 56-bit limbs, see `field`).

use super::field::Fe;
use crate::Error;
use crate::ct::{self, Choice};
use crate::rand::SecureRandom;
use crate::zeroize::Zeroize;

/// Length of scalars, u-coordinates and shared secrets.
pub const KEY_LEN: usize = 56;

/// The u-coordinate of the curve448 base point (5), RFC 7748 §4.2.
pub const BASEPOINT: [u8; 56] = {
    let mut b = [0u8; 56];
    b[0] = 5;
    b
};

/// `a24 = (156326 - 2) / 4` (RFC 7748 §5).
const A24: u32 = 39_081;

/// Applies the RFC 7748 §5 `decodeScalar448` clamping: clear the two least
/// significant bits and set the most significant bit.
#[inline]
fn clamp(scalar: &[u8; 56]) -> [u8; 56] {
    let mut k = *scalar;
    k[0] &= 252;
    k[55] |= 128;
    k
}

/// The RFC 7748 X448 function: `scalar` (clamped) times the point with
/// u-coordinate `u`, as 56 little-endian bytes.
#[must_use]
pub fn x448(scalar: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let mut k = clamp(scalar);
    let out = ladder(&k, u);
    k.zeroize();
    out
}

/// `x448(scalar, BASEPOINT)`: the public key for `scalar`.
#[must_use]
pub fn x448_base(scalar: &[u8; 56]) -> [u8; 56] {
    x448(scalar, &BASEPOINT)
}

/// Whether an X448 output is all zero (the peer's point had small order),
/// computed by ORing all bytes together (RFC 7748 §6.1, §6.2). TLS rejects
/// such a shared secret (RFC 9846 §7.4.2).
#[must_use]
pub fn is_all_zero(out: &[u8; 56]) -> bool {
    ct::eq_bytes(out, &[0u8; 56]).declassify()
}

/// Constant-time Montgomery ladder (RFC 7748 §5) on a clamped scalar.
fn ladder(k: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;
    // The step temporaries live outside the loop so that the last step's
    // values, which determine the output, can be wiped.
    let mut t = [Fe::ZERO; 9];
    for bit in (0..448).rev() {
        let kt = u64::from((k[bit >> 3] >> (bit & 7)) & 1);
        swap ^= kt;
        let c = Choice::from_bit(swap);
        Fe::conditional_swap(&mut x2, &mut x3, c);
        Fe::conditional_swap(&mut z2, &mut z3, c);
        swap = kt;
        let [a, aa, b, bb, e, c, d, da, cb] = &mut t;
        *a = x2.add(&z2);
        *aa = a.square();
        *b = x2.sub(&z2);
        *bb = b.square();
        *e = aa.sub(bb);
        *c = x3.add(&z3);
        *d = x3.sub(&z3);
        *da = d.mul(a);
        *cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(&da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(&aa.add(&e.mul_small(A24)));
    }
    let c = Choice::from_bit(swap);
    Fe::conditional_swap(&mut x2, &mut x3, c);
    Fe::conditional_swap(&mut z2, &mut z3, c);
    let mut z_inv = z2.invert();
    let mut result = x2.mul(&z_inv);
    let out = result.to_bytes();
    for v in t
        .iter_mut()
        .chain([&mut x2, &mut z2, &mut x3, &mut z3, &mut z_inv, &mut result])
    {
        v.0.zeroize();
    }
    out
}

/// An X448 private key (a 56-byte scalar, clamped on use). Zeroised on drop.
pub struct PrivateKey {
    scalar: [u8; 56],
}

impl PrivateKey {
    /// Generates a key from `rng` (56 random bytes, RFC 7748 §6.2).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomFailure`] if the random source fails.
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self, Error> {
        let mut scalar = [0u8; 56];
        if let Err(e) = rng.fill(&mut scalar) {
            scalar.zeroize();
            return Err(e);
        }
        Ok(Self { scalar })
    }

    /// Wraps existing private-key bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 56]) -> Self {
        Self { scalar: *bytes }
    }

    /// Wraps private-key bytes from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] unless `bytes` is exactly 56 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let b: &[u8; 56] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self::from_bytes(b))
    }

    /// Returns the private-key bytes (as supplied, unclamped).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.scalar
    }

    /// Returns the public key `X448(k, 5)`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 56] {
        x448_base(&self.scalar)
    }

    /// Computes the shared secret with `peer`'s public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyAgreementFailed`] if the result is all zero (the
    /// peer sent a point of small order), as TLS requires.
    pub fn diffie_hellman(&self, peer: &[u8; 56]) -> Result<[u8; 56], Error> {
        let mut shared = x448(&self.scalar, peer);
        if is_all_zero(&shared) {
            shared.zeroize();
            return Err(Error::KeyAgreementFailed);
        }
        Ok(shared)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("x448::PrivateKey { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::super::edwards::EdwardsPoint;
    use super::super::scalar::Scalar;
    use super::*;

    /// X448 of the base point equals the 4-isogeny image `y^2 / x^2` of
    /// `[k]B` on edwards448 (RFC 7748 §4.2 maps B to u = 5): an independent
    /// check of the ladder against the Edwards arithmetic.
    #[test]
    fn ladder_matches_edwards_isogeny() {
        let mut st = 5u64;
        for _ in 0..8 {
            let mut k = [0u8; 56];
            for b in &mut k {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (st >> 56) as u8;
            }
            let mut wide = [0u8; 57];
            wide[..56].copy_from_slice(&clamp(&k));
            let s = Scalar::from_bytes_mod_order(&wide);
            let ed = EdwardsPoint::mul_base(&s).to_montgomery_u();
            assert_eq!(x448_base(&k), ed);
        }
    }
}
