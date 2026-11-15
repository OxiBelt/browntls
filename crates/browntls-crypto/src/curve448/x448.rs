//! X448 Diffie-Hellman (RFC 7748 §5, §6.2).
//!
//! * [`x448`] is the RFC 7748 function: `decodeScalar448` clamping, then a
//!   constant-time Montgomery ladder over all 448 scalar bits with a
//!   constant-time conditional swap. u-coordinates are 56 bytes with no
//!   masked bit (RFC 7748 §5: only X25519 masks the top bit); non-canonical
//!   values (`p` through `2^448 - 1`) are accepted and processed as if
//!   reduced. Low-order inputs are not rejected here; they yield an all-zero
//!   output, which [`is_all_zero`] detects.
//! * [`x448_base`] is `x448(k, 5)` (the base point u-coordinate 5), computed
//!   with the fixed-base comb of edwards448 and the 4-isogeny to curve448.
//! * [`PrivateKey::diffie_hellman`] additionally rejects an all-zero shared
//!   secret with [`Error::KeyAgreementFailed`] (RFC 7748 §6.2, RFC 9846
//!   §7.4.2, RFC 8422 §5.11).
//!
//! There is a single portable backend (eight 56-bit limbs, see `field`).

use super::edwards::EdwardsPoint;
use super::field::Fe;
use super::scalar::Scalar;
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
///
/// Computed on edwards448 with the constant-time fixed-base comb instead of
/// a ladder: the 4-isogeny of RFC 7748 §4.2, `u = y^2 / x^2`, is a group
/// homomorphism that maps the Ed448 base point B (of prime order `L`) to the
/// X448 base point `u = 5`, so `[k](u = 5)` is the image of `[k mod L]B`. If
/// `L` divides the clamped scalar (only `k = 4L`), both sides are the
/// identity and the output is zero, as with the ladder.
#[must_use]
pub fn x448_base(scalar: &[u8; 56]) -> [u8; 56] {
    let mut clamped = clamp(scalar);
    let mut wide = [0u8; 57];
    wide[..56].copy_from_slice(&clamped);
    let mut k = Scalar::from_bytes_mod_order(&wide);
    clamped.zeroize();
    wide.zeroize();
    // The affine point is the public key in another form, but its projective
    // representation depends on how `k` was processed, so it is wiped too.
    let mut point = EdwardsPoint::mul_base(&k);
    let out = point.to_montgomery_u();
    point.zeroize();
    k.zeroize();
    out
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
    use super::*;

    /// The comb-based public key equals the ladder on `u = 5` for random
    /// scalars and for scalars at the edges of the clamped range, including
    /// `4L` (the only clamped multiple of the group order), whose result is
    /// the identity and therefore zero.
    #[test]
    fn base_matches_ladder() {
        let via_ladder = |k: &[u8; 56]| ladder(&clamp(k), &BASEPOINT);
        let mut cases = std::vec![[0u8; 56], [0xff; 56], [0x55; 56], [0xaa; 56]];
        // 4L = 2^448 - 4 * 13818066809895115352007386748515426880336692474882178609894547503885:
        // L little endian, shifted left by two bits.
        let l: [u8; 56] = [
            0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2,
            0x6c, 0x21, 0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
        ];
        let mut four_l = [0u8; 56];
        let mut carry = 0u8;
        for (o, b) in four_l.iter_mut().zip(l) {
            *o = (b << 2) | carry;
            carry = b >> 6;
        }
        assert_eq!(carry, 0);
        assert_eq!(clamp(&four_l), four_l, "4L is a clamped scalar");
        assert_eq!(x448_base(&four_l), [0u8; 56]);
        cases.push(four_l);
        // 4L +- 4 are clamped too: +-4 B.
        let mut near = four_l;
        near[0] = near[0].wrapping_add(4);
        cases.push(near);
        near[0] = four_l[0].wrapping_sub(4);
        cases.push(near);
        let mut st = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..64 {
            let mut k = [0u8; 56];
            for b in &mut k {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (st >> 56) as u8;
            }
            cases.push(k);
        }
        for k in &cases {
            assert_eq!(x448_base(k), via_ladder(k), "k = {k:x?}");
            assert_eq!(x448_base(k), x448(k, &BASEPOINT));
        }
    }
}
