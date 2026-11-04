//! X25519 Diffie-Hellman (RFC 7748).
//!
//! * [`x25519`] is the RFC 7748 function: clamping, then a constant-time
//!   Montgomery ladder. Non-canonical u-coordinates (`>= p`) are accepted and
//!   reduced, and the most significant bit of `u` is ignored, as required.
//!   Low-order inputs are not rejected here; they yield an all-zero output.
//! * [`x25519_base`] computes public keys with the constant-time fixed-base
//!   Edwards comb and the birational map `u = (1 + y) / (1 - y)`.
//! * [`PrivateKey::diffie_hellman`] additionally rejects an all-zero shared
//!   secret with [`Error::KeyAgreementFailed`] (RFC 7748 §6.1,
//!   RFC 8446 §7.4.2).
//!
//! Backends: the portable radix-2^51 ladder everywhere, and on x86-64 a
//! radix-2^64 ladder using BMI2 `MULX` with ADX `ADCX`/`ADOX`, selected at run
//! time through [`crate::cpu::features`].

use super::edwards::EdwardsPoint;
use super::field::Fe;
use crate::Error;
use crate::ct::{self, Choice};
use crate::rand::SecureRandom;
use crate::zeroize::Zeroize;

/// The u-coordinate of the curve25519 base point (9).
pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// Applies the RFC 7748 §5 "decodeScalar25519" clamping.
#[inline]
fn clamp(scalar: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// An X25519 implementation tier, for tests and benchmarks.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Backend {
    /// Portable radix-2^51 field arithmetic with 64x64->128-bit products.
    Portable,
    /// x86-64 radix-2^64 field arithmetic with BMI2 `MULX` and ADX.
    X86Adx,
}

impl Backend {
    /// Every backend, available or not.
    pub const ALL: [Self; 2] = [Self::Portable, Self::X86Adx];

    /// Whether the backend can run on this CPU.
    #[must_use]
    pub fn is_available(self) -> bool {
        match self {
            Self::Portable => true,
            Self::X86Adx => {
                let f = crate::cpu::features();
                f.x86_bmi2() && f.x86_adx()
            }
        }
    }

    /// The backend [`x25519`] dispatches to.
    #[must_use]
    pub fn best() -> Self {
        crate::accel::select::<Self>()
    }
}

impl crate::accel::Backends for Backend {
    const ALGORITHM: crate::accel::Algorithm = crate::accel::Algorithm::X25519;
    const PREFERENCE: &'static [Self] = &[Self::X86Adx, Self::Portable];

    fn available(self) -> bool {
        self.is_available()
    }

    fn uses(self) -> crate::accel::Uses {
        use crate::accel::Uses;
        match self {
            Self::Portable => Uses::PORTABLE,
            Self::X86Adx => Uses::DEDICATED,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::X86Adx => "BMI2/ADX",
        }
    }
}

/// The X25519 function with a specific backend, or `None` if the backend is
/// not available on this CPU. Intended for differential tests.
#[doc(hidden)]
#[must_use]
pub fn x25519_with_backend(backend: Backend, scalar: &[u8; 32], u: &[u8; 32]) -> Option<[u8; 32]> {
    if !backend.is_available() {
        return None;
    }
    let mut k = clamp(scalar);
    let out = match backend {
        Backend::Portable => ladder_portable(&k, u),
        #[cfg(target_arch = "x86_64")]
        Backend::X86Adx => super::x86_adx::x25519(&k, u),
        #[cfg(not(target_arch = "x86_64"))]
        Backend::X86Adx => return None,
    };
    k.zeroize();
    Some(out)
}

/// The RFC 7748 X25519 function: `scalar` (clamped) times the point with
/// u-coordinate `u`.
#[must_use]
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = clamp(scalar);
    #[cfg(target_arch = "x86_64")]
    let out = if Backend::X86Adx.is_available() {
        super::x86_adx::x25519(&k, u)
    } else {
        ladder_portable(&k, u)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let out = ladder_portable(&k, u);
    k.zeroize();
    out
}

/// `x25519(scalar, BASEPOINT)` computed with the fixed-base Edwards comb.
#[must_use]
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut k = clamp(scalar);
    // Clamped scalars are below 2^255, as `mul_base` requires. The result is
    // never the identity: k is a non-zero multiple of 8 below 8L.
    let out = EdwardsPoint::mul_base(&k).to_montgomery_u();
    k.zeroize();
    out
}

/// Portable constant-time Montgomery ladder (RFC 7748 §5) on a clamped scalar.
fn ladder_portable(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= kt;
        let c = Choice::from_bit(swap);
        Fe::conditional_swap(&mut x2, &mut x3, c);
        Fe::conditional_swap(&mut z2, &mut z3, c);
        swap = kt;
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(121_665)));
    }
    let c = Choice::from_bit(swap);
    Fe::conditional_swap(&mut x2, &mut x3, c);
    Fe::conditional_swap(&mut z2, &mut z3, c);
    let out = x2.mul(&z2.invert()).to_bytes();
    for v in [&mut x2, &mut z2, &mut x3, &mut z3] {
        v.0.zeroize();
    }
    out
}

/// An X25519 private key (a 32-byte scalar, clamped on use). Zeroised on drop.
pub struct PrivateKey {
    scalar: [u8; 32],
}

impl PrivateKey {
    /// Generates a key from `rng`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomFailure`] if the random source fails.
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self, Error> {
        let mut scalar = [0u8; 32];
        if let Err(e) = rng.fill(&mut scalar) {
            scalar.zeroize();
            return Err(e);
        }
        Ok(Self { scalar })
    }

    /// Wraps existing private-key bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { scalar: *bytes }
    }

    /// Wraps private-key bytes from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] unless `bytes` is exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let b: &[u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self::from_bytes(b))
    }

    /// Returns the private-key bytes (as supplied, unclamped).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.scalar
    }

    /// Returns the public key `X25519(k, 9)`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        x25519_base(&self.scalar)
    }

    /// Computes the shared secret with `peer`'s public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyAgreementFailed`] if the result is all zero (the
    /// peer sent a low-order point), as TLS 1.3 requires.
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut shared = x25519(&self.scalar, peer);
        if ct::eq_bytes(&shared, &[0u8; 32]).declassify() {
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
        f.write_str("x25519::PrivateKey { .. }")
    }
}
