//! Finite-field Diffie-Hellman over the RFC 7919 groups, as TLS 1.3 uses
//! them (RFC 9846 §4.3.8.1 and §7.4.1).
//!
//! # Groups
//!
//! Each [`Group`] is a safe prime `p` (`q = (p - 1) / 2` is prime) with
//! generator `g = 2` ([`GENERATOR`]), copied from RFC 7919 Appendix A
//! ([`Group::prime_be`]). Every modulus is a whole number of 64-bit limbs
//! with its top and bottom 64 bits set.
//!
//! # Private exponents
//!
//! RFC 7919 §5.2 lets peers draw a short exponent, "an m-bit integer where m
//! is at least" a per-group bound, instead of one from `[2, p - 2]`, and
//! Appendix A gives that bound next to the group's estimated
//! symmetric-equivalent strength. The best attacks on an `m`-bit exponent
//! (Pollard's kangaroo, baby-step giant-step) cost about `2^(m/2)` group
//! operations, so `m >= 2 * strength` keeps the group's strength; the RFC
//! bounds add a deliberate margin above that (RFC 7919 §8.2). Here `m` is
//! the RFC bound rounded up to whole limbs, because the constant-time
//! exponentiation processes whole limbs anyway, and generated exponents have
//! bit `m - 1` set, so `x` lies in `[2^(m-1), 2^m)` as in the §5.2 example
//! and carries `m - 1` random bits:
//!
//! | Group | Strength (RFC) | RFC minimum `m` | `m` used | Random bits |
//! |---|---:|---:|---:|---:|
//! | ffdhe2048 | 103 | 225 | 256 | 255 |
//! | ffdhe3072 | 125 | 275 | 320 | 319 |
//! | ffdhe4096 | 150 | 325 | 384 | 383 |
//! | ffdhe6144 | 175 | 375 | 384 | 383 |
//! | ffdhe8192 | 192 | 400 | 448 | 447 |
//!
//! Every such `x` is far below `q`, hence in `[2, p - 2]`.
//!
//! # Encodings and validation
//!
//! Public values and shared secrets are big-endian integers left-padded with
//! zeros to the length of `p` ([`Group::element_len`]): RFC 9846 §4.3.8.1
//! for `Y = g^x mod p`, §7.4.1 for `Z = Y^x mod p` (which, unlike TLS 1.2,
//! keeps its leading zeros). A peer value is accepted only with exactly that
//! length and `1 < Y < p - 1` (RFC 7919 §5.1, RFC 9846 §4.3.8.1), which with
//! a safe prime excludes the subgroups of order 1 and 2. RFC 9846 §7.4.1
//! performs "a conventional Diffie-Hellman \[KEYAGREEMENT\] computation"
//! (NIST SP 800-56A Rev. 3), whose FFC DH primitive (§5.7.1.1) rejects a
//! shared secret `Z <= 1` or `Z = p - 1`; that check is applied too. For a
//! validated `Y` and `2 <= x < q` it cannot fire, so it acts as a fault
//! check.
//!
//! # Timing and backends
//!
//! Both exponentiations (`g^x` and `Y^x`) use the constant-time fixed-window
//! exponentiation of the RSA arithmetic: all `m` exponent bits are
//! processed, table lookups touch every entry and every conditional is a
//! mask, so the running time depends only on the group. Range checks on
//! public values are the only data-dependent decisions. The Montgomery
//! kernels are RSA's and follow the [`crate::accel::Algorithm::Rsa`] policy,
//! selected per operation: BMI2/ADX on x86-64 where available, otherwise the
//! portable `u128` kernel. (The AVX-512 IFMA backend only implements
//! public-exponent and CRT exponentiations and is not used here.)
//!
//! # Memory
//!
//! Nothing is heap allocated. ffdhe2048 to ffdhe4096 use 64-limb Montgomery
//! contexts (an 8 KiB exponentiation table), ffdhe6144 and ffdhe8192
//! 128-limb ones (16 KiB). A whole exchange through the TLS provider (both
//! peers' key generation and agreement) ran on thread stacks of 28 KiB and
//! 44 KiB respectively (x86-64 release build, 4 KiB steps, thread start-up
//! included). The exponent and every secret temporary are zeroised after
//! use; [`PrivateKey`] zeroises its exponent on drop.
//!
//! Cost: each side performs two exponentiations (`g^x` and `Y^x`), each
//! `m` squarings, `m / 4` window multiplications and 14 table
//! multiplications modulo `p`.
//!
//! ```
//! use browntls_crypto::ffdhe::{Group, PrivateKey};
//! use browntls_crypto::rand::OsRng;
//!
//! let group = Group::Ffdhe2048;
//! let alice = PrivateKey::generate(group, &OsRng)?;
//! let bob = PrivateKey::generate(group, &OsRng)?;
//! let (mut a_pub, mut b_pub) = ([0u8; 256], [0u8; 256]);
//! alice.public_key(&mut a_pub)?;
//! bob.public_key(&mut b_pub)?;
//! let (mut z1, mut z2) = ([0u8; 256], [0u8; 256]);
//! alice.diffie_hellman(&b_pub, &mut z1)?;
//! bob.diffie_hellman(&a_pub, &mut z2)?;
//! assert_eq!(z1, z2);
//! # Ok::<(), browntls_crypto::Error>(())
//! ```

mod primes;

use crate::Error;
use crate::ct::Choice;
use crate::rand::SecureRandom;
use crate::rsa::bigint::mont::{Kernel, Mont};
use crate::rsa::bigint::{self, HALF_LIMBS, MAX_LIMBS};
use crate::zeroize::Zeroize;

/// The generator of every RFC 7919 group.
pub const GENERATOR: u64 = 2;

/// Length in bytes of the largest group's elements (ffdhe8192).
pub const MAX_ELEMENT_LEN: usize = 1024;

/// Length in bytes of the longest private exponent (ffdhe8192).
pub const MAX_EXPONENT_LEN: usize = 56;

const MAX_EXPONENT_LIMBS: usize = MAX_EXPONENT_LEN / 8;

/// An RFC 7919 finite-field group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Group {
    /// ffdhe2048 (RFC 7919 Appendix A.1, `NamedGroup` 0x0100).
    Ffdhe2048,
    /// ffdhe3072 (RFC 7919 Appendix A.2, `NamedGroup` 0x0101).
    Ffdhe3072,
    /// ffdhe4096 (RFC 7919 Appendix A.3, `NamedGroup` 0x0102).
    Ffdhe4096,
    /// ffdhe6144 (RFC 7919 Appendix A.4, `NamedGroup` 0x0103).
    Ffdhe6144,
    /// ffdhe8192 (RFC 7919 Appendix A.5, `NamedGroup` 0x0104).
    Ffdhe8192,
}

impl Group {
    /// Every group, smallest first.
    pub const ALL: [Self; 5] = [
        Self::Ffdhe2048,
        Self::Ffdhe3072,
        Self::Ffdhe4096,
        Self::Ffdhe6144,
        Self::Ffdhe8192,
    ];

    /// The RFC 7919 name, for example `"ffdhe2048"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ffdhe2048 => "ffdhe2048",
            Self::Ffdhe3072 => "ffdhe3072",
            Self::Ffdhe4096 => "ffdhe4096",
            Self::Ffdhe6144 => "ffdhe6144",
            Self::Ffdhe8192 => "ffdhe8192",
        }
    }

    /// Size of the prime `p` in bits.
    #[must_use]
    pub const fn prime_bits(self) -> usize {
        match self {
            Self::Ffdhe2048 => 2048,
            Self::Ffdhe3072 => 3072,
            Self::Ffdhe4096 => 4096,
            Self::Ffdhe6144 => 6144,
            Self::Ffdhe8192 => 8192,
        }
    }

    /// Length in bytes of `p`, and so of every public value and shared
    /// secret.
    #[must_use]
    pub const fn element_len(self) -> usize {
        self.prime_bits() / 8
    }

    /// The prime `p`, big-endian, as printed in RFC 7919 Appendix A.
    #[must_use]
    pub fn prime_be(self) -> &'static [u8] {
        match self {
            Self::Ffdhe2048 => &primes::FFDHE2048,
            Self::Ffdhe3072 => &primes::FFDHE3072,
            Self::Ffdhe4096 => &primes::FFDHE4096,
            Self::Ffdhe6144 => &primes::FFDHE6144,
            Self::Ffdhe8192 => &primes::FFDHE8192,
        }
    }

    /// The estimated symmetric-equivalent strength in bits (RFC 7919
    /// Appendix A).
    #[must_use]
    pub const fn security_bits(self) -> usize {
        match self {
            Self::Ffdhe2048 => 103,
            Self::Ffdhe3072 => 125,
            Self::Ffdhe4096 => 150,
            Self::Ffdhe6144 => 175,
            Self::Ffdhe8192 => 192,
        }
    }

    /// The shortest secret exponent RFC 7919 Appendix A recommends for the
    /// short-exponent optimisation (§5.2), in bits.
    #[must_use]
    pub const fn min_exponent_bits(self) -> usize {
        match self {
            Self::Ffdhe2048 => 225,
            Self::Ffdhe3072 => 275,
            Self::Ffdhe4096 => 325,
            Self::Ffdhe6144 => 375,
            Self::Ffdhe8192 => 400,
        }
    }

    /// The exponent length `m` used here: [`Self::min_exponent_bits`]
    /// rounded up to a multiple of 64 (see the [module documentation](crate::ffdhe)).
    #[must_use]
    pub const fn exponent_bits(self) -> usize {
        self.min_exponent_bits().div_ceil(64) * 64
    }

    /// Length in bytes of an encoded private exponent
    /// ([`PrivateKey::from_exponent_be`]).
    #[must_use]
    pub const fn exponent_len(self) -> usize {
        self.exponent_bits() / 8
    }

    /// Number of 64-bit limbs of `p`.
    const fn limbs(self) -> usize {
        self.prime_bits() / 64
    }

    /// Number of 64-bit limbs of a private exponent.
    const fn exponent_limbs(self) -> usize {
        self.exponent_bits() / 64
    }

    /// Writes `p` as little-endian limbs into `out` (`limbs()` long).
    fn load_prime(self, out: &mut [u64]) -> Result<(), Error> {
        bigint::from_be_bytes(out, self.prime_be())
    }

    /// Writes `p - 1` as little-endian limbs into `out` (`limbs()` long).
    fn load_prime_minus_one(self, out: &mut [u64]) -> Result<(), Error> {
        self.load_prime(out)?;
        // p is odd, so this never borrows.
        bigint::sub_word(out, 1);
        Ok(())
    }

    /// Checks a peer's public value: exactly [`Self::element_len`] bytes
    /// (big-endian, left-padded) and `1 < Y < p - 1` (RFC 7919 §5.1,
    /// RFC 9846 §4.3.8.1).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for a value of the wrong length or out
    /// of range.
    pub fn validate_public_key(self, peer: &[u8]) -> Result<(), Error> {
        let mut y = [0u64; MAX_LIMBS];
        self.load_public(peer, &mut y[..self.limbs()])
    }

    /// Validates `peer` as [`Self::validate_public_key`] does and writes it
    /// as little-endian limbs into `out` (`limbs()` long).
    fn load_public(self, peer: &[u8], out: &mut [u64]) -> Result<(), Error> {
        let len = self.limbs();
        debug_assert_eq!(out.len(), len);
        if peer.len() != self.element_len() {
            return Err(Error::InvalidKey);
        }
        bigint::from_be_bytes(out, peer)?;
        let mut pm1 = [0u64; MAX_LIMBS];
        self.load_prime_minus_one(&mut pm1[..len])?;
        let mut one = [0u64; MAX_LIMBS];
        one[0] = 1;
        // Public data: the comparison result may be declassified.
        let in_range = bigint::ct_lt(&one[..len], out).and(bigint::ct_lt(out, &pm1[..len]));
        if in_range.declassify() {
            Ok(())
        } else {
            out.fill(0);
            Err(Error::InvalidKey)
        }
    }
}

/// An ephemeral FFDHE private key: the secret exponent `x` and its group.
/// The exponent is zeroised on drop.
pub struct PrivateKey {
    group: Group,
    /// `x` in little-endian limbs; only the first `group.exponent_limbs()`
    /// are used.
    x: [u64; MAX_EXPONENT_LIMBS],
}

impl PrivateKey {
    /// Draws an exponent of [`Group::exponent_bits`] bits with its top bit
    /// set from `rng` (RFC 7919 §5.2).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomFailure`] if the random source fails.
    pub fn generate(group: Group, rng: &dyn SecureRandom) -> Result<Self, Error> {
        let n = group.exponent_len();
        let limbs = group.exponent_limbs();
        let mut key = Self {
            group,
            x: [0; MAX_EXPONENT_LIMBS],
        };
        let mut bytes = [0u8; MAX_EXPONENT_LEN];
        let result = rng
            .fill(&mut bytes[..n])
            .and_then(|()| bigint::from_be_bytes(&mut key.x[..limbs], &bytes[..n]));
        bytes.zeroize();
        // On failure `key` is dropped, which zeroises it.
        result?;
        key.x[limbs - 1] |= 1 << 63;
        Ok(key)
    }

    /// Imports a secret exponent: exactly [`Group::exponent_len`] bytes,
    /// big-endian, with a value of at least 2. Unlike
    /// [`Self::generate`], the top bit need not be set.
    ///
    /// Intended for known-answer tests; ephemeral keys should come from
    /// [`Self::generate`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] for a wrong length or an exponent
    /// below 2.
    pub fn from_exponent_be(group: Group, exponent: &[u8]) -> Result<Self, Error> {
        if exponent.len() != group.exponent_len() {
            return Err(Error::InvalidKey);
        }
        let limbs = group.exponent_limbs();
        let mut key = Self {
            group,
            x: [0; MAX_EXPONENT_LIMBS],
        };
        bigint::from_be_bytes(&mut key.x[..limbs], exponent)?;
        let mut two = [0u64; MAX_EXPONENT_LIMBS];
        two[0] = 2;
        // Only the accept / reject decision is declassified.
        if bigint::ct_lt(&key.x[..limbs], &two[..limbs]).declassify() {
            return Err(Error::InvalidKey);
        }
        Ok(key)
    }

    /// The key's group.
    #[must_use]
    pub fn group(&self) -> Group {
        self.group
    }

    /// Computes the public value `Y = g^x mod p` into `out`, which must be
    /// exactly [`Group::element_len`] bytes (big-endian, left-padded;
    /// RFC 9846 §4.3.8.1). Costs one exponentiation per call.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out` has the wrong length.
    pub fn public_key(&self, out: &mut [u8]) -> Result<(), Error> {
        self.public_key_with(out, Kernel::detect())
    }

    fn public_key_with(&self, out: &mut [u8], kernel: Kernel) -> Result<(), Error> {
        let group = self.group;
        if out.len() != group.element_len() {
            return Err(Error::InvalidLength);
        }
        let len = group.limbs();
        let mut base = [0u64; MAX_LIMBS];
        base[0] = GENERATOR;
        let mut y = [0u64; MAX_LIMBS];
        let result = self.exp(&base[..len], &mut y[..len], kernel);
        if result.is_ok() {
            bigint::to_be_bytes(&y[..len], out);
        }
        y.zeroize();
        result
    }

    /// Computes the shared secret `Z = peer^x mod p` into `out`, which must
    /// be exactly [`Group::element_len`] bytes (big-endian, left-padded;
    /// RFC 9846 §7.4.1).
    ///
    /// The peer value is validated first ([`Group::validate_public_key`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out` has the wrong length,
    /// [`Error::InvalidKey`] for an invalid peer value, and
    /// [`Error::KeyAgreementFailed`] if `Z` is 0, 1 or `p - 1`. `out` is
    /// left untouched on error.
    pub fn diffie_hellman(&self, peer: &[u8], out: &mut [u8]) -> Result<(), Error> {
        self.diffie_hellman_with(peer, out, Kernel::detect())
    }

    fn diffie_hellman_with(
        &self,
        peer: &[u8],
        out: &mut [u8],
        kernel: Kernel,
    ) -> Result<(), Error> {
        let group = self.group;
        if out.len() != group.element_len() {
            return Err(Error::InvalidLength);
        }
        let len = group.limbs();
        let mut y = [0u64; MAX_LIMBS];
        group.load_public(peer, &mut y[..len])?;
        let mut z = [0u64; MAX_LIMBS];
        let result = self.exp(&y[..len], &mut z[..len], kernel).and_then(|()| {
            if is_degenerate(group, &z[..len])?.declassify() {
                Err(Error::KeyAgreementFailed)
            } else {
                bigint::to_be_bytes(&z[..len], out);
                Ok(())
            }
        });
        z.zeroize();
        result
    }

    /// `out = base^x mod p` for `base < p` (both `group.limbs()` long).
    fn exp(&self, base: &[u64], out: &mut [u64], kernel: Kernel) -> Result<(), Error> {
        let group = self.group;
        let len = group.limbs();
        let mut p = [0u64; MAX_LIMBS];
        group.load_prime(&mut p[..len])?;
        let x = &self.x[..group.exponent_limbs()];
        if len <= HALF_LIMBS {
            mod_exp::<HALF_LIMBS>(&p[..len], base, x, out, kernel)
        } else {
            mod_exp::<MAX_LIMBS>(&p[..len], base, x, out, kernel)
        }
    }
}

/// `out = base^x mod p` in a Montgomery context of capacity `CAP`, with the
/// constant-time windowed exponentiation.
#[inline(never)]
fn mod_exp<const CAP: usize>(
    p: &[u64],
    base: &[u64],
    x: &[u64],
    out: &mut [u64],
    kernel: Kernel,
) -> Result<(), Error> {
    let len = p.len();
    let ctx = Mont::<CAP>::new(p, kernel)?;
    let mut base_m = [0u64; CAP];
    let mut acc = [0u64; CAP];
    ctx.to_mont(&mut base_m[..len], base);
    ctx.exp_ct(&mut acc[..len], &base_m[..len], x);
    ctx.demont(out, &acc[..len]);
    base_m.zeroize();
    acc.zeroize();
    Ok(())
}

/// `TRUE` when the (fully reduced) shared secret `z` is 0, 1 or `p - 1`
/// (SP 800-56A Rev. 3 §5.7.1.1). Constant time.
fn is_degenerate(group: Group, z: &[u64]) -> Result<Choice, Error> {
    let len = z.len();
    let mut pm1 = [0u64; MAX_LIMBS];
    group.load_prime_minus_one(&mut pm1[..len])?;
    let mut one = [0u64; MAX_LIMBS];
    one[0] = 1;
    Ok(bigint::is_zero(z)
        .or(bigint::ct_eq(z, &one[..len]))
        .or(bigint::ct_eq(z, &pm1[..len])))
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ffdhe::PrivateKey")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
