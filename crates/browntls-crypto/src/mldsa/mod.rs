//! ML-DSA (FIPS 204) at the 44, 65 and 87 parameter sets: key generation,
//! hedged and deterministic signing, verification, and the FIPS 204 byte
//! encodings of public keys, expanded private keys and signatures.
//!
//! ```
//! use browntls_crypto::mldsa::{MlDsa65, SigningKey};
//! use browntls_crypto::rand::OsRng;
//!
//! let sk = SigningKey::<MlDsa65>::generate(&OsRng)?;
//! let sig = sk.sign(b"message", b"", &OsRng)?;
//! sk.verifying_key().verify(b"message", &sig)?;
//! # Ok::<(), browntls_crypto::Error>(())
//! ```
//!
//! Only pure ML-DSA is provided (FIPS 204 Algorithms 1 to 3 with the
//! context string of §5.2 and §5.3). HashML-DSA (pre-hashing, §5.4) is not
//! implemented: RFC 9881 does not allow it in X.509.
//!
//! # Keys
//!
//! * A [`SigningKey`] is created from the 32-byte seed `xi`
//!   ([`SigningKey::from_seed`], ML-DSA.KeyGen_internal) or loaded from the
//!   FIPS 204 expanded encoding ([`SigningKey::from_expanded_bytes`]). The
//!   expanded encoding is checked: `s1` and `s2` coefficients must
//!   be in `[-eta, eta]`, and `t0` and `tr` must equal the values recomputed
//!   from `rho`, `s1` and `s2`; this also yields the public key.
//!   The signing seed `K` is not bound to the rest of the key and cannot be
//!   checked: only a key given with its seed detects a changed `K`.
//! * A [`VerifyingKey`] accepts any byte string of the right length, as
//!   FIPS 204 `pkDecode` does (every 10-bit `t1` value is valid). It caches
//!   `tr = H(pk, 64)`.
//! * Keys hold their encodings only: `VerifyingKey` is the public key plus
//!   `tr` (1.4, 2.0 and 2.7 KB for ML-DSA-44, -65 and -87), `SigningKey` the
//!   expanded private key, the seed and the verifying key (3.9, 6.1 and
//!   7.6 KB). The matrix `A` and the NTT forms of `s1`, `s2` and `t0` are
//!   recomputed for each operation rather than cached, trading some speed
//!   for small key objects.
//!
//! # X.509 and PKCS #8 encodings (RFC 9881)
//!
//! The same OBJECT IDENTIFIER, [`ParameterSet::OID`] (`id-ml-dsa-44`, `-65`
//! or `-87`), identifies a parameter set's public keys, private keys and
//! signatures; its parameters are always absent, and an
//! `AlgorithmIdentifier` with any parameters (NULL included) is rejected.
//!
//! * [`VerifyingKey::from_spki_der`] and [`VerifyingKey::to_spki_der`] read
//!   and write the RFC 9881 §4 `SubjectPublicKeyInfo`: the raw public key in
//!   a BIT STRING without unused bits ([`VerifyingKey::SPKI_LEN`] bytes).
//! * [`SigningKey::from_pkcs8_der`] reads an RFC 9881 §6 PKCS #8
//!   `OneAsymmetricKey` (version 1 or 2) in strict DER, with the private
//!   key in any of the three `ML-DSA-*-PrivateKey` CHOICE forms, `seed`,
//!   `expandedKey` and `both`, told apart by tag only. An `expandedKey` is
//!   validated as by [`SigningKey::from_expanded_bytes`], which cannot
//!   check its `K`; the `seed` and `both` forms detect a changed `K`. For
//!   `both`, the expanded key derived from the seed must equal the
//!   presented one byte for byte (the RFC 9881 §8.2 consistency check, in
//!   constant time). With every form, an optional `publicKey` must equal
//!   the public key of the private key. Failing a check rejects the key.
//!   Attributes must have the DER `Attribute` structure and are otherwise
//!   ignored (their values and SET OF ordering are not checked).
//! * [`SigningKey::to_pkcs8_der`] writes version 1 (no attributes, no public
//!   key) in the [`PrivateKeyFormat`] chosen; the seed form RFC 9881
//!   RECOMMENDS needs a key that still has its seed.
//!
//! Loading a private key and comparing its `SubjectPublicKeyInfo` with a
//! certificate's associates the key with the certificate.
//!
//! # Stack use
//!
//! Nothing allocates. All temporaries are sized for the parameter set in
//! use. Signing holds the expanded matrix `A` (`k l` polynomials of 1 KiB)
//! for the whole rejection loop plus about `2 l + 3 k + 3` further
//! polynomials and `k` 256-byte hint rows. Key generation and the
//! expanded-key check (`k + l + 3` polynomials) and verification (`l + 4`
//! polynomials and the hints) sample `A` one entry at a time. Peak stack
//! measured on x86-64 in a release build: signing about 42, 66 and 102 KiB
//! (ML-DSA-44, -65, -87), key generation up to about 20 KiB, verification
//! up to about 15 KiB. Other targets and compiler versions differ.
//!
//! # Hedged and deterministic signing
//!
//! [`SigningKey::sign`] is the hedged variant FIPS 204 §3.4 recommends:
//! 32 fresh bytes `rnd` from the random source enter the derivation of the
//! mask seed together with the private `K` and the message digest `mu`. If
//! the source fails the call returns [`Error::RandomFailure`]; it never
//! falls back to deterministic signing.
//! [`SigningKey::sign_deterministic`] uses `rnd = 0^32`, so signing the same
//! message twice repeats the computation exactly. That makes fault attacks
//! easier (a fault in one of two identical runs can yield a differential
//! that exposes key material) and exposes the same computation to repeated
//! side-channel measurement; prefer hedged signing unless reproducible
//! signatures are required. Neither variant depends on the quality of the
//! randomness for unforgeability.
//!
//! # Side channels
//!
//! The portable scalar code avoids secret-dependent branches, memory
//! indices and divisions, with these exceptions, all public or independent
//! of secrets by design:
//!
//! * The number of signing iterations (rejections), the leak inherent in
//!   signing with aborts (FIPS 204 Algorithm 7): each iteration draws a
//!   fresh mask `y`, and the expected count depends only on the parameter
//!   set up to a weak statistical dependence on the key. Each iteration
//!   computes all four rejection conditions (`||z||`, `||r0||`, `||c t0||`,
//!   hint count) over every coefficient without early exit and branches
//!   only on the combined bit, so which condition failed, and where, is not
//!   revealed.
//! * Rejection sampling: `ExpandA` samples the public matrix and branches
//!   freely. `ExpandS` (key generation) and `SampleInBall` (signing) consume
//!   a data-dependent number of SHAKE bytes; which candidates are rejected
//!   is independent of the accepted values. Accepted `ExpandS` coefficients
//!   are computed branch-free. The `SampleInBall` swap reads and writes
//!   through masked scans of all 256 positions, with the masks passed
//!   through a value barrier ([`core::hint::black_box`]) to discourage the
//!   compiler from turning the scans back into an indexed access. The
//!   aim is that the challenge positions of a rejected iteration (an
//!   intermediate value that FIPS 204 §3.6.3 requires to stay secret) do
//!   not leak through memory access or branches.
//! * `Decompose`, `HighBits`, `LowBits` and `MakeHint` on secret-dependent
//!   values use multiply-shift constants, never `/` or `%` (the
//!   KyberSlash class of timing leak). Modular reductions are
//!   branch-free (Montgomery, a shift-based `reduce32`, mask-based
//!   conditional additions). The sign masks of the conditional additions,
//!   of `centre`, of the norm checks and of `Decompose` go through the same
//!   value barrier: without it LLVM turns `(x >> 31) & c` into a select,
//!   and an earlier form of this code was observed to compile the
//!   `r1 = 44` wrap of `Decompose` to a conditional branch on x86-64. The
//!   barrier is defence in depth, not a measured necessity of the present
//!   source, and not a guarantee: `black_box` is a best-effort hint that
//!   the standard library does not offer for security purposes. The
//!   evidence is the inspection described next.
//! * The expanded-key check compares `t0` and `tr` with an accumulated XOR
//!   and reveals only accept or reject.
//! * Verification works on public data and may branch (hint decoding,
//!   `UseHint`, the norm check of `z`).
//!
//! Beyond these source-level properties, the generated code was inspected
//! once, for rustc 1.100.0 release builds (`codegen-units = 1`) of
//! `x86_64-unknown-linux-gnu` (default CPU and `x86-64-v3`),
//! `aarch64-unknown-linux-gnu` and `riscv64gc-unknown-linux-gnu`: in
//! `sample_in_ball`, the signing loop, key generation and the expanded-key
//! check, the only conditional branches were loop control, bounds checks
//! on public indices, the combined accept bit, the `ExpandMask` counter
//! bound, the rejection branches listed above, hint packing after
//! acceptance and CPU-feature detection.
//! This is a manual inspection of one compiler version, not a proof; other
//! compilers, options or targets may differ.
//!
//! Secret intermediates (`xi`, `rho'`, `K`, `s1`, `s2`, `t0`, their NTT
//! forms, `y`, `z`, `w`, `c t0`, the hints of rejected iterations, `rho''`
//! and `rnd`) are zeroised after use, and keys on drop. As elsewhere in this
//! crate, the SHAKE states that absorbed them are not wiped. Rust moves
//! values by copying them, and a moved-from copy is not wiped: returning a
//! key from [`SigningKey::from_seed`], [`SigningKey::from_expanded_bytes`]
//! or [`SigningKey::generate`], moving a `SigningKey`, and the
//! [`Zeroizing`] returned by [`SigningKey::to_expanded_bytes`] can each
//! leave an unwiped copy of the private key on the stack. The constructors
//! write the key into its final structure rather than moving it in, which
//! avoids one such copy but not the return itself. Keep keys in place (for
//! example behind a reference or in a `Box`) where this matters.
//!
//! # Backends
//!
//! Only the portable scalar backend exists; the polynomial arithmetic lives
//! in its own module so that a SIMD backend can be added later. ML-DSA does
//! not take part in load-aware routing ([`crate::accel::load`]).

mod dsa;
mod encode;
mod params;
mod pkcs8;
mod poly;
mod rounding;
mod sample;

#[cfg(test)]
mod kat_tests;
#[cfg(test)]
mod tests;

use core::marker::PhantomData;

pub use params::{ByteArray, MlDsa44, MlDsa65, MlDsa87, ParameterSet};
pub use pkcs8::PrivateKeyFormat;

use crate::Error;
use crate::hash::Shake256;
use crate::rand::SecureRandom;
use crate::zeroize::{Zeroize, Zeroizing};

/// Seed (`xi`) length in bytes.
pub const SEED_LEN: usize = 32;
/// Maximum context string length in bytes.
pub const MAX_CONTEXT_LEN: usize = 255;

/// `mu = H(tr || M', 64)` with `M' = prefix || msg`.
fn compute_mu(tr: &[u8; 64], prefix: &[&[u8]], msg: &[u8]) -> [u8; 64] {
    let mut h = Shake256::new();
    h.update(tr);
    for p in prefix {
        h.update(p);
    }
    h.update(msg);
    let mut mu = [0u8; 64];
    h.finalize_xof().read(&mut mu);
    mu
}

/// `mu` for the pure external interface: `M' = 0 || |ctx| || ctx || M`
/// (FIPS 204 Algorithms 2 and 3).
fn external_mu(tr: &[u8; 64], msg: &[u8], ctx: &[u8]) -> Result<[u8; 64], Error> {
    let Ok(len) = u8::try_from(ctx.len()) else {
        return Err(Error::InvalidLength);
    };
    Ok(compute_mu(tr, &[&[0, len], ctx], msg))
}

/// An ML-DSA verifying (public) key.
#[derive(Clone)]
pub struct VerifyingKey<P: ParameterSet> {
    bytes: P::VerifyingKeyBytes,
    /// `tr = H(pk, 64)`.
    tr: [u8; 64],
    _p: PhantomData<P>,
}

impl<P: ParameterSet> core::fmt::Debug for VerifyingKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("parameter_set", &P::NAME)
            .finish_non_exhaustive()
    }
}

impl<P: ParameterSet> PartialEq for VerifyingKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: ParameterSet> Eq for VerifyingKey<P> {}

impl<P: ParameterSet> VerifyingKey<P> {
    /// Parses an encoded public key (`pkDecode`, FIPS 204 Algorithm 23).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `bytes` is not
    /// [`ParameterSet::VERIFYING_KEY_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::VERIFYING_KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let mut arr = P::VerifyingKeyBytes::zeroed();
        arr.as_mut().copy_from_slice(bytes);
        Ok(Self::from_array(arr))
    }

    fn from_array(bytes: P::VerifyingKeyBytes) -> Self {
        let mut tr = [0u8; 64];
        let mut h = Shake256::new();
        h.update(bytes.as_ref());
        h.finalize_xof().read(&mut tr);
        Self {
            bytes,
            tr,
            _p: PhantomData,
        }
    }

    /// The encoded key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// The encoded key as an array.
    #[must_use]
    pub fn to_bytes(&self) -> P::VerifyingKeyBytes {
        self.bytes
    }

    /// ML-DSA.Verify (FIPS 204 Algorithm 3) with an empty context.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSignature`] for every rejection, including a wrong
    /// signature length and a malformed hint encoding.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.verify_with_context(msg, &[], sig)
    }

    /// ML-DSA.Verify (FIPS 204 Algorithm 3) with context string `ctx`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `ctx` is longer than
    /// [`MAX_CONTEXT_LEN`] bytes; [`Error::InvalidSignature`] for every
    /// rejection of the signature.
    pub fn verify_with_context(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), Error> {
        let mu = external_mu(&self.tr, msg, ctx)?;
        self.verify_mu(&mu, sig)
    }

    /// Verification from `mu` (the external-mu form of
    /// ML-DSA.Verify_internal).
    pub(crate) fn verify_mu(&self, mu: &[u8; 64], sig: &[u8]) -> Result<(), Error> {
        if sig.len() == P::SIGNATURE_LEN && P::verify_mu(self.bytes.as_ref(), mu, sig) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// ML-DSA.Verify_internal (FIPS 204 Algorithm 8) on the formatted
    /// message `M'` (known-answer tests only).
    #[cfg(test)]
    pub(crate) fn verify_internal(&self, m_prime: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.verify_mu(&compute_mu(&self.tr, &[], m_prime), sig)
    }
}

/// An ML-DSA signing (private) key. Zeroised on drop.
pub struct SigningKey<P: ParameterSet> {
    /// The expanded private key `rho || K || tr || s1 || s2 || t0`.
    sk: P::SigningKeyBytes,
    /// `xi`, when the key was created from a seed.
    seed: [u8; SEED_LEN],
    has_seed: bool,
    vk: VerifyingKey<P>,
}

impl<P: ParameterSet> Drop for SigningKey<P> {
    fn drop(&mut self) {
        self.sk.zeroize();
        self.seed.zeroize();
    }
}

impl<P: ParameterSet> core::fmt::Debug for SigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("parameter_set", &P::NAME)
            .finish_non_exhaustive()
    }
}

impl<P: ParameterSet> SigningKey<P> {
    /// Generates a key from a fresh 32-byte seed (ML-DSA.KeyGen, FIPS 204
    /// Algorithm 1).
    ///
    /// # Errors
    ///
    /// [`Error::RandomFailure`] if `rng` fails.
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self, Error> {
        let mut seed = Zeroizing([0u8; SEED_LEN]);
        rng.fill(&mut seed.0)?;
        Ok(Self::from_seed(&seed))
    }

    /// Derives the key from the seed `xi` (ML-DSA.KeyGen_internal, FIPS 204
    /// Algorithm 6).
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        // The private key is written in place rather than moved in.
        let mut key = Self::empty();
        let mut pk = P::VerifyingKeyBytes::zeroed();
        P::keygen(seed, pk.as_mut(), key.sk.as_mut());
        key.seed = *seed;
        key.has_seed = true;
        key.vk = VerifyingKey::from_array(pk);
        key
    }

    /// An all-zero key, to be filled in place.
    fn empty() -> Self {
        Self {
            sk: P::SigningKeyBytes::zeroed(),
            seed: [0; SEED_LEN],
            has_seed: false,
            vk: VerifyingKey {
                bytes: P::VerifyingKeyBytes::zeroed(),
                tr: [0; 64],
                _p: PhantomData,
            },
        }
    }

    /// Loads an expanded private key (`skDecode`, FIPS 204 Algorithm 25)
    /// and validates it: `s1` and `s2` coefficients must lie in
    /// `[-eta, eta]`, and the stored `t0` and `tr` must equal the values
    /// recomputed from `rho`, `s1` and `s2`. The verifying key is derived
    /// in the process. The checks reveal only whether the key was accepted.
    /// The signing seed `K` is not bound to the rest of the key and cannot
    /// be checked; only a key derived from its seed detects a changed `K`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a wrong length, [`Error::InvalidKey`]
    /// if a check fails.
    pub fn from_expanded_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::SIGNING_KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let mut pk = P::VerifyingKeyBytes::zeroed();
        if !P::check_expanded(bytes, pk.as_mut()) {
            return Err(Error::InvalidKey);
        }
        let mut key = Self::empty();
        key.sk.as_mut().copy_from_slice(bytes);
        key.vk = VerifyingKey::from_array(pk);
        Ok(key)
    }

    /// The seed `xi`, if the key was created from one (`None` for a key
    /// loaded with [`Self::from_expanded_bytes`]).
    #[must_use]
    pub fn seed(&self) -> Option<&[u8; SEED_LEN]> {
        self.has_seed.then_some(&self.seed)
    }

    /// The expanded FIPS 204 encoding (`skEncode`, Algorithm 24).
    #[must_use]
    pub fn to_expanded_bytes(&self) -> Zeroizing<P::SigningKeyBytes> {
        Zeroizing(self.sk)
    }

    /// The corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey<P> {
        &self.vk
    }

    /// Hedged ML-DSA.Sign (FIPS 204 Algorithm 2) with context string
    /// `ctx`: `rnd` is 32 fresh bytes from `rng`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `ctx` is longer than
    /// [`MAX_CONTEXT_LEN`] bytes; [`Error::RandomFailure`] if `rng` fails
    /// (there is no deterministic fallback); [`Error::InvalidKey`] in the
    /// negligible-probability case that the signing loop exhausts its
    /// 16-bit counter.
    pub fn sign(
        &self,
        msg: &[u8],
        ctx: &[u8],
        rng: &dyn SecureRandom,
    ) -> Result<P::Signature, Error> {
        let mu = external_mu(&self.vk.tr, msg, ctx)?;
        let mut rnd = Zeroizing([0u8; 32]);
        rng.fill(&mut rnd.0)?;
        self.sign_mu(&mu, &rnd)
    }

    /// Deterministic ML-DSA.Sign (`rnd = 0^32`, FIPS 204 §3.4) with context
    /// string `ctx`. See the [module documentation](self) for why hedged
    /// signing is preferable.
    ///
    /// # Errors
    ///
    /// As [`Self::sign`], without the random source.
    pub fn sign_deterministic(&self, msg: &[u8], ctx: &[u8]) -> Result<P::Signature, Error> {
        let mu = external_mu(&self.vk.tr, msg, ctx)?;
        self.sign_mu(&mu, &[0; 32])
    }

    /// Signing from `mu` (the external-mu form of ML-DSA.Sign_internal).
    pub(crate) fn sign_mu(&self, mu: &[u8; 64], rnd: &[u8; 32]) -> Result<P::Signature, Error> {
        let mut sig = P::Signature::zeroed();
        P::sign_mu(self.sk.as_ref(), mu, rnd, sig.as_mut())?;
        Ok(sig)
    }

    /// ML-DSA.Sign_internal (FIPS 204 Algorithm 7) on the formatted message
    /// `M'` (known-answer tests only).
    #[cfg(test)]
    pub(crate) fn sign_internal(
        &self,
        m_prime: &[u8],
        rnd: &[u8; 32],
    ) -> Result<P::Signature, Error> {
        self.sign_mu(&compute_mu(&self.vk.tr, &[], m_prime), rnd)
    }
}
