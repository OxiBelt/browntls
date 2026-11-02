//! ML-KEM (FIPS 203) at the 512, 768 and 1024 parameter sets.
//!
//! ```
//! use browntls_crypto::mlkem::{DecapsulationKey, MlKem768};
//! use browntls_crypto::rand::OsRng;
//!
//! let (dk, ek) = DecapsulationKey::<MlKem768>::generate(&OsRng)?;
//! let (ct, ss_sender) = ek.encapsulate(&OsRng)?;
//! let ss_receiver = dk.decapsulate(&ct)?;
//! assert_eq!(ss_sender, ss_receiver);
//! # Ok::<(), browntls_crypto::Error>(())
//! ```
//!
//! # Design
//!
//! * Keys and ciphertexts are fixed-size arrays; nothing allocates.
//! * Decapsulation keys are usually created from (and stored as) the 64-byte
//!   seed `d || z` ([`DecapsulationKey::from_seed`]), as TLS implementations
//!   do; the FIPS 203 expanded encoding is supported with the §7.3 hash check.
//! * Encapsulation keys are validated with the FIPS 203 §7.2 modulus check.
//! * Decapsulation uses implicit rejection: the re-encryption comparison and
//!   the selection between the real and the rejection key are constant time.
//! * Polynomial arithmetic dispatches at run time ([`Backend`]) to AVX2
//!   (x86-64), NEON (aarch64) or RVV (riscv64), falling back to portable code.
//!   All backends keep NTT-domain coefficients in the canonical FIPS 203 order
//!   and produce bit-identical results. Compression, encodings and CBD
//!   sampling are shared, branch-free scalar code (compression uses a
//!   multiply-shift, never a division).
//! * Secret polynomials and seeds are zeroised after use and on drop.

mod backend;
mod kpke;
mod params;
mod poly;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod x86;

#[cfg(test)]
mod tests;

use core::marker::PhantomData;

pub use backend::Backend;
use backend::Engine;
use params::params;
pub use params::{ByteArray, MlKem512, MlKem768, MlKem1024, ParameterSet};
use poly::{Poly, PolyVec};

use crate::Error;
use crate::hash::{HashFunction, Sha3_256, Sha3_512, Shake256};
use crate::rand::SecureRandom;
use crate::zeroize::{Zeroize, Zeroizing};

/// Shared secret length in bytes (all parameter sets).
pub const SHARED_SECRET_LEN: usize = 32;
/// Decapsulation key seed (`d || z`) length in bytes.
pub const SEED_LEN: usize = 64;

/// An ML-KEM encapsulation (public) key.
#[derive(Clone)]
pub struct EncapsulationKey<P: ParameterSet> {
    bytes: P::EncapsulationKeyBytes,
    /// `t̂`, NTT domain, coefficients in `(-q, q)`.
    t_hat: PolyVec,
    /// `H(ek)`.
    h: [u8; 32],
    engine: Engine,
    _p: PhantomData<P>,
}

impl<P: ParameterSet> core::fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncapsulationKey")
            .field("parameter_set", &P::NAME)
            .field("backend", &self.engine.backend())
            .finish_non_exhaustive()
    }
}

impl<P: ParameterSet> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: ParameterSet> Eq for EncapsulationKey<P> {}

impl<P: ParameterSet> EncapsulationKey<P> {
    /// Parses and validates an encapsulation key (FIPS 203 §7.2: length and
    /// modulus checks).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a wrong length, [`Error::InvalidKey`] if a
    /// coefficient is not reduced modulo `q`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::ENCAPSULATION_KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let k = P::K;
        let polys = &bytes[..384 * k].as_chunks::<384>().0;
        if !polys.iter().all(poly::check12) {
            return Err(Error::InvalidKey);
        }
        let mut t_hat = [Poly::ZERO; 4];
        for (t, b) in t_hat.iter_mut().zip(polys.iter()) {
            poly::decode12_raw(b, t);
        }
        let mut arr = P::EncapsulationKeyBytes::zeroed();
        arr.as_mut().copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            t_hat,
            h: Sha3_256::digest(bytes),
            engine: Engine::detect(),
            _p: PhantomData,
        })
    }

    /// Builds the key from a freshly generated `t̂` and `rho`.
    fn from_parts(t_hat: PolyVec, rho: &[u8; 32], engine: Engine) -> Self {
        let k = P::K;
        let mut bytes = P::EncapsulationKeyBytes::zeroed();
        {
            let b = bytes.as_mut();
            for (t, o) in t_hat[..k].iter().zip(b.as_chunks_mut::<384>().0) {
                poly::encode12(t, o);
            }
            b[384 * k..].copy_from_slice(rho);
        }
        Self {
            h: Sha3_256::digest(bytes.as_ref()),
            bytes,
            t_hat,
            engine,
            _p: PhantomData,
        }
    }

    /// Returns a copy that uses `backend` for its arithmetic (for testing and
    /// benchmarking).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] if the backend is not available on this CPU.
    pub fn with_backend(mut self, backend: Backend) -> Result<Self, Error> {
        self.engine = Engine::new(backend)?;
        Ok(self)
    }

    /// The arithmetic backend this key uses.
    #[must_use]
    pub fn backend(&self) -> Backend {
        self.engine.backend()
    }

    /// The encoded key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// The encoded key as an array.
    #[must_use]
    pub fn to_bytes(&self) -> P::EncapsulationKeyBytes {
        self.bytes
    }

    fn rho(&self) -> [u8; 32] {
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&self.bytes.as_ref()[384 * P::K..]);
        rho
    }

    /// Encapsulates a fresh shared secret (FIPS 203 Algorithm 20), returning
    /// the ciphertext and the 32-byte shared secret.
    ///
    /// # Errors
    ///
    /// [`Error::RandomFailure`] if `rng` fails.
    pub fn encapsulate(
        &self,
        rng: &dyn SecureRandom,
    ) -> Result<(P::Ciphertext, [u8; SHARED_SECRET_LEN]), Error> {
        let mut m = Zeroizing([0u8; 32]);
        rng.fill(&mut m.0)?;
        Ok(self.encapsulate_deterministic(&m))
    }

    /// Deterministic encapsulation with caller-provided randomness `m`
    /// (ML-KEM.Encaps_internal, FIPS 203 Algorithm 17).
    ///
    /// Only for known-answer tests: `m` must be fresh, uniformly random and
    /// secret.
    #[must_use]
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; 32],
    ) -> (P::Ciphertext, [u8; SHARED_SECRET_LEN]) {
        let mut g = Sha3_512::new();
        g.update(m);
        g.update(&self.h);
        let mut kr = g.finalize();
        let mut key = [0u8; 32];
        let mut r = [0u8; 32];
        key.copy_from_slice(&kr[..32]);
        r.copy_from_slice(&kr[32..]);
        kr.zeroize();
        let mut ct = P::Ciphertext::zeroed();
        kpke::encrypt(
            self.engine,
            params::<P>(),
            &self.t_hat,
            &self.rho(),
            m,
            &r,
            ct.as_mut(),
        );
        r.zeroize();
        (ct, key)
    }
}

/// An ML-KEM decapsulation (private) key. Zeroised on drop.
pub struct DecapsulationKey<P: ParameterSet> {
    /// `ŝ`, NTT domain, coefficients in `(-q, q)`.
    s_hat: PolyVec,
    ek: EncapsulationKey<P>,
    z: [u8; 32],
    /// `d || z` when the key was created from a seed.
    seed: [u8; SEED_LEN],
    has_seed: bool,
}

impl<P: ParameterSet> Drop for DecapsulationKey<P> {
    fn drop(&mut self) {
        poly::zeroize_vec(&mut self.s_hat);
        self.z.zeroize();
        self.seed.zeroize();
    }
}

impl<P: ParameterSet> core::fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("parameter_set", &P::NAME)
            .field("backend", &self.ek.engine.backend())
            .finish_non_exhaustive()
    }
}

impl<P: ParameterSet> DecapsulationKey<P> {
    /// Generates a key pair (FIPS 203 Algorithm 19).
    ///
    /// # Errors
    ///
    /// [`Error::RandomFailure`] if `rng` fails.
    pub fn generate(rng: &dyn SecureRandom) -> Result<(Self, EncapsulationKey<P>), Error> {
        let mut seed = Zeroizing([0u8; SEED_LEN]);
        rng.fill(&mut seed.0)?;
        let dk = Self::from_seed(&seed);
        let ek = dk.ek.clone();
        Ok((dk, ek))
    }

    /// Deterministic key generation from `d` and `z`
    /// (ML-KEM.KeyGen_internal, FIPS 203 Algorithm 16).
    #[must_use]
    pub fn generate_deterministic(d: &[u8; 32], z: &[u8; 32]) -> (Self, EncapsulationKey<P>) {
        let mut seed = Zeroizing([0u8; SEED_LEN]);
        seed[..32].copy_from_slice(d);
        seed[32..].copy_from_slice(z);
        let dk = Self::from_seed(&seed);
        let ek = dk.ek.clone();
        (dk, ek)
    }

    /// Expands the 64-byte seed `d || z` into a key pair.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self::keygen(Engine::detect(), seed)
    }

    /// Like [`Self::from_seed`] with an explicit backend (for testing and
    /// benchmarking).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] if the backend is not available on this CPU.
    pub fn from_seed_with_backend(seed: &[u8; SEED_LEN], backend: Backend) -> Result<Self, Error> {
        Ok(Self::keygen(Engine::new(backend)?, seed))
    }

    fn keygen(engine: Engine, seed: &[u8; SEED_LEN]) -> Self {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let mut t_hat = [Poly::ZERO; 4];
        let mut s_hat = [Poly::ZERO; 4];
        let mut rho = [0u8; 32];
        kpke::keygen(engine, params::<P>(), &d, &mut t_hat, &mut s_hat, &mut rho);
        d.zeroize();
        Self {
            s_hat,
            ek: EncapsulationKey::from_parts(t_hat, &rho, engine),
            z,
            seed: *seed,
            has_seed: true,
        }
    }

    /// Parses an expanded decapsulation key
    /// `dk_pke || ek || H(ek) || z` (FIPS 203 §7.3 length and hash checks; the
    /// embedded encapsulation key must also pass the §7.2 modulus check).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a wrong length, [`Error::InvalidKey`] if a
    /// check fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::DECAPSULATION_KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let k = P::K;
        let (dk_pke, rest) = bytes.split_at(384 * k);
        let (ek_bytes, rest) = rest.split_at(384 * k + 32);
        let (h, z) = rest.split_at(32);
        let ek = EncapsulationKey::<P>::from_bytes(ek_bytes).map_err(|_| Error::InvalidKey)?;
        // Public values: a variable-time comparison is fine.
        if ek.h[..] != h[..] {
            return Err(Error::InvalidKey);
        }
        let mut s_hat = [Poly::ZERO; 4];
        for (s, b) in s_hat.iter_mut().zip(dk_pke.as_chunks::<384>().0) {
            poly::decode12(b, s);
        }
        let mut zz = [0u8; 32];
        zz.copy_from_slice(z);
        Ok(Self {
            s_hat,
            ek,
            z: zz,
            seed: [0; SEED_LEN],
            has_seed: false,
        })
    }

    /// Returns a copy of this key that uses `backend` for its arithmetic (for
    /// testing and benchmarking).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] if the backend is not available on this CPU.
    pub fn with_backend(mut self, backend: Backend) -> Result<Self, Error> {
        self.ek.engine = Engine::new(backend)?;
        Ok(self)
    }

    /// The arithmetic backend this key uses.
    #[must_use]
    pub fn backend(&self) -> Backend {
        self.ek.engine.backend()
    }

    /// The corresponding encapsulation key.
    #[must_use]
    pub fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.ek
    }

    /// The 64-byte seed `d || z`, if the key was created from one.
    #[must_use]
    pub fn seed(&self) -> Option<&[u8; SEED_LEN]> {
        self.has_seed.then_some(&self.seed)
    }

    /// The expanded FIPS 203 encoding `dk_pke || ek || H(ek) || z`.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<P::DecapsulationKeyBytes> {
        let k = P::K;
        let mut out = Zeroizing(P::DecapsulationKeyBytes::zeroed());
        let b = out.0.as_mut();
        for (s, o) in self.s_hat[..k].iter().zip(b.as_chunks_mut::<384>().0) {
            poly::encode12(s, o);
        }
        let mut off = 384 * k;
        b[off..off + P::ENCAPSULATION_KEY_LEN].copy_from_slice(self.ek.as_bytes());
        off += P::ENCAPSULATION_KEY_LEN;
        b[off..off + 32].copy_from_slice(&self.ek.h);
        b[off + 32..].copy_from_slice(&self.z);
        out
    }

    /// Decapsulates `ct` (FIPS 203 Algorithm 21 with the §7.3 ciphertext
    /// length check). An invalid ciphertext of the right length yields the
    /// implicit-rejection key `J(z || ct)`; the choice is made in constant
    /// time.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `ct` has the wrong length.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<[u8; SHARED_SECRET_LEN], Error> {
        if ct.len() != P::CIPHERTEXT_LEN {
            return Err(Error::InvalidLength);
        }
        let p = params::<P>();
        let engine = self.ek.engine;
        let mut m = [0u8; 32];
        kpke::decrypt(engine, p, &self.s_hat, ct, &mut m);

        let mut g = Sha3_512::new();
        g.update(&m);
        g.update(&self.ek.h);
        let mut kr = g.finalize();
        let mut key = [0u8; 32];
        let mut r = [0u8; 32];
        key.copy_from_slice(&kr[..32]);
        r.copy_from_slice(&kr[32..]);
        kr.zeroize();

        let mut reject = [0u8; 32];
        let mut j = Shake256::new();
        j.update(&self.z);
        j.update(ct);
        j.finalize_xof().read(&mut reject);

        let mut ct2 = P::Ciphertext::zeroed();
        kpke::encrypt(
            engine,
            p,
            &self.ek.t_hat,
            &self.ek.rho(),
            &m,
            &r,
            ct2.as_mut(),
        );
        let ok = crate::ct::eq_bytes(ct, ct2.as_ref());
        crate::ct::conditional_copy(ok, &mut reject, &key);

        m.zeroize();
        r.zeroize();
        key.zeroize();
        ct2.zeroize();
        Ok(reject)
    }
}
