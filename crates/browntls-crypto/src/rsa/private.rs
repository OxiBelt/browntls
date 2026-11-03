//! RSA private keys: PKCS #1 / PKCS #8 parsing, consistency validation,
//! export, and CRT signing with base blinding and a fault check.
//!
//! # Signing (RSASP1 with CRT)
//!
//! 1. Derive a blinding factor `r` (see [`RsaPrivateKey::derive_blinding`])
//!    and blind the encoded message: `m' = m r^e mod n` (public exponent).
//! 2. Reduce `m'` modulo `p` and `q` with Montgomery multiplications only,
//!    then compute `s_p' = m'^dp mod p` and `s_q' = m'^dq mod q` with the
//!    constant-time fixed-window exponentiation.
//! 3. Unblind each half with `r^-1 mod p = r^(p-2)` and `r^-1 mod q = r^(q-2)`
//!    (Fermat; same constant-time exponentiation), and recombine with
//!    Garner's formula `s = s_q + q ((s_p - s_q) qInv mod p)`.
//! 4. Verify `s^e mod n == m` with the public key before releasing `s`; a
//!    mismatch (hardware fault, inconsistent key) returns an error.
//!
//! Every step has a running time that depends only on the key size.

use super::bigint::mont::Mont;
use super::bigint::{self, HALF_LIMBS, MAX_LIMBS};
use super::{MAX_MODULUS_BYTES, OID_RSA_ENCRYPTION, RsaPublicKey, pkcs1, pss};
use crate::Error;
use crate::ct::{self, Choice};
use crate::der::{self, Writer, tag};
use crate::hash::{DynHash, HashAlgorithm, MAX_OUTPUT_LEN, Shake256};
use crate::rand::SecureRandom;
use crate::zeroize::Zeroize;

/// Byte capacity of a CRT half.
const HALF_BYTES: usize = MAX_MODULUS_BYTES / 2;

/// Upper bound on the length of a PKCS #1 `RSAPrivateKey` encoding produced
/// by [`RsaPrivateKey::to_pkcs1_der`] (an 8192-bit key needs 4655 bytes).
pub const MAX_PKCS1_PRIVATE_KEY_DER_LEN: usize = 4672;
/// Upper bound on the length of a PKCS #8 `PrivateKeyInfo` encoding produced
/// by [`RsaPrivateKey::to_pkcs8_der`].
pub const MAX_PKCS8_PRIVATE_KEY_DER_LEN: usize = MAX_PKCS1_PRIVATE_KEY_DER_LEN + 32;

/// Message signed during the load-time self-test.
const SELF_TEST_MESSAGE: &[u8] = b"browntls RSA private key self-test";

/// An RSA private key with CRT parameters.
///
/// Secret components are zeroised on drop. The structure is about 8 KiB;
/// callers may want to keep it boxed.
pub struct RsaPrivateKey {
    public: RsaPublicKey,
    p: Mont<HALF_LIMBS>,
    q: Mont<HALF_LIMBS>,
    dp: [u64; HALF_LIMBS],
    dq: [u64; HALF_LIMBS],
    /// `q^-1 mod p` in Montgomery form modulo `p`.
    qinv_mont: [u64; HALF_LIMBS],
    /// `q^-1 mod p` (kept for export).
    qinv: [u64; HALF_LIMBS],
    /// The private exponent (kept for export).
    d: [u64; MAX_LIMBS],
    /// Limbs of each prime (`ceil(limbs(n) / 2)`).
    half: usize,
}

impl core::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("bits", &self.public.modulus_bits())
            .finish_non_exhaustive()
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv_mont.zeroize();
        self.qinv.zeroize();
        self.d.zeroize();
        // `p` and `q` zeroise themselves.
    }
}

/// Big-endian components of an `RSAPrivateKey`.
struct Components<'a> {
    n: &'a [u8],
    e: &'a [u8],
    d: &'a [u8],
    p: &'a [u8],
    q: &'a [u8],
    dp: &'a [u8],
    dq: &'a [u8],
    qinv: &'a [u8],
}

fn parse_pkcs1<'a>(der: &'a [u8]) -> Result<Components<'a>, Error> {
    der::parse_sequence(der, |r| {
        if r.read_small_integer()? != 0 {
            // Multi-prime keys (version 1) are not supported.
            return Err(Error::Unsupported);
        }
        Ok(Components {
            n: r.read_positive_integer()?,
            e: r.read_positive_integer()?,
            d: r.read_positive_integer()?,
            p: r.read_positive_integer()?,
            q: r.read_positive_integer()?,
            dp: r.read_positive_integer()?,
            dq: r.read_positive_integer()?,
            qinv: r.read_positive_integer()?,
        })
    })
}

/// `TRUE` when `e * x == 1 (mod modulus - 1)` for an odd prime `modulus`
/// (`x` of any length). Constant time.
#[inline(never)]
fn exponent_consistent(e: u64, x: &[u64], modulus: &[u64]) -> Choice {
    let mut t = [0u64; MAX_LIMBS + 1];
    let t = &mut t[..x.len() + 1];
    bigint::mul_word(t, x, e);
    let borrow = bigint::sub_word(t, 1);
    let mut m1 = [0u64; HALF_LIMBS];
    let m1 = &mut m1[..modulus.len()];
    m1.copy_from_slice(modulus);
    bigint::sub_word(m1, 1);
    let mut r = [0u64; HALF_LIMBS];
    let r = &mut r[..modulus.len()];
    bigint::ct_mod(r, t, m1);
    let ok = bigint::is_zero(r).and(ct::is_zero_u64(borrow));
    t.zeroize();
    m1.zeroize();
    r.zeroize();
    ok
}

/// `TRUE` when `q * qinv == 1 (mod p)`. Constant time.
#[inline(never)]
fn coefficient_consistent(q: &[u64], qinv: &[u64], p: &[u64]) -> Choice {
    let mut prod = [0u64; MAX_LIMBS];
    let prod = &mut prod[..2 * p.len()];
    bigint::mul(prod, q, qinv);
    let mut r = [0u64; HALF_LIMBS];
    let r = &mut r[..p.len()];
    bigint::ct_mod(r, prod, p);
    let mut one = [0u64; HALF_LIMBS];
    one[0] = 1;
    let ok = bigint::ct_eq(r, &one[..p.len()]);
    prod.zeroize();
    r.zeroize();
    ok
}

/// Reduces an `x` of up to `2 * ctx.len()` limbs into Montgomery form modulo
/// the context's prime using multiplications only (constant time).
#[inline(never)]
fn reduce_to_mont(ctx: &Mont<HALF_LIMBS>, x: &[u64], out: &mut [u64]) {
    let h = ctx.len();
    debug_assert!(x.len() >= h && x.len() <= 2 * h && out.len() == h);
    let mut lo = [0u64; HALF_LIMBS];
    let mut hi = [0u64; HALF_LIMBS];
    lo[..h].copy_from_slice(&x[..h]);
    hi[..x.len() - h].copy_from_slice(&x[h..]);
    let mut a = [0u64; HALF_LIMBS];
    let mut b = [0u64; HALF_LIMBS];
    ctx.to_mont(&mut a[..h], &lo[..h]); // lo R
    ctx.to_mont(&mut b[..h], &hi[..h]); // hi R
    ctx.to_mont(&mut lo[..h], &b[..h]); // hi R^2 = Montgomery form of hi R
    bigint::mod_add(out, &a[..h], &lo[..h], ctx.modulus());
    lo.zeroize();
    hi.zeroize();
    a.zeroize();
    b.zeroize();
}

/// Fills `buf` from the operating-system entropy source when one is
/// compiled in; returns `false` otherwise or on failure.
fn os_entropy(buf: &mut [u8]) -> bool {
    #[cfg(any(
        all(
            target_os = "linux",
            any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "riscv64"
            )
        ),
        feature = "getrandom"
    ))]
    {
        return crate::rand::OsRng.fill(buf).is_ok();
    }
    #[allow(unreachable_code)]
    {
        let _ = buf;
        false
    }
}

impl RsaPrivateKey {
    /// Parses a PKCS #1 `RSAPrivateKey` (RFC 8017, appendix A.1.2) and
    /// validates it.
    ///
    /// Validation checks `n = p q`, `e dP = 1 (mod p-1)`, `e dQ = 1 (mod q-1)`,
    /// `e d = 1 (mod p-1)` and `(mod q-1)`, `q qInv = 1 (mod p)`, the size
    /// rules of [`RsaPublicKey::from_components`], and finally signs and
    /// verifies a test message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for malformed DER,
    /// [`Error::Unsupported`] for multi-prime keys and [`Error::InvalidKey`]
    /// for inconsistent or out-of-range components. `p` and `q` must each fit
    /// in `ceil(limbs(n) / 2)` 64-bit limbs with a non-zero top limb, which
    /// holds for every balanced key.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        let c = parse_pkcs1(der)?;
        Self::from_components(&c)
    }

    /// Parses a PKCS #8 `PrivateKeyInfo` (RFC 5208 / RFC 5958 version 1 or
    /// 2) holding an `rsaEncryption` key, and validates it as
    /// [`Self::from_pkcs1_der`].
    ///
    /// # Errors
    ///
    /// As [`Self::from_pkcs1_der`].
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let inner = der::parse_sequence(der, |r| {
            if r.read_small_integer()? > 1 {
                return Err(Error::InvalidEncoding);
            }
            let mut alg = r.read_sequence()?;
            if alg.read_oid()? != OID_RSA_ENCRYPTION || !alg.read(tag::NULL)?.is_empty() {
                return Err(Error::InvalidEncoding);
            }
            alg.finish()?;
            let key = r.read_octet_string()?;
            // attributes [0] IMPLICIT SET OF Attribute OPTIONAL
            r.read_optional(tag::context_constructed(0))?;
            // publicKey [1] IMPLICIT BIT STRING OPTIONAL (version 2)
            r.read_optional(tag::context_primitive(1))?;
            Ok(key)
        })?;
        Self::from_pkcs1_der(inner)
    }

    /// Generates a new key with `e = 65537` and `bits` in `{2048, 3072,
    /// 4096}`, following FIPS 186-5 appendix A.1.3 (probable primes with
    /// Miller–Rabin), then validates it like a loaded key.
    ///
    /// Key generation is not constant time (trial division and candidate
    /// rejection are data dependent), which is standard for this rare
    /// operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] for other sizes and
    /// [`Error::RandomFailure`] if the entropy source fails or no prime is
    /// found within the attempt budget.
    pub fn generate(bits: usize, rng: &dyn SecureRandom) -> Result<Self, Error> {
        super::keygen::generate(bits, rng)
    }

    #[inline(never)]
    fn from_components(c: &Components<'_>) -> Result<Self, Error> {
        let public = RsaPublicKey::from_components(c.n, c.e)?;
        let l = public.limbs();
        let half = l.div_ceil(2);
        let mut d = [0u64; MAX_LIMBS];
        let mut p = [0u64; HALF_LIMBS];
        let mut q = [0u64; HALF_LIMBS];
        let mut dp = [0u64; HALF_LIMBS];
        let mut dq = [0u64; HALF_LIMBS];
        let mut qinv = [0u64; HALF_LIMBS];
        let loaded = bigint::from_be_bytes(&mut d[..l], c.d)
            .and(bigint::from_be_bytes(&mut p[..half], c.p))
            .and(bigint::from_be_bytes(&mut q[..half], c.q))
            .and(bigint::from_be_bytes(&mut dp[..half], c.dp))
            .and(bigint::from_be_bytes(&mut dq[..half], c.dq))
            .and(bigint::from_be_bytes(&mut qinv[..half], c.qinv));
        let result = match loaded {
            Ok(()) => Self::from_limbs(
                public,
                &d[..l],
                &p[..half],
                &q[..half],
                &dp[..half],
                &dq[..half],
                &qinv[..half],
            ),
            Err(_) => Err(Error::InvalidKey),
        };
        d.zeroize();
        p.zeroize();
        q.zeroize();
        dp.zeroize();
        dq.zeroize();
        qinv.zeroize();
        result
    }

    /// Builds and validates a key from limb components (`p`, `q`, `dp`,
    /// `dq`, `qinv` of `ceil(limbs(n) / 2)` limbs, `d` of `limbs(n)` limbs).
    pub(super) fn from_limbs(
        public: RsaPublicKey,
        d: &[u64],
        p: &[u64],
        q: &[u64],
        dp: &[u64],
        dq: &[u64],
        qinv: &[u64],
    ) -> Result<Self, Error> {
        let l = public.limbs();
        let half = l.div_ceil(2);
        if d.len() != l || [p, q, dp, dq, qinv].iter().any(|x| x.len() != half) {
            return Err(Error::InvalidKey);
        }
        let kernel = public.n.kernel();
        let p_ctx = Mont::<HALF_LIMBS>::new(p, kernel)?;
        let q_ctx = Mont::<HALF_LIMBS>::new(q, kernel)?;

        // Range checks (RFC 8017 appendix A.1.2): 0 < d < n, dP < p, dQ < q,
        // qInv < p, p != q.
        let mut n_pad = [0u64; MAX_LIMBS];
        n_pad[..l].copy_from_slice(public.n.modulus());
        let mut ok = bigint::ct_lt(d, &n_pad[..l])
            .and(!bigint::is_zero(d))
            .and(bigint::ct_lt(dp, p))
            .and(bigint::ct_lt(dq, q))
            .and(bigint::ct_lt(qinv, p))
            .and(!bigint::ct_eq(p, q));

        // n == p q
        let mut prod = [0u64; MAX_LIMBS];
        bigint::mul(&mut prod[..2 * half], p, q);
        n_pad[l..2 * half].fill(0);
        ok = ok.and(bigint::ct_eq(&prod[..2 * half], &n_pad[..2 * half]));
        prod.zeroize();

        // Exponent relations.
        let e = public.e();
        ok = ok
            .and(exponent_consistent(e, dp, p))
            .and(exponent_consistent(e, dq, q))
            .and(exponent_consistent(e, d, p))
            .and(exponent_consistent(e, d, q))
            .and(coefficient_consistent(q, qinv, p));
        if !ok.declassify() {
            return Err(Error::InvalidKey);
        }

        let mut key = Self {
            public,
            p: p_ctx,
            q: q_ctx,
            dp: [0; HALF_LIMBS],
            dq: [0; HALF_LIMBS],
            qinv_mont: [0; HALF_LIMBS],
            qinv: [0; HALF_LIMBS],
            d: [0; MAX_LIMBS],
            half,
        };
        key.dp[..half].copy_from_slice(dp);
        key.dq[..half].copy_from_slice(dq);
        key.qinv[..half].copy_from_slice(qinv);
        key.d[..l].copy_from_slice(d);
        key.p.to_mont(&mut key.qinv_mont[..half], qinv);

        // Sign/verify self-test (the fault check inside `rsasp1` verifies the
        // signature with the public key; this also catches composite primes).
        key.self_test()?;
        Ok(key)
    }

    #[inline(never)]
    fn self_test(&self) -> Result<(), Error> {
        let k = self.modulus_len_bytes();
        let mut em = [0u8; MAX_MODULUS_BYTES];
        let mut sig = [0u8; MAX_MODULUS_BYTES];
        pkcs1::encode(HashAlgorithm::Sha256, SELF_TEST_MESSAGE, &mut em[..k])
            .map_err(|_| Error::InvalidKey)?;
        self.rsasp1(&em[..k], &[], &mut sig[..k])
            .map_err(|_| Error::InvalidKey)
    }

    /// The corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    /// Modulus length in bytes (the signature length).
    #[must_use]
    pub fn modulus_len_bytes(&self) -> usize {
        self.public.modulus_len_bytes()
    }

    /// Modulus length in bits.
    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        self.public.modulus_bits()
    }

    /// Signs `msg` with RSASSA-PKCS1-v1_5 and writes the signature to `out`,
    /// returning its length (the modulus length).
    ///
    /// PKCS #1 v1.5 signatures are deterministic; the blinding factor is
    /// derived from the key, the message and, when an operating-system
    /// entropy source is compiled in, fresh random bytes. Use
    /// [`Self::sign_pkcs1v15_with_rng`] to supply the entropy explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out` is too small or the modulus
    /// is too short for `hash`, and [`Error::InvalidKey`] if the signature
    /// fails the internal verification (fault detected).
    pub fn sign_pkcs1v15(
        &self,
        hash: HashAlgorithm,
        msg: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut entropy = [0u8; 32];
        let have = os_entropy(&mut entropy);
        let result = self.sign_pkcs1v15_inner(hash, msg, if have { &entropy } else { &[] }, out);
        entropy.zeroize();
        result
    }

    /// [`Self::sign_pkcs1v15`] with caller-supplied entropy for blinding.
    ///
    /// # Errors
    ///
    /// As [`Self::sign_pkcs1v15`], plus errors from `rng`.
    pub fn sign_pkcs1v15_with_rng(
        &self,
        hash: HashAlgorithm,
        msg: &[u8],
        rng: &dyn SecureRandom,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut entropy = [0u8; 32];
        rng.fill(&mut entropy)?;
        let result = self.sign_pkcs1v15_inner(hash, msg, &entropy, out);
        entropy.zeroize();
        result
    }

    fn sign_pkcs1v15_inner(
        &self,
        hash: HashAlgorithm,
        msg: &[u8],
        entropy: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let k = self.modulus_len_bytes();
        if out.len() < k {
            return Err(Error::InvalidLength);
        }
        let mut em = [0u8; MAX_MODULUS_BYTES];
        pkcs1::encode(hash, msg, &mut em[..k])?;
        self.rsasp1(&em[..k], entropy, &mut out[..k])?;
        Ok(k)
    }

    /// Signs `msg` with RSASSA-PSS (MGF1 with `hash`, salt length equal to
    /// the digest length) and writes the signature to `out`, returning its
    /// length (the modulus length). `rng` provides the salt and blinding
    /// entropy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out` is too small or the modulus
    /// is too short for `hash`, errors from `rng`, and [`Error::InvalidKey`]
    /// if the signature fails the internal verification (fault detected).
    pub fn sign_pss(
        &self,
        hash: HashAlgorithm,
        msg: &[u8],
        rng: &dyn SecureRandom,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let k = self.modulus_len_bytes();
        let h_len = hash.output_len();
        let em_bits = self.modulus_bits() - 1;
        let em_len = em_bits.div_ceil(8);
        if out.len() < k || em_len < 2 * h_len + 2 {
            return Err(Error::InvalidLength);
        }
        let mut salt = [0u8; MAX_OUTPUT_LEN];
        rng.fill(&mut salt[..h_len])?;
        let mut entropy = [0u8; 32];
        rng.fill(&mut entropy)?;
        let m_hash = DynHash::digest(hash, msg);
        let mut em = [0u8; MAX_MODULUS_BYTES];
        pss::encode(
            hash,
            m_hash.as_ref(),
            &salt[..h_len],
            em_bits,
            &mut em[k - em_len..k],
        )?;
        let result = self.rsasp1(&em[..k], &entropy, &mut out[..k]);
        salt.zeroize();
        entropy.zeroize();
        result.map(|()| k)
    }

    /// Derives the blinding factor `r < 2^(bits-1)` (odd) from the key, the
    /// encoded message and optional fresh entropy with SHAKE256. Without
    /// entropy the derivation is deterministic but unpredictable to anyone
    /// who does not know `p` and `q`.
    #[inline(never)]
    fn derive_blinding(&self, em: &[u8], entropy: &[u8], r: &mut [u64]) {
        let half = self.half;
        let mut xof = Shake256::new();
        xof.update(b"browntls-rsa-blinding-v1");
        let mut buf = [0u8; HALF_BYTES];
        bigint::to_be_bytes(self.p.modulus(), &mut buf[..half * 8]);
        xof.update(&buf[..half * 8]);
        bigint::to_be_bytes(self.q.modulus(), &mut buf[..half * 8]);
        xof.update(&buf[..half * 8]);
        buf.zeroize();
        xof.update(&(em.len() as u64).to_be_bytes());
        xof.update(em);
        xof.update(&(entropy.len() as u64).to_be_bytes());
        xof.update(entropy);
        let mut reader = xof.finalize_xof();
        let k = self.modulus_len_bytes();
        let mut rb = [0u8; MAX_MODULUS_BYTES];
        reader.read(&mut rb[..k]);
        // `k` bytes always fit in `limbs(n)` limbs.
        let _ = bigint::from_be_bytes(r, &rb[..k]);
        rb.zeroize();
        // Clear bits from `bits - 1` upwards so that r < 2^(bits-1) <= n.
        let top = self.modulus_bits() - 1;
        let limb = top / 64;
        let shift = top % 64;
        r[limb] &= if shift == 0 { 0 } else { (1u64 << shift) - 1 };
        for x in r[limb + 1..].iter_mut() {
            *x = 0;
        }
        r[0] |= 1;
    }

    /// RSASP1 with CRT, blinding and fault check. `em` and `out` are `k`
    /// bytes; `em` must encode an integer below `n`.
    #[inline(never)]
    pub(super) fn rsasp1(&self, em: &[u8], entropy: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let k = self.modulus_len_bytes();
        let l = self.public.limbs();
        let half = self.half;
        if em.len() != k || out.len() != k {
            return Err(Error::InvalidLength);
        }
        let n = &self.public.n;
        let e = self.public.e();

        let mut m = [0u64; MAX_LIMBS];
        bigint::from_be_bytes(&mut m[..l], em).map_err(|_| Error::InvalidLength)?;
        if !bigint::ct_lt(&m[..l], n.modulus()).declassify() {
            return Err(Error::InvalidLength);
        }

        // Blinding: m_blind = m r^e mod n.
        let mut r = [0u64; MAX_LIMBS];
        self.derive_blinding(em, entropy, &mut r[..l]);
        let mut t1 = [0u64; MAX_LIMBS];
        let mut t2 = [0u64; MAX_LIMBS];
        n.to_mont(&mut t1[..l], &r[..l]); // r in Montgomery form
        n.exp_pub_vartime(&mut t2[..l], &t1[..l], e); // (r^e) Montgomery form
        n.to_mont(&mut t1[..l], &m[..l]); // m in Montgomery form
        let mut m_blind = [0u64; MAX_LIMBS];
        n.mul(&mut m_blind[..l], &t1[..l], &t2[..l]); // (m r^e) Montgomery form
        n.demont(&mut t1[..l], &m_blind[..l]);
        m_blind[..l].copy_from_slice(&t1[..l]); // m r^e mod n, normal form

        // CRT exponentiations on the blinded message.
        let mut sp = [0u64; HALF_LIMBS];
        let mut sq = [0u64; HALF_LIMBS];
        let mut base = [0u64; HALF_LIMBS];
        reduce_to_mont(&self.p, &m_blind[..l], &mut base[..half]);
        self.p
            .exp_ct(&mut sp[..half], &base[..half], &self.dp[..half]);
        reduce_to_mont(&self.q, &m_blind[..l], &mut base[..half]);
        self.q
            .exp_ct(&mut sq[..half], &base[..half], &self.dq[..half]);

        // Unblind each half: multiply by r^-1 = r^(prime - 2).
        let mut exp = [0u64; HALF_LIMBS];
        let mut rinv = [0u64; HALF_LIMBS];
        let mut tmp = [0u64; HALF_LIMBS];
        reduce_to_mont(&self.p, &r[..l], &mut base[..half]);
        exp[..half].copy_from_slice(self.p.modulus());
        bigint::sub_word(&mut exp[..half], 2);
        self.p
            .exp_ct(&mut rinv[..half], &base[..half], &exp[..half]);
        self.p.mul(&mut tmp[..half], &sp[..half], &rinv[..half]);
        sp[..half].copy_from_slice(&tmp[..half]);
        reduce_to_mont(&self.q, &r[..l], &mut base[..half]);
        exp[..half].copy_from_slice(self.q.modulus());
        bigint::sub_word(&mut exp[..half], 2);
        self.q
            .exp_ct(&mut rinv[..half], &base[..half], &exp[..half]);
        self.q.mul(&mut tmp[..half], &sq[..half], &rinv[..half]);
        sq[..half].copy_from_slice(&tmp[..half]);

        // Garner: s = s_q + q * ((s_p - s_q) qInv mod p).
        let mut sq_n = [0u64; HALF_LIMBS];
        self.q.demont(&mut sq_n[..half], &sq[..half]); // s_q, normal form, < q
        self.p.to_mont(&mut tmp[..half], &sq_n[..half]); // s_q mod p, Montgomery form
        let mut diff = [0u64; HALF_LIMBS];
        bigint::mod_sub(
            &mut diff[..half],
            &sp[..half],
            &tmp[..half],
            self.p.modulus(),
        );
        self.p
            .mul(&mut tmp[..half], &diff[..half], &self.qinv_mont[..half]);
        let mut h = [0u64; HALF_LIMBS];
        self.p.demont(&mut h[..half], &tmp[..half]); // h < p
        // Reuse the (dead) blinded-message buffer for the signature.
        let s = &mut m_blind;
        bigint::mul(&mut s[..2 * half], self.q.modulus(), &h[..half]);
        let carry = bigint::add_assign(&mut s[..half], &sq_n[..half]);
        bigint::add_word(&mut s[half..2 * half], carry);
        // s < n, so the limbs above `l` are zero.
        debug_assert!(bigint::is_zero(&s[l..2 * half]).declassify());

        // Fault check: s^e mod n must equal the encoded message.
        n.to_mont(&mut t1[..l], &s[..l]);
        n.exp_pub_vartime(&mut t2[..l], &t1[..l], e);
        n.demont(&mut t1[..l], &t2[..l]);
        let good = bigint::ct_eq(&t1[..l], &m[..l]);
        // Never release a bad signature: clear it on failure.
        let keep = core::hint::black_box(good.mask());
        for limb in s[..l].iter_mut() {
            *limb &= keep;
        }
        bigint::to_be_bytes(&s[..l], out);

        r.zeroize();
        t1.zeroize();
        t2.zeroize();
        m_blind.zeroize();
        m.zeroize();
        sp.zeroize();
        sq.zeroize();
        base.zeroize();
        exp.zeroize();
        rinv.zeroize();
        tmp.zeroize();
        sq_n.zeroize();
        diff.zeroize();
        h.zeroize();
        if good.declassify() {
            Ok(())
        } else {
            out.zeroize();
            Err(Error::InvalidKey)
        }
    }

    /// Writes the PKCS #1 `RSAPrivateKey` encoding to `out` and returns its
    /// length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out` is too small
    /// ([`MAX_PKCS1_PRIVATE_KEY_DER_LEN`] bytes always suffice).
    pub fn to_pkcs1_der(&self, out: &mut [u8]) -> Result<usize, Error> {
        let k = self.modulus_len_bytes();
        let hb = self.half * 8;
        let mut d = [0u8; MAX_MODULUS_BYTES];
        let mut p = [0u8; HALF_BYTES];
        let mut q = [0u8; HALF_BYTES];
        let mut dp = [0u8; HALF_BYTES];
        let mut dq = [0u8; HALF_BYTES];
        let mut qinv = [0u8; HALF_BYTES];
        let l = self.public.limbs();
        bigint::to_be_bytes(&self.d[..l], &mut d[..k]);
        bigint::to_be_bytes(self.p.modulus(), &mut p[..hb]);
        bigint::to_be_bytes(self.q.modulus(), &mut q[..hb]);
        bigint::to_be_bytes(&self.dp[..self.half], &mut dp[..hb]);
        bigint::to_be_bytes(&self.dq[..self.half], &mut dq[..hb]);
        bigint::to_be_bytes(&self.qinv[..self.half], &mut qinv[..hb]);
        let ints: [&[u8]; 9] = [
            &[0],
            self.public.n_be(),
            self.public.e_be(),
            &d[..k],
            &p[..hb],
            &q[..hb],
            &dp[..hb],
            &dq[..hb],
            &qinv[..hb],
        ];
        let content: usize = ints.iter().map(|i| Writer::positive_integer_len(i)).sum();
        let mut w = Writer::new(out);
        let result = w.header(tag::SEQUENCE, content).and_then(|()| {
            for i in ints {
                w.positive_integer(i)?;
            }
            Ok(w.len())
        });
        d.zeroize();
        p.zeroize();
        q.zeroize();
        dp.zeroize();
        dq.zeroize();
        qinv.zeroize();
        if result.is_err() {
            out.zeroize();
        }
        result
    }

    /// Writes the PKCS #8 `PrivateKeyInfo` (version 0) encoding to `out` and
    /// returns its length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out` is too small
    /// ([`MAX_PKCS8_PRIVATE_KEY_DER_LEN`] bytes always suffice).
    pub fn to_pkcs8_der(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut inner = [0u8; MAX_PKCS1_PRIVATE_KEY_DER_LEN];
        let result = self.to_pkcs1_der(&mut inner).and_then(|n| {
            let alg_len = 2 + OID_RSA_ENCRYPTION.len() + 2;
            let content = 3 + 2 + alg_len + der::header_len(n) + n;
            let mut w = Writer::new(out);
            w.header(tag::SEQUENCE, content)?;
            w.tlv(tag::INTEGER, &[0])?;
            w.header(tag::SEQUENCE, alg_len)?;
            w.tlv(tag::OID, &OID_RSA_ENCRYPTION)?;
            w.tlv(tag::NULL, &[])?;
            w.tlv(tag::OCTET_STRING, &inner[..n])?;
            Ok(w.len())
        });
        inner.zeroize();
        if result.is_err() {
            out.zeroize();
        }
        result
    }
}
