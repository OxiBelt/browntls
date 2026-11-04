//! ECDSA (FIPS 186-5, section 6) with RFC 6979 nonces.
//!
//! Nonces come from the RFC 6979 HMAC_DRBG seeded with the private key and the
//! message digest. Hedged signing appends fresh randomness to that seed as the
//! `k'` additional data of RFC 6979 section 3.6, so a failed RNG degrades to
//! plain deterministic signing instead of nonce reuse, while a bias in the
//! deterministic derivation is masked by the randomness.
//!
//! Signing is constant time in the private key and the nonce (fixed-base
//! comb, constant-time inversion, Montgomery arithmetic modulo `n`).
//! Verification is variable time, as its inputs are public.

use crate::Error;
use crate::der::{self, Writer, tag};
use crate::hash::{
    HashAlgorithm, HashFunction, Output, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384,
    Sha512,
};
use crate::hmac::Hmac;
use crate::zeroize::{Zeroizing, zeroize_bytes, zeroize_u64};

use super::curve::{Affine, Curve, fe_to_canonical, to_affine};
use super::jacobian;
use super::keys::{MAX_FIELD_LEN, SecretScalar};
use super::mont;
use super::scalar_mul;

/// Length of the DER `Ecdsa-Sig-Value` for the worst-case `r` and `s` of a
/// curve with `field_len`-byte scalars.
pub(crate) const fn der_max_len(field_len: usize) -> usize {
    let int_tlv = header_len(field_len + 1) + field_len + 1;
    header_len(2 * int_tlv) + 2 * int_tlv
}

const fn header_len(content: usize) -> usize {
    if content < 0x80 {
        2
    } else if content < 0x100 {
        3
    } else {
        4
    }
}

/// `x mod n` for `x < p < 2n`.
#[inline]
fn reduce_once<C: Curve<N>, const N: usize>(x: &[u64; N]) -> [u64; N] {
    let (d, borrow) = mont::sub(x, &C::ORDER);
    mont::select(mont::barrier((borrow ^ 1).wrapping_neg()), &d, x)
}

/// `bits2int(digest) mod n`: the leftmost `min(8 * len, BITS)` bits of the
/// digest, reduced once (RFC 6979 section 2.3.2, FIPS 186-5 section 6.4.1).
pub(crate) fn digest_to_scalar<C: Curve<N>, const N: usize>(digest: &[u8]) -> [u64; N] {
    let take = digest.len().min(C::FIELD_LEN);
    let mut e = mont::from_be_bytes::<N>(&digest[..take]).unwrap_or([0; N]);
    let excess = (8 * take).saturating_sub(C::BITS);
    if excess > 0 {
        // excess < 8 because take <= ceil(BITS / 8).
        #[allow(clippy::cast_possible_truncation)]
        {
            e = mont::shr_small(&e, excess as u32);
        }
    }
    reduce_once::<C, N>(&e)
}

/// `1 <= v < n`, as a declassified public outcome.
fn in_scalar_range<C: Curve<N>, const N: usize>(v: &[u64; N]) -> bool {
    let ok = mont::lt(v, &C::ORDER) & !mont::is_zero(v);
    crate::ct::Choice::from_bit(ok & 1).declassify()
}

/// RFC 6979 section 3.2 HMAC_DRBG over hash `H`. The state is derived from the
/// private key; `k` and `v` are zeroised on drop.
///
/// The HMAC keyed with the current `K` is kept and cloned for each MAC under
/// that key, and the state update after an output (step h.3) is deferred to
/// the next request, which only happens when a candidate nonce is rejected.
/// The output stream is that of RFC 6979.
struct HmacDrbg<H: HashFunction> {
    k: H::Output,
    v: H::Output,
    keyed: Hmac<H>,
    stale: bool,
}

impl<H: HashFunction> Drop for HmacDrbg<H> {
    fn drop(&mut self) {
        zeroize_bytes(self.k.as_mut());
        zeroize_bytes(self.v.as_mut());
    }
}

impl<H: HashFunction> HmacDrbg<H> {
    /// Steps b–g: instantiate with `int2octets(x) || bits2octets(h1) || k'`.
    fn new(seed: &[&[u8]]) -> Self {
        let k = H::Output::zeroed();
        let mut d = Self {
            keyed: Hmac::<H>::new(k.as_ref()),
            k,
            v: H::Output::zeroed(),
            stale: false,
        };
        for b in d.v.as_mut() {
            *b = 0x01;
        }
        d.update(seed);
        d
    }

    /// `HMAC_K(V)` under the current key.
    fn mac_v(&self) -> H::Output {
        let mut m = self.keyed.clone();
        m.update(self.v.as_ref());
        m.finalize()
    }

    /// `K = HMAC_K(V || 0x00 || seed); V = HMAC_K(V); K = HMAC_K(V || 0x01 || seed); V = HMAC_K(V)`.
    fn update(&mut self, seed: &[&[u8]]) {
        for sep in [0x00u8, 0x01] {
            let mut m = self.keyed.clone();
            m.update(self.v.as_ref());
            m.update(&[sep]);
            for part in seed {
                m.update(part);
            }
            self.k = m.finalize();
            self.keyed = Hmac::<H>::new(self.k.as_ref());
            self.v = self.mac_v();
            if seed.is_empty() {
                break;
            }
        }
    }

    /// Step h: fills `out` with `V` blocks (after the deferred update of the
    /// previous request, if any).
    fn generate(&mut self, out: &mut [u8]) {
        if self.stale {
            self.update(&[]);
        }
        let mut filled = 0;
        while filled < out.len() {
            self.v = self.mac_v();
            let take = (out.len() - filled).min(H::OUTPUT_LEN);
            out[filled..filled + take].copy_from_slice(&self.v.as_ref()[..take]);
            filled += take;
        }
        self.stale = true;
    }
}

macro_rules! dyn_drbg {
    ($($variant:ident),*) => {
        /// A run-time selected [`HmacDrbg`].
        enum DynDrbg {
            $($variant(HmacDrbg<$variant>),)*
        }

        impl DynDrbg {
            fn new(alg: HashAlgorithm, seed: &[&[u8]]) -> Self {
                match alg {
                    $(HashAlgorithm::$variant => Self::$variant(HmacDrbg::new(seed)),)*
                }
            }

            fn generate(&mut self, out: &mut [u8]) {
                match self {
                    $(Self::$variant(d) => d.generate(out),)*
                }
            }
        }
    };
}

dyn_drbg!(Sha224, Sha256, Sha384, Sha512, Sha3_256, Sha3_384, Sha3_512);

/// Produces `(r, s)` for `digest` under `d`. `extra` is the optional RFC 6979
/// section 3.6 additional data (fresh randomness for hedged signatures).
pub(crate) fn sign<C: Curve<N>, const N: usize>(
    d: &SecretScalar<N>,
    alg: HashAlgorithm,
    digest: &[u8],
    extra: Option<&[u8]>,
) -> Result<([u64; N], [u64; N]), Error> {
    let fl = C::FIELD_LEN;
    let e = digest_to_scalar::<C, N>(digest);
    let mut x_octets = Zeroizing([0u8; MAX_FIELD_LEN]);
    mont::to_be_bytes(&d.0, &mut x_octets[..fl]);
    let mut h_octets = [0u8; MAX_FIELD_LEN];
    mont::to_be_bytes(&e, &mut h_octets[..fl]);
    let mut drbg = DynDrbg::new(
        alg,
        &[&x_octets[..fl], &h_octets[..fl], extra.unwrap_or(&[])],
    );
    let mut d_mont = Zeroizing(mont::to_mont(&d.0, &C::ORDER, C::ORDER_INV, &C::ORDER_R2));
    let mut t = Zeroizing([0u8; MAX_FIELD_LEN]);
    // A nonce out of range or a zero r / s is a 2^-128 event; the bound keeps
    // the loop finite without affecting conforming behaviour.
    for _ in 0..256 {
        drbg.generate(&mut t[..fl]);
        let mut k = Zeroizing(mont::from_be_bytes::<N>(&t[..fl]).unwrap_or([0; N]));
        // bits2int keeps the leftmost BITS bits of the 8 * fl generated.
        let shift = 8 * fl - C::BITS;
        if shift > 0 {
            #[allow(clippy::cast_possible_truncation)]
            {
                *k = mont::shr_small(&k, shift as u32);
            }
        }
        if !in_scalar_range::<C, N>(&k) {
            continue;
        }
        let mut kg = scalar_mul::mul_base::<C, N>(&k);
        let r_point = to_affine::<C, N>(&kg);
        zeroize_u64(&mut kg.x);
        zeroize_u64(&mut kg.y);
        zeroize_u64(&mut kg.z);
        let Some(r_point) = r_point else {
            continue;
        };
        let r = reduce_once::<C, N>(&fe_to_canonical::<C, N>(&r_point.x));
        if mont::is_zero(&r) != 0 {
            continue;
        }
        // s = k^-1 (e + r d) mod n, with k^-1 and d in Montgomery form so each
        // product lands in the plain domain.
        let k_mont = Zeroizing(mont::to_mont(&k, &C::ORDER, C::ORDER_INV, &C::ORDER_R2));
        let k_inv = Zeroizing(C::scalar_invert(&k_mont));
        let rd = Zeroizing(mont::mont_mul(&r, &d_mont, &C::ORDER, C::ORDER_INV));
        let sum = Zeroizing(mont::add_mod(&e, &rd, &C::ORDER));
        let s = mont::mont_mul(&sum, &k_inv, &C::ORDER, C::ORDER_INV);
        if mont::is_zero(&s) != 0 {
            continue;
        }
        zeroize_u64(&mut *d_mont);
        return Ok((r, s));
    }
    zeroize_u64(&mut *d_mont);
    Err(Error::RandomFailure)
}

/// Verifies `(r, s)` over `digest` for the public point `q`. Variable time.
pub(crate) fn verify<C: Curve<N>, const N: usize>(
    q: &Affine<N>,
    digest: &[u8],
    r: &[u64; N],
    s: &[u64; N],
) -> Result<(), Error> {
    if !in_scalar_range::<C, N>(r) || !in_scalar_range::<C, N>(s) {
        return Err(Error::InvalidSignature);
    }
    let e = digest_to_scalar::<C, N>(digest);
    let s_mont = mont::to_mont(s, &C::ORDER, C::ORDER_INV, &C::ORDER_R2);
    let w = C::scalar_invert(&s_mont);
    let u1 = mont::mont_mul(&e, &w, &C::ORDER, C::ORDER_INV);
    let u2 = mont::mont_mul(r, &w, &C::ORDER, C::ORDER_INV);
    let point = scalar_mul::mul_double_vartime::<C, N>(&u1, &u2, q);
    // x(point) mod n == r, i.e. x == r or (when r + n < p) x == r + n, checked
    // projectively as X == x Z^2 (no inversion). The identity never matches.
    if jacobian::x_equals::<C, N>(&point, &fe_from_canonical_rt::<C, N>(r)) {
        return Ok(());
    }
    let (rn, carry) = mont::add(r, &C::ORDER);
    if carry == 0
        && mont::lt(&rn, &C::P) != 0
        && jacobian::x_equals::<C, N>(&point, &fe_from_canonical_rt::<C, N>(&rn))
    {
        return Ok(());
    }
    Err(Error::InvalidSignature)
}

/// Converts a public value `a < p` into the field's Montgomery form.
#[inline]
fn fe_from_canonical_rt<C: Curve<N>, const N: usize>(a: &[u64; N]) -> [u64; N] {
    C::mul(a, &C::R2)
}

/// Writes the DER `Ecdsa-Sig-Value` of `(r, s)`; returns the length.
pub(crate) fn encode_der<C: Curve<N>, const N: usize>(
    r: &[u64; N],
    s: &[u64; N],
    out: &mut [u8],
) -> Result<usize, Error> {
    let fl = C::FIELD_LEN;
    let mut rb = [0u8; MAX_FIELD_LEN];
    let mut sb = [0u8; MAX_FIELD_LEN];
    mont::to_be_bytes(r, &mut rb[..fl]);
    mont::to_be_bytes(s, &mut sb[..fl]);
    let content = Writer::positive_integer_len(&rb[..fl]) + Writer::positive_integer_len(&sb[..fl]);
    let mut w = Writer::new(out);
    w.header(tag::SEQUENCE, content)?;
    w.positive_integer(&rb[..fl])?;
    w.positive_integer(&sb[..fl])?;
    Ok(w.len())
}

/// Loads a DER INTEGER magnitude (sign octet already stripped) as a scalar in
/// `[1, n - 1]`.
fn scalar_from_der_int<C: Curve<N>, const N: usize>(bytes: &[u8]) -> Result<[u64; N], Error> {
    if bytes.len() > C::FIELD_LEN {
        return Err(Error::InvalidEncoding);
    }
    let v = mont::from_be_bytes::<N>(bytes).ok_or(Error::InvalidEncoding)?;
    if in_scalar_range::<C, N>(&v) {
        Ok(v)
    } else {
        Err(Error::InvalidEncoding)
    }
}

/// Parses a strict DER `Ecdsa-Sig-Value` with `1 <= r, s < n`.
pub(crate) fn decode_der<C: Curve<N>, const N: usize>(
    sig: &[u8],
) -> Result<([u64; N], [u64; N]), Error> {
    der::parse_sequence(sig, |rd| {
        let r = scalar_from_der_int::<C, N>(rd.read_positive_integer()?)?;
        let s = scalar_from_der_int::<C, N>(rd.read_positive_integer()?)?;
        Ok((r, s))
    })
}

/// Parses the fixed-size `r || s` form (IEEE P1363) with `1 <= r, s < n`.
pub(crate) fn decode_fixed<C: Curve<N>, const N: usize>(
    sig: &[u8],
) -> Result<([u64; N], [u64; N]), Error> {
    let fl = C::FIELD_LEN;
    if sig.len() != 2 * fl {
        return Err(Error::InvalidEncoding);
    }
    let r = scalar_from_der_int::<C, N>(&sig[..fl])?;
    let s = scalar_from_der_int::<C, N>(&sig[fl..])?;
    Ok((r, s))
}

/// Writes `r || s`, each `FIELD_LEN` bytes.
pub(crate) fn encode_fixed<C: Curve<N>, const N: usize>(
    r: &[u64; N],
    s: &[u64; N],
    out: &mut [u8],
) {
    let fl = C::FIELD_LEN;
    mont::to_be_bytes(r, &mut out[..fl]);
    mont::to_be_bytes(s, &mut out[fl..2 * fl]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{DynHash, HashAlgorithm};
    use crate::nist::params::P256;

    #[test]
    fn der_lengths() {
        assert_eq!(der_max_len(32), 72);
        assert_eq!(der_max_len(48), 104);
        assert_eq!(der_max_len(66), 141);
    }

    #[test]
    fn digest_truncation_and_reduction() {
        // A 64-byte digest is truncated to its first 32 bytes for P-256.
        let digest = [0xffu8; 64];
        let e = digest_to_scalar::<P256, 4>(&digest);
        let (expected, _) = mont::sub(&[u64::MAX; 4], &P256::ORDER);
        assert_eq!(e, expected);
        // A short digest is used as is.
        assert_eq!(digest_to_scalar::<P256, 4>(&[1, 2]), [0x0102, 0, 0, 0]);
    }

    /// The DRBG (cached key, deferred update) produces the stream of a
    /// literal RFC 6979 section 3.2 implementation, retries included.
    #[test]
    fn drbg_matches_reference_stream() {
        use crate::hash::Sha256;
        fn mac(k: &[u8], parts: &[&[u8]]) -> [u8; 32] {
            let mut m = Hmac::<Sha256>::new(k);
            for p in parts {
                m.update(p);
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(m.finalize().as_ref());
            out
        }
        let seed: [&[u8]; 3] = [&[0x11; 32], &[0x22; 32], &[0x33; 32]];
        // Steps b-g.
        let mut v = [1u8; 32];
        let mut k = [0u8; 32];
        k = mac(&k, &[&v, &[0], seed[0], seed[1], seed[2]]);
        v = mac(&k, &[&v]);
        k = mac(&k, &[&v, &[1], seed[0], seed[1], seed[2]]);
        v = mac(&k, &[&v]);
        let mut drbg = DynDrbg::new(HashAlgorithm::Sha256, &seed);
        for len in [32usize, 48, 32, 64, 1] {
            // Step h: T = V blocks, then K = HMAC_K(V || 0), V = HMAC_K(V).
            let mut want = std::vec::Vec::new();
            while want.len() < len {
                v = mac(&k, &[&v]);
                want.extend_from_slice(&v);
            }
            let mut got = std::vec![0u8; len];
            drbg.generate(&mut got);
            assert_eq!(got[..], want[..len]);
            k = mac(&k, &[&v, &[0]]);
            v = mac(&k, &[&v]);
        }
    }

    #[test]
    fn drbg_matches_rfc6979_a1_structure() {
        // Deterministic: the same seed yields the same stream.
        let mut a = DynDrbg::new(HashAlgorithm::Sha256, &[b"key", b"hash"]);
        let mut b = DynDrbg::new(HashAlgorithm::Sha256, &[b"key", b"hash"]);
        let mut x = [0u8; 40];
        let mut y = [0u8; 40];
        a.generate(&mut x);
        b.generate(&mut y);
        assert_eq!(x, y);
        a.generate(&mut x);
        assert_ne!(x, y);
        let _ = DynHash::digest(HashAlgorithm::Sha256, b"");
    }
}
