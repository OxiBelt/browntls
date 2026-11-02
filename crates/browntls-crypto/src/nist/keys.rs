//! Private scalars, public points and their encodings.
//!
//! * Scalars: big-endian, fixed length, validated to `1 <= d < n`, zeroised on
//!   drop.
//! * Points: SEC 1 uncompressed (`04 || X || Y`) and compressed (`02/03 || X`)
//!   with full validation (coordinates below `p`, point on the curve). The
//!   identity has no valid encoding and hybrid forms are rejected.
//! * Containers: `SubjectPublicKeyInfo` (RFC 5480), `ECPrivateKey` (RFC 5915)
//!   and `PrivateKeyInfo` / `OneAsymmetricKey` (RFC 5208 / RFC 5958), all with
//!   the `namedCurve` form only.
//!
//! Decoding of *public* material is variable time where convenient (the square
//! root for compressed points); everything touching the private scalar is
//! constant time.

use crate::Error;
use crate::ct::Choice;
use crate::der::{self, Reader, Writer, tag};
use crate::rand::SecureRandom;
use crate::zeroize::{Zeroizing, zeroize_u64};

use super::curve::{
    Affine, Curve, fe_add, fe_from_canonical, fe_neg, fe_sub, fe_to_canonical, is_on_curve,
    to_affine,
};
use super::mont;
use super::params::ID_EC_PUBLIC_KEY;
use super::scalar_mul;

/// Largest field element / scalar encoding (P-521).
pub(crate) const MAX_FIELD_LEN: usize = 66;

/// A private scalar in `[1, n - 1]` as little-endian limbs, zeroised on drop.
pub(crate) struct SecretScalar<const N: usize>(pub(crate) [u64; N]);

impl<const N: usize> Drop for SecretScalar<N> {
    fn drop(&mut self) {
        zeroize_u64(&mut self.0);
    }
}

impl<const N: usize> Clone for SecretScalar<N> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

/// Declassifies a mask (all ones / zero) that is a public outcome.
#[inline]
fn mask_is_set(mask: u64) -> bool {
    Choice::from_bit(mask & 1).declassify()
}

/// Loads a big-endian scalar. With `exact`, the length must be `FIELD_LEN`;
/// otherwise up to `FIELD_LEN` bytes are accepted (RFC 5915 encoders sometimes
/// strip leading zeros). Requires `1 <= d < n`.
pub(crate) fn scalar_from_bytes<C: Curve<N>, const N: usize>(
    bytes: &[u8],
    exact: bool,
) -> Result<SecretScalar<N>, Error> {
    if bytes.len() > C::FIELD_LEN || (exact && bytes.len() != C::FIELD_LEN) {
        return Err(Error::InvalidKey);
    }
    let d = mont::from_be_bytes::<N>(bytes).ok_or(Error::InvalidKey)?;
    let mut d = SecretScalar(d);
    let ok = mont::lt(&d.0, &C::ORDER) & !mont::is_zero(&d.0);
    if mask_is_set(ok) {
        Ok(d)
    } else {
        zeroize_u64(&mut d.0);
        Err(Error::InvalidKey)
    }
}

/// Writes the scalar big-endian into `out` (`out.len() == FIELD_LEN`).
pub(crate) fn scalar_to_bytes<const N: usize>(d: &SecretScalar<N>, out: &mut [u8]) {
    mont::to_be_bytes(&d.0, out);
}

/// Generates a uniformly random scalar in `[1, n - 1]` by rejection sampling
/// (FIPS 186-5, A.2.2). The number of iterations leaks nothing about the result.
pub(crate) fn generate<C: Curve<N>, const N: usize>(
    rng: &dyn SecureRandom,
) -> Result<SecretScalar<N>, Error> {
    let mut buf = Zeroizing([0u8; MAX_FIELD_LEN]);
    let buf = &mut buf[..C::FIELD_LEN];
    // Bits above BITS are masked so the rejection probability stays negligible.
    let top_mask: u8 = if C::BITS % 8 == 0 {
        0xff
    } else {
        (1u8 << (C::BITS % 8)) - 1
    };
    for _ in 0..128 {
        rng.fill(buf)?;
        buf[0] &= top_mask;
        if let Ok(d) = scalar_from_bytes::<C, N>(buf, true) {
            return Ok(d);
        }
    }
    Err(Error::RandomFailure)
}

/// `d * G` in affine coordinates (constant time in `d`).
pub(crate) fn public_key<C: Curve<N>, const N: usize>(
    d: &SecretScalar<N>,
) -> Result<Affine<N>, Error> {
    let mut p = scalar_mul::mul_base::<C, N>(&d.0);
    // d in [1, n - 1] never yields the identity; the check is defensive.
    let a = to_affine::<C, N>(&p).ok_or(Error::InvalidKey);
    zeroize_u64(&mut p.x);
    zeroize_u64(&mut p.y);
    zeroize_u64(&mut p.z);
    a
}

/// ECDH: the x-coordinate of `d * peer`, big-endian, into `out`
/// (`out.len() == FIELD_LEN`). Constant time in `d`.
pub(crate) fn ecdh<C: Curve<N>, const N: usize>(
    d: &SecretScalar<N>,
    peer: &Affine<N>,
    out: &mut [u8],
) -> Result<(), Error> {
    let mut p = scalar_mul::mul::<C, N>(peer, &d.0);
    let result = to_affine::<C, N>(&p);
    zeroize_u64(&mut p.x);
    zeroize_u64(&mut p.y);
    zeroize_u64(&mut p.z);
    // A valid peer point has prime order, so the product cannot be the identity.
    let mut a = result.ok_or(Error::KeyAgreementFailed)?;
    let mut x = fe_to_canonical::<C, N>(&a.x);
    mont::to_be_bytes(&x, out);
    zeroize_u64(&mut x);
    zeroize_u64(&mut a.x);
    zeroize_u64(&mut a.y);
    Ok(())
}

/// Loads a big-endian field element of exactly `FIELD_LEN` bytes, `< p`.
fn load_coordinate<C: Curve<N>, const N: usize>(bytes: &[u8]) -> Result<[u64; N], Error> {
    if bytes.len() != C::FIELD_LEN {
        return Err(Error::InvalidEncoding);
    }
    let v = mont::from_be_bytes::<N>(bytes).ok_or(Error::InvalidEncoding)?;
    if mont::lt(&v, &C::P) == 0 {
        return Err(Error::InvalidKey);
    }
    Ok(v)
}

/// Square root in `GF(p)` for `p = 3 mod 4` (all three curves): `a^((p+1)/4)`.
/// Variable time; only used on public data.
fn sqrt<C: Curve<N>, const N: usize>(a: &[u64; N]) -> Option<[u64; N]> {
    debug_assert_eq!(C::P[0] & 3, 3);
    let mut one = [0u64; N];
    one[0] = 1;
    let (p1, _) = mont::add(&C::P, &one);
    let exp = mont::shr_small(&p1, 2);
    let r = mont::pow_pubexp(a, &exp, &C::P, C::P_INV, &C::ONE);
    let r2 = mont::mont_mul(&r, &r, &C::P, C::P_INV);
    (mont::eq(&r2, a) != 0).then_some(r)
}

/// Decodes a SEC 1 point (uncompressed or compressed) with full validation.
pub(crate) fn decode_point<C: Curve<N>, const N: usize>(bytes: &[u8]) -> Result<Affine<N>, Error> {
    let fl = C::FIELD_LEN;
    match bytes {
        [0x04, rest @ ..] if rest.len() == 2 * fl => {
            let x = load_coordinate::<C, N>(&rest[..fl])?;
            let y = load_coordinate::<C, N>(&rest[fl..])?;
            let a = Affine {
                x: fe_from_canonical::<C, N>(&x),
                y: fe_from_canonical::<C, N>(&y),
            };
            if is_on_curve::<C, N>(&a) {
                Ok(a)
            } else {
                Err(Error::InvalidKey)
            }
        }
        [sign @ (0x02 | 0x03), rest @ ..] if rest.len() == fl => {
            let x = fe_from_canonical::<C, N>(&load_coordinate::<C, N>(rest)?);
            // y^2 = x^3 - 3x + b
            let x2 = mont::mont_mul(&x, &x, &C::P, C::P_INV);
            let x3 = mont::mont_mul(&x2, &x, &C::P, C::P_INV);
            let three_x = fe_add::<C, N>(&fe_add::<C, N>(&x, &x), &x);
            let rhs = fe_add::<C, N>(&fe_sub::<C, N>(&x3, &three_x), &C::B);
            let y = sqrt::<C, N>(&rhs).ok_or(Error::InvalidKey)?;
            let want_odd = *sign == 0x03;
            let is_odd = fe_to_canonical::<C, N>(&y)[0] & 1 == 1;
            let y = if is_odd == want_odd {
                y
            } else {
                fe_neg::<C, N>(&y)
            };
            // y = 0 would be a point of order two, which these curves lack.
            if (fe_to_canonical::<C, N>(&y)[0] & 1 == 1) != want_odd {
                return Err(Error::InvalidKey);
            }
            Ok(Affine { x, y })
        }
        _ => Err(Error::InvalidEncoding),
    }
}

/// Writes the uncompressed SEC 1 encoding (`out.len() == 1 + 2 * FIELD_LEN`).
pub(crate) fn encode_uncompressed<C: Curve<N>, const N: usize>(a: &Affine<N>, out: &mut [u8]) {
    let fl = C::FIELD_LEN;
    debug_assert_eq!(out.len(), 1 + 2 * fl);
    out[0] = 0x04;
    mont::to_be_bytes(&fe_to_canonical::<C, N>(&a.x), &mut out[1..1 + fl]);
    mont::to_be_bytes(&fe_to_canonical::<C, N>(&a.y), &mut out[1 + fl..]);
}

/// Reads `AlgorithmIdentifier { id-ecPublicKey, namedCurve }` for curve `C`.
fn read_ec_algorithm<C: Curve<N>, const N: usize>(r: &mut Reader<'_>) -> Result<(), Error> {
    let mut alg = r.read_sequence()?;
    if alg.read_oid()? != ID_EC_PUBLIC_KEY {
        return Err(Error::InvalidEncoding);
    }
    if alg.read_oid()? != C::OID {
        return Err(Error::InvalidKey);
    }
    alg.finish()
}

/// Parses a `SubjectPublicKeyInfo` for curve `C`.
pub(crate) fn decode_spki<C: Curve<N>, const N: usize>(der: &[u8]) -> Result<Affine<N>, Error> {
    der::parse_sequence(der, |r| {
        read_ec_algorithm::<C, N>(r)?;
        let point = r.read_bit_string_octets()?;
        decode_point::<C, N>(point)
    })
}

/// Writes a `SubjectPublicKeyInfo` with the uncompressed point; returns the length.
pub(crate) fn encode_spki<C: Curve<N>, const N: usize>(
    a: &Affine<N>,
    out: &mut [u8],
) -> Result<usize, Error> {
    // BIT STRING contents: unused-bits octet followed by the point.
    let mut bits = [0u8; 2 + 2 * MAX_FIELD_LEN];
    let bits = &mut bits[..2 + 2 * C::FIELD_LEN];
    encode_uncompressed::<C, N>(a, &mut bits[1..]);
    let alg_len = 2 + ID_EC_PUBLIC_KEY.len() + 2 + C::OID.len();
    let content = der::header_len(alg_len) + alg_len + der::header_len(bits.len()) + bits.len();
    let mut w = Writer::new(out);
    w.header(tag::SEQUENCE, content)?;
    w.header(tag::SEQUENCE, alg_len)?;
    w.tlv(tag::OID, ID_EC_PUBLIC_KEY)?;
    w.tlv(tag::OID, C::OID)?;
    w.tlv(tag::BIT_STRING, bits)?;
    Ok(w.len())
}

/// Parses an RFC 5915 `ECPrivateKey`; returns the scalar and the embedded
/// public point, if any (the caller checks it against `d * G`).
pub(crate) fn decode_sec1_private<C: Curve<N>, const N: usize>(
    der: &[u8],
) -> Result<(SecretScalar<N>, Option<Affine<N>>), Error> {
    der::parse_sequence(der, |r| decode_ec_private_key::<C, N>(r))
}

fn decode_ec_private_key<'a, C: Curve<N>, const N: usize>(
    r: &mut Reader<'a>,
) -> Result<(SecretScalar<N>, Option<Affine<N>>), Error> {
    if r.read_small_integer()? != 1 {
        return Err(Error::InvalidEncoding);
    }
    let d_bytes = r.read_octet_string()?;
    if let Some(params) = r.read_optional(tag::context_constructed(0))? {
        let mut pr = Reader::new(params);
        if pr.read_oid()? != C::OID {
            return Err(Error::InvalidKey);
        }
        pr.finish()?;
    }
    let public = match r.read_optional(tag::context_constructed(1))? {
        Some(pk) => {
            let mut pr = Reader::new(pk);
            let point = decode_point::<C, N>(pr.read_bit_string_octets()?)?;
            pr.finish()?;
            Some(point)
        }
        None => None,
    };
    let d = scalar_from_bytes::<C, N>(d_bytes, false)?;
    Ok((d, public))
}

/// Parses a PKCS#8 `PrivateKeyInfo` (v1) or `OneAsymmetricKey` (v2) holding an
/// `ECPrivateKey` for curve `C`; returns the scalar and the embedded public
/// point, if any.
pub(crate) fn decode_pkcs8<C: Curve<N>, const N: usize>(
    der: &[u8],
) -> Result<(SecretScalar<N>, Option<Affine<N>>), Error> {
    der::parse_sequence(der, |r| {
        let version = r.read_small_integer()?;
        if version > 1 {
            return Err(Error::InvalidEncoding);
        }
        read_ec_algorithm::<C, N>(r)?;
        let inner = r.read_octet_string()?;
        let (d, mut public) = decode_sec1_private::<C, N>(inner)?;
        // attributes [0] IMPLICIT Attributes OPTIONAL: skipped.
        r.read_optional(tag::context_constructed(0))?;
        if let Some(pk) = r.read_optional(tag::context_primitive(1))? {
            // [1] IMPLICIT BIT STRING (v2 only).
            if version != 1 {
                return Err(Error::InvalidEncoding);
            }
            let point = match pk {
                [0, point @ ..] => decode_point::<C, N>(point)?,
                _ => return Err(Error::InvalidEncoding),
            };
            if public.is_some_and(|inner| inner != point) {
                return Err(Error::InvalidKey);
            }
            public = Some(point);
        }
        Ok((d, public))
    })
}

/// Writes an RFC 5915 `ECPrivateKey` with parameters and public key; returns
/// the length.
pub(crate) fn encode_sec1_private<C: Curve<N>, const N: usize>(
    d: &SecretScalar<N>,
    public: &Affine<N>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let fl = C::FIELD_LEN;
    let mut d_bytes = Zeroizing([0u8; MAX_FIELD_LEN]);
    scalar_to_bytes(d, &mut d_bytes[..fl]);
    let mut bits = [0u8; 2 + 2 * MAX_FIELD_LEN];
    let bits = &mut bits[..2 + 2 * fl];
    encode_uncompressed::<C, N>(public, &mut bits[1..]);
    let oid_tlv = 2 + C::OID.len();
    let bits_tlv = der::header_len(bits.len()) + bits.len();
    let content = 3 + der::header_len(fl) + fl + 2 + oid_tlv + der::header_len(bits_tlv) + bits_tlv;
    let mut w = Writer::new(out);
    w.header(tag::SEQUENCE, content)?;
    w.tlv(tag::INTEGER, &[1])?;
    w.tlv(tag::OCTET_STRING, &d_bytes[..fl])?;
    w.header(tag::context_constructed(0), oid_tlv)?;
    w.tlv(tag::OID, C::OID)?;
    w.header(tag::context_constructed(1), bits_tlv)?;
    w.tlv(tag::BIT_STRING, bits)?;
    Ok(w.len())
}
