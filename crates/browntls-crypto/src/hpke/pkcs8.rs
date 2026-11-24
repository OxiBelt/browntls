//! PKCS#8 for the five DHKEM private keys supported by HPKE.

use super::ber::{Budget, MAX_BYTES, Reader};
use super::{Kem, MAX_PRIVATE_KEY_LEN, MAX_PUBLIC_KEY_LEN, PrivateKey};
use crate::Error;
use crate::der::{Writer, header_len, tag};
use crate::nist::{p256, p384, p521};
use crate::zeroize::Zeroizing;

#[cfg(all(test, feature = "alloc"))]
mod tests;

const ID_X25519: &[u8] = &[0x2b, 0x65, 0x6e];
const ID_X448: &[u8] = &[0x2b, 0x65, 0x6f];
const ID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const ID_EC_DH: &[u8] = &[0x2b, 0x81, 0x04, 0x01, 0x0c];

const PARAMETERS: u8 = tag::context_constructed(0);
const ATTRIBUTES: u8 = tag::context_constructed(0);
const INNER_PUBLIC: u8 = tag::context_constructed(1);
const OUTER_PUBLIC: u8 = tag::context_primitive(1);
const OUTER_PUBLIC_CONSTRUCTED: u8 = tag::context_constructed(1);
const SET: u8 = 0x31;
const MAX_INNER_DER_LEN: usize = p521::SEC1_PRIVATE_MAX_LEN;

/// Maximum buffer size needed by [`PrivateKey::to_pkcs8_der`].
///
/// The largest encoding is P-521. This bound allows the inner SEC 1
/// encoding, its OCTET STRING header (3), the outer SEQUENCE header (3),
/// version (3), and algorithm identifier (18).
pub const MAX_PKCS8_DER_LEN: usize = MAX_INNER_DER_LEN + 27;

impl PrivateKey {
    /// Imports a BER or DER PKCS#8 `PrivateKeyInfo` or `OneAsymmetricKey`
    /// for any supported DHKEM.
    ///
    /// X25519 and X448 use the nested OCTET STRING from RFC 8410 with
    /// absent parameters. Imported scalars are clamped. NIST keys use
    /// RFC 5915 with an outer named curve and either `id-ecPublicKey` or
    /// `id-ecDH`, preserving the algorithm OID for export. Short NIST
    /// scalars are zero-padded on the left. Any inner parameters and
    /// embedded public keys must match the key.
    /// Attribute envelopes and values are checked structurally and discarded.
    ///
    /// The BER decoder allows indefinite-length constructed values and
    /// segmented strings, with limits of 16 KiB each for input and total
    /// flattened bytes, 16 levels and 4096 TLVs, including encapsulated
    /// ASN.1. Public keys must be byte-aligned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] on malformed input or a resource
    /// limit violation, and [`Error::InvalidKey`] for an unsupported
    /// algorithm or curve, an invalid scalar or inconsistent key material.
    pub fn from_pkcs8_der_or_ber(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let mut budget = Budget::default();
        let mut outer = Reader::new(input, 0);
        let mut scalar = Zeroizing([0; MAX_PRIVATE_KEY_LEN]);
        let (kem, ecdh_oid, inner_public, outer_public) =
            outer.constructed(tag::SEQUENCE, &mut budget, |r, budget| {
                let version = read_version(r, budget)?;
                let (kem, ecdh_oid) = r.constructed(tag::SEQUENCE, budget, read_algorithm)?;
                let scalar = &mut scalar[..kem.private_key_len()];
                let inner_public = r.octets::<MAX_BYTES, _>(budget, |bytes, depth, budget| {
                    read_private_value(bytes, depth, budget, kem, scalar)
                })?;
                if r.peek() == Some(ATTRIBUTES) {
                    r.constructed(ATTRIBUTES, budget, read_attributes)?;
                }
                let outer_public = match (version, r.peek()) {
                    (0, None) => None,
                    (1, Some(OUTER_PUBLIC | OUTER_PUBLIC_CONSTRUCTED)) => {
                        Some(read_public(r, OUTER_PUBLIC, budget)?)
                    }
                    _ => return Err(Error::InvalidEncoding),
                };
                Ok((kem, ecdh_oid, inner_public, outer_public))
            })?;
        outer.finish()?;
        let key = Self::from_bytes(kem, &scalar[..kem.private_key_len()])?;
        for public in [inner_public, outer_public].into_iter().flatten() {
            if !public.matches(&key) {
                return Err(Error::InvalidKey);
            }
        }
        Ok(if ecdh_oid {
            key.with_pkcs8_ecdh_oid()
        } else {
            key
        })
    }

    /// Writes a canonical DER PKCS#8 `PrivateKeyInfo` into `out`.
    ///
    /// NIST keys use `id-ecPublicKey` or `id-ecDH` with a named curve and
    /// an RFC 5915 private key containing the curve and uncompressed
    /// public point. See [`Self::pkcs8_uses_ecdh_oid`].
    /// X25519 and X448 scalars are written clamped with absent algorithm
    /// parameters, using the RFC 8410 OCTET STRING wrapper. The returned
    /// length covers the encoded private key. The caller owns its cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if the encoding does not fit. A buffer
    /// of [`MAX_PKCS8_DER_LEN`] bytes always suffices. On error, `out`
    /// is unchanged.
    pub fn to_pkcs8_der(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut inner = Zeroizing([0u8; MAX_INNER_DER_LEN]);
        let len = self.write_pkcs8_inner_der(&mut inner[..])?;
        let (oid, curve) = match self.kem() {
            Kem::DhX25519HkdfSha256 => (ID_X25519, None),
            Kem::DhX448HkdfSha512 => (ID_X448, None),
            kem => {
                let oid = if self.pkcs8_uses_ecdh_oid() {
                    ID_EC_DH
                } else {
                    ID_EC_PUBLIC_KEY
                };
                (oid, named_curve(kem))
            }
        };
        let alg_len = tlv_len(oid.len()) + curve.map_or(0, |oid| tlv_len(oid.len()));
        let content_len = tlv_len(1) + tlv_len(alg_len) + tlv_len(len);
        let out = out
            .get_mut(..tlv_len(content_len))
            .ok_or(Error::InvalidLength)?;
        let mut writer = Writer::new(out);
        writer.header(tag::SEQUENCE, content_len)?;
        writer.tlv(tag::INTEGER, &[0])?;
        writer.header(tag::SEQUENCE, alg_len)?;
        writer.tlv(tag::OID, oid)?;
        if let Some(curve) = curve {
            writer.tlv(tag::OID, curve)?;
        }
        writer.tlv(tag::OCTET_STRING, &inner[..len])?;
        Ok(writer.len())
    }
}

fn tlv_len(len: usize) -> usize {
    header_len(len) + len
}

fn named_curve(kem: Kem) -> Option<&'static [u8]> {
    match kem {
        Kem::DhP256HkdfSha256 => Some(p256::OID),
        Kem::DhP384HkdfSha384 => Some(p384::OID),
        Kem::DhP521HkdfSha512 => Some(p521::OID),
        Kem::DhX25519HkdfSha256 | Kem::DhX448HkdfSha512 => None,
    }
}

fn read_version(r: &mut Reader<'_>, budget: &mut Budget) -> Result<u8, Error> {
    match r.primitive(tag::INTEGER, budget)? {
        [version @ (0 | 1)] => Ok(*version),
        _ => Err(Error::InvalidEncoding),
    }
}

fn read_algorithm(r: &mut Reader<'_>, budget: &mut Budget) -> Result<(Kem, bool), Error> {
    let oid = r.oid(budget)?;
    match oid {
        ID_X25519 => Ok((Kem::DhX25519HkdfSha256, false)),
        ID_X448 => Ok((Kem::DhX448HkdfSha512, false)),
        ID_EC_PUBLIC_KEY | ID_EC_DH => {
            let curve = r.oid(budget)?;
            Kem::ALL
                .into_iter()
                .find(|kem| named_curve(*kem) == Some(curve))
                .map(|kem| (kem, oid == ID_EC_DH))
                .ok_or(Error::InvalidKey)
        }
        _ => Err(Error::InvalidKey),
    }
}

fn read_private_value(
    bytes: &[u8],
    depth: usize,
    budget: &mut Budget,
    kem: Kem,
    scalar: &mut [u8],
) -> Result<Option<EmbeddedPublic>, Error> {
    let mut inner = Reader::new(bytes, depth);
    let public = if let Some(curve) = named_curve(kem) {
        inner.constructed(tag::SEQUENCE, budget, |r, budget| {
            if read_version(r, budget)? != 1 {
                return Err(Error::InvalidEncoding);
            }
            r.octets::<MAX_PRIVATE_KEY_LEN, _>(budget, |bytes, _, _| {
                let start = scalar
                    .len()
                    .checked_sub(bytes.len())
                    .filter(|_| !bytes.is_empty())
                    .ok_or(Error::InvalidKey)?;
                scalar[start..].copy_from_slice(bytes);
                Ok(())
            })?;
            if r.peek() == Some(PARAMETERS) {
                r.constructed(PARAMETERS, budget, |r, budget| {
                    if r.oid(budget)? != curve {
                        return Err(Error::InvalidKey);
                    }
                    Ok(())
                })?;
            }
            if r.peek() == Some(INNER_PUBLIC) {
                return r
                    .constructed(INNER_PUBLIC, budget, |r, budget| {
                        read_public(r, tag::BIT_STRING, budget)
                    })
                    .map(Some);
            }
            Ok(None)
        })?
    } else {
        inner.octets::<MAX_PRIVATE_KEY_LEN, _>(budget, |bytes, _, _| {
            if bytes.len() != scalar.len() {
                return Err(Error::InvalidKey);
            }
            scalar.copy_from_slice(bytes);
            Ok(())
        })?;
        None
    };
    inner.finish()?;
    Ok(public)
}

struct EmbeddedPublic {
    bytes: [u8; MAX_PUBLIC_KEY_LEN],
    len: usize,
}

impl EmbeddedPublic {
    fn matches(&self, key: &PrivateKey) -> bool {
        let supplied = &self.bytes[..self.len];
        let derived = key.public_key().as_bytes();
        if supplied == derived {
            return true;
        }
        // For compressed SEC 1, the derived point gives the only acceptable
        // x-coordinate and y parity. HPKE itself still uses uncompressed
        // NIST keys.
        let width = key.kem().private_key_len();
        named_curve(key.kem()).is_some()
            && supplied.len() == width + 1
            && supplied[0] == (0x02 | (derived[2 * width] & 1))
            && supplied[1..] == derived[1..=width]
    }
}

fn read_public(
    r: &mut Reader<'_>,
    primitive_tag: u8,
    budget: &mut Budget,
) -> Result<EmbeddedPublic, Error> {
    let mut bytes = [0u8; MAX_PUBLIC_KEY_LEN];
    let len = r.bit_string(primitive_tag, budget, &mut bytes)?;
    Ok(EmbeddedPublic { bytes, len })
}

fn read_attributes(r: &mut Reader<'_>, budget: &mut Budget) -> Result<(), Error> {
    // [0] IMPLICIT SET OF Attribute. Each Attribute has a type OID and
    // a SET OF open-typed values, which may be empty.
    while !r.at_end() {
        r.constructed(tag::SEQUENCE, budget, |r, budget| {
            r.oid(budget)?;
            r.constructed(SET, budget, |r, budget| {
                while !r.at_end() {
                    r.skip_value(budget)?;
                }
                Ok(())
            })
        })?;
    }
    Ok(())
}
