//! RFC 9881 ASN.1 encodings of ML-DSA keys: the private key as a PKCS #8
//! `OneAsymmetricKey` (RFC 5958, RFC 9881 §6) and the public key as a
//! `SubjectPublicKeyInfo` (RFC 9881 §4).

use super::{ParameterSet, SEED_LEN, SigningKey, VerifyingKey};
use crate::Error;
use crate::ct;
use crate::der::{self, Reader, Writer, tag};
use crate::zeroize::{Zeroizing, zeroize_bytes};

// The RFC 9881 OIDs (2.16.840.1.101.3.4.3.17 to .19) and the encoding
// lengths, checked against independently computed values (the lengths of
// the RFC 9881 Appendix C examples).
const _: () = {
    use super::{MlDsa44, MlDsa65, MlDsa87};
    const ARC: [u8; 8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    const fn is_oid(oid: &[u8], last: u8) -> bool {
        if oid.len() != 9 || oid[8] != last {
            return false;
        }
        let mut i = 0;
        while i < 8 {
            if oid[i] != ARC[i] {
                return false;
            }
            i += 1;
        }
        true
    }
    assert!(is_oid(MlDsa44::OID, 0x11));
    assert!(is_oid(MlDsa65::OID, 0x12));
    assert!(is_oid(MlDsa87::OID, 0x13));
    // Hand sums: SEQUENCE header 4, version 3, algorithm 13, OCTET STRING
    // header 4, then the CHOICE (expanded: header 4 + key; both: header 4,
    // seed 34, header 4 + key). SPKI: 4, 13, BIT STRING header 4, the
    // unused-bits octet and the key. The seed form is 54 bytes for every
    // set.
    const fn check<P: ParameterSet>(seed: usize, expanded: usize, both: usize, spki: usize) {
        assert!(tlv_len(pkcs8_content_len::<P>(PrivateKeyFormat::Seed)) == seed);
        assert!(tlv_len(pkcs8_content_len::<P>(PrivateKeyFormat::Expanded)) == expanded);
        assert!(tlv_len(pkcs8_content_len::<P>(PrivateKeyFormat::Both)) == both);
        assert!(SigningKey::<P>::PKCS8_MAX_LEN == both);
        assert!(VerifyingKey::<P>::SPKI_LEN == spki);
        assert!(4 + 13 + 4 + 1 + P::VERIFYING_KEY_LEN == spki);
        assert!(4 + 3 + 13 + 4 + 4 + P::SIGNING_KEY_LEN == expanded);
        assert!(4 + 3 + 13 + 4 + 4 + 34 + 4 + P::SIGNING_KEY_LEN == both);
    }
    check::<MlDsa44>(54, 2588, 2626, 1334);
    check::<MlDsa65>(54, 4060, 4098, 1974);
    check::<MlDsa87>(54, 4924, 4962, 2614);
};

/// The `ML-DSA-*-PrivateKey` CHOICE alternative written by
/// [`SigningKey::to_pkcs8_der`] (RFC 9881 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyFormat {
    /// `seed [0] IMPLICIT OCTET STRING (SIZE (32))`: the seed `xi` only.
    /// RFC 9881 RECOMMENDS this format.
    Seed,
    /// `expandedKey OCTET STRING`: the FIPS 204 expanded private key only.
    Expanded,
    /// `both SEQUENCE { seed, expandedKey }`.
    Both,
}

/// Length of a DER TLV with `n` bytes of content (definite length, at most
/// four length octets, which covers every ML-DSA encoding).
const fn tlv_len(n: usize) -> usize {
    n + if n < 0x80 {
        2
    } else if n < 0x100 {
        3
    } else if n < 0x1_0000 {
        4
    } else {
        5
    }
}

/// Length of `AlgorithmIdentifier { id-ml-dsa-* }` with absent parameters.
const fn alg_id_len<P: ParameterSet>() -> usize {
    tlv_len(tlv_len(P::OID.len()))
}

/// Content length of the `both` SEQUENCE.
const fn both_content_len<P: ParameterSet>() -> usize {
    tlv_len(SEED_LEN) + tlv_len(P::SIGNING_KEY_LEN)
}

/// Length of the `ML-DSA-*-PrivateKey` CHOICE encoding in `format`.
const fn choice_len<P: ParameterSet>(format: PrivateKeyFormat) -> usize {
    match format {
        PrivateKeyFormat::Seed => tlv_len(SEED_LEN),
        PrivateKeyFormat::Expanded => tlv_len(P::SIGNING_KEY_LEN),
        PrivateKeyFormat::Both => tlv_len(both_content_len::<P>()),
    }
}

/// Content length of the PKCS #8 v1 SEQUENCE in `format`: `version`
/// (INTEGER 0), `privateKeyAlgorithm` and `privateKey`.
const fn pkcs8_content_len<P: ParameterSet>(format: PrivateKeyFormat) -> usize {
    tlv_len(1) + alg_id_len::<P>() + tlv_len(choice_len::<P>(format))
}

/// Content length of the `SubjectPublicKeyInfo` SEQUENCE.
const fn spki_content_len<P: ParameterSet>() -> usize {
    alg_id_len::<P>() + tlv_len(1 + P::VERIFYING_KEY_LEN)
}

/// Reads `AlgorithmIdentifier { id-ml-dsa-* }` and requires the OID of `P`
/// with absent parameters.
fn read_algorithm<P: ParameterSet>(r: &mut Reader<'_>) -> Result<(), Error> {
    let mut alg = r.read_sequence()?;
    if alg.read_oid()? != P::OID {
        return Err(Error::InvalidKey);
    }
    alg.finish().map_err(|_| Error::InvalidKey)
}

/// Writes `AlgorithmIdentifier { id-ml-dsa-* }` with absent parameters.
fn write_algorithm<P: ParameterSet>(w: &mut Writer<'_>) -> Result<(), Error> {
    w.header(tag::SEQUENCE, tlv_len(P::OID.len()))?;
    w.tlv(tag::OID, P::OID)
}

/// The universal SET (OF) tag, constructed.
const SET: u8 = 0x31;

/// Checks the contents of `attributes [0] IMPLICIT Attributes`: zero or
/// more DER `Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER,
/// attrValues SET OF AttributeValue }` (RFC 5958, RFC 5912), each with at
/// least one value, each consumed in full. The values themselves (any
/// TLV with a single-byte tag) and the DER ordering of both SET OFs (the
/// attributes, and the values of each) are not checked.
fn check_attributes(contents: &[u8]) -> Result<(), Error> {
    let mut r = Reader::new(contents);
    while !r.is_empty() {
        let mut attr = r.read_sequence()?;
        attr.read_oid()?;
        let mut values = Reader::new(attr.read(SET)?);
        attr.finish()?;
        if values.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        while !values.is_empty() {
            values.read_any()?;
        }
    }
    Ok(())
}

/// Copies a seed out of the input into a buffer that is wiped on drop.
fn read_seed(bytes: &[u8]) -> Result<Zeroizing<[u8; SEED_LEN]>, Error> {
    if bytes.len() != SEED_LEN {
        return Err(Error::InvalidKey);
    }
    let mut seed = Zeroizing([0u8; SEED_LEN]);
    seed.0.copy_from_slice(bytes);
    Ok(seed)
}

impl<P: ParameterSet> SigningKey<P> {
    /// Length of the longest encoding [`Self::to_pkcs8_der`] writes (the
    /// [`PrivateKeyFormat::Both`] form): 2626, 4098 and 4962 bytes for
    /// ML-DSA-44, -65 and -87.
    pub const PKCS8_MAX_LEN: usize = tlv_len(pkcs8_content_len::<P>(PrivateKeyFormat::Both));

    /// Parses an RFC 9881 §6 PKCS #8 `OneAsymmetricKey` (RFC 5958 version
    /// 1 or 2, encoded as `version` 0 or 1) in strict DER.
    ///
    /// `privateKeyAlgorithm` must be [`ParameterSet::OID`] with absent
    /// parameters. `privateKey` must hold exactly one `ML-DSA-*-PrivateKey`
    /// CHOICE, selected by its tag alone:
    ///
    /// * `seed` (`0x80`, 32 bytes): the key is derived with
    ///   [`Self::from_seed`];
    /// * `expandedKey` (`0x04`, [`ParameterSet::SIGNING_KEY_LEN`] bytes):
    ///   loaded and validated with [`Self::from_expanded_bytes`]; the
    ///   resulting key has no seed;
    /// * `both` (`0x30`): the key is derived from the seed and the presented
    ///   expanded key must equal the derived one byte for byte, compared in
    ///   constant time (the RFC 9881 §8.2 consistency check).
    ///
    /// An expanded key alone cannot be fully checked: its `K` is not bound
    /// to the rest of the key, so a changed `K` goes unnoticed; only the
    /// `seed` and `both` forms detect it.
    ///
    /// Attributes must have the DER `Attribute` structure (an OBJECT
    /// IDENTIFIER and a SET of at least one value) and are otherwise
    /// ignored: the values and the DER ordering of both SET OFs are not
    /// checked, and a value with a multi-byte tag is rejected. A
    /// `publicKey` (version 1 only), whatever the CHOICE form, must be a BIT
    /// STRING without unused bits that equals the derived public key;
    /// version 1 without a `publicKey` is accepted. Which CHOICE the key
    /// came from is not retained, except that a key loaded from
    /// `expandedKey` alone has no seed ([`Self::seed`]).
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidEncoding`]: input that is not one well-formed DER
    ///   `OneAsymmetricKey` (bad lengths, trailing data at any level, a
    ///   version other than 0 or 1, malformed or repeated attributes, a
    ///   `publicKey` with version 0 or with unused bits, a CHOICE tag other
    ///   than `0x80`, `0x04` and `0x30`, a `both` SEQUENCE that is not two
    ///   OCTET STRINGs).
    /// * [`Error::InvalidKey`]: a well-formed structure with another
    ///   algorithm or parameters present, a seed or expanded key of the
    ///   wrong size, an expanded key that fails validation, a `both` whose
    ///   expanded key does not match its seed, or a `publicKey` that does
    ///   not match the private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let (private_key, public) = der::parse_sequence(der, |r| {
            let version = r.read_small_integer()?;
            if version > 1 {
                return Err(Error::InvalidEncoding);
            }
            read_algorithm::<P>(r)?;
            let private_key = r.read_octet_string()?;
            if let Some(attributes) = r.read_optional(tag::context_constructed(0))? {
                check_attributes(attributes)?;
            }
            let public = match (version, r.read_optional(tag::context_primitive(1))?) {
                (_, None) => None,
                (0, Some(_)) => return Err(Error::InvalidEncoding),
                (_, Some([0, rest @ ..])) => Some(rest),
                (_, Some(_)) => return Err(Error::InvalidEncoding),
            };
            Ok((private_key, public))
        })?;

        let mut choice = Reader::new(private_key);
        let (choice_tag, value) = choice.read_any()?;
        choice.finish()?;
        let key = match choice_tag {
            t if t == tag::context_primitive(0) => Self::from_seed(&read_seed(value)?.0),
            tag::OCTET_STRING => {
                if value.len() != P::SIGNING_KEY_LEN {
                    return Err(Error::InvalidKey);
                }
                Self::from_expanded_bytes(value)?
            }
            tag::SEQUENCE => {
                let mut both = Reader::new(value);
                let seed = both.read_octet_string()?;
                let expanded = both.read_octet_string()?;
                both.finish()?;
                if expanded.len() != P::SIGNING_KEY_LEN {
                    return Err(Error::InvalidKey);
                }
                let key = Self::from_seed(&read_seed(seed)?.0);
                // `key` is wiped on drop if the check fails.
                if !ct::eq_bytes(key.sk.as_ref(), expanded).declassify() {
                    return Err(Error::InvalidKey);
                }
                key
            }
            _ => return Err(Error::InvalidEncoding),
        };
        match public {
            Some(p) if p != key.vk.as_bytes() => Err(Error::InvalidKey),
            _ => Ok(key),
        }
    }

    /// Writes the key as an RFC 9881 §6 PKCS #8 `OneAsymmetricKey` (RFC 5958
    /// version 1: `version` 0, no attributes, no public key) with the
    /// `privateKey` CHOICE given by `format`, and returns its length.
    ///
    /// RFC 9881 RECOMMENDS [`PrivateKeyFormat::Seed`] (54 bytes for every
    /// parameter set) and recommends retaining the seed even when the
    /// expanded key is exported. The output holds secret key material: the
    /// caller is responsible for wiping `out`. On the errors below `out` is
    /// unchanged.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for [`PrivateKeyFormat::Seed`] and
    /// [`PrivateKeyFormat::Both`] if the key has no seed (it was loaded
    /// from an expanded key, from which the seed cannot be recovered;
    /// RFC 9881 §8.1); [`Error::InvalidLength`] if `out` is too small
    /// ([`Self::PKCS8_MAX_LEN`] bytes always suffice).
    pub fn to_pkcs8_der(&self, format: PrivateKeyFormat, out: &mut [u8]) -> Result<usize, Error> {
        let seed = match (format, self.seed()) {
            (PrivateKeyFormat::Expanded, _) => None,
            (_, Some(seed)) => Some(seed),
            (_, None) => return Err(Error::Unsupported),
        };
        let content = pkcs8_content_len::<P>(format);
        let len = tlv_len(content);
        let out = out.get_mut(..len).ok_or(Error::InvalidLength)?;
        let written = self.write_pkcs8(format, seed, content, out);
        if written != Ok(len) {
            // Unreachable by the length assertions above; never leave a
            // partial encoding of the key behind.
            zeroize_bytes(out);
            return Err(Error::InvalidLength);
        }
        Ok(len)
    }

    fn write_pkcs8(
        &self,
        format: PrivateKeyFormat,
        seed: Option<&[u8; SEED_LEN]>,
        content: usize,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.header(tag::SEQUENCE, content)?;
        w.tlv(tag::INTEGER, &[0])?;
        write_algorithm::<P>(&mut w)?;
        w.header(tag::OCTET_STRING, choice_len::<P>(format))?;
        match (format, seed) {
            (PrivateKeyFormat::Seed, Some(seed)) => w.tlv(tag::context_primitive(0), seed)?,
            (PrivateKeyFormat::Both, Some(seed)) => {
                w.header(tag::SEQUENCE, both_content_len::<P>())?;
                w.tlv(tag::OCTET_STRING, seed)?;
                w.tlv(tag::OCTET_STRING, self.sk.as_ref())?;
            }
            (PrivateKeyFormat::Expanded, _) => w.tlv(tag::OCTET_STRING, self.sk.as_ref())?,
            _ => return Err(Error::Unsupported),
        }
        Ok(w.len())
    }
}

impl<P: ParameterSet> VerifyingKey<P> {
    /// Length of the `SubjectPublicKeyInfo` encoding (fixed per parameter
    /// set): 1334, 1974 and 2614 bytes for ML-DSA-44, -65 and -87.
    pub const SPKI_LEN: usize = tlv_len(spki_content_len::<P>());

    /// Parses an RFC 9881 §4 `SubjectPublicKeyInfo` in strict DER: the
    /// algorithm must be [`ParameterSet::OID`] with absent parameters and
    /// the BIT STRING (without unused bits) the raw FIPS 204 public key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEncoding`] for malformed DER, trailing data or unused
    /// bits; [`Error::InvalidKey`] for another algorithm, parameters present
    /// or a key of the wrong length.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        der::parse_sequence(der, |r| {
            read_algorithm::<P>(r)?;
            let key = r.read_bit_string_octets()?;
            Self::from_bytes(key).map_err(|_| Error::InvalidKey)
        })
    }

    /// Writes the RFC 9881 §4 `SubjectPublicKeyInfo` and returns its length
    /// ([`Self::SPKI_LEN`]).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `out` is shorter than [`Self::SPKI_LEN`];
    /// `out` is then unchanged.
    pub fn to_spki_der(&self, out: &mut [u8]) -> Result<usize, Error> {
        let len = Self::SPKI_LEN;
        let out = out.get_mut(..len).ok_or(Error::InvalidLength)?;
        let mut w = Writer::new(out);
        w.header(tag::SEQUENCE, spki_content_len::<P>())?;
        write_algorithm::<P>(&mut w)?;
        w.header(tag::BIT_STRING, 1 + P::VERIFYING_KEY_LEN)?;
        let n = w.len();
        let (unused_bits, key) = out[n..].split_at_mut(1);
        unused_bits[0] = 0;
        key.copy_from_slice(self.as_bytes());
        Ok(len)
    }
}
