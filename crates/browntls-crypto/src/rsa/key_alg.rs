//! RSA key algorithm identifiers: `rsaEncryption`, and `id-RSASSA-PSS` with
//! its `RSASSA-PSS-params` (RFC 4055 §1.2 and §3.1, updated by RFC 5756 §2),
//! as they appear in X.509 `SubjectPublicKeyInfo` and PKCS #8
//! `PrivateKeyInfo`. [`RsaKeyAlgorithm`] documents the accepted encodings.

use crate::Error;
use crate::der::{Reader, Writer, tag};
use crate::hash::HashAlgorithm;

use super::OID_RSA_ENCRYPTION;

/// `id-RSASSA-PSS` OBJECT IDENTIFIER contents (1.2.840.113549.1.1.10).
const OID_RSASSA_PSS: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
/// `id-mgf1` OBJECT IDENTIFIER contents (1.2.840.113549.1.1.8).
const OID_MGF1: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
/// `id-sha256` OBJECT IDENTIFIER contents (2.16.840.1.101.3.4.2.1).
const OID_SHA256: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `id-sha384` OBJECT IDENTIFIER contents (2.16.840.1.101.3.4.2.2).
const OID_SHA384: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// `id-sha512` OBJECT IDENTIFIER contents (2.16.840.1.101.3.4.2.3).
const OID_SHA512: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// `saltLength` when the field is absent (RFC 4055 §3.1).
const DEFAULT_SALT_LEN: u8 = 20;

/// Largest `AlgorithmIdentifier` contents [`RsaKeyAlgorithm`] encodes (an
/// `id-RSASSA-PSS` identifier with parameters).
pub const MAX_ALGORITHM_IDENTIFIER_LEN: usize = 65;

/// The algorithm an RSA key is identified with in its
/// `SubjectPublicKeyInfo` or PKCS #8 `PrivateKeyInfo`, and so what it may
/// sign.
///
/// Both identifiers carry the same PKCS #1 `RSAPublicKey` and
/// `RSAPrivateKey` (RFC 4055 §1.2); they differ in what the key may be used
/// for. An `id-RSASSA-PSS` key may only make RSASSA-PSS signatures and, when
/// its parameters are present, only with the hash, mask generation function
/// and trailer field they name and a salt at least as long as their
/// `saltLength` (RFC 4055 §1.2, §3.3). TLS signs with such keys under
/// `rsa_pss_pss_*` and with `rsaEncryption` keys under `rsa_pss_rsae_*`
/// (RFC 9846 §4.3.3).
///
/// # Accepted `id-RSASSA-PSS` parameters
///
/// * **Absent**: the key is unrestricted (RFC 4055 §3.3, case 2) and serves
///   RSASSA-PSS with any supported hash: [`Self::RsassaPss`]`(None)`.
/// * **Present**, restricting the key to the hash `H`, one of SHA-256,
///   SHA-384 and SHA-512: [`Self::RsassaPss`]`(Some(H))`. The fields are
///   * `hashAlgorithm` naming `H`, with NULL or absent parameters (RFC 4055
///     §2.1: "All implementations MUST accept both NULL and absent
///     parameters as legal and equivalent encodings");
///   * `maskGenAlgorithm` MGF1 over `H`, its hash identifier likewise with
///     NULL or absent parameters;
///   * `saltLength` absent (DEFAULT 20) or at most the digest length `hLen`.
///     In a key it is the shortest salt the key's signatures may use
///     (RFC 4055 §3.3, case 3); TLS always signs with `hLen` bytes
///     (RFC 9846 §4.3.3), which satisfies every such minimum. OpenSSL 3.0
///     omits the field for `-pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt
///     rsa_pss_keygen_mgf1_md:sha256` and writes 0 for
///     `rsa_pss_keygen_saltlen:0`;
///   * `trailerField` absent or 1.
///
///   Whatever the minimum salt length, the key serves exactly one TLS
///   scheme, `rsa_pss_pss_H` (MGF1 with the message hash and a salt of the
///   digest length).
///
/// Well-formed parameters outside this set are rejected with
/// [`Error::Unsupported`]:
///
/// * SHA-1 (also as the `hashAlgorithm` DEFAULT, when the field is absent),
///   SHA-224, and any other hash;
/// * a mask generation function other than MGF1, or MGF1 over a hash other
///   than `H` (also its DEFAULT, MGF1 with SHA-1). OpenSSL 3.0 writes
///   `{ hashAlgorithm SHA-256 }` alone for `-pkeyopt rsa_pss_keygen_md:sha256`
///   without `rsa_pss_keygen_mgf1_md`; such a key fits no TLS scheme;
/// * a `saltLength` greater than `hLen`, which no TLS signature satisfies;
/// * a `trailerField` other than 1 (RFC 4055 §3.1 defines no other value).
///
/// # DEFAULT values written explicitly
///
/// DER omits a component equal to its DEFAULT (X.690 §11.5), and RFC 9846
/// §4.3.3 and X.509 require DER. RFC 4055 §3.1 nevertheless tells
/// signature validators to recognise three such encodings. The decision per
/// field, shared with `browntls_pki::alg_id::canonical_public_key_alg_id`:
///
/// * `hashAlgorithm` `sha1Identifier` and `maskGenAlgorithm`
///   `mgf1SHA1Identifier`: recognised as RFC 4055 asks, as SHA-1 and MGF1
///   with SHA-1, and so [`Error::Unsupported`] like their absent forms;
/// * `trailerField` 1: accepted, as RFC 4055 §3.1 requires ("MUST recognize
///   both a present trailerField field with value 1 and an absent
///   trailerField field"). This is the only non-DER form accepted;
/// * `saltLength` 20: RFC 4055 asks nobody to recognise it, so it is
///   rejected as non-DER ([`Error::InvalidEncoding`]); no encoder this crate
///   knows of writes it (OpenSSL omits it).
///
/// Malformed DER, parameters that are not `RSASSA-PSS-params` (for example
/// NULL), fields out of order or repeated, hash identifiers with other
/// parameters, an MGF1 identifier without its hash, and negative integers
/// are [`Error::InvalidEncoding`].
///
/// # Encoding
///
/// [`Self::encode_algorithm_identifier`] writes one canonical form per
/// value: no parameters for an unrestricted key, and
/// `{ H with NULL, MGF1(H with NULL), saltLength hLen }` (OpenSSL's
/// encoding for `rsa_pss_keygen_saltlen` equal to the digest length) for a
/// key restricted to `H`. The other accepted encodings parse to the same
/// value, so callers that need a key's original bytes (for example to
/// compare its `SubjectPublicKeyInfo` with a certificate's) keep them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RsaKeyAlgorithm {
    /// `rsaEncryption` with NULL parameters (RFC 4055 §1.2, RFC 3279
    /// §2.3.1): RSASSA-PKCS1-v1_5 and RSASSA-PSS with any hash.
    RsaEncryption,
    /// `id-RSASSA-PSS` (RFC 4055 §3.1): RSASSA-PSS only. `None` when the
    /// parameters are absent; `Some(hash)` when they restrict the key to
    /// `hash` with MGF1 over `hash` (and a minimum salt length that a salt of
    /// the digest length satisfies).
    RsassaPss(Option<HashAlgorithm>),
}

/// The OBJECT IDENTIFIER of a hash this module accepts in parameters.
fn hash_oid(hash: HashAlgorithm) -> Option<&'static [u8; 9]> {
    match hash {
        HashAlgorithm::Sha256 => Some(&OID_SHA256),
        HashAlgorithm::Sha384 => Some(&OID_SHA384),
        HashAlgorithm::Sha512 => Some(&OID_SHA512),
        _ => None,
    }
}

/// The supported hash `oid` names, if any.
fn supported_hash(oid: &[u8]) -> Option<HashAlgorithm> {
    [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ]
    .into_iter()
    .find(|&h| hash_oid(h).is_some_and(|o| o.as_slice() == oid))
}

/// Reads a hash `AlgorithmIdentifier` and returns its OBJECT IDENTIFIER;
/// the parameters may be NULL or absent (RFC 4055 §2.1).
fn read_hash<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let mut alg = r.read_sequence()?;
    let oid = alg.read_oid()?;
    if let Some(null) = alg.read_optional(tag::NULL)?
        && !null.is_empty()
    {
        return Err(Error::InvalidEncoding);
    }
    alg.finish()?;
    Ok(oid)
}

/// A `maskGenAlgorithm` value.
enum MaskGen<'a> {
    /// MGF1 with the hash of this OBJECT IDENTIFIER.
    Mgf1(&'a [u8]),
    /// Another function, whose parameters are not examined.
    Other,
}

/// Reads a `MaskGenAlgorithm` (RFC 4055 §2.2): MGF1, whose parameters MUST
/// be a hash identifier, or another function.
fn read_mask_gen<'a>(r: &mut Reader<'a>) -> Result<MaskGen<'a>, Error> {
    let mut alg = r.read_sequence()?;
    if alg.read_oid()? != OID_MGF1 {
        while !alg.is_empty() {
            alg.read_any()?;
        }
        return Ok(MaskGen::Other);
    }
    let hash = read_hash(&mut alg)?;
    alg.finish()?;
    Ok(MaskGen::Mgf1(hash))
}

/// Reads the explicitly tagged field `[n]`, if it is next, with `f`, which
/// must consume its contents.
fn optional_field<'a, T>(
    r: &mut Reader<'a>,
    n: u8,
    f: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    r.read_optional(tag::context_constructed(n))?
        .map(|contents| {
            let mut field = Reader::new(contents);
            let value = f(&mut field)?;
            field.finish()?;
            Ok(value)
        })
        .transpose()
}

/// Parses the contents of `RSASSA-PSS-params` (RFC 4055 §3.1) and returns
/// the hash they restrict the key to; see [`RsaKeyAlgorithm`] for the
/// accepted forms.
///
/// The structure is checked completely first ([`Error::InvalidEncoding`]),
/// then the values ([`Error::Unsupported`]).
fn parse_pss_params(contents: &[u8]) -> Result<HashAlgorithm, Error> {
    let mut r = Reader::new(contents);
    // Every field has a DEFAULT; `None` stands for an absent field.
    let hash = optional_field(&mut r, 0, read_hash)?;
    let mask_gen = optional_field(&mut r, 1, read_mask_gen)?;
    let salt_len = optional_field(&mut r, 2, Reader::read_positive_integer)?;
    let trailer = optional_field(&mut r, 3, Reader::read_positive_integer)?;
    // Fields out of order, repeated or unknown.
    r.finish()?;
    // An explicit DEFAULT salt length is not DER (X.690 §11.5) and, unlike
    // the trailer field, not one RFC 4055 asks validators to recognise.
    if salt_len == Some(&[DEFAULT_SALT_LEN][..]) {
        return Err(Error::InvalidEncoding);
    }

    // hashAlgorithm DEFAULT sha1Identifier: unsupported when absent.
    let hash = hash.and_then(supported_hash).ok_or(Error::Unsupported)?;
    // maskGenAlgorithm DEFAULT mgf1SHA1Identifier: MGF1 over `hash` only.
    match mask_gen {
        Some(MaskGen::Mgf1(oid)) if supported_hash(oid) == Some(hash) => {}
        _ => return Err(Error::Unsupported),
    }
    // saltLength DEFAULT 20: a minimum, which a salt of hLen bytes must meet
    // (the magnitude has no leading zeros, so longer ones exceed 255).
    let salt_len = match salt_len {
        None => DEFAULT_SALT_LEN,
        Some(&[len]) => len,
        Some(_) => return Err(Error::Unsupported),
    };
    if usize::from(salt_len) > hash.output_len() {
        return Err(Error::Unsupported);
    }
    // trailerField DEFAULT 1, the only value (0xBC); explicit 1 is accepted.
    match trailer {
        None | Some(&[1]) => Ok(hash),
        Some(_) => Err(Error::Unsupported),
    }
}

impl RsaKeyAlgorithm {
    /// Parses the contents of an `AlgorithmIdentifier` SEQUENCE (the OID and
    /// parameters, without the outer tag and length).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for malformed or non-DER input
    /// and for an algorithm other than `rsaEncryption` and `id-RSASSA-PSS`,
    /// and [`Error::Unsupported`] for well-formed `RSASSA-PSS-params`
    /// outside the accepted set, including parameters whose omitted fields
    /// default to SHA-1 (see [`RsaKeyAlgorithm`]).
    pub fn from_algorithm_identifier(contents: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(contents);
        let oid = r.read_oid()?;
        let alg = if oid == OID_RSA_ENCRYPTION {
            if !r.read(tag::NULL)?.is_empty() {
                return Err(Error::InvalidEncoding);
            }
            Self::RsaEncryption
        } else if oid == OID_RSASSA_PSS {
            match r.read_optional(tag::SEQUENCE)? {
                None => Self::RsassaPss(None),
                Some(params) => {
                    // Nothing may follow the parameters (checked before
                    // their values are judged).
                    r.finish()?;
                    Self::RsassaPss(Some(parse_pss_params(params)?))
                }
            }
        } else {
            return Err(Error::InvalidEncoding);
        };
        r.finish()?;
        Ok(alg)
    }

    /// Writes the contents of this algorithm's `AlgorithmIdentifier`, in the
    /// canonical form described under [`RsaKeyAlgorithm`] (which
    /// [`Self::from_algorithm_identifier`] parses back to `self`), to `out`
    /// and returns their length (at most [`MAX_ALGORITHM_IDENTIFIER_LEN`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] for a restriction to a hash other than
    /// SHA-256, SHA-384 or SHA-512, and [`Error::InvalidLength`] if `out` is
    /// too small.
    pub fn encode_algorithm_identifier(self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        match self {
            Self::RsaEncryption => {
                w.tlv(tag::OID, &OID_RSA_ENCRYPTION)?;
                w.tlv(tag::NULL, &[])?;
            }
            Self::RsassaPss(None) => w.tlv(tag::OID, &OID_RSASSA_PSS)?,
            Self::RsassaPss(Some(hash)) => {
                let oid = hash_oid(hash).ok_or(Error::Unsupported)?;
                // Every length below is fixed and short-form. Encoded
                // sizes: a hash AlgorithmIdentifier { OID, NULL } is 15
                // bytes, MGF1 with it 28, the salt INTEGER 3, the
                // parameters' contents 17 + 30 + 5 = 52.
                let hash_tlv = 2 + (2 + oid.len()) + 2;
                let mgf_tlv = 2 + (2 + OID_MGF1.len()) + hash_tlv;
                let salt_tlv = 3;
                let params_len = (2 + hash_tlv) + (2 + mgf_tlv) + (2 + salt_tlv);
                w.tlv(tag::OID, &OID_RSASSA_PSS)?;
                w.header(tag::SEQUENCE, params_len)?;
                w.header(tag::context_constructed(0), hash_tlv)?;
                write_hash(&mut w, oid)?;
                w.header(tag::context_constructed(1), mgf_tlv)?;
                w.header(tag::SEQUENCE, mgf_tlv - 2)?;
                w.tlv(tag::OID, &OID_MGF1)?;
                write_hash(&mut w, oid)?;
                w.header(tag::context_constructed(2), salt_tlv)?;
                // hLen <= 64, so the INTEGER is one positive octet.
                #[allow(clippy::cast_possible_truncation)]
                w.tlv(tag::INTEGER, &[hash.output_len() as u8])?;
            }
        }
        Ok(w.len())
    }

    /// Whether the key may make RSASSA-PKCS1-v1_5 signatures (only an
    /// `rsaEncryption` key may; RFC 4055 §1.2).
    #[must_use]
    pub fn allows_pkcs1v15(self) -> bool {
        self == Self::RsaEncryption
    }

    /// Whether the key may make RSASSA-PSS signatures with `hash`, MGF1 over
    /// `hash` and a salt of the digest length (which meets the minimum salt
    /// length of every accepted restricted key).
    #[must_use]
    pub fn allows_pss(self, hash: HashAlgorithm) -> bool {
        match self {
            Self::RsaEncryption | Self::RsassaPss(None) => true,
            Self::RsassaPss(Some(restricted)) => restricted == hash,
        }
    }
}

/// Writes a hash `AlgorithmIdentifier` with NULL parameters.
fn write_hash(w: &mut Writer<'_>, oid: &[u8]) -> Result<(), Error> {
    w.header(tag::SEQUENCE, 2 + oid.len() + 2)?;
    w.tlv(tag::OID, oid)?;
    w.tlv(tag::NULL, &[])
}

/// Parses an X.509 `SubjectPublicKeyInfo` holding an RSA key and returns
/// its algorithm and the `RSAPublicKey` bytes.
pub(super) fn split_spki(der: &[u8]) -> Result<(RsaKeyAlgorithm, &[u8]), Error> {
    crate::der::parse_sequence(der, |r| {
        let alg = RsaKeyAlgorithm::from_algorithm_identifier(r.read(tag::SEQUENCE)?)?;
        Ok((alg, r.read_bit_string_octets()?))
    })
}

/// Parses a PKCS #8 `PrivateKeyInfo` (RFC 5208 / RFC 5958 version 1 or 2)
/// holding an RSA key and returns its algorithm and the `RSAPrivateKey`
/// bytes.
pub(super) fn split_pkcs8(der: &[u8]) -> Result<(RsaKeyAlgorithm, &[u8]), Error> {
    crate::der::parse_sequence(der, |r| {
        if r.read_small_integer()? > 1 {
            return Err(Error::InvalidEncoding);
        }
        let alg = RsaKeyAlgorithm::from_algorithm_identifier(r.read(tag::SEQUENCE)?)?;
        let key = r.read_octet_string()?;
        // attributes [0] IMPLICIT SET OF Attribute OPTIONAL
        r.read_optional(tag::context_constructed(0))?;
        // publicKey [1] IMPLICIT BIT STRING OPTIONAL (version 2)
        r.read_optional(tag::context_primitive(1))?;
        Ok((alg, key))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// `AlgorithmIdentifier` contents of OpenSSL 3.0.13 public keys (from
    /// `openssl genpkey -algorithm RSA-PSS [-pkeyopt ...]` and
    /// `openssl pkey -pubout`): without parameters, and with
    /// `rsa_pss_keygen_md:sha256`, `rsa_pss_keygen_mgf1_md:sha256` and
    /// `rsa_pss_keygen_saltlen:32`.
    const OPENSSL_PSS: &str = "06092a864886f70d01010a";
    const OPENSSL_PSS_SHA256: &str = "06092a864886f70d01010a3034a00f300d0609608648016503040201\
        0500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120";
    /// The same without `rsa_pss_keygen_saltlen` (saltLength omitted: the
    /// DEFAULT 20 is the minimum) and with `rsa_pss_keygen_saltlen:0`.
    const OPENSSL_PSS_SHA256_SALT_DEFAULT: &str = "06092a864886f70d01010a302fa00f300d060960\
        86480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500";
    const OPENSSL_PSS_SHA256_SALT_0: &str = "06092a864886f70d01010a3034a00f300d0609608648016503\
        0402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020100";
    /// OpenSSL 3.0.13 with only `rsa_pss_keygen_md:sha256`: MGF1 and the
    /// salt length are left at their SHA-1 / 20-byte defaults.
    const OPENSSL_PSS_SHA256_MGF1_SHA1: &str =
        "06092a864886f70d01010a3011a00f300d06096086480165030402010500";

    const OID_SHA1: [u8; 5] = [0x2b, 0x0e, 0x03, 0x02, 0x1a];
    const OID_SHA224: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
    const S256: &[u8] = &OID_SHA256;
    const S384: &[u8] = &OID_SHA384;
    const S512: &[u8] = &OID_SHA512;
    const SUPPORTED: [(HashAlgorithm, &[u8]); 3] = [
        (HashAlgorithm::Sha256, S256),
        (HashAlgorithm::Sha384, S384),
        (HashAlgorithm::Sha512, S512),
    ];

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 0x80);
        [&[tag, value.len() as u8][..], value].concat()
    }

    fn hash_alg(oid: &[u8], null: bool) -> Vec<u8> {
        let mut v = tlv(tag::OID, oid);
        if null {
            v.extend([tag::NULL, 0]);
        }
        tlv(tag::SEQUENCE, &v)
    }

    fn field(n: u8, value: &[u8]) -> Vec<u8> {
        tlv(tag::context_constructed(n), value)
    }

    fn mgf1(hash_alg: &[u8]) -> Vec<u8> {
        tlv(
            tag::SEQUENCE,
            &[tlv(tag::OID, &OID_MGF1), hash_alg.to_vec()].concat(),
        )
    }

    fn salt(len: &[u8]) -> Vec<u8> {
        field(2, &tlv(tag::INTEGER, len))
    }

    fn trailer(value: &[u8]) -> Vec<u8> {
        field(3, &tlv(tag::INTEGER, value))
    }

    /// `id-RSASSA-PSS` with `RSASSA-PSS-params` made of `fields`.
    fn pss(fields: &[Vec<u8>]) -> Vec<u8> {
        [
            tlv(tag::OID, &OID_RSASSA_PSS),
            tlv(tag::SEQUENCE, &fields.concat()),
        ]
        .concat()
    }

    /// The parameters for `hash`, MGF1 over `mgf_hash` (both with NULL
    /// parameters), an explicit salt length and an optional trailer field.
    fn params(hash: &[u8], mgf_hash: &[u8], salt_len: u8, trailer_field: Option<u8>) -> Vec<u8> {
        let mut fields = [
            field(0, &hash_alg(hash, true)),
            field(1, &mgf1(&hash_alg(mgf_hash, true))),
            salt(&[salt_len]),
        ]
        .to_vec();
        if let Some(t) = trailer_field {
            fields.push(trailer(&[t]));
        }
        pss(&fields)
    }

    /// One way of writing the parameters of a key restricted to `oid`.
    #[derive(Clone, Copy, Debug)]
    struct Form {
        hash_null: bool,
        mgf_hash_null: bool,
        salt_len: Option<u8>,
        trailer_one: bool,
    }

    impl Form {
        fn encode(self, oid: &[u8]) -> Vec<u8> {
            let mut fields = vec![
                field(0, &hash_alg(oid, self.hash_null)),
                field(1, &mgf1(&hash_alg(oid, self.mgf_hash_null))),
            ];
            if let Some(len) = self.salt_len {
                // At most 64: one positive octet.
                assert!(len < 0x80);
                fields.push(salt(&[len]));
            }
            if self.trailer_one {
                fields.push(trailer(&[1]));
            }
            pss(&fields)
        }
    }

    /// Every accepted form for a digest of `h_len` bytes.
    fn accepted_forms(h_len: u8) -> Vec<Form> {
        let mut forms = Vec::new();
        for hash_null in [true, false] {
            for mgf_hash_null in [true, false] {
                for trailer_one in [false, true] {
                    let salts =
                        core::iter::once(None).chain((0..=h_len).filter(|&s| s != 20).map(Some));
                    for salt_len in salts {
                        forms.push(Form {
                            hash_null,
                            mgf_hash_null,
                            salt_len,
                            trailer_one,
                        });
                    }
                }
            }
        }
        forms
    }

    fn encode(alg: RsaKeyAlgorithm) -> Vec<u8> {
        let mut out = [0u8; MAX_ALGORITHM_IDENTIFIER_LEN];
        let len = alg.encode_algorithm_identifier(&mut out).unwrap();
        out[..len].to_vec()
    }

    fn parse(contents: &[u8]) -> Result<RsaKeyAlgorithm, Error> {
        RsaKeyAlgorithm::from_algorithm_identifier(contents)
    }

    fn parse_hex(contents: &str) -> Result<RsaKeyAlgorithm, Error> {
        parse(&hex::decode(contents).unwrap())
    }

    #[test]
    fn openssl_encodings() {
        let sha256 = RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256));
        assert_eq!(parse_hex(OPENSSL_PSS), Ok(RsaKeyAlgorithm::RsassaPss(None)));
        assert_eq!(parse_hex(OPENSSL_PSS_SHA256), Ok(sha256));
        // A minimum salt length of 20 (the DEFAULT) or 0 bytes: a salt of
        // 32 bytes satisfies both (RFC 4055 §3.3).
        assert_eq!(parse_hex(OPENSSL_PSS_SHA256_SALT_DEFAULT), Ok(sha256));
        assert_eq!(parse_hex(OPENSSL_PSS_SHA256_SALT_0), Ok(sha256));
        assert_eq!(
            hex::encode(encode(RsaKeyAlgorithm::RsassaPss(None))),
            OPENSSL_PSS
        );
        // The canonical encoding is OpenSSL's for a salt of the digest
        // length.
        assert_eq!(hex::encode(encode(sha256)), OPENSSL_PSS_SHA256);
        // Missing maskGenAlgorithm (MGF1 with SHA-1) and saltLength (20).
        assert_eq!(
            parse_hex(OPENSSL_PSS_SHA256_MGF1_SHA1),
            Err(Error::Unsupported)
        );
        assert_eq!(
            hex::encode(encode(RsaKeyAlgorithm::RsaEncryption)),
            "06092a864886f70d0101010500"
        );
    }

    #[test]
    fn encodings_round_trip() {
        for alg in [
            RsaKeyAlgorithm::RsaEncryption,
            RsaKeyAlgorithm::RsassaPss(None),
            RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256)),
            RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha384)),
            RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha512)),
        ] {
            let der = encode(alg);
            assert!(der.len() <= MAX_ALGORITHM_IDENTIFIER_LEN);
            assert_eq!(parse(&der), Ok(alg));
        }
        for (hash, oid) in SUPPORTED {
            let by_hand = params(oid, oid, hash.output_len() as u8, None);
            assert_eq!(encode(RsaKeyAlgorithm::RsassaPss(Some(hash))), by_hand);
            assert_eq!(by_hand.len(), MAX_ALGORITHM_IDENTIFIER_LEN);
        }
        let mut out = [0u8; MAX_ALGORITHM_IDENTIFIER_LEN];
        for hash in [HashAlgorithm::Sha224, HashAlgorithm::Sha3_256] {
            assert_eq!(
                RsaKeyAlgorithm::RsassaPss(Some(hash)).encode_algorithm_identifier(&mut out),
                Err(Error::Unsupported)
            );
        }
        assert_eq!(
            RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256))
                .encode_algorithm_identifier(&mut out[..64]),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn equivalent_encodings_are_accepted() {
        // NULL or absent hash parameters (RFC 4055 §2.1), any minimum salt
        // length up to hLen including the DEFAULT 20 when omitted
        // (RFC 4055 §3.3), and an absent or explicit trailer field 1
        // (RFC 4055 §3.1) all restrict the key to the same hash.
        let mut count = 0;
        for (hash, oid) in SUPPORTED {
            for form in accepted_forms(hash.output_len() as u8) {
                assert_eq!(
                    parse(&form.encode(oid)),
                    Ok(RsaKeyAlgorithm::RsassaPss(Some(hash))),
                    "{hash:?} {form:?}"
                );
                count += 1;
            }
        }
        // 2 * 2 * 2 forms of each salt length: absent or 0..=hLen but 20.
        assert_eq!(count, 8 * ((1 + 32) + (1 + 48) + (1 + 64)));
    }

    #[test]
    fn unsupported_parameters_are_rejected() {
        let mgf256 = field(1, &mgf1(&hash_alg(S256, true)));
        let hash256 = field(0, &hash_alg(S256, true));
        let unsupported = [
            // MGF1 over another hash.
            params(S256, S384, 32, None),
            params(S512, S256, 64, None),
            params(S256, &OID_SHA1, 32, None),
            pss(&[
                hash256.clone(),
                field(1, &mgf1(&hash_alg(&OID_SHA1, false))),
            ]),
            // Salt lengths longer than the digest: no TLS signature (salt =
            // hLen) meets them.
            params(S256, S256, 33, None),
            params(S256, S256, 64, None),
            params(S384, S384, 49, None),
            params(S512, S512, 65, None),
            pss(&[hash256.clone(), mgf256.clone(), salt(&[0x00, 0xff])]),
            pss(&[hash256.clone(), mgf256.clone(), salt(&[0x01, 0x00])]),
            pss(&[hash256.clone(), mgf256.clone(), salt(&[0x7f; 9])]),
            // SHA-224 (which RFC 4055 lists), SHA-1 explicit and without
            // NULL, and an unknown hash.
            params(&OID_SHA224, &OID_SHA224, 28, None),
            params(&OID_SHA1, &OID_SHA1, 19, None),
            pss(&[field(0, &hash_alg(&OID_SHA1, false))]),
            params(&[0x2a, 0x03], &[0x2a, 0x03], 0, None),
            // A mask generation function other than MGF1 (here id-sha256),
            // with or without parameters.
            pss(&[
                hash256.clone(),
                field(
                    1,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, S256), hash_alg(S256, true)].concat(),
                    ),
                ),
                salt(&[32]),
            ]),
            pss(&[
                hash256.clone(),
                field(1, &tlv(tag::SEQUENCE, &tlv(tag::OID, S256))),
            ]),
            // Trailer fields other than 1.
            params(S256, S256, 32, Some(0)),
            params(S256, S256, 32, Some(2)),
            pss(&[hash256.clone(), mgf256.clone(), trailer(&[0x01, 0x00])]),
            // Omitted fields defaulting to SHA-1: empty parameters (all
            // DEFAULT), no hashAlgorithm, no maskGenAlgorithm.
            pss(&[]),
            pss(&[mgf256.clone(), salt(&[32])]),
            pss(core::slice::from_ref(&hash256)),
            pss(&[hash256.clone(), salt(&[32])]),
            pss(&[trailer(&[1])]),
        ];
        for bad in &unsupported {
            assert_eq!(parse(bad), Err(Error::Unsupported), "{}", hex::encode(bad));
        }
    }

    #[test]
    fn malformed_parameters_are_rejected() {
        let mgf256 = field(1, &mgf1(&hash_alg(S256, true)));
        let hash256 = field(0, &hash_alg(S256, true));
        let malformed = [
            // NULL instead of RSASSA-PSS-params, and parameters followed by
            // more data.
            [tlv(tag::OID, &OID_RSASSA_PSS), [tag::NULL, 0].to_vec()].concat(),
            [params(S256, S256, 32, None), [tag::NULL, 0].to_vec()].concat(),
            // An explicit DEFAULT salt length (not DER, X.690 §11.5), even
            // when the rest would be unsupported anyway.
            params(S256, S256, 20, None),
            params(S512, S512, 20, Some(1)),
            params(&OID_SHA1, &OID_SHA1, 20, None),
            // Fields out of order, repeated, or unknown.
            pss(&[mgf256.clone(), hash256.clone(), salt(&[32])]),
            pss(&[hash256.clone(), salt(&[32]), mgf256.clone()]),
            pss(&[hash256.clone(), mgf256.clone(), trailer(&[1]), salt(&[32])]),
            pss(&[hash256.clone(), hash256.clone(), mgf256.clone()]),
            pss(&[hash256.clone(), mgf256.clone(), salt(&[32]), salt(&[32])]),
            pss(&[
                hash256.clone(),
                mgf256.clone(),
                field(4, &tlv(tag::INTEGER, &[1])),
            ]),
            // Hash identifiers with parameters other than NULL, or a NULL
            // with contents.
            pss(&[
                field(
                    0,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, S256), tlv(tag::OID, S256)].concat(),
                    ),
                ),
                mgf256.clone(),
            ]),
            pss(&[
                field(
                    0,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, S256), tlv(tag::NULL, &[0])].concat(),
                    ),
                ),
                mgf256.clone(),
            ]),
            // MGF1 without its hash, or with NULL instead.
            pss(&[
                hash256.clone(),
                field(1, &tlv(tag::SEQUENCE, &tlv(tag::OID, &OID_MGF1))),
            ]),
            pss(&[
                hash256.clone(),
                field(
                    1,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, &OID_MGF1), tlv(tag::NULL, &[])].concat(),
                    ),
                ),
            ]),
            // A negative or non-minimal salt length or trailer field.
            pss(&[hash256.clone(), mgf256.clone(), salt(&[0xe0])]),
            pss(&[hash256.clone(), mgf256.clone(), salt(&[0, 32])]),
            pss(&[hash256.clone(), mgf256.clone(), salt(&[])]),
            pss(&[hash256.clone(), mgf256.clone(), trailer(&[0xff])]),
            pss(&[hash256.clone(), mgf256.clone(), trailer(&[0, 1])]),
            // Two values inside an explicit field, or a field holding the
            // wrong type.
            pss(&[
                field(0, &[hash_alg(S256, true), hash_alg(S256, true)].concat()),
                mgf256.clone(),
                salt(&[32]),
            ]),
            pss(&[
                hash256.clone(),
                mgf256.clone(),
                field(2, &tlv(tag::OCTET_STRING, &[32])),
            ]),
            pss(&[field(0, &tlv(tag::OID, S256)), mgf256.clone()]),
            // An unknown algorithm, rsaEncryption without NULL.
            hex::decode("06072a8648ce3d0201").unwrap(),
            hex::decode("06092a864886f70d010101").unwrap(),
        ];
        for bad in &malformed {
            assert_eq!(
                parse(bad),
                Err(Error::InvalidEncoding),
                "{}",
                hex::encode(bad)
            );
        }
        // Trailing data, and every truncation of a good encoding except the
        // bare OID (an unrestricted key).
        let good = encode(RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha384)));
        assert!(parse(&[good.as_slice(), &[tag::NULL, 0]].concat()).is_err());
        assert_eq!(parse(&good[..11]), Ok(RsaKeyAlgorithm::RsassaPss(None)));
        for len in (0..good.len()).filter(|&len| len != 11) {
            assert!(parse(&good[..len]).is_err(), "{len}");
        }
    }

    #[test]
    fn restrictions() {
        use HashAlgorithm::{Sha256, Sha384, Sha512};
        let rsae = RsaKeyAlgorithm::RsaEncryption;
        let pss = RsaKeyAlgorithm::RsassaPss(None);
        let pss384 = RsaKeyAlgorithm::RsassaPss(Some(Sha384));
        assert!(rsae.allows_pkcs1v15());
        assert!(!pss.allows_pkcs1v15());
        assert!(!pss384.allows_pkcs1v15());
        for h in [Sha256, Sha384, Sha512] {
            assert!(rsae.allows_pss(h));
            assert!(pss.allows_pss(h));
            assert_eq!(pss384.allows_pss(h), h == Sha384);
        }
        // A key with a minimum salt length of 0 is restricted like one with
        // the digest length.
        let zero = parse(&params(S384, S384, 0, None)).unwrap();
        assert_eq!(zero, pss384);
    }
}
