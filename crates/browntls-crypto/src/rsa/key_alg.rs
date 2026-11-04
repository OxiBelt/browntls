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
/// and trailer field they name (RFC 4055 §1.2, §3.3). TLS signs with such
/// keys under `rsa_pss_pss_*` and with `rsaEncryption` keys under
/// `rsa_pss_rsae_*` (RFC 9846 §4.3.3).
///
/// # Accepted `id-RSASSA-PSS` parameters
///
/// * **Absent**: the key is unrestricted (RFC 4055 §3.3, case 2) and serves
///   RSASSA-PSS with any supported hash.
/// * **`{ hashAlgorithm H, maskGenAlgorithm MGF1(H), saltLength hLen }`**
///   for `H` one of SHA-256, SHA-384 and SHA-512: exactly the parameters of
///   the TLS scheme `rsa_pss_pss_H` (MGF1 with the message hash and a salt
///   as long as the digest, RFC 9846 §4.3.3). The key is restricted to `H`.
///
/// Everything else is rejected, including:
///
/// * SHA-1 (the `RSASSA-PSS-params` default), SHA-224, and any other hash;
/// * an MGF1 hash that differs from `H`, or a mask generation function other
///   than MGF1. OpenSSL 3.0 writes `{ hashAlgorithm SHA-256 }` alone (MGF1
///   with SHA-1 and a 20-byte salt by default) for
///   `-pkeyopt rsa_pss_keygen_md:sha256`; such a key fits no TLS scheme.
///   Adding `rsa_pss_keygen_mgf1_md:sha256` and `rsa_pss_keygen_saltlen:32`
///   gives the accepted form;
/// * a salt length other than `hLen`. RFC 4055 §3.3 lets the key's
///   `saltLength` be a minimum, but RFC 9846 §4.3.3 requires certificate
///   signature parameters identical to the key's and fixes TLS salts at
///   `hLen`, so only `hLen` can be used;
/// * an explicit `trailerField` and any other field equal to its DEFAULT:
///   RFC 9846 §4.3.3 requires DER, which omits defaults (X.690 §11.5);
/// * hash identifiers without their NULL parameters. RFC 4055 §2.1 asks
///   verifiers to accept both forms, but defines `sha256Identifier` and the
///   others with NULL, which is what OpenSSL writes; `browntls-pki` compares
///   algorithm identifiers byte for byte, so only that form can be validated
///   in certificates, and it is the only one accepted for keys.
///
/// `id-RSASSA-PSS` is therefore accepted in exactly four encodings, which
/// [`RsaKeyAlgorithm::encode_algorithm_identifier`] reproduces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RsaKeyAlgorithm {
    /// `rsaEncryption` with NULL parameters (RFC 4055 §1.2, RFC 3279
    /// §2.3.1): RSASSA-PKCS1-v1_5 and RSASSA-PSS with any hash.
    RsaEncryption,
    /// `id-RSASSA-PSS` (RFC 4055 §3.1): RSASSA-PSS only. `None` when the
    /// parameters are absent; `Some(hash)` when they restrict the key to
    /// `hash` with MGF1 over `hash` and a salt of the digest length.
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

/// Parses the contents of a hash `AlgorithmIdentifier`: SHA-256, SHA-384 or
/// SHA-512 with NULL parameters (RFC 4055 §2.1).
fn parse_hash(contents: &[u8]) -> Result<HashAlgorithm, Error> {
    let mut r = Reader::new(contents);
    let oid = r.read_oid()?;
    if !r.read(tag::NULL)?.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    r.finish()?;
    [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ]
    .into_iter()
    .find(|&h| hash_oid(h).is_some_and(|o| o.as_slice() == oid))
    .ok_or(Error::Unsupported)
}

/// Reads the explicitly tagged field `[n]` and returns a reader over it.
fn explicit<'a>(r: &mut Reader<'a>, n: u8) -> Result<Reader<'a>, Error> {
    r.read(tag::context_constructed(n)).map(Reader::new)
}

/// Parses the contents of `RSASSA-PSS-params` (RFC 4055 §3.1) and returns
/// the hash they restrict the key to; see [`RsaKeyAlgorithm`] for the
/// accepted form.
fn parse_pss_params(contents: &[u8]) -> Result<HashAlgorithm, Error> {
    let mut r = Reader::new(contents);
    // hashAlgorithm [0]: required, since the SHA-1 default is unsupported.
    let mut field = explicit(&mut r, 0)?;
    let hash = parse_hash(field.read(tag::SEQUENCE)?)?;
    field.finish()?;
    // maskGenAlgorithm [1]: MGF1 with the same hash (the default, MGF1
    // with SHA-1, is unsupported).
    let mut field = explicit(&mut r, 1)?;
    let mut mgf = field.read_sequence()?;
    field.finish()?;
    if mgf.read_oid()? != OID_MGF1 {
        return Err(Error::Unsupported);
    }
    let mgf_hash = parse_hash(mgf.read(tag::SEQUENCE)?)?;
    mgf.finish()?;
    // saltLength [2]: the digest length, which is never the default 20.
    let mut field = explicit(&mut r, 2)?;
    let salt_len = field.read_small_integer()?;
    field.finish()?;
    // trailerField [3] may only be 1, its DEFAULT, which DER omits; nothing
    // else may follow.
    r.finish()?;
    if mgf_hash != hash || salt_len != hash.output_len() as u64 {
        return Err(Error::Unsupported);
    }
    Ok(hash)
}

impl RsaKeyAlgorithm {
    /// Parses the contents of an `AlgorithmIdentifier` SEQUENCE (the OID and
    /// parameters, without the outer tag and length).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for malformed DER or an algorithm
    /// other than `rsaEncryption` and `id-RSASSA-PSS`, and
    /// [`Error::Unsupported`] for well-formed `RSASSA-PSS-params` outside the
    /// accepted set.
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
                Some(params) => Self::RsassaPss(Some(parse_pss_params(params)?)),
            }
        } else {
            return Err(Error::InvalidEncoding);
        };
        r.finish()?;
        Ok(alg)
    }

    /// Writes the contents of this algorithm's `AlgorithmIdentifier` (as
    /// [`Self::from_algorithm_identifier`] accepts them) to `out` and returns
    /// their length (at most [`MAX_ALGORITHM_IDENTIFIER_LEN`]).
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
    /// `hash` and a salt of the digest length.
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
    use std::vec::Vec;

    /// `AlgorithmIdentifier` contents of OpenSSL 3.0.13 public keys (from
    /// `openssl genpkey -algorithm RSA-PSS [-pkeyopt ...]` and
    /// `openssl pkey -pubout`): without parameters, and with
    /// `rsa_pss_keygen_md:sha256`, `rsa_pss_keygen_mgf1_md:sha256` and
    /// `rsa_pss_keygen_saltlen:32`.
    const OPENSSL_PSS: &str = "06092a864886f70d01010a";
    const OPENSSL_PSS_SHA256: &str = "06092a864886f70d01010a3034a00f300d0609608648016503040201\
        0500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120";
    /// OpenSSL 3.0.13 with only `rsa_pss_keygen_md:sha256`: MGF1 and the
    /// salt length are left at their SHA-1 / 20-byte defaults.
    const OPENSSL_PSS_SHA256_MGF1_SHA1: &str =
        "06092a864886f70d01010a3011a00f300d06096086480165030402010500";

    const OID_SHA1: [u8; 5] = [0x2b, 0x0e, 0x03, 0x02, 0x1a];
    const OID_SHA224: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];

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

    /// `id-RSASSA-PSS` with `RSASSA-PSS-params` made of `fields`.
    fn pss(fields: &[Vec<u8>]) -> Vec<u8> {
        [
            tlv(tag::OID, &OID_RSASSA_PSS),
            tlv(tag::SEQUENCE, &fields.concat()),
        ]
        .concat()
    }

    /// The parameters for `hash`, MGF1 over `mgf_hash`, a salt length and an
    /// optional trailer field.
    fn params(hash: &[u8], mgf_hash: &[u8], salt_len: u8, trailer: Option<u8>) -> Vec<u8> {
        let mut fields = [
            field(0, &hash_alg(hash, true)),
            field(1, &mgf1(&hash_alg(mgf_hash, true))),
            salt(&[salt_len]),
        ]
        .to_vec();
        if let Some(t) = trailer {
            fields.push(field(3, &tlv(tag::INTEGER, &[t])));
        }
        pss(&fields)
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
        assert_eq!(parse_hex(OPENSSL_PSS), Ok(RsaKeyAlgorithm::RsassaPss(None)));
        assert_eq!(
            parse_hex(OPENSSL_PSS_SHA256),
            Ok(RsaKeyAlgorithm::RsassaPss(Some(HashAlgorithm::Sha256)))
        );
        assert_eq!(
            hex::encode(encode(RsaKeyAlgorithm::RsassaPss(None))),
            OPENSSL_PSS
        );
        assert_eq!(
            hex::encode(encode(RsaKeyAlgorithm::RsassaPss(Some(
                HashAlgorithm::Sha256
            )))),
            OPENSSL_PSS_SHA256
        );
        // Missing maskGenAlgorithm (MGF1 with SHA-1) and saltLength (20).
        assert!(parse_hex(OPENSSL_PSS_SHA256_MGF1_SHA1).is_err());
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
        for (hash, oid) in [
            (HashAlgorithm::Sha256, OID_SHA256),
            (HashAlgorithm::Sha384, OID_SHA384),
            (HashAlgorithm::Sha512, OID_SHA512),
        ] {
            let by_hand = params(&oid, &oid, hash.output_len() as u8, None);
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
    fn inconsistent_parameters_are_rejected() {
        let s256 = &OID_SHA256[..];
        let s384 = &OID_SHA384[..];
        let s512 = &OID_SHA512[..];
        let unsupported = [
            // MGF1 over another hash.
            params(s256, s384, 32, None),
            params(s512, s256, 64, None),
            params(s256, &OID_SHA1, 32, None),
            // Salt lengths other than hLen.
            params(s256, s256, 20, None),
            params(s256, s256, 31, None),
            params(s256, s256, 64, None),
            params(s384, s384, 32, None),
            params(s512, s512, 0, None),
            // SHA-224 (which RFC 4055 lists) and SHA-1.
            params(&OID_SHA224, &OID_SHA224, 28, None),
            params(&OID_SHA1, &OID_SHA1, 20, None),
            // A mask generation function other than MGF1 (here id-sha256).
            pss(&[
                field(0, &hash_alg(s256, true)),
                field(
                    1,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, s256), hash_alg(s256, true)].concat(),
                    ),
                ),
                salt(&[32]),
            ]),
        ];
        for bad in &unsupported {
            assert_eq!(parse(bad), Err(Error::Unsupported), "{}", hex::encode(bad));
        }
        let mgf256 = field(1, &mgf1(&hash_alg(s256, true)));
        let hash256 = field(0, &hash_alg(s256, true));
        let malformed = [
            // An explicit trailer field, even the DEFAULT 1.
            params(s256, s256, 32, Some(1)),
            params(s256, s256, 32, Some(2)),
            // Empty parameters (every field DEFAULT: SHA-1) and NULL.
            pss(&[]),
            [tlv(tag::OID, &OID_RSASSA_PSS), [tag::NULL, 0].to_vec()].concat(),
            // Missing fields, and fields out of order.
            pss(core::slice::from_ref(&hash256)),
            pss(&[hash256.clone(), mgf256.clone()]),
            pss(&[mgf256.clone(), salt(&[32])]),
            pss(&[mgf256.clone(), hash256.clone(), salt(&[32])]),
            // Hash identifiers without their NULL parameters.
            pss(&[
                field(0, &hash_alg(s256, false)),
                mgf256.clone(),
                salt(&[32]),
            ]),
            pss(&[
                hash256.clone(),
                field(1, &mgf1(&hash_alg(s256, false))),
                salt(&[32]),
            ]),
            // A negative or non-minimal salt length.
            pss(&[hash256.clone(), mgf256.clone(), salt(&[0xe0])]),
            pss(&[hash256.clone(), mgf256.clone(), salt(&[0, 32])]),
            // Two values inside an explicit field.
            pss(&[
                field(0, &[hash_alg(s256, true), hash_alg(s256, true)].concat()),
                mgf256.clone(),
                salt(&[32]),
            ]),
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
    }
}
