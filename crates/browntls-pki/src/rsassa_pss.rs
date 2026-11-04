//! Canonical forms of `id-RSASSA-PSS` `AlgorithmIdentifier`s (RFC 4055
//! §2.1, §3.1 and §3.3), so that every accepted encoding of the same
//! parameters matches the same [`SignatureVerificationAlgorithm`].
//!
//! Verification algorithms are matched to certificates and keys by their
//! `AlgorithmIdentifier`s. For most algorithms one DER encoding exists, but
//! `RSASSA-PSS-params` can be written in several ways RFC 4055 treats as
//! equal, and a key's `saltLength` is only a minimum. Before matching, an
//! `id-RSASSA-PSS` identifier is therefore mapped to one of the canonical
//! constants of [`alg_id`]:
//!
//! * a `SubjectPublicKeyInfo` algorithm to [`alg_id::RSASSA_PSS`] (no
//!   parameters: any hash) or to [`alg_id::RSASSA_PSS_SHA256_KEY`],
//!   [`alg_id::RSASSA_PSS_SHA384_KEY`] or [`alg_id::RSASSA_PSS_SHA512_KEY`]
//!   (parameters restricting the key to one hash, with any minimum salt
//!   length up to the digest length, which TLS signatures meet);
//! * a signature algorithm to [`alg_id::RSA_PSS_SHA256`],
//!   [`alg_id::RSA_PSS_SHA384`] or [`alg_id::RSA_PSS_SHA512`], whose salt
//!   must be exactly the digest length: the only RSASSA-PSS signatures a
//!   TLS signature scheme describes (RFC 9846 §4.3.3).
//!
//! # Accepted parameters
//!
//! The rules are those of `browntls_crypto::rsa::RsaKeyAlgorithm`, which
//! parses the same identifiers in keys; `browntls` tests that both agree on
//! every combination of the fields below.
//!
//! * `hashAlgorithm`: SHA-256, SHA-384 or SHA-512, with NULL or absent
//!   parameters (RFC 4055 §2.1). Absent (SHA-1), SHA-1, SHA-224 and other
//!   hashes are not supported.
//! * `maskGenAlgorithm`: MGF1 over the same hash, NULL or absent hash
//!   parameters. Absent (MGF1 with SHA-1) and other functions are not
//!   supported.
//! * `saltLength`: for a key absent (DEFAULT 20) or at most the digest
//!   length (RFC 4055 §3.3: the signature's salt must be at least the
//!   key's); for a signature exactly the digest length.
//! * `trailerField`: absent or 1.
//!
//! DER omits fields equal to their DEFAULT (X.690 §11.5). Of the explicit
//! DEFAULTs RFC 4055 §3.1 tells validators to recognise, `sha1Identifier`
//! and `mgf1SHA1Identifier` are unsupported anyway, and `trailerField` 1 is
//! accepted as RFC 4055 requires: the one non-DER form accepted.
//! `saltLength` 20 written explicitly is rejected as non-DER.
//!
//! RFC 9846 §4.3.3 asks certificate signature parameters to be "identical"
//! to those of a restricted issuer key. They are compared here as values
//! after these equivalences (RFC 4055 §3.3: equal except `saltLength`,
//! where the signature's must be at least the key's), not as bytes.
//!
//! [`SignatureVerificationAlgorithm`]: crate::SignatureVerificationAlgorithm

use crate::alg_id::{self, AlgorithmIdentifier};
use crate::der::{Reader, read_all, tag};
use crate::error::Error;

/// `id-mgf1` OBJECT IDENTIFIER contents (1.2.840.113549.1.1.8).
const OID_MGF1: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
/// `id-sha256`, `id-sha384` and `id-sha512` (2.16.840.1.101.3.4.2.{1,2,3})
/// without their last arc.
const OID_SHA2_PREFIX: [u8; 8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];
/// `saltLength` when the field is absent (RFC 4055 §3.1).
const DEFAULT_SALT_LEN: u8 = 20;

/// The hashes accepted in `RSASSA-PSS-params`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// The hash named by OBJECT IDENTIFIER contents `oid`, if supported.
    fn from_oid(oid: &[u8]) -> Option<Self> {
        match oid.split_last() {
            Some((1, prefix)) if prefix == OID_SHA2_PREFIX => Some(Self::Sha256),
            Some((2, prefix)) if prefix == OID_SHA2_PREFIX => Some(Self::Sha384),
            Some((3, prefix)) if prefix == OID_SHA2_PREFIX => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The digest length in bytes.
    fn len(self) -> u8 {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The identifier of a key restricted to this hash.
    fn key(self) -> AlgorithmIdentifier {
        match self {
            Self::Sha256 => alg_id::RSASSA_PSS_SHA256_KEY,
            Self::Sha384 => alg_id::RSASSA_PSS_SHA384_KEY,
            Self::Sha512 => alg_id::RSASSA_PSS_SHA512_KEY,
        }
    }

    /// The identifier of signatures with this hash, MGF1 over it and a salt
    /// of its length.
    fn signature(self) -> AlgorithmIdentifier {
        match self {
            Self::Sha256 => alg_id::RSA_PSS_SHA256,
            Self::Sha384 => alg_id::RSA_PSS_SHA384,
            Self::Sha512 => alg_id::RSA_PSS_SHA512,
        }
    }
}

/// Why an identifier has no canonical form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rejected {
    /// The algorithm is not `id-RSASSA-PSS`.
    NotRsassaPss,
    /// Malformed or non-DER, or parameters missing where required.
    Malformed,
    /// Well-formed parameters outside the accepted set.
    Unsupported,
}

/// A `maskGenAlgorithm` value.
enum MaskGen<'a> {
    /// MGF1 with the hash of this OBJECT IDENTIFIER.
    Mgf1(&'a [u8]),
    /// Another function, whose parameters are not examined.
    Other,
}

/// The fields of `RSASSA-PSS-params`, `None` when absent (DEFAULT).
struct Fields<'a> {
    hash: Option<&'a [u8]>,
    mask_gen: Option<MaskGen<'a>>,
    salt_len: Option<&'a [u8]>,
    trailer: Option<&'a [u8]>,
}

/// Validated parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Params {
    hash: Hash,
    /// `saltLength` (the DEFAULT when absent); `None` above 255.
    salt_len: Option<u8>,
}

/// Reads a hash `AlgorithmIdentifier` with NULL or absent parameters
/// (RFC 4055 §2.1) and returns its OBJECT IDENTIFIER.
fn read_hash<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    r.nested(tag::SEQUENCE, |r| {
        let oid = r.oid()?;
        if let Some(null) = r.optional(tag::NULL)?
            && !null.is_empty()
        {
            return Err(Error::BadDer);
        }
        Ok(oid)
    })
}

/// Reads a `MaskGenAlgorithm`: MGF1, whose parameters MUST be a hash
/// identifier (RFC 4055 §2.2), or another function.
fn read_mask_gen<'a>(r: &mut Reader<'a>) -> Result<MaskGen<'a>, Error> {
    r.nested(tag::SEQUENCE, |r| {
        if r.oid()? != OID_MGF1 {
            while !r.at_end() {
                r.tlv()?;
            }
            return Ok(MaskGen::Other);
        }
        read_hash(r).map(MaskGen::Mgf1)
    })
}

/// Reads the explicitly tagged field `[n]` with `f` if it is next.
fn optional_field<'a, T>(
    r: &mut Reader<'a>,
    n: u8,
    f: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    if r.peek(tag::context_constructed(n)) {
        r.nested(tag::context_constructed(n), f).map(Some)
    } else {
        Ok(None)
    }
}

/// Parses the structure of `RSASSA-PSS-params` contents.
fn fields(contents: &[u8]) -> Result<Fields<'_>, Error> {
    read_all(contents, |r| {
        let hash = optional_field(r, 0, read_hash)?;
        let mask_gen = optional_field(r, 1, read_mask_gen)?;
        let salt_len = optional_field(r, 2, Reader::nonnegative_integer)?;
        let trailer = optional_field(r, 3, Reader::nonnegative_integer)?;
        // A DEFAULT salt length written out is not DER (X.690 §11.5).
        if salt_len == Some(&[DEFAULT_SALT_LEN][..]) {
            return Err(Error::BadDer);
        }
        Ok(Fields {
            hash,
            mask_gen,
            salt_len,
            trailer,
        })
    })
}

/// Parses and checks `RSASSA-PSS-params` contents.
fn parse_params(contents: &[u8]) -> Result<Params, Rejected> {
    let fields = fields(contents).map_err(|_| Rejected::Malformed)?;
    // hashAlgorithm DEFAULT sha1Identifier.
    let hash = fields
        .hash
        .and_then(Hash::from_oid)
        .ok_or(Rejected::Unsupported)?;
    // maskGenAlgorithm DEFAULT mgf1SHA1Identifier.
    match fields.mask_gen {
        Some(MaskGen::Mgf1(oid)) if Hash::from_oid(oid) == Some(hash) => {}
        _ => return Err(Rejected::Unsupported),
    }
    // trailerField DEFAULT 1, its only value; explicit 1 is recognised.
    if !matches!(fields.trailer, None | Some([1])) {
        return Err(Rejected::Unsupported);
    }
    let salt_len = match fields.salt_len {
        None => Some(DEFAULT_SALT_LEN),
        Some(&[len]) => Some(len),
        Some(_) => None,
    };
    Ok(Params { hash, salt_len })
}

/// Splits `id-RSASSA-PSS` identifier contents into its optional
/// parameters' contents.
fn rsassa_pss_parameters(contents: &[u8]) -> Result<Option<&[u8]>, Rejected> {
    let oid = alg_id::RSASSA_PSS.as_bytes();
    if !contents.starts_with(oid) {
        return Err(Rejected::NotRsassaPss);
    }
    // RFC 4055 §1.2: absent, or RSASSA-PSS-params (not NULL).
    read_all(&contents[oid.len()..], |r| r.optional(tag::SEQUENCE)).map_err(|_| Rejected::Malformed)
}

/// The canonical form of a `SubjectPublicKeyInfo` algorithm.
pub(crate) fn public_key(contents: &[u8]) -> Result<AlgorithmIdentifier, Rejected> {
    let Some(params) = rsassa_pss_parameters(contents)? else {
        return Ok(alg_id::RSASSA_PSS);
    };
    let params = parse_params(params)?;
    // RFC 4055 §3.3: a signature's salt must be at least the key's;
    // TLS salts are the digest length.
    match params.salt_len {
        Some(len) if len <= params.hash.len() => Ok(params.hash.key()),
        _ => Err(Rejected::Unsupported),
    }
}

/// The canonical form of a signature algorithm.
pub(crate) fn signature(contents: &[u8]) -> Result<AlgorithmIdentifier, Rejected> {
    // RFC 4055 §3.1: the parameters MUST be present for a signature value.
    let params = rsassa_pss_parameters(contents)?.ok_or(Rejected::Malformed)?;
    let params = parse_params(params)?;
    if params.salt_len == Some(params.hash.len()) {
        Ok(params.hash.signature())
    } else {
        Err(Rejected::Unsupported)
    }
}

/// Builders for `id-RSASSA-PSS` identifiers in tests (public bytes only).
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    pub(crate) const OID_SHA1: [u8; 5] = [0x2b, 0x0e, 0x03, 0x02, 0x1a];
    pub(crate) const OID_SHA224: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
    pub(crate) const S256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    pub(crate) const S384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    pub(crate) const S512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

    pub(crate) fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 0x80);
        [&[tag, value.len() as u8][..], value].concat()
    }

    /// A hash `AlgorithmIdentifier` with NULL or absent parameters.
    pub(crate) fn hash_alg(oid: &[u8], null: bool) -> Vec<u8> {
        let mut v = tlv(tag::OID, oid);
        if null {
            v.extend([tag::NULL, 0]);
        }
        tlv(tag::SEQUENCE, &v)
    }

    /// The explicitly tagged field `[n]`.
    pub(crate) fn field(n: u8, value: &[u8]) -> Vec<u8> {
        tlv(tag::context_constructed(n), value)
    }

    pub(crate) fn mgf1(hash_alg: &[u8]) -> Vec<u8> {
        tlv(
            tag::SEQUENCE,
            &[tlv(tag::OID, &OID_MGF1), hash_alg.to_vec()].concat(),
        )
    }

    /// `hashAlgorithm [0]`.
    pub(crate) fn hash_field(oid: &[u8], null: bool) -> Vec<u8> {
        field(0, &hash_alg(oid, null))
    }

    /// `maskGenAlgorithm [1]`: MGF1 over the hash `oid`.
    pub(crate) fn mgf_field(oid: &[u8], null: bool) -> Vec<u8> {
        field(1, &mgf1(&hash_alg(oid, null)))
    }

    /// `saltLength [2]` with INTEGER contents `len`.
    pub(crate) fn salt(len: &[u8]) -> Vec<u8> {
        field(2, &tlv(tag::INTEGER, len))
    }

    /// `trailerField [3]` with INTEGER contents `value`.
    pub(crate) fn trailer(value: &[u8]) -> Vec<u8> {
        field(3, &tlv(tag::INTEGER, value))
    }

    /// `id-RSASSA-PSS` with `RSASSA-PSS-params` made of `fields`.
    pub(crate) fn pss(fields: &[Vec<u8>]) -> Vec<u8> {
        [
            alg_id::RSASSA_PSS.as_bytes().to_vec(),
            tlv(tag::SEQUENCE, &fields.concat()),
        ]
        .concat()
    }

    /// Parameters for the hash `oid` with the given hash parameter forms,
    /// explicit salt length and explicit trailer field 1.
    pub(crate) fn restricted(
        oid: &[u8],
        hash_null: bool,
        mgf_null: bool,
        salt_len: Option<u8>,
        trailer_one: bool,
    ) -> Vec<u8> {
        let mut fields = vec![hash_field(oid, hash_null), mgf_field(oid, mgf_null)];
        if let Some(len) = salt_len {
            assert!(len < 0x80);
            fields.push(salt(&[len]));
        }
        if trailer_one {
            fields.push(trailer(&[1]));
        }
        pss(&fields)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use alloc::vec::Vec;

    const SUPPORTED: [(Hash, &[u8]); 3] = [
        (Hash::Sha256, S256),
        (Hash::Sha384, S384),
        (Hash::Sha512, S512),
    ];

    /// `AlgorithmIdentifier` contents of OpenSSL 3.0.13 public keys made
    /// with `rsa_pss_keygen_md:sha256` and `rsa_pss_keygen_mgf1_md:sha256`,
    /// without `rsa_pss_keygen_saltlen` (saltLength omitted) and with
    /// `rsa_pss_keygen_saltlen:0`.
    const OPENSSL_SALT_DEFAULT: &str = "06092a864886f70d01010a302fa00f300d06096086480165030402\
        010500a11c301a06092a864886f70d010108300d06096086480165030402010500";
    const OPENSSL_SALT_0: &str = "06092a864886f70d01010a3034a00f300d0609608648016503040201050\
        0a11c301a06092a864886f70d010108300d06096086480165030402010500a203020100";

    /// Parameters naming `oid` twice in every accepted way, with an
    /// optional explicit salt length.
    fn forms(oid: &[u8], salt_len: Option<u8>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for hash_null in [true, false] {
            for mgf_null in [true, false] {
                for trailer_one in [false, true] {
                    out.push(restricted(oid, hash_null, mgf_null, salt_len, trailer_one));
                }
            }
        }
        out
    }

    #[test]
    fn canonical_constants_are_their_own_canonical_form() {
        assert_eq!(
            public_key(alg_id::RSASSA_PSS.as_bytes()),
            Ok(alg_id::RSASSA_PSS)
        );
        for (hash, _) in SUPPORTED {
            assert_eq!(public_key(hash.key().as_bytes()), Ok(hash.key()));
            assert_eq!(signature(hash.signature().as_bytes()), Ok(hash.signature()));
            // A signature identifier read as a key's: the same restriction.
            assert_eq!(public_key(hash.signature().as_bytes()), Ok(hash.key()));
        }
        // Absent parameters: a key, never a signature (RFC 4055 §3.1).
        assert_eq!(
            signature(alg_id::RSASSA_PSS.as_bytes()),
            Err(Rejected::Malformed)
        );
        for other in [
            alg_id::RSA_ENCRYPTION,
            alg_id::RSA_PKCS1_SHA256,
            alg_id::ECDSA_P256,
            alg_id::ED25519,
        ] {
            assert_eq!(public_key(other.as_bytes()), Err(Rejected::NotRsassaPss));
            assert_eq!(signature(other.as_bytes()), Err(Rejected::NotRsassaPss));
        }
    }

    #[test]
    fn openssl_keys_with_short_minimum_salts() {
        for key in [OPENSSL_SALT_DEFAULT, OPENSSL_SALT_0] {
            let key = hex::decode(key).unwrap();
            assert_eq!(public_key(&key), Ok(alg_id::RSASSA_PSS_SHA256_KEY));
            // As a signature identifier the salt is not the digest length.
            assert_eq!(signature(&key), Err(Rejected::Unsupported));
        }
    }

    #[test]
    fn equivalent_key_encodings_are_canonicalised() {
        for (hash, oid) in SUPPORTED {
            let salts =
                core::iter::once(None).chain((0..=hash.len()).filter(|&s| s != 20).map(Some));
            for salt_len in salts {
                for form in forms(oid, salt_len) {
                    assert_eq!(public_key(&form), Ok(hash.key()), "{}", hex::encode(&form));
                    let sig = signature(&form);
                    if salt_len == Some(hash.len()) {
                        assert_eq!(sig, Ok(hash.signature()), "{}", hex::encode(&form));
                    } else {
                        assert_eq!(sig, Err(Rejected::Unsupported), "{}", hex::encode(&form));
                    }
                }
            }
            // Longer minimum salts than the digest: unusable keys, and no
            // TLS signature.
            for salt_len in [hash.len() + 1, 0x7f] {
                for form in forms(oid, Some(salt_len)) {
                    assert_eq!(public_key(&form), Err(Rejected::Unsupported));
                    assert_eq!(signature(&form), Err(Rejected::Unsupported));
                }
            }
        }
        // Salt lengths above 255.
        for len in [&[0x01, 0x00][..], &[0x7f; 9]] {
            let form = pss(&[hash_field(S256, true), mgf_field(S256, true), salt(len)]);
            assert_eq!(public_key(&form), Err(Rejected::Unsupported));
            assert_eq!(signature(&form), Err(Rejected::Unsupported));
        }
    }

    #[test]
    fn unsupported_parameters_are_rejected() {
        let h256 = hash_field(S256, true);
        let m256 = mgf_field(S256, true);
        let unsupported = [
            // MGF1 over another hash, or the MGF1-SHA1 DEFAULT.
            pss(&[h256.clone(), mgf_field(S384, true), salt(&[32])]),
            pss(&[h256.clone(), mgf_field(&OID_SHA1, false), salt(&[32])]),
            pss(&[h256.clone(), salt(&[32])]),
            pss(core::slice::from_ref(&h256)),
            // SHA-1 (explicit or DEFAULT), SHA-224, an unknown hash.
            pss(&[hash_field(&OID_SHA1, true), mgf_field(&OID_SHA1, true)]),
            pss(&[]),
            pss(&[m256.clone(), salt(&[32])]),
            pss(&[
                hash_field(&OID_SHA224, true),
                mgf_field(&OID_SHA224, true),
                salt(&[28]),
            ]),
            pss(&[
                hash_field(&[0x2a, 0x03], true),
                mgf_field(&[0x2a, 0x03], true),
            ]),
            // Another mask generation function (here id-sha256).
            pss(&[
                h256.clone(),
                field(
                    1,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, S256), hash_alg(S256, true)].concat(),
                    ),
                ),
                salt(&[32]),
            ]),
            // Trailer fields other than 1.
            pss(&[h256.clone(), m256.clone(), salt(&[32]), trailer(&[0])]),
            pss(&[h256.clone(), m256.clone(), salt(&[32]), trailer(&[2])]),
            pss(&[h256.clone(), m256.clone(), salt(&[32]), trailer(&[1, 0])]),
        ];
        for bad in &unsupported {
            assert_eq!(
                public_key(bad),
                Err(Rejected::Unsupported),
                "{}",
                hex::encode(bad)
            );
            assert_eq!(
                signature(bad),
                Err(Rejected::Unsupported),
                "{}",
                hex::encode(bad)
            );
        }
    }

    #[test]
    fn malformed_parameters_are_rejected() {
        let h256 = hash_field(S256, true);
        let m256 = mgf_field(S256, true);
        let malformed = [
            // NULL instead of RSASSA-PSS-params; data after the parameters.
            [alg_id::RSASSA_PSS.as_bytes(), &[tag::NULL, 0]].concat(),
            [alg_id::RSA_PSS_SHA256.as_bytes(), &[tag::NULL, 0]].concat(),
            // An explicit DEFAULT salt length (X.690 §11.5).
            pss(&[h256.clone(), m256.clone(), salt(&[20])]),
            pss(&[hash_field(&OID_SHA1, true), salt(&[20])]),
            // Fields out of order, repeated or unknown.
            pss(&[m256.clone(), h256.clone(), salt(&[32])]),
            pss(&[h256.clone(), salt(&[32]), m256.clone()]),
            pss(&[h256.clone(), h256.clone(), m256.clone()]),
            pss(&[h256.clone(), m256.clone(), trailer(&[1]), salt(&[32])]),
            pss(&[
                h256.clone(),
                m256.clone(),
                field(4, &tlv(tag::INTEGER, &[1])),
            ]),
            // Hash parameters other than NULL; a NULL with contents.
            pss(&[
                field(
                    0,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, S256), tlv(tag::OID, S256)].concat(),
                    ),
                ),
                m256.clone(),
            ]),
            pss(&[
                field(
                    0,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, S256), tlv(tag::NULL, &[0])].concat(),
                    ),
                ),
                m256.clone(),
            ]),
            // MGF1 without its hash, or with NULL.
            pss(&[
                h256.clone(),
                field(1, &tlv(tag::SEQUENCE, &tlv(tag::OID, &OID_MGF1))),
            ]),
            pss(&[
                h256.clone(),
                field(
                    1,
                    &tlv(
                        tag::SEQUENCE,
                        &[tlv(tag::OID, &OID_MGF1), tlv(tag::NULL, &[])].concat(),
                    ),
                ),
            ]),
            // Negative, empty or non-minimal integers.
            pss(&[h256.clone(), m256.clone(), salt(&[0xe0])]),
            pss(&[h256.clone(), m256.clone(), salt(&[0, 32])]),
            pss(&[h256.clone(), m256.clone(), salt(&[])]),
            pss(&[h256.clone(), m256.clone(), trailer(&[0xff])]),
            pss(&[h256.clone(), m256.clone(), trailer(&[0, 1])]),
            // Two values in a field, or the wrong type.
            pss(&[
                field(0, &[hash_alg(S256, true), hash_alg(S256, true)].concat()),
                m256.clone(),
            ]),
            pss(&[
                h256.clone(),
                m256.clone(),
                field(2, &tlv(tag::OCTET_STRING, &[32])),
            ]),
            pss(&[field(0, &tlv(tag::OID, S256)), m256.clone()]),
        ];
        for bad in &malformed {
            assert_eq!(
                public_key(bad),
                Err(Rejected::Malformed),
                "{}",
                hex::encode(bad)
            );
            assert_eq!(
                signature(bad),
                Err(Rejected::Malformed),
                "{}",
                hex::encode(bad)
            );
        }
        // Every truncation of a canonical identifier but the bare OID.
        let good = alg_id::RSA_PSS_SHA384.as_bytes();
        for len in 0..good.len() {
            let result = public_key(&good[..len]);
            match len {
                0..11 => assert_eq!(result, Err(Rejected::NotRsassaPss), "{len}"),
                11 => assert_eq!(result, Ok(alg_id::RSASSA_PSS)),
                _ => assert_eq!(result, Err(Rejected::Malformed), "{len}"),
            }
        }
    }
}
