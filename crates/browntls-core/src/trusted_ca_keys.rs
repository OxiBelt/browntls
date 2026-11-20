//! Identifiers of the `trusted_ca_keys` extension (RFC 6066 §6): building
//! them from CA certificates and trust anchors, matching them against a CA
//! certificate, and checking a client's list before it is sent.

use browntls_pki::{CertificateDer, SubjectPublicKeyInfoDer, TrustAnchor};

use crate::error::{CertificateError, Error};
use crate::msgs::handshake::{
    DistinguishedName, MAX_TRUSTED_AUTHORITIES, TrustedAuthority, encode_trusted_authorities,
};
use crate::x509;

/// `rsaEncryption` (RFC 8017 §A.1).
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `id-RSASSA-PSS` (RFC 4055 §3.1): an RSA key restricted to RSASSA-PSS.
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];

fn bad_encoding() -> Error {
    CertificateError::BadEncoding.into()
}

/// The bytes RFC 6066 §6 hashes for `key_sha1_hash`, from the contents of
/// an `AlgorithmIdentifier` and the `subjectPublicKey` value.
fn hashed_key_bytes<'a>(alg: &[u8], key: &'a [u8]) -> Result<&'a [u8], Error> {
    let oid = x509::algorithm_oid(alg)?;
    if oid == OID_RSA_ENCRYPTION || oid == OID_RSASSA_PSS {
        // "For RSA keys, the hash is of the big-endian byte string
        // representation of the modulus without any initial zero-valued
        // bytes."
        let modulus = x509::rsa_modulus(key)?;
        let start = modulus
            .iter()
            .position(|b| *b != 0)
            .ok_or_else(bad_encoding)?;
        Ok(&modulus[start..])
    } else {
        // DSA and ECDSA keys: "the hash of the subjectPublicKey value". The
        // RFC names no other key type; EdDSA and the rest are hashed the
        // same way.
        Ok(key)
    }
}

fn anchor_of<'a>(ca_cert: &'a CertificateDer<'a>) -> Result<TrustAnchor<'a>, Error> {
    browntls_pki::anchor_from_trusted_cert(ca_cert).map_err(|_| bad_encoding())
}

impl TrustedAuthority {
    /// `cert_sha1_hash`: the SHA-1 hash of the DER-encoded `ca_cert`.
    ///
    /// `sha1` is a one-shot SHA-1 function, for instance
    /// `crypto::native::sha1` or `crypto::rustcrypto::sha1`. The
    /// certificate is not parsed.
    pub fn cert_sha1_hash(ca_cert: &CertificateDer<'_>, sha1: fn(&[u8]) -> [u8; 20]) -> Self {
        Self::CertSha1Hash(sha1(ca_cert.as_ref()))
    }

    /// `key_sha1_hash`: the SHA-1 hash of the public key of `ca_cert`.
    ///
    /// RFC 6066 §6: for an RSA key (`rsaEncryption` or `id-RSASSA-PSS`)
    /// the hash covers the big-endian modulus without leading zero bytes;
    /// for an ECDSA or DSA key, the `subjectPublicKey` value (the BIT
    /// STRING contents after the unused-bits octet). The RFC defines no
    /// other key type; for those (Ed25519, Ed448, ...) the
    /// `subjectPublicKey` value is hashed as well, so both peers must use
    /// this same rule.
    ///
    /// Certificates of version 1, and ones with unknown critical
    /// extensions, are accepted, as for trust anchors. A malformed
    /// certificate is [`CertificateError::BadEncoding`].
    pub fn key_sha1_hash(
        ca_cert: &CertificateDer<'_>,
        sha1: fn(&[u8]) -> [u8; 20],
    ) -> Result<Self, Error> {
        Self::key_sha1_hash_of_anchor(&anchor_of(ca_cert)?, sha1)
    }

    /// `key_sha1_hash` from a DER `SubjectPublicKeyInfo` (with its outer
    /// SEQUENCE); see [`Self::key_sha1_hash`] for what is hashed.
    pub fn key_sha1_hash_of_spki(
        spki: &SubjectPublicKeyInfoDer<'_>,
        sha1: fn(&[u8]) -> [u8; 20],
    ) -> Result<Self, Error> {
        let (alg, key) = x509::split_spki(spki.as_ref())?;
        Ok(Self::KeySha1Hash(sha1(hashed_key_bytes(alg, key)?)))
    }

    /// `key_sha1_hash` of a trust anchor, for instance one of
    /// [`RootCertStore::roots`](crate::RootCertStore::roots); see
    /// [`Self::key_sha1_hash`] for what is hashed.
    pub fn key_sha1_hash_of_anchor(
        anchor: &TrustAnchor<'_>,
        sha1: fn(&[u8]) -> [u8; 20],
    ) -> Result<Self, Error> {
        let spki = x509::wrap_in_sequence(anchor.subject_public_key_info.as_ref());
        Self::key_sha1_hash_of_spki(&SubjectPublicKeyInfoDer::from(spki), sha1)
    }

    /// `x509_name`: the subject `Name` of `ca_cert`, DER-encoded as it
    /// appears in the certificate.
    ///
    /// Certificates are accepted as by [`Self::key_sha1_hash`]; a
    /// malformed one is [`CertificateError::BadEncoding`].
    pub fn x509_name(ca_cert: &CertificateDer<'_>) -> Result<Self, Error> {
        Ok(Self::x509_name_of_anchor(&anchor_of(ca_cert)?))
    }

    /// `x509_name` of a trust anchor: its subject `Name`, DER-encoded.
    pub fn x509_name_of_anchor(anchor: &TrustAnchor<'_>) -> Self {
        Self::X509Name(DistinguishedName::in_sequence(anchor.subject.as_ref()))
    }

    /// Whether this identifier names the CA certificate `ca_cert`:
    /// `cert_sha1_hash` and `key_sha1_hash` compare the hash, `x509_name`
    /// compares the DER bytes of the subject name. `pre_agreed` names no
    /// certificate and never matches; neither does a certificate that
    /// cannot be parsed, for the identifiers that need parsing.
    ///
    /// Each call hashes or parses `ca_cert` again. To compare a client's
    /// list, which may hold up to 1024 entries, with known roots on every
    /// handshake, derive the roots' identifiers once and compare them with
    /// `==` instead.
    pub fn matches_certificate(
        &self,
        ca_cert: &CertificateDer<'_>,
        sha1: fn(&[u8]) -> [u8; 20],
    ) -> bool {
        match self {
            Self::PreAgreed => false,
            Self::CertSha1Hash(_) => *self == Self::cert_sha1_hash(ca_cert, sha1),
            Self::KeySha1Hash(_) => {
                Self::key_sha1_hash(ca_cert, sha1).is_ok_and(|ours| ours == *self)
            }
            Self::X509Name(_) => Self::x509_name(ca_cert).is_ok_and(|ours| ours == *self),
        }
    }
}

/// The longest `TrustedAuthorities` list a ClientHello can carry: the
/// extension body holds the list and its two-byte length prefix, under the
/// extension's own two-byte length.
const MAX_LIST_LEN: usize = 0xffff - 2;

/// Checks a configured `trusted_ca_keys` list when a client connection is
/// created: it must be encodable, so that no malformed ClientHello is sent.
/// Whether the whole ClientHello fits is checked when it is built.
pub(crate) fn check_config(list: Option<&[TrustedAuthority]>) -> Result<(), Error> {
    let Some(list) = list else {
        return Ok(());
    };
    // A server built from this crate refuses longer lists (decode_error).
    if list.len() > MAX_TRUSTED_AUTHORITIES {
        return Err(Error::General(
            "the trusted_ca_keys list has more than 1024 entries".into(),
        ));
    }
    // RFC 6066 §6: DistinguishedName<1..2^16-1>.
    let names_ok = list.iter().all(|entry| match entry {
        TrustedAuthority::X509Name(name) => (1..=0xffff).contains(&name.as_ref().len()),
        _ => true,
    });
    if !names_ok {
        return Err(Error::General(
            "a trusted_ca_keys x509_name is empty or longer than 65535 bytes".into(),
        ));
    }
    let mut encoded = alloc::vec::Vec::new();
    encode_trusted_authorities(list, &mut encoded);
    if encoded.len() - 2 > MAX_LIST_LEN {
        return Err(Error::General(
            "the trusted_ca_keys list does not fit in a ClientHello".into(),
        ));
    }
    Ok(())
}
