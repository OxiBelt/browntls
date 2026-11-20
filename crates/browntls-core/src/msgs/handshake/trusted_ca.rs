//! The `trusted_ca_keys` extension body (RFC 6066 §6).

use alloc::vec::Vec;

use super::DistinguishedName;
use crate::error::InvalidMessage;
use crate::msgs::codec::{Codec, ListLength, Reader, encode_vec_u16, read_list};

/// The length of a SHA-1 digest.
const SHA1_LEN: usize = 20;

/// The most `TrustedAuthority` entries read from one list. RFC 6066 sets no
/// limit, but a one-byte `pre_agreed` entry costs 32 bytes once decoded, so
/// an unbounded list would let a ClientHello of 64 KiB take 2 MiB before
/// the handshake is authenticated. A client names the roots it trusts; even
/// a whole public root store is a few hundred.
pub(crate) const MAX_TRUSTED_AUTHORITIES: usize = 1024;

/// `IdentifierType` values (RFC 6066 §6).
const PRE_AGREED: u8 = 0;
const KEY_SHA1_HASH: u8 = 1;
const X509_NAME: u8 = 2;
const CERT_SHA1_HASH: u8 = 3;

/// One certification authority root key a client says it possesses: a
/// `TrustedAuthority` of the `trusted_ca_keys` extension (RFC 6066 §6).
///
/// SHA-1 only names a key or certificate here; nothing is authenticated
/// through it (RFC 6066 §11.4).
///
/// A client lists these in
/// [`ClientConfig::trusted_ca_keys`](crate::ClientConfig::trusted_ca_keys);
/// a server reads them with
/// [`ClientHello::trusted_ca_keys`](crate::server::ClientHello::trusted_ca_keys).
/// The constructors that derive an identifier from a CA certificate or a
/// trust anchor take the SHA-1 function as an argument
/// (`crypto::native::sha1` or `crypto::rustcrypto::sha1`).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustedAuthority {
    /// `pre_agreed`: no key is named; client and server know the set of
    /// root keys by other means.
    PreAgreed,
    /// `key_sha1_hash`: the SHA-1 hash of the root key. For an RSA key the
    /// hash covers the big-endian modulus without leading zero bytes; for
    /// an ECDSA (or DSA) key, the `subjectPublicKey` value.
    KeySha1Hash([u8; SHA1_LEN]),
    /// `x509_name`: the DER-encoded distinguished name of the authority.
    X509Name(DistinguishedName),
    /// `cert_sha1_hash`: the SHA-1 hash of a DER-encoded certificate that
    /// holds the root key.
    CertSha1Hash([u8; SHA1_LEN]),
}

fn read_sha1(r: &mut Reader<'_>) -> Result<[u8; SHA1_LEN], InvalidMessage> {
    r.take(SHA1_LEN)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(InvalidMessage::MissingData("SHA1Hash"))
}

impl Codec<'_> for TrustedAuthority {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::PreAgreed => bytes.push(PRE_AGREED),
            Self::KeySha1Hash(hash) => {
                bytes.push(KEY_SHA1_HASH);
                bytes.extend_from_slice(hash);
            }
            Self::X509Name(name) => {
                bytes.push(X509_NAME);
                name.encode(bytes);
            }
            Self::CertSha1Hash(hash) => {
                bytes.push(CERT_SHA1_HASH);
                bytes.extend_from_slice(hash);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match u8::read(r)? {
            PRE_AGREED => Ok(Self::PreAgreed),
            KEY_SHA1_HASH => Ok(Self::KeySha1Hash(read_sha1(r)?)),
            X509_NAME => Ok(Self::X509Name(DistinguishedName::read(r)?)),
            CERT_SHA1_HASH => Ok(Self::CertSha1Hash(read_sha1(r)?)),
            // The identifier carries no length of its own, so an entry of a
            // type this crate does not know cannot be skipped.
            _ => Err(InvalidMessage::UnknownTrustedAuthorityType),
        }
    }
}

/// Encodes `TrustedAuthorities`: a list that may be empty.
pub(crate) fn encode_trusted_authorities(authorities: &[TrustedAuthority], bytes: &mut Vec<u8>) {
    encode_vec_u16(bytes, authorities);
}

/// Reads `TrustedAuthorities`. An empty list is valid: the client then
/// claims a set of root keys agreed by other means. A list of more than
/// [`MAX_TRUSTED_AUTHORITIES`] entries is refused (`MessageTooLarge`).
pub(crate) fn read_trusted_authorities(
    r: &mut Reader<'_>,
) -> Result<Vec<TrustedAuthority>, InvalidMessage> {
    read_list(ListLength::U16, r, MAX_TRUSTED_AUTHORITIES)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn sample() -> Vec<TrustedAuthority> {
        vec![
            TrustedAuthority::PreAgreed,
            TrustedAuthority::KeySha1Hash([0x11; SHA1_LEN]),
            TrustedAuthority::X509Name(DistinguishedName::in_sequence(&[0x31, 0x00])),
            TrustedAuthority::CertSha1Hash([0x22; SHA1_LEN]),
        ]
    }

    #[test]
    fn round_trip() {
        let mut bytes = Vec::new();
        encode_trusted_authorities(&sample(), &mut bytes);

        let mut expected = vec![0, 50];
        expected.push(PRE_AGREED);
        expected.push(KEY_SHA1_HASH);
        expected.extend([0x11; SHA1_LEN]);
        expected.extend([X509_NAME, 0, 4, 0x30, 0x02, 0x31, 0x00]);
        expected.push(CERT_SHA1_HASH);
        expected.extend([0x22; SHA1_LEN]);
        assert_eq!(bytes, expected);

        let mut r = Reader::init(&bytes);
        assert_eq!(read_trusted_authorities(&mut r).unwrap(), sample());
        assert!(!r.any_left());
    }

    #[test]
    fn empty_list_is_valid() {
        let mut bytes = Vec::new();
        encode_trusted_authorities(&[], &mut bytes);
        assert_eq!(bytes, [0, 0]);
        assert_eq!(
            read_trusted_authorities(&mut Reader::init(&bytes)).unwrap(),
            []
        );
    }

    /// A list of `n` `pre_agreed` entries, with its length prefix.
    fn pre_agreed_list(n: usize) -> Vec<u8> {
        let mut bytes = u16::try_from(n).unwrap().to_be_bytes().to_vec();
        bytes.resize(2 + n, PRE_AGREED);
        bytes
    }

    #[test]
    fn entry_count_is_bounded() {
        let at_limit = pre_agreed_list(MAX_TRUSTED_AUTHORITIES);
        assert_eq!(
            read_trusted_authorities(&mut Reader::init(&at_limit))
                .unwrap()
                .len(),
            MAX_TRUSTED_AUTHORITIES
        );
        let over = pre_agreed_list(MAX_TRUSTED_AUTHORITIES + 1);
        assert_eq!(
            read_trusted_authorities(&mut Reader::init(&over)),
            Err(InvalidMessage::MessageTooLarge)
        );
    }

    #[test]
    fn malformed_entries() {
        // An identifier type RFC 6066 does not define.
        assert_eq!(
            read_trusted_authorities(&mut Reader::init(&[0, 1, 4])),
            Err(InvalidMessage::UnknownTrustedAuthorityType)
        );
        // A hash cut short.
        let mut short = vec![0, 20, KEY_SHA1_HASH];
        short.extend([0u8; SHA1_LEN - 1]);
        assert_eq!(
            read_trusted_authorities(&mut Reader::init(&short)),
            Err(InvalidMessage::MissingData("SHA1Hash"))
        );
        // DistinguishedName<1..2^16-1>: an empty name is not allowed.
        assert_eq!(
            read_trusted_authorities(&mut Reader::init(&[0, 3, X509_NAME, 0, 0])),
            Err(InvalidMessage::IllegalEmptyValue)
        );
        // The list is shorter than its length prefix says.
        assert_eq!(
            read_trusted_authorities(&mut Reader::init(&[0, 2, PRE_AGREED])),
            Err(InvalidMessage::MessageTooShort)
        );
    }
}
