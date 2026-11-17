//! Typed views of `basicConstraints`, `keyUsage`, `extKeyUsage` and
//! `authorityKeyIdentifier`.

use core::fmt;

use crate::der::{BitFlags, HexDebug, OidDebug, Reader};
use crate::name::GeneralNames;

/// `BasicConstraints` (RFC 5280 §4.2.1.9), decoded when the certificate is
/// parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BasicConstraints {
    /// `cA`: whether the subject is a CA (absent means `false`).
    pub ca: bool,
    /// `pathLenConstraint`: the most non-self-issued intermediate
    /// certificates that may follow this one in a path. A value above 255
    /// rejects the certificate when it is parsed. Some end-entity
    /// certificates carry one although it is only meaningful for CAs.
    pub path_len_constraint: Option<u8>,
}

/// A named bit of `KeyUsage` (RFC 5280 §4.2.1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyUsageBit {
    /// `digitalSignature (0)`.
    DigitalSignature,
    /// `nonRepudiation (1)`, renamed `contentCommitment` by recent X.509
    /// editions.
    NonRepudiation,
    /// `keyEncipherment (2)`.
    KeyEncipherment,
    /// `dataEncipherment (3)`.
    DataEncipherment,
    /// `keyAgreement (4)`.
    KeyAgreement,
    /// `keyCertSign (5)`.
    KeyCertSign,
    /// `cRLSign (6)`.
    CrlSign,
    /// `encipherOnly (7)`.
    EncipherOnly,
    /// `decipherOnly (8)`.
    DecipherOnly,
}

impl KeyUsageBit {
    /// Every bit, in bit-number order.
    pub const ALL: [Self; 9] = [
        Self::DigitalSignature,
        Self::NonRepudiation,
        Self::KeyEncipherment,
        Self::DataEncipherment,
        Self::KeyAgreement,
        Self::KeyCertSign,
        Self::CrlSign,
        Self::EncipherOnly,
        Self::DecipherOnly,
    ];

    /// The bit number.
    const fn number(self) -> usize {
        match self {
            Self::DigitalSignature => 0,
            Self::NonRepudiation => 1,
            Self::KeyEncipherment => 2,
            Self::DataEncipherment => 3,
            Self::KeyAgreement => 4,
            Self::KeyCertSign => 5,
            Self::CrlSign => 6,
            Self::EncipherOnly => 7,
            Self::DecipherOnly => 8,
        }
    }
}

/// A `KeyUsage` extension (RFC 5280 §4.2.1.3): a `BIT STRING` of
/// [`KeyUsageBit`]s, whose encoding (unused-bit count and zero padding) is
/// checked when the certificate is parsed. Bits beyond `decipherOnly` are
/// ignored.
///
/// Path validation treats an absent `KeyUsage` as permitting every usage;
/// this view only reports what the extension says.
#[derive(Clone, Copy)]
pub struct KeyUsageFlags<'a>(pub(crate) BitFlags<'a>);

impl KeyUsageFlags<'_> {
    /// Whether `bit` is set.
    #[must_use]
    pub fn contains(&self, bit: KeyUsageBit) -> bool {
        self.0.bit_set(bit.number())
    }
}

impl fmt::Debug for KeyUsageFlags<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyUsageFlags(")?;
        f.debug_list()
            .entries(KeyUsageBit::ALL.iter().filter(|b| self.contains(**b)))
            .finish()?;
        f.write_str(")")
    }
}

/// An iterator over the `KeyPurposeId`s of an `extKeyUsage` extension (RFC
/// 5280 §4.2.1.12), as `OBJECT IDENTIFIER` contents (without tag and
/// length; [`KeyUsage::server_auth`] has the encoding of `id-kp-serverAuth`
/// for example), in encoding order.
///
/// Every purpose is checked to be a well-formed `OBJECT IDENTIFIER` when
/// the certificate is parsed, so iteration cannot fail. An empty extension
/// (which path validation rejects) yields nothing.
///
/// [`KeyUsage::server_auth`]: crate::KeyUsage::server_auth
#[derive(Clone)]
pub struct KeyPurposeIdIter<'a> {
    reader: Reader<'a>,
}

impl<'a> KeyPurposeIdIter<'a> {
    /// Iterates over validated `SEQUENCE OF KeyPurposeId` contents.
    pub(crate) fn new(contents: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(contents),
        }
    }
}

impl<'a> Iterator for KeyPurposeIdIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }
        match self.reader.oid() {
            Ok(oid) => Some(oid),
            Err(_) => {
                self.reader = Reader::new(&[]);
                None
            }
        }
    }
}

impl core::iter::FusedIterator for KeyPurposeIdIter<'_> {}

impl fmt::Debug for KeyPurposeIdIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyPurposeIdIter(")?;
        f.debug_list()
            .entries(self.clone().map(OidDebug))
            .finish()?;
        f.write_str(")")
    }
}

/// An `AuthorityKeyIdentifier` extension (RFC 5280 §4.2.1.1).
///
/// When the certificate is parsed, the fields are checked to appear in
/// order, each at most once, with their tags; their contents are not
/// interpreted there. Path building uses only `keyIdentifier`, as a hint.
#[derive(Clone, Copy)]
pub struct AuthorityKeyIdentifier<'a> {
    pub(crate) key_identifier: Option<&'a [u8]>,
    pub(crate) authority_cert_issuer: Option<&'a [u8]>,
    pub(crate) authority_cert_serial_number: Option<&'a [u8]>,
}

impl<'a> AuthorityKeyIdentifier<'a> {
    /// `keyIdentifier [0]`: the issuer key's identifier, usually its
    /// `subjectKeyIdentifier`.
    #[must_use]
    pub fn key_identifier(&self) -> Option<&'a [u8]> {
        self.key_identifier
    }

    /// `authorityCertIssuer [1] GeneralNames`, read lazily: an entry that
    /// is not a well-formed `GeneralName` is returned as an error.
    #[must_use]
    pub fn authority_cert_issuer(&self) -> Option<GeneralNames<'a>> {
        self.authority_cert_issuer
            .map(|names| GeneralNames::new(Some(names)))
    }

    /// `authorityCertSerialNumber [2]`: the contents octets of the issuer
    /// certificate's serial number `INTEGER`, as encoded (not checked to
    /// be a minimal encoding).
    #[must_use]
    pub fn authority_cert_serial_number(&self) -> Option<&'a [u8]> {
        self.authority_cert_serial_number
    }
}

impl fmt::Debug for AuthorityKeyIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorityKeyIdentifier")
            .field("key_identifier", &self.key_identifier.map(HexDebug))
            .field("authority_cert_issuer", &self.authority_cert_issuer())
            .field(
                "authority_cert_serial_number",
                &self.authority_cert_serial_number.map(HexDebug),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::bit_string_flags;
    use alloc::format;

    #[test]
    fn key_usage_bits() {
        // digitalSignature, keyCertSign and decipherOnly.
        let flags = KeyUsageFlags(bit_string_flags(&[7, 0x84, 0x80]).unwrap());
        let set: alloc::vec::Vec<_> = KeyUsageBit::ALL
            .into_iter()
            .filter(|b| flags.contains(*b))
            .collect();
        assert_eq!(
            set,
            [
                KeyUsageBit::DigitalSignature,
                KeyUsageBit::KeyCertSign,
                KeyUsageBit::DecipherOnly
            ]
        );
        assert_eq!(
            format!("{flags:?}"),
            "KeyUsageFlags([DigitalSignature, KeyCertSign, DecipherOnly])"
        );
        let none = KeyUsageFlags(bit_string_flags(&[0]).unwrap());
        assert!(KeyUsageBit::ALL.iter().all(|b| !none.contains(*b)));
    }

    #[test]
    fn purposes() {
        // serverAuth, clientAuth.
        let eku =
            b"\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02";
        let it = KeyPurposeIdIter::new(eku);
        assert_eq!(it.clone().count(), 2);
        assert_eq!(
            format!("{it:?}"),
            "KeyPurposeIdIter([1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2])"
        );
        // A malformed entry (impossible after parsing) ends the iteration.
        assert_eq!(KeyPurposeIdIter::new(b"\x06\x01\x80").count(), 0);
    }
}
