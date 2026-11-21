//! `ECHConfig` and `ECHConfigList` (RFC 9849 §4).

use alloc::vec::Vec;

use browntls_pki::DnsName;

use crate::crypto::hpke::{HpkeAead, HpkeKdf, HpkeKem, HpkeSymmetricCipherSuite};
use crate::error::InvalidMessage;
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, LengthPrefixedBuffer, ListLength, Reader};

/// The ECH version this crate implements (the extension code point).
pub(crate) const ECH_VERSION: u16 = 0xfe0d;

impl Codec<'_> for HpkeSymmetricCipherSuite {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.kdf_id.0.encode(bytes);
        self.aead_id.0.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            kdf_id: HpkeKdf(u16::read(r)?),
            aead_id: HpkeAead(u16::read(r)?),
        })
    }
}

/// `HpkeKeyConfig`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HpkeKeyConfig {
    pub(crate) config_id: u8,
    pub(crate) kem_id: HpkeKem,
    pub(crate) public_key: PayloadU16,
    pub(crate) cipher_suites: Vec<HpkeSymmetricCipherSuite>,
}

/// One `ECHConfigExtension`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EchConfigExtension {
    pub(crate) typ: u16,
    pub(crate) data: PayloadU16,
}

impl EchConfigExtension {
    /// Mandatory extensions have the high bit of their type set (§4.2).
    pub(crate) fn is_mandatory(&self) -> bool {
        self.typ & 0x8000 != 0
    }
}

/// `ECHConfigContents`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EchConfigContents {
    pub(crate) key_config: HpkeKeyConfig,
    pub(crate) maximum_name_length: u8,
    pub(crate) public_name: Vec<u8>,
    pub(crate) extensions: Vec<EchConfigExtension>,
}

impl Codec<'_> for EchConfigContents {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let kc = &self.key_config;
        kc.config_id.encode(bytes);
        kc.kem_id.0.encode(bytes);
        kc.public_key.encode(bytes);
        {
            let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
            for cs in &kc.cipher_suites {
                cs.encode(list.buf);
            }
        }
        self.maximum_name_length.encode(bytes);
        {
            let name = LengthPrefixedBuffer::new(ListLength::U8, bytes);
            name.buf.extend_from_slice(&self.public_name);
        }
        let list = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        for ext in &self.extensions {
            ext.typ.encode(list.buf);
            ext.data.encode(list.buf);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let config_id = u8::read(r)?;
        let kem_id = HpkeKem(u16::read(r)?);
        let public_key = PayloadU16::read(r)?;
        if public_key.0.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        // cipher_suites<4..2^16-4>: at least one, a whole number of pairs.
        let len = usize::from(u16::read(r)?);
        if len < 4 || len % 4 != 0 {
            return Err(InvalidMessage::InvalidEchConfig);
        }
        let mut sub = r.sub(len)?;
        let mut cipher_suites = Vec::new();
        while sub.any_left() {
            cipher_suites.push(HpkeSymmetricCipherSuite::read(&mut sub)?);
        }
        let maximum_name_length = u8::read(r)?;
        let name_len = usize::from(u8::read(r)?);
        if name_len == 0 {
            return Err(InvalidMessage::InvalidEchConfig);
        }
        let public_name = r
            .take(name_len)
            .ok_or(InvalidMessage::MissingData("public_name"))?
            .to_vec();
        let len = usize::from(u16::read(r)?);
        let mut sub = r.sub(len)?;
        let mut extensions: Vec<EchConfigExtension> = Vec::new();
        while sub.any_left() {
            let typ = u16::read(&mut sub)?;
            let data = PayloadU16::read(&mut sub)?;
            // §4.2: no two extensions of the same type.
            if extensions.iter().any(|e| e.typ == typ) {
                return Err(InvalidMessage::InvalidEchConfig);
            }
            extensions.push(EchConfigExtension { typ, data });
        }
        Ok(Self {
            key_config: HpkeKeyConfig {
                config_id,
                kem_id,
                public_key,
                cipher_suites,
            },
            maximum_name_length,
            public_name,
            extensions,
        })
    }
}

/// One `ECHConfig` from a list, with its exact encoding (the HPKE `info`
/// covers the serialized `ECHConfig`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EchConfigEntry {
    pub(crate) version: u16,
    /// `Some` for [`ECH_VERSION`]; other versions are kept opaque.
    pub(crate) contents: Option<EchConfigContents>,
    /// `version || length || contents`.
    pub(crate) encoded: Vec<u8>,
}

impl EchConfigEntry {
    /// Encodes `contents` as a version-`0xfe0d` `ECHConfig`.
    pub(crate) fn from_contents(contents: EchConfigContents) -> Self {
        let mut encoded = Vec::new();
        ECH_VERSION.encode(&mut encoded);
        {
            let body = LengthPrefixedBuffer::new(ListLength::U16, &mut encoded);
            contents.encode(body.buf);
        }
        Self {
            version: ECH_VERSION,
            contents: Some(contents),
            encoded,
        }
    }

    /// Reads one entry; `encoded` is left for the caller, which has the
    /// bytes as received.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let version = u16::read(r)?;
        let len = usize::from(u16::read(r)?);
        let mut body = r.sub(len)?;
        let contents = if version == ECH_VERSION {
            let c = EchConfigContents::read(&mut body)?;
            body.expect_empty("ECHConfigContents")?;
            Some(c)
        } else {
            body.rest();
            None
        };
        Ok(Self {
            version,
            contents,
            encoded: Vec::new(),
        })
    }
}

/// Parses an `ECHConfigList` (`ECHConfig ECHConfigList<4..2^16-1>`),
/// keeping configurations of unknown versions as opaque entries.
pub(crate) fn read_config_list(bytes: &[u8]) -> Result<Vec<EchConfigEntry>, InvalidMessage> {
    let mut r = Reader::init(bytes);
    let len = usize::from(u16::read(&mut r)?);
    if len < 4 {
        return Err(InvalidMessage::InvalidEchConfig);
    }
    let mut sub = r.sub(len)?;
    r.expect_empty("ECHConfigList")?;
    let mut out = Vec::new();
    while sub.any_left() {
        let before = sub.used();
        let mut entry = EchConfigEntry::read(&mut sub)?;
        // Keep the received bytes, so the HPKE info matches the server's.
        entry.encoded = bytes[2 + before..2 + sub.used()].to_vec();
        out.push(entry);
    }
    Ok(out)
}

/// Encodes a list of configurations as an `ECHConfigList`.
pub(crate) fn encode_config_list<'a>(entries: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let list = LengthPrefixedBuffer::new(ListLength::U16, &mut out);
        for e in entries {
            list.buf.extend_from_slice(e);
        }
    }
    out
}

/// Checks `public_name` as RFC 9849 §6.1.7 asks: a host name in preferred
/// name syntax whose last label is neither all digits nor a hexadecimal
/// `0x` literal (which could be read as an IPv4 address).
pub(crate) fn valid_public_name(name: &[u8]) -> Option<DnsName<'static>> {
    let s = core::str::from_utf8(name).ok()?;
    if s.is_empty() || s.starts_with('.') || s.ends_with('.') {
        return None;
    }
    for label in s.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || bytes[0] == b'-'
            || bytes[bytes.len() - 1] == b'-'
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return None;
        }
    }
    let last = s.rsplit('.').next()?;
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if let Some(hex) = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X"))
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    DnsName::try_from_ascii(s).ok().map(|dns| dns.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example `ech` SvcParam of RFC 9848 §3 (public name
    /// `ech-sites.example.net`).
    pub(crate) const RFC9848_EXAMPLE: &str = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA=";

    #[test]
    fn parses_rfc9848_example_and_round_trips() {
        let bytes = browntls_pki::pem::base64_decode(RFC9848_EXAMPLE.as_bytes()).unwrap();
        let list = read_config_list(&bytes).unwrap();
        assert_eq!(list.len(), 1);
        let c = list[0].contents.as_ref().unwrap();
        assert_eq!(c.key_config.config_id, 1);
        assert_eq!(c.key_config.kem_id, HpkeKem::DHKEM_X25519_HKDF_SHA256);
        assert_eq!(c.key_config.public_key.0.len(), 32);
        assert_eq!(
            c.key_config.cipher_suites,
            [HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM
            }]
        );
        assert_eq!(c.maximum_name_length, 100);
        assert_eq!(c.public_name, b"ech-sites.example.net");
        assert!(c.extensions.is_empty());
        // Re-encoding reproduces the received entry and list.
        let again = EchConfigEntry::from_contents(c.clone());
        assert_eq!(again.encoded, list[0].encoded);
        assert_eq!(
            encode_config_list(list.iter().map(|e| e.encoded.as_slice())),
            bytes
        );
    }

    #[test]
    fn rejects_malformed_lists() {
        let bytes = browntls_pki::pem::base64_decode(RFC9848_EXAMPLE.as_bytes()).unwrap();
        // Truncated, trailing data, empty list.
        assert!(read_config_list(&bytes[..bytes.len() - 1]).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(read_config_list(&long).is_err());
        assert!(read_config_list(&[0, 0]).is_err());
        // An odd cipher_suites length.
        let mut bad = bytes.clone();
        bad[2 + 4 + 1 + 2 + 2 + 32 + 1] = 5;
        assert!(read_config_list(&bad).is_err());
        // An unknown version is kept opaque.
        let mut other = bytes.clone();
        other[2] = 0xfe;
        other[3] = 0x0c;
        let list = read_config_list(&other).unwrap();
        assert!(list[0].contents.is_none());
        assert_eq!(list[0].encoded, other[2..]);
    }

    #[test]
    fn public_name_rules() {
        assert!(valid_public_name(b"example.com").is_some());
        assert!(valid_public_name(b"a-b.example").is_some());
        for bad in [
            &b""[..],
            b".example.com",
            b"example.com.",
            b"exa mple.com",
            b"-a.example",
            b"192.0.2.1",
            b"example.0x1f",
            b"example.0X",
            b"example.123",
        ] {
            assert!(valid_public_name(bad).is_none(), "{bad:?}");
        }
        let long = [b'a'; 64];
        assert!(valid_public_name(&long).is_none());
    }
}
