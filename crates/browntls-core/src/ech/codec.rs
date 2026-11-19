//! The `encrypted_client_hello` extension payloads (RFC 9849 §5).

use alloc::vec::Vec;
use core::ops::Range;

use crate::crypto::hpke::HpkeSymmetricCipherSuite;
use crate::error::InvalidMessage;
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};

/// `ECHClientHelloType`.
const TYPE_OUTER: u8 = 0;
const TYPE_INNER: u8 = 1;

/// The outer variant of `ECHClientHello`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EchOuter {
    pub(crate) cipher_suite: HpkeSymmetricCipherSuite,
    pub(crate) config_id: u8,
    pub(crate) enc: PayloadU16,
    pub(crate) payload: PayloadU16,
}

/// `ECHClientHello` as sent in a ClientHello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EchClientHello {
    Outer(EchOuter),
    Inner,
    /// An `ECHClientHelloType` this version does not define; a server
    /// answers it with `illegal_parameter` (§7).
    Unknown(u8),
}

impl Codec<'_> for EchClientHello {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Outer(o) => {
                TYPE_OUTER.encode(bytes);
                o.cipher_suite.encode(bytes);
                o.config_id.encode(bytes);
                o.enc.encode(bytes);
                o.payload.encode(bytes);
            }
            Self::Inner => TYPE_INNER.encode(bytes),
            Self::Unknown(t) => t.encode(bytes),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match u8::read(r)? {
            TYPE_OUTER => {
                let cipher_suite = HpkeSymmetricCipherSuite::read(r)?;
                let config_id = u8::read(r)?;
                let enc = PayloadU16::read(r)?;
                let payload = PayloadU16::read(r)?;
                if payload.0.is_empty() {
                    return Err(InvalidMessage::IllegalEmptyValue);
                }
                Ok(Self::Outer(EchOuter {
                    cipher_suite,
                    config_id,
                    enc,
                    payload,
                }))
            }
            TYPE_INNER => Ok(Self::Inner),
            other => {
                r.rest();
                Ok(Self::Unknown(other))
            }
        }
    }
}

/// One entry of an encoded extension block, by offsets into the block
/// (which starts with its `u16` length).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawExtension {
    pub(crate) typ: u16,
    /// From the type field to the end of the body.
    pub(crate) whole: Range<usize>,
    /// The body alone.
    pub(crate) body: Range<usize>,
}

/// Splits an extension block (`u16` length, then entries) into entries,
/// or `None` if it is malformed or has trailing data.
pub(crate) fn raw_extensions(block: &[u8]) -> Option<Vec<RawExtension>> {
    let len = usize::from(u16::from_be_bytes([*block.first()?, *block.get(1)?]));
    if block.len() != 2 + len {
        return None;
    }
    let mut out = Vec::new();
    let mut at = 2;
    while at < block.len() {
        let typ = u16::from_be_bytes([*block.get(at)?, *block.get(at + 1)?]);
        let body_len = usize::from(u16::from_be_bytes([
            *block.get(at + 2)?,
            *block.get(at + 3)?,
        ]));
        let end = at + 4 + body_len;
        if end > block.len() {
            return None;
        }
        out.push(RawExtension {
            typ,
            whole: at..end,
            body: at + 4..end,
        });
        at = end;
    }
    Some(out)
}

/// The offset of the extension block in an encoded ClientHello body
/// (without the handshake header), or `None` if there is none.
pub(crate) fn client_hello_extensions_offset(body: &[u8]) -> Option<usize> {
    // legacy_version, random
    let mut at = 2 + 32;
    // legacy_session_id<0..32>
    at += 1 + usize::from(*body.get(at)?);
    // cipher_suites<2..2^16-2>
    at += 2 + usize::from(u16::from_be_bytes([*body.get(at)?, *body.get(at + 1)?]));
    // legacy_compression_methods<1..2^8-1>
    at += 1 + usize::from(*body.get(at)?);
    (at < body.len()).then_some(at)
}

/// The offset of the extension block in an encoded ServerHello or
/// HelloRetryRequest body (without the handshake header).
pub(crate) fn server_hello_extensions_offset(body: &[u8]) -> Option<usize> {
    // legacy_version, random, legacy_session_id_echo, cipher_suite,
    // legacy_compression_method
    let at = 2 + 32;
    let at = at + 1 + usize::from(*body.get(at)?) + 2 + 1;
    (at < body.len()).then_some(at)
}

/// The range of the body of extension `typ` within `body`, a ClientHello or
/// ServerHello body located by `offset_of`.
pub(crate) fn find_extension(
    body: &[u8],
    offset_of: fn(&[u8]) -> Option<usize>,
    typ: u16,
) -> Option<Range<usize>> {
    let start = offset_of(body)?;
    raw_extensions(&body[start..])?
        .into_iter()
        .find(|e| e.typ == typ)
        .map(|e| start + e.body.start..start + e.body.end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hpke::{HpkeAead, HpkeKdf};

    #[test]
    fn round_trips_and_rejects() {
        let outer = EchClientHello::Outer(EchOuter {
            cipher_suite: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            },
            config_id: 7,
            enc: PayloadU16::new(alloc::vec![1; 32]),
            payload: PayloadU16::new(alloc::vec![2; 48]),
        });
        for v in [outer, EchClientHello::Inner] {
            let enc = v.get_encoding();
            assert_eq!(EchClientHello::read_bytes(&enc).unwrap(), v);
        }
        assert_eq!(
            EchClientHello::read_bytes(&[5, 1, 2]).unwrap(),
            EchClientHello::Unknown(5)
        );
        // Empty payload, truncated body, trailing data after `inner`.
        assert!(EchClientHello::read_bytes(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0]).is_err());
        assert!(EchClientHello::read_bytes(&[0, 0, 1]).is_err());
        assert!(EchClientHello::read_bytes(&[1, 0]).is_err());
    }

    #[test]
    fn raw_extension_blocks() {
        let block = [0, 9, 0, 1, 0, 1, 7, 0xfe, 0x0d, 0, 0];
        let exts = raw_extensions(&block).unwrap();
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].typ, 1);
        assert_eq!(&block[exts[0].body.clone()], &[7]);
        assert_eq!(exts[1].whole, 7..11);
        assert!(exts[1].body.is_empty());
        // Overrun, trailing data, short length.
        assert!(raw_extensions(&[0, 4, 0, 1, 0, 1]).is_none());
        assert!(raw_extensions(&[0, 0, 1]).is_none());
        assert!(raw_extensions(&[0, 3, 0, 1, 0]).is_none());
        assert!(raw_extensions(&[0]).is_none());
    }
}
