//! GREASE values (RFC 8701): reserved codepoints an endpoint sprinkles into
//! the lists it offers, so that peers which mishandle unknown values are
//! noticed early, instead of the ecosystem ossifying around today's values.
//!
//! Every two-byte GREASE value has the form `0x?A?A` with both high nibbles
//! equal (RFC 8701 §2): 0x0A0A, 0x1A1A, ..., 0xFAFA. They are reserved for
//! cipher suites, extensions, named groups, signature algorithms, versions
//! and ALPN identifiers. `psk_key_exchange_modes` uses the one-byte values
//! 0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5 and 0xE4.
//!
//! A client offers them in its ClientHello (§3.1, [`GreaseValues`]); a
//! server in the two TLS 1.3 messages whose extension points it offers and
//! the client selects from (§4.1, [`ServerGreaseValues`]): a
//! CertificateRequest and a NewSessionTicket.
//!
//! Whoever receives GREASE values ignores them like any unknown value and
//! never selects one; whoever sent them never accepts one back. Neither
//! needs special code for that: a GREASE value is never in a configuration,
//! and the sender keeps the GREASE values it sent out of the lists it checks
//! the peer's choices against.

use crate::crypto::SecureRandom;
use crate::error::Error;

/// Whether `value` is one of the sixteen two-byte GREASE values.
pub(crate) const fn is_grease_u16(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 12 == (value >> 4) & 0x0f
}

/// Whether `value` is one of the eight GREASE `PskKeyExchangeMode` values.
#[cfg(test)]
pub(crate) const fn is_grease_psk_mode(value: u8) -> bool {
    value >= 0x0b && (value - 0x0b).is_multiple_of(0x1f)
}

/// The GREASE values one connection uses. They are drawn once per
/// connection and reused for a second ClientHello after a
/// HelloRetryRequest, which must otherwise repeat the first (RFC 9846
/// §4.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GreaseValues {
    pub(crate) cipher_suite: u16,
    pub(crate) group: u16,
    pub(crate) signature_scheme: u16,
    pub(crate) version: u16,
    /// The empty GREASE extension, sent first.
    pub(crate) first_extension: u16,
    /// The non-empty GREASE extension, sent last but for `padding` and
    /// `pre_shared_key`; always different from `first_extension`.
    pub(crate) last_extension: u16,
    pub(crate) psk_mode: u8,
}

impl GreaseValues {
    /// Draws a fresh set of values.
    pub(crate) fn random(rng: &dyn SecureRandom) -> Result<Self, Error> {
        let mut seed = [0u8; 7];
        rng.fill(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    fn from_seed(seed: [u8; 7]) -> Self {
        let (first_extension, last_extension) = extension_pair(seed[4], seed[5]);
        Self {
            cipher_suite: two_byte(seed[0]),
            group: two_byte(seed[1]),
            signature_scheme: two_byte(seed[2]),
            version: two_byte(seed[3]),
            first_extension,
            last_extension,
            psk_mode: 0x0b + 0x1f * (seed[6] & 0x07),
        }
    }
}

/// The GREASE values a server puts into one message (RFC 8701 §4.1): a
/// TLS 1.3 CertificateRequest or NewSessionTicket. They are drawn for each
/// message: nothing ties the values of one message to those of another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServerGreaseValues {
    /// Sent first in the `signature_algorithms` of a CertificateRequest; a
    /// NewSessionTicket has no use for it.
    pub(crate) signature_scheme: u16,
    /// The empty GREASE extension, sent first.
    pub(crate) first_extension: u16,
    /// The one-byte GREASE extension, sent last; always different from
    /// `first_extension`.
    pub(crate) last_extension: u16,
}

impl ServerGreaseValues {
    /// Draws a fresh set of values.
    pub(crate) fn random(rng: &dyn SecureRandom) -> Result<Self, Error> {
        let mut seed = [0u8; 3];
        rng.fill(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    fn from_seed(seed: [u8; 3]) -> Self {
        let (first_extension, last_extension) = extension_pair(seed[1], seed[2]);
        Self {
            signature_scheme: two_byte(seed[0]),
            first_extension,
            last_extension,
        }
    }
}

/// The two-byte GREASE value the low nibble of `b` selects.
fn two_byte(b: u8) -> u16 {
    let nibble = u16::from(b & 0x0f);
    (nibble << 12) | (nibble << 4) | 0x0a0a
}

/// Two GREASE extension types for one extension block, which must differ
/// (RFC 8701 §5: an extension type appears once in a block).
fn extension_pair(first: u8, last: u8) -> (u16, u16) {
    let first = two_byte(first);
    let mut last = two_byte(last);
    if last == first {
        last ^= 0x1010;
    }
    (first, last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_exactly_the_reserved_values() {
        let two_byte: alloc::vec::Vec<u16> = (0..=u16::MAX).filter(|v| is_grease_u16(*v)).collect();
        assert_eq!(two_byte.len(), 16);
        assert_eq!(two_byte[0], 0x0a0a);
        assert_eq!(two_byte[15], 0xfafa);
        assert!(two_byte.iter().all(|v| v >> 8 == v & 0xff));
        let one_byte: alloc::vec::Vec<u8> =
            (0..=u8::MAX).filter(|v| is_grease_psk_mode(*v)).collect();
        assert_eq!(one_byte, [0x0b, 0x2a, 0x49, 0x68, 0x87, 0xa6, 0xc5, 0xe4]);
    }

    #[test]
    fn every_seed_gives_grease_values() {
        for a in 0..=u8::MAX {
            let values = GreaseValues::from_seed([a, a, a, a, a, a.wrapping_mul(7), a]);
            for v in [
                values.cipher_suite,
                values.group,
                values.signature_scheme,
                values.version,
                values.first_extension,
                values.last_extension,
            ] {
                assert!(is_grease_u16(v), "{v:#06x}");
            }
            assert!(is_grease_psk_mode(values.psk_mode));
            assert_ne!(values.first_extension, values.last_extension);
        }
    }

    #[test]
    fn every_seed_gives_server_grease_values() {
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                let values = ServerGreaseValues::from_seed([a ^ b, a, b]);
                for v in [
                    values.signature_scheme,
                    values.first_extension,
                    values.last_extension,
                ] {
                    assert!(is_grease_u16(v), "{v:#06x}");
                }
                assert_ne!(values.first_extension, values.last_extension);
            }
        }
    }
}
