//! The DTLS 1.3 encodings of the hello messages (RFC 9147 §5.3, §5.4),
//! and the parser of DTLS handshake messages.
//!
//! The handshake state machines see TLS version numbers in DTLS too: the
//! codec maps them to the DTLS ones on the wire and back. What goes into
//! the transcript is the DTLS encoding, as sent (RFC 9147 §5.2).

use super::super::{HandshakePayload, MAX_HANDSHAKE_SIZE, read_payload};
use super::{ClientHelloPayload, HandshakeMessagePayload, ServerHelloOrRetry, ServerHelloPayload};
use crate::enums::{HandshakeType, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::msgs::base::Payload;
use crate::msgs::codec::{Codec, Reader, u24};

/// Maps a TLS version to the DTLS version that stands for it, and back
/// (RFC 9147 §5.3): 0xfefc is DTLS 1.3 (TLS 1.3), 0xfefd DTLS 1.2 (TLS
/// 1.2) and 0xfeff DTLS 1.0 (TLS 1.1). Every other value maps to itself,
/// so the mapping is its own inverse: a decoded message encodes back to
/// the bytes it came from.
pub(crate) fn swap_version(version: ProtocolVersion) -> ProtocolVersion {
    let swapped: u16 = match u16::from(version) {
        0x0304 => 0xfefc,
        0xfefc => 0x0304,
        0x0303 => 0xfefd,
        0xfefd => 0x0303,
        0x0302 => 0xfeff,
        0xfeff => 0x0302,
        other => other,
    };
    ProtocolVersion::from(swapped)
}

/// `version` as it goes on the wire: its DTLS form when `dtls`.
pub(super) fn on_wire(version: ProtocolVersion, dtls: bool) -> ProtocolVersion {
    match dtls {
        true => swap_version(version),
        false => version,
    }
}

impl<'a> HandshakeMessagePayload<'a> {
    /// Parses a DTLS 1.3 handshake message, reassembled into its TLS form
    /// (type, 24-bit length, body: RFC 9147 §5.2), as
    /// [`Self::read_version`] does a TLS one. ClientHello, ServerHello and
    /// HelloRetryRequest are read in their DTLS encodings, with TLS
    /// versions in place of the DTLS ones.
    ///
    /// EndOfEarlyData does not exist in DTLS 1.3 (RFC 9147 §5.6),
    /// HelloVerifyRequest belongs to DTLS 1.2 (§5.1) and connection IDs
    /// (§9) are not supported: such a message reads as an unknown one,
    /// which every handshake state refuses with `unexpected_message`.
    pub(crate) fn read_dtls(
        r: &mut Reader<'a>,
        version: ProtocolVersion,
    ) -> Result<Self, InvalidMessage> {
        let typ = HandshakeType::read(r)?;
        let len = u24::read(r)?.0;
        if len > MAX_HANDSHAKE_SIZE {
            return Err(InvalidMessage::HandshakePayloadTooLarge);
        }
        let mut sub = r.sub(len as usize)?;
        let payload = match typ {
            HandshakeType::ClientHello => {
                HandshakePayload::ClientHello(ClientHelloPayload::read_with(&mut sub, true)?)
            }
            HandshakeType::ServerHello => match ServerHelloPayload::read(&mut sub)? {
                ServerHelloOrRetry::Hello(mut hello) => {
                    hello.legacy_version = swap_version(hello.legacy_version);
                    hello.extensions.supported_versions =
                        hello.extensions.supported_versions.map(swap_version);
                    hello.dtls = true;
                    HandshakePayload::ServerHello(hello)
                }
                ServerHelloOrRetry::Retry(mut retry) => {
                    retry.legacy_version = swap_version(retry.legacy_version);
                    retry.extensions.supported_versions =
                        retry.extensions.supported_versions.map(swap_version);
                    retry.dtls = true;
                    HandshakePayload::HelloRetryRequest(retry)
                }
            },
            HandshakeType::EndOfEarlyData
            | HandshakeType::HelloVerifyRequest
            | HandshakeType::RequestConnectionId
            | HandshakeType::NewConnectionId => {
                HandshakePayload::Unknown((typ, Payload::read(&mut sub)))
            }
            _ => return read_payload(typ, version, &mut sub).map(Self),
        };
        sub.expect_empty("HandshakeMessagePayload")?;
        Ok(Self(payload))
    }
}

#[cfg(test)]
mod tests;
