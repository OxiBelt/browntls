//! Alert messages (RFC 8446 §6).

use alloc::vec::Vec;

use super::codec::{Codec, Reader};
use super::enums::AlertLevel;
use crate::enums::AlertDescription;
use crate::error::InvalidMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AlertMessagePayload {
    pub(crate) level: AlertLevel,
    pub(crate) description: AlertDescription,
}

impl Codec<'_> for AlertMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.level.encode(bytes);
        self.description.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let level = AlertLevel::read(r)?;
        let description = AlertDescription::read(r)?;
        r.expect_empty("AlertMessagePayload")
            .map(|_| Self { level, description })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_reject_trailing() {
        let a = AlertMessagePayload {
            level: AlertLevel::Fatal,
            description: AlertDescription::HandshakeFailure,
        };
        assert_eq!(a.get_encoding(), [2, 40]);
        assert_eq!(AlertMessagePayload::read_bytes(&[2, 40]).unwrap(), a);
        assert_eq!(
            AlertMessagePayload::read_bytes(&[2, 40, 0]),
            Err(InvalidMessage::TrailingData("AlertMessagePayload"))
        );
        assert_eq!(
            AlertMessagePayload::read_bytes(&[2]),
            Err(InvalidMessage::MissingData("AlertDescription"))
        );
    }
}
