//! The ChangeCipherSpec message (RFC 5246 §7.1, RFC 8446 §5).

use alloc::vec::Vec;

use super::codec::{Codec, Reader};
use crate::error::InvalidMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChangeCipherSpecPayload;

impl Codec<'_> for ChangeCipherSpecPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        1u8.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match u8::read(r)? {
            1 => r.expect_empty("ChangeCipherSpecPayload").map(|_| Self),
            _ => Err(InvalidMessage::InvalidCcs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_0x01_is_valid() {
        assert_eq!(ChangeCipherSpecPayload.get_encoding(), [1]);
        assert!(ChangeCipherSpecPayload::read_bytes(&[1]).is_ok());
        assert_eq!(
            ChangeCipherSpecPayload::read_bytes(&[2]),
            Err(InvalidMessage::InvalidCcs)
        );
        assert_eq!(
            ChangeCipherSpecPayload::read_bytes(&[1, 1]),
            Err(InvalidMessage::TrailingData("ChangeCipherSpecPayload"))
        );
        assert_eq!(
            ChangeCipherSpecPayload::read_bytes(&[]),
            Err(InvalidMessage::MissingData("u8"))
        );
    }
}
