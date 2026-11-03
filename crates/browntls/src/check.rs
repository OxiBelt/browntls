//! Helpers for checking that a message has the expected shape.

use alloc::vec::Vec;

use crate::enums::{ContentType, HandshakeType};
use crate::error::Error;
use crate::msgs::message::MessagePayload;

/// The error for a message whose content type was not expected.
pub(crate) fn inappropriate_message(
    payload: &MessagePayload<'_>,
    content_types: &[ContentType],
) -> Error {
    Error::InappropriateMessage {
        expect_types: content_types.to_vec(),
        got_type: payload.content_type(),
    }
}

/// The error for a handshake message whose type was not expected.
pub(crate) fn inappropriate_handshake_message(
    payload: &MessagePayload<'_>,
    content_types: &[ContentType],
    handshake_types: &[HandshakeType],
) -> Error {
    match payload {
        MessagePayload::Handshake { parsed, .. } => Error::InappropriateHandshakeMessage {
            expect_types: handshake_types.to_vec(),
            got_type: parsed.typ(),
        },
        payload => inappropriate_message(payload, content_types),
    }
}

/// Extracts a borrowed handshake payload of one specific type from a message.
macro_rules! require_handshake_msg(
    ( $m:expr, $handshake_type:path, $payload_type:path ) => (
        match &$m.payload {
            $crate::msgs::message::MessagePayload::Handshake {
                parsed: $crate::msgs::handshake::HandshakeMessagePayload($payload_type(hm)),
                ..
            } => Ok(hm),
            payload => Err($crate::check::inappropriate_handshake_message(
                payload,
                &[$crate::enums::ContentType::Handshake],
                &[$handshake_type],
            )),
        }
    )
);

#[allow(dead_code)]
fn keep_vec_import(_: Vec<u8>) {}
