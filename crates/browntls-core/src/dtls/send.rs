//! How the shared state machines' outgoing messages reach the DTLS engine
//! instead of the TLS record layer.

use crate::common_state::CommonState;
use crate::enums::ContentType;
use crate::msgs::message::{MessagePayload, PlainMessage};

impl CommonState {
    /// On a DTLS connection, handshake messages join the flight being
    /// prepared and alerts are sent once, both under the current sending
    /// epoch whatever the caller asked about encryption. There is no
    /// ChangeCipherSpec in DTLS 1.3 (RFC 9147 §5), and application data
    /// does not come this way. Returns whether this is a DTLS connection.
    pub(crate) fn send_to_dtls(&mut self, payload: &MessagePayload<'_>) -> bool {
        let Some(dtls) = &mut self.dtls else {
            return false;
        };
        match payload {
            MessagePayload::Handshake { encoded, .. } => dtls.queue_handshake(encoded.bytes()),
            MessagePayload::Alert(alert) => dtls.queue_alert(alert.level, alert.description),
            _ => {}
        }
        true
    }

    /// As [`Self::send_to_dtls`], for a message to encrypt: only handshake
    /// messages (KeyUpdate) come this way.
    pub(crate) fn send_plain_to_dtls(&mut self, m: &PlainMessage) -> bool {
        let Some(dtls) = &mut self.dtls else {
            return false;
        };
        if m.typ == ContentType::Handshake {
            dtls.queue_handshake(m.payload.bytes());
        }
        true
    }
}
