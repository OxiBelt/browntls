//! How the shared state machines' outgoing messages reach the DTLS engine
//! instead of the TLS record layer.

use alloc::vec::Vec;

use super::state::{APPLICATION_EPOCH, Dtls, WriteEpoch};
use crate::common_state::CommonState;
use crate::enums::ContentType;
use crate::error::Error;
use crate::msgs::message::{MessagePayload, PlainMessage};

impl CommonState {
    /// On a DTLS connection, handshake messages join the flight being
    /// prepared and alerts are sent once, both under the current sending
    /// epoch whatever the caller asked about encryption. There is no
    /// ChangeCipherSpec in DTLS 1.3 (RFC 9147 §5). DTLS 1.2 queues CCS in
    /// its flight; application data does not come this way. Returns whether
    /// this is a DTLS connection.
    pub(crate) fn send_to_dtls(&mut self, payload: &MessagePayload<'_>) -> bool {
        let Some(dtls) = &mut self.dtls else {
            return false;
        };
        match payload {
            MessagePayload::Handshake { encoded, .. } => dtls.queue_handshake(encoded.bytes()),
            #[cfg(feature = "tls12")]
            MessagePayload::ChangeCipherSpec(_) if dtls.is_v12() => dtls.queue_v12_ccs(),
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

impl Dtls {
    /// The most application data one record of the current sending epoch
    /// carries in one datagram, once application data may be sent.
    pub(crate) fn max_application_data(&self) -> Option<usize> {
        let epoch = self.write_epoch();
        if epoch < APPLICATION_EPOCH && !(self.is_v12() && epoch == 1) {
            return None;
        }
        self.record_room(epoch, self.settings.mtu)
    }

    /// Seals `data` as one application data record under the current
    /// sending epoch, appended to `out` as a datagram of its own.
    ///
    /// Returns whether the confidentiality limit of the keys is near, so
    /// that the caller updates them (RFC 9147 §4.5.3).
    pub(crate) fn seal_application_data(
        &mut self,
        out: &mut Vec<u8>,
        data: &[u8],
    ) -> Result<bool, Error> {
        self.seal_application_record(out, ContentType::ApplicationData, data)
    }

    /// Application traffic, including RRC, shares one key usage budget.
    pub(super) fn seal_application_record(
        &mut self,
        out: &mut Vec<u8>,
        typ: ContentType,
        data: &[u8],
    ) -> Result<bool, Error> {
        let epoch = self.write_epoch();
        #[cfg(feature = "tls12")]
        if self.is_v12() {
            if epoch != 1 {
                return Err(Error::HandshakeNotComplete);
            }
            if self
                .record_len(epoch, data.len())
                .is_none_or(|len| len > self.settings.mtu)
            {
                return Err(Error::EncryptError);
            }
            self.seal_record(out, epoch, typ, data)?;
            return Ok(false);
        }
        let (limit, next_seq) = match self.write.last() {
            Some(WriteEpoch {
                keys: Some(keys),
                next_seq,
                ..
            }) if epoch >= APPLICATION_EPOCH => (keys.confidentiality_limit(), *next_seq),
            _ => return Err(Error::HandshakeNotComplete),
        };
        if next_seq >= limit {
            return Err(Error::EncryptError);
        }
        if self
            .record_len(epoch, data.len())
            .is_none_or(|len| len > self.settings.mtu)
        {
            let kind = if typ == ContentType::ApplicationData {
                "application data"
            } else {
                "RRC control"
            };
            return Err(Error::General(alloc::format!(
                "{} bytes of {kind} do not fit one DTLS datagram",
                data.len()
            )));
        }
        self.seal_record(out, epoch, typ, data)?;
        // Ask for new keys with a margin: the KeyUpdate itself and its
        // retransmissions use the current keys until it is acknowledged.
        Ok(next_seq + 1 >= limit.saturating_sub(limit / 8))
    }
}
