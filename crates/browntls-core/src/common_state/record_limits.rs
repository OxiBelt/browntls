//! Directional record limits negotiated with the peer (RFC 8449).

use super::{CommonState, MIN_RECORD_SIZE_LIMIT, max_record_size_limit};
use crate::enums::AlertDescription;
use crate::error::{Error, PeerMisbehaved};

impl CommonState {
    /// A value below 64 is illegal even when we decline negotiation.
    pub(crate) fn validate_peer_record_size_limit(&mut self, limit: u16) -> Result<(), Error> {
        if limit < MIN_RECORD_SIZE_LIMIT {
            return Err(self.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalRecordSizeLimit,
            ));
        }
        Ok(())
    }

    pub(crate) fn local_record_size_limit(
        &self,
        stream_setting: Option<u16>,
        tls13: bool,
    ) -> Option<u16> {
        if self.is_quic() {
            return None;
        }
        let configured = match &self.dtls {
            Some(dtls) => dtls.record_size_limit_offer(),
            None => stream_setting,
        };
        configured.map(|limit| limit.min(max_record_size_limit(tls13)))
    }

    /// Applies the advertised bounds in their respective directions.
    /// RFC 8449 §4 allows us to accept values above the version maximum.
    pub(crate) fn apply_record_size_limits(
        &mut self,
        ours: u16,
        peers: u16,
        tls13: bool,
    ) -> Result<(), Error> {
        self.validate_peer_record_size_limit(peers)?;
        let max = max_record_size_limit(tls13);
        let peers = peers.min(max);
        let ours = ours.min(max);
        let result = if let Some(dtls) = &mut self.dtls {
            dtls.set_record_size_limits(ours, peers, tls13)
        } else {
            self.message_fragmenter
                .set_peer_record_size_limit(usize::from(peers) - usize::from(tls13));
            self.record_layer.set_inbound_record_size_limit(ours)
        };
        result.map_err(|err| self.send_fatal_alert(AlertDescription::RecordOverflow, err))
    }

    pub(crate) fn negotiated_receive_record_size_limit(&self) -> Option<u16> {
        self.record_layer.inbound_record_size_limit()
    }

    pub(crate) fn peer_tls13_record_size_limit(&self) -> u16 {
        self.message_fragmenter.peer_max_fragment_len() as u16 + 1
    }

    pub(crate) fn set_early_data_record_size_limit(&mut self, limit: Option<u16>) {
        self.message_fragmenter
            .set_early_data_max_fragment_len(limit.map(|limit| usize::from(limit) - 1));
    }
}
